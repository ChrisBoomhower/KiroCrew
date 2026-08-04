/**
 * Trust-consent gate for third-party app code execution.
 *
 * Covers the contract that matters for security UX: the gate opens on the
 * machine-readable `app_execution_denied` CODE (never on message text),
 * confirming grants trust for exactly one app and then retries the enable,
 * every other enable failure stays a plain error, and Cancel grants nothing.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Routes, Route } from 'react-router-dom'

// --- Mocks -----------------------------------------------------------------
const listApps = vi.fn()
const listRegistry = vi.fn()
const listRegistries = vi.fn()
const enableApp = vi.fn()
const trustApp = vi.fn()
const getApp = vi.fn()
const system = vi.fn()
const installFromRegistryStream = vi.fn()

vi.mock('../api/client', () => ({
  api: {
    listApps: (...a: unknown[]) => listApps(...a),
    listRegistry: (...a: unknown[]) => listRegistry(...a),
    listRegistries: (...a: unknown[]) => listRegistries(...a),
    updateRegistries: vi.fn(),
    refreshRegistries: vi.fn(),
    enableApp: (...a: unknown[]) => enableApp(...a),
    trustApp: (...a: unknown[]) => trustApp(...a),
    getApp: (...a: unknown[]) => getApp(...a),
    system: (...a: unknown[]) => system(...a),
    installFromRegistryStream: (...a: unknown[]) => installFromRegistryStream(...a),
    disableApp: vi.fn(),
    updateApp: vi.fn(),
    uninstallApp: vi.fn(),
    uninstallPreview: vi.fn().mockResolvedValue({ dependencies: { removable: [], shared: [], userInstalled: [] } }),
    installApp: vi.fn(),
    openApp: vi.fn(),
  },
}))

vi.mock('../hooks/useTheme', () => ({ useTheme: () => ({ theme: 'dark' }) }))

// Render catalog KEYS, not English. The trust-modal strings are authored in the
// locale catalogs; asserting on their English would make this suite a copy of
// the copywriting and break on any reword. Interpolated values are appended so
// the {{app}} threading is still observable.
vi.mock('../i18n/t', () => ({
  i18nT: (key: string, vars?: Record<string, unknown>) =>
    vars && Object.keys(vars).length ? `${key} ${Object.values(vars).join(' ')}` : key,
}))

vi.mock('../components/AppIcon', () => ({
  default: () => <div data-testid="app-icon" />,
}))

// SegmentedControl measures its container (0px in jsdom) and collapses to a
// dropdown, hiding tab labels — stub it with plain buttons.
vi.mock('../components/SegmentedControl', () => ({
  default: ({ segments, onChange }: {
    segments: { key: string; label: string }[]
    onChange: (key: string) => void
  }) => (
    <div>
      {segments.map(s => (
        <button key={s.key} type="button" onClick={() => onChange(s.key)}>{s.label}</button>
      ))}
    </div>
  ),
}))

import AppsPage from '../pages/AppsPage'
import AppDetailPage from '../pages/AppDetailPage'
import { isTrustDeniedError, APP_EXECUTION_DENIED, safeHref } from '../components/appstore/TrustAppModal'

/** An ApiError-shaped rejection: message plus the raw structured body. */
function apiError(status: number, body: object, message = 'boom') {
  return Object.assign(new Error(message), { status, body: JSON.stringify(body) })
}

const TRUST_DENIED = () => apiError(403, {
  error: 'App third-party is not trusted to run its own code.',
  code: APP_EXECUTION_DENIED,
})

/**
 * How a REFUSED registry install arrives: the SSE stream resolves its `done`
 * payload, so the code travels on the result rather than on a rejection.
 */
const INSTALL_DENIED = () => ({
  ok: false,
  name: 'launchdarkly',
  error: 'blocked by execution policy: App launchdarkly is not trusted to run its own code.',
  code: APP_EXECUTION_DENIED,
  log: '',
})

const THIRD_PARTY = {
  name: 'launchdarkly',
  displayName: 'LaunchDarkly',
  description: 'Feature flags in your agentic workspace.',
  version: '1.0.0',
  author: 'launchdarkly',
  repo: 'https://github.com/launchdarkly-labs/launchdarkly-kiro-crew-app',
  tags: ['feature-flags'],
  featured: 1,
  installed: true,
  enabled: false,
  origin: 'registry',
  updateAvailable: false,
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/apps']}>
        <Routes>
          <Route path="/apps" element={<AppsPage />} />
          <Route path="/apps/detail/:name" element={<div data-testid="detail-route" />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/**
 * Render the DETAIL page the way the App Store's Get button reaches it.
 *
 * Get on AppsPage (and on FeaturedSpotlight, which takes `onGet` as a prop)
 * navigates to `/apps/detail/:name` with `autoAction: 'install'` in ROUTER STATE
 * — never a query param — and the detail page runs the install from there. So the
 * install-refusal consent flow is exercised here, at the surface that owns the
 * install call.
 */
function renderDetailFromGet(name = THIRD_PARTY.name) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[{ pathname: `/apps/detail/${name}`, state: { autoAction: 'install' } }]}>
        <Routes>
          <Route path="/apps/detail/:name" element={<AppDetailPage />} />
          <Route path="/apps" element={<div data-testid="apps-route" />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/**
 * Click Enable on the third-party app.
 *
 * The Library tab is the surface that offers it: FeaturedSpotlight/AppListRow
 * only render Enable for a hidden BUILT-IN, so an installed-but-disabled
 * third-party app is enabled from its installed card (or the detail page).
 */
async function clickEnable() {
  fireEvent.click(await screen.findByRole('button', { name: /appsPage\.library/ }))
  const btn = await screen.findByRole('button', { name: /installedAppCard\.enable$/ })
  fireEvent.click(btn)
  return btn
}

const K = 'components.appstore.trustAppModal'
const modalTitle = () => screen.queryByText(`${K}.title ${THIRD_PARTY.displayName}`)
const confirmBtn = () => screen.getByRole('button', { name: new RegExp(`${K}\\.(confirm|working)`) })
const cancelBtn = () => screen.getByRole('button', { name: new RegExp(`${K}\\.cancel`) })

beforeEach(() => {
  vi.clearAllMocks()
  sessionStorage.clear()
  listApps.mockResolvedValue([
    {
      name: THIRD_PARTY.name, displayName: THIRD_PARTY.displayName, version: '1.0.0',
      enabled: false, installedAt: '2026-08-03T00:00:00Z', origin: 'registry',
      manifest: {
        name: THIRD_PARTY.name, version: '1.0.0', displayName: THIRD_PARTY.displayName,
        description: THIRD_PARTY.description, author: THIRD_PARTY.author, repo: THIRD_PARTY.repo,
      },
    },
  ])
  listRegistry.mockResolvedValue({ apps: [THIRD_PARTY], serverPlatform: { os: 'darwin', arch: 'arm64' } })
  listRegistries.mockResolvedValue({ registries: [] })
  trustApp.mockResolvedValue({ apps: [THIRD_PARTY.name], ineffective: [], allowAll: false })
  // Detail-page load: not installed yet, so the registry entry is the source of
  // truth and the page offers Get rather than Enable/Disable.
  getApp.mockRejectedValue(new Error('not installed'))
  system.mockResolvedValue({ hostname: 'localhost' })
})

describe('isTrustDeniedError', () => {
  it('matches only the app_execution_denied code, ignoring the message text', () => {
    expect(isTrustDeniedError(TRUST_DENIED())).toBe(true)
    // Same English wording, different code → NOT the trust gate.
    expect(isTrustDeniedError(apiError(403, {
      error: 'App third-party is not trusted to run its own code.',
      code: 'some_other_code',
    }))).toBe(false)
    expect(isTrustDeniedError(apiError(500, { error: 'kaboom' }))).toBe(false)
    expect(isTrustDeniedError(new Error('app_execution_denied'))).toBe(false)
    expect(isTrustDeniedError(undefined)).toBe(false)
  })

  it('also matches a RESOLVED install result, which carries the code on the payload', () => {
    // The SSE install stream reports a refusal by RESOLVING `done` with this
    // shape, so a check that only understood rejections would never open the
    // consent modal on the install path.
    expect(isTrustDeniedError(INSTALL_DENIED())).toBe(true)
    expect(isTrustDeniedError({ ok: false, error: 'clone failed' })).toBe(false)
  })
})

describe('AppsPage trust gate', () => {
  it('opens the consent modal when enable is refused with app_execution_denied', async () => {
    enableApp.mockRejectedValue(TRUST_DENIED())
    renderPage()
    await clickEnable()

    await waitFor(() => expect(modalTitle()).toBeTruthy())
    // Scope disclosure, the three capabilities, and the provenance line.
    expect(screen.getByText(`${K}.scope`)).toBeTruthy()
    expect(screen.getByText(`${K}.capability_python`)).toBeTruthy()
    expect(screen.getByText(`${K}.capability_backend`)).toBeTruthy()
    expect(screen.getByText(`${K}.capability_shell`)).toBeTruthy()
    expect(screen.getByText(`${K}.source`)).toBeTruthy()
    expect(screen.getByText(THIRD_PARTY.repo)).toBeTruthy()
    // The raw backend string never reaches the user.
    expect(screen.queryByText(/is not trusted to run its own code/)).toBeNull()
  })

  it('grants trust for that one app and retries the enable on confirm', async () => {
    enableApp.mockRejectedValueOnce(TRUST_DENIED()).mockResolvedValue({ ok: true })
    renderPage()
    await clickEnable()
    await waitFor(() => expect(modalTitle()).toBeTruthy())

    fireEvent.click(confirmBtn())

    await waitFor(() => expect(trustApp).toHaveBeenCalledWith(THIRD_PARTY.name))
    await waitFor(() => expect(enableApp).toHaveBeenCalledTimes(2))
    expect(trustApp).toHaveBeenCalledTimes(1)
    // Grant landed and the retry succeeded → the modal closes.
    await waitFor(() => expect(modalTitle()).toBeNull())
  })

  it('keeps the modal open and reports inline when the retried enable fails', async () => {
    enableApp.mockRejectedValue(TRUST_DENIED())
    renderPage()
    await clickEnable()
    await waitFor(() => expect(modalTitle()).toBeTruthy())

    fireEvent.click(confirmBtn())

    await waitFor(() => expect(screen.getByRole('alert').textContent)
      .toBe(`${K}.failed LaunchDarkly`))
    expect(modalTitle()).toBeTruthy()
  })

  it('does NOT open the modal for a non-trust enable failure', async () => {
    enableApp.mockRejectedValue(apiError(500, { error: 'gateway exploded' }, 'gateway exploded'))
    renderPage()
    await clickEnable()

    await waitFor(() => expect(screen.getByText(/gateway exploded/)).toBeTruthy())
    expect(modalTitle()).toBeNull()
    expect(trustApp).not.toHaveBeenCalled()
  })

  it('grants nothing when the user cancels', async () => {
    enableApp.mockRejectedValue(TRUST_DENIED())
    renderPage()
    await clickEnable()
    await waitFor(() => expect(modalTitle()).toBeTruthy())

    fireEvent.click(cancelBtn())

    await waitFor(() => expect(modalTitle()).toBeNull())
    expect(trustApp).not.toHaveBeenCalled()
    expect(enableApp).toHaveBeenCalledTimes(1)
  })
})

/**
 * The INSTALL side of the same gate.
 *
 * The registry install path checks the execution gate BEFORE cloning, so a Get on
 * an untrusted third-party app is refused before anything reaches disk. That
 * refusal must open the same consent modal — and confirming must retry the
 * INSTALL, not the enable: nothing is installed yet, so an enable retry would
 * fail on a missing app and strand the user.
 */
describe('registry install trust gate', () => {
  /** Same app, not installed yet — the state a Get starts from. */
  const NOT_INSTALLED = { ...THIRD_PARTY, installed: false, enabled: false }

  beforeEach(() => {
    listRegistry.mockResolvedValue({ apps: [NOT_INSTALLED], serverPlatform: { os: 'darwin', arch: 'arm64' } })
  })

  it('opens the consent modal when the install is refused with app_execution_denied', async () => {
    installFromRegistryStream.mockResolvedValue(INSTALL_DENIED())
    renderDetailFromGet()

    await waitFor(() => expect(modalTitle()).toBeTruthy())
    expect(screen.getByText(`${K}.capability_python`)).toBeTruthy()
    // The raw backend sentence never reaches the user.
    expect(screen.queryByText(/blocked by execution policy/)).toBeNull()
  })

  it('grants trust then retries the INSTALL — never the enable', async () => {
    installFromRegistryStream
      .mockResolvedValueOnce(INSTALL_DENIED())
      .mockResolvedValue({ ok: true, name: THIRD_PARTY.name })
    renderDetailFromGet()
    await waitFor(() => expect(modalTitle()).toBeTruthy())
    expect(installFromRegistryStream).toHaveBeenCalledTimes(1)

    fireEvent.click(confirmBtn())

    await waitFor(() => expect(trustApp).toHaveBeenCalledWith(THIRD_PARTY.name))
    // The retry is the install, re-run once for the same app.
    await waitFor(() => expect(installFromRegistryStream).toHaveBeenCalledTimes(2))
    expect(installFromRegistryStream.mock.calls[1][0]).toBe(THIRD_PARTY.name)
    expect(enableApp).not.toHaveBeenCalled()
    // Grant landed and the retried install succeeded → the modal closes.
    await waitFor(() => expect(modalTitle()).toBeNull())
  })

  it('keeps the modal open and reports inline when the retried install is refused again', async () => {
    // A grant that did not take effect must not look like success.
    installFromRegistryStream.mockResolvedValue(INSTALL_DENIED())
    renderDetailFromGet()
    await waitFor(() => expect(modalTitle()).toBeTruthy())

    fireEvent.click(confirmBtn())

    await waitFor(() => expect(screen.getByRole('alert').textContent)
      .toBe(`${K}.failed LaunchDarkly`))
    expect(modalTitle()).toBeTruthy()
  })

  it('does NOT open the modal for an ordinary install failure', async () => {
    installFromRegistryStream.mockResolvedValue({ ok: false, error: 'git clone exploded' })
    renderDetailFromGet()

    await waitFor(() => expect(screen.getByText(/git clone exploded/)).toBeTruthy())
    expect(modalTitle()).toBeNull()
    expect(trustApp).not.toHaveBeenCalled()
  })

  it('grants nothing when the user cancels the install consent', async () => {
    installFromRegistryStream.mockResolvedValue(INSTALL_DENIED())
    renderDetailFromGet()
    await waitFor(() => expect(modalTitle()).toBeTruthy())

    fireEvent.click(cancelBtn())

    await waitFor(() => expect(modalTitle()).toBeNull())
    expect(trustApp).not.toHaveBeenCalled()
    expect(installFromRegistryStream).toHaveBeenCalledTimes(1)
  })
})

describe('safeHref — the provenance link is not a script sink', () => {
  // REGRESSION: `app.repo` is registry-index content. Rendering it straight into
  // `href` made `javascript:...` a one-click script-execution vector in the
  // dashboard's own origin — on the very dialog whose job is to gate code
  // execution. The link was added to satisfy a usability finding and opened this.
  it('accepts http(s) and refuses every script-capable scheme', () => {
    expect(safeHref('https://github.com/owner/repo')).toBe('https://github.com/owner/repo')
    expect(safeHref('http://example.com/x')).toBe('http://example.com/x')
    for (const bad of [
      'javascript:alert(1)',
      'JaVaScRiPt:alert(1)',
      '\tjavascript:alert(1)',
      ' javascript:alert(1)',
      'data:text/html,<script>alert(1)</script>',
      'blob:https://example.com/uuid',
      'file:///etc/passwd',
      'vbscript:msgbox(1)',
      'not a url at all',
      '',
    ]) {
      expect(safeHref(bad)).toBeNull()
    }
  })
})
