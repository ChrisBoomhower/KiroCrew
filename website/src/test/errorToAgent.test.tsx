/**
 * Error → agent hand-off.
 *
 * Covers the three load-bearing claims of the feature:
 *  1. the transport journals every API failure with its full context, so a UI
 *     holding only `e.message` can recover it (the zero-migration path);
 *  2. nothing credential-shaped reaches the prompt (it is fed to an LLM);
 *  3. the button lands the prompt in the chat composer.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import ErrorNotice from '../components/ErrorNotice'
import { mergeIntoDraft } from '../utils/chatDrafts'
import { buildErrorPrompt } from '../utils/errorReport.prompt'
import {
  ERROR_HANDOFF_KEY,
  MAX_DETAIL,
  MAX_JOURNAL,
  MAX_MESSAGE,
  consumeChatHandoff,
  findReport,
  handoffToChat,
  installSoftNavigate,
  parseErrorCode,
  recentErrors,
  recordError,
  redactSecrets,
  requestPath,
  sendErrorToChat,
  subscribeChatHandoff,
  __resetErrorJournalForTests,
  __resetNavSeamForTests,
} from '../utils/errorReport'

const navigated: string[] = []

beforeEach(() => {
  __resetErrorJournalForTests()
  __resetNavSeamForTests()
  navigated.length = 0
  sessionStorage.clear()
  installSoftNavigate(to => { navigated.push(to) })
})

afterEach(() => {
  __resetNavSeamForTests()
  vi.restoreAllMocks()
})

describe('errorReport journal', () => {
  it('keeps newest-first and caps at MAX_JOURNAL', () => {
    for (let i = 0; i < MAX_JOURNAL + 5; i++) recordError({ source: 'api', message: `boom ${i}` })
    const all = recentErrors()
    expect(all).toHaveLength(MAX_JOURNAL)
    expect(all[0].message).toBe(`boom ${MAX_JOURNAL + 4}`)
  })

  it('findReport recovers structured context from the bare message string', () => {
    recordError({
      source: 'api',
      message: 'blocked by execution policy',
      status: 403,
      code: 'app_execution_denied',
      endpoint: '/api/apps/install',
    })
    const found = findReport('blocked by execution policy')
    expect(found?.status).toBe(403)
    expect(found?.code).toBe('app_execution_denied')
    expect(found?.endpoint).toBe('/api/apps/install')
  })

  it('findReport is a no-op for unknown or empty messages', () => {
    expect(findReport('never happened')).toBeUndefined()
    expect(findReport('')).toBeUndefined()
    expect(findReport(null)).toBeUndefined()
  })
})

describe('redaction', () => {
  it('blanks credential-shaped substrings', () => {
    expect(redactSecrets('key AKIAIOSFODNN7EXAMPLE here')).toContain('[redacted-access-key]')
    expect(redactSecrets('Authorization: Bearer abcdef1234567890')).not.toContain('abcdef1234567890')
    expect(redactSecrets('{"token": "s3cr3t-value-x"}')).not.toContain('s3cr3t-value-x')
    expect(redactSecrets('password=hunter2hunter2')).not.toContain('hunter2hunter2')
  })

  it('leaves ordinary diagnostic text intact', () => {
    const text = 'ENOENT: no such file or directory, open /tmp/report.json'
    expect(redactSecrets(text)).toBe(text)
  })

  it('stays linear on a pathological body — the key-name wings are bounded', () => {
    // Regression, and the reason the `[\w-]{0,32}` bound exists. Unbounded wings
    // made this quadratic: 500KB of `token_` took 23s and 2MB took ~6min, freezing
    // the main thread. The input is reachable — `friendlyErrText` returns a
    // non-JSON response body verbatim, so `message`/`detail` can be a whole page.
    // Budget is deliberately loose (a loaded CI box is slow); the defect it guards
    // is three orders of magnitude away, not a few percent.
    const pathological = 'token_'.repeat(80_000) // ~480KB, all word characters
    const started = Date.now()
    redactSecrets(pathological)
    expect(Date.now() - started).toBeLessThan(2_000)
  })

  it('caps message and detail so a whole error page cannot reach the prompt', () => {
    const huge = 'x'.repeat(50_000)
    const r = recordError({ source: 'api', message: huge, detail: huge })
    expect(r.message.length).toBeLessThanOrEqual(MAX_MESSAGE + 32)
    expect(r.detail!.length).toBeLessThanOrEqual(MAX_DETAIL + 32)
  })

  it('still redacts a credential that sits before the detail cap', () => {
    // Capping happens BEFORE scrubbing, so pin that the order did not open a hole:
    // a key and the head of its value on the same side of the cut still match.
    const r = recordError({
      source: 'api',
      message: 'boom',
      detail: `access_token=ghp_liveValue123456\n${'x'.repeat(50_000)}`,
    })
    expect(r.detail).not.toContain('ghp_liveValue123456')
  })

  it('applies redaction to the stored message and detail', () => {
    const r = recordError({
      source: 'api',
      message: 'auth failed for AKIAIOSFODNN7EXAMPLE',
      detail: 'session_key=abcdef123456',
    })
    expect(r.message).not.toContain('AKIAIOSFODNN7EXAMPLE')
    expect(r.detail).not.toContain('abcdef123456')
  })

  it('requestPath drops the query string so a ?token= is never journaled', () => {
    expect(requestPath('http://localhost:5476/api/config?token=supersecret')).toBe('/api/config')
    expect(requestPath(undefined)).toBeUndefined()
  })

  it('never journals the route query string — the dashboard auth hand-off is ?token=', () => {
    // Regression: `route` is the ONE field recordError does not scrub, so it has
    // to be safe by construction. The dashboard is opened as `/?token=<cred>`
    // and an effect strips it later — a failure before that would have leaked it.
    const url = new URL(window.location.href)
    url.pathname = '/settings'
    url.search = '?tab=security&token=live-session-credential'
    window.history.replaceState({}, '', url.toString())
    try {
      const r = recordError({ source: 'api', message: 'save failed' })
      expect(r.route).toBe('/settings')
      expect(r.route).not.toContain('token')
      expect(buildErrorPrompt(r, 'LEAD')).not.toContain('live-session-credential')
    } finally {
      window.history.replaceState({}, '', '/')
    }
  })

  it('redacts URL userinfo, the shape a git remote error echoes back', () => {
    // nosemgrep: generic.secrets.security.detected-username-and-password-in-uri.detected-username-and-password-in-uri -- the credential-bearing URI is the FIXTURE, not a leaked secret: this line is the exact input redactSecrets must neutralise, and the assertions below prove it does. The token is fabricated. Removing it would delete the regression test for a PAT reaching an LLM prompt.
    const remote = 'https://x-access-token:ghp_liveTokenValue123@github.com/org/repo.git'
    const out = redactSecrets(`fatal: could not read from ${remote}`)
    expect(out).not.toContain('ghp_liveTokenValue123')
    expect(out).not.toContain('x-access-token')
    // The useful part of the diagnostic survives.
    expect(out).toContain('github.com/org/repo.git')
  })

  it('leaves an ordinary URL with no userinfo alone', () => {
    const url = 'https://github.com/kirodotdev/KiroCrew/pull/1234'
    expect(redactSecrets(`see ${url}`)).toContain(url)
  })

  it('catches prefixed credential key names (a bare \\btoken\\b misses access_token)', () => {
    for (const key of ['access_token', 'refresh_token', 'id_token', 'client_secret', 'apiKey']) {
      const out = redactSecrets(`{"${key}": "liveCredentialValue"}`)
      expect(out, key).not.toContain('liveCredentialValue')
    }
  })

  it('scrubs the assembled prompt, so a bare message with no journal entry is covered', () => {
    // AskAgentButton's last fallback is `{ message }` with no journal entry —
    // the path every un-migrated `setError(e.message)` site takes. That string
    // never passed through recordError, so the prompt boundary must scrub it.
    const prompt = buildErrorPrompt(
      // nosemgrep: generic.secrets.security.detected-username-and-password-in-uri.detected-username-and-password-in-uri -- fabricated credential URI used as the FIXTURE: this is the un-journaled bare-message path, and the assertion proves the prompt boundary scrubs it before an LLM ever sees it.
      { message: 'clone failed: https://x-access-token:ghp_bareFallback99@github.com/o/r.git' },
      'LEAD',
    )
    expect(prompt).not.toContain('ghp_bareFallback99')
  })
})

describe('parseErrorCode', () => {
  it('reads the backend machine-readable code', () => {
    expect(parseErrorCode('{"error":"nope","code":"app_execution_denied"}')).toBe('app_execution_denied')
  })
  it('returns undefined for prose or malformed bodies', () => {
    expect(parseErrorCode('plain prose failure')).toBeUndefined()
    expect(parseErrorCode('{not json')).toBeUndefined()
    expect(parseErrorCode(undefined)).toBeUndefined()
  })
})

describe('buildErrorPrompt', () => {
  it('leads with the translated instruction and lists the machine facts', () => {
    const r = recordError({
      source: 'api',
      message: 'blocked by execution policy',
      status: 403,
      code: 'app_execution_denied',
      endpoint: '/api/apps/install',
      route: '/apps/launchdarkly',
      detail: 'third-party apps are disabled',
    })
    const prompt = buildErrorPrompt(r, 'FIX THIS')
    expect(prompt.startsWith('FIX THIS')).toBe(true)
    expect(prompt).toContain('/api/apps/install -> HTTP 403')
    expect(prompt).toContain('- Code: app_execution_denied')
    expect(prompt).toContain('- Route: /apps/launchdarkly')
    expect(prompt).toContain('third-party apps are disabled')
  })

  it('works from a bare message with no journal entry', () => {
    expect(buildErrorPrompt({ message: 'something broke' }, 'LEAD')).toContain('- Message: something broke')
  })
})

describe('chat hand-off channel', () => {
  it('round-trips and clears', () => {
    handoffToChat('prompt text')
    expect(sessionStorage.getItem(ERROR_HANDOFF_KEY)).toBeTruthy()
    expect(consumeChatHandoff()).toBe('prompt text')
    // Single-use: a second drain must not re-deliver.
    expect(consumeChatHandoff()).toBeNull()
  })

  it('drops a stale hand-off instead of ambushing a later visit', () => {
    sessionStorage.setItem(ERROR_HANDOFF_KEY, JSON.stringify({ prompt: 'old', ts: Date.now() - 600_000 }))
    expect(consumeChatHandoff()).toBeNull()
  })

  it('ignores a malformed payload', () => {
    sessionStorage.setItem(ERROR_HANDOFF_KEY, 'not json')
    expect(consumeChatHandoff()).toBeNull()
  })

  it('notifies an already-mounted subscriber, then soft-navigates', () => {
    const seen: (string | null)[] = []
    const off = subscribeChatHandoff(() => { seen.push(consumeChatHandoff()) })
    sendErrorToChat('please fix')
    off()
    expect(seen).toEqual(['please fix'])
    expect(navigated).toEqual(['/chat'])
  })

  it('a subscriber can append the prompt to an in-progress draft', () => {
    // Pins the ChatPage drain contract: the hand-off fires with no route change
    // while the composer may hold unsent text, and the pending-input consumer
    // REPLACES + persists the draft. A drain that plain-sets destroys the
    // user's typing unrecoverably, so it must append via mergeIntoDraft.
    let delivered = ''
    const off = subscribeChatHandoff(() => {
      const prompt = consumeChatHandoff()
      if (prompt) delivered = mergeIntoDraft('half-typed question  ', prompt)
    })
    sendErrorToChat('- Message: save failed')
    off()
    expect(delivered).toBe('half-typed question\n\n- Message: save failed')
  })

  it('mergeIntoDraft leaves an empty composer with just the prompt', () => {
    expect(mergeIntoDraft('', 'P')).toBe('P')
    expect(mergeIntoDraft(null, 'P')).toBe('P')
    expect(mergeIntoDraft('   \n ', 'P')).toBe('P')
  })

  it('hard mode bypasses the soft navigator entirely', () => {
    const assign = vi.fn()
    // happy-dom refuses to reassign `location`, so stub only the method.
    vi.spyOn(window.location, 'assign').mockImplementation(assign)
    sendErrorToChat('please fix', { hard: true })
    expect(navigated).toEqual([])
    expect(assign).toHaveBeenCalledWith('/chat')
    // The prompt is still staged, so it survives the page load.
    expect(consumeChatHandoff()).toBe('please fix')
  })

  it('falls back to a full page load when no navigator is installed', () => {
    __resetNavSeamForTests()
    const assign = vi.fn()
    vi.spyOn(window.location, 'assign').mockImplementation(assign)
    sendErrorToChat('please fix')
    expect(assign).toHaveBeenCalledWith('/chat')
  })
})

describe('ErrorNotice', () => {
  it('renders nothing when there is no message', () => {
    const { container } = render(<ErrorNotice message={null} />)
    expect(container.firstChild).toBeNull()
  })

  it('shows the error and an ask-the-agent action', () => {
    render(<ErrorNotice message="disk is full" />)
    expect(screen.getByRole('alert')).toHaveTextContent('disk is full')
    expect(screen.getByRole('button', { name: /ask the agent/i })).toBeInTheDocument()
  })

  it('renders with no Redux or Router context — the crash-fallback contract', () => {
    // No <Provider>, no <MemoryRouter>: a boundary fallback cannot assume either.
    expect(() => render(<ErrorNotice message="tree threw" />)).not.toThrow()
  })

  it('hands the journaled context — not just the visible sentence — to the composer', async () => {
    recordError({
      source: 'api',
      message: 'blocked by execution policy',
      status: 403,
      code: 'app_execution_denied',
      endpoint: '/api/apps/install',
    })
    render(<ErrorNotice message="blocked by execution policy" />)
    await userEvent.click(screen.getByRole('button', { name: /ask the agent/i }))

    expect(navigated).toEqual(['/chat'])
    const staged = consumeChatHandoff() ?? ''
    expect(staged).toContain('blocked by execution policy')
    expect(staged).toContain('app_execution_denied')
    expect(staged).toContain('/api/apps/install')
  })

  it('resolves the report at CLICK time, not render time', () => {
    // Pins the boundary ordering contract. React renders the fallback BEFORE
    // componentDidCatch journals the report, and a recovered-then-recrashed
    // boundary would hand down the PREVIOUS crash's report as a prop. So the
    // boundaries pass only `message` and resolution happens on click.
    render(<ErrorNotice message="frame failed to render" />)
    // Journal arrives only now — after the button has already rendered.
    recordError({
      source: 'render',
      message: 'frame failed to render',
      code: 'message_render',
      detail: 'at AssistantMessage (chat.tsx:236)',
    })
    screen.getByRole('button', { name: /ask the agent/i }).click()

    const staged = consumeChatHandoff() ?? ''
    expect(staged).toContain('at AssistantMessage')
    expect(staged).toContain('- Code: message_render')
  })

  it('askAgent={false} opts a non-actionable error out of the button', () => {
    render(<ErrorNotice message="name is required" askAgent={false} />)
    expect(screen.queryByRole('button', { name: /ask the agent/i })).not.toBeInTheDocument()
  })

  it('title is a separate lead, so the journal lookup key stays the raw message', async () => {
    recordError({ source: 'api', message: 'disk quota exceeded', status: 507, endpoint: '/api/artifacts' })
    render(<ErrorNotice message="disk quota exceeded" title="Save failed" />)
    expect(screen.getByRole('alert')).toHaveTextContent('Save failed')

    await userEvent.click(screen.getByRole('button', { name: /ask the agent/i }))
    const staged = consumeChatHandoff() ?? ''
    // Concatenating the title into `message` would have broken this lookup.
    expect(staged).toContain('/api/artifacts')
    expect(staged).toContain('HTTP 507')
  })

  it('inline variant renders no box, keeping an existing flex row intact', () => {
    // The block variant is a bordered card; dropping one into a button row would
    // break the row, which is why the inline shape exists at all.
    const { container } = render(<ErrorNotice message="not connected" variant="inline" />)
    const alert = screen.getByRole('alert')
    expect(alert.tagName).toBe('SPAN')
    expect(alert.className).not.toMatch(/border-danger\/40/)
    expect(container.querySelector('.rounded-lg')).toBeNull()
    // Same hand-off as the block variant.
    expect(screen.getByRole('button', { name: /ask the agent/i })).toBeInTheDocument()
  })

  it('block variant is the default and is a boxed banner', () => {
    render(<ErrorNotice message="not connected" />)
    const alert = screen.getByRole('alert')
    expect(alert.tagName).toBe('DIV')
    expect(alert.className).toMatch(/border-danger\/40/)
  })

  it('renders a dismiss affordance only when a handler is given', async () => {
    const onDismiss = vi.fn()
    const { unmount } = render(<ErrorNotice message="oops" onDismiss={onDismiss} />)
    await userEvent.click(screen.getByRole('button', { name: /dismiss/i }))
    expect(onDismiss).toHaveBeenCalledOnce()
    unmount()

    render(<ErrorNotice message="oops" />)
    expect(screen.queryByRole('button', { name: /dismiss/i })).not.toBeInTheDocument()
  })
})
