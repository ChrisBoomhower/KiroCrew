/**
 * TrustAppModal — the consent gate for third-party app code execution.
 *
 * A third-party app is refused execution until the user grants it trust, so both
 * `POST /api/apps/{name}/enable` and the registry INSTALL path (which checks the
 * gate before cloning, so the refusal arrives before anything is on disk) answer
 * with `code: "app_execution_denied"`. Surfacing that raw backend string left the
 * user with no way forward; this modal turns the refusal into an informed
 * decision and, on confirm, grants trust for THIS APP ONLY and retries whichever
 * action was refused.
 *
 * The trust check keys off the machine-readable CODE, never the English
 * message: `isTrustDeniedError` reads the structured error body, so a reworded
 * backend message can never silently turn the consent flow back into a raw
 * error card. It reads the body STRUCTURALLY (duck-typed `body` / `code`
 * fields) rather than via `instanceof ApiError`, so it keeps working both for
 * the ApiError-shaped rejections that page tests stub in AND for a RESOLVED
 * install result — the SSE stream reports a refused install as a `done` payload
 * carrying the code, not as a rejection.
 */
import { useCallback, useState } from 'react'
import { Code2, GitBranch, Loader2, Server, ShieldAlert, Terminal } from 'lucide-react'

import { api } from '../../api/client'
import Modal from '../Modal'
import { Badge, Btn } from '../ui'
import { i18nT } from '../../i18n/t'
import { sourceLabel, type RegistryApp } from './types'

/** Machine-readable code the enable and registry-install paths return when trust is missing. */
export const APP_EXECUTION_DENIED = 'app_execution_denied'

/**
 * The subset of an app row the consent modal needs: identity for the grant,
 * display name for the title, and provenance (repo + source label) so the
 * user can see WHO they are about to trust.
 */
export type TrustAppTarget = Pick<RegistryApp, 'name' | '_registry' | 'origin'> & {
  displayName?: string
  repo?: string
}

/** Pull a machine-readable `code` out of an API rejection, if it carries one. */
function errorCode(e: unknown): string | null {
  if (!e || typeof e !== 'object') return null
  const direct = (e as { code?: unknown }).code
  if (typeof direct === 'string') return direct
  const body = (e as { body?: unknown }).body
  if (typeof body !== 'string' || !body.trim().startsWith('{')) return null
  try {
    const code = (JSON.parse(body) as { code?: unknown }).code
    return typeof code === 'string' ? code : null
  } catch {
    return null
  }
}

/**
 * True when a failure is the missing-trust gate rather than a real error.
 *
 * Accepts a rejection OR a resolved payload: a refused registry install comes
 * back as `{ ok: false, code: "app_execution_denied" }` on the SSE `done` event,
 * while a refused enable (and the non-streaming install route) rejects with the
 * code inside the response body.
 */
export function isTrustDeniedError(e: unknown): boolean {
  return errorCode(e) === APP_EXECUTION_DENIED
}

/**
 * Owns the consent-modal state and the grant-then-retry sequence, so the page
 * that owns the refused mutation drives one modal instead of each button
 * duplicating the flow.
 *
 * `retryEnable` is the DEFAULT action re-run once the grant lands (the page's own
 * enable path, including its cache invalidation). Two different gates now open
 * this same modal — enable, and the registry install, which checks the execution
 * gate before cloning — so `open()` takes an optional per-refusal retry: which
 * action to resume is a property of the refusal, not of the hook. The retry
 * travels WITH the target in one state object, so a confirm can never pair an
 * app with the wrong action.
 */
export function useTrustGate(retryEnable: (name: string) => Promise<void>) {
  const [gate, setGate] = useState<{
    app: TrustAppTarget
    retry: (name: string) => Promise<void>
  } | null>(null)
  const [pending, setPending] = useState(false)
  const [failed, setFailed] = useState(false)
  // Whether `trustApp` SUCCEEDED before a failure. The two failure cases need
  // different advice: a landed grant leaves state the user should know about and
  // may want to remove; a failed grant changed nothing, and sending them to
  // Settings to "check and remove it" would send them after nothing.
  const [granted, setGranted] = useState(false)

  const open = useCallback((app: TrustAppTarget, retry?: (name: string) => Promise<void>) => {
    setGate({ app, retry: retry ?? retryEnable })
    setPending(false)
    setFailed(false)
    setGranted(false)
  }, [retryEnable])

  const cancel = useCallback(() => {
    // Cancel grants nothing — it only drops the pending action.
    setGate(null)
    setPending(false)
    setFailed(false)
    setGranted(false)
  }, [])

  const confirm = useCallback(async () => {
    if (!gate || pending) return
    setPending(true)
    setFailed(false)
    try {
      await api.trustApp(gate.app.name)
      setGranted(true)
      await gate.retry(gate.app.name)
      setGate(null)
    } catch {
      // Keep the modal open and report inline: the grant may have landed while
      // the retried action failed for an unrelated reason, and closing here
      // would strand the user back on the raw-error path this modal replaces.
      setFailed(true)
    } finally {
      setPending(false)
    }
  }, [gate, pending])

  return { target: gate?.app ?? null, pending, failed, granted, open, cancel, confirm }
}

/**
 * Return *raw* as an href ONLY if it is a scheme we can hand a user, else `null`.
 *
 * `app.repo` is registry-index content, so it reaches this dialog untrusted. Parsed
 * with the URL constructor rather than a regex: a prefix check is defeated by
 * `\tjavascript:`, `JaVaScRiPt:`, and percent/entity encodings that the browser
 * still resolves, whereas `new URL().protocol` is the browser's own normalized
 * answer. Everything outside the allowlist — `javascript:`, `data:`, `blob:`,
 * `file:` — is refused, and a value the parser rejects outright is refused too.
 */
export function safeHref(raw: string): string | null {
  try {
    const url = new URL(raw)
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null
  } catch {
    return null
  }
}

/**
 * The three capabilities a trust grant confers, each paired with its icon.
 *
 * The label is a RESOLVED STRING, not a key: `check-i18n-keys.mjs` can only
 * verify a key it sees as a literal at the `i18nT()` call site, so mapping over
 * a list of key strings and calling `i18nT(key)` in the row makes the reference
 * invisible to the gate (it reports the file as a dynamic-key site) and a typo
 * would reach users as a raw key. A function, not a module constant, because the
 * strings must re-resolve on a language switch rather than freeze at import.
 */
function capabilities(): { label: string; Icon: typeof Code2 }[] {
  return [
    { label: i18nT('components.appstore.trustAppModal.capability_python'), Icon: Code2 },
    { label: i18nT('components.appstore.trustAppModal.capability_backend'), Icon: Server },
    { label: i18nT('components.appstore.trustAppModal.capability_shell'), Icon: Terminal },
  ]
}

export default function TrustAppModal({ app, pending, failed, granted, onCancel, onConfirm }: {
  /** The app awaiting consent; `null` keeps the modal closed. */
  app: TrustAppTarget | null
  pending: boolean
  failed: boolean
  /** True when the grant was written and only the retried action failed. */
  granted: boolean
  onCancel: () => void
  onConfirm: () => void
}) {
  const name = app ? (app.displayName || app.name) : ''
  return (
    <Modal
      open={!!app}
      onClose={onCancel}
      maxWidth={560}
      title={i18nT('components.appstore.trustAppModal.title', { app: name })}
      footer={
        <>
          <Btn onClick={onCancel} disabled={pending}>
            {i18nT('components.appstore.trustAppModal.cancel')}
          </Btn>
          <Btn primary onClick={onConfirm} disabled={pending}>
            {pending
              ? <><Loader2 size={14} className="animate-spin" /> {i18nT('components.appstore.trustAppModal.working')}</>
              : failed
                ? <><ShieldAlert size={14} /> {i18nT('components.appstore.trustAppModal.confirm_after_failure')}</>
                : <><ShieldAlert size={14} /> {i18nT('components.appstore.trustAppModal.confirm')}</>}
          </Btn>
        </>
      }
    >
      {app && (
        <div className="flex flex-col gap-3.5 text-[13px]">
          <p className="text-muted leading-relaxed">
            {i18nT('components.appstore.trustAppModal.scope')}
          </p>
          <p className="text-text leading-relaxed">
            {i18nT('components.appstore.trustAppModal.intro')}
          </p>
          {/* Explicit color-mix rather than a `bg-card/88` opacity modifier:
              theme colors are raw `var(--x)`, so the translucency depends on
              the config's opacity shim rather than on Tailwind's own alpha
              path. Verified to emit
              `background-color: color-mix(in srgb,var(--card) 88%,transparent)`. */}
          <ul className="flex flex-col gap-2.5 rounded-lg border border-border bg-[color-mix(in_srgb,var(--card)_88%,transparent)] px-3.5 py-3">
            {capabilities().map(({ label, Icon }) => (
              <li key={label} className="flex items-start gap-2.5 text-text leading-relaxed">
                <Icon size={14} className="mt-[3px] shrink-0 text-warn" />
                <span>{label}</span>
              </li>
            ))}
          </ul>
          {/* The three rows are a CEILING, not a manifest reading: trust grants all
              three regardless of what this app happens to use, and Kiro Crew cannot
              narrow it. Listing them without saying so reads as "here is what it
              does", which would be a promise we do not keep. */}
          <p className="text-muted leading-relaxed">
            {i18nT('components.appstore.trustAppModal.capability_note')}
          </p>
          <div className="flex flex-wrap items-center gap-2 text-muted">
            <GitBranch size={14} className="shrink-0" />
            <span className="shrink-0">{i18nT('components.appstore.trustAppModal.source')}</span>
            {app.repo && (
              /* Provenance is shown as a LINK only when the URL is one the user can
                 safely be handed: `app.repo` is index-controlled content, and
                 rendering it into `href` unchecked makes `javascript:...` a
                 one-click script-execution vector in the dashboard's own origin —
                 on the very dialog whose job is to gate code execution. So the
                 scheme is allowlisted, and anything else degrades to plain text
                 (still visible, still copyable, just not clickable) rather than
                 being hidden, because a weird URL is exactly what the user should
                 see before granting trust. `noreferrer` also keeps the dashboard
                 URL, which carries a session, out of the referrer header. */
              safeHref(app.repo)
                ? (
                  <a
                    href={safeHref(app.repo) ?? undefined}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-[12px] text-accent underline break-all hover:text-accent-hover"
                  >
                    {app.repo}
                  </a>
                )
                : (
                  <span className="font-mono text-[12px] text-text break-all">{app.repo}</span>
                )
            )}
            <Badge variant="muted">{sourceLabel(app)}</Badge>
          </div>
          {/* The registry badge above reads as an endorsement. It is not one. */}
          <p className="text-muted leading-relaxed">
            {i18nT('components.appstore.trustAppModal.not_reviewed')}
          </p>
          {/* Consent needs an exit: what refusing does, and that this is reversible
              plus where. Without these the dialog is a one-way door. */}
          <p className="text-muted leading-relaxed">
            {i18nT('components.appstore.trustAppModal.on_cancel', { app: name })}
          </p>
          <p className="text-muted leading-relaxed">
            {i18nT('components.appstore.trustAppModal.revocable')}
          </p>
          {failed && (
            /* Two failure strings, because the two cases need different advice: if
               the grant landed and only the enable failed, the user has state to
               clean up; if nothing was written, telling them to go check Settings
               sends them after something that isn't there. */
            <p role="alert" className="text-danger leading-relaxed">
              {granted
                ? i18nT('components.appstore.trustAppModal.failed', { app: name })
                : i18nT('components.appstore.trustAppModal.failed_generic', { app: name })}
            </p>
          )}
        </div>
      )}
    </Modal>
  )
}
