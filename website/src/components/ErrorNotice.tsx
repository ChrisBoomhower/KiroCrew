import { AlertTriangle, X } from 'lucide-react'
import AskAgentButton from './AskAgentButton'
import type { ErrorReport } from '../utils/errorReport'

import { i18nT } from '../i18n/t'

/**
 * The shared error surface — one place that renders an error *and* offers to
 * hand it to the agent.
 *
 * Replaces the ad-hoc `{err && <div className="text-danger">{err}</div>}` shape
 * repeated across the dashboard. The migration is deliberately trivial: pass the
 * same string the call site already had and the structured context (endpoint,
 * status, backend `code`) is recovered from the error journal
 * (`utils/errorReport`), so no call site has to start threading an error object.
 *
 * Pass `report` instead when the caller genuinely holds one (a caught
 * `ApiError`), which skips the message-match lookup.
 *
 * ## Two variants, because the dashboard has two shapes
 *
 * `block` is the boxed banner at the top of a panel. `inline` is the compact
 * run of text that sits inside an existing button row — those sites are laid out
 * as flex children, so dropping a bordered box into one would break the row. The
 * variant is a layout choice only; both carry the same agent hand-off.
 */
export default function ErrorNotice({
  message,
  report,
  title,
  onDismiss,
  variant = 'block',
  askAgent = true,
  className = '',
}: {
  /** Human error text. Falsy renders nothing, so `<ErrorNotice message={err} />` needs no `&&` guard. */
  message?: string | null
  /** Structured report, when known. Otherwise looked up by `message`. */
  report?: ErrorReport
  /**
   * Optional bold lead ("Save failed"). Kept separate from `message` rather than
   * concatenated, because `message` is the journal lookup key — prefixing it
   * would lose the structured context this component exists to recover.
   */
  title?: string
  /** Renders a dismiss affordance when provided. */
  onDismiss?: () => void
  /** `block` = boxed banner; `inline` = compact text for an existing flex row. */
  variant?: 'block' | 'inline'
  /** Escape hatch for the rare error the agent cannot act on (e.g. a form validation hint). */
  askAgent?: boolean
  className?: string
}) {
  if (!message) return null

  if (variant === 'inline') {
    return (
      <span role="alert" className={`inline-flex items-center gap-1.5 text-[12px] text-danger ${className}`}>
        <AlertTriangle size={14} className="shrink-0" aria-hidden="true" />
        {title && <strong className="font-semibold">{title}</strong>}
        <span className="min-w-0" style={{ overflowWrap: 'anywhere' }}>{message}</span>
        {askAgent && <AskAgentButton report={report} message={message} />}
        {onDismiss && (
          <button
            type="button"
            className="shrink-0 bg-transparent border-none p-0 cursor-pointer text-danger/70 hover:text-danger transition-colors"
            aria-label={i18nT('components.errorNotice.dismiss')}
            onClick={onDismiss}
          >
            <X size={13} aria-hidden="true" />
          </button>
        )}
      </span>
    )
  }

  return (
    <div
      role="alert"
      className={`rounded-lg border border-danger/40 bg-danger/10 px-3 py-2 flex items-start gap-2 text-[13px] text-danger ${className}`}
    >
      <AlertTriangle size={14} className="mt-[2px] shrink-0" aria-hidden="true" />
      <div className="min-w-0 flex-1 whitespace-pre-wrap" style={{ overflowWrap: 'anywhere' }}>
        {title && <strong className="font-semibold">{title} </strong>}
        {message}
      </div>
      {askAgent && <AskAgentButton report={report} message={message} className="mt-[1px]" />}
      {onDismiss && (
        <button
          type="button"
          className="shrink-0 bg-transparent border-none p-0 cursor-pointer text-danger/70 hover:text-danger transition-colors"
          aria-label={i18nT('components.errorNotice.dismiss')}
          onClick={onDismiss}
        >
          <X size={14} aria-hidden="true" />
        </button>
      )}
    </div>
  )
}
