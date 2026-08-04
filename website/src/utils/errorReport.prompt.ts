/**
 * The error → agent prompt. Model-facing text only, per the `*.prompt.ts`
 * convention in `eslint.i18n.config.js`: everything here is the body of a message
 * sent to the agent, so it is English by design and carries no UI copy.
 */

import { redactSecrets, type ErrorReport } from './errorReport'

/**
 * Build the chat prompt for an error.
 *
 * `lead` is the caller-supplied, *translated* instruction line — the one sentence
 * a human reads, so it comes from the catalog rather than from here. The fact
 * block below it is deliberately NOT translated: it is log output, and field
 * labels a model reads are more useful stable than localized.
 *
 * **The assembled prompt is scrubbed here, at the boundary.** `recordError`
 * already scrubs `message` and `detail` on the way into the journal, but two
 * paths reach this function without ever passing through it: a caller that has
 * no journal entry and hands over a bare `{ message }` (AskAgentButton's last
 * fallback, which is what the ~80 un-migrated `setError(e.message)` sites hit),
 * and the `route` / `code` / `endpoint` fields, which `recordError` stores
 * verbatim. Scrubbing the finished string is the only place that covers every
 * field and every caller, including ones added later.
 */
export function buildErrorPrompt(report: ErrorReport | { message: string }, lead: string): string {
  const r = report as Partial<ErrorReport> & { message: string }
  const lines: string[] = [lead, '']
  if (r.route) lines.push(`- Route: ${r.route}`)
  if (r.endpoint) {
    lines.push(`- Request: ${r.endpoint}${r.status ? ` -> HTTP ${r.status}` : ''}`)
  } else if (r.status) {
    lines.push(`- Status: HTTP ${r.status}`)
  }
  if (r.code) lines.push(`- Code: ${r.code}`)
  if (r.source) lines.push(`- Source: ${r.source}`)
  lines.push(`- Message: ${r.message}`)
  if (r.detail && r.detail !== r.message) {
    lines.push('', '```', r.detail, '```')
  }
  return redactSecrets(lines.join('\n'))
}
