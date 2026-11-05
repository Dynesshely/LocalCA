/**
 * Certificates and audit entries share one date shape: `yyyy-MM-dd`.
 *
 * Built from the reader's local calendar parts rather than sliced out of the ISO
 * string, because an expiry is a moment: slicing would print the UTC date, which
 * is a day off for anyone far enough east or west of it. The format itself is
 * deliberately locale-independent — an operator comparing a certificate against a
 * log line or a config wants the same digits in both.
 */
const pad = (value) => String(value).padStart(2, '0')

function toDate(value) {
  if (!value) {
    return null
  }
  const date = value instanceof Date ? value : new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

/** `yyyy-MM-dd`, or `-` when there is no usable value. */
export function formatDate(value) {
  const date = toDate(value)
  if (!date) {
    return '-'
  }
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`
}

/** `yyyy-MM-dd HH:mm:ss`, for entries where the time of day matters. */
export function formatDateTime(value) {
  const date = toDate(value)
  if (!date) {
    return '-'
  }
  const time = `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
  return `${formatDate(date)} ${time}`
}
