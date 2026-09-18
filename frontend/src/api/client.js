/**
 * Thin fetch wrapper for the LocalCA API.
 *
 * Authentication is Django's session cookie plus a CSRF token. The cookie is
 * planted by the SPA shell on load; every state-changing request echoes it back
 * in the X-CSRFToken header, which is what Django's CSRF middleware expects for
 * same-origin fetch calls.
 */

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE'])

function readCookie(name) {
  const match = document.cookie.match(new RegExp('(^|;\\s*)' + name + '=([^;]*)'))
  return match ? decodeURIComponent(match[2]) : null
}

/** Raised for any non-2xx API response, carrying the parsed payload. */
export class ApiError extends Error {
  constructor(message, { status, payload } = {}) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.payload = payload || {}
    this.errors = this.payload.errors || []
  }
}

async function parse(response) {
  const type = response.headers.get('content-type') || ''
  if (type.includes('application/json')) {
    try {
      return await response.json()
    } catch (err) {
      return null
    }
  }
  return await response.text()
}

/**
 * Perform an API request.
 *
 * @param {string} path      API path, e.g. '/api/certificates/'
 * @param {object} [options]
 * @param {string} [options.method]
 * @param {object|FormData} [options.body]  Plain objects are sent as JSON
 * @returns {Promise<any>}   The parsed JSON payload
 * @throws {ApiError}
 */
export async function request(path, options = {}) {
  const method = (options.method || 'GET').toUpperCase()
  const init = {
    method,
    credentials: 'same-origin',
    headers: { Accept: 'application/json', ...(options.headers || {}) },
  }

  if (options.body !== undefined && options.body !== null) {
    if (options.body instanceof FormData) {
      // Let the browser set the multipart boundary.
      init.body = options.body
    } else {
      init.headers['Content-Type'] = 'application/json'
      init.body = JSON.stringify(options.body)
    }
  }

  if (!SAFE_METHODS.has(method)) {
    const token = readCookie('csrftoken')
    if (token) {
      init.headers['X-CSRFToken'] = token
    }
  }

  const response = await fetch(path, init)
  const payload = await parse(response)

  if (!response.ok) {
    const message = (payload && (payload.errors?.[0] || payload.detail || payload.message))
      || `Request failed with status ${response.status}`
    throw new ApiError(message, { status: response.status, payload })
  }
  return payload
}

/**
 * Download a file from an endpoint that streams bytes (certificates, keys,
 * PKCS12). Kept separate from `request` because the response is not JSON.
 *
 * @param {string} path
 * @param {string} fallbackName  Used when the server sends no filename
 * @param {FormData} [body]
 */
export async function download(path, fallbackName = 'download', body) {
  const init = { method: body ? 'POST' : 'GET', credentials: 'same-origin' }
  if (body) {
    init.body = body
    const token = readCookie('csrftoken')
    if (token) {
      init.headers = { 'X-CSRFToken': token }
    }
  }

  const response = await fetch(path, init)
  if (!response.ok) {
    let payload = null
    try {
      payload = await response.json()
    } catch (err) {
      payload = null
    }
    const message = (payload && (payload.errors?.[0] || payload.detail))
      || `Download failed with status ${response.status}`
    throw new ApiError(message, { status: response.status, payload })
  }

  const blob = await response.blob()
  const disposition = response.headers.get('content-disposition') || ''
  let filename = fallbackName
  const utf8 = disposition.match(/filename\*=UTF-8''([^;]+)/i)
  const ascii = disposition.match(/filename="?([^";]+)"?/i)
  if (utf8) {
    filename = decodeURIComponent(utf8[1])
  } else if (ascii) {
    filename = ascii[1]
  }

  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
  return filename
}
