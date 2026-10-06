/**
 * Typed-ish wrappers around the LocalCA API. Keeping the paths in one module
 * means components never build URLs by hand.
 */
import { download, request } from './client'

export const session = {
  /** Current session, and plants the CSRF cookie. */
  get: () => request('/api/session/'),
  login: (username, password) =>
    request('/api/login/', { method: 'POST', body: { username, password } }),
  logout: () => request('/api/logout/', { method: 'POST' }),
  changePassword: (payload) => request('/api/password/', { method: 'POST', body: payload }),
}

export const meta = {
  get: () => request('/api/meta/'),
}

/**
 * The keystore: named credentials, each a password wrapping one root key.
 *
 * A private key names the credential that wraps it, so "which password?" has an
 * answer that is not "the account's". Passwords are sent once per unlock and are
 * never stored by the client.
 */
export const keystore = {
  get: () => request('/api/keystore/'),
  create: (name, vaultPassword, { encryptExisting = true } = {}) =>
    request('/api/keystore/credentials/', {
      method: 'POST',
      body: {
        name,
        vault_password: vaultPassword,
        encrypt_existing: encryptExisting ? 'true' : 'false',
      },
    }),
  unlock: (id, vaultPassword) =>
    request(`/api/keystore/credentials/${id}/unlock/`, {
      method: 'POST',
      body: { vault_password: vaultPassword },
    }),
  lock: (id) => request(`/api/keystore/credentials/${id}/lock/`, { method: 'POST' }),
  lockAll: () => request('/api/keystore/lock/', { method: 'POST' }),
  changePassword: (id, oldPassword, newPassword) =>
    request(`/api/keystore/credentials/${id}/password/`, {
      method: 'POST',
      body: { old_password: oldPassword, new_password: newPassword },
    }),
  rename: (id, name) =>
    request(`/api/keystore/credentials/${id}/rename/`, { method: 'POST', body: { name } }),
  setDefault: (id) =>
    request(`/api/keystore/credentials/${id}/default/`, { method: 'POST' }),
  remove: (id) =>
    request(`/api/keystore/credentials/${id}/delete/`, { method: 'POST' }),
  /** Encrypt one certificate's key with a credential, or move it to another. */
  assign: (credentialId, kind, id) =>
    request('/api/keystore/assign/', {
      method: 'POST',
      body: { credential_id: credentialId, kind, id },
    }),
}

export const certificates = {
  tree: () => request('/api/certificates/'),
  mine: () => request('/api/certificates/mine/'),
  issuers: () => request('/api/issuers/'),
  create: (kind, payload) =>
    request(`/api/certificates/create/${kind}/`, { method: 'POST', body: payload }),
  revoke: (kind, id, payload) =>
    request(`/api/certificates/${kind}/${id}/revoke/`, { method: 'POST', body: payload }),
  remove: (kind, id) =>
    request(`/api/certificates/${kind}/${id}/delete/`, { method: 'POST' }),
}

export const files = {
  /**
   * Download one format of a certificate.
   *
   * One function for every format, public or private, because the server owns
   * the list and the rules (`/api/meta/` -> `download_formats`); the client only
   * decides *which* one the operator asked for.
   *
   * `body` carries whatever that format needs: an export password for the
   * encrypted ones, or `confirm` for the unprotected ones. A GET means no body
   * went with it, which is exactly how the public formats are fetched.
   */
  format: (serial, format, fallbackName, body) => (
    body
      ? download(`/api/download/${serial}/${format}/`, fallbackName, body)
      : download(`/api/download/${serial}/${format}/`, fallbackName)
  ),
}

export const audit = {
  list: (limit = 100) => request(`/api/audit/?limit=${limit}`),
}

/**
 * Certificate import.
 *
 * Two steps against the same endpoint: `analyze` uploads the files and gets a
 * plan back (nothing is written), `commit` uploads the same files again to apply
 * it. Re-uploading rather than staging the upload server-side means no key
 * material is kept between the two calls.
 */
function importBody(files, { password, overrides, dryRun } = {}) {
  const body = new FormData()
  for (const file of files) {
    body.append('files', file)
  }
  if (password) {
    body.append('password', password)
  }
  if (overrides && Object.keys(overrides).length) {
    body.append('overrides', JSON.stringify(overrides))
  }
  body.append('dry_run', dryRun ? '1' : '0')
  return body
}

export const imports = {
  analyze: (files, options) =>
    request('/api/import/', { method: 'POST', body: importBody(files, { ...options, dryRun: true }) }),
  commit: (files, options) =>
    request('/api/import/', { method: 'POST', body: importBody(files, { ...options, dryRun: false }) }),
}
