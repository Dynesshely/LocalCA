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
 * Private keys are encrypted at rest, so using one requires the vault to be open.
 * The password is sent once per unlock and is never stored by the client.
 */
export const vault = {
  status: () => request('/api/vault/status/'),
  unseal: (vaultPassword) =>
    request('/api/vault/unseal/', {
      method: 'POST',
      body: { vault_password: vaultPassword },
    }),
  lock: () => request('/api/vault/lock/', { method: 'POST' }),
  rotate: (oldPassword, newPassword) =>
    request('/api/vault/password/', {
      method: 'POST',
      body: { old_password: oldPassword, new_password: newPassword },
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
  /** Public certificate, or a leaf's chain. Needs no vault. */
  publicPem: (serial, name) => download(`/api/download/${serial}/pem/`, `${name}.pem`),

  /**
   * Password-protected PKCS12 export.
   *
   * This is the only way a private key leaves the system: the server requires an
   * export password and will not emit an unencrypted bundle. There is
   * deliberately no plaintext private key download.
   */
  pkcs12: (serial, name, password) => {
    const body = new FormData()
    body.append('p12_password', password)
    return download(`/api/download/${serial}/pkcs12/`, `${name}.p12`, body)
  },
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
