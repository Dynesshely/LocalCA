/**
 * Typed-ish wrappers around the LocalCA API. Keeping the paths in one module
 * means the components never build URLs by hand.
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
  publicPem: (serial, name) => download(`/api/download/${serial}/pem/`, `${name}.pem`),
  privatePem: (serial, name) =>
    download(`/api/download/${serial}/private/`, `${name}_private.pem`),
  pkcs12: (serial, name, password) => {
    const body = new FormData()
    body.append('p12_password', password || '')
    return download(`/api/download/${serial}/pkcs12/`, `${name}.p12`, body)
  },
}

export const audit = {
  list: (limit = 100) => request(`/api/audit/?limit=${limit}`),
}
