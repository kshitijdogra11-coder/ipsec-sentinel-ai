// Minimal API client. Auth rides on an HttpOnly SameSite=Strict cookie set by the
// backend; every request carries the anti-CSRF header the backend requires.
const BASE = '/api/v1'

export class ApiError extends Error {
  constructor(status, detail) {
    super(typeof detail === 'string' ? detail : 'Request failed')
    this.status = status
    this.detail = detail
  }
}

let onUnauthorized = () => {}
export const setUnauthorizedHandler = (fn) => { onUnauthorized = fn }

async function request(path, { method = 'GET', body, form, raw } = {}) {
  const headers = { 'X-Requested-With': 'IPsecSentinel' }
  let payload
  if (form) payload = form
  else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body) }
  const res = await fetch(BASE + path, { method, headers, body: payload, credentials: 'same-origin' })
  if (res.status === 401 && !path.startsWith('/auth/login')) onUnauthorized()
  if (!res.ok) {
    let detail = res.statusText
    try { const j = await res.json(); detail = j.detail || detail; if (j.errors) detail += ': ' + j.errors.map(e => `${e.field} ${e.msg}`).join('; ') } catch { /* ignore */ }
    throw new ApiError(res.status, detail)
  }
  if (raw) return res
  const ct = res.headers.get('content-type') || ''
  return ct.includes('application/json') ? res.json() : res.text()
}

export const api = {
  login: (username, password) => request('/auth/login', { method: 'POST', body: { username, password } }),
  logout: () => request('/auth/logout', { method: 'POST' }),
  me: () => request('/auth/me'),
  changePassword: (current_password, new_password) => request('/auth/change-password', { method: 'POST', body: { current_password, new_password } }),
  stats: () => request('/stats'),
  analyses: () => request('/analyses'),
  analysis: (id) => request(`/analyses/${id}`),
  deleteAnalysis: (id) => request(`/analyses/${id}`, { method: 'DELETE' }),
  upload: (file) => { const f = new FormData(); f.append('file', file); return request('/analyses', { method: 'POST', form: f }) },
  presets: () => request('/testbed/presets'),
  generate: (cfg) => request('/testbed/generate', { method: 'POST', body: cfg }),
  model: () => request('/model'),
  dataset: () => request('/dataset'),
  users: () => request('/users'),
  createUser: (u) => request('/users', { method: 'POST', body: u }),
  patchUser: (id, p) => request(`/users/${id}`, { method: 'PATCH', body: p }),
  unlockUser: (id) => request(`/users/${id}/unlock`, { method: 'POST' }),
  deleteUser: (id) => request(`/users/${id}`, { method: 'DELETE' }),
  audit: () => request('/audit?limit=300'),
  verifyAudit: () => request('/audit/verify'),
  download: async (path, filename) => {
    const res = await request(path, { raw: true })
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 2000)
  },
}
