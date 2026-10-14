// Тонкая обёртка над JSON API бэкенда.
const BASE = '/api'
const TOKEN_KEY = 'lt_token'

// Bearer-токен хранится в localStorage, чтобы сессия переживала перезагрузку.
// Параллельно бэкенд ставит httpOnly-куку lt_session, так что всё работает даже
// если localStorage недоступен (приватный режим).
let token = null
try { token = localStorage.getItem(TOKEN_KEY) || null } catch (e) { token = null }

export function getToken() { return token }

export function setToken(t) {
  token = t || null
  try {
    if (t) localStorage.setItem(TOKEN_KEY, t)
    else localStorage.removeItem(TOKEN_KEY)
  } catch (e) { /* localStorage может быть недоступен */ }
}

async function req(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) }
  if (token) headers.Authorization = 'Bearer ' + token
  const res = await fetch(BASE + path, {
    credentials: 'same-origin',
    ...opts,
    headers
  })
  if (!res.ok) {
    let msg = res.statusText
    try { msg = (await res.json()).error || msg } catch (e) { /* ignore */ }
    const err = new Error(msg)
    err.status = res.status
    throw err
  }
  const ct = res.headers.get('content-type') || ''
  return ct.includes('application/json') ? res.json() : res.text()
}

export const api = {
  tree: () => req('/tree'),
  lesson: (id) => req('/lessons/' + encodeURIComponent(id)),
  lab: (id) => req('/labs/' + encodeURIComponent(id)),
  lessons: () => req('/lessons'),
  search: (q) => req('/search?q=' + encodeURIComponent(q)),
  meta: () => req('/meta'),
  progress: () => req('/progress'),
  section: (body) => req('/progress/section', { method: 'POST', body: JSON.stringify(body) }),
  quiz: (body) => req('/progress/quiz', { method: 'POST', body: JSON.stringify(body) }),
  complete: (lesson_id, completed = true) => req('/progress/complete', { method: 'POST', body: JSON.stringify({ lesson_id, completed }) }),
  notes: (lesson_id, text) => req('/notes', { method: 'POST', body: JSON.stringify({ lesson_id, text }) }),
  exportProgress: () => req('/export'),
  importProgress: (data) => req('/import', { method: 'POST', body: JSON.stringify(data) }),
  // --- аккаунты -----------------------------------------------------------
  authMe: () => req('/auth/me'),
  register: (username, password) => req('/auth/register', { method: 'POST', body: JSON.stringify({ username, password }) }),
  login: (username, password) => req('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  logout: () => req('/auth/logout', { method: 'POST' })
}
