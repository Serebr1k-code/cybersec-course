// Тонкая обёртка над JSON API бэкенда.
const BASE = '/api'

async function req(path, opts = {}) {
  const res = await fetch(BASE + path, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    ...opts
  })
  if (!res.ok) {
    let msg = res.statusText
    try { msg = (await res.json()).error || msg } catch (e) { /* ignore */ }
    throw new Error(msg)
  }
  const ct = res.headers.get('content-type') || ''
  return ct.includes('application/json') ? res.json() : res.text()
}

export const api = {
  tree: () => req('/tree'),
  lesson: (id) => req('/lessons/' + encodeURIComponent(id)),
  lessons: () => req('/lessons'),
  search: (q) => req('/search?q=' + encodeURIComponent(q)),
  meta: () => req('/meta'),
  progress: () => req('/progress'),
  section: (body) => req('/progress/section', { method: 'POST', body: JSON.stringify(body) }),
  quiz: (body) => req('/progress/quiz', { method: 'POST', body: JSON.stringify(body) }),
  complete: (lesson_id, completed = true) => req('/progress/complete', { method: 'POST', body: JSON.stringify({ lesson_id, completed }) }),
  notes: (lesson_id, text) => req('/notes', { method: 'POST', body: JSON.stringify({ lesson_id, text }) }),
  exportProgress: () => req('/export'),
  importProgress: (data) => req('/import', { method: 'POST', body: JSON.stringify(data) })
}
