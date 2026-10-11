import { marked } from 'marked'
import DOMPurify from 'dompurify'
import hljs from 'highlight.js'

marked.setOptions({ gfm: true, breaks: false, headerIds: false, mangle: false })

export function renderMarkdown(md) {
  const html = marked.parse(md || '')
  return DOMPurify.sanitize(html, { ADD_ATTR: ['target', 'rel'] })
}

// Подсветка синтаксиса для уже отрендеренных <pre><code>.
export function highlightAll(root) {
  if (!root) return
  root.querySelectorAll('pre code').forEach((el) => {
    if (el.dataset.hl === '1') return
    try { hljs.highlightElement(el); el.dataset.hl = '1' } catch (e) { /* ignore */ }
  })
}
