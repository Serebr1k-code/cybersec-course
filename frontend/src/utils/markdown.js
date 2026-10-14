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

// --- Маркер встраивания лаборатории -----------------------------------------
// Урок с блоком `lab:` может пометить ТОЧНОЕ место в теле, где нужно показать
// интерактивный терминал (вместо панели внизу). Поддерживаются две записи в
// любом месте текста:
//
//     <!-- lab -->         HTML-комментарий (не виден в отрендеренном тексте)
//     ```lab ... ```       огороженный блок с информационной строкой `lab`
//
// Терминал ставится только по ПЕРВОМУ маркеру; остальные маркеры вырезаются,
// чтобы в текст не попал «сырой» маркер.
const LAB_MARKER_RES = [
  /^[ \t]*```[ \t]*lab[ \t]*\r?\n[\s\S]*?^[ \t]*```[ \t]*$/m, // ```lab \n ... \n ```
  /```[ \t]*lab[ \t]*```/i,                                    // однострочный ```lab```
  /<!--[ \t]*lab[ \t]*-->/i,                                   // <!-- lab -->
]

// findLabMarker(md) → { found, before, after }. Возвращает текст ДО и ПОСЛЕ
// первого маркера, чтобы отрендерить обе половины секции вокруг терминала.
export function findLabMarker(md) {
  const src = md || ''
  let best = null
  for (const re of LAB_MARKER_RES) {
    const m = re.exec(src)
    if (m && (best === null || m.index < best.index)) best = m
  }
  if (!best) return { found: false, before: src, after: '' }
  return { found: true, before: src.slice(0, best.index), after: src.slice(best.index + best[0].length) }
}

export function hasLabMarker(md) { return findLabMarker(md).found }

// Глобальная версия тех же шаблонов — вырезает ВСЕ маркеры из текста.
const LAB_ANY_RE = new RegExp(
  [
    '^[ \\t]*```[ \\t]*lab[ \\t]*\\r?\\n[\\s\\S]*?^[ \\t]*```[ \\t]*$',
    '```[ \\t]*lab[ \\t]*```',
    '<!--[ \\t]*lab[ \\t]*-->',
  ].join('|'),
  'gim'
)

export function stripLabMarkers(md) { return (md || '').replace(LAB_ANY_RE, '') }
