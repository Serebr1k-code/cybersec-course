import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { renderMarkdown, highlightAll, findLabMarker, hasLabMarker, stripLabMarkers } from './markdown'

describe('utils/markdown – renderMarkdown', () => {
  it('renders plain markdown to HTML', () => {
    const html = renderMarkdown('# Title\n\nsome **bold** text')
    expect(html).toContain('<h1')
    expect(html).toContain('Title')
    expect(html).toContain('<strong>bold</strong>')
  })

  it('keeps fenced code blocks and language class', () => {
    const html = renderMarkdown('```js\nconst a = 1\n```')
    expect(html).toContain('<pre>')
    expect(html).toContain('<code')
    expect(html).toContain('const a = 1')
  })

  it('strips <script> tags (DOMPurify)', () => {
    const html = renderMarkdown('<script>alert(1)</script>')
    expect(html.toLowerCase()).not.toContain('<script')
    expect(html).not.toContain('alert(1)')
  })

  it('strips inline event handlers (onerror/onclick)', () => {
    const html = renderMarkdown('<img src=x onerror="alert(1)">')
    expect(html.toLowerCase()).not.toContain('onerror')
    expect(html).not.toContain('alert(1)')
  })

  it('strips javascript: URLs', () => {
    const html = renderMarkdown('[click](javascript:alert(1))')
    expect(html.toLowerCase()).not.toContain('javascript:')
  })

  it('strips iframe / object / embed', () => {
    const html = renderMarkdown('<iframe src="http://evil"></iframe><object data="x"></object>')
    expect(html.toLowerCase()).not.toContain('<iframe')
    expect(html.toLowerCase()).not.toContain('<object')
  })

  it('keeps target and rel attributes (ADD_ATTR allowlist)', () => {
    const html = renderMarkdown('<a href="https://example.com" target="_blank" rel="noopener">x</a>')
    expect(html).toContain('href="https://example.com"')
    expect(html).toContain('target="_blank"')
    expect(html).toContain('rel="noopener"')
  })

  it('handles empty / null / undefined input without throwing', () => {
    expect(renderMarkdown('')).toBe('')
    expect(renderMarkdown(null)).toBe('')
    expect(renderMarkdown(undefined)).toBe('')
  })

  it('escapes raw inline HTML instead of injecting it', () => {
    const html = renderMarkdown('hello <svg/onload=alert(1)> world')
    expect(html).not.toContain('<svg')
    expect(html).toContain('&lt;svg')
  })
})

describe('utils/markdown – inline lab marker', () => {
  it('detects an HTML-comment marker and splits the text around it', () => {
    const r = findLabMarker('до маркера\n\n<!-- lab -->\n\nпосле маркера')
    expect(r.found).toBe(true)
    expect(r.before).toContain('до маркера')
    expect(r.before).not.toContain('lab')
    expect(r.after).toContain('после маркера')
  })

  it('detects a fenced ```lab block (content ignored)', () => {
    const md = 'текст\n\n```lab\nчто угодно\n```\n\nдальше'
    const r = findLabMarker(md)
    expect(r.found).toBe(true)
    expect(r.before.trim()).toBe('текст')
    expect(r.after.trim()).toBe('дальше')
  })

  it('detects a one-line ```lab``` fence', () => {
    expect(findLabMarker('a\n```lab```\nb').found).toBe(true)
  })

  it('is case-insensitive for the comment marker', () => {
    expect(findLabMarker('x <!-- LAB --> y').found).toBe(true)
  })

  it('reports no marker when the text has none', () => {
    expect(hasLabMarker('обычный текст без маркера')).toBe(false)
    expect(findLabMarker('обычный текст').before).toBe('обычный текст')
    expect(findLabMarker('').found).toBe(false)
    expect(findLabMarker(null).found).toBe(false)
  })

  it('does not confuse a normal code block for a marker', () => {
    expect(hasLabMarker('```bash\nls -la\n```')).toBe(false)
  })

  it('stripLabMarkers removes every marker but keeps surrounding text', () => {
    const md = 'A\n\n<!-- lab -->\n\nB\n\n```lab\nx\n```\n\nC\n\n```lab```\n\nD'
    const out = stripLabMarkers(md)
    expect(out).toContain('A')
    expect(out).toContain('B')
    expect(out).toContain('C')
    expect(out).toContain('D')
    expect(out.toLowerCase()).not.toContain('lab')
  })

  it('stripLabMarkers is a no-op without markers and on null', () => {
    expect(stripLabMarkers('просто текст')).toBe('просто текст')
    expect(stripLabMarkers(null)).toBe('')
  })

  it('the rendered comment marker is invisible (DOMPurify drops comments)', () => {
    expect(renderMarkdown('a <!-- lab --> b')).not.toContain('lab')
  })
})

describe('utils/markdown – highlightAll', () => {
  let root

  beforeEach(() => {
    root = document.createElement('div')
    document.body.appendChild(root)
  })

  afterEach(() => {
    root.remove()
  })

  it('marks rendered code blocks with data-hl="1"', () => {
    root.innerHTML = '<pre><code>const x = 1</code></pre>'
    highlightAll(root)
    const code = root.querySelector('pre code')
    expect(code.dataset.hl).toBe('1')
  })

  it('does not re-highlight an already highlighted block', () => {
    root.innerHTML = '<pre><code>const x = 1</code></pre>'
    const code = root.querySelector('pre code')
    code.dataset.hl = '1'
    // Spy on the innerHTML class additions: a second pass must leave it untouched.
    const before = code.className
    highlightAll(root)
    expect(code.dataset.hl).toBe('1')
    expect(code.className).toBe(before)
  })

  it('handles a null root gracefully', () => {
    expect(() => highlightAll(null)).not.toThrow()
    expect(highlightAll(null)).toBeUndefined()
  })

  it('ignores a root without code blocks', () => {
    root.innerHTML = '<p>no code here</p>'
    expect(() => highlightAll(root)).not.toThrow()
  })
})
