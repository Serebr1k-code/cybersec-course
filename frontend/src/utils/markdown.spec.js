import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { renderMarkdown, highlightAll } from './markdown'

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
