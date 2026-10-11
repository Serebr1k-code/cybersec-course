import { describe, it, expect } from 'vitest'
import { normalizeAlias, buildAliasIndex, linkTopics, shortestPath } from './topicLinks'

// A tiny slice of the real web tree, enough to exercise aliasing + paths.
const NODES = [
  { id: 'web-http-basics', title: 'Основы HTTP', parent: '', depth: 0, estimated_minutes: 25, tags: ['http', 'requests'] },
  { id: 'web-host-header', title: 'Host header и X-Forwarded атаки', parent: 'web-http-basics', depth: 1, estimated_minutes: 34, tags: ['host-header'] },
  { id: 'web-password-reset', title: 'Password reset', parent: 'web-host-header', depth: 2, estimated_minutes: 38, tags: ['host-header', 'password-reset'] },
  { id: 'web-request-smuggling', title: 'HTTP Request Smuggling', parent: 'web-host-header', depth: 2, estimated_minutes: 46, tags: ['http'] },
  { id: 'web-client-side-desync', title: 'Client-side desync', parent: 'web-request-smuggling', depth: 3, estimated_minutes: 44, tags: ['http'] },
  { id: 'web-ssrf', title: 'SSRF', parent: '', depth: 0, estimated_minutes: 42, tags: ['ssrf'] },
  // Two lessons sharing a multi-word tag -> 'race condition' is ambiguous.
  { id: 'web-race-conditions', title: 'Race conditions', parent: '', depth: 0, estimated_minutes: 38, tags: ['race-condition'] },
  { id: 'web-race-single-packet', title: 'Single-packet attack', parent: 'web-race-conditions', depth: 1, estimated_minutes: 42, tags: ['race-condition'] },
  // Slug 'stego-network' -> 'network', but the title never says "network" and
  // the tag is a single generic word -> must NOT be indexed.
  { id: 'stego-network', title: 'Стеганография в сетевых протоколах', parent: '', depth: 0, estimated_minutes: 40, tags: ['stego', 'network'] }
]
const BY_ID = Object.fromEntries(NODES.map((n) => [n.id, n]))

function resolve(alias, index) {
  const e = index.aliases.find((a) => a.alias === alias)
  return e ? e.targetId : undefined
}

describe('utils/topicLinks — normalizeAlias', () => {
  it('lowercases and turns separators into single spaces', () => {
    expect(normalizeAlias('Host-Header')).toBe('host header')
    expect(normalizeAlias('X-Forwarded_Host')).toBe('x forwarded host')
    expect(normalizeAlias('  SQL-инъекции  ')).toBe('sql инъекции')
  })
})

describe('utils/topicLinks — buildAliasIndex', () => {
  const index = buildAliasIndex(NODES)

  it('resolves an id-slug alias even when a weaker tag collides', () => {
    // 'host header' is claimed by web-host-header (id slug, w=3) and by the
    // host-header tag on two lessons (w=1) — the id slug must win.
    expect(resolve('host header', index)).toBe('web-host-header')
  })

  it('resolves a single-word id slug that names the lesson', () => {
    // web-ssrf's slug 'ssrf' appears in its title, so it is trusted.
    expect(resolve('ssrf', index)).toBe('web-ssrf')
  })

  it('resolves a multi-word tag alias', () => {
    expect(resolve('password reset', index)).toBe('web-password-reset')
  })

  it('drops an ambiguous alias (several lessons, same weight) instead of guessing', () => {
    // 'race condition' is a tag on two lessons, neither owning it as a slug.
    expect(resolve('race condition', index)).toBe(null)
  })

  it('never indexes a single generic word from a tag', () => {
    expect(resolve('http', index)).toBeUndefined()
    expect(resolve('header', index)).toBeUndefined()
    // The 'stego-network' slug would yield the bare word 'network' — gated out.
    expect(resolve('network', index)).toBeUndefined()
  })

  it('ignores aliases shorter than the minimum length', () => {
    expect(resolve('xss', index)).toBeUndefined()
  })
})

describe('utils/topicLinks — linkTopics', () => {
  const index = buildAliasIndex(NODES)

  function makeDom() {
    const root = document.createElement('div')
    root.innerHTML = [
      '<p>Дальше про host header injection и ещё раз про host header.</p>',
      '<p><code>host header</code> в инлайн-коде</p>',
      '<pre><code>host header</code></pre>',
      '<h2>host header в заголовке</h2>',
      '<p><a href="/x">host header в существующей ссылке</a></p>',
      '<p>А также SSRF тут.</p>'
    ].join('')
    return root
  }

  it('links only the FIRST occurrence per target and never inside code/links/headings', () => {
    const root = makeDom()
    const n = linkTopics(root, { index, currentId: 'web-http-basics', byId: BY_ID })
    expect(n).toBe(2) // one host header + one ssrf
    const links = root.querySelectorAll('.topic-link')
    expect(links.length).toBe(2)

    const hh = root.querySelector('.topic-link[data-topic-id="web-host-header"]')
    expect(hh).not.toBeNull()
    expect(hh.textContent).toBe('host header')
    expect(hh.getAttribute('href')).toBe('/lesson/web-host-header')

    // The inline code, pre block, heading and existing anchor are untouched.
    expect(root.querySelector('code').querySelector('.topic-link')).toBeNull()
    expect(root.querySelector('pre').querySelector('.topic-link')).toBeNull()
    expect(root.querySelector('h2').querySelector('.topic-link')).toBeNull()
    expect(root.querySelector('a[href="/x"]').querySelector('.topic-link')).toBeNull()

    // The second prose mention was NOT wrapped again (one link per target).
    const firstP = root.querySelector('p')
    expect(firstP.querySelectorAll('.topic-link').length).toBe(1)
    expect(firstP.textContent).toBe('Дальше про host header injection и ещё раз про host header.')
  })

  it('does not link a lesson to itself', () => {
    const root = makeDom()
    linkTopics(root, { index, currentId: 'web-host-header', byId: BY_ID })
    expect(root.querySelector('.topic-link[data-topic-id="web-host-header"]')).toBeNull()
    // A different target is still linked.
    expect(root.querySelector('.topic-link[data-topic-id="web-ssrf"]')).not.toBeNull()
  })

  it('links a target only once per lesson when the set is shared across sections', () => {
    const root = document.createElement('div')
    root.innerHTML = [
      '<div class="md">про host header тут</div>',
      '<div class="md">и снова host header здесь</div>'
    ].join('')
    const linked = new Set()
    const a = linkTopics(root.children[0], { index, currentId: 'web-http-basics', byId: BY_ID, linked })
    const b = linkTopics(root.children[1], { index, currentId: 'web-http-basics', byId: BY_ID, linked })
    expect(a).toBe(1)
    expect(b).toBe(0)
    expect(root.querySelectorAll('.topic-link').length).toBe(1)
  })

  it('is a no-op without an index', () => {
    const root = makeDom()
    expect(linkTopics(root, { currentId: 'web-http-basics' })).toBe(0)
    expect(root.querySelectorAll('.topic-link').length).toBe(0)
  })
})

describe('utils/topicLinks — shortestPath', () => {
  it('direct parent -> child', () => {
    const p = shortestPath('web-http-basics', 'web-host-header', BY_ID)
    expect(p.nodes.map((n) => n.id)).toEqual(['web-http-basics', 'web-host-header'])
    expect(p.hops).toBe(1)
    expect(p.minutes).toBe(34) // excludes the current lesson
    expect(p.disconnected).toBe(false)
  })

  it('siblings go up to the LCA and back down', () => {
    const p = shortestPath('web-password-reset', 'web-request-smuggling', BY_ID)
    expect(p.nodes.map((n) => n.id)).toEqual([
      'web-password-reset', 'web-host-header', 'web-request-smuggling'
    ])
    expect(p.hops).toBe(2)
    expect(p.minutes).toBe(34 + 46) // LCA + target, excludes current
  })

  it('returns 0 hops for the same lesson', () => {
    const p = shortestPath('web-ssrf', 'web-ssrf', BY_ID)
    expect(p.hops).toBe(0)
    expect(p.nodes.length).toBe(1)
  })

  it('flags disconnected lessons (no common ancestor)', () => {
    const p = shortestPath('web-http-basics', 'web-ssrf', BY_ID)
    expect(p.disconnected).toBe(true)
    expect(p.nodes).toEqual([])
  })

  it('returns null for unknown ids', () => {
    expect(shortestPath('nope', 'web-ssrf', BY_ID)).toBeNull()
  })
})
