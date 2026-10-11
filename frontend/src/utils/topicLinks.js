// ============================================================
// Smart cross-links between lessons.
//
// Given the flat list of tree nodes (each: id, title, tags, parent,
// estimated_minutes, depth) this module can:
//   1. buildAliasIndex()  — map a prose mention ("host header",
//      "XSS", "SQL-инъекции", "ssrf", …) to the lesson that covers it,
//      derived from tags, the id slug and the title (no backend change);
//   2. linkTopics()       — post-process a rendered markdown DOM subtree
//      and wrap the FIRST mention of each distinct target in an
//      <a class="topic-link"> (skipping code, links and headings);
//   3. shortestPath()     — the shortest path (via lowest common ancestor)
//      from the current lesson to the target, with a lesson count + time.
// ============================================================

// Mentions shorter than this are too noisy (e.g. "xss", "api", "jwt").
const MIN_ALIAS_LEN = 4

// Alias source weights: an id-slug is the strongest signal (it is unique by
// construction), a title is specific, a tag is the weakest (tags are shared
// across many lessons, so a tag-only alias that collides is dropped).
const W_ID = 3
const W_TITLE = 2
const W_TAG = 1

// Tags / headings / existing links inside which we must never inject a link.
const SKIP_TAGS = new Set([
  'PRE', 'CODE', 'A', 'SCRIPT', 'STYLE', 'BUTTON', 'TEXTAREA', 'SVG',
  'H1', 'H2', 'H3', 'H4', 'H5', 'H6'
])

const escapeRegExp = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

// Lowercase, and turn every run of non-letter/non-digit chars (hyphen,
// underscore, dot, slash…) into a single space. Unicode-aware, so Cyrillic
// aliases survive.
export function normalizeAlias(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .trim()
}

// 'web-host-header' -> 'host header' (drop the leading category segment).
function slugAlias(id) {
  const parts = String(id).split('-').filter(Boolean)
  const rest = parts.length > 1 ? parts.slice(1) : parts
  return rest.join(' ')
}

// A whole-word, separator-tolerant regex for one alias: 'host header' matches
// "host header", "Host-Header", "HOST_HEADER" and "host   header", but not
// "hostheader" or "myhost header".
function aliasRegex(alias) {
  const words = alias.split(' ').filter(Boolean).map(escapeRegExp)
  return new RegExp(
    '(?<![\\p{L}\\p{N}])' + words.join('[\\s\\-_]+') + '(?![\\p{L}\\p{N}])',
    'giu'
  )
}

// Build the alias -> target-lesson index from the flat node list.
// Returns { aliases: [{ alias, targetId, re, firstWord }] } sorted longest
// alias first. targetId is null when the alias is ambiguous (several lessons
// claim it with the same weight) — we then refuse to link it rather than
// guess a wrong target.
export function buildAliasIndex(nodes) {
  const claims = new Map() // alias -> Map(lessonId -> weight)

  const claim = (rawAlias, id, weight) => {
    const alias = normalizeAlias(rawAlias)
    if (alias.length < MIN_ALIAS_LEN) return
    let byId = claims.get(alias)
    if (!byId) { byId = new Map(); claims.set(alias, byId) }
    byId.set(id, Math.max(byId.get(id) || 0, weight))
  }

  // Whole-word test against an already-normalized string.
  const wordInText = (word, text) => {
    if (!text) return false
    return new RegExp(
      '(?<![\\p{L}\\p{N}])' + escapeRegExp(word) + '(?![\\p{L}\\p{N}])', 'iu'
    ).test(text)
  }

  for (const n of nodes || []) {
    if (!n || !n.id) continue
    const title = normalizeAlias(n.title)
    const slug = normalizeAlias(slugAlias(n.id))
    // A single-word id slug must actually NAME the lesson (appear in its
    // title); otherwise generic slugs like 'stego-network' -> 'network' would
    // hijack unrelated prose. Multi-word slugs ('host header') are specific
    // enough on their own.
    if (slug.length >= MIN_ALIAS_LEN && (slug.includes(' ') || wordInText(slug, title))) {
      claim(slug, n.id, W_ID)
    }
    if (title) claim(title, n.id, W_TITLE)
    const rawTitle = n.title || ''
    const colon = rawTitle.indexOf(':')
    if (colon > 0) claim(rawTitle.slice(0, colon), n.id, W_TITLE)
    for (const t of n.tags || []) {
      // Single-word tags are too generic to auto-link ("header", "html",
      // "delete"); only multi-word tags ("host-header", "open-redirect") are
      // specific enough to be trusted.
      if (normalizeAlias(t).includes(' ')) claim(t, n.id, W_TAG)
    }
  }

  const aliases = []
  for (const [alias, byId] of claims) {
    let bestId = null
    let bestW = -1
    let tie = false
    for (const [id, w] of byId) {
      if (w > bestW) { bestW = w; bestId = id; tie = false }
      else if (w === bestW) tie = true
    }
    aliases.push({
      alias,
      targetId: tie ? null : bestId,
      re: aliasRegex(alias),
      firstWord: alias.split(' ')[0]
    })
  }
  aliases.sort((a, b) => b.alias.length - a.alias.length)
  return { aliases }
}

// Find the best match for `text`: earliest match wins; at equal position the
// longer alias wins (so "host header" beats a hypothetical "host").
function findBestMatch(text, entries, currentId, linked) {
  const lower = text.toLowerCase()
  let best = null
  for (const e of entries) {
    if (!e.targetId || e.targetId === currentId || linked.has(e.targetId)) continue
    if (!lower.includes(e.firstWord)) continue
    e.re.lastIndex = 0
    const m = e.re.exec(text)
    if (!m) continue
    if (!best || m.index < best.index || (m.index === best.index && m[0].length > best.len)) {
      best = { index: m.index, len: m[0].length, text: m[0], targetId: e.targetId }
    }
  }
  return best
}

// Walk the text nodes of a rendered-markdown element and wrap the first
// mention of each distinct target lesson in an <a class="topic-link">.
// Mutates the DOM in place; returns the number of links created.
// `linked` may be shared across the several .md sections of one lesson so a
// target is linked only once per LESSON (not once per section).
export function linkTopics(root, { index, currentId, byId, linked: shared } = {}) {
  if (!root || !index || !index.aliases) return 0
  const linked = shared || new Set()
  let count = 0

  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      if (!node.nodeValue || !node.nodeValue.trim()) return NodeFilter.FILTER_REJECT
      for (let p = node.parentNode; p && p !== root; p = p.parentNode) {
        if (SKIP_TAGS.has(p.nodeName)) return NodeFilter.FILTER_REJECT
      }
      return NodeFilter.FILTER_ACCEPT
    }
  })

  const textNodes = []
  while (walker.nextNode()) textNodes.push(walker.currentNode)

  for (const node of textNodes) {
    let cur = node
    let guard = 0
    while (cur && cur.nodeValue && guard++ < 100) {
      const best = findBestMatch(cur.nodeValue, index.aliases, currentId, linked)
      if (!best) break
      const parent = cur.parentNode
      if (!parent) break
      const value = cur.nodeValue
      const a = document.createElement('a')
      a.className = 'topic-link'
      a.setAttribute('href', '/lesson/' + best.targetId)
      a.setAttribute('data-topic-id', best.targetId)
      a.textContent = best.text
      const before = value.slice(0, best.index)
      const afterNode = document.createTextNode(value.slice(best.index + best.len))
      if (before) parent.insertBefore(document.createTextNode(before), cur)
      parent.insertBefore(a, cur)
      parent.insertBefore(afterNode, cur)
      parent.removeChild(cur)
      linked.add(best.targetId)
      count++
      cur = afterNode
    }
  }
  return count
}

// Ancestor chain of a node, from the node itself up to the root.
function ancestorChain(id, byId) {
  const chain = []
  let cur = byId[id]
  let guard = 0
  while (cur && guard++ < 200) {
    chain.push(cur)
    cur = cur.parent ? byId[cur.parent] : null
  }
  return chain
}

// Shortest path from `fromId` to `toId` through their lowest common ancestor.
// Returns { nodes, hops, minutes, disconnected } where `nodes` runs from the
// current lesson to the target inclusive, `hops` is the number of edges
// ("N уроков") and `minutes` sums estimated_minutes of everything to traverse
// (excluding the current lesson). If the two lessons share no ancestor the
// path cannot be built -> { nodes: [], disconnected: true }.
export function shortestPath(fromId, toId, byId) {
  if (!byId || !byId[fromId] || !byId[toId]) return null
  if (fromId === toId) return { nodes: [byId[fromId]], hops: 0, minutes: 0, disconnected: false }

  const aChain = ancestorChain(fromId, byId) // from .. root
  const bChain = ancestorChain(toId, byId)   // to   .. root
  const bPos = new Map(bChain.map((n, i) => [n.id, i]))

  let lcaIdx = -1
  let bIdx = -1
  for (let i = 0; i < aChain.length; i++) {
    if (bPos.has(aChain[i].id)) { lcaIdx = i; bIdx = bPos.get(aChain[i].id); break }
  }
  if (lcaIdx < 0) return { nodes: [], hops: null, minutes: null, disconnected: true }

  const up = aChain.slice(0, lcaIdx + 1)               // from .. lca
  const down = bChain.slice(0, bIdx).reverse()         // child-of-lca .. to
  const nodes = up.concat(down)
  const hops = nodes.length - 1
  const minutes = nodes.slice(1).reduce((sum, n) => sum + (n.estimated_minutes || 0), 0)
  return { nodes, hops, minutes, disconnected: false }
}
