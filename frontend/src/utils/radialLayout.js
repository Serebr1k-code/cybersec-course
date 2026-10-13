// Radial ("sunburst") HYBRID layout for one category of the learning tree.
//
// Two kinds of node are laid out side by side:
//   * a REAL LESSON renders as a WIDE TEXT CARD (CARD_W x radialCardHeight) —
//     the title is always visible, so the card needs room for its width along
//     the ring tangent and for its (content-driven) height across the rings;
//   * a HUB / CONNECTOR node (a module / roadmap index page) renders as a SMALL
//     CIRCLE (HUB_D px, no text) — it only needs a small square.
//
// Design goals
//   * the ROOT of the category sits at the CENTRE; every depth is a concentric
//     RING (radius grows with depth);
//   * a node's angular slot is proportional to its subtree size (leaf count),
//     but with a floor so that every node keeps enough arc for its own box — this
//     is what makes branches spread evenly and never overlap;
//   * every node reserves its REAL box (card rectangle or hub square) so the
//     layout can push a dense ring out until its boxes fit — never clipping,
//     never overlapping;
//   * text stays HORIZONTAL (cards are never rotated), so the ring radius must be
//     large enough for the card WIDTH along the tangent.
//
// The output is a pure data structure (positions + edges) so it is trivially
// unit-testable and free of DOM/canvas concerns.

import { nodeHeight } from './nodeLayout'

// ---- hub / connector detection --------------------------------------------
// A node is a HUB (module / roadmap / connector) — NOT a real lesson — when it
// is a module/roadmap index page. This mirrors the canonical detector used by
// the content tooling (`tools/thin-lessons.py:131-152` is_roadmap): the title
// starts with "Модуль:" OR the front-matter `tags` contain "roadmap". Both are
// exposed on every /api/tree node (internal/model/model.go:68-81), so the rule
// is computable from frontend-visible data alone. (The tool's third rule — a
// short, code-less body with a roadmap marker — needs the body, which the tree
// API does not ship, so it is intentionally not used here.)
export function isHubNode(node) {
  if (!node) return false
  const title = String(node.title || '')
  if (title.startsWith('Модуль:') || title.toLowerCase().includes('модуль:')) return true
  const tags = node.tags
  if (Array.isArray(tags)) return tags.some((t) => String(t).toLowerCase() === 'roadmap')
  return false
}

// ---- node geometry --------------------------------------------------------
// HUB / CONNECTOR nodes are minimal colourless bullets: no title text on the
// face, so the layout reserves a single small square per hub.
export const HUB_D = 18            // hub circle diameter (px) — fixed, keeps layout deterministic
export const NODE_D = HUB_D        // backwards-compatible alias for the small node size
export const NODE_R = HUB_D / 2    // hub circle radius (px)

// REAL LESSON nodes are text cards (LessonNode.vue). The card is deliberately
// SMALL and NEAT: the title is capped at 3 lines and the reserved height is
// ~40–62px. These values MUST match the rendered card so the layout reserves
// exactly what the card needs — never clipping, never overlapping.
export const CARD_W = 150          // node card width (fixed — keeps layout deterministic)
export const CARD_H = 44           // fallback card height (empty tree / missing title)
export const RADIAL_CONTENT_W = 126   // inner text width (150px card − 2×8px padding − 2px border, minus a little)
export const RADIAL_MAX_LINES = 3     // cap the title at 3 lines -> compact cards
export const RADIAL_FONT_SCALE = 11 / 13.5   // radial card title font (11px) vs the 224px node font
export const RADIAL_LINE_H = 13       // per-line title height (11px × 1.15 ≈ 12.65 → round up)
export const RADIAL_PAD = 10          // vertical padding (4px×2) + border (1px×2)
export const RADIAL_META_H = 13       // meta row: 2px gap + 11px star/duration row
export const RADIAL_MIN_H = 40        // compact floor for a one-line card

// Content-driven card height for the radial card (shared by the layout and the
// node component so the reserved height always matches the rendered card).
// 1 line -> 40px, 2 -> 49px, 3 -> 62px.
export function radialCardHeight(node) {
  return nodeHeight(node, {
    contentWidth: RADIAL_CONTENT_W,
    maxLines: RADIAL_MAX_LINES,
    scale: RADIAL_FONT_SCALE,
    pad: RADIAL_PAD,
    lineHeight: RADIAL_LINE_H,
    metaHeight: RADIAL_META_H,
    minHeight: RADIAL_MIN_H
  })
}

// Per-node reserved box: a hub is a small square, a lesson is a wide card.
export function nodeBox(node) {
  if (isHubNode(node)) return { w: HUB_D, h: HUB_D }
  return { w: CARD_W, h: radialCardHeight(node) }
}

export const GAP_X = 16            // minimum EDGE gap between neighbouring boxes on a ring
export const GAP_Y = 14            // minimum vertical gap between rings
export const RING_STEP = CARD_W + GAP_Y   // base radial distance between consecutive rings
export const MIN_SHARE = 0.9       // floor = MIN_SHARE * (even share) for the water-fill
export const START_ANGLE = -Math.PI / 2   // first DFS slot starts at the top
const VROOT = '__vroot__'          // key for "no parent" (multiple roots case)
const EPS = 1e-9

// Build parent -> children (sorted by order then title) and the root list.
function indexTree(nodes) {
  const byId = new Map()
  for (const n of nodes) byId.set(n.id, n)
  const children = new Map()
  for (const n of nodes) {
    const p = n.parent && byId.has(n.parent) ? n.parent : VROOT
    if (!children.has(p)) children.set(p, [])
    children.get(p).push(n)
  }
  for (const arr of children.values()) {
    arr.sort((a, b) => ((a.order ?? 0) - (b.order ?? 0)) || String(a.title || '').localeCompare(String(b.title || ''), 'ru'))
  }
  return { byId, children, roots: children.get(VROOT) || [] }
}

/**
 * Compute a radial layout for `nodes` (one category).
 * @param {Array} nodes  lesson nodes {id,title,parent,order,tags,...}
 * @param {Object} [opts]
 * @param {Set|Array} [opts.collapsed] ids whose subtree is collapsed (hidden)
 * @param {Set|Array|null} [opts.visible] allow-list of ids to render (progressive
 *   reveal / fog-of-war). Nodes outside the set are pruned like a collapse, but
 *   a node CAN be rendered while only SOME of its children are (unlike collapse,
 *   which hides all of them). `null` = everything is visible. The set must be
 *   ancestor-closed (every visible node's ancestors are visible) so edges stay
 *   connected — that holds for the progressive-reveal set built by TreeGraph.
 * @returns {{
 *   pos: Object<string,{x,y,left,top,depth,angle,r,w,h,hub}>,
 *   edges: Array<{id,from,to,d}>,
 *   parentOf: Object<string,string>,
 *   depth: Object<string,number>,
 *   order: string[],
 *   w:number, h:number, cx:number, cy:number, maxR:number, maxDepth:number,
 *   hasChildren: Object<string,boolean>
 * }}
 */
export function radialLayout(nodes, opts = {}) {
  const list = nodes || []
  const collapsed = opts.collapsed instanceof Set ? opts.collapsed : new Set(opts.collapsed || [])
  const visible = opts.visible == null
    ? null
    : (opts.visible instanceof Set ? opts.visible : new Set(opts.visible))
  const { byId, children, roots } = indexTree(list)

  const parentOf = {}
  const depth = {}
  const order = []
  const seen = new Set()
  const hasChildren = {}
  for (const n of list) hasChildren[n.id] = (children.get(n.id) || []).length > 0

  function dfs(node, d, parent) {
    if (seen.has(node.id)) return
    seen.add(node.id)
    order.push(node.id)
    depth[node.id] = d
    if (parent) parentOf[node.id] = parent
    if (collapsed.has(node.id)) return
    for (const c of children.get(node.id) || []) {
      if (visible && !visible.has(c.id)) continue
      dfs(c, d + 1, node.id)
    }
  }
  // One root -> it is the centre (depth 0). Several roots -> they start on the
  // first ring (depth 1) around an implicit centre that is not rendered.
  const single = roots.length === 1
  for (const r of roots) {
    if (visible && !visible.has(r.id)) continue
    dfs(r, single ? 0 : 1, null)
  }

  // Subtree leaf weight (respecting collapse) drives the angular share.
  const leaves = {}
  function leavesOf(id) {
    if (id in leaves) return leaves[id]
    if (collapsed.has(id)) return (leaves[id] = 1)
    const kids = (children.get(id) || []).filter((k) => !visible || visible.has(k.id))
    if (!kids.length) return (leaves[id] = 1)
    let s = 0
    for (const k of kids) s += leavesOf(k.id)
    return (leaves[id] = s)
  }

  // Group visible nodes by depth, preserving DFS order (keeps children near
  // their parent in angle).
  const byDepth = new Map()
  for (const id of order) {
    const d = depth[id]
    if (!byDepth.has(d)) byDepth.set(d, [])
    byDepth.get(d).push(id)
  }

  // Angular allocation per depth: share proportional to leaf weight, floored
  // with a water-fill so no node gets a slot too small for its box.
  const angle = {}
  const span = {}
  for (const [, ids] of byDepth) {
    if (ids.length === 1) {
      span[ids[0]] = 2 * Math.PI
      angle[ids[0]] = START_ANGLE
      continue
    }
    const even = (2 * Math.PI) / ids.length
    const floor = MIN_SHARE * even
    const w = {}
    for (const id of ids) w[id] = leavesOf(id)
    let pool = ids.slice()
    let rem = 2 * Math.PI
    while (pool.length) {
      let s = 0
      for (const id of pool) s += w[id]
      const small = pool.filter((id) => (w[id] / s) * rem < floor)
      if (!small.length) {
        for (const id of pool) span[id] = (w[id] / s) * rem
        break
      }
      for (const id of small) { span[id] = floor; rem -= floor }
      const smallSet = new Set(small)
      pool = pool.filter((id) => !smallSet.has(id))
      if (!pool.length) break
    }
    let cur = START_ANGLE
    for (const id of ids) { angle[id] = cur + span[id] / 2; cur += span[id] }
  }

  // Per-node box (card rectangle or hub square) and the tallest/widest box on
  // each ring — they drive the radial spacing between consecutive rings.
  const box = {}
  for (const n of list) box[n.id] = nodeBox(n)
  const maxH = {}
  const maxW = {}
  for (const id of order) {
    const d = depth[id]
    const b = box[id] || { w: CARD_W, h: CARD_H }
    maxH[d] = Math.max(maxH[d] ?? 0, b.h)
    maxW[d] = Math.max(maxW[d] ?? 0, b.w)
  }

  // Ring radii: grow with depth (RING_STEP) and, on dense rings, until the
  // closest pair of boxes on that ring clears the box footprint. The footprint
  // is the box DIAGONAL (the wider box's width + the pair's half-heights) so two
  // tall cards can never overlap diagonally. Between consecutive rings the
  // minimum centre distance is the radial step, which must clear the diagonal of
  // the tallest / widest boxes involved — otherwise a tall card can overlap its
  // neighbour on the next ring at a diagonal angle.
  const depths = [...byDepth.keys()].sort((a, b) => a - b)
  const radius = { 0: 0 }
  for (const d of depths) {
    if (d === 0) { radius[0] = 0; continue }
    const ids = byDepth.get(d)
    let need = RING_STEP
    if (ids.length > 1) {
      for (let i = 0; i < ids.length; i++) {
        const a = ids[i]
        const b = ids[(i + 1) % ids.length]
        const gap = (span[a] + span[b]) / 2
        if (gap > EPS) {
          const ba = box[a] || { w: CARD_W, h: CARD_H }
          const bb = box[b] || { w: CARD_W, h: CARD_H }
          const half = (ba.h + bb.h) / 2
          const wMax = Math.max(ba.w, bb.w)
          const footprint = Math.hypot(wMax, half) + GAP_X
          // chord = 2r*sin(gap/2) must clear the footprint
          const chordGap = 2 * Math.sin(Math.min(Math.PI, gap) / 2)
          need = Math.max(need, footprint / chordGap)
        }
      }
    }
    const halfSum = ((maxH[d - 1] ?? CARD_H) + (maxH[d] ?? CARD_H)) / 2
    const wPair = Math.max(maxW[d - 1] ?? CARD_W, maxW[d] ?? CARD_W)
    const radialGap = Math.hypot(wPair, halfSum)
    radius[d] = Math.max((radius[d - 1] ?? 0) + Math.max(RING_STEP, radialGap), need)
  }

  const maxR = depths.length ? Math.max(...depths.map((d) => radius[d])) : 0

  // Place boxes around the origin (x,y = box CENTRE), then shift everything so
  // the stage box starts at (0,0). The box is derived from the real rectangles
  // (per-node width + height), not a uniform size, so no node can fall outside.
  const raw = {}
  let minL = Infinity, minT = Infinity, maxRt = -Infinity, maxBt = -Infinity
  for (const id of order) {
    const r = radius[depth[id]] ?? 0
    const a = angle[id] ?? START_ANGLE
    const b = box[id] || { w: CARD_W, h: CARD_H }
    const w = b.w
    const hh = b.h
    const x0 = r * Math.cos(a)
    const y0 = r * Math.sin(a)
    const left = x0 - w / 2
    const top = y0 - hh / 2
    raw[id] = { x0, y0, left, top, w, h: hh, depth: depth[id], angle: a, r }
    if (left < minL) minL = left
    if (top < minT) minT = top
    if (left + w > maxRt) maxRt = left + w
    if (top + hh > maxBt) maxBt = top + hh
  }
  if (!order.length) { minL = minT = 0; maxRt = CARD_W; maxBt = CARD_H }
  const boxW = maxRt - minL
  const boxH = maxBt - minT
  const cx = -minL
  const cy = -minT

  const pos = {}
  for (const id of order) {
    const q = raw[id]
    pos[id] = {
      x: q.x0 - minL, y: q.y0 - minT,
      left: q.left - minL, top: q.top - minT,
      depth: q.depth, angle: q.angle, r: q.r, w: q.w, h: q.h,
      hub: isHubNode(byId.get(id))
    }
  }

  // Curved radial connectors: cubic bezier whose control points sit on the
  // parent / child angles so the edge bulges along the ring.
  //
  // SHARED CENTRE CONVENTION: both endpoints are the node CENTRE — (pos.x, pos.y),
  // i.e. the same point the DOM node-slot is centred on (TreeGraph.vue positions
  // each slot with `translate(pos.x, pos.y) translate(-50%,-50%)`). `pos.left/top`
  // are the box top-left corners (kept for callers that still want them), but the
  // edges and the DOM MUST both anchor on (x, y) so a circle/card lands exactly on
  // the line intersection.
  const edges = []
  for (const id of order) {
    const p = parentOf[id]
    if (!p || !pos[p]) continue
    const P = pos[p]
    const C = pos[id]
    const r1 = P.r + (C.r - P.r) * 0.45
    const r2 = P.r + (C.r - P.r) * 0.55
    const c1x = cx + r1 * Math.cos(P.angle)
    const c1y = cy + r1 * Math.sin(P.angle)
    const c2x = cx + r2 * Math.cos(C.angle)
    const c2y = cy + r2 * Math.sin(C.angle)
    edges.push({ id, from: p, to: id, d: `M ${P.x} ${P.y} C ${c1x} ${c1y}, ${c2x} ${c2y}, ${C.x} ${C.y}` })
  }

  return {
    pos, edges, parentOf, depth, order, hasChildren,
    w: boxW,
    h: boxH,
    cx, cy, maxR,
    maxDepth: depths.length ? depths[depths.length - 1] : 0
  }
}
