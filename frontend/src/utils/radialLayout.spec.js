import { describe, it, expect } from 'vitest'
import { radialLayout, CARD_W, CARD_H, RING_STEP, MIN_SHARE, radialCardHeight } from './radialLayout'

const NODES = [
  { id: 'r', title: 'Root', parent: null, order: 1 },
  { id: 'a', title: 'A', parent: 'r', order: 1 },
  { id: 'b', title: 'B', parent: 'r', order: 2 },
  { id: 'c', title: 'C', parent: 'r', order: 3 },
  { id: 'a1', title: 'A1', parent: 'a', order: 1 },
  { id: 'a2', title: 'A2', parent: 'a', order: 2 },
  { id: 'b1', title: 'B1', parent: 'b', order: 1 }
]

function overlapping(L) {
  const ids = Object.keys(L.pos)
  const bad = []
  for (let i = 0; i < ids.length; i++) {
    for (let j = i + 1; j < ids.length; j++) {
      const a = L.pos[ids[i]], b = L.pos[ids[j]]
      if (a.left < b.left + b.w && b.left < a.left + a.w &&
          a.top < b.top + b.h && b.top < a.top + a.h) bad.push([ids[i], ids[j]])
    }
  }
  return bad
}

// Deterministic "wide + deep" tree (up to 4 children per node, like the real
// categories after the restructure) to stress the overlap guarantee.
function bigTree() {
  const out = [{ id: 'n0', title: 'root', parent: null, order: 0 }]
  let seed = 1234567
  const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff)
  let n = 0
  const queue = ['n0']
  while (n < 120 && queue.length) {
    const p = queue.shift()
    const kids = 1 + Math.floor(rnd() * 4)
    for (let i = 0; i < kids && n < 120; i++) {
      const id = 'n' + (++n)
      out.push({ id, title: 'Lesson number ' + n + ' with a fairly long title', parent: p, order: i })
      if (rnd() > 0.25) queue.push(id)
    }
  }
  return out
}

describe('utils/radialLayout.js — sunburst geometry', () => {
  it('places the single root at the centre of the stage', () => {
    const L = radialLayout(NODES)
    expect(L.pos.r.x).toBeCloseTo(L.cx, 6)
    expect(L.pos.r.y).toBeCloseTo(L.cy, 6)
    expect(L.pos.r.r).toBe(0)
  })

  it('puts every depth on its own ring, radius growing with depth', () => {
    const L = radialLayout(NODES)
    expect(L.pos.a.depth).toBe(1)
    expect(L.pos.a1.depth).toBe(2)
    expect(L.pos.a.r).toBeCloseTo(RING_STEP, 6)
    expect(L.pos.a1.r).toBeGreaterThan(L.pos.a.r)
  })

  it('keeps every node fully inside the reported stage box', () => {
    const L = radialLayout(NODES)
    for (const id in L.pos) {
      const p = L.pos[id]
      expect(p.left).toBeGreaterThanOrEqual(-1e-6)
      expect(p.top).toBeGreaterThanOrEqual(-1e-6)
      expect(p.left + p.w).toBeLessThanOrEqual(L.w + 1e-6)
      expect(p.top + p.h).toBeLessThanOrEqual(L.h + 1e-6)
    }
  })

  it('never overlaps two cards (small tree)', () => {
    expect(overlapping(radialLayout(NODES))).toEqual([])
  })

  it('never overlaps two cards on a wide, deep tree', () => {
    const L = radialLayout(bigTree())
    expect(Object.keys(L.pos).length).toBeGreaterThan(60)
    expect(overlapping(L)).toEqual([])
  })

  it('emits one curved edge per non-root node', () => {
    const L = radialLayout(NODES)
    expect(L.edges.length).toBe(NODES.length - 1)
    for (const e of L.edges) expect(e.d).toMatch(/^M .* C /)
  })

  it('gives every node at least the floored share of its ring', () => {
    const L = radialLayout(NODES)
    // depth 1 has 3 children of equal weight -> equal thirds
    const a = L.pos.a, b = L.pos.b, c = L.pos.c
    const angs = [a.angle, b.angle, c.angle].sort((x, y) => x - y)
    const gaps = [angs[1] - angs[0], angs[2] - angs[1]]
    for (const g of gaps) expect(g).toBeGreaterThanOrEqual(MIN_SHARE * (2 * Math.PI / 3) - 1e-9)
  })

  it('prunes a collapsed subtree from the layout', () => {
    const L = radialLayout(NODES, { collapsed: new Set(['a']) })
    expect(L.pos.a).toBeTruthy()
    expect(L.pos.a1).toBeUndefined()
    expect(L.pos.a2).toBeUndefined()
    expect(L.pos.b1).toBeTruthy()
    expect(L.hasChildren.a).toBe(true)
    expect(L.hasChildren.a1).toBe(false)
    expect(L.edges.length).toBe(4) // r-a, r-b, r-c, b-b1
  })

  it('renders only the allow-listed nodes (progressive reveal / fog of war)', () => {
    const L = radialLayout(NODES, { visible: new Set(['r', 'a', 'a1']) })
    expect(L.pos.r).toBeTruthy()
    expect(L.pos.a).toBeTruthy()
    expect(L.pos.a1).toBeTruthy()
    expect(L.pos.b).toBeUndefined()
    expect(L.pos.c).toBeUndefined()
    expect(L.pos.a2).toBeUndefined()
    expect(L.edges.length).toBe(2) // r-a, a-a1
  })

  it('can show a node while hiding only SOME of its children', () => {
    const L = radialLayout(NODES, { visible: new Set(['r', 'a', 'a1', 'b', 'c']) })
    expect(L.pos.a).toBeTruthy()
    expect(L.pos.a1).toBeTruthy()
    expect(L.pos.a2).toBeUndefined() // hidden even though its parent is visible
    expect(L.pos.b).toBeTruthy()
    expect(L.pos.b1).toBeUndefined()
  })

  it('spreads multiple roots on the first ring instead of stacking them', () => {
    const two = [
      { id: 'x', title: 'X', parent: null, order: 1 },
      { id: 'y', title: 'Y', parent: null, order: 2 }
    ]
    const L = radialLayout(two)
    expect(L.pos.x.r).toBeCloseTo(RING_STEP, 6)
    expect(L.pos.y.r).toBeCloseTo(RING_STEP, 6)
    expect(L.pos.x.x).not.toBeCloseTo(L.pos.y.x, 3)
    expect(overlapping(L)).toEqual([])
  })

  it('handles an empty node list', () => {
    const L = radialLayout([])
    expect(L.edges).toEqual([])
    expect(Object.keys(L.pos)).toEqual([])
    expect(L.w).toBe(CARD_W)
    expect(L.h).toBe(CARD_H)
  })

  it('sizes each card from its own title height (content-driven, per node)', () => {
    const LONG = 'Request Smuggling advanced: TE.TE, TE.CL, CL.0, response-queue poisoning'
    const mixed = [
      { id: 'r', title: 'Root', parent: null, order: 1 },
      { id: 'short', title: 'XSS', parent: 'r', order: 1 },
      { id: 'long', title: LONG, parent: 'r', order: 2 }
    ]
    const L = radialLayout(mixed)
    expect(L.pos.short.h).toBe(40)                       // 1 line (compact floor)
    expect(L.pos.long.h).toBe(radialCardHeight({ title: LONG }))
    expect(L.pos.long.h).toBeGreaterThan(L.pos.short.h)
    // the stage box must contain the taller card
    expect(L.pos.long.top + L.pos.long.h).toBeLessThanOrEqual(L.h + 1e-6)
  })

  it('keeps the card compact: title capped at 3 lines (max height ~62px)', () => {
    const HUGE = 'Request Smuggling advanced: TE.TE, TE.CL, CL.0, response-queue poisoning and HTTP/2 downgrade'
    const h = radialCardHeight({ title: HUGE })
    expect(h).toBeLessThanOrEqual(62)
    expect(h).toBeGreaterThanOrEqual(40)
    // 1-line title uses the compact floor, not the old 65px
    expect(radialCardHeight({ title: 'XSS' })).toBe(40)
  })

  it('never overlaps cards when every title is long (tall cards)', () => {
    const out = [{ id: 'n0', title: 'Корень всего дерева с очень длинным названием', parent: null, order: 0 }]
    let seed = 987654
    const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff)
    let n = 0
    const queue = ['n0']
    while (n < 90 && queue.length) {
      const p = queue.shift()
      const kids = 1 + Math.floor(rnd() * 4)
      for (let i = 0; i < kids && n < 90; i++) {
        const id = 'n' + (++n)
        out.push({
          id,
          title: 'Очень длинное название урока номер ' + n + ' с подробным описанием темы и подтемы занятия',
          parent: p,
          order: i
        })
        if (rnd() > 0.25) queue.push(id)
      }
    }
    const L = radialLayout(out)
    expect(Object.keys(L.pos).length).toBeGreaterThan(40)
    expect(overlapping(L)).toEqual([])
  })
})
