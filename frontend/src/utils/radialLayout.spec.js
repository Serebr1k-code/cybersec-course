import { describe, it, expect } from 'vitest'
import { radialLayout, NODE_D, NODE_R, RING_STEP, GAP_X, GAP_Y, MIN_SHARE } from './radialLayout'

const NODES = [
  { id: 'r', title: 'Root', parent: null, order: 1 },
  { id: 'a', title: 'A', parent: 'r', order: 1 },
  { id: 'b', title: 'B', parent: 'r', order: 2 },
  { id: 'c', title: 'C', parent: 'r', order: 3 },
  { id: 'a1', title: 'A1', parent: 'a', order: 1 },
  { id: 'a2', title: 'A2', parent: 'a', order: 2 },
  { id: 'b1', title: 'B1', parent: 'b', order: 1 }
]

// Circles overlap when the distance between their centres is smaller than the
// sum of their radii (both are NODE_D wide).
function overlapping(L) {
  const ids = Object.keys(L.pos)
  const bad = []
  for (let i = 0; i < ids.length; i++) {
    for (let j = i + 1; j < ids.length; j++) {
      const a = L.pos[ids[i]], b = L.pos[ids[j]]
      const dx = a.x - b.x, dy = a.y - b.y
      const minDist = (a.w + b.w) / 2
      if (Math.hypot(dx, dy) < minDist - 1e-6) bad.push([ids[i], ids[j]])
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

describe('utils/radialLayout.js — sunburst geometry of circle nodes', () => {
  it('places the single root at the centre of the stage', () => {
    const L = radialLayout(NODES)
    expect(L.pos.r.x).toBeCloseTo(L.cx, 6)
    expect(L.pos.r.y).toBeCloseTo(L.cy, 6)
    expect(L.pos.r.r).toBe(0)
  })

  it('sizes every node as a fixed circle (no content-driven card height)', () => {
    const L = radialLayout(NODES)
    for (const id in L.pos) {
      expect(L.pos[id].w).toBe(NODE_D)
      expect(L.pos[id].h).toBe(NODE_D)
    }
    expect(NODE_R).toBe(NODE_D / 2)
  })

  it('puts every depth on its own ring, radius growing with depth', () => {
    const L = radialLayout(NODES)
    expect(L.pos.a.depth).toBe(1)
    expect(L.pos.a1.depth).toBe(2)
    expect(L.pos.a.r).toBeCloseTo(RING_STEP, 6)
    expect(L.pos.a1.r).toBeGreaterThan(L.pos.a.r)
  })

  it('packs rings tightly: RING_STEP is one diameter plus the ring gap', () => {
    expect(RING_STEP).toBe(NODE_D + GAP_Y)
    // a sparse ring needs no extra room, so its radius is exactly RING_STEP
    const L = radialLayout(NODES)
    expect(L.pos.a.r).toBeCloseTo(RING_STEP, 6)
  })

  it('grows the radius of a dense ring so its circles never collide', () => {
    const wide = [{ id: 'r', title: 'R', parent: null, order: 0 }]
    for (let i = 0; i < 40; i++) wide.push({ id: 'c' + i, title: 'C' + i, parent: 'r', order: i })
    const L = radialLayout(wide)
    // 40 circles on one ring need a radius well beyond the base step
    expect(L.pos.c0.r).toBeGreaterThan(RING_STEP)
    // adjacent circles clear the required centre distance (diameter + gap)
    const ids = Object.keys(L.pos).filter((id) => id !== 'r')
    const angs = ids.map((id) => ({ id, a: L.pos[id].angle })).sort((x, y) => x.a - y.a)
    for (let i = 0; i < angs.length; i++) {
      const p = L.pos[angs[i].id], q = L.pos[angs[(i + 1) % angs.length].id]
      expect(Math.hypot(p.x - q.x, p.y - q.y)).toBeGreaterThanOrEqual(NODE_D + GAP_X - 1e-6)
    }
    expect(overlapping(L)).toEqual([])
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

  it('never overlaps two circles (small tree)', () => {
    expect(overlapping(radialLayout(NODES))).toEqual([])
  })

  it('never overlaps two circles on a wide, deep tree', () => {
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
    expect(L.w).toBe(NODE_D)
    expect(L.h).toBe(NODE_D)
  })
})
