import { describe, it, expect } from 'vitest'
import {
  radialLayout, isHubNode, nodeBox, radialCardHeight,
  HUB_D, NODE_D, NODE_R, CARD_W, CARD_H, RING_STEP, GAP_X, GAP_Y, MIN_SHARE
} from './radialLayout'

const NODES = [
  { id: 'r', title: 'Root', parent: null, order: 1 },
  { id: 'a', title: 'A', parent: 'r', order: 1 },
  { id: 'b', title: 'B', parent: 'r', order: 2 },
  { id: 'c', title: 'C', parent: 'r', order: 3 },
  { id: 'a1', title: 'A1', parent: 'a', order: 1 },
  { id: 'a2', title: 'A2', parent: 'a', order: 2 },
  { id: 'b1', title: 'B1', parent: 'b', order: 1 }
]

// Two axis-aligned boxes overlap when their rectangles intersect (with a tiny
// tolerance so exact edge contact is NOT an overlap).
function rectsOverlap(a, b) {
  const eps = 1e-6
  return !(
    a.left + a.w <= b.left + eps ||
    b.left + b.w <= a.left + eps ||
    a.top + a.h <= b.top + eps ||
    b.top + b.h <= a.top + eps
  )
}

// Boxes overlap when their rectangles intersect.
function overlapping(L) {
  const ids = Object.keys(L.pos)
  const bad = []
  for (let i = 0; i < ids.length; i++) {
    for (let j = i + 1; j < ids.length; j++) {
      if (rectsOverlap(L.pos[ids[i]], L.pos[ids[j]])) bad.push([ids[i], ids[j]])
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

describe('utils/radialLayout.js — hub detection', () => {
  it('treats a title starting with "Модуль:" as a hub', () => {
    expect(isHubNode({ title: 'Модуль: сетевой анализ' })).toBe(true)
    expect(isHubNode({ title: 'модуль: строчная' })).toBe(true)
  })

  it('treats a roadmap tag as a hub (canonical thin-lessons.py rule)', () => {
    expect(isHubNode({ title: 'Архитектура: базовый фундамент', tags: ['web', 'roadmap'] })).toBe(true)
    expect(isHubNode({ title: 'Обычный урок', tags: ['roadmap', 'ssrf'] })).toBe(true)
  })

  it('does not treat a normal lesson as a hub', () => {
    expect(isHubNode({ title: 'SQL-инъекции', tags: ['web', 'sqli'] })).toBe(false)
    expect(isHubNode({ title: 'Модульный тест', tags: [] })).toBe(false) // "Модульный" is not "Модуль:"
    expect(isHubNode(null)).toBe(false)
  })

  it('sizes a hub as a small square and a lesson as a wide card', () => {
    expect(nodeBox({ title: 'Модуль: X' })).toEqual({ w: HUB_D, h: HUB_D })
    const card = nodeBox({ title: 'SQL-инъекции' })
    expect(card.w).toBe(CARD_W)
    expect(card.h).toBe(radialCardHeight({ title: 'SQL-инъекции' }))
    expect(card.h).toBeGreaterThanOrEqual(40)
  })
})

describe('utils/radialLayout.js — sunburst geometry of hybrid nodes', () => {
  it('places the single root at the centre of the stage', () => {
    const L = radialLayout(NODES)
    expect(L.pos.r.x).toBeCloseTo(L.cx, 6)
    expect(L.pos.r.y).toBeCloseTo(L.cy, 6)
    expect(L.pos.r.r).toBe(0)
  })

  it('reserves a wide card for lessons and a small square for hubs', () => {
    const nodes = [
      { id: 'r', title: 'Root', parent: null, order: 0 },
      { id: 'h', title: 'Модуль: группа', parent: 'r', order: 1 },
      { id: 'l', title: 'Настоящий урок', parent: 'r', order: 2 }
    ]
    const L = radialLayout(nodes)
    expect(L.pos.l.w).toBe(CARD_W)
    expect(L.pos.l.h).toBe(radialCardHeight({ title: 'Настоящий урок' }))
    expect(L.pos.h.w).toBe(HUB_D)
    expect(L.pos.h.h).toBe(HUB_D)
    expect(L.pos.h.hub).toBe(true)
    expect(L.pos.l.hub).toBe(false)
  })

  it('keeps the backwards-compatible small-node aliases', () => {
    expect(NODE_D).toBe(HUB_D)
    expect(NODE_R).toBe(HUB_D / 2)
  })

  it('puts every depth on its own ring, radius growing with depth', () => {
    const L = radialLayout(NODES)
    expect(L.pos.a.depth).toBe(1)
    expect(L.pos.a1.depth).toBe(2)
    expect(L.pos.a.r).toBeCloseTo(RING_STEP, 6)
    expect(L.pos.a1.r).toBeGreaterThan(L.pos.a.r)
  })

  it('packs a sparse ring at the base radial step', () => {
    expect(RING_STEP).toBe(CARD_W + GAP_Y)
    const L = radialLayout(NODES)
    expect(L.pos.a.r).toBeCloseTo(RING_STEP, 6)
  })

  it('grows the radius of a dense ring so its boxes never collide', () => {
    const wide = [{ id: 'r', title: 'R', parent: null, order: 0 }]
    for (let i = 0; i < 40; i++) wide.push({ id: 'c' + i, title: 'C' + i, parent: 'r', order: i })
    const L = radialLayout(wide)
    // 40 cards on one ring need a radius well beyond the base step
    expect(L.pos.c0.r).toBeGreaterThan(RING_STEP)
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

  it('never overlaps two boxes (small tree)', () => {
    expect(overlapping(radialLayout(NODES))).toEqual([])
  })

  it('never overlaps two boxes on a wide, deep tree', () => {
    const L = radialLayout(bigTree())
    expect(Object.keys(L.pos).length).toBeGreaterThan(60)
    expect(overlapping(L)).toEqual([])
  })

  it('never overlaps a mixed hub + lesson tree', () => {
    const nodes = [
      { id: 'r', title: 'Root lesson', parent: null, order: 0 },
      { id: 'h1', title: 'Модуль: A', parent: 'r', order: 1, tags: ['roadmap'] },
      { id: 'h2', title: 'Модуль: B', parent: 'r', order: 2 },
      { id: 'l1', title: 'Урок 1', parent: 'h1', order: 1 },
      { id: 'l2', title: 'Урок 2 с длинным названием', parent: 'h1', order: 2 },
      { id: 'l3', title: 'Урок 3', parent: 'h2', order: 1 }
    ]
    expect(overlapping(radialLayout(nodes))).toEqual([])
  })

  it('emits one curved edge per non-root node', () => {
    const L = radialLayout(NODES)
    expect(L.edges.length).toBe(NODES.length - 1)
    for (const e of L.edges) expect(e.d).toMatch(/^M .* C /)
  })

  it('anchors every edge endpoint on the node CENTRE (centre-to-centre convention)', () => {
    // The DOM node-slot is centred on (pos.x, pos.y); the SVG edge endpoints must
    // use the SAME point, otherwise a circle would sit off the line intersection.
    const L = radialLayout(NODES)
    for (const e of L.edges) {
      const nums = e.d.match(/-?[\d.]+/g).map(Number)
      // "M fromX fromY C c1x c1y, c2x c2y, toX toY"
      expect(nums[0]).toBeCloseTo(L.pos[e.from].x, 6)
      expect(nums[1]).toBeCloseTo(L.pos[e.from].y, 6)
      expect(nums[nums.length - 2]).toBeCloseTo(L.pos[e.to].x, 6)
      expect(nums[nums.length - 1]).toBeCloseTo(L.pos[e.to].y, 6)
    }
  })

  it('reports the box centre (x, y) exactly half a box from the top-left corner', () => {
    const L = radialLayout(NODES)
    for (const id in L.pos) {
      const p = L.pos[id]
      expect(p.x).toBeCloseTo(p.left + p.w / 2, 6)
      expect(p.y).toBeCloseTo(p.top + p.h / 2, 6)
    }
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
})
