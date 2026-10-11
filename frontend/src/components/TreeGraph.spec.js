import { describe, it, expect, vi } from 'vitest'
import { mount, RouterLinkStub, flushPromises } from '@vue/test-utils'
import { nextTick } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import TreeGraph from './TreeGraph.vue'
import { useProgressStore } from '../stores/progress'
import { CARD_W, RING_STEP, radialLayout, radialCardHeight } from '../utils/radialLayout'

vi.mock('../api/client', () => ({
  api: { complete: vi.fn().mockResolvedValue({ completed: true, xp: 0 }) }
}))

const NODES = [
  { id: 'a', title: 'Root', parent: null, order: 1, sections: 3 },
  { id: 'b', title: 'Bee', parent: 'a', order: 1, sections: 2 },
  { id: 'c', title: 'Cee', parent: 'a', order: 2, sections: 2 }
]

// Canvas mocked as an 800x600 box at (100,50) in viewport coords, so a wheel
// at clientX=300,clientY=250 lands at (200,200) canvas-relative.
const RECT = { left: 100, top: 50, width: 800, height: 600, right: 900, bottom: 650, x: 100, y: 50 }

async function factory(props = {}) {
  const w = mount(TreeGraph, {
    props: { nodes: NODES, ...props },
    global: { plugins: [createPinia()], stubs: { RouterLink: RouterLinkStub } }
  })
  w.find('.canvas').element.getBoundingClientRect = () => ({ ...RECT })
  await flushPromises()
  return w
}

// Mount with a pinia we can reach, so tests can mutate the progress store.
async function factoryWithProgress(props = {}) {
  const pinia = createPinia()
  setActivePinia(pinia)
  const store = useProgressStore()
  const w = mount(TreeGraph, {
    props: { nodes: NODES, ...props },
    global: { plugins: [pinia], stubs: { RouterLink: RouterLinkStub } }
  })
  w.find('.canvas').element.getBoundingClientRect = () => ({ ...RECT })
  await flushPromises()
  return { w, store }
}

function view(w) {
  const style = w.find('.stage').attributes('style')
  const m = style.match(/translate\(([-\d.eE+]+)px,\s*([-\d.eE+]+)px\)\s*scale\(([-\d.eE+]+)\)/)
  return { tx: +m[1], ty: +m[2], scale: +m[3] }
}

function slots(w) {
  return w.findAll('.node-slot').map((s) => {
    const m = s.attributes('style').match(/translate\(([-\d.eE+]+)px,\s*([-\d.eE+]+)px\)/)
    const rn = s.find('.rnode')
    const hm = rn.attributes('style').match(/min-height:\s*([\d.]+)px/)
    return { x: +m[1], y: +m[2], h: hm ? +hm[1] : 0, title: s.find('.title').text(), el: s }
  })
}
function slotByTitle(w, title) {
  return slots(w).find((s) => s.title === title)
}

async function wheel(w, { deltaY = -100, clientX = 300, clientY = 250 } = {}) {
  const ev = new Event('wheel', { bubbles: true, cancelable: true })
  Object.defineProperty(ev, 'deltaY', { value: deltaY })
  Object.defineProperty(ev, 'clientX', { value: clientX })
  Object.defineProperty(ev, 'clientY', { value: clientY })
  w.find('.canvas').element.dispatchEvent(ev)
  await nextTick()
}
async function clickControl(w, i) {
  w.findAll('.controls button')[i].trigger('click')
  await flushPromises()
}

describe('components/TreeGraph.vue — radial layout', () => {
  it('renders one compact card per visible node', async () => {
    const w = await factory()
    expect(slots(w).length).toBe(3)
    expect(w.findAll('.rnode').length).toBe(3)
  })

  it('sizes each card from its own title (longer title -> taller card)', async () => {
    const LONG = 'Request Smuggling advanced: TE.TE, TE.CL, CL.0, response-queue poisoning'
    const nodes = [
      { id: 'a', title: 'Root', parent: null, order: 1, sections: 1 },
      { id: 'b', title: 'XSS', parent: 'a', order: 1, sections: 1 },
      { id: 'c', title: LONG, parent: 'a', order: 2, sections: 1 }
    ]
    const { w } = await factoryWithProgress({ nodes })
    const hs = Object.fromEntries(slots(w).map((s) => [s.title, s.h]))
    expect(hs['XSS']).toBe(40)
    expect(hs[LONG]).toBeGreaterThan(hs['XSS'])
    expect(hs[LONG]).toBe(radialCardHeight({ title: LONG }))
  })

  it('places the category root at the centre and children on the first ring', async () => {
    const w = await factory()
    const L = radialLayout(NODES)
    const root = slotByTitle(w, 'Root')
    const b = slotByTitle(w, 'Bee')
    // the slot's translate equals the layout card's top-left corner
    expect(root.x).toBeCloseTo(L.pos.a.left, 3)
    expect(root.y).toBeCloseTo(L.pos.a.top, 3)
    // b sits RING_STEP away from the layout centre
    const bcx = b.x + CARD_W / 2
    const bcy = b.y + L.pos.b.h / 2
    expect(Math.hypot(bcx - L.cx, bcy - L.cy)).toBeCloseTo(RING_STEP, 3)
    const c = slotByTitle(w, 'Cee')
    expect(c.x).not.toBeCloseTo(b.x, 1)
  })

  it('auto-fits the whole category into the canvas on mount', async () => {
    const w = await factory()
    const v = view(w)
    const L = radialLayout(NODES)
    expect(v.scale).toBeCloseTo(Math.min(800 / L.w, 600 / L.h) * 0.95, 4)
    expect(v.tx).toBeCloseTo((800 - v.scale * L.w) / 2, 3)
    expect(v.ty).toBeCloseTo((600 - v.scale * L.h) / 2, 3)
    // content lies fully inside the canvas
    expect(v.tx).toBeGreaterThanOrEqual(-0.5)
    expect(v.ty).toBeGreaterThanOrEqual(-0.5)
    expect(v.tx + v.scale * L.w).toBeLessThanOrEqual(800.5)
    expect(v.ty + v.scale * L.h).toBeLessThanOrEqual(600.5)
  })

  it('anchors wheel zoom at the cursor', async () => {
    const w = await factory()
    const before = view(w)
    const p = { x: (200 - before.tx) / before.scale, y: (200 - before.ty) / before.scale }
    await wheel(w)
    const after = view(w)
    expect(after.scale).toBeGreaterThan(before.scale)
    expect(after.tx + after.scale * p.x).toBeCloseTo(200, 3)
    expect(after.ty + after.scale * p.y).toBeCloseTo(200, 3)
  })

  it('clamps the scale to [0.05, 4]', async () => {
    const w = await factory()
    for (let i = 0; i < 60; i++) await clickControl(w, 1) // −
    expect(view(w).scale).toBeCloseTo(0.05, 5)
    for (let i = 0; i < 90; i++) await clickControl(w, 0) // ＋
    expect(view(w).scale).toBeCloseTo(4, 5)
  })

  it('Сброс re-fits the whole tree (not the top-left corner)', async () => {
    const w = await factory()
    await wheel(w) // pan/zoom away
    await clickControl(w, 2) // ⤢ Сброс
    const v = view(w)
    const L = radialLayout(NODES)
    expect(v.scale).toBeCloseTo(Math.min(800 / L.w, 600 / L.h) * 0.95, 4)
    expect(v.tx).toBeCloseTo((800 - v.scale * L.w) / 2, 3)
  })
})

describe('components/TreeGraph.vue — focus, collapse and highlight', () => {
  it('focusNode() centres a node in the canvas', async () => {
    const w = await factory()
    expect(w.vm.focusNode('b')).toBe(true)
    await nextTick()
    const v = view(w)
    const b = slotByTitle(w, 'Bee')
    expect(v.tx + v.scale * (b.x + CARD_W / 2)).toBeCloseTo(400, 3)
    expect(v.ty + v.scale * (b.y + b.h / 2)).toBeCloseTo(300, 3)
  })

  it('does nothing when the focus id is not in this category', async () => {
    const w = await factory()
    const before = view(w)
    expect(w.vm.focusNode('missing')).toBe(false)
    expect(view(w)).toEqual(before)
  })

  it('collapsing a node hides its subtree and re-lays out', async () => {
    const w = await factory()
    expect(slots(w).length).toBe(3)
    await w.find('.node-slot .chev').trigger('click')
    await flushPromises()
    expect(slots(w).length).toBe(1)
    expect(slotByTitle(w, 'Bee')).toBeUndefined()
    expect(w.findAll('.edges path').length).toBe(0)
  })

  it('highlights the root→hovered path and dims the rest only on hover', async () => {
    const w = await factory()
    // nothing is highlighted or dimmed before a real hover
    expect(w.findAll('.rnode.on').length).toBe(0)
    expect(w.findAll('.rnode.dim').length).toBe(0)
    const bee = slotByTitle(w, 'Bee')
    await bee.el.trigger('mouseenter')
    const on = slots(w).filter((s) => s.el.find('.rnode').classes().includes('on')).map((s) => s.title)
    const dim = slots(w).filter((s) => s.el.find('.rnode').classes().includes('dim')).map((s) => s.title)
    expect(on.sort()).toEqual(['Bee', 'Root'])
    expect(dim).toEqual(['Cee'])
    // moving the pointer away clears the highlight/dim
    await bee.el.trigger('mouseleave')
    expect(w.findAll('.rnode.on').length).toBe(0)
    expect(w.findAll('.rnode.dim').length).toBe(0)
  })

  it('does not highlight or dim on mount when a focusId (last opened lesson) is set', async () => {
    const w = await factory({ focusId: 'b' })
    expect(w.findAll('.rnode.on').length).toBe(0)
    expect(w.findAll('.rnode.dim').length).toBe(0)
  })

  it('opens on a readable overview with the focus node visible but unhighlighted', async () => {
    const w = await factory({ focusId: 'b' })
    const v = view(w)
    // NODES are only 2 levels deep, so nothing collapses: the whole tree fits.
    const L = radialLayout(NODES)
    expect(v.scale).toBeCloseTo(Math.min(800 / L.w, 600 / L.h) * 0.95, 4)
    // the last-opened lesson stays visible (camera), but is NOT highlighted
    const b = slotByTitle(w, 'Bee')
    expect(b).toBeDefined()
    expect(b.el.find('.rnode').classes()).not.toContain('on')
    expect(b.el.find('.rnode').classes()).not.toContain('dim')
  })

  it('does not dim the overview when the focus is the category root', async () => {
    const w = await factory({ focusId: 'a' })
    expect(w.findAll('.rnode.dim').length).toBe(0)
    expect(w.findAll('.rnode.on').length).toBe(0)
  })

  it('emits one curved connector per visible non-root node', async () => {
    const w = await factory()
    const paths = w.findAll('.edges path')
    expect(paths.length).toBe(2)
    for (const p of paths) expect(p.attributes('d')).toMatch(/^M .* C /)
  })
})

describe('components/TreeGraph.vue — edge colour by both endpoints', () => {
  const strokes = (w) => w.findAll('.edges path').map((p) => p.attributes('stroke'))

  it('dims edges when neither endpoint is completed', async () => {
    const { w } = await factoryWithProgress()
    expect(strokes(w)).toEqual(['#26384a', '#26384a'])
  })

  it('paints an edge white when exactly one endpoint is completed', async () => {
    const { w, store } = await factoryWithProgress()
    store.user.lessons.a = { completed: true } // root only -> both edges "one"
    await nextTick()
    expect(strokes(w)).toEqual(['#e6edf3', '#e6edf3'])
  })

  it('paints an edge green only when BOTH endpoints are completed', async () => {
    const { w, store } = await factoryWithProgress()
    store.user.lessons.a = { completed: true }
    store.user.lessons.b = { completed: true }
    await nextTick()
    const s = strokes(w)
    // a->b both done = green, a->c only parent done = white
    expect(s).toContain('#22c55e')
    expect(s).toContain('#e6edf3')
  })

  it('updates edge colours reactively as progress changes', async () => {
    const { w, store } = await factoryWithProgress()
    expect(strokes(w)[0]).toBe('#26384a')
    store.user.lessons.b = { completed: true }
    await nextTick()
    expect(strokes(w)[0]).toBe('#e6edf3')
    store.user.lessons.a = { completed: true }
    await nextTick()
    expect(strokes(w)[0]).toBe('#22c55e')
  })
})

describe('components/TreeGraph.vue — right-click completion toggle', () => {
  it('opens a context menu on right-click and closes on Escape', async () => {
    const { w } = await factoryWithProgress()
    expect(w.find('.ctx-menu').exists()).toBe(false)
    await w.findAll('.node-slot')[1].trigger('contextmenu') // "Bee"
    expect(w.find('.ctx-menu').exists()).toBe(true)
    expect(w.findAll('.ctx-item').length).toBe(2)
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await nextTick()
    expect(w.find('.ctx-menu').exists()).toBe(false)
  })

  it('marks a lesson completed and persists through the store', async () => {
    const { w, store } = await factoryWithProgress()
    await w.findAll('.node-slot')[1].trigger('contextmenu')
    await w.findAll('.ctx-item')[0].trigger('click') // Отметить пройденным
    await flushPromises()
    expect(store.user.lessons.b.completed).toBe(true)
    expect(w.find('.ctx-menu').exists()).toBe(false)
  })

  it('unmarks a lesson (Отметить непройденным)', async () => {
    const { w, store } = await factoryWithProgress()
    store.user.lessons.b = { completed: true }
    await nextTick()
    await w.findAll('.node-slot')[1].trigger('contextmenu')
    await w.findAll('.ctx-item')[1].trigger('click') // Отметить непройденным
    await flushPromises()
    expect(store.user.lessons.b.completed).toBe(false)
  })

  it('closes the menu on an outside click', async () => {
    const { w } = await factoryWithProgress()
    await w.findAll('.node-slot')[1].trigger('contextmenu')
    expect(w.find('.ctx-menu').exists()).toBe(true)
    window.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
    await nextTick()
    expect(w.find('.ctx-menu').exists()).toBe(false)
  })
})

describe('components/TreeGraph.vue — progressive reveal (fog of war)', () => {
  // Every rendered card must fit inside the 800x600 canvas after the transform.
  function allInside(w) {
    const v = view(w)
    return slots(w).every((s) => {
      const x = v.tx + v.scale * s.x
      const y = v.ty + v.scale * s.y
      return x >= -1 && y >= -1 &&
        x + v.scale * CARD_W <= 801 && y + v.scale * s.h <= 601
    })
  }
  // Root -> L1 -> L2 -> L3 -> L4 plus a sibling branch L1b (6 nodes, 4 levels).
  const TREE = [
    { id: 'a', title: 'Root', parent: null, order: 1, sections: 1 },
    { id: 'b', title: 'L1', parent: 'a', order: 1, sections: 1 },
    { id: 'e', title: 'L1b', parent: 'a', order: 2, sections: 1 },
    { id: 'c', title: 'L2', parent: 'b', order: 1, sections: 1 },
    { id: 'd', title: 'L3', parent: 'c', order: 1, sections: 1 },
    { id: 'g', title: 'L4', parent: 'd', order: 1, sections: 1 }
  ]

  it('shows the root plus levels 1 and 2 by default when nothing is started', async () => {
    const { w } = await factoryWithProgress({ nodes: TREE })
    // depth-2 default: Root(0), L1/L1b(1), L2(2); deeper L3/L4 stay hidden
    expect(slots(w).map((s) => s.title).sort()).toEqual(['L1', 'L1b', 'L2', 'Root'])
    expect(slotByTitle(w, 'L3')).toBeUndefined()
    expect(slotByTitle(w, 'L4')).toBeUndefined()
  })

  it('reveals a started lesson with its path from the root and its direct children', async () => {
    const { w, store } = await factoryWithProgress({ nodes: TREE })
    // L3 (d, depth 3) started -> path Root..L3 + its direct child L4
    store.user.lessons.d = { sections: { s1: { read: true } }, completed: false }
    await nextTick(); await flushPromises()
    expect(slots(w).map((s) => s.title).sort()).toEqual(['L1', 'L1b', 'L2', 'L3', 'L4', 'Root'])
  })

  it('treats a completed lesson as started (its next steps appear)', async () => {
    const { w, store } = await factoryWithProgress({ nodes: TREE })
    expect(slotByTitle(w, 'L3')).toBeUndefined() // depth 3 hidden by default
    store.user.lessons.c = { completed: true } // L2 done -> its child L3 appears
    await nextTick(); await flushPromises()
    expect(slotByTitle(w, 'L3')).toBeDefined()
    expect(slotByTitle(w, 'L4')).toBeUndefined()
  })

  it('grows live as more lessons are started', async () => {
    const { w, store } = await factoryWithProgress({ nodes: TREE })
    // depth-2 default already shows Root,L1,L1b,L2; L3 (depth 3) is hidden
    expect(slotByTitle(w, 'L3')).toBeUndefined()
    store.user.lessons.c = { completed: true } // L2 done -> L3 appears
    await nextTick(); await flushPromises()
    expect(slotByTitle(w, 'L3')).toBeDefined()
    store.user.lessons.d = { completed: true } // L3 done -> L4 appears
    await nextTick(); await flushPromises()
    expect(slotByTitle(w, 'L4')).toBeDefined()
  })

  it('«Развернуть всё» shows the whole tree; «Свернуть всё» returns to progressive reveal', async () => {
    const { w, store } = await factoryWithProgress({ nodes: TREE })
    store.user.lessons.c = { completed: true } // progressive: Root,L1,L1b,L2,L3 (no L4)
    await nextTick(); await flushPromises()
    expect(slotByTitle(w, 'L4')).toBeUndefined()
    await clickControl(w, 4) // ⊞ Развернуть всё
    expect(slots(w).length).toBe(6)
    expect(slotByTitle(w, 'L4')).toBeDefined()
    await clickControl(w, 3) // ⊟ Свернуть всё -> progressive reveal default
    expect(slots(w).map((s) => s.title).sort()).toEqual(['L1', 'L1b', 'L2', 'L3', 'Root'])
    expect(slotByTitle(w, 'L4')).toBeUndefined()
  })

  it('fits the whole revealed tree on mount (all cards inside the canvas)', async () => {
    const { w, store } = await factoryWithProgress({ nodes: TREE })
    store.user.lessons.g = { completed: true } // reveal everything
    await nextTick(); await flushPromises()
    expect(slots(w).length).toBe(6)
    expect(allInside(w)).toBe(true)
  })

  it('keeps a manually expanded subtree open (chevron overrides fog-of-war)', async () => {
    const { w } = await factoryWithProgress({ nodes: TREE })
    expect(slotByTitle(w, 'L3')).toBeUndefined()
    const l2 = slotByTitle(w, 'L2') // L2 has hidden child L3 -> chevron expands
    await l2.el.find('.chev').trigger('click')
    await flushPromises()
    expect(slotByTitle(w, 'L3')).toBeDefined()
    await nextTick()
    expect(slotByTitle(w, 'L3')).toBeDefined()
  })

  it('shows a legend hint explaining the progressive reveal', async () => {
    const { w } = await factoryWithProgress({ nodes: TREE })
    expect(w.find('.hint').text()).toMatch(/пройденные/i)
  })

  it('re-fits the visible subtree on Сброс after collapsing', async () => {
    const { w } = await factoryWithProgress({ nodes: TREE })
    await clickControl(w, 3) // ⊟ Свернуть всё -> depth-2 default (4 nodes)
    const v = view(w)
    const L = radialLayout(TREE, { visible: new Set(['a', 'b', 'e', 'c']) })
    expect(v.scale).toBeCloseTo(Math.min(800 / L.w, 600 / L.h) * 0.95, 4)
  })
})
