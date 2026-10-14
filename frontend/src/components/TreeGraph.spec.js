import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount, RouterLinkStub, flushPromises } from '@vue/test-utils'
import { nextTick } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import TreeGraph from './TreeGraph.vue'
import { useProgressStore } from '../stores/progress'
import { HUB_D, CARD_W, RING_STEP, radialLayout } from '../utils/radialLayout'

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

// Parse each rendered node slot. The slot transform is
// `translate(x, y) translate(-50%, -50%)`, so (x, y) is the node's CENTRE — the
// exact point the SVG edge endpoints use (centre-to-centre convention).
function slots(w) {
  return w.findAll('.node-slot').map((s) => {
    const m = s.attributes('style').match(/translate\(([-\d.eE+]+)px,\s*([-\d.eE+]+)px\)/)
    const rn = s.find('.rnode')
    const style = rn.attributes('style') || ''
    const hub = rn.classes().includes('hub')
    const wm = style.match(/width:\s*([\d.]+)px/)
    const hm = style.match(/height:\s*([\d.]+)px/)
    const dm = style.match(/--d:\s*([\d.]+)px/)
    const width = hub ? (dm ? +dm[1] : 0) : (wm ? +wm[1] : 0)
    const height = hub ? (dm ? +dm[1] : 0) : (hm ? +hm[1] : 0)
    const title = rn.find('.title').exists()
      ? rn.find('.title').text()
      : (rn.attributes('aria-label') || '')
    return { x: +m[1], y: +m[2], width, height, hub, title, el: s, rn }
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
  it('renders one node per visible node', async () => {
    const w = await factory()
    expect(slots(w).length).toBe(3)
    expect(w.findAll('.rnode').length).toBe(3)
  })

  it('renders real lessons as fixed-width cards and hubs as small circles', async () => {
    const LONG = 'Request Smuggling advanced: TE.TE, TE.CL, CL.0, response-queue poisoning'
    const nodes = [
      { id: 'a', title: 'Root', parent: null, order: 1, sections: 1 },
      { id: 'b', title: 'XSS', parent: 'a', order: 1, sections: 1 },
      { id: 'c', title: LONG, parent: 'a', order: 2, sections: 1 },
      { id: 'h', title: 'Модуль: группа', parent: 'a', order: 3, sections: 1, tags: ['roadmap'] }
    ]
    const { w } = await factoryWithProgress({ nodes })
    // lessons: a fixed-width (150px) card whose height grows with the title
    const xss = slotByTitle(w, 'XSS')
    const long = slotByTitle(w, LONG)
    expect(xss.width).toBe(CARD_W)
    expect(long.width).toBe(CARD_W)
    expect(long.height).toBeGreaterThanOrEqual(xss.height)
    expect(xss.rn.find('.title').text()).toBe('XSS')
    // hub: a small circle with NO title text on its face
    const h = slotByTitle(w, 'Модуль: группа')
    expect(h.width).toBe(HUB_D)
    expect(h.height).toBe(HUB_D)
    expect(h.hub).toBe(true)
    expect(h.rn.find('.title').exists()).toBe(false)
    expect(xss.hub).toBe(false)
  })

  it('places the category root at the centre and children on the first ring', async () => {
    const w = await factory()
    const L = radialLayout(NODES)
    const root = slotByTitle(w, 'Root')
    const b = slotByTitle(w, 'Bee')
    // the slot's translate IS the node CENTRE (== the layout centre / edge endpoint)
    expect(root.x).toBeCloseTo(L.pos.a.x, 3)
    expect(root.y).toBeCloseTo(L.pos.a.y, 3)
    // b's centre sits RING_STEP away from the layout centre
    expect(Math.hypot(b.x - L.cx, b.y - L.cy)).toBeCloseTo(RING_STEP, 3)
    const c = slotByTitle(w, 'Cee')
    expect(c.x).not.toBeCloseTo(b.x, 1)
  })

  it('anchors every rendered node centre exactly on its layout (x, y) — the edge endpoint', async () => {
    const w = await factory()
    const L = radialLayout(NODES)
    // Every node slot's centre must equal the layout centre for that node, and
    // every edge endpoint must equal the SAME point (centre-to-centre convention).
    const edgeEnds = {}
    for (const e of L.edges) edgeEnds[e.to] = { x: L.pos[e.to].x, y: L.pos[e.to].y }
    for (const s of slots(w)) {
      const id = Object.keys(L.pos).find((k) => L.pos[k].x === s.x && L.pos[k].y === s.y)
      expect(id).toBeDefined()
      // the parsed DOM centre is exactly the layout centre (sub-pixel)
      expect(s.x).toBeCloseTo(L.pos[id].x, 6)
      expect(s.y).toBeCloseTo(L.pos[id].y, 6)
    }
    // the rendered edge path endpoints (start/end of the `d`) are the centres too
    for (const p of w.findAll('.edges path')) {
      const nums = p.attributes('d').match(/-?[\d.]+/g).map(Number)
      const startX = nums[0], startY = nums[1], endX = nums[nums.length - 2], endY = nums[nums.length - 1]
      const to = Object.keys(L.pos).find((k) => L.pos[k].x === endX && L.pos[k].y === endY)
      expect(to).toBeDefined()
    }
  })

  it('auto-fits the whole category into the canvas on mount', async () => {
    const w = await factory()
    const v = view(w)
    const L = radialLayout(NODES)
    // fit scale is clamped to the [0.05, 4] zoom range (the compact circle
    // layout packs small trees above the cap)
    const fit = Math.max(0.05, Math.min(4, Math.min(800 / L.w, 600 / L.h) * 0.95))
    expect(v.scale).toBeCloseTo(fit, 4)
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
    // the whole (tiny) tree fits above the 4x cap, so zoom out once to give the
    // wheel headroom to actually change the scale
    await clickControl(w, 1) // −
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
    const fit = Math.max(0.05, Math.min(4, Math.min(800 / L.w, 600 / L.h) * 0.95))
    expect(v.scale).toBeCloseTo(fit, 4)
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
    expect(v.tx + v.scale * b.x).toBeCloseTo(400, 3)
    expect(v.ty + v.scale * b.y).toBeCloseTo(300, 3)
  })

  it('does nothing when the focus id is not in this category', async () => {
    const w = await factory()
    const before = view(w)
    expect(w.vm.focusNode('missing')).toBe(false)
    expect(view(w)).toEqual(before)
  })

  it('collapsing a node (toggleCollapse) hides its subtree and re-lays out', async () => {
    const w = await factory()
    expect(slots(w).length).toBe(3)
    // the on-node chevron was removed; the collapse API stays exposed on the vm
    expect(w.find('.node-slot .chev').exists()).toBe(false)
    w.vm.toggleCollapse('a')
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
    const fit = Math.max(0.05, Math.min(4, Math.min(800 / L.w, 600 / L.h) * 0.95))
    expect(v.scale).toBeCloseTo(fit, 4)
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

describe('components/TreeGraph.vue — long-press (touch) opens the same menu', () => {
  // jsdom has no TouchEvent, so dispatch a generic event carrying a `touches`
  // list shaped like the real thing (the handlers only read clientX/clientY).
  function nodeTouch(el, type, touches) {
    const ev = new Event(type, { bubbles: true, cancelable: true })
    Object.defineProperty(ev, 'touches', { value: touches })
    el.dispatchEvent(ev)
    return ev
  }
  afterEach(() => vi.useRealTimers())

  it('opens the completion menu after a ~500ms press, at the touch point', async () => {
    const { w } = await factoryWithProgress()
    expect(w.find('.ctx-menu').exists()).toBe(false)
    vi.useFakeTimers()
    const slot = w.findAll('.node-slot')[1] // "Bee" (a real lesson)
    nodeTouch(slot.element, 'touchstart', [{ clientX: 300, clientY: 250 }])
    // not yet — the press has to be HELD
    expect(w.find('.ctx-menu').exists()).toBe(false)
    vi.advanceTimersByTime(500)
    await nextTick()
    expect(w.find('.ctx-menu').exists()).toBe(true)
    expect(w.findAll('.ctx-item').length).toBe(2)
    // positioned at the touch point (canvas is mocked at left=100, top=50)
    const style = w.find('.ctx-menu').attributes('style')
    expect(style).toContain('left: 200px')
    expect(style).toContain('top: 200px')
  })

  it('swallows the synthesized click after the long-press (no navigation)', async () => {
    const { w } = await factoryWithProgress()
    vi.useFakeTimers()
    const slot = w.findAll('.node-slot')[1]
    nodeTouch(slot.element, 'touchstart', [{ clientX: 300, clientY: 250 }])
    vi.advanceTimersByTime(500)
    await nextTick()
    expect(w.find('.ctx-menu').exists()).toBe(true)
    nodeTouch(slot.element, 'touchend', [])
    const click = new MouseEvent('click', { bubbles: true, cancelable: true })
    slot.element.dispatchEvent(click)
    expect(click.defaultPrevented).toBe(true)
    expect(w.find('.ctx-menu').exists()).toBe(true) // menu stays open
  })

  it('a short tap never opens the menu and still lets the click through', async () => {
    const { w } = await factoryWithProgress()
    vi.useFakeTimers()
    const slot = w.findAll('.node-slot')[1]
    nodeTouch(slot.element, 'touchstart', [{ clientX: 300, clientY: 250 }])
    vi.advanceTimersByTime(200) // < 500ms
    nodeTouch(slot.element, 'touchend', [])
    vi.advanceTimersByTime(800)
    await nextTick()
    expect(w.find('.ctx-menu').exists()).toBe(false)
    const click = new MouseEvent('click', { bubbles: true, cancelable: true })
    slot.element.dispatchEvent(click)
    expect(click.defaultPrevented).toBe(false)
  })

  it('cancels the long-press once the finger drags (so panning wins)', async () => {
    const { w } = await factoryWithProgress()
    vi.useFakeTimers()
    const slot = w.findAll('.node-slot')[1]
    nodeTouch(slot.element, 'touchstart', [{ clientX: 300, clientY: 250 }])
    nodeTouch(slot.element, 'touchmove', [{ clientX: 340, clientY: 250 }]) // > 10px
    vi.advanceTimersByTime(900)
    await nextTick()
    expect(w.find('.ctx-menu').exists()).toBe(false)
  })

  it('a long-press on a hub node opens nothing (hubs have no menu)', async () => {
    const nodes = [
      { id: 'a', title: 'Root', parent: null, order: 1, sections: 1 },
      { id: 'h', title: 'Модуль: Группа', parent: 'a', order: 1, sections: 1, tags: ['roadmap'] }
    ]
    const { w } = await factoryWithProgress({ nodes })
    vi.useFakeTimers()
    const hub = slots(w).find((s) => s.hub)
    expect(hub).toBeDefined()
    nodeTouch(hub.el.element, 'touchstart', [{ clientX: 200, clientY: 200 }])
    vi.advanceTimersByTime(700)
    await nextTick()
    expect(w.find('.ctx-menu').exists()).toBe(false)
  })

  it('long-press → «Отметить пройденным» persists through the store', async () => {
    const { w, store } = await factoryWithProgress()
    vi.useFakeTimers()
    const slot = w.findAll('.node-slot')[1]
    nodeTouch(slot.element, 'touchstart', [{ clientX: 300, clientY: 250 }])
    vi.advanceTimersByTime(500)
    vi.useRealTimers()
    await nextTick()
    expect(w.find('.ctx-menu').exists()).toBe(true)
    await w.findAll('.ctx-item')[0].trigger('click') // ✓ Отметить пройденным
    await flushPromises()
    expect(store.user.lessons.b.completed).toBe(true)
    expect(w.find('.ctx-menu').exists()).toBe(false)
  })

  it('a touch outside the menu closes it (touch has no mouse mousedown)', async () => {
    const { w } = await factoryWithProgress()
    vi.useFakeTimers()
    const slot = w.findAll('.node-slot')[1]
    nodeTouch(slot.element, 'touchstart', [{ clientX: 300, clientY: 250 }])
    vi.advanceTimersByTime(500)
    await nextTick()
    expect(w.find('.ctx-menu').exists()).toBe(true)
    // A fresh touch that lands outside the menu: in the (detached) test DOM the
    // event can't bubble to window, so dispatch it on window directly — exactly
    // how the existing outside-click test reaches the window listener.
    const outside = new Event('touchstart', { bubbles: true, cancelable: true })
    Object.defineProperty(outside, 'touches', { value: [{ clientX: 20, clientY: 20 }] })
    window.dispatchEvent(outside)
    await nextTick()
    expect(w.find('.ctx-menu').exists()).toBe(false)
  })
})

describe('components/TreeGraph.vue — progressive reveal (fog of war)', () => {
  // Every rendered box must fit inside the 800x600 canvas after the transform.
  function allInside(w) {
    const v = view(w)
    return slots(w).every((s) => {
      // s.x/s.y are the node CENTRE; the box spans centre ± size/2.
      const x = v.tx + v.scale * (s.x - s.width / 2)
      const y = v.ty + v.scale * (s.y - s.height / 2)
      return x >= -1 && y >= -1 &&
        x + v.scale * s.width <= 801 && y + v.scale * s.height <= 601
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

  it('keeps a manually expanded subtree open (toggleCollapse overrides fog-of-war)', async () => {
    const { w } = await factoryWithProgress({ nodes: TREE })
    expect(slotByTitle(w, 'L3')).toBeUndefined()
    // no on-node chevron any more — expand programmatically via the exposed API
    w.vm.toggleCollapse('c') // L2 has hidden child L3
    await flushPromises()
    expect(slotByTitle(w, 'L3')).toBeDefined()
    await nextTick()
    expect(slotByTitle(w, 'L3')).toBeDefined()
  })

  // Root -> L1 -> hub -> {L2a, L2b -> L3}. The hub sits at depth 2 (visible by
  // the default 2-level overview) but its children are at depth 3 (hidden by the
  // old rule). Hubs are transparent, so the children must appear anyway.
  const HUB_TREE = [
    { id: 'a', title: 'Root', parent: null, order: 1, sections: 1 },
    { id: 'b', title: 'L1', parent: 'a', order: 1, sections: 1 },
    { id: 'h', title: 'Модуль: Группа', parent: 'b', order: 1, sections: 1, tags: ['roadmap'] },
    { id: 'c', title: 'L2a', parent: 'h', order: 1, sections: 1 },
    { id: 'd', title: 'L2b', parent: 'h', order: 2, sections: 1 },
    { id: 'e', title: 'L3', parent: 'd', order: 1, sections: 1 }
  ]

  it('passes the fog of war through a hub: a revealed hub also reveals its children', async () => {
    const { w } = await factoryWithProgress({ nodes: HUB_TREE })
    // Root(0), L1(1), hub(2) from the default overview; the hub is TRANSPARENT so
    // its depth-3 children L2a/L2b appear too — the hub never dead-ends the fog.
    expect(slots(w).map((s) => s.title).sort())
      .toEqual(['L1', 'L2a', 'L2b', 'Root', 'Модуль: Группа'])
    // a REAL lesson is NOT transparent: L2b's child L3 stays hidden
    expect(slotByTitle(w, 'L3')).toBeUndefined()
  })

  // Root -> hubA -> hubB -> Real -> Next: the cascade must chain through hubs.
  const CHAINED_HUB_TREE = [
    { id: 'a', title: 'Root', parent: null, order: 1, sections: 1 },
    { id: 'h1', title: 'Модуль: A', parent: 'a', order: 1, sections: 1 },
    { id: 'h2', title: 'Модуль: B', parent: 'h1', order: 1, sections: 1 },
    { id: 'c', title: 'Real', parent: 'h2', order: 1, sections: 1 },
    { id: 'd', title: 'Next', parent: 'c', order: 1, sections: 1 }
  ]

  it('passes the fog of war through CHAINED hubs until real lessons are reached', async () => {
    const { w } = await factoryWithProgress({ nodes: CHAINED_HUB_TREE })
    // Root + both hubs (depth<=2) + the first real lesson beyond the chain.
    expect(slots(w).map((s) => s.title).sort())
      .toEqual(['Real', 'Root', 'Модуль: A', 'Модуль: B'])
    // a real lesson keeps the old rule: its own child is not auto-revealed
    expect(slotByTitle(w, 'Next')).toBeUndefined()
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
    const fit = Math.max(0.05, Math.min(4, Math.min(800 / L.w, 600 / L.h) * 0.95))
    expect(v.scale).toBeCloseTo(fit, 4)
  })
})
