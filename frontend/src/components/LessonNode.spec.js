import { describe, it, expect } from 'vitest'
import { mount, RouterLinkStub } from '@vue/test-utils'
import LessonNode from './LessonNode.vue'
import { HUB_D, CARD_W, radialCardHeight } from '../utils/radialLayout'

const LESSON = {
  id: 'web-sqli',
  title: 'SQL-инъекции',
  difficulty: 'hard',
  category: 'web',
  sections: 5,
  estimated_minutes: 90
}

const HUB = {
  id: 'web-auth-core',
  title: 'Аутентификация: ядро сессий',
  difficulty: 'easy',
  category: 'web',
  tags: ['web', 'roadmap']
}

function factory(props = {}) {
  return mount(LessonNode, {
    props: { node: LESSON, ...props },
    global: { stubs: { RouterLink: RouterLinkStub } }
  })
}
function hub(props = {}) {
  return mount(LessonNode, {
    props: { node: HUB, ...props },
    global: { stubs: { RouterLink: RouterLinkStub } }
  })
}

const DIFF_COLORS = {
  beginner: '#22c55e', easy: '#84cc16', medium: '#eab308', hard: '#f97316', expert: '#ef4444'
}

describe('components/LessonNode.vue — real lesson renders a text card', () => {
  it('links to the lesson route', () => {
    expect(factory().findComponent(RouterLinkStub).props('to')).toBe('/lesson/web-sqli')
  })

  it('shows the title text on the card face', () => {
    const w = factory()
    expect(w.find('.title').text()).toBe('SQL-инъекции')
    expect(w.classes()).toContain('card')
    expect(w.classes()).not.toContain('hub')
  })

  it('colours the card accent + stars by difficulty (--diff + star class)', () => {
    for (const d of Object.keys(DIFF_COLORS)) {
      const w = factory({ node: { ...LESSON, difficulty: d } })
      expect(w.attributes('style')).toContain('--diff: ' + DIFF_COLORS[d])
      expect(w.find('.stars').classes()).toContain('d-' + d)
    }
  })

  it('defaults an unknown/empty difficulty to the beginner colour + 1 star', () => {
    for (const d of [undefined, '', 'weird']) {
      const w = factory({ node: { ...LESSON, difficulty: d } })
      expect(w.attributes('style')).toContain('--diff: ' + DIFF_COLORS.beginner)
      expect(w.find('.stars').text()).toBe('★')
    }
  })

  it('renders a 1–5 star rating matching the difficulty', () => {
    expect(factory({ node: { ...LESSON, difficulty: 'expert' } }).find('.stars').text()).toBe('★★★★★')
    expect(factory({ node: { ...LESSON, difficulty: 'medium' } }).find('.stars').text()).toBe('★★★')
  })

  it('formats the estimated duration compactly and hides it when absent', () => {
    const dur = (minutes) => factory({ node: { ...LESSON, estimated_minutes: minutes } }).find('.dur')
    expect(dur(25).text()).toBe('25м')
    expect(dur(60).text()).toBe('1ч')
    expect(dur(140).text()).toBe('2ч 20м')
    expect(dur(0).exists()).toBe(false)
    expect(factory({ node: { ...LESSON, estimated_minutes: undefined } }).find('.dur').exists()).toBe(false)
    // legacy field fallback
    expect(factory({ node: { ...LESSON, estimated_minutes: 0, estMinutes: 45 } }).find('.dur').text()).toBe('45м')
  })

  it('applies the custom category colour as the hover accent CSS variable', () => {
    expect(factory({ color: '#ff0000' }).attributes('style')).toContain('--cat: #ff0000')
  })

  it('sizes the card to the layout box (width + reserved height)', () => {
    const w = factory()
    expect(w.attributes('style')).toContain('width: ' + CARD_W + 'px')
    // the rendered height is CLAMPED to the reserved height so the card centre
    // always matches the layout centre (the edge endpoint).
    expect(w.attributes('style')).toContain('height: ' + radialCardHeight(LESSON) + 'px')
    expect(w.attributes('style')).not.toContain('min-height')
    // an explicit height overrides the content-derived one
    expect(factory({ height: 62 }).attributes('style')).toContain('height: 62px')
  })

  it('shows reading progress as a green fill bar', () => {
    expect(factory({ ratio: 0.5 }).find('.fill').attributes('style')).toContain('width: 50%')
    expect(factory({ ratio: 0.756 }).find('.fill').attributes('style')).toContain('width: 76%')
  })

  it('clamps out-of-range ratios', () => {
    expect(factory({ ratio: 1.9 }).find('.fill').attributes('style')).toContain('width: 100%')
    expect(factory({ ratio: -0.5 }).find('.fill').attributes('style')).toContain('width: 0%')
  })

  it('forces a full green fill + shows the check badge when completed', () => {
    const w = factory({ ratio: 0.2, completed: true })
    expect(w.find('.fill').attributes('style')).toContain('width: 100%')
    expect(w.classes()).toContain('done')
    expect(w.find('.badge').exists()).toBe(true)
    expect(w.find('.badge').text()).toBe('✓')
  })

  it('hides the check badge when not completed', () => {
    expect(factory({ completed: false }).find('.badge').exists()).toBe(false)
  })

  it('reflects the path / dim interaction state as classes', () => {
    expect(factory({ onpath: true }).classes()).toContain('on')
    expect(factory({ dimmed: true }).classes()).toContain('dim')
  })

  it('renders NO collapse chevron on the card (on-node chevrons were removed)', () => {
    // The little collapse arrows were removed from every node: the chevron
    // button, its `folded` / `has-chev` state classes and the toggle emit are
    // all gone (the tree toolbar still collapses via TreeGraph.collapseAll).
    const w = factory()
    expect(w.find('.chev').exists()).toBe(false)
    expect(w.find('button').exists()).toBe(false)
    expect(w.classes()).not.toContain('folded')
    expect(w.classes()).not.toContain('has-chev')
  })

  it('carries the title + difficulty name in the accessibility label', () => {
    const w = factory({ node: { ...LESSON, difficulty: 'expert' } })
    expect(w.attributes('title')).toContain('SQL-инъекции')
    expect(w.attributes('title')).toContain('Эксперт')
  })
})

describe('components/LessonNode.vue — hub renders a plain small circle', () => {
  it('links to the module page', () => {
    expect(hub().findComponent(RouterLinkStub).props('to')).toBe('/lesson/web-auth-core')
  })

  it('is a hub circle and carries NO title text on its face', () => {
    const w = hub()
    expect(w.classes()).toContain('hub')
    expect(w.classes()).not.toContain('card')
    expect(w.find('.title').exists()).toBe(false)
    expect(w.find('.fill').exists()).toBe(false)
    expect(w.find('.badge').exists()).toBe(false)
    expect(w.find('.bullet').exists()).toBe(true)
  })

  it('renders NO hover tooltip and NO native title attribute (hover shows nothing)', () => {
    const w = hub()
    // the custom popover is gone entirely
    expect(w.find('.tip').exists()).toBe(false)
    expect(w.find('.tip-title').exists()).toBe(false)
    // ...and so is the native browser title popup
    expect(w.attributes('title')).toBeUndefined()
    // the module title is only exposed to assistive tech (no visible popup)
    expect(w.attributes('aria-label')).toBe('Аутентификация: ядро сессий')
  })

  it('is a small fixed-size circle (default HUB_D) that can be overridden', () => {
    expect(hub().attributes('style')).toContain('--d: ' + HUB_D + 'px')
    expect(hub({ size: 30 }).attributes('style')).toContain('--d: 30px')
  })

  it('colours the bullet ring with the category accent', () => {
    expect(hub({ color: '#ff0000' }).attributes('style')).toContain('--cat: #ff0000')
  })

  it('renders NO collapse chevron on the hub circle (on-node chevrons were removed)', () => {
    const w = hub()
    expect(w.find('.chev').exists()).toBe(false)
    expect(w.find('button').exists()).toBe(false)
    expect(w.classes()).not.toContain('folded')
    expect(w.classes()).not.toContain('has-chev')
  })

  it('reflects the path / dim interaction state as classes', () => {
    expect(hub({ onpath: true }).classes()).toContain('on')
    expect(hub({ dimmed: true }).classes()).toContain('dim')
  })
})

describe('components/LessonNode.vue — waystone gate renders a golden block', () => {
  const WS = { ...LESSON, waystone: true, waystone_tasks: ['a', 'b', 'c', 'd', 'e'] }

  it('renders no waystone block for a plain lesson', () => {
    expect(factory().find('.ws').exists()).toBe(false)
    expect(factory({ gate: null }).find('.ws').exists()).toBe(false)
  })

  it('renders a locked waystone as a gold block with a left→right fill', () => {
    const w = factory({ node: WS, gate: { total: 5, solved: 2, locked: true } })
    const b = w.find('.ws')
    expect(b.exists()).toBe(true)
    expect(b.classes()).toContain('locked')
    expect(b.classes()).not.toContain('open')
    // the face carries NO lock icon and NO "N/M" pill text — only the fill
    expect(w.find('.gate').exists()).toBe(false)
    expect(w.text()).not.toContain('🔒')
    expect(w.text()).not.toContain('🔓')
    expect(w.text()).not.toMatch(/\d\s*\/\s*\d/)
    // fill = solved/total = 2/5 = 40%
    expect(w.find('.ws-fill').attributes('style')).toContain('width: 40%')
  })

  it('renders a full waystone as an open gold block that links to the lesson', () => {
    const w = factory({ node: WS, gate: { total: 5, solved: 5, locked: false } })
    const b = w.find('.ws')
    expect(b.classes()).toContain('open')
    expect(b.classes()).not.toContain('locked')
    expect(w.find('.ws-fill').attributes('style')).toContain('width: 100%')
    expect(w.findComponent(RouterLinkStub).props('to')).toBe('/lesson/web-sqli')
  })

  it('a locked waystone is a <button> (NOT a link) that emits gate-open on click', async () => {
    const w = factory({ node: WS, gate: { total: 5, solved: 1, locked: true } })
    const b = w.find('button.ws')
    expect(b.exists()).toBe(true)
    // no RouterLink at all for a locked gate -> a click can never navigate
    expect(w.findComponent(RouterLinkStub).exists()).toBe(false)
    await b.trigger('click')
    expect(w.emitted('gate-open')).toBeTruthy()
    expect(w.emitted('gate-open').length).toBe(1)
  })

  it('prefers the pre-computed gate.fill fraction when provided', () => {
    const w = factory({ node: WS, gate: { total: 4, solved: 1, locked: true, fill: 0.25 } })
    expect(w.find('.ws-fill').attributes('style')).toContain('width: 25%')
  })

  it('renders a zero-task waystone as an empty (unlocked) gold block', () => {
    const w = factory({ node: WS, gate: { total: 0, solved: 0, locked: false } })
    expect(w.find('.ws').exists()).toBe(true)
    expect(w.find('.ws-fill').attributes('style')).toContain('width: 0%')
  })

  it('renders the block even when the waystone node is a hub (not a circle)', () => {
    const w = hub({ node: { ...HUB, waystone: true, waystone_tasks: ['a'] }, gate: { total: 1, solved: 0, locked: true } })
    expect(w.find('.ws').exists()).toBe(true)
    expect(w.classes()).toContain('ws')
    expect(w.classes()).not.toContain('hub')
    // the hub bullet is NOT rendered for a waystone
    expect(w.find('.bullet').exists()).toBe(false)
    expect(w.find('.title').text()).toBe('Аутентификация: ядро сессий')
  })

  it('sizes the block to read clearly even when the reserved hub box is tiny', () => {
    const w = hub({ node: { ...HUB, waystone: true, waystone_tasks: ['a'] }, size: 18, width: 18, height: 18, gate: { total: 1, solved: 0, locked: true } })
    const style = w.attributes('style')
    expect(style).toContain('width: 120px')
    expect(style).toContain('height: 30px')
  })

  it('describes the gate state in the title/aria-label (not on the face)', () => {
    const locked = factory({ node: WS, gate: { total: 5, solved: 2, locked: true } })
    expect(locked.attributes('title')).toMatch(/заперт/i)
    expect(locked.attributes('title')).toContain('2 из 5')
    expect(locked.attributes('aria-label')).toMatch(/заперт/i)
    const open = factory({ node: WS, gate: { total: 5, solved: 5, locked: false } })
    expect(open.attributes('title')).toMatch(/открыт/i)
  })
})
