import { describe, it, expect } from 'vitest'
import { mount, RouterLinkStub } from '@vue/test-utils'
import LessonNode from './LessonNode.vue'
import { radialCardHeight } from '../utils/radialLayout'

const NODE = {
  id: 'web-sqli',
  title: 'SQL-инъекции',
  difficulty: 'hard',
  category: 'web',
  sections: 5,
  estimated_minutes: 90
}

function factory(props = {}) {
  return mount(LessonNode, {
    props: { node: NODE, ...props },
    global: { stubs: { RouterLink: RouterLinkStub } }
  })
}

describe('components/LessonNode.vue — compact radial card', () => {
  it('links to the lesson route', () => {
    const w = factory()
    expect(w.findComponent(RouterLinkStub).props('to')).toBe('/lesson/web-sqli')
  })

  it('renders the title', () => {
    expect(factory().find('.title').text()).toBe('SQL-инъекции')
  })

  it('maps the difficulty to a 1–5 star rating coloured by difficulty', () => {
    const stars = { beginner: 1, easy: 2, medium: 3, hard: 4, expert: 5 }
    for (const d of ['beginner', 'easy', 'medium', 'hard', 'expert']) {
      const w = factory({ node: { ...NODE, difficulty: d } })
      const el = w.find('.stars')
      expect(el.classes()).toContain('d-' + d)
      expect(el.text()).toBe('★'.repeat(stars[d]))
      // no textual difficulty label on the card anymore
      expect(el.text()).not.toMatch(/Новичок|Легко|Средне|Сложно|Эксперт/)
    }
  })

  it('defaults an unknown/empty difficulty to a single star', () => {
    for (const d of [undefined, '', 'weird']) {
      const w = factory({ node: { ...NODE, difficulty: d } })
      expect(w.find('.stars').text()).toBe('★')
    }
  })

  it('keeps the full difficulty name in the title tooltip + aria-label', () => {
    const w = factory({ node: { ...NODE, difficulty: 'expert' } })
    const el = w.find('.stars')
    expect(el.attributes('aria-label')).toBe('Эксперт')
    expect(el.attributes('title')).toBe('Эксперт')
    expect(w.attributes('title')).toContain('Эксперт')
  })

  it('applies the custom category colour as a CSS variable', () => {
    expect(factory({ color: '#ff0000' }).attributes('style')).toContain('--cat: #ff0000')
  })

  it('uses a fixed width but a compact content-driven min-height (never clips)', () => {
    const w = factory({ width: 150 })
    const style = w.attributes('style')
    expect(style).toContain('width: 150px')
    // default title needs one line -> 40px compact floor
    expect(style).toContain('min-height: 40px')
    // an explicit height overrides the estimate (layout can pin it)
    expect(factory({ width: 150, height: 60 }).attributes('style')).toContain('min-height: 60px')
  })

  it('grows the card with the title but caps it at 3 lines (compact)', () => {
    const h = (node) => +factory({ node }).attributes('style').match(/min-height:\s*(\d+)px/)[1]
    const longTitle = 'Request Smuggling advanced: TE.TE, TE.CL, CL.0, response-queue poisoning'
    const short = h({ ...NODE, title: 'XSS' })
    const long = h({ ...NODE, title: longTitle })
    expect(short).toBe(40)
    expect(long).toBeGreaterThan(short)
    expect(long).toBeLessThanOrEqual(62)          // 3-line cap -> never a giant card
    expect(long).toBe(radialCardHeight({ title: longTitle }))
  })

  it('shows the estimated duration (human hours/minutes) on the meta row, no progress bar', () => {
    const dur = (minutes) => factory({ node: { ...NODE, estimated_minutes: minutes } }).find('.dur')
    expect(dur(25).text()).toBe('25м')
    expect(dur(60).text()).toBe('1ч')
    expect(dur(90).text()).toBe('1ч 30м')
    expect(dur(140).text()).toBe('2ч 20м')
    // the progress bar is gone (the green .fill already shows progress)
    expect(factory().find('.bar').exists()).toBe(false)
    // 0 / absent minutes -> the duration text is hidden
    expect(dur(0).exists()).toBe(false)
    expect(factory({ node: { ...NODE, estimated_minutes: undefined } }).find('.dur').exists()).toBe(false)
    // legacy field fallback
    expect(factory({ node: { ...NODE, estimated_minutes: 0, estMinutes: 45 } }).find('.dur').text()).toBe('45м')
  })

  it('sets the green fill background to the ratio', () => {
    const w = factory({ ratio: 0.5 })
    expect(w.find('.fill').attributes('style')).toContain('width: 50%')
    expect(factory({ ratio: 0.756 }).find('.fill').attributes('style')).toContain('width: 76%')
  })

  it('clamps out-of-range ratios', () => {
    expect(factory({ ratio: 1.9 }).find('.fill').attributes('style')).toContain('width: 100%')
    expect(factory({ ratio: -0.5 }).find('.fill').attributes('style')).toContain('width: 0%')
  })

  it('shows the completed badge and the done class', () => {
    const w = factory({ ratio: 1, completed: true })
    expect(w.find('.badge').exists()).toBe(true)
    expect(w.find('.badge').text()).toBe('✓')
    expect(w.classes()).toContain('done')
  })

  it('hides the badge when not completed', () => {
    expect(factory({ completed: false }).find('.badge').exists()).toBe(false)
  })

  it('reflects the path / dim interaction state as classes', () => {
    expect(factory({ onpath: true }).classes()).toContain('on')
    expect(factory({ dimmed: true }).classes()).toContain('dim')
  })

  it('renders a collapse chevron only for nodes with children', () => {
    expect(factory({ hasChildren: false }).find('.chev').exists()).toBe(false)
    const w = factory({ hasChildren: true, collapsed: false })
    expect(w.find('.chev').exists()).toBe(true)
    expect(factory({ hasChildren: true, collapsed: true }).classes()).toContain('folded')
  })

  it('emits toggle when the chevron is clicked', async () => {
    const w = factory({ hasChildren: true })
    await w.find('.chev').trigger('click')
    expect(w.emitted('toggle')).toBeTruthy()
    expect(w.emitted('toggle')[0]).toEqual(['web-sqli'])
  })
})
