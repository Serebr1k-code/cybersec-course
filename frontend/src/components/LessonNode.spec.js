import { describe, it, expect } from 'vitest'
import { mount, RouterLinkStub } from '@vue/test-utils'
import LessonNode from './LessonNode.vue'
import { NODE_D } from '../utils/radialLayout'

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

const DIFF_COLORS = {
  beginner: '#22c55e', easy: '#84cc16', medium: '#eab308', hard: '#f97316', expert: '#ef4444'
}

describe('components/LessonNode.vue — minimal coloured circle', () => {
  it('links to the lesson route', () => {
    const w = factory()
    expect(w.findComponent(RouterLinkStub).props('to')).toBe('/lesson/web-sqli')
  })

  it('renders NO title text on the face of the node', () => {
    const w = factory()
    // the visible face is just the ring + the coloured disc — both textless
    expect(w.find('.arc').text()).toBe('')
    expect(w.find('.disc').text()).toBe('')
    // the title is exposed through the hover tooltip instead
    expect(w.find('.tip-title').text()).toBe('SQL-инъекции')
  })

  it('colours the circle by difficulty (filled disc + --diff variable)', () => {
    for (const d of Object.keys(DIFF_COLORS)) {
      const w = factory({ node: { ...NODE, difficulty: d } })
      expect(w.attributes('style')).toContain('--diff: ' + DIFF_COLORS[d])
      expect(w.find('.disc').exists()).toBe(true)
    }
  })

  it('defaults an unknown/empty difficulty to the beginner colour', () => {
    for (const d of [undefined, '', 'weird']) {
      const w = factory({ node: { ...NODE, difficulty: d } })
      expect(w.attributes('style')).toContain('--diff: ' + DIFF_COLORS.beginner)
      expect(w.find('.tip-diff').text()).toBe('Новичок')
    }
  })

  it('reveals the title + difficulty name + duration in the hover tooltip', () => {
    const w = factory({ node: { ...NODE, difficulty: 'expert', estimated_minutes: 90 } })
    expect(w.find('.tip-title').text()).toBe('SQL-инъекции')
    expect(w.find('.tip-diff').text()).toBe('Эксперт')
    expect(w.find('.tip-dur').text()).toContain('1ч 30м')
    // accessibility label carries the same info
    expect(w.attributes('aria-label')).toContain('SQL-инъекции')
    expect(w.attributes('aria-label')).toContain('Эксперт')
  })

  it('formats the estimated duration compactly and hides it when absent', () => {
    const dur = (minutes) => factory({ node: { ...NODE, estimated_minutes: minutes } }).find('.tip-dur')
    expect(dur(25).text()).toBe('· 25м')
    expect(dur(60).text()).toBe('· 1ч')
    expect(dur(140).text()).toBe('· 2ч 20м')
    expect(dur(0).exists()).toBe(false)
    expect(factory({ node: { ...NODE, estimated_minutes: undefined } }).find('.tip-dur').exists()).toBe(false)
    // legacy field fallback
    expect(factory({ node: { ...NODE, estimated_minutes: 0, estMinutes: 45 } }).find('.tip-dur').text()).toBe('· 45м')
  })

  it('applies the custom category colour as the accent CSS variable', () => {
    expect(factory({ color: '#ff0000' }).attributes('style')).toContain('--cat: #ff0000')
  })

  it('is a fixed-size circle (default 22px) that can be overridden', () => {
    expect(factory().attributes('style')).toContain('--d: ' + NODE_D + 'px')
    expect(factory({ size: 30 }).attributes('style')).toContain('--d: 30px')
  })

  it('shows reading progress as a green arc fraction (--pct)', () => {
    expect(factory({ ratio: 0.5 }).attributes('style')).toContain('--pct: 50%')
    expect(factory({ ratio: 0.756 }).attributes('style')).toContain('--pct: 76%')
  })

  it('clamps out-of-range ratios', () => {
    expect(factory({ ratio: 1.9 }).attributes('style')).toContain('--pct: 100%')
    expect(factory({ ratio: -0.5 }).attributes('style')).toContain('--pct: 0%')
  })

  it('forces a full green ring + shows the check badge when completed', () => {
    const w = factory({ ratio: 0.2, completed: true })
    expect(w.attributes('style')).toContain('--pct: 100%')
    expect(w.classes()).toContain('done')
    expect(w.find('.check').exists()).toBe(true)
    expect(w.find('.check').text()).toBe('✓')
  })

  it('hides the check badge when not completed', () => {
    expect(factory({ completed: false }).find('.check').exists()).toBe(false)
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

  it('counter-scales the tooltip with the canvas zoom (stays readable)', () => {
    expect(factory({ zoom: 1 }).attributes('style')).toContain('--tip-scale: 1')
    expect(factory({ zoom: 0.5 }).attributes('style')).toContain('--tip-scale: 2')
    // zooming IN shrinks the popover in stage space so its screen size stays 1x
    expect(factory({ zoom: 2 }).attributes('style')).toContain('--tip-scale: 0.5')
    // clamped at both extremes so the popover never becomes absurd
    expect(factory({ zoom: 0.05 }).attributes('style')).toContain('--tip-scale: 8')
    expect(factory({ zoom: 20 }).attributes('style')).toContain('--tip-scale: 0.1')
  })
})
