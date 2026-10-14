import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'

// The lab terminal (and @xterm with it) is code-split. Stub the component so the
// test can assert WHERE it lands (inline vs. the bottom panel) without a terminal.
vi.mock('../components/LabPanel.vue', () => ({
  __esModule: true,
  default: {
    name: 'LabPanel',
    __isTeleport: false,
    props: { lessonId: String, lab: Object, inline: { type: Boolean, default: false } },
    template: '<div class="lab-panel-stub" :data-inline="inline ? \'1\' : \'0\'">LAB</div>'
  }
}))

vi.mock('../api/client', () => ({
  api: {
    tree: vi.fn(),
    lesson: vi.fn(),
    lessons: vi.fn(),
    search: vi.fn(),
    meta: vi.fn(),
    progress: vi.fn(),
    section: vi.fn(),
    quiz: vi.fn(),
    complete: vi.fn(),
    notes: vi.fn(),
    lab: vi.fn(),
    exportProgress: vi.fn(),
    importProgress: vi.fn()
  }
}))

const { routerPush } = vi.hoisted(() => ({ routerPush: vi.fn() }))
vi.mock('vue-router', () => ({
  useRoute: () => ({ params: { id: 'network-dns-enum' } }),
  useRouter: () => ({ push: routerPush })
}))

import LessonView from './LessonView.vue'
import { api } from '../api/client'

class MockIntersectionObserver {
  constructor() {}
  observe() {}
  unobserve() {}
  disconnect() {}
}

const LAB = { kind: 'shell', title: 'DNS', toolset: ['dig'], check: "grep -q x y" }

function lesson({ sections, lab = LAB }) {
  return {
    id: 'network-dns-enum',
    title: 'DNS',
    category: 'network',
    parent: 'network-module-dns',
    difficulty: 'medium',
    order: 1,
    tags: [],
    estimated_minutes: 40,
    summary: 's',
    lab,
    sections
  }
}

function mountView() {
  const pinia = createPinia()
  setActivePinia(pinia)
  return mount(LessonView, {
    global: {
      plugins: [pinia],
      components: { RouterLink: { template: '<a><slot /></a>' } },
      stubs: { NotesPanel: true }
    }
  })
}

describe('views/LessonView.vue — inline lab placement', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    Element.prototype.getBoundingClientRect = () => ({
      top: 0, bottom: 100, left: 0, right: 0, width: 0, height: 100, x: 0, y: 0, toJSON() {}
    })
    vi.stubGlobal('IntersectionObserver', MockIntersectionObserver)
    window.scrollTo = vi.fn()
    Object.defineProperty(window, 'scrollY', { value: 0, configurable: true, writable: true })
    Object.defineProperty(document, 'hidden', { value: false, configurable: true })
    api.tree.mockResolvedValue({ categories: [], nodes: [], total: 0 })
    api.progress.mockResolvedValue({ user: { lessons: {}, activity: {} }, xp: 0, streak: 0, achievements: [] })
    api.lab.mockResolvedValue({})
  })

  afterEach(() => vi.unstubAllGlobals())

  it('mounts the terminal INLINE at the marker and drops the bottom panel', async () => {
    api.lesson.mockResolvedValue(lesson({
      sections: [
        { id: 's1', title: 'Теория', markdown: 'вступление', required_seconds: 5 },
        { id: 's2', title: 'Практика', markdown: 'сделай так:\n\n<!-- lab -->\n\nпотом проверь', required_seconds: 5 }
      ]
    }))
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()
    await flushPromises()

    const labs = wrapper.findAll('.lab-panel-stub')
    // Exactly ONE terminal per lesson.
    expect(labs.length).toBe(1)
    expect(labs[0].attributes('data-inline')).toBe('1')
    // It sits inside the section that carried the marker, after the intro text.
    const sec = wrapper.findAll('.sec')[1]
    expect(sec.find('.lab-panel-stub').exists()).toBe(true)
    expect(sec.text()).toContain('сделай так:')
    expect(sec.text()).toContain('потом проверь')
    // The raw marker must never leak into the rendered body.
    expect(wrapper.html()).not.toContain('lab -->')
    wrapper.unmount()
  })

  it('falls back to the bottom panel when the lesson has a lab but no marker', async () => {
    api.lesson.mockResolvedValue(lesson({
      sections: [
        { id: 's1', title: 'Теория', markdown: 'текст', required_seconds: 5 },
        { id: 's2', title: 'Ещё', markdown: 'ещё текст', required_seconds: 5 }
      ]
    }))
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()
    await flushPromises()

    const labs = wrapper.findAll('.lab-panel-stub')
    expect(labs.length).toBe(1)
    expect(labs[0].attributes('data-inline')).toBe('0')
    // The panel lives OUTSIDE any section (after the last one).
    expect(wrapper.findAll('.sec .lab-panel-stub').length).toBe(0)
    wrapper.unmount()
  })

  it('renders nothing when the lesson has no lab at all', async () => {
    api.lesson.mockResolvedValue(lesson({
      lab: null,
      sections: [{ id: 's1', title: 'Т', markdown: 'текст', required_seconds: 5 }]
    }))
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()
    await flushPromises()
    expect(wrapper.find('.lab-panel-stub').exists()).toBe(false)
    wrapper.unmount()
  })

  it('uses only the FIRST marker and strips any later ones', async () => {
    api.lesson.mockResolvedValue(lesson({
      sections: [
        { id: 's1', title: 'A', markdown: 'начало\n\n<!-- lab -->\n\nконец', required_seconds: 5 },
        { id: 's2', title: 'B', markdown: 'второй маркер\n\n<!-- lab -->\n\nхвост', required_seconds: 5 }
      ]
    }))
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()
    await flushPromises()

    expect(wrapper.findAll('.lab-panel-stub').length).toBe(1)
    expect(wrapper.findAll('.sec')[0].find('.lab-panel-stub').exists()).toBe(true)
    expect(wrapper.findAll('.sec')[1].find('.lab-panel-stub').exists()).toBe(false)
    // The stray second marker is gone from the text, its prose kept.
    expect(wrapper.findAll('.sec')[1].text()).toContain('второй маркер')
    expect(wrapper.findAll('.sec')[1].text()).toContain('хвост')
    expect(wrapper.html()).not.toContain('lab -->')
    wrapper.unmount()
  })
})
