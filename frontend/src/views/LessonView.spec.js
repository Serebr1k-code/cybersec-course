import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'

// API is fully mocked — no network.
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
    exportProgress: vi.fn(),
    importProgress: vi.fn()
  }
}))

// useRoute only — RouterLink is provided as a global component below.
const { routerPush } = vi.hoisted(() => ({ routerPush: vi.fn() }))
vi.mock('vue-router', () => ({
  useRoute: () => ({ params: { id: 'web-xss' } }),
  useRouter: () => ({ push: routerPush })
}))

import LessonView from './LessonView.vue'
import { api } from '../api/client'

// Capture the IntersectionObserver callback + options so the test can drive visibility.
let ioCallback = null
let ioOptions = null
class MockIntersectionObserver {
  constructor(cb, opts) {
    ioCallback = cb
    ioOptions = opts
  }
  observe() {}
  unobserve() {}
  disconnect() {}
}

// jsdom returns an all-zero rect for every element. The reading timer now keys
// off getBoundingClientRect().top/.bottom, so give every element a visible rect
// whose top sits above the 60% viewport line by default; tests that care about
// the threshold override individual sections.
const origGetBoundingClientRect = Element.prototype.getBoundingClientRect
function stubVisibleRects() {
  Element.prototype.getBoundingClientRect = () => ({
    top: 0, bottom: 100, left: 0, right: 0, width: 0, height: 100, x: 0, y: 0, toJSON() {}
  })
}
function restoreRects() {
  Element.prototype.getBoundingClientRect = origGetBoundingClientRect
}

// The min-scroll gate (later sections only tick once the reader has actually
// scrolled) reads window.scrollY. jsdom reports 0 — i.e. "at the very top".
// Tests that need the reader to have scrolled call setScrollY(); every test
// starts back at the top.
function setScrollY(y) {
  Object.defineProperty(window, 'scrollY', { value: y, configurable: true, writable: true })
}
beforeEach(() => setScrollY(0))

function lessonFixture(requiredSeconds = 17) {
  return {
    id: 'web-xss',
    title: 'XSS',
    category: 'web',
    parent: 'web-sqli',
    difficulty: 'medium',
    order: 8,
    tags: [],
    estimated_minutes: 40,
    summary: 's',
    sections: [
      { id: 'введение', title: 'Введение', markdown: 'привет', required_seconds: requiredSeconds },
      { id: 'теория', title: 'Теория', markdown: 'текст', required_seconds: 5 }
    ]
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

// Server-side read threshold mirrored by the mocked /progress/section response.
let serverThreshold = 17

describe('views/LessonView.vue — live reading indicator', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    stubVisibleRects()
    vi.stubGlobal('IntersectionObserver', MockIntersectionObserver)
    window.scrollTo = vi.fn()
    Object.defineProperty(document, 'hidden', { value: false, configurable: true })

    api.tree.mockResolvedValue({ categories: [], nodes: [], total: 0 })
    api.progress.mockResolvedValue({ user: { lessons: {}, activity: {} }, xp: 0, streak: 0, achievements: [] })
    api.lesson.mockResolvedValue(lessonFixture())
    serverThreshold = 17
    api.section.mockImplementation(({ seconds }) =>
      Promise.resolve({ read_seconds: seconds, read: seconds >= serverThreshold, completed: false, xp: 0 })
    )

    // Fake the intervals (so flushPromises' real setImmediate still works) AND
    // Date, so the Date.now()-based between-sections pause is deterministic.
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    restoreRects()
  })

  // Regression: the per-section counter used to read `serverSecs[s.id]` only,
  // so the number only changed when flush() posted to the server (every 5s) and
  // never ticked live. The visible text counter was replaced by a minimal ring
  // that fills from the live seconds; the numbers now live only in the tooltip.
  it('fills the per-section ring live every second without a server flush', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    const states = () => wrapper.findAll('.sec-state')
    const ringPct = (i) => wrapper.findAll('.sec-ring')[i].element.style.getPropertyValue('--p')
    expect(states().length).toBe(2)
    // No noisy "0с / 16с" text is rendered — the numbers are tooltip-only.
    expect(states()[0].text()).toBe('')
    expect(states()[0].attributes('title')).toBe('0с / 17с')
    expect(ringPct(0)).toBe('0')

    // Mark the first section as the visible/active one.
    ioCallback([{ target: { dataset: { sectionId: 'введение' } }, intersectionRatio: 0.5 }])
    await flushPromises()

    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(states()[0].attributes('title')).toBe('1с / 17с')
    // ~1/17 → 6% — the ring grows live, driven by the local accumulator.
    expect(ringPct(0)).toBe('6')
    // No server round-trip has happened yet (flush is every 2s) — the ring is live.
    expect(api.section).not.toHaveBeenCalled()

    wrapper.unmount()
  })

  // Regression: isRead only flipped after a server round-trip, delaying the ✓.
  it('shows the check optimistically once the threshold is reached', async () => {
    serverThreshold = 2
    api.lesson.mockResolvedValue(lessonFixture(2))
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    ioCallback([{ target: { dataset: { sectionId: 'введение' } }, intersectionRatio: 0.5 }])
    await flushPromises()

    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(wrapper.findAll('.sec-state')[0].attributes('title')).toBe('1с / 2с')
    expect(wrapper.findAll('.sec-ring')[0].element.style.getPropertyValue('--p')).toBe('50')

    vi.advanceTimersByTime(1000)
    await flushPromises()
    const read = wrapper.findAll('.sec-state')[0]
    expect(read.classes()).toContain('on')
    expect(read.attributes('title')).toBe('Прочитано')
    expect(read.find('.sec-check').exists()).toBe(true)
    expect(wrapper.findAll('.sec-ring')[0].element.style.getPropertyValue('--p')).toBe('100')
    // Progress was persisted promptly rather than waiting for the 2s flush.
    expect(api.section).toHaveBeenCalled()

    wrapper.unmount()
  })

  // Sequential rule: only the FIRST not-yet-read section (in document order)
  // may accrue time. A later section must NOT jump ahead while an earlier one
  // is still unread — even when it sits above the 60% line.
  it('accrues time only for the first unread section, never a later one', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    const states = () => wrapper.findAll('.sec-state')
    const secs = wrapper.findAll('.sec')
    // Both sections are on screen and above the 60% line.
    secs[0].element.getBoundingClientRect = () => ({
      top: 100, bottom: 600, left: 0, right: 0, width: 0, height: 500, x: 0, y: 100, toJSON() {}
    })
    secs[1].element.getBoundingClientRect = () => ({
      top: 120, bottom: 620, left: 0, right: 0, width: 0, height: 500, x: 0, y: 120, toJSON() {}
    })
    ioCallback([
      { target: { dataset: { sectionId: 'введение' } }, intersectionRatio: 0.6 },
      { target: { dataset: { sectionId: 'теория' } }, intersectionRatio: 0.5 }
    ])
    await flushPromises()

    vi.advanceTimersByTime(1000)
    await flushPromises()
    // Section 0 (first unread) ticks; section 1 is blocked despite being visible.
    expect(states()[0].attributes('title')).toBe('1с / 17с')
    expect(states()[1].attributes('title')).toBe('0с / 5с')

    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(states()[0].attributes('title')).toBe('2с / 17с')
    expect(states()[1].attributes('title')).toBe('0с / 5с')

    wrapper.unmount()
  })

  // The 60%-line rule still applies to the FIRST unread section: it accrues only
  // once its top has risen above 60% of the viewport (and it is still partially
  // visible, rect.bottom > 0). A block that merely appeared at the bottom does
  // NOT tick, and a later block never ticks ahead of the first unread one.
  it('ticks the first unread section only after its top crosses the 60% line', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    // The observer still fires on first-pixel visibility (drives the TOC highlight).
    expect(ioOptions.rootMargin).toBe('0px')
    expect(ioOptions.threshold).toContain(0)

    const states = () => wrapper.findAll('.sec-state')
    const secs = wrapper.findAll('.sec')
    // Viewport height 768 -> 60% line at 460.8px. The first unread section's top
    // (470) sits just BELOW the line; the later section is above it.
    secs[0].element.getBoundingClientRect = () => ({
      top: 470, bottom: 900, left: 0, right: 0, width: 0, height: 430, x: 0, y: 470, toJSON() {}
    })
    secs[1].element.getBoundingClientRect = () => ({
      top: 100, bottom: 600, left: 0, right: 0, width: 0, height: 500, x: 0, y: 100, toJSON() {}
    })
    ioCallback([
      { target: { dataset: { sectionId: 'введение' } }, intersectionRatio: 0.4 },
      { target: { dataset: { sectionId: 'теория' } }, intersectionRatio: 0.6 }
    ])
    await flushPromises()

    vi.advanceTimersByTime(1000)
    await flushPromises()
    // Nothing accrues: the first unread section is below the line, and the later
    // one must not jump ahead of it.
    expect(states()[0].attributes('title')).toBe('0с / 17с')
    expect(states()[1].attributes('title')).toBe('0с / 5с')

    // Scroll: the first unread section's top (400) now crosses above the line -> it starts.
    secs[0].element.getBoundingClientRect = () => ({
      top: 400, bottom: 830, left: 0, right: 0, width: 0, height: 430, x: 0, y: 400, toJSON() {}
    })
    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(states()[0].attributes('title')).toBe('1с / 17с')
    expect(states()[1].attributes('title')).toBe('0с / 5с')

    // A block scrolled entirely above the viewport (bottom <= 0) stops ticking,
    // even though its top is far above the 60% line.
    secs[0].element.getBoundingClientRect = () => ({
      top: -600, bottom: -50, left: 0, right: 0, width: 0, height: 550, x: 0, y: -600, toJSON() {}
    })
    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(states()[0].attributes('title')).toBe('1с / 17с')
    expect(states()[1].attributes('title')).toBe('0с / 5с')

    wrapper.unmount()
  })

  // Between-sections pause: after a section reaches "read", the next one only
  // starts accruing ~3.5s later (SECTION_PAUSE_MS).
  it('waits ~3.5s after a section is read before the next section starts', async () => {
    serverThreshold = 2
    api.lesson.mockResolvedValue(lessonFixture(2)) // section 0 needs 2s, section 1 needs 5s
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    // The reader has scrolled down (min-scroll gate satisfied) — the test is about
    // the between-sections pause, not about the "at the top" gate.
    setScrollY(200)

    const states = () => wrapper.findAll('.sec-state')
    const secs = wrapper.findAll('.sec')
    secs[0].element.getBoundingClientRect = () => ({
      top: 100, bottom: 600, left: 0, right: 0, width: 0, height: 500, x: 0, y: 100, toJSON() {}
    })
    secs[1].element.getBoundingClientRect = () => ({
      top: 120, bottom: 620, left: 0, right: 0, width: 0, height: 500, x: 0, y: 120, toJSON() {}
    })
    ioCallback([
      { target: { dataset: { sectionId: 'введение' } }, intersectionRatio: 0.6 },
      { target: { dataset: { sectionId: 'теория' } }, intersectionRatio: 0.5 }
    ])
    await flushPromises()

    // Fill section 0 to the read threshold (2s).
    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(states()[0].attributes('title')).toBe('1с / 2с')
    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(states()[0].classes()).toContain('on')

    // Section 1 stays blocked during the pause window (3s < 3.5s).
    vi.advanceTimersByTime(3000)
    await flushPromises()
    expect(states()[1].attributes('title')).toBe('0с / 5с')

    // The pause is 3.5s, but ticks are 1s apart, so section 1 first accrues on the
    // next tick after the pause elapses (~4s after section 0 became read).
    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(states()[1].attributes('title')).toBe('1с / 5с')

    wrapper.unmount()
  })

  // Min-scroll gate (FIX 2): a short first section can leave the next section
  // already above the 60% line at page open. At the very top (scrollY < 60px)
  // ONLY the first section may tick; a later section must wait until the reader
  // actually scrolls the page down.
  it('ticks only the first section at the very top; a later section waits for a real scroll', async () => {
    serverThreshold = 2
    api.lesson.mockResolvedValue(lessonFixture(2)) // short section 0 (2s), section 1 (5s)
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    const states = () => wrapper.findAll('.sec-state')
    const secs = wrapper.findAll('.sec')
    // Both sections are already above the 60% line at page open (short first one).
    secs[0].element.getBoundingClientRect = () => ({
      top: 100, bottom: 600, left: 0, right: 0, width: 0, height: 500, x: 0, y: 100, toJSON() {}
    })
    secs[1].element.getBoundingClientRect = () => ({
      top: 120, bottom: 620, left: 0, right: 0, width: 0, height: 500, x: 0, y: 120, toJSON() {}
    })
    ioCallback([
      { target: { dataset: { sectionId: 'введение' } }, intersectionRatio: 0.6 },
      { target: { dataset: { sectionId: 'теория' } }, intersectionRatio: 0.5 }
    ])
    await flushPromises()

    // scrollY = 0: the first section still ticks and becomes read.
    vi.advanceTimersByTime(2000)
    await flushPromises()
    expect(states()[0].classes()).toContain('on')

    // ...but section 1 must NOT start just because it is above the 60% line —
    // even long after the between-sections pause has elapsed.
    vi.advanceTimersByTime(4000)
    await flushPromises()
    expect(states()[1].attributes('title')).toBe('0с / 5с')

    // Once the reader really scrolls down, section 1 begins on the next tick.
    setScrollY(200)
    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(states()[1].attributes('title')).toBe('1с / 5с')

    wrapper.unmount()
  })
})

describe('views/LessonView.vue — reading pause', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    stubVisibleRects()
    vi.stubGlobal('IntersectionObserver', MockIntersectionObserver)
    window.scrollTo = vi.fn()
    Object.defineProperty(document, 'hidden', { value: false, configurable: true })

    api.tree.mockResolvedValue({ categories: [], nodes: [], total: 0 })
    api.progress.mockResolvedValue({ user: { lessons: {}, activity: {} }, xp: 0, streak: 0, achievements: [] })
    api.lesson.mockResolvedValue(lessonFixture())
    serverThreshold = 17
    api.section.mockImplementation(({ seconds }) =>
      Promise.resolve({ read_seconds: seconds, read: seconds >= serverThreshold, completed: false, xp: 0 })
    )

    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    restoreRects()
  })

  function key(k) {
    return document.dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true }))
  }

  it('Space freezes ticking + shows the pause glyph, Space resumes', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    ioCallback([{ target: { dataset: { sectionId: 'введение' } }, intersectionRatio: 0.5 }])
    await flushPromises()
    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(wrapper.findAll('.sec-state')[0].attributes('title')).toBe('1с / 17с')

    // Space -> pause.
    const ev = new KeyboardEvent('keydown', { key: ' ', bubbles: true, cancelable: true })
    document.dispatchEvent(ev)
    await flushPromises()
    expect(ev.defaultPrevented).toBe(true)
    expect(wrapper.find('.pause-badge').exists()).toBe(true)
    expect(wrapper.findAll('.sec-ring')[0].classes()).toContain('paused')
    expect(wrapper.find('.sec-pause').exists()).toBe(true)

    // While paused, the timer must NOT accrue.
    vi.advanceTimersByTime(3000)
    await flushPromises()
    expect(wrapper.findAll('.sec-state')[0].attributes('title')).toBe('1с / 17с')

    // Space again -> resume; ticking continues from where it froze.
    key(' ')
    await flushPromises()
    expect(wrapper.find('.pause-badge').exists()).toBe(false)
    expect(wrapper.find('.sec-pause').exists()).toBe(false)
    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(wrapper.findAll('.sec-state')[0].attributes('title')).toBe('2с / 17с')

    wrapper.unmount()
  })

  it('Escape also toggles pause', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    key('Escape')
    await flushPromises()
    expect(wrapper.find('.pause-badge').exists()).toBe(true)

    key('Escape')
    await flushPromises()
    expect(wrapper.find('.pause-badge').exists()).toBe(false)

    wrapper.unmount()
  })

  // Regression: the paused class was applied to EVERY ring, so already-READ
  // sections got desaturated to gray (filter: saturate) and lost their green +
  // check. Pause must only affect sections that are NOT yet read.
  it('keeps READ sections green with their check while paused', async () => {
    serverThreshold = 2
    api.lesson.mockResolvedValue(lessonFixture(2))
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    // Drive the first section to "read".
    ioCallback([{ target: { dataset: { sectionId: 'введение' } }, intersectionRatio: 0.5 }])
    await flushPromises()
    vi.advanceTimersByTime(1000)
    await flushPromises()
    vi.advanceTimersByTime(1000)
    await flushPromises()
    const states = wrapper.findAll('.sec-state')
    expect(states[0].classes()).toContain('on')

    key(' ')
    await flushPromises()

    const rings = wrapper.findAll('.sec-ring')
    // Read section: still green (on), check present, NO paused treatment.
    expect(states[0].classes()).toContain('on')
    expect(rings[0].classes()).not.toContain('paused')
    expect(states[0].find('.sec-check').exists()).toBe(true)
    expect(states[0].find('.sec-pause').exists()).toBe(false)
    // Unread section: gets the pause glyph.
    expect(rings[1].classes()).toContain('paused')
    expect(states[1].find('.sec-pause').exists()).toBe(true)

    wrapper.unmount()
  })

  it('ignores Space typed inside an input/textarea (typing notes works)', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    const ta = document.createElement('textarea')
    document.body.appendChild(ta)
    ta.dispatchEvent(new KeyboardEvent('keydown', { key: ' ', bubbles: true, cancelable: true }))
    await flushPromises()
    expect(wrapper.find('.pause-badge').exists()).toBe(false)

    ta.remove()
    wrapper.unmount()
  })

  it('keeps persisting accumulated seconds while paused (flush still runs)', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    ioCallback([{ target: { dataset: { sectionId: 'введение' } }, intersectionRatio: 0.5 }])
    await flushPromises()
    vi.advanceTimersByTime(1000)
    await flushPromises()

    key(' ')
    await flushPromises()
    // The 2s flush interval still fires and persists the 1s already accumulated.
    vi.advanceTimersByTime(2000)
    await flushPromises()
    expect(api.section).toHaveBeenCalledWith({ lesson_id: 'web-xss', section_id: 'введение', seconds: 1 })

    wrapper.unmount()
  })

  // Mobile: phones have no keyboard, so the reading strip carries an always-visible
  // pause/resume button. It shows ⏸ while running and ▶ when paused, and tapping it
  // toggles the same `paused` ref the Space/Esc shortcut uses.
  it('toggles pause via the always-visible strip button (⏸/▶)', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    const btn = () => wrapper.find('.pause-btn')
    expect(btn().exists()).toBe(true)
    // Running: glyph ⏸, no paused styling, aria-pressed=false.
    expect(btn().text()).toBe('⏸')
    expect(btn().classes()).not.toContain('pause-badge')
    expect(btn().attributes('aria-pressed')).toBe('false')

    await btn().trigger('click')
    await flushPromises()
    // Paused: glyph ▶, gets the pause-badge styling, timer frozen.
    expect(btn().text()).toBe('▶')
    expect(btn().classes()).toContain('pause-badge')
    expect(btn().attributes('aria-pressed')).toBe('true')
    expect(wrapper.find('.pause-badge').exists()).toBe(true)
    expect(wrapper.findAll('.sec-ring')[0].classes()).toContain('paused')

    await btn().trigger('click')
    await flushPromises()
    expect(btn().text()).toBe('⏸')
    expect(btn().classes()).not.toContain('pause-badge')
    expect(wrapper.find('.pause-badge').exists()).toBe(false)

    wrapper.unmount()
  })
})

describe('views/LessonView.vue — auto-pause on scroll', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    stubVisibleRects()
    vi.stubGlobal('IntersectionObserver', MockIntersectionObserver)
    window.scrollTo = vi.fn()
    Object.defineProperty(document, 'hidden', { value: false, configurable: true })

    api.tree.mockResolvedValue({ categories: [], nodes: [], total: 0 })
    api.progress.mockResolvedValue({ user: { lessons: {}, activity: {} }, xp: 0, streak: 0, achievements: [] })
    api.lesson.mockResolvedValue(lessonFixture())
    serverThreshold = 17
    // Faithful to the backend: /progress/section returns CUMULATIVE read_seconds,
    // not the delta it was sent. (The other describes echo the delta, which is fine
    // for their assertions, but a mid-window flush would clobber the accumulated
    // seconds and hide whether the timer actually resumed.)
    let cumulative = 0
    api.section.mockImplementation(({ seconds }) => {
      cumulative += seconds
      return Promise.resolve({ read_seconds: cumulative, read: cumulative >= serverThreshold, completed: false, xp: 0 })
    })

    // setTimeout/clearTimeout are needed for the ~1s scroll-stop debounce.
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'setTimeout', 'clearTimeout'] })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    restoreRects()
  })

  it('freezes the timer while scrolling and resumes ~1s after scrolling stops', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    ioCallback([{ target: { dataset: { sectionId: 'введение' } }, intersectionRatio: 0.5 }])
    await flushPromises()

    const title = () => wrapper.findAll('.sec-state')[0].attributes('title')
    const btn = () => wrapper.find('.pause-btn')

    // One second of calm reading.
    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(title()).toBe('1с / 17с')

    // Keep scrolling: re-fire before the ~1s debounce expires so the flag stays on.
    window.dispatchEvent(new Event('scroll'))
    await flushPromises()
    vi.advanceTimersByTime(800)
    window.dispatchEvent(new Event('scroll'))
    vi.advanceTimersByTime(800)
    window.dispatchEvent(new Event('scroll'))
    vi.advanceTimersByTime(800)
    await flushPromises()
    // ~2.4s of scrolling elapsed, but NO reading time accrued.
    expect(title()).toBe('1с / 17с')
    // Shown as a temporary (auto) pause, NOT a manual one.
    expect(btn().classes()).toContain('auto-paused')
    expect(btn().classes()).not.toContain('pause-badge')

    // Scrolling stops: after the ~1s debounce the timer auto-resumes.
    vi.advanceTimersByTime(200) // debounce fires -> scrolling=false
    await flushPromises()
    expect(title()).toBe('1с / 17с') // still no tick yet
    vi.advanceTimersByTime(1000) // next tick accrues again
    await flushPromises()
    expect(title()).toBe('2с / 17с')
    expect(btn().classes()).not.toContain('auto-paused')

    wrapper.unmount()
  })

  it('does not auto-resume a MANUAL pause when scrolling stops', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    ioCallback([{ target: { dataset: { sectionId: 'введение' } }, intersectionRatio: 0.5 }])
    await flushPromises()
    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(wrapper.findAll('.sec-state')[0].attributes('title')).toBe('1с / 17с')

    // Manual pause via the button.
    await wrapper.find('.pause-btn').trigger('click')
    await flushPromises()
    expect(wrapper.find('.pause-btn').classes()).toContain('pause-badge')

    // User scrolls and stops: the auto-pause must NOT lift the manual pause.
    window.dispatchEvent(new Event('scroll'))
    await flushPromises()
    vi.advanceTimersByTime(2000) // debounce fires + several ticks
    await flushPromises()
    expect(wrapper.findAll('.sec-state')[0].attributes('title')).toBe('1с / 17с')
    expect(wrapper.find('.pause-btn').classes()).toContain('pause-badge')

    // Still paused until the user taps resume.
    await wrapper.find('.pause-btn').trigger('click')
    await flushPromises()
    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(wrapper.findAll('.sec-state')[0].attributes('title')).toBe('2с / 17с')

    wrapper.unmount()
  })

  // FIX 1: the auto-pause must work on DESKTOP too. Desktop scrolling arrives as
  // `wheel` events (mouse wheel / trackpad, incl. momentum) — the listener is on
  // window, so wheel-only activity must freeze the timer and resume ~1s after it
  // stops, exactly like touch.
  it('pauses accrual on DESKTOP wheel scrolling (not only touch/scroll)', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    ioCallback([{ target: { dataset: { sectionId: 'введение' } }, intersectionRatio: 0.5 }])
    await flushPromises()

    const title = () => wrapper.findAll('.sec-state')[0].attributes('title')
    const btn = () => wrapper.find('.pause-btn')

    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(title()).toBe('1с / 17с')

    // Desktop wheel: fire ONLY `wheel` events (no touchmove, no explicit scroll).
    window.dispatchEvent(new Event('wheel'))
    vi.advanceTimersByTime(800)
    window.dispatchEvent(new Event('wheel'))
    vi.advanceTimersByTime(800)
    window.dispatchEvent(new Event('wheel'))
    vi.advanceTimersByTime(800)
    await flushPromises()
    // ~2.4s of desktop scrolling elapsed — NO reading time accrued.
    expect(title()).toBe('1с / 17с')
    expect(btn().classes()).toContain('auto-paused')

    // Stop scrolling: ~1s later the timer auto-resumes.
    vi.advanceTimersByTime(200) // debounce fires -> scrolling=false
    await flushPromises()
    vi.advanceTimersByTime(1000) // next tick accrues again
    await flushPromises()
    expect(title()).toBe('2с / 17с')
    expect(btn().classes()).not.toContain('auto-paused')

    wrapper.unmount()
  })
})

describe('views/LessonView.vue — smart cross-links', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    stubVisibleRects()
    vi.stubGlobal('IntersectionObserver', MockIntersectionObserver)
    window.scrollTo = vi.fn()
    Object.defineProperty(document, 'hidden', { value: false, configurable: true })

    api.tree.mockResolvedValue({
      categories: [],
      nodes: [
        { id: 'web-xss', title: 'XSS', parent: '', depth: 0, estimated_minutes: 40, tags: [] },
        { id: 'web-host-header', title: 'Host header и X-Forwarded атаки', parent: 'web-xss', depth: 1, estimated_minutes: 34, tags: ['host-header'] }
      ],
      total: 2
    })
    api.progress.mockResolvedValue({ user: { lessons: {}, activity: {} }, xp: 0, streak: 0, achievements: [] })
    api.lesson.mockResolvedValue({
      id: 'web-xss', title: 'XSS', category: 'web', parent: '', difficulty: 'medium',
      tags: [], estimated_minutes: 40, summary: 's',
      sections: [{ id: 'введение', title: 'Введение', markdown: 'Тут про **host header injection** и всё.', required_seconds: 17 }]
    })
    serverThreshold = 17
    api.section.mockImplementation(({ seconds }) =>
      Promise.resolve({ read_seconds: seconds, read: seconds >= serverThreshold, completed: false, xp: 0 })
    )

    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    restoreRects()
  })

  it('turns a prose mention into a link pointing at the target lesson', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    const link = wrapper.find('.md .topic-link')
    expect(link.exists()).toBe(true)
    expect(link.text()).toBe('host header')
    expect(link.attributes('href')).toBe('/lesson/web-host-header')
    expect(link.attributes('data-topic-id')).toBe('web-host-header')
    // The surrounding prose is preserved verbatim.
    expect(wrapper.find('.md').text()).toContain('host header injection')

    wrapper.unmount()
  })

  it('shows the shortest-path + distance tooltip on hover', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    await wrapper.find('.md .topic-link').trigger('mouseover')
    await flushPromises()

    const tip = wrapper.find('.topic-tip')
    expect(tip.exists()).toBe(true)
    expect(tip.find('.tt-title').text()).toBe('Host header и X-Forwarded атаки')
    // Breadcrumb runs from the current lesson to the target.
    const crumbs = tip.findAll('.tt-crumb').map((c) => c.text())
    expect(crumbs).toEqual(['XSS', 'Host header и X-Forwarded атаки'])
    expect(tip.find('.tt-dist').text()).toContain('нужно пройти 1 урок')
    expect(tip.find('.tt-dist').text()).toContain('~34 мин')

    wrapper.unmount()
  })

  it('navigates to the target lesson on click (router.push)', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    await wrapper.find('.md .topic-link').trigger('click')
    expect(routerPush).toHaveBeenCalledWith('/lesson/web-host-header')

    wrapper.unmount()
  })
})

describe('views/LessonView.vue — quiz progress drives the section', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    stubVisibleRects()
    vi.stubGlobal('IntersectionObserver', MockIntersectionObserver)
    window.scrollTo = vi.fn()
    Object.defineProperty(document, 'hidden', { value: false, configurable: true })

    api.tree.mockResolvedValue({ categories: [], nodes: [], total: 0 })
    api.progress.mockResolvedValue({ user: { lessons: {}, activity: {} }, xp: 0, streak: 0, achievements: [] })
    api.lesson.mockResolvedValue({
      id: 'web-xss', title: 'XSS', category: 'web', parent: '', difficulty: 'medium',
      tags: [], estimated_minutes: 40, summary: 's',
      sections: [
        { id: 'введение', title: 'Введение', markdown: 'привет', required_seconds: 17 },
        { id: 'квиз', title: 'Квиз', markdown: '', required_seconds: 10 }
      ],
      quiz: [
        { text: 'Q1?', options: ['a', 'b'], answer: 0 },
        { text: 'Q2?', options: ['c', 'd'], answer: 1 }
      ]
    })
    serverThreshold = 10
    api.section.mockImplementation(({ seconds }) =>
      Promise.resolve({ read_seconds: seconds, read: seconds >= serverThreshold, completed: false, xp: 0 })
    )
    api.quiz.mockResolvedValue({ quiz_best: 2, quiz_total: 2, xp: 20 })

    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    restoreRects()
  })

  const ringPct = (w, i) => w.findAll('.sec-ring')[i].element.style.getPropertyValue('--p')

  // Regression: the quiz section used to accrue progress from the time-based
  // tick() just like a prose section, so its ring filled by scrolling/waiting.
  it('does not fill the quiz ring from the reading timer', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    // Both sections sit above the 60% line (stub rects) — 'введение' ticks by
    // time, but the quiz section must NOT accrue any reading seconds.
    vi.advanceTimersByTime(3000)
    await flushPromises()
    expect(wrapper.findAll('.sec-state')[0].attributes('title')).toBe('3с / 17с')
    expect(ringPct(wrapper, 0)).toBe('18') // 3/17
    expect(wrapper.findAll('.sec-state')[1].attributes('title')).toBe('Отвечено: 0/2')
    expect(ringPct(wrapper, 1)).toBe('0')

    wrapper.unmount()
  })

  it('fills the quiz ring as options are answered and marks it read when done', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    const opts = wrapper.findAll('.option') // q0: a,b  q1: c,d
    await opts[0].trigger('click')
    await flushPromises()
    expect(wrapper.findAll('.sec-state')[1].attributes('title')).toBe('Отвечено: 1/2')
    expect(ringPct(wrapper, 1)).toBe('50')

    await opts[3].trigger('click')
    await flushPromises()
    const state = wrapper.findAll('.sec-state')[1]
    expect(state.classes()).toContain('on')
    expect(state.find('.sec-check').exists()).toBe(true)
    expect(ringPct(wrapper, 1)).toBe('100')
    // Completion is persisted so the backend records the section as read.
    expect(api.section).toHaveBeenCalledWith({ lesson_id: 'web-xss', section_id: 'квиз', seconds: 10 })

    wrapper.unmount()
  })

  it('keeps the quiz ring answerable while reading is paused', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    document.dispatchEvent(new KeyboardEvent('keydown', { key: ' ', bubbles: true, cancelable: true }))
    await flushPromises()
    const rings = wrapper.findAll('.sec-ring')
    expect(rings[0].classes()).toContain('paused') // prose reading frozen
    expect(rings[1].classes()).not.toContain('paused') // quiz stays interactive

    await wrapper.findAll('.option')[0].trigger('click')
    await flushPromises()
    expect(ringPct(wrapper, 1)).toBe('50')

    wrapper.unmount()
  })
})

describe('views/LessonView.vue — reading speed multiplier', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
    stubVisibleRects()
    vi.stubGlobal('IntersectionObserver', MockIntersectionObserver)
    window.scrollTo = vi.fn()
    Object.defineProperty(document, 'hidden', { value: false, configurable: true })

    api.tree.mockResolvedValue({ categories: [], nodes: [], total: 0 })
    api.progress.mockResolvedValue({ user: { lessons: {}, activity: {} }, xp: 0, streak: 0, achievements: [] })
    api.lesson.mockResolvedValue(lessonFixture())
    serverThreshold = 17
    api.section.mockImplementation(({ seconds }) =>
      Promise.resolve({ read_seconds: seconds, read: seconds >= serverThreshold, completed: false, xp: 0 })
    )

    // setTimeout/clearTimeout are still faked (reading timers / scroll debounce),
    // but the speed slider no longer uses a press-and-hold timer.
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'setTimeout', 'clearTimeout'] })
  })

  afterEach(() => {
    localStorage.clear()
    vi.useRealTimers()
    vi.unstubAllGlobals()
    restoreRects()
  })

  // Press on a per-section ring: pointerdown opens the slider IMMEDIATELY.
  function holdRing(wrapper, i = 0) {
    const el = wrapper.findAll('.sec-ring')[i].element
    el.dispatchEvent(new MouseEvent('pointerdown', { bubbles: true, button: 0 }))
  }
  // The vertical track is centered: its top edge sits 110px above the viewport
  // middle (SPEED_TRACK_H / 2 = 110 for the 220px track).
  const trackTop = () => (window.innerHeight || 768) / 2 - 110
  const dragTo = (clientY) => window.dispatchEvent(new MouseEvent('pointermove', { clientY }))
  const release = () => window.dispatchEvent(new MouseEvent('pointerup'))

  it('opens the vertical slider immediately on pointerdown (no hold delay)', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()
    expect(wrapper.find('.speed-overlay').exists()).toBe(false)

    holdRing(wrapper)
    await flushPromises()
    // No timer advance: the slider is already open on the very next tick.
    expect(wrapper.find('.speed-overlay').exists()).toBe(true)
    expect(wrapper.find('.speed-val').text()).toBe('x1.0') // default multiplier

    wrapper.unmount()
  })

  it('a plain tap (no drag) keeps the slider open; a backdrop tap closes it', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    holdRing(wrapper)
    await flushPromises()
    expect(wrapper.find('.speed-overlay').exists()).toBe(true)

    // Release with no movement -> treated as a tap, slider stays open (no flash).
    release()
    vi.advanceTimersByTime(2000)
    await flushPromises()
    expect(wrapper.find('.speed-overlay').exists()).toBe(true)

    // Tapping the backdrop closes it.
    await wrapper.find('.speed-overlay').trigger('pointerdown')
    await flushPromises()
    expect(wrapper.find('.speed-overlay').exists()).toBe(false)

    wrapper.unmount()
  })

  it('drag up = x2.0 (max), drag down = x0.5 (min), middle = x1.3', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()
    holdRing(wrapper)
    await flushPromises()

    dragTo(trackTop()) // very top -> max
    await flushPromises()
    expect(wrapper.find('.speed-val').text()).toBe('x2.0')

    dragTo(trackTop() + 220) // very bottom -> min
    await flushPromises()
    expect(wrapper.find('.speed-val').text()).toBe('x0.5')

    dragTo(trackTop() + 110) // middle -> 1.25 -> rounds to x1.3
    await flushPromises()
    expect(wrapper.find('.speed-val').text()).toBe('x1.3')

    wrapper.unmount()
  })

  // The multiplier scales the ACCRUAL of every section ring: x2 credits twice
  // the reading seconds per tick, so the ring fills twice as fast.
  it('applies the multiplier to the accrual (x2 credits twice the seconds)', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    holdRing(wrapper)
    await flushPromises()
    dragTo(trackTop()) // x2.0
    await flushPromises()
    release() // releasing a drag closes the slider
    await flushPromises()
    expect(wrapper.find('.speed-overlay').exists()).toBe(false)

    vi.advanceTimersByTime(1000) // a single 1s tick
    await flushPromises()
    expect(wrapper.findAll('.sec-state')[0].attributes('title')).toBe('2с / 17с')

    wrapper.unmount()
  })

  it('x0.5 halves the accrual (one tick = 0.5s)', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()

    holdRing(wrapper)
    await flushPromises()
    dragTo(trackTop() + 220) // x0.5
    await flushPromises()
    release()
    await flushPromises()

    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(wrapper.findAll('.sec-state')[0].attributes('title')).toBe('0.5с / 17с')

    wrapper.unmount()
  })

  it('persists the multiplier in localStorage and restores it on a fresh mount', async () => {
    const wrapper = mountView()
    await flushPromises()
    await flushPromises()
    holdRing(wrapper)
    await flushPromises()
    dragTo(trackTop()) // x2.0
    await flushPromises()
    release()
    await flushPromises()
    expect(localStorage.getItem('lt-reading-speed')).toBe('2')
    wrapper.unmount()

    const w2 = mountView()
    await flushPromises()
    await flushPromises()
    holdRing(w2)
    await flushPromises()
    expect(w2.find('.speed-val').text()).toBe('x2.0')
    w2.unmount()
  })
})
