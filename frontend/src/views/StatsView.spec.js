import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'

vi.mock('../api/client', () => ({
  api: {
    tree: vi.fn(),
    progress: vi.fn(),
    exportProgress: vi.fn(),
    importProgress: vi.fn()
  }
}))

import StatsView from './StatsView.vue'
import { api } from '../api/client'

// 60 synthetic achievements across two themes, half unlocked.
function mkAch(n) {
  return Array.from({ length: n }, (_, i) => ({
    id: 'a' + i,
    theme: i < 3 ? 'Чтение' : 'Квизы',
    title: 'T' + i,
    desc: 'D' + i,
    icon: '🌟',
    unlocked: i % 2 === 0,
    progress: 50
  }))
}

describe('StatsView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    api.tree.mockResolvedValue({ categories: [], nodes: [], total: 0 })
    api.progress.mockResolvedValue({
      user: { lessons: {}, activity: {} },
      xp: 120,
      streak: 3,
      achievements: mkAch(60),
      stats: {
        lessons_total: 100,
        lessons_completed: 10,
        lessons_started: 12,
        lessons_remaining: 90,
        total_read_human: '2 ч',
        avg_read_human: '12 мин',
        current_streak: 3,
        longest_streak: 7,
        active_days: 9,
        xp: 120,
        level: 2,
        level_progress: 0.4,
        xp_to_next: 380,
        quiz: { answered: 50, correct: 45, accuracy: 90, perfect: 5, attempts: 9, fails: 2, avg_score: 88, best_score: 5 },
        categories: [{ slug: 'web', name: 'Web', color: '#38bdf8', icon: '🌐', total: 10, done: 5, pct: 50 }],
        difficulties: [{ key: 'easy', label: 'Легко', color: '#84cc16', total: 4, done: 2, pct: 50 }],
        most_progressed_category: { slug: 'web', name: 'Web', pct: 50 },
        least_progressed_category: { slug: 'web', name: 'Web', pct: 50 },
        recent: [
          { id: 'web-xss', title: 'XSS', category: 'web', icon: '🌐', updated_at: 1700000000, completed: true, sections_read: 3, read_seconds: 200 }
        ]
      }
    })
  })

  it('renders all achievements grouped by theme', async () => {
    const w = mount(StatsView)
    await flushPromises()
    expect(w.findAll('.ach').length).toBe(60)
    expect(w.findAll('.ach-group').length).toBe(2)
  })

  it('shows quiz accuracy and counts from stats', async () => {
    const w = mount(StatsView)
    await flushPromises()
    expect(w.text()).toContain('90%')
    expect(w.text()).toContain('45')
    expect(w.text()).toContain('2 ч')
  })

  it('renders category and difficulty breakdowns', async () => {
    const w = mount(StatsView)
    await flushPromises()
    expect(w.findAll('.cat-card').length).toBe(1)
    expect(w.findAll('.diff-row').length).toBe(1)
    expect(w.findAll('.recent-row').length).toBe(1)
  })

  it('filters to locked achievements', async () => {
    const w = mount(StatsView)
    await flushPromises()
    const btns = w.findAll('.ach-filter .btn')
    expect(btns.length).toBe(3)
    await btns[2].trigger('click') // Закрытые
    await flushPromises()
    expect(w.findAll('.ach').length).toBe(30)
  })
})
