import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useProgressStore } from './progress'
import { api } from '../api/client'

vi.mock('../api/client', () => ({
  api: {
    progress: vi.fn(),
    section: vi.fn(),
    quiz: vi.fn(),
    notes: vi.fn(),
    complete: vi.fn()
  }
}))

describe('stores/progress', () => {
  beforeEach(() => {
    localStorage.clear()
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  describe('getters', () => {
    it('lessonRatio returns 0 when the lesson is unknown', () => {
      const s = useProgressStore()
      expect(s.lessonRatio('nope', 4)).toBe(0)
    })

    it('lessonRatio returns 1 for a completed lesson without section data', () => {
      const s = useProgressStore()
      s.user.lessons.x = { completed: true }
      expect(s.lessonRatio('x', 4)).toBe(1)
    })

    it('lessonRatio = read sections / total sections', () => {
      const s = useProgressStore()
      s.user.lessons.x = { sections: { s1: { read: true }, s2: { read: false }, s3: { read: true } } }
      expect(s.lessonRatio('x', 4)).toBe(0.5)
      expect(s.lessonRatio('x')).toBeCloseTo(2 / 3)
    })

    it('lessonRatio is clamped to 1', () => {
      const s = useProgressStore()
      s.user.lessons.x = { sections: { s1: { read: true }, s2: { read: true } } }
      expect(s.lessonRatio('x', 1)).toBe(1)
    })

    it('lessonRatio returns 0 when there is no section info', () => {
      const s = useProgressStore()
      s.user.lessons.x = { sections: {} }
      expect(s.lessonRatio('x', 0)).toBe(0)
    })

    it('isCompleted reflects the completed flag', () => {
      const s = useProgressStore()
      s.user.lessons.x = { completed: true }
      expect(s.isCompleted('x')).toBe(true)
      expect(s.isCompleted('y')).toBe(false)
    })

    it('lessonRead is true when completed or any section read', () => {
      const s = useProgressStore()
      s.user.lessons.a = { completed: true }
      s.user.lessons.b = { sections: { s1: { read: false }, s2: { read: true } } }
      s.user.lessons.c = { sections: { s1: { read: false } } }
      expect(s.lessonRead('a')).toBe(true)
      expect(s.lessonRead('b')).toBe(true)
      expect(s.lessonRead('c')).toBe(false)
      expect(s.lessonRead('zzz')).toBe(false)
    })

    it('level / levelProgress / xpToNext derive from xp', () => {
      const s = useProgressStore()
      s.xp = 0
      expect(s.level).toBe(1)
      expect(s.levelProgress).toBe(0)
      expect(s.xpToNext).toBe(500)
      s.xp = 499
      expect(s.level).toBe(1)
      expect(s.xpToNext).toBe(1)
      s.xp = 500
      expect(s.level).toBe(2)
      expect(s.levelProgress).toBe(0)
      s.xp = 1250
      expect(s.level).toBe(3)
      expect(s.levelProgress).toBe(0.5)
    })

    it('quiz getter returns best/total or defaults', () => {
      const s = useProgressStore()
      s.user.lessons.x = { quiz_best: 4, quiz_total: 5 }
      expect(s.quiz('x')).toEqual({ best: 4, total: 5 })
      expect(s.quiz('missing')).toEqual({ best: 0, total: 0 })
    })

    it('notes getter returns the stored note or empty string', () => {
      const s = useProgressStore()
      s.user.lessons.x = { notes: 'hi' }
      expect(s.notes('x')).toBe('hi')
      expect(s.notes('missing')).toBe('')
    })
  })

  describe('actions', () => {
    it('load() populates user, xp, streak, achievements', async () => {
      const s = useProgressStore()
      api.progress.mockResolvedValue({
        user: { lessons: { a: { completed: true } }, activity: {} },
        xp: 120,
        streak: 3,
        achievements: ['first'],
        stats: { quiz: { accuracy: 80 } }
      })
      await s.load()
      expect(s.xp).toBe(120)
      expect(s.streak).toBe(3)
      expect(s.achievements).toEqual(['first'])
      expect(s.stats).toEqual({ quiz: { accuracy: 80 } })
      expect(s.loaded).toBe(true)
      expect(s.user.lessons.a.completed).toBe(true)
    })

    it('load() defaults stats to null when the backend omits them', async () => {
      const s = useProgressStore()
      api.progress.mockResolvedValue({ user: { lessons: {}, activity: {} }, xp: 0, streak: 0, achievements: [] })
      await s.load()
      expect(s.stats).toBeNull()
    })

    it('load() falls back to defaults on failure and warns', async () => {
      const s = useProgressStore()
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
      api.progress.mockRejectedValue(new Error('nope'))
      await s.load()
      expect(s.loaded).toBe(false)
      expect(warn).toHaveBeenCalled()
      warn.mockRestore()
    })

    it('setLastLesson persists to localStorage', () => {
      const s = useProgressStore()
      s.setLastLesson('lesson-9')
      expect(s.lastLesson).toBe('lesson-9')
      expect(localStorage.getItem('lt_last_lesson')).toBe('lesson-9')
    })

    it('pushSection() records the section, completion and xp', async () => {
      const s = useProgressStore()
      api.section.mockResolvedValue({ read_seconds: 30, read: true, completed: false, xp: 5 })
      const r = await s.pushSection('l1', 'sec1', 30)
      expect(api.section).toHaveBeenCalledWith({ lesson_id: 'l1', section_id: 'sec1', seconds: 30 })
      expect(r.xp).toBe(5)
      expect(s.xp).toBe(5)
      expect(s.user.lessons.l1.sections.sec1.read).toBe(true)
      expect(s.user.lessons.l1.sections.sec1.read_seconds).toBe(30)
      expect(s.user.lessons.l1.completed).toBe(false)
    })

    it('pushSection() creates a lessons entry that has no sections yet', async () => {
      const s = useProgressStore()
      // Simulate a lesson entry that exists without a sections map.
      s.user.lessons.l2 = {}
      api.section.mockResolvedValue({ read_seconds: 10, read: true, completed: true, xp: 40 })
      await s.pushSection('l2', 's1', 10)
      expect(s.user.lessons.l2.sections.s1.read).toBe(true)
      expect(s.user.lessons.l2.completed).toBe(true)
    })

    it('pushSection() swallows API errors', async () => {
      const s = useProgressStore()
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
      api.section.mockRejectedValue(new Error('down'))
      const r = await s.pushSection('l1', 's1', 1)
      expect(r).toBeUndefined()
      expect(warn).toHaveBeenCalled()
      warn.mockRestore()
    })

    it('submitQuiz() sends args and stores best/total/xp', async () => {
      const s = useProgressStore()
      api.quiz.mockResolvedValue({ quiz_best: 3, quiz_total: 5, xp: 50 })
      const r = await s.submitQuiz('l1', 3, 5)
      expect(api.quiz).toHaveBeenCalledWith({ lesson_id: 'l1', score: 3, total: 5 })
      expect(r.xp).toBe(50)
      expect(s.xp).toBe(50)
      expect(s.user.lessons.l1.quiz_best).toBe(3)
      expect(s.user.lessons.l1.quiz_total).toBe(5)
    })

    it('saveNotes() persists the note locally', async () => {
      const s = useProgressStore()
      api.notes.mockResolvedValue('ok')
      await s.saveNotes('l1', 'my note')
      expect(api.notes).toHaveBeenCalledWith('l1', 'my note')
      expect(s.user.lessons.l1.notes).toBe('my note')
    })

    it('complete() marks the lesson completed and updates xp', async () => {
      const s = useProgressStore()
      api.complete.mockResolvedValue({ xp: 99 })
      await s.complete('l1')
      expect(api.complete).toHaveBeenCalledWith('l1')
      expect(s.user.lessons.l1.completed).toBe(true)
      expect(s.xp).toBe(99)
    })

    it('complete() syncs the filled sections returned by the server', async () => {
      const s = useProgressStore()
      api.complete.mockResolvedValue({ xp: 40, sections: { s1: { read: true }, s2: { read: true } } })
      await s.complete('l1')
      expect(s.user.lessons.l1.completed).toBe(true)
      expect(s.user.lessons.l1.sections).toEqual({ s1: { read: true }, s2: { read: true } })
    })

    it('setCompleted() marks and unmarks a lesson, syncing sections + xp', async () => {
      const s = useProgressStore()
      // Marking complete fills every section from the server response (100%).
      api.complete.mockResolvedValue({
        completed: true,
        xp: 60,
        sections: { s1: { read: true }, s2: { read: true } }
      })
      await s.setCompleted('l1', true)
      expect(api.complete).toHaveBeenCalledWith('l1', true)
      expect(s.user.lessons.l1.completed).toBe(true)
      expect(s.user.lessons.l1.sections).toEqual({ s1: { read: true }, s2: { read: true } })
      expect(s.xp).toBe(60)

      // Unmarking clears the sections locally too (0% fill).
      api.complete.mockResolvedValue({ completed: false, xp: 0, sections: {} })
      await s.setCompleted('l1', false)
      expect(api.complete).toHaveBeenCalledWith('l1', false)
      expect(s.user.lessons.l1.completed).toBe(false)
      expect(s.user.lessons.l1.sections).toEqual({})
      expect(s.xp).toBe(0)
    })

    it('setCompleted(false) clears sections even if the API omits them', async () => {
      const s = useProgressStore()
      s.user.lessons.l1 = { completed: true, sections: { s1: { read: true } } }
      api.complete.mockResolvedValue({ completed: false, xp: 0 })
      await s.setCompleted('l1', false)
      expect(s.user.lessons.l1.completed).toBe(false)
      expect(s.user.lessons.l1.sections).toEqual({})
    })
  })
})
