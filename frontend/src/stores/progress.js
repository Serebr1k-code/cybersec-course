import { defineStore } from 'pinia'
import { api } from '../api/client'

export const useProgressStore = defineStore('progress', {
  state: () => ({
    user: { lessons: {}, activity: {} },
    xp: 0,
    streak: 0,
    achievements: [],
    stats: null,
    loaded: false,
    lastLesson: localStorage.getItem('lt_last_lesson') || null
  }),
  getters: {
    // Прогресс урока как доля прочитанных секций (0..1).
    lessonRatio: (s) => (id, totalSections) => {
      const lp = s.user.lessons?.[id]
      if (!lp || !lp.sections) return lp?.completed ? 1 : 0
      const total = totalSections || Object.keys(lp.sections).length || 0
      if (!total) return 0
      let read = 0
      for (const k in lp.sections) if (lp.sections[k].read) read++
      return Math.min(1, read / total)
    },
    lessonRead: (s) => (id) => {
      const lp = s.user.lessons?.[id]
      if (!lp) return false
      return lp.completed || (lp.sections && Object.values(lp.sections).some((x) => x.read))
    },
    isCompleted: (s) => (id) => !!s.user.lessons?.[id]?.completed,
    level: (s) => Math.floor(s.xp / 500) + 1,
    levelProgress: (s) => (s.xp % 500) / 500,
    xpToNext: (s) => 500 - (s.xp % 500),
    notes: (s) => (id) => s.user.lessons?.[id]?.notes || '',
    quiz: (s) => (id) => {
      const lp = s.user.lessons?.[id]
      return lp ? { best: lp.quiz_best || 0, total: lp.quiz_total || 0 } : { best: 0, total: 0 }
    }
  },
  actions: {
    async load() {
      try {
        const p = await api.progress()
        this.user = p.user || { lessons: {}, activity: {} }
        this.xp = p.xp || 0
        this.streak = p.streak || 0
        this.achievements = p.achievements || []
        this.stats = p.stats || null
        this.loaded = true
      } catch (e) {
        console.warn('progress load failed', e)
      }
    },
    setLastLesson(id) {
      this.lastLesson = id
      localStorage.setItem('lt_last_lesson', id)
    },
    async pushSection(lesson_id, section_id, seconds) {
      try {
        const r = await api.section({ lesson_id, section_id, seconds })
        const lp = (this.user.lessons[lesson_id] ||= { sections: {} })
        if (!lp.sections) lp.sections = {}
        lp.sections[section_id] = { read_seconds: r.read_seconds, read: r.read, updated_at: Date.now() / 1000 }
        lp.completed = r.completed
        this.xp = r.xp
        return r
      } catch (e) {
        console.warn('section push failed', e)
      }
    },
    async submitQuiz(lesson_id, score, total) {
      const r = await api.quiz({ lesson_id, score, total })
      const lp = (this.user.lessons[lesson_id] ||= { sections: {} })
      lp.quiz_best = r.quiz_best
      lp.quiz_total = r.quiz_total
      this.xp = r.xp
      return r
    },
    async saveNotes(lesson_id, text) {
      await api.notes(lesson_id, text)
      const lp = (this.user.lessons[lesson_id] ||= { sections: {} })
      lp.notes = text
    },
    async complete(lesson_id) {
      const r = await api.complete(lesson_id)
      const lp = (this.user.lessons[lesson_id] ||= { sections: {} })
      lp.completed = true
      // Сервер возвращает заполненные секции — синхронизируем локально,
      // чтобы дерево сразу показало 100% заливку после отметки из урока.
      if (r && r.sections) lp.sections = r.sections
      this.xp = r.xp
    },
    // Отметить/снять отметку «пройден» (контекстное меню дерева).
    // Сервер возвращает актуальные секции: при отметке «пройден» все они
    // прочитаны (зелёная заливка = 100%), при снятии — очищены (0%).
    // Локально синхронизируем секции, чтобы дерево и рёбра перекрасились сразу.
    async setCompleted(lesson_id, completed) {
      const r = await api.complete(lesson_id, completed)
      const lp = (this.user.lessons[lesson_id] ||= { sections: {} })
      lp.completed = !!completed
      if (r && r.sections) {
        lp.sections = r.sections
      } else if (!completed) {
        lp.sections = {}
      }
      if (r && typeof r.xp === 'number') this.xp = r.xp
      return r
    }
  }
})
