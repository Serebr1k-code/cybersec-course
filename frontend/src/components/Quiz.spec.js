import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import Quiz from './Quiz.vue'
import { useProgressStore } from '../stores/progress'

vi.mock('../api/client', () => ({
  api: {
    progress: vi.fn(),
    section: vi.fn(),
    quiz: vi.fn(),
    notes: vi.fn(),
    complete: vi.fn()
  }
}))

const QUESTIONS = [
  { text: 'Что такое SQLi?', options: ['Спорт', 'Инъекция в SQL-запрос', 'Вёрстка'], answer: 1, explanation: 'SQLi — инъекция в SQL-запрос.' },
  { text: 'Инструмент фаззинга?', options: ['ffuf', 'exiftool'], answer: 0, explanation: 'ffuf — фаззер.' }
]

function factory(questions = QUESTIONS, priorLesson = null) {
  const pinia = createPinia()
  setActivePinia(pinia)
  const store = useProgressStore()
  if (priorLesson) store.user.lessons.l1 = priorLesson
  const wrapper = mount(Quiz, {
    props: { lessonId: 'l1', questions },
    global: { plugins: [pinia] }
  })
  return { wrapper, store }
}

const optionButtons = (w) => w.findAll('.option')
const resetBtn = (w) => w.findAll('button').find((b) => b.text().includes('Пройти заново'))
const submitBtn = (w) => w.findAll('button').find((b) => b.text().includes('Проверить'))

describe('components/Quiz.vue', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders every question with its options', () => {
    const { wrapper } = factory()
    expect(wrapper.findAll('.question').length).toBe(2)
    expect(wrapper.text()).toContain('Что такое SQLi?')
    expect(wrapper.text()).toContain('Инъекция в SQL-запрос')
    expect(optionButtons(wrapper).length).toBe(5) // 3 + 2
  })

  it('shows A/B/C option markers', () => {
    const { wrapper } = factory()
    const markers = optionButtons(wrapper).map((b) => b.find('.marker').text())
    expect(markers).toEqual(['A', 'B', 'C', 'A', 'B'])
  })

  it('has no batch-submit button (per-question feedback only)', () => {
    const { wrapper } = factory()
    expect(submitBtn(wrapper)).toBeUndefined()
    expect(wrapper.text()).not.toContain('Проверить ответы')
  })

  it('immediately marks a correct pick green and shows the explanation', async () => {
    const { wrapper } = factory()
    await optionButtons(wrapper)[1].trigger('click') // correct q0
    expect(optionButtons(wrapper)[1].classes()).toContain('correct')
    expect(optionButtons(wrapper)[1].find('.ic').text()).toBe('✓')
    expect(wrapper.find('.explain').text()).toContain('инъекция в SQL-запрос')
  })

  it('immediately marks a wrong pick red, the correct one green, and shows the explanation', async () => {
    const { wrapper } = factory()
    await optionButtons(wrapper)[0].trigger('click') // wrong q0 (answer=1)
    const btns = optionButtons(wrapper)
    expect(btns[0].classes()).toContain('wrong')
    expect(btns[1].classes()).toContain('correct')
    expect(btns[0].find('.ic').text()).toBe('✕')
    expect(wrapper.find('.explain').classes()).toContain('bad')
    expect(wrapper.find('.explain').text()).toContain('инъекция в SQL-запрос')
  })

  it('does not render an explanation for a question that has none', async () => {
    const { wrapper } = factory([{ text: 'q', options: ['a', 'b'], answer: 0 }])
    await optionButtons(wrapper)[0].trigger('click')
    expect(wrapper.find('.explain').exists()).toBe(false)
  })

  it('locks each question after the first click (cannot change the answer)', async () => {
    const { wrapper } = factory()
    await optionButtons(wrapper)[0].trigger('click') // wrong q0
    for (let i = 0; i < 3; i++) expect(optionButtons(wrapper)[i].attributes('disabled')).toBeDefined()
    // a second click on another option of the same question must not change it
    await optionButtons(wrapper)[1].trigger('click')
    expect(optionButtons(wrapper)[0].classes()).toContain('wrong')
    expect(optionButtons(wrapper)[1].classes()).toContain('correct')
  })

  it('keeps other questions interactive after one is answered', async () => {
    const { wrapper } = factory()
    await optionButtons(wrapper)[0].trigger('click') // q0 locked
    expect(optionButtons(wrapper)[3].attributes('disabled')).toBeUndefined() // q1 still open
    await optionButtons(wrapper)[3].trigger('click') // correct q1
    expect(optionButtons(wrapper)[3].classes()).toContain('correct')
  })

  it('calls submitQuiz once with the final score when every question is answered', async () => {
    const { wrapper, store } = factory()
    const spy = vi.spyOn(store, 'submitQuiz').mockResolvedValue({ quiz_best: 2, quiz_total: 2, xp: 20 })
    await optionButtons(wrapper)[1].trigger('click') // correct q0
    expect(spy).not.toHaveBeenCalled() // not complete yet
    await optionButtons(wrapper)[3].trigger('click') // correct q1
    await flushPromises()
    expect(spy).toHaveBeenCalledTimes(1)
    expect(spy).toHaveBeenCalledWith('l1', 2, 2)
  })

  it('shows the result summary and a perfect message once all are answered', async () => {
    const { wrapper, store } = factory()
    vi.spyOn(store, 'submitQuiz').mockResolvedValue({ quiz_best: 2, quiz_total: 2, xp: 20 })
    expect(wrapper.find('.result').exists()).toBe(false)
    await optionButtons(wrapper)[1].trigger('click')
    await optionButtons(wrapper)[3].trigger('click')
    await flushPromises()
    expect(wrapper.find('.result').text()).toContain('2 / 2')
    expect(wrapper.find('.result').classes()).toContain('perfect')
    expect(wrapper.find('.result').text()).toContain('Идеально')
  })

  it('resets all answers and re-enables the options', async () => {
    const { wrapper, store } = factory()
    vi.spyOn(store, 'submitQuiz').mockResolvedValue({ quiz_best: 2, quiz_total: 2, xp: 20 })
    await optionButtons(wrapper)[1].trigger('click')
    await optionButtons(wrapper)[3].trigger('click')
    await flushPromises()
    await resetBtn(wrapper).trigger('click')
    expect(wrapper.find('.result').exists()).toBe(false)
    expect(wrapper.find('.explain').exists()).toBe(false)
    for (const b of optionButtons(wrapper)) {
      expect(b.attributes('disabled')).toBeUndefined()
      expect(b.classes()).not.toContain('correct')
      expect(b.classes()).not.toContain('wrong')
    }
  })

  it('shows the prior best score chip when available', () => {
    const { wrapper } = factory(QUESTIONS, { quiz_best: 2, quiz_total: 2 })
    expect(wrapper.text()).toContain('лучший: 2/2')
  })

  // Regression: LessonView reuses this component across lessons (the quiz
  // section id is "квиз" in every lesson), so a new `questions` prop must
  // fully reset the quiz.
  it('resets state when the questions prop changes (SPA navigation)', async () => {
    const { wrapper, store } = factory()
    vi.spyOn(store, 'submitQuiz').mockResolvedValue({ quiz_best: 2, quiz_total: 2, xp: 20 })
    await optionButtons(wrapper)[1].trigger('click')
    await optionButtons(wrapper)[3].trigger('click')
    await flushPromises()
    expect(wrapper.find('.result').exists()).toBe(true)

    const nextQuestions = [{ text: 'Новый вопрос?', options: ['a', 'b', 'c'], answer: 2, explanation: 'потому что c' }]
    await wrapper.setProps({ lessonId: 'l2', questions: nextQuestions })

    expect(wrapper.find('.result').exists()).toBe(false)
    expect(optionButtons(wrapper).length).toBe(3)
    for (const b of optionButtons(wrapper)) {
      expect(b.attributes('disabled')).toBeUndefined()
      expect(b.classes()).not.toContain('correct')
      expect(b.classes()).not.toContain('wrong')
    }
  })

  // The quiz section's ring is driven by ANSWERING, not the reading timer:
  // Quiz emits the answered ratio on every option click so LessonView can fill
  // the section ring (and mark it read once everything is answered).
  it('emits the answered ratio as questions are answered', async () => {
    const { wrapper } = factory()
    expect(wrapper.emitted('progress')).toBeFalsy()

    await optionButtons(wrapper)[0].trigger('click') // 1 of 2 answered
    let evs = wrapper.emitted('progress')
    expect(evs[evs.length - 1]).toEqual([0.5, 1])

    await optionButtons(wrapper)[3].trigger('click') // 2 of 2 answered
    evs = wrapper.emitted('progress')
    expect(evs[evs.length - 1]).toEqual([1, 2])
  })

  it('emits `answered` exactly once when every question is answered', async () => {
    const { wrapper } = factory()
    expect(wrapper.emitted('answered')).toBeFalsy()

    await optionButtons(wrapper)[0].trigger('click')
    expect(wrapper.emitted('answered')).toBeFalsy() // not yet

    await optionButtons(wrapper)[3].trigger('click')
    expect(wrapper.emitted('answered')).toBeTruthy()
    expect(wrapper.emitted('answered').length).toBe(1)
  })

  it('re-emits progress 0 when the quiz is reset', async () => {
    const { wrapper, store } = factory()
    vi.spyOn(store, 'submitQuiz').mockResolvedValue({ quiz_best: 2, quiz_total: 2, xp: 20 })
    await optionButtons(wrapper)[1].trigger('click')
    await optionButtons(wrapper)[3].trigger('click')
    await flushPromises()

    await resetBtn(wrapper).trigger('click')
    const evs = wrapper.emitted('progress')
    expect(evs[evs.length - 1]).toEqual([0, 0])
  })
})
