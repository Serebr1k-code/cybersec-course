import { describe, it, expect } from 'vitest'
import { parseQuiz } from './quiz'

const MD = `
## Квиз

1. Что такое SQLi?
- [x] Инъекция в SQL-запрос
- Вид спорта
- Ошибка вёрстки

2. Какой инструмент для фаззинга?
- sqlmap
- [x] ffuf
- exiftool
`

describe('utils/quiz – parseQuiz', () => {
  it('returns null for empty input', () => {
    expect(parseQuiz('')).toBeNull()
    expect(parseQuiz(null)).toBeNull()
    expect(parseQuiz(undefined)).toBeNull()
  })

  it('parses numbered questions and options', () => {
    const qs = parseQuiz(MD)
    expect(qs).not.toBeNull()
    expect(qs.length).toBe(2)
    expect(qs[0].text).toContain('SQLi')
    expect(qs[0].options).toContain('Инъекция в SQL-запрос')
  })

  it('marks the [x] option as correct and cleans the marker', () => {
    const qs = parseQuiz(MD)
    expect(qs[0].answer).toBe(0)
    expect(qs[0].options[0]).toBe('Инъекция в SQL-запрос')
    expect(qs[1].answer).toBe(1)
    expect(qs[1].options[1]).toBe('ffuf')
  })

  it('supports bold **answer** markers', () => {
    const qs = parseQuiz('1. Q?\n- wrong\n- **right one**\n- also wrong')
    expect(qs[0].answer).toBe(1)
    expect(qs[0].options[1]).toBe('right one')
  })

  it('supports (верно)/(правильно)/(+) suffixes', () => {
    const qs = parseQuiz('1. Q?\n- a (верно)\n- b\n\n2. Q2?\n- x\n- y +')
    expect(qs[0].answer).toBe(0)
    expect(qs[0].options[0]).toBe('a')
    expect(qs[1].answer).toBe(1)
    expect(qs[1].options[1]).toBe('y')
  })

  it('supports explicit "Ответ: B" letter answers', () => {
    const qs = parseQuiz('1. Q?\n- a\n- b\n- c\nОтвет: B')
    expect(qs[0].answer).toBe(1)
  })

  it('supports explicit "Правильный ответ: 2" numeric answers', () => {
    const qs = parseQuiz('1. Q?\n- a\n- b\n- c\nПравильный ответ: 2')
    expect(qs[0].answer).toBe(1)
  })

  it('drops questions with fewer than two options', () => {
    const qs = parseQuiz('1. only one option\n- single')
    expect(qs).toBeNull()
  })

  it('parses "Вопрос 1:" style headers', () => {
    const qs = parseQuiz('Вопрос 1: Что?\n- [x] a\n- b')
    expect(qs.length).toBe(1)
    expect(qs[0].answer).toBe(0)
  })
})
