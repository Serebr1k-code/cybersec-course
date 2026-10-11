// Разбор секции «## Квиз» в структуру вопросов с вариантами.
// Поддерживает пометку правильного ответа: [x], жирный **текст**,
// суффиксы (верно)/(правильно)/(+), либо строку «Ответ: ...».
export function parseQuiz(markdown) {
  if (!markdown) return null
  const lines = markdown.split('\n')
  const questions = []
  let cur = null

  const correctMarker = (t) =>
    /\(верно\)|\(правильно\)|\(correct\)|✅/i.test(t) || /\+$/.test(t.trim())

  const clean = (t) =>
    t.replace(/\(верно\)|\(правильно\)|\(correct\)|✅/gi, '')
      .replace(/\s*\+\s*$/, '')
      .replace(/\*\*/g, '')
      .trim()

  for (const raw of lines) {
    const line = raw.trimEnd()
    if (!line.trim()) continue

    // Новый вопрос: "1. ..." / "1) ..." / "**1.** ..." / "Вопрос 1: ..."
    const qm = line.match(/^\s*(?:\*\*)?(\d+)[.)]\s*(?:\*\*)?\s*(.+?)(?:\*\*)?\s*$/)
    const qm2 = line.match(/^\s*(?:Вопрос|Question)\s*(\d+)\s*[:.]\s*(.+)$/i)
    if (qm && !/^\s*[-*]\s/.test(line)) {
      if (cur && cur.options.length) questions.push(cur)
      cur = { n: parseInt(qm[1], 10), text: clean(qm[2]), options: [], answer: -1 }
      continue
    }
    if (qm2) {
      if (cur && cur.options.length) questions.push(cur)
      cur = { n: parseInt(qm2[1], 10), text: clean(qm2[2]), options: [], answer: -1 }
      continue
    }

    // Вариант ответа
    const om = line.match(/^\s*[-*]\s+(.+)$/)
    if (om && cur) {
      let t = om[1].trim()
      let isCorrect = false
      const cb = t.match(/^\[( |x|X)\]\s*(.+)$/)
      if (cb) {
        isCorrect = cb[1].toLowerCase() === 'x'
        t = cb[2]
      } else if (/\*\*(.+?)\*\*/.test(t)) {
        isCorrect = true
      } else if (correctMarker(t)) {
        isCorrect = true
      }
      cur.options.push(clean(t))
      if (isCorrect) cur.answer = cur.options.length - 1
      continue
    }

    // Явная строка ответа: "Ответ: B" / "Правильный ответ: 2"
    const am = line.match(/^\s*(?:Правильный\s+ответ|Ответ|Answer)\s*[:—-]\s*(.+)$/i)
    if (am && cur) {
      const v = am[1].trim()
      let idx = -1
      const letter = v.match(/^[A-Fa-fА-Яа-я]$/)
      if (/^\d+$/.test(v)) idx = parseInt(v, 10) - 1
      else if (letter) idx = v.toUpperCase().charCodeAt(0) - 65
      else idx = cur.options.findIndex((o) => o.toLowerCase() === clean(v).toLowerCase())
      if (idx >= 0 && idx < cur.options.length) cur.answer = idx
      continue
    }
  }
  if (cur && cur.options.length) questions.push(cur)

  const valid = questions.filter((q) => q.options.length >= 2)
  return valid.length ? valid : null
}
