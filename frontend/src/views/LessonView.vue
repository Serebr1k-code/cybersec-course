<script setup>
import { ref, reactive, computed, onMounted, onBeforeUnmount, nextTick, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '../api/client'
import { useTreeStore } from '../stores/tree'
import { useProgressStore } from '../stores/progress'
import { renderMarkdown, highlightAll } from '../utils/markdown'
import { buildAliasIndex, linkTopics, shortestPath } from '../utils/topicLinks'
import Quiz from '../components/Quiz.vue'
import NotesPanel from '../components/NotesPanel.vue'

const route = useRoute()
const router = useRouter()
const tree = useTreeStore()
const progress = useProgressStore()

const lesson = ref(null)
const loading = ref(true)
const error = ref('')
const bodyEl = ref(null)
const tocEl = ref(null)

// --- чтение: учёт времени по секциям ---
const acc = reactive({})        // секунды, накопленные с последнего флеша
const serverSecs = reactive({}) // подтверждённые сервером секунды
const isRead = reactive({})     // секция прочитана
const activeId = ref('')
const ratios = {}               // видимость секций (IntersectionObserver)
const visibleIds = ref(new Set()) // ВСЕ секции, хоть чуть-чуть видимые сейчас
const paused = ref(false)       // РУЧНАЯ пауза чтения (пробел / Esc / кнопка) — таймер не тикает
// АВТО-пауза при прокрутке: пока пользователь активно листает текст
// (touchmove / wheel / momentum-скролл), время НЕ накапливается; спустя ~1с
// после остановки таймер возобновляется сам. Флаг отдельный от `paused`:
// ручная пауза остаётся главной и авто-паузой НЕ снимается.
const scrolling = ref(false)
const autoPaused = computed(() => scrolling.value && !paused.value)
let scrollStopTimer = null

// --- глобальный множитель скорости чтения ---
// Удержание кольца секции ~0.7с открывает вертикальный слайдер; перетаскивание
// вверх/вниз задаёт множитель x0.5..x2.0, который масштабирует накопление
// времени ЧТЕНИЯ (acc) для ВСЕХ секций сразу. Значение хранится в localStorage,
// поэтому сохраняется между уроками. x1.0 — обычное поведение.
const SPEED_MIN = 0.5
const SPEED_MAX = 2.0
const SPEED_KEY = 'lt-reading-speed'
const SPEED_HOLD_MS = 700
const SPEED_TRACK_H = 220

function clampSpeed(v) { return Math.min(SPEED_MAX, Math.max(SPEED_MIN, v)) }
function loadSpeed() {
  try {
    const v = parseFloat(localStorage.getItem(SPEED_KEY))
    if (Number.isFinite(v)) return clampSpeed(v)
  } catch (e) { /* localStorage может быть недоступен (приватный режим) */ }
  return 1
}
function saveSpeed(v) {
  try { localStorage.setItem(SPEED_KEY, String(v)) } catch (e) { /* игнорируем */ }
}

const speed = ref(loadSpeed())
const speedOpen = ref(false)
const speedPct = computed(() => Math.round(((speed.value - SPEED_MIN) / (SPEED_MAX - SPEED_MIN)) * 100))
let holdTimer = null

watch(speed, (v) => saveSpeed(v))

function cancelHold() {
  if (holdTimer) { clearTimeout(holdTimer); holdTimer = null }
}

// pointerdown на кольце запускает таймер удержания; отпускание раньше срока
// (pointerup/pointerleave/cancel) отменяет его. По истечении — показываем слайдер.
function onRingPointerDown(e) {
  if (e.button != null && e.button !== 0) return
  cancelHold()
  holdTimer = setTimeout(() => { holdTimer = null; speedOpen.value = true }, SPEED_HOLD_MS)
}
function onRingPointerLeave() {
  // Увели палец/курсор ДО открытия слайдера — отменяем удержание.
  if (!speedOpen.value) cancelHold()
}

// Перетаскивание: Y-координата указателя отображается на диапазон x0.5..x2.0.
// Верх трека = максимум (быстрее), низ = минимум (медленнее).
function applySpeedFromY(clientY) {
  const top = (window.innerHeight || 768) / 2 - SPEED_TRACK_H / 2
  const t = Math.min(1, Math.max(0, (clientY - top) / SPEED_TRACK_H))
  const v = SPEED_MAX - t * (SPEED_MAX - SPEED_MIN)
  speed.value = Math.round(v * 10) / 10
}

function closeSpeedSlider() {
  cancelHold()
  speedOpen.value = false
}

// Глобальные обработчики: работают и для мыши, и для тача (pointer events).
function onGlobalPointerMove(e) {
  if (!speedOpen.value) return
  applySpeedFromY(e.clientY)
}
function onGlobalPointerUp() {
  cancelHold()
  if (speedOpen.value) closeSpeedSlider()
}
// Метка времени (мс), раньше которой СЛЕДУЮЩАЯ секция не накапливает время.
// Ставится, когда предыдущая секция стала прочитанной: даёт паузу между секциями.
const nextStartAt = ref(0)
let io = null
let tickTimer = null
let flushTimer = null

const sections = computed(() => lesson.value?.sections || [])
const quizSection = computed(() => sections.value.find((s) => /^квиз|quiz/i.test(s.title)))
const quizSid = computed(() => quizSection.value?.id || '')
// Прогресс секции «Квиз» приходит из Quiz.vue (доля отвеченных вопросов),
// а НЕ из таймера чтения: кольцо этой секции заполняется по ответам.
const quizRatio = ref(0)
const quizAnswered = ref(0)
const readCount = computed(() => sections.value.filter((s) => isRead[s.id]).length)
const lessonPct = computed(() => sections.value.length ? Math.round((readCount.value / sections.value.length) * 100) : 0)

// Живое число секунд по секции = подтверждённое сервером + локальный
// аккумулятор. acc/serverSecs реактивны, поэтому вызов из шаблона
// пересчитывается каждую секунду, не дожидаясь флеша на сервер.
function liveSecs(sid) { return (serverSecs[sid] || 0) + (acc[sid] || 0) }

// Процент заполнения кольца секции (0..100). Считается от «живых» секунд,
// поэтому индикатор плавно растёт каждую секунду; при достижении порога
// секция помечается прочитанной и кольцо становится полностью зелёным.
// Для секции «Квиз» вместо времени берётся доля отвеченных вопросов.
function secPct(sid) {
  if (isRead[sid]) return 100
  if (sid === quizSid.value) return Math.round(quizRatio.value * 100)
  const sec = sections.value.find((s) => s.id === sid)
  const req = sec?.required_seconds || 0
  if (req <= 0) return 0
  return Math.min(100, Math.round((liveSecs(sid) / req) * 100))
}

// Текст подсказки: секунды показываем только в title (не в видимой разметке).
function secTitle(sid) {
  if (isRead[sid]) return 'Прочитано'
  if (sid === quizSid.value) {
    return 'Отвечено: ' + quizAnswered.value + '/' + (lesson.value?.quiz?.length || 0)
  }
  const sec = sections.value.find((s) => s.id === sid)
  return liveSecs(sid) + 'с / ' + (sec?.required_seconds || 0) + 'с'
}

// Порядок уроков для навигации «назад/вперёд»
const ordered = computed(() => {
  if (!lesson.value) return []
  const cat = tree.nodes.filter((n) => n.category === lesson.value.category)
  return cat.sort((a, b) => (a.depth - b.depth) || (a.order - b.order) || a.title.localeCompare(b.title))
})
const idx = computed(() => ordered.value.findIndex((n) => n.id === lesson.value?.id))
const prev = computed(() => (idx.value > 0 ? ordered.value[idx.value - 1] : null))
const next = computed(() => (idx.value >= 0 && idx.value < ordered.value.length - 1 ? ordered.value[idx.value + 1] : null))

const breadcrumb = computed(() => {
  if (!lesson.value) return []
  const chain = []
  let cur = tree.byId[lesson.value.parent]
  let guard = 0
  while (cur && guard++ < 20) { chain.unshift(cur); cur = tree.byId[cur.parent] }
  return chain
})

// --- умные кросс-ссылки между уроками ---
// Индекс алиасов строится из дерева (id-slug + теги + заголовок) и не требует
// изменений на бэкенде. После рендера markdown мы оборачиваем первое упоминание
// темы в <a class="topic-link">, а на ховере показываем путь до целевого урока.
const aliasIndex = computed(() => buildAliasIndex(tree.nodes))

function applyTopicLinks() {
  if (!bodyEl.value) return
  const index = aliasIndex.value
  const currentId = lesson.value?.id
  // Один общий набор на урок: каждый целевой урок линкуется один раз,
  // даже если упоминается в нескольких секциях (не засоряем текст).
  const linked = new Set()
  bodyEl.value.querySelectorAll('.md').forEach((el) => {
    linkTopics(el, { index, currentId, byId: tree.byId, linked })
  })
}

const tip = reactive({
  show: false, title: '', nodes: [], hops: null, minutes: null,
  disconnected: false, est: 0, x: 0, y: 0
})
const tipEl = ref(null)

function pluralLessons(n) {
  const m10 = n % 10
  const m100 = n % 100
  if (m10 === 1 && m100 !== 11) return 'урок'
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return 'урока'
  return 'уроков'
}

// Найти .topic-link по событию (делегирование) и убедиться, что он наш.
function topicLinkFrom(e) {
  const t = e.target
  if (!t || typeof t.closest !== 'function') return null
  const a = t.closest('.topic-link')
  return a && bodyEl.value && bodyEl.value.contains(a) ? a : null
}

function positionTip(a) {
  const el = tipEl.value
  const r = a.getBoundingClientRect()
  const w = el ? el.offsetWidth : 300
  const h = el ? el.offsetHeight : 120
  const vw = window.innerWidth || 1024
  const vh = window.innerHeight || 768
  // Не вылезаем за вьюпорт: прижимаем по горизонтали и переворачиваем вверх,
  // если снизу не хватает места.
  const left = Math.min(Math.max(8, r.left), Math.max(8, vw - w - 8))
  let top = r.bottom + 8
  if (top + h + 8 > vh) top = Math.max(8, r.top - h - 8)
  tip.x = left
  tip.y = top
}

async function onTopicOver(e) {
  const a = topicLinkFrom(e)
  if (!a) return
  const id = a.getAttribute('data-topic-id')
  const target = tree.byId[id]
  if (!target) return
  const p = shortestPath(lesson.value?.id, id, tree.byId)
  tip.title = target.title
  tip.nodes = p && !p.disconnected ? p.nodes : []
  tip.hops = p ? p.hops : null
  tip.minutes = p ? p.minutes : null
  tip.disconnected = !!(p && p.disconnected)
  tip.est = target.estimated_minutes || 0
  tip.show = true
  await nextTick()
  positionTip(a)
}

function onTopicOut(e) {
  const a = topicLinkFrom(e)
  if (!a) return
  // Не прячем подсказку при переходе курсора между дочерними узлами ссылки.
  if (e.relatedTarget && a.contains(e.relatedTarget)) return
  tip.show = false
}

function onTopicClick(e) {
  const a = topicLinkFrom(e)
  if (!a) return
  e.preventDefault()
  tip.show = false
  const id = a.getAttribute('data-topic-id')
  if (id) router.push('/lesson/' + id)
}

function hideTip() { tip.show = false }

function render(md) { return renderMarkdown(md) }

async function load(id) {
  loading.value = true
  error.value = ''
  try {
    const l = await api.lesson(id)
    lesson.value = l
    progress.setLastLesson(l.id)
    // сброс локального состояния чтения
    for (const k in acc) delete acc[k]
    for (const k in serverSecs) delete serverSecs[k]
    for (const k in isRead) delete isRead[k]
    quizRatio.value = 0
    quizAnswered.value = 0
    nextStartAt.value = 0
    const lp = progress.user.lessons?.[l.id]
    if (lp?.sections) {
      for (const sid in lp.sections) {
        serverSecs[sid] = lp.sections[sid].read_seconds || 0
        isRead[sid] = !!lp.sections[sid].read
      }
    }
    // Контент рендерится только когда loading=false (ветка v-else-if="lesson"),
    // поэтому сначала снимаем флаг, дожидаемся отрисовки DOM и только потом
    // подсвечиваем код / ставим observer — иначе bodyEl ещё null.
    loading.value = false
    await nextTick()
    highlightAll(bodyEl.value)
    applyTopicLinks()
    setupObserver()
    window.scrollTo({ top: 0 })
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

function setupObserver() {
  if (io) io.disconnect()
  for (const k in ratios) delete ratios[k]
  visibleIds.value.clear()
  io = new IntersectionObserver((entries) => {
    for (const e of entries) {
      const sid = e.target.dataset.sectionId
      ratios[sid] = e.intersectionRatio
      // Секция «видима», как только её хоть на пиксель занесло в вьюпорт.
      if (e.intersectionRatio > 0) visibleIds.value.add(sid)
      else visibleIds.value.delete(sid)
    }
    // activeId (для подсветки в оглавлении) — только самая видимая секция.
    let best = '', bestR = 0
    for (const k in ratios) if (ratios[k] > bestR) { bestR = ratios[k]; best = k }
    activeId.value = best
  // Порог 0 — срабатывает, как только секция показалась; дальше мелкая сетка,
  // чтобы ratios не «застывали» и activeId (подсветка в оглавлении) был точным.
  }, { threshold: Array.from({ length: 21 }, (_, i) => i / 20), rootMargin: '0px' })
  document.querySelectorAll('[data-section-id]').forEach((el) => io.observe(el))
}

// Доля высоты вьюпорта, выше которой должна подняться верхняя граница секции,
// чтобы её время начало начисляться (линия «60% сверху»).
const READ_LINE = 0.6

// Пауза между секциями (мс): после того как секция стала прочитанной, следующая
// начинает накапливать время не раньше, чем через этот интервал.
const SECTION_PAUSE_MS = 3500

// Минимальная прокрутка страницы (px), после которой РАЗРЕШЕНО начислять время
// НЕ первой секции. Пока читатель в самом верху (window.scrollY < порога),
// тикает ТОЛЬКО первая секция: если первая секция короткая, следующая может
// оказаться выше линии 60% уже при открытии урока — без этого правила она
// начала бы копить время, хотя читатель ещё не прокрутил ни пикселя.
const MIN_SCROLL_PX = 60

// Сколько ждать покоя после последнего события прокрутки, прежде чем снять
// авто-паузу и продолжить начислять время (мс).
const SCROLL_RESUME_MS = 1000

function tick() {
  if (paused.value) return     // ручная пауза: время не накапливается, но видимость не сбрасываем
  if (scrolling.value) return  // авто-пауза: пользователь прокручивает — текст ещё «в движении»
  if (document.hidden) return
  const root = bodyEl.value
  if (!root) return
  // Секции в порядке документа (секция «Квиз» исключена — она answer-driven).
  const els = []
  for (const el of root.querySelectorAll('[data-section-id]')) {
    if (el.dataset.sectionId === quizSid.value) continue
    els.push(el)
  }
  // Секции заполняются СТРОГО ПОСЛЕДОВАТЕЛЬНО: накапливает время только ПЕРВАЯ
  // (в порядке документа) ещё НЕ прочитанная секция. Пока она не прочитана,
  // ни одна последующая не тикает. Секция «Квиз» исключена из этой цепочки —
  // она answer-driven и не блокирует/не блокируется таймером чтения.
  let target = null
  for (const el of els) {
    if (isRead[el.dataset.sectionId]) continue
    target = el
    break
  }
  if (!target) return
  // Пауза между секциями: следующая начинает тикать только спустя
  // SECTION_PAUSE_MS после того, как предыдущая стала прочитанной.
  if (Date.now() < nextStartAt.value) return
  // Гейт минимальной прокрутки: в самом верху страницы (scrollY < MIN_SCROLL_PX)
  // время накапливает ТОЛЬКО первая секция урока. Любая следующая ждёт, пока
  // читатель реально прокрутит страницу вниз. Иначе короткая первая секция и
  // следующая, уже висящая выше линии 60%, начали бы тикать сразу при открытии.
  const isFirstSection = els.length > 0 && els[0] === target
  if (!isFirstSection && window.scrollY < MIN_SCROLL_PX) return
  // Первая непрочитанная секция читается, только когда её ВЕРХ поднялся выше
  // линии 60% от высоты вьюпорта И низ ещё не ушёл за верх экрана (секция хотя
  // бы частично видна). Блок, лишь показавшийся снизу, ещё не тикает.
  const line = READ_LINE * window.innerHeight
  const sid = target.dataset.sectionId
  const r = target.getBoundingClientRect()
  if (r.top < line && r.bottom > 0) {
    // Множитель скорости чтения применяется к НАКОПЛЕНИЮ времени: x2.0
    // засчитывает вдвое больше секунд за тот же тик (кольцо заполняется быстрее),
    // x0.5 — вдвое медленнее. acc хранит дробные секунды; на сервер уходят
    // только целые (см. flush).
    acc[sid] = (acc[sid] || 0) + speed.value
    markReadIfReached(sid)
  }
}

// Прогресс секции «Квиз» из Quiz.vue: доля отвеченных вопросов (0..1).
// Когда отвечено всё — помечаем секцию прочитанной и досылаем на сервер
// столько секунд, сколько нужно, чтобы backend засчитал секцию прочитанной
// (у секции-квиза своего времени нет, поэтому шлём required_seconds).
function onQuizProgress(ratio, answered) {
  quizRatio.value = Math.min(1, Math.max(0, ratio || 0))
  quizAnswered.value = answered || 0
  const sid = quizSid.value
  if (!sid || isRead[sid]) return
  if (quizRatio.value >= 1) {
    isRead[sid] = true
    const sec = sections.value.find((s) => s.id === sid)
    const req = sec?.required_seconds || 0
    const need = Math.max(req - (serverSecs[sid] || 0), 1)
    acc[sid] = need
    flush()
  }
}

// Оптимистично помечаем секцию прочитанной, как только набрали порог,
// не дожидаясь флеша на сервер — иначе ✓ и зелёный статус запаздывают.
function markReadIfReached(sid) {
  if (isRead[sid]) return
  const sec = sections.value.find((s) => s.id === sid)
  if (!sec) return
  if (liveSecs(sid) >= (sec.required_seconds || 0)) {
    isRead[sid] = true
    // Пауза между секциями: следующая начнёт накапливать время не раньше,
    // чем через SECTION_PAUSE_MS от этого момента.
    nextStartAt.value = Date.now() + SECTION_PAUSE_MS
    flush() // сразу закрепляем прогресс на сервере
  }
}

async function flush() {
  // acc хранит дробные секунды (множитель скорости), а backend принимает только
  // ЦЕЛЫЕ секунды (Seconds int). Поэтому отправляем целую часть, а дробный
  // остаток оставляем в acc до следующего флеша. При x1.0 acc всегда целый,
  // так что поведение не меняется.
  const ids = Object.keys(acc).filter((k) => acc[k] >= 1)
  if (!ids.length || !lesson.value) return
  const payload = ids.map((k) => {
    const whole = Math.floor(acc[k])
    acc[k] -= whole
    return { sid: k, secs: whole }
  })
  for (const { sid, secs } of payload) {
    try {
      const r = await progress.pushSection(lesson.value.id, sid, secs)
      if (r) {
        serverSecs[sid] = r.read_seconds
        isRead[sid] = r.read
      }
    } catch (e) { /* тихо игнорируем */ }
  }
}

function onVisibility() { if (document.hidden) flush() }

// Ручная пауза/продолжение — единый обработчик для пробела, Esc и кнопки в
// полосе чтения. Ручная пауза авторитетна: её не снимает авто-пауза прокрутки.
function togglePause() { paused.value = !paused.value }

// Активность прокрутки — ГЛОБАЛЬНО, а не только для тача: слушаем window
// 'scroll' (срабатывает и от колеса, и от трекпада/инерции, и от тача, и от
// клавиатуры) ПЛЮС явные 'wheel' (десктоп: колесо/трекпад) и 'touchmove'
// (телефон). Включаем авто-паузу и перезапускаем debounce; ~SCROLL_RESUME_MS
// покоя — снова читаем. Пока флаг стоит, tick() не начисляет время.
function onScrollActivity() {
  scrolling.value = true
  if (scrollStopTimer) clearTimeout(scrollStopTimer)
  scrollStopTimer = setTimeout(() => { scrolling.value = false }, SCROLL_RESUME_MS)
}

// Пробел / Escape переключают паузу чтения. Игнорируем ввод в полях (заметки),
// чтобы пробел печатался как обычно, и не мешаем открытым модалкам/меню.
function isTypingTarget(t) {
  if (!t || !t.tagName) return false
  const tag = t.tagName.toLowerCase()
  return tag === 'input' || tag === 'textarea' || tag === 'select' || t.isContentEditable === true
}

function onKeydown(e) {
  if (e.key !== ' ' && e.key !== 'Spacebar' && e.key !== 'Escape') return
  if (isTypingTarget(e.target)) return
  // Не перехватываем, если открыт диалог/модалка (Escape обычно закрывает их).
  if (document.querySelector('[role="dialog"], .modal, .overlay')) return
  togglePause()
  e.preventDefault()
}

onMounted(async () => {
  await tree.load()
  await progress.load()
  await load(route.params.id)
  tickTimer = setInterval(tick, 1000)
  flushTimer = setInterval(flush, 2000)
  document.addEventListener('visibilitychange', onVisibility)
  document.addEventListener('keydown', onKeydown)
  window.addEventListener('scroll', hideTip, true)
  // Авто-пауза при прокрутке: ловим и обычный scroll (в т.ч. инерцию на
  // телефоне), и явные touchmove/wheel.
  window.addEventListener('scroll', onScrollActivity, { passive: true })
  window.addEventListener('wheel', onScrollActivity, { passive: true })
  window.addEventListener('touchmove', onScrollActivity, { passive: true })
  // Слайдер скорости чтения: перетаскивание и отпускание ловим глобально,
  // чтобы работать независимо от того, куда уехал указатель.
  window.addEventListener('pointermove', onGlobalPointerMove, { passive: true })
  window.addEventListener('pointerup', onGlobalPointerUp)
  window.addEventListener('pointercancel', onGlobalPointerUp)
})

watch(() => route.params.id, async (id) => { if (id) { await flush(); await load(id) } })

onBeforeUnmount(() => {
  clearInterval(tickTimer)
  clearInterval(flushTimer)
  document.removeEventListener('visibilitychange', onVisibility)
  document.removeEventListener('keydown', onKeydown)
  window.removeEventListener('scroll', hideTip, true)
  window.removeEventListener('scroll', onScrollActivity)
  window.removeEventListener('wheel', onScrollActivity)
  window.removeEventListener('touchmove', onScrollActivity)
  window.removeEventListener('pointermove', onGlobalPointerMove)
  window.removeEventListener('pointerup', onGlobalPointerUp)
  window.removeEventListener('pointercancel', onGlobalPointerUp)
  cancelHold()
  if (scrollStopTimer) clearTimeout(scrollStopTimer)
  if (io) io.disconnect()
  flush()
})

function scrollTo(sid) {
  const el = document.getElementById('sec-' + sid)
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

async function markComplete() {
  if (!lesson.value) return
  await progress.complete(lesson.value.id)
  for (const s of sections.value) isRead[s.id] = true
}
</script>

<template>
  <div class="lesson-view">
    <!-- Тонкая полоса чтения: единственный верхний бар на странице урока.
         Максимум места под текст: назад, заголовок (обрезается) + прогресс и
         маленький индикатор паузы. -->
    <div class="reading-bar">
      <RouterLink to="/" class="rb-back" title="К дереву" aria-label="К дереву">←</RouterLink>
      <span class="rb-title" :title="lesson?.title || ''">{{ lesson?.title || 'Урок' }}</span>
      <span
        v-if="lesson"
        class="rb-progress"
        :title="readCount + '/' + sections.length + ' разделов прочитано'"
      >
        <span class="rb-bar"><i :style="{ width: lessonPct + '%' }"></i></span>
        <span class="rb-count mono">{{ readCount }}/{{ sections.length }}</span>
        <span class="rb-pct mono">{{ lessonPct }}%</span>
      </span>
      <!-- Пауза/продолжение: ВСЕГДА видимая кнопка-тап-таргет 44px в полосе
           чтения. Состояние: ⏸ (идёт) / ▶ (ручная пауза). При авто-паузе от
           прокрутки подсвечивается классом .auto-paused, ручная — .pause-badge. -->
      <button
        type="button"
        class="pause-btn"
        :class="{ 'pause-badge': paused, 'auto-paused': autoPaused }"
        :aria-pressed="paused"
        :aria-label="paused ? 'Продолжить чтение' : 'Пауза чтения'"
        :title="paused
          ? 'Продолжить чтение (пробел)'
          : (autoPaused ? 'Пауза при прокрутке — возобновится автоматически' : 'Пауза чтения (пробел)')"
        @click="togglePause"
      ><span aria-hidden="true">{{ paused ? '▶' : '⏸' }}</span></button>
    </div>

    <div class="lesson-body">
      <div v-if="loading" class="center loading"><span class="spin">⏳</span> Загрузка урока…</div>
      <div v-else-if="error" class="center loading">Урок не найден: {{ error }}</div>

      <template v-else-if="lesson">
      <!-- Хлебные крошки -->
      <nav class="crumbs">
        <RouterLink to="/">Дерево</RouterLink>
        <span class="sep">/</span>
        <RouterLink :to="'/?cat=' + lesson.category">{{ lesson.category }}</RouterLink>
        <template v-for="b in breadcrumb" :key="b.id">
          <span class="sep">/</span>
          <RouterLink :to="'/lesson/' + b.id">{{ b.title }}</RouterLink>
        </template>
      </nav>

      <div class="reader">
        <article
          class="doc"
          ref="bodyEl"
          @mouseover="onTopicOver"
          @mouseout="onTopicOut"
          @click="onTopicClick"
        >
          <header class="doc-head">
            <div class="dh-top">
              <span class="diff" :class="'diff-' + lesson.difficulty">{{ lesson.difficulty }}</span>
              <span class="chip">{{ lesson.estimated_minutes }} мин</span>
              <span class="chip">{{ sections.length }} разделов</span>
            </div>
            <h1>{{ lesson.title }}</h1>
            <p class="summary soft">{{ lesson.summary }}</p>
            <div class="tags" v-if="lesson.tags?.length">
              <span v-for="t in lesson.tags" :key="t" class="chip tag">#{{ t }}</span>
            </div>

            <div class="read-progress">
              <div class="bar"><i :style="{ width: lessonPct + '%' }"></i></div>
              <span class="rp-label mono">{{ readCount }}/{{ sections.length }} разделов</span>
            </div>
          </header>

          <section
            v-for="(s, i) in sections"
            :id="'sec-' + s.id"
            :key="s.id"
            class="sec"
            :data-section-id="s.id"
            :class="{ read: isRead[s.id] }"
          >
            <div class="sec-head">
              <h2>{{ s.title }}</h2>
              <span
                class="sec-state"
                :class="{ on: isRead[s.id] }"
                :title="secTitle(s.id)"
                :aria-label="secTitle(s.id)"
              >
                <span
                  class="sec-ring"
                  :class="{ paused: paused && !isRead[s.id] && s.id !== quizSid }"
                  :style="{ '--p': secPct(s.id) }"
                  title="Удерживайте, чтобы задать скорость чтения"
                  @pointerdown="onRingPointerDown"
                  @pointerleave="onRingPointerLeave"
                  @contextmenu.prevent
                >
                  <svg v-if="isRead[s.id]" class="sec-check" viewBox="0 0 24 24" width="10" height="10" aria-hidden="true">
                    <path d="M20 6L9 17l-5-5" fill="none" stroke="currentColor" stroke-width="3.5"
                      stroke-linecap="round" stroke-linejoin="round" />
                  </svg>
                  <span v-else-if="paused" class="sec-pause" aria-hidden="true"><i></i><i></i></span>
                </span>
              </span>
            </div>

            <template v-if="/^квиз|quiz/i.test(s.title) && lesson.quiz?.length">
              <div v-if="s.markdown.trim()" class="md" v-html="render(s.markdown)"></div>
              <Quiz :lesson-id="lesson.id" :questions="lesson.quiz" @progress="onQuizProgress" />
            </template>
            <div v-else class="md" v-html="render(s.markdown)"></div>
          </section>

          <NotesPanel :lesson-id="lesson.id" />

          <div class="doc-foot">
            <button class="btn btn-primary" @click="markComplete" :disabled="progress.isCompleted(lesson.id)">
              {{ progress.isCompleted(lesson.id) ? '✓ Урок пройден' : 'Отметить как пройденный' }}
            </button>
            <span class="spacer"></span>
            <RouterLink v-if="prev" :to="'/lesson/' + prev.id" class="btn">← {{ prev.title }}</RouterLink>
            <RouterLink v-if="next" :to="'/lesson/' + next.id" class="btn"> {{ next.title }} →</RouterLink>
          </div>
        </article>

        <!-- Оглавление -->
        <aside class="toc" ref="tocEl">
          <div class="toc-title">Содержание</div>
          <a
            v-for="s in sections"
            :key="s.id"
            class="toc-item"
            :class="{ active: activeId === s.id, read: isRead[s.id] }"
            @click.prevent="scrollTo(s.id)"
            :href="'#sec-' + s.id"
          >
            <span class="toc-dot"></span>
            <span class="toc-text">{{ s.title }}</span>
          </a>
          <div class="toc-foot">
            <div class="mini-ring" :style="{ '--p': lessonPct }">
              <span>{{ lessonPct }}%</span>
            </div>
            <span class="muted">прочитано</span>
          </div>
        </aside>
      </div>

      <!-- Тултип умной кросс-ссылки: путь до урока + дистанция -->
      <div
        v-if="tip.show"
        ref="tipEl"
        class="topic-tip"
        role="tooltip"
        :style="{ left: tip.x + 'px', top: tip.y + 'px' }"
      >
        <div class="tt-title">{{ tip.title }}</div>
        <div v-if="tip.nodes.length" class="tt-path">
          <template v-for="(n, i) in tip.nodes" :key="n.id + '-' + i">
            <span v-if="i" class="tt-sep">›</span>
            <span
              class="tt-crumb"
              :class="{ cur: i === 0, tgt: i === tip.nodes.length - 1 }"
            >{{ n.title }}</span>
          </template>
        </div>
        <div class="tt-dist">
          <template v-if="tip.disconnected">~{{ tip.est }} мин · другая ветка дерева</template>
          <template v-else-if="tip.hops !== null">нужно пройти {{ tip.hops }} {{ pluralLessons(tip.hops) }} · ~{{ tip.minutes }} мин</template>
          <template v-else>~{{ tip.est }} мин</template>
        </div>
      </div>
      </template>
    </div>

    <!-- Глобальный множитель скорости чтения: появляется при удержании кольца
         секции ~0.7с. Перетаскивание вверх/вниз задаёт x0.5..x2.0; отпускание
         или тап по фону скрывает. Значение сохраняется в localStorage. -->
    <div v-if="speedOpen" class="speed-overlay" @pointerdown.self="closeSpeedSlider">
      <div
        class="speed-track"
        role="slider"
        aria-label="Скорость чтения"
        :aria-valuemin="SPEED_MIN"
        :aria-valuemax="SPEED_MAX"
        :aria-valuenow="speed"
      >
        <i class="speed-fill" :style="{ height: speedPct + '%' }"></i>
        <span class="speed-knob" :style="{ bottom: speedPct + '%' }"></span>
      </div>
      <div class="speed-readout">
        <div class="speed-val mono">x{{ speed.toFixed(1) }}</div>
        <div class="speed-hint">↑ быстрее · ↓ медленнее</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.lesson-view { flex: 1; width: 100%; }

/* ---- Тонкая полоса чтения (единственный верхний бар на уроке) ---- */
.reading-bar {
  position: sticky; top: 0; z-index: 40;
  height: var(--reading-bar-h);
  display: flex; align-items: center; gap: 12px;
  padding: 0 16px;
  background: rgba(9, 14, 21, 0.86);
  backdrop-filter: blur(14px);
  border-bottom: 1px solid var(--border);
}
.rb-back {
  flex: none;
  display: grid; place-items: center;
  width: 30px; height: 30px; border-radius: var(--r-sm);
  color: var(--text-soft); font-size: 17px; line-height: 1;
  background: var(--panel-2); border: 1px solid var(--border);
}
.rb-back:hover { background: var(--panel-3); color: var(--text); text-decoration: none; border-color: var(--border-strong); }
.rb-title {
  flex: 1; min-width: 0;
  font-size: 13.5px; font-weight: 650; color: var(--text);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.rb-progress { flex: none; display: flex; align-items: center; gap: 8px; }
.rb-bar { width: 90px; height: 5px; border-radius: 999px; background: var(--panel-3); overflow: hidden; }
.rb-bar > i { display: block; height: 100%; border-radius: 999px; background: linear-gradient(90deg, #38bdf8, #818cf8); transition: width .4s ease; }
.rb-count, .rb-pct { font-size: 11.5px; color: var(--muted); white-space: nowrap; }
.rb-pct { color: var(--text-soft); font-weight: 700; min-width: 34px; text-align: right; }

/* Кнопка паузы/продолжения — ВСЕГДА видна в полосе чтения; тап-таргет 44px.
   Ручная пауза помечается классом .pause-badge (жёлтая подсветка, как у старого
   бейджа), авто-пауза при прокрутке — .auto-paused (приглушённая жёлтая). */
.pause-btn {
  flex: none;
  display: inline-flex; align-items: center; justify-content: center;
  width: 44px; height: 44px; padding: 0;
  border-radius: var(--r-sm);
  background: var(--panel-2); border: 1px solid var(--border);
  color: var(--text-soft); font-size: 15px; line-height: 1; font-weight: 700;
  cursor: pointer; user-select: none;
  -webkit-tap-highlight-color: transparent;
  transition: background .13s, border-color .13s, color .13s, transform .08s;
}
.pause-btn:hover { background: var(--panel-3); border-color: var(--border-strong); color: var(--text); }
.pause-btn:active { transform: scale(.94); }
.pause-btn.pause-badge {
  background: rgba(234, 179, 8, .14); border-color: rgba(234, 179, 8, .4);
  color: var(--yellow);
}
.pause-btn.auto-paused {
  background: rgba(234, 179, 8, .09); border-color: rgba(234, 179, 8, .28);
  color: var(--yellow);
}

/* ---- Читательская колонка: максимум места под текст ---- */
.lesson-body {
  max-width: calc(72ch + 300px);
  margin: 0 auto; width: 100%;
  padding: 16px 24px 80px;
}
.loading { gap: 10px; color: var(--muted); min-height: 40vh; }

.crumbs { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--muted); flex-wrap: wrap; margin-bottom: 14px; }
.crumbs a { color: var(--muted); }
.crumbs a:hover { color: var(--accent); }
.sep { color: var(--faint); }

.reader { display: grid; grid-template-columns: minmax(0, 1fr) 240px; gap: 32px; align-items: start; }

.doc { min-width: 0; width: 100%; max-width: 72ch; margin: 0 auto; }
.doc-head { padding-bottom: 14px; border-bottom: 1px solid var(--border); margin-bottom: 6px; }
.dh-top { display: flex; gap: 8px; align-items: center; margin-bottom: 10px; flex-wrap: wrap; }
.doc-head h1 { margin: 0 0 8px; font-size: clamp(1.45rem, 4.5vw, 2rem); }
.summary { margin: 0 0 14px; font-size: 15px; }
.tags { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 14px; }
.read-progress { display: flex; align-items: center; gap: 12px; margin-top: 8px; }
.read-progress .bar { flex: 1; }
.rp-label { font-size: 12px; color: var(--muted); white-space: nowrap; }

.sec { padding: 18px 0; border-bottom: 1px solid var(--border-soft); position: relative; }
.sec.read::before {
  content: ''; position: absolute; left: -14px; top: 22px; bottom: 22px; width: 3px;
  background: var(--green); border-radius: 3px; opacity: .6;
}
.sec-head { display: flex; align-items: baseline; justify-content: space-between; gap: 14px; margin-bottom: 10px; }
.sec-head h2 { margin: 0; font-size: clamp(1.15rem, 3.6vw, 1.4rem); }
.sec-state { display: inline-flex; align-items: center; flex: none; }
.sec-ring {
  --p: 0;
  width: 20px; height: 20px; border-radius: 50%;
  display: grid; place-items: center; position: relative;
  background: conic-gradient(var(--green) calc(var(--p) * 1%), var(--panel-3) 0);
  /* Долгое нажатие на кольце открывает слайдер скорости чтения: гасим
     выделение/контекстное меню и не даём странице скроллиться под пальцем. */
  cursor: grab; touch-action: none; user-select: none;
  -webkit-touch-callout: none; -webkit-tap-highlight-color: transparent;
}
.sec-ring:active { cursor: grabbing; }
.sec-ring::before { content: ''; position: absolute; inset: 3px; border-radius: 50%; background: var(--bg); }
/* Иконки — абсолютные оверлеи внутри кольца 20x20: не участвуют в потоке grid-контейнера,
   поэтому базовая линия и позиция кольца ОДИНАКОВЫ в любом состоянии (read/partial/paused) — нет сдвига. */
.sec-check { position: absolute; inset: 0; margin: auto; color: var(--green); }
.sec-state.on .sec-ring { background: var(--green); }

/* Пауза чтения: кольцо заморожено, поверх — глиф ⏸ (две вертикальные полосы).
   Показывается ТОЛЬКО у непрочитанных секций; у прочитанных остаётся зелёное кольцо с галочкой. */
.sec-ring.paused { filter: saturate(.3); }
.sec-pause { position: absolute; inset: 0; margin: auto; width: fit-content; height: fit-content; display: inline-flex; gap: 2px; }
.sec-pause i { width: 2px; height: 8px; border-radius: 1px; background: var(--muted); }

/* Умные кросс-ссылки: упоминание темы в прозе -> ссылка на урок.
   Стиль самой ссылки .topic-link — глобальный (main.css), т.к. элемент
   вставляется в DOM из JS и не получает scoped-атрибут. Здесь — только
   тултип, который отрисован Vue-шаблоном. */
.topic-tip {
  position: fixed; z-index: 80; max-width: 340px;
  padding: 9px 11px; border-radius: var(--r-sm);
  background: var(--panel-2); border: 1px solid var(--border-strong);
  box-shadow: var(--shadow-lg); pointer-events: none;
  font-size: 12px; line-height: 1.5; color: var(--text-soft);
}
.topic-tip .tt-title { color: var(--text); font-weight: 700; margin-bottom: 5px; }
.topic-tip .tt-path { display: flex; flex-wrap: wrap; align-items: baseline; gap: 3px 5px; margin-bottom: 6px; }
.topic-tip .tt-crumb { color: var(--muted); }
.topic-tip .tt-crumb.cur { color: var(--text-soft); }
.topic-tip .tt-crumb.tgt { color: var(--accent); font-weight: 600; }
.topic-tip .tt-sep { color: var(--faint); }
.topic-tip .tt-dist { color: var(--yellow); font-size: 11px; font-weight: 600; }

.doc-foot { display: flex; align-items: center; gap: 10px; margin-top: 30px; flex-wrap: wrap; }

/* Оглавление */
.toc {
  position: sticky; top: calc(var(--reading-bar-h) + 18px);
  max-height: calc(100vh - var(--reading-bar-h) - 40px); overflow-y: auto;
  padding-left: 4px;
}
.toc-title { font-size: 11px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); font-weight: 700; margin-bottom: 12px; }
.toc-item {
  display: flex; align-items: flex-start; gap: 9px;
  padding: 6px 8px; border-radius: var(--r-sm); cursor: pointer;
  font-size: 13px; color: var(--muted); text-decoration: none;
  transition: background .13s, color .13s;
}
.toc-item:hover { background: var(--panel-2); color: var(--text-soft); text-decoration: none; }
.toc-item.active { background: var(--panel-2); color: var(--text); }
.toc-item.read .toc-dot { background: var(--green); }
.toc-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--faint); margin-top: 6px; flex: none; }
.toc-text { line-height: 1.4; }
.toc-foot { display: flex; align-items: center; gap: 10px; margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--border); font-size: 12px; }
.mini-ring {
  --p: 0;
  width: 44px; height: 44px; border-radius: 50%;
  display: grid; place-items: center; font-size: 11px; font-weight: 800; color: var(--green);
  background: conic-gradient(var(--green) calc(var(--p) * 1%), var(--panel-3) 0);
  position: relative;
}
.mini-ring::before { content: ''; position: absolute; inset: 5px; border-radius: 50%; background: var(--bg); }
.mini-ring span { position: relative; }

.spin { animation: pulse 1s infinite; }

/* ---- Глобальный множитель скорости чтения (оверлей по удержанию кольца) ---- */
.speed-overlay {
  position: fixed; inset: 0; z-index: 120;
  background: rgba(2, 6, 12, 0.45);
  backdrop-filter: blur(2px);
  touch-action: none;
}
/* Трек позиционируется РОВНО по центру вьюпорта: верх = innerHeight/2 - 110.
   Именно это предполагает applySpeedFromY(), поэтому визуальный край трека
   совпадает с границами диапазона x0.5..x2.0. */
.speed-track {
  position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%);
  width: 12px; height: 220px;
  border-radius: 999px; background: var(--panel-3); border: 1px solid var(--border);
  box-shadow: var(--shadow-lg);
}
.speed-fill {
  position: absolute; left: 0; right: 0; bottom: 0;
  border-radius: 999px;
  background: linear-gradient(0deg, #38bdf8, #818cf8);
}
.speed-knob {
  position: absolute; left: 50%; width: 22px; height: 22px;
  margin-left: -11px; border-radius: 50%;
  background: #e2e8f0; border: 2px solid #818cf8;
  transform: translateY(50%);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.5);
}
.speed-readout {
  position: absolute; left: 50%; top: calc(50% + 126px); transform: translateX(-50%);
  display: flex; flex-direction: column; align-items: center; gap: 3px;
  padding: 7px 12px; border-radius: var(--r);
  background: rgba(9, 14, 21, 0.97);
  border: 1px solid var(--border-strong);
  box-shadow: var(--shadow-lg);
  user-select: none;
}
.speed-val { font-size: 15px; font-weight: 800; color: var(--text); }
.speed-hint { font-size: 10.5px; color: var(--muted); white-space: nowrap; }

@media (max-width: 1000px) {
  .reader { grid-template-columns: 1fr; }
  .toc { display: none; }
}

/* Телефоны: полоса чтения уже, читательская колонка — во всю ширину,
   вертикальный ритм плотнее, кнопки навигации во всю ширину. */
@media (max-width: 560px) {
  .reading-bar { gap: 8px; padding: 0 10px; }
  .rb-count { display: none; }
  .rb-bar { width: 56px; }
  .rb-pct { min-width: 30px; }
  .lesson-body { padding: 12px 14px 72px; }
  /* Крошки в одну строку с горизонтальным скроллом — не съедают экран. */
  .crumbs { flex-wrap: nowrap; overflow-x: auto; scrollbar-width: none; margin-bottom: 10px; }
  .crumbs::-webkit-scrollbar { display: none; }
  .sec { padding: 16px 0; }
  .sec.read::before { left: -8px; top: 20px; bottom: 20px; }
  .doc-foot { flex-direction: column; align-items: stretch; gap: 8px; }
  /* Кнопки навигации — во всю ширину и с переносом текста (иначе длинный
     заголовок соседнего урока растягивает страницу по горизонтали). */
  .doc-foot .btn { justify-content: center; white-space: normal; text-align: center; max-width: 100%; }
  .doc-foot .spacer { display: none; }
}
</style>
