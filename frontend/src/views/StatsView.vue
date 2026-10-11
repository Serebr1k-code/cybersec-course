<script setup>
import { computed, onMounted, ref } from 'vue'
import { useTreeStore } from '../stores/tree'
import { useProgressStore } from '../stores/progress'
import { api } from '../api/client'

const tree = useTreeStore()
const progress = useProgressStore()
const imported = ref('')
const achFilter = ref('all') // all | unlocked | locked

const stats = computed(() => progress.stats || null)

// --- категории: берём из stats, иначе считаем по дереву (fallback) --------
const byCat = computed(() => {
  const m = {}
  for (const n of tree.nodes) (m[n.category] ||= []).push(n)
  return m
})

const treeCatRows = computed(() =>
  tree.categories
    .map((c) => {
      const nodes = byCat.value[c.slug] || []
      let done = 0
      for (const n of nodes) if (progress.isCompleted(n.id)) done++
      return {
        slug: c.slug, name: c.name, color: c.color, icon: c.icon,
        total: nodes.length, done,
        pct: nodes.length ? Math.round((done / nodes.length) * 100) : 0
      }
    })
    .filter((c) => c.total > 0)
)

const catRows = computed(() =>
  stats.value?.categories?.length ? stats.value.categories : treeCatRows.value
)

const diffRows = computed(() => stats.value?.difficulties || [])

const overall = computed(() => {
  if (stats.value) {
    const total = stats.value.lessons_total
    const done = stats.value.lessons_completed
    return { done, total, pct: total ? Math.round((done / total) * 100) : 0 }
  }
  const total = tree.total
  let done = 0
  for (const n of tree.nodes) if (progress.isCompleted(n.id)) done++
  return { done, total, pct: total ? Math.round((done / total) * 100) : 0 }
})

const quiz = computed(
  () =>
    stats.value?.quiz || {
      answered: 0, correct: 0, accuracy: 0, perfect: 0,
      attempted: 0, attempts: 0, fails: 0, avg_score: 0, best_score: 0
    }
)

// --- время чтения (fallback, если stats недоступен) ----------------------
const totalReadSecs = computed(() => {
  if (stats.value?.total_read_seconds != null) return stats.value.total_read_seconds
  let s = 0
  const lessons = progress.user.lessons || {}
  for (const id in lessons) {
    const secs = lessons[id].sections || {}
    for (const k in secs) s += secs[k].read_seconds || 0
  }
  return s
})

function humanTime(secs) {
  secs = secs || 0
  if (secs < 60) return secs + ' сек'
  const m = Math.floor(secs / 60)
  if (m < 60) return m + ' мин'
  const h = Math.floor(m / 60)
  if (h < 24) return h + ' ч ' + (m % 60 ? (m % 60) + ' мин' : '').trim()
  return Math.floor(h / 24) + ' д ' + (h % 24 ? (h % 24) + ' ч' : '').trim()
}

const readTime = computed(() => stats.value?.total_read_human || humanTime(totalReadSecs.value))

const avgRead = computed(() => stats.value?.avg_read_human || humanTime(stats.value?.avg_read_seconds || 0))

// --- достижения, сгруппированные по темам --------------------------------
const achGroups = computed(() => {
  const order = []
  const m = {}
  for (const a of progress.achievements) {
    const t = a.theme || 'Прочее'
    if (!m[t]) {
      m[t] = []
      order.push(t)
    }
    m[t].push(a)
  }
  return order.map((t) => {
    let items = m[t]
    if (achFilter.value === 'unlocked') items = items.filter((a) => a.unlocked)
    if (achFilter.value === 'locked') items = items.filter((a) => !a.unlocked)
    return { theme: t, items, unlocked: m[t].filter((a) => a.unlocked).length, total: m[t].length }
  }).filter((g) => g.items.length > 0)
})

const achUnlocked = computed(() => progress.achievements.filter((a) => a.unlocked).length)
const achTotal = computed(() => progress.achievements.length)

const levelProgress = computed(() => {
  if (stats.value) return Math.round((stats.value.level_progress || 0) * 100)
  return Math.round(progress.levelProgress * 100)
})
const xpToNext = computed(() => stats.value?.xp_to_next ?? progress.xpToNext)
const level = computed(() => stats.value?.level ?? progress.level)

// --- тепловая карта активности за последние ~16 недель --------------------
const heat = computed(() => {
  const days = []
  const today = new Date()
  const start = new Date(today)
  start.setDate(today.getDate() - 111)
  start.setDate(start.getDate() - start.getDay()) // к началу недели
  const act = progress.user.activity || {}
  for (let i = 0; i < 119; i++) {
    const d = new Date(start)
    d.setDate(start.getDate() + i)
    const key = d.toISOString().slice(0, 10)
    const n = act[key] || 0
    days.push({ key, n, future: d > today })
  }
  return days
})

function heatClass(n) {
  if (n <= 0) return 'h0'
  if (n < 5) return 'h1'
  if (n < 15) return 'h2'
  if (n < 30) return 'h3'
  return 'h4'
}

function shortDate(ts) {
  if (!ts) return ''
  const d = new Date(ts * 1000)
  return d.toLocaleDateString('ru-RU', { day: '2-digit', month: 'short' })
}

async function doExport() {
  const data = await api.exportProgress()
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'learning-tree-progress.json'
  a.click()
  URL.revokeObjectURL(url)
}

function doImport(e) {
  const file = e.target.files[0]
  if (!file) return
  const reader = new FileReader()
  reader.onload = async () => {
    try {
      await api.importProgress(JSON.parse(reader.result))
      imported.value = 'Импортировано ✓'
      await progress.load()
      setTimeout(() => (imported.value = ''), 2000)
    } catch (err) {
      imported.value = 'Ошибка импорта'
    }
  }
  reader.readAsText(file)
}

onMounted(async () => {
  await tree.load()
  await progress.load()
})
</script>

<template>
  <div class="stats-view">
    <h1>Прогресс обучения</h1>

    <!-- HERO: общий прогресс + ключевые метрики -->
    <div class="hero card">
      <div class="hero-left">
        <div class="big-ring" :style="{ '--p': overall.pct }"><span>{{ overall.pct }}%</span></div>
        <div>
          <div class="hero-done">{{ overall.done }} из {{ overall.total }}</div>
          <div class="muted">уроков пройдено</div>
        </div>
      </div>
      <div class="hero-metrics">
        <div class="metric"><span class="m-val">{{ progress.xp }}</span><span class="m-lbl">XP</span></div>
        <div class="metric"><span class="m-val">LVL {{ level }}</span><span class="m-lbl">уровень</span></div>
        <div class="metric"><span class="m-val">🔥 {{ progress.streak }}</span><span class="m-lbl">дней подряд</span></div>
        <div class="metric"><span class="m-val">{{ readTime }}</span><span class="m-lbl">время чтения</span></div>
      </div>
    </div>

    <!-- КАРТОЧКИ КЛЮЧЕВЫХ МЕТРИК -->
    <section class="block">
      <div class="cards-grid">
        <div class="kpi card">
          <span class="kpi-ico">⏱️</span>
          <span class="kpi-val">{{ readTime }}</span>
          <span class="kpi-lbl">Всего прочитано</span>
          <span class="muted kpi-sub">в среднем {{ avgRead }} на урок</span>
        </div>
        <div class="kpi card">
          <span class="kpi-ico">📘</span>
          <span class="kpi-val">{{ stats?.lessons_completed ?? overall.done }}</span>
          <span class="kpi-lbl">Уроков пройдено</span>
          <span class="muted kpi-sub">начато {{ stats?.lessons_started ?? 0 }} · осталось {{ stats?.lessons_remaining ?? (overall.total - overall.done) }}</span>
        </div>
        <div class="kpi card">
          <span class="kpi-ico">🎯</span>
          <span class="kpi-val">{{ quiz.accuracy }}%</span>
          <span class="kpi-lbl">Точность квизов</span>
          <span class="muted kpi-sub">{{ quiz.correct }} из {{ quiz.answered }} вопросов</span>
        </div>
        <div class="kpi card">
          <span class="kpi-ico">🔥</span>
          <span class="kpi-val">{{ stats?.current_streak ?? progress.streak }}</span>
          <span class="kpi-lbl">Дней подряд</span>
          <span class="muted kpi-sub">рекорд {{ stats?.longest_streak ?? 0 }} · дней всего {{ stats?.active_days ?? 0 }}</span>
        </div>
        <div class="kpi card">
          <span class="kpi-ico">⭐</span>
          <span class="kpi-val">LVL {{ level }}</span>
          <span class="kpi-lbl">{{ progress.xp }} XP</span>
          <div class="bar kpi-bar"><i :style="{ width: levelProgress + '%' }"></i></div>
          <span class="muted kpi-sub">{{ xpToNext }} XP до следующего</span>
        </div>
        <div class="kpi card">
          <span class="kpi-ico">🏆</span>
          <span class="kpi-val">{{ achUnlocked }}<small>/{{ achTotal }}</small></span>
          <span class="kpi-lbl">Достижений открыто</span>
          <div class="bar kpi-bar"><i :style="{ width: (achTotal ? (achUnlocked / achTotal) * 100 : 0) + '%' }"></i></div>
        </div>
      </div>
    </section>

    <!-- ПАНЕЛЬ КВИЗОВ -->
    <section class="block">
      <h2>Квизы</h2>
      <div class="quiz card">
        <div class="quiz-ring-wrap">
          <div class="big-ring sm" :style="{ '--p': quiz.accuracy }"><span>{{ quiz.accuracy }}%</span></div>
          <span class="muted">точность</span>
        </div>
        <div class="quiz-facts">
          <div class="fact"><span class="f-val">{{ quiz.answered }}</span><span class="f-lbl">вопросов отвечено</span></div>
          <div class="fact"><span class="f-val">{{ quiz.correct }}</span><span class="f-lbl">верных ответов</span></div>
          <div class="fact"><span class="f-val">{{ quiz.perfect }}</span><span class="f-lbl">идеальных квизов</span></div>
          <div class="fact"><span class="f-val">{{ quiz.avg_score }}%</span><span class="f-lbl">средний балл</span></div>
          <div class="fact"><span class="f-val">{{ quiz.best_score }}</span><span class="f-lbl">лучший результат</span></div>
          <div class="fact"><span class="f-val">{{ quiz.attempts }}</span><span class="f-lbl">попыток всего</span></div>
        </div>
      </div>
    </section>

    <!-- ПО КАТЕГОРИЯМ -->
    <section class="block">
      <h2>По категориям</h2>
      <div class="cats-grid">
        <div v-for="c in catRows" :key="c.slug" class="cat-card card">
          <div class="cc-head">
            <span class="cc-ico" :style="{ borderColor: c.color }">{{ c.icon }}</span>
            <div class="cc-main">
              <span class="cc-name">{{ c.name }}</span>
              <span class="muted">{{ c.done }} / {{ c.total }}</span>
            </div>
            <span class="cc-pct" :style="{ color: c.color }">{{ c.pct }}%</span>
          </div>
          <div class="bar"><i :style="{ width: c.pct + '%', background: c.color }"></i></div>
        </div>
      </div>
      <p v-if="stats?.most_progressed_category" class="muted hint">
        Лучше всего: <b>{{ stats.most_progressed_category.name }}</b> ({{ stats.most_progressed_category.pct }}%) ·
        стоит подтянуть: <b>{{ stats.least_progressed_category.name }}</b> ({{ stats.least_progressed_category.pct }}%)
      </p>
    </section>

    <!-- ПО СЛОЖНОСТИ -->
    <section v-if="diffRows.length" class="block">
      <h2>По сложности</h2>
      <div class="diff-list card">
        <div v-for="d in diffRows" :key="d.key" class="diff-row">
          <span class="d-label">{{ d.label }}</span>
          <div class="bar diff-bar"><i :style="{ width: d.pct + '%', background: d.color }"></i></div>
          <span class="d-count muted">{{ d.done }}/{{ d.total }}</span>
        </div>
      </div>
    </section>

    <!-- ДОСТИЖЕНИЯ -->
    <section class="block">
      <div class="ach-head">
        <h2>Достижения <span class="muted ach-count">{{ achUnlocked }} / {{ achTotal }}</span></h2>
        <div class="ach-filter">
          <button class="btn btn-sm" :class="{ 'btn-primary': achFilter === 'all' }" @click="achFilter = 'all'">Все</button>
          <button class="btn btn-sm" :class="{ 'btn-primary': achFilter === 'unlocked' }" @click="achFilter = 'unlocked'">Открытые</button>
          <button class="btn btn-sm" :class="{ 'btn-primary': achFilter === 'locked' }" @click="achFilter = 'locked'">Закрытые</button>
        </div>
      </div>
      <div v-for="g in achGroups" :key="g.theme" class="ach-group">
        <h3 class="ach-theme">{{ g.theme }} <span class="muted">{{ g.unlocked }}/{{ g.total }}</span></h3>
        <div class="ach-grid">
          <div v-for="a in g.items" :key="a.id" class="ach card" :class="{ locked: !a.unlocked }">
            <span class="ach-ico">{{ a.icon }}</span>
            <div class="ach-body">
              <span class="ach-title">{{ a.title }}</span>
              <span class="muted ach-desc">{{ a.desc }}</span>
              <div v-if="!a.unlocked" class="bar ach-bar"><i :style="{ width: a.progress + '%' }"></i></div>
              <span v-else class="ach-have muted">открыто</span>
            </div>
            <span v-if="a.unlocked" class="ach-check">✓</span>
          </div>
        </div>
      </div>
    </section>

    <!-- АКТИВНОСТЬ -->
    <section class="block">
      <h2>Активность</h2>
      <div class="heat card">
        <div class="heat-grid">
          <span
            v-for="d in heat"
            :key="d.key"
            class="cell"
            :class="[heatClass(d.n), { future: d.future }]"
            :title="d.key + ': ' + d.n + ' событий'"
          ></span>
        </div>
        <div class="heat-legend">
          <span class="muted">меньше</span>
          <i class="cell h0"></i><i class="cell h1"></i><i class="cell h2"></i><i class="cell h3"></i><i class="cell h4"></i>
          <span class="muted">больше</span>
        </div>
      </div>
    </section>

    <!-- НЕДАВНЯЯ АКТИВНОСТЬ -->
    <section v-if="stats?.recent?.length" class="block">
      <h2>Недавно открытые уроки</h2>
      <div class="recent card">
        <div v-for="r in stats.recent" :key="r.id" class="recent-row">
          <span class="r-ico">{{ r.icon }}</span>
          <div class="r-main">
            <span class="r-title">{{ r.title }}</span>
            <span class="muted r-sub">{{ r.category }} · прочитано секций: {{ r.sections_read }}</span>
          </div>
          <span v-if="r.completed" class="chip good r-done">✓ пройден</span>
          <span class="muted r-date">{{ shortDate(r.updated_at) }}</span>
        </div>
      </div>
    </section>

    <!-- ДАННЫЕ -->
    <section class="block">
      <h2>Данные</h2>
      <div class="data card">
        <p class="muted">Прогресс хранится на сервере (привязан к cookie браузера). Экспортируйте его для бэкапа или переноса на другое устройство.</p>
        <div class="row">
          <button class="btn" @click="doExport">⬇ Экспорт</button>
          <label class="btn">⬆ Импорт<input type="file" accept="application/json" @change="doImport" hidden /></label>
          <span v-if="imported" class="chip good">{{ imported }}</span>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.stats-view { width: 100%; max-width: 1080px; margin: 0 auto; padding: 28px 24px 80px; box-sizing: border-box; }
h1 { font-size: 1.7rem; margin: 0 0 22px; }
h2 { font-size: 1.1rem; margin: 0 0 14px; }
h3 { font-size: 1rem; }
.block { margin-top: 32px; }

/* HERO */
.hero { display: flex; align-items: center; justify-content: space-between; gap: 24px; padding: 24px 28px; flex-wrap: wrap; }
.hero-left { display: flex; align-items: center; gap: 20px; }
.big-ring {
  --p: 0; width: 92px; height: 92px; border-radius: 50%;
  display: grid; place-items: center; position: relative;
  background: conic-gradient(var(--green) calc(var(--p) * 1%), var(--panel-3) 0);
}
.big-ring::before { content: ''; position: absolute; inset: 8px; border-radius: 50%; background: var(--panel); }
.big-ring span { position: relative; font-size: 1.4rem; font-weight: 800; color: var(--green); }
.big-ring.sm { width: 84px; height: 84px; }
.big-ring.sm span { font-size: 1.15rem; }
.hero-done { font-size: 1.2rem; font-weight: 700; }
.hero-metrics { display: flex; gap: 26px; flex-wrap: wrap; }
.metric { display: flex; flex-direction: column; }
.m-val { font-size: 1.3rem; font-weight: 800; }
.m-lbl { font-size: 11.5px; color: var(--muted); }

/* KPI CARDS */
.cards-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(190px, 1fr)); gap: 12px; }
.kpi { display: flex; flex-direction: column; gap: 3px; padding: 16px 18px; }
.kpi-ico { font-size: 20px; }
.kpi-val { font-size: 1.5rem; font-weight: 800; line-height: 1.1; }
.kpi-val small { font-size: .9rem; color: var(--muted); font-weight: 600; }
.kpi-lbl { font-size: 12.5px; color: var(--text-soft); }
.kpi-sub { font-size: 11.5px; }
.kpi-bar { margin-top: 7px; height: 5px; }

/* QUIZ */
.quiz { display: flex; align-items: center; gap: 28px; padding: 20px 24px; flex-wrap: wrap; }
.quiz-ring-wrap { display: flex; flex-direction: column; align-items: center; gap: 6px; }
.quiz-facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 14px 24px; flex: 1; }
.fact { display: flex; flex-direction: column; }
.f-val { font-size: 1.25rem; font-weight: 800; }
.f-lbl { font-size: 11.5px; color: var(--muted); }

/* CATEGORIES */
.cats-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; }
.cat-card { padding: 14px 16px; }
.cc-head { display: flex; align-items: center; gap: 12px; margin-bottom: 11px; }
.cc-ico { width: 34px; height: 34px; border-radius: 9px; display: grid; place-items: center; border: 1px solid var(--border-strong); font-size: 17px; }
.cc-main { flex: 1; display: flex; flex-direction: column; }
.cc-name { font-weight: 600; font-size: 14px; }
.cc-main .muted { font-size: 12px; }
.cc-pct { font-weight: 800; font-size: 15px; }
.hint { margin: 12px 2px 0; font-size: 12.5px; }

/* DIFFICULTY */
.diff-list { display: flex; flex-direction: column; gap: 12px; padding: 18px 20px; }
.diff-row { display: grid; grid-template-columns: 90px 1fr 54px; align-items: center; gap: 12px; }
.d-label { font-size: 13px; font-weight: 600; }
.diff-bar { height: 8px; }
.d-count { font-size: 12px; text-align: right; }

/* ACHIEVEMENTS */
.ach-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 6px; }
.ach-head h2 { margin: 0; }
.ach-count { font-size: .85rem; font-weight: 500; }
.ach-filter { display: flex; gap: 6px; }
.ach-group { margin-top: 20px; }
.ach-theme { margin: 0 0 10px; color: var(--text-soft); display: flex; align-items: center; gap: 8px; }
.ach-theme .muted { font-size: 12px; }
.ach-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; }
.ach { display: flex; align-items: center; gap: 13px; padding: 14px 16px; }
.ach.locked { opacity: .6; }
.ach-ico { font-size: 26px; }
.ach-body { flex: 1; display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.ach-title { font-weight: 600; font-size: 14px; }
.ach-desc { font-size: 12px; }
.ach-bar { margin-top: 6px; height: 5px; }
.ach-have { font-size: 11px; color: var(--green); }
.ach-check { color: var(--green); font-weight: 900; font-size: 18px; }

/* HEATMAP */
.heat { padding: 18px; }
.heat-grid { display: grid; grid-auto-flow: column; grid-template-rows: repeat(7, 13px); gap: 3px; overflow-x: auto; padding-bottom: 6px; }
.cell { width: 13px; height: 13px; border-radius: 3px; background: var(--panel-3); }
.cell.h0 { background: var(--panel-3); }
.cell.h1 { background: #14532d; }
.cell.h2 { background: #15803d; }
.cell.h3 { background: #22c55e; }
.cell.h4 { background: #4ade80; }
.cell.future { opacity: .25; }
.heat-legend { display: flex; align-items: center; gap: 5px; margin-top: 12px; font-size: 11px; }

/* RECENT */
.recent { display: flex; flex-direction: column; padding: 6px 8px; }
.recent-row { display: flex; align-items: center; gap: 12px; padding: 10px 10px; border-bottom: 1px solid var(--border-soft); }
.recent-row:last-child { border-bottom: none; }
.r-ico { font-size: 20px; }
.r-main { flex: 1; display: flex; flex-direction: column; min-width: 0; }
.r-title { font-size: 14px; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.r-sub { font-size: 11.5px; }
.r-done { font-size: 11px; }
.r-date { font-size: 11.5px; white-space: nowrap; }

/* DATA */
.data { padding: 18px 20px; }
.data p { margin: 0 0 14px; font-size: 13.5px; }
.chip.good { background: rgba(34,197,94,.15); border-color: rgba(34,197,94,.4); color: #86efac; }

/* Телефоны: одна колонка, меньше отступы, ничего не вылезает по горизонтали. */
@media (max-width: 700px) {
  .stats-view { padding: 18px 14px 72px; }
  h1 { font-size: 1.4rem; margin-bottom: 16px; }
  .block { margin-top: 24px; }
  .hero { padding: 18px; gap: 16px; }
  .hero-left { gap: 14px; }
  .big-ring { width: 74px; height: 74px; }
  .big-ring span { font-size: 1.15rem; }
  .hero-metrics { gap: 14px 22px; }
  .m-val { font-size: 1.15rem; }
  .cards-grid { grid-template-columns: 1fr 1fr; }
  .kpi { padding: 14px; }
  .kpi-val { font-size: 1.25rem; }
  .quiz { gap: 16px; padding: 16px; }
  .cats-grid, .ach-grid { grid-template-columns: 1fr; }
  .diff-row { grid-template-columns: 74px 1fr 46px; gap: 9px; }
  .data .row { flex-wrap: wrap; }
}
</style>
