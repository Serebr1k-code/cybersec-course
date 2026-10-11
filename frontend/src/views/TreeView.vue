<script setup>
import { ref, computed, onMounted } from 'vue'
import { useTreeStore } from '../stores/tree'
import { useProgressStore } from '../stores/progress'
import TreeGraph from '../components/TreeGraph.vue'

const tree = useTreeStore()
const progress = useProgressStore()
const selected = ref('')
// Узел, который нужно центрировать в графе (последний открытый урок или корень).
const focusId = ref('')
// На телефоне список категорий — выезжающий ящик (drawer). По умолчанию закрыт.
const catsOpen = ref(false)

const byCat = computed(() => {
  const m = {}
  for (const n of tree.nodes) (m[n.category] ||= []).push(n)
  return m
})

// Корень категории: узел без родителя (или с родителем вне категории),
// при равенстве — по order, затем по названию.
function rootOf(slug) {
  const nodes = byCat.value[slug] || []
  if (!nodes.length) return null
  const ids = new Set(nodes.map((n) => n.id))
  const roots = nodes
    .filter((n) => !n.parent || !ids.has(n.parent))
    .sort((a, b) => (a.order - b.order) || a.title.localeCompare(b.title))
  const pick = roots[0] || nodes.slice().sort((a, b) => (a.order - b.order) || a.title.localeCompare(b.title))[0]
  return pick ? pick.id : null
}

// Цель фокуса для категории: последний открытый урок, если он в этой
// категории, иначе — корень категории.
function focusTargetFor(slug) {
  const nodes = byCat.value[slug] || []
  if (!nodes.length) return ''
  const last = progress.lastLesson
  if (last && nodes.some((n) => n.id === last)) return last
  return rootOf(slug) || ''
}

function catProgress(slug) {
  const nodes = byCat.value[slug] || []
  if (!nodes.length) return { done: 0, total: 0, pct: 0 }
  let done = 0
  for (const n of nodes) if (progress.isCompleted(n.id)) done++
  return { done, total: nodes.length, pct: Math.round((done / nodes.length) * 100) }
}

const overall = computed(() => {
  const total = tree.total
  let done = 0
  for (const n of tree.nodes) if (progress.isCompleted(n.id)) done++
  return { done, total, pct: total ? Math.round((done / total) * 100) : 0 }
})

const currentCat = computed(() => tree.categories.find((c) => c.slug === selected.value))
const currentNodes = computed(() => byCat.value[selected.value] || [])

// Рекомендация: следующий непрочитанный урок выбранной категории.
const recommendation = computed(() => {
  const nodes = currentNodes.value
  const next = nodes.find((n) => !progress.lessonRead(n.id))
  return next || null
})

onMounted(async () => {
  await tree.load()
  await progress.load()
  if (!selected.value) {
    // Категория последнего открытого урока имеет приоритет над дефолтной.
    const last = progress.lastLesson
    const lastCat = last ? tree.node(last)?.category : null
    const withContent = tree.categories.find((c) => byCat.value[c.slug]?.length)
    selected.value =
      (lastCat && byCat.value[lastCat]?.length ? lastCat : null) ||
      withContent?.slug ||
      tree.categories[0]?.slug ||
      ''
  }
  focusId.value = focusTargetFor(selected.value)
})

function pick(slug) {
  selected.value = slug
  catsOpen.value = false // на телефоне после выбора категории ящик закрывается
  // Ручной выбор категории: фокус на её последнем прочитанном узле или корне.
  focusId.value = focusTargetFor(slug)
}
</script>

<template>
  <div class="tree-view" :class="{ 'cats-open': catsOpen }">
    <aside class="sidebar">
      <button class="cats-close" type="button" title="Закрыть" @click="catsOpen = false">✕</button>
      <div class="overall card">
        <div class="ov-top">
          <span class="ov-label">Общий прогресс</span>
          <b>{{ overall.pct }}%</b>
        </div>
        <div class="bar"><i :style="{ width: overall.pct + '%' }"></i></div>
        <div class="ov-stats">
          <span><b>{{ overall.done }}</b> / {{ overall.total }} уроков</span>
          <span>🔥 {{ progress.streak }} дн.</span>
          <span>⭐ {{ progress.xp }} XP</span>
        </div>
      </div>

      <nav class="cats">
        <button
          v-for="c in tree.categories"
          :key="c.slug"
          class="cat"
          :class="{ active: selected === c.slug, empty: !byCat[c.slug]?.length }"
          :style="{ '--c': c.color }"
          @click="pick(c.slug)"
        >
          <span class="cat-ico">{{ c.icon }}</span>
          <span class="cat-main">
            <span class="cat-name">{{ c.name }}</span>
            <span class="cat-bar"><i :style="{ width: catProgress(c.slug).pct + '%' }"></i></span>
          </span>
          <span class="cat-count">{{ catProgress(c.slug).done }}/{{ catProgress(c.slug).total }}</span>
        </button>
      </nav>
    </aside>

    <div v-if="catsOpen" class="cats-backdrop" @click="catsOpen = false"></div>

    <section class="main">
      <button class="cats-toggle" type="button" @click="catsOpen = true">
        <span aria-hidden="true">☰</span> Категории
      </button>
      <header v-if="currentCat" class="cat-head">
        <div class="ch-left">
          <span class="ch-ico" :style="{ background: currentCat.color + '22', borderColor: currentCat.color }">{{ currentCat.icon }}</span>
          <div>
            <h1>{{ currentCat.name }}</h1>
            <p class="muted">{{ currentCat.description }}</p>
          </div>
        </div>
        <div class="ch-right">
          <span class="chip">{{ currentNodes.length }} уроков</span>
          <span class="chip">{{ catProgress(selected).done }} пройдено</span>
        </div>
      </header>

      <div v-if="recommendation" class="reco card">
        <span class="reco-ico">▶</span>
        <div class="reco-body">
          <span class="muted">Продолжить обучение</span>
          <RouterLink :to="'/lesson/' + recommendation.id" class="reco-title">{{ recommendation.title }}</RouterLink>
        </div>
        <RouterLink :to="'/lesson/' + recommendation.id" class="btn btn-primary btn-sm">Открыть</RouterLink>
      </div>

      <div v-if="tree.loading" class="loading center"><span class="spin">⏳</span> Загрузка дерева…</div>
      <div v-else-if="!currentNodes.length" class="empty-state card">
        <p>В этой категории пока нет уроков.</p>
        <p class="muted">Запустите агента-автора: он создаст уроки в <code>content/{{ selected }}/</code>.</p>
      </div>
      <TreeGraph v-else :nodes="currentNodes" :color="currentCat?.color || '#38bdf8'" :focus-id="focusId" />
    </section>
  </div>
</template>

<style scoped>
.tree-view { display: flex; flex: 1; min-height: 0; height: calc(100vh - var(--topbar-h)); }

.sidebar {
  width: var(--sidebar-w); flex: none;
  border-right: 1px solid var(--border);
  padding: 16px; overflow-y: auto;
  background: rgba(11,17,26,.5);
}
.overall { padding: 14px; margin-bottom: 16px; }
.ov-top { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: 8px; }
.ov-label { font-size: 13px; color: var(--muted); }
.ov-top b { font-size: 1.3rem; color: var(--green); }
.ov-stats { display: flex; gap: 12px; margin-top: 10px; font-size: 12px; color: var(--muted); flex-wrap: wrap; }
.ov-stats b { color: var(--text); }

.cats { display: flex; flex-direction: column; gap: 4px; }
.cat {
  display: flex; align-items: center; gap: 11px;
  width: 100%; padding: 10px 11px; border-radius: var(--r);
  background: transparent; border: 1px solid transparent;
  color: var(--text-soft); font: inherit; cursor: pointer; text-align: left;
  transition: background .14s, border-color .14s;
}
.cat:hover { background: var(--panel-2); }
.cat.active { background: var(--panel-2); border-color: var(--border-strong); color: var(--text); box-shadow: inset 3px 0 0 var(--c); }
.cat.empty { opacity: .5; }
.cat-ico { font-size: 18px; width: 24px; text-align: center; }
.cat-main { flex: 1; display: flex; flex-direction: column; gap: 5px; min-width: 0; }
.cat-name { font-size: 13.5px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.cat-bar { height: 4px; border-radius: 999px; background: var(--panel-3); overflow: hidden; }
.cat-bar > i { display: block; height: 100%; background: var(--c, var(--green)); transition: width .4s; }
.cat-count { font-size: 11px; color: var(--muted); font-family: var(--mono); }

.main { flex: 1; min-width: 0; display: flex; flex-direction: column; padding: 18px; gap: 14px; }
.cat-head { display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
.ch-left { display: flex; align-items: center; gap: 14px; }
.ch-ico {
  width: 46px; height: 46px; border-radius: 13px; display: grid; place-items: center;
  font-size: 23px; border: 1px solid var(--border-strong);
}
.cat-head h1 { margin: 0; font-size: 1.4rem; }
.cat-head p { margin: 3px 0 0; font-size: 13px; max-width: 560px; }
.ch-right { display: flex; gap: 8px; }

.reco { display: flex; align-items: center; gap: 14px; padding: 12px 16px; }
.reco-ico { color: var(--green); font-size: 15px; }
.reco-body { flex: 1; display: flex; flex-direction: column; }
.reco-body .muted { font-size: 11.5px; }
.reco-title { font-weight: 600; font-size: 14.5px; }

.loading { flex: 1; gap: 10px; color: var(--muted); }
.empty-state { padding: 40px; text-align: center; }
.empty-state code { color: #a5e6ff; }

/* Элементы мобильного «ящика» категорий скрыты на десктопе. */
.cats-toggle, .cats-close, .cats-backdrop { display: none; }

@media (max-width: 900px) {
  /* На телефоне дерево занимает весь экран под топбаром, а список категорий
     превращается в выезжающий ящик (drawer) — освобождает место под канвас. */
  .tree-view {
    position: relative;
    flex-direction: row;
    height: calc(100vh - var(--topbar-h));
    height: calc(100dvh - var(--topbar-h));
    overflow: hidden;
  }

  .sidebar {
    position: absolute; top: 0; bottom: 0; left: 0; z-index: 30;
    width: min(86vw, 320px); max-width: 320px;
    padding: 14px;
    border-right: 1px solid var(--border); border-bottom: none;
    background: var(--bg-soft);
    box-shadow: var(--shadow-lg);
    transform: translateX(-102%);
    transition: transform .22s ease;
    will-change: transform;
  }
  .tree-view.cats-open .sidebar { transform: none; }

  .cats-close {
    display: grid; place-items: center;
    position: absolute; top: 10px; right: 10px;
    width: 34px; height: 34px; border-radius: var(--r-sm);
    background: var(--panel-2); border: 1px solid var(--border);
    color: var(--text-soft); font-size: 14px; cursor: pointer;
  }
  .cats-backdrop {
    display: block; position: absolute; inset: 0; z-index: 25;
    background: rgba(3, 6, 10, .55); backdrop-filter: blur(2px);
  }

  .cats-toggle {
    display: inline-flex; align-items: center; gap: 8px;
    align-self: flex-start;
    padding: 8px 14px; border-radius: var(--r);
    background: var(--panel-2); border: 1px solid var(--border);
    color: var(--text); font: inherit; font-size: 13.5px; font-weight: 600;
    cursor: pointer;
  }
  .cats-toggle span { font-size: 16px; }

  .main { flex: 1; min-width: 0; height: auto; padding: 12px; gap: 10px; }
  .cat-head p { display: none; }        /* описание категории прячем на телефоне */
  .ch-ico { width: 38px; height: 38px; font-size: 19px; border-radius: 10px; }
  .cat-head h1 { font-size: 1.15rem; }
  .ch-right { display: none; }          /* счётчики-чипы прячем — экономим строку */
}

/* ---------- Узкие телефоны (<=700px): убираем карточку «Продолжить обучение» ----------
   На маленьком экране она отнимает высоту у канваса дерева, а сам урок всегда
   доступен тапом по узлу. Это чисто визуальное скрытие: логика recommendation
   и роутинг не меняются. На планшетах/десктопе (>700px) карточка остаётся. */
@media (max-width: 700px) {
  .reco { display: none; }
}
</style>
