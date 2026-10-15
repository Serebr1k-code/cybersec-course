<script setup>
import { onMounted, onBeforeUnmount, computed, ref } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'
import { useTreeStore } from './stores/tree'
import { useProgressStore } from './stores/progress'
import { useAuthStore } from './stores/auth'
import SearchBox from './components/SearchBox.vue'

const tree = useTreeStore()
const progress = useProgressStore()
const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

const nav = [
  { to: '/', label: 'Дерево', icon: '🕸️' },
  { to: '/stats', label: 'Прогресс', icon: '📊' },
  { to: '/about', label: 'О проекте', icon: 'ℹ️' }
]

const levelPct = computed(() => Math.round(progress.levelProgress * 100))

// На странице урока обычный топбар заменяется тонкой полосой чтения, которую
// рисует сам LessonView (максимум места под текст). Здесь мы его просто прячем.
const isLesson = computed(() => route.name === 'lesson')

// На экране входа/регистрации топбар тоже не нужен — он ведёт на закрытые
// маршруты и отвлекал бы от формы.
const showTopbar = computed(() => !isLesson.value && route.name !== 'login')

// --- Обновление данных без перезагрузки страницы ---------------------------
// Перезапрашивает дерево (со всеми уроками/счётчиками) и прогресс с сервера.
const refreshing = ref(false)
const justRefreshed = ref(false)
// Троттлинг авто-обновления: не чаще одного раза в ~10 секунд.
const THROTTLE_MS = 10000
let lastRefresh = Date.now()
let doneTimer = null

async function refresh(force = true) {
  if (refreshing.value) return
  refreshing.value = true
  lastRefresh = Date.now()
  try {
    await tree.load(force)
    await progress.load()
    justRefreshed.value = true
    clearTimeout(doneTimer)
    doneTimer = setTimeout(() => { justRefreshed.value = false }, 1600)
  } finally {
    refreshing.value = false
  }
}

function autoRefresh() {
  if (document.visibilityState !== 'visible') return
  if (Date.now() - lastRefresh < THROTTLE_MS) return
  refresh(true)
}

function onVisibility() {
  if (document.visibilityState === 'visible') autoRefresh()
}

// Выход из аккаунта: чистим сессию на сервере и возвращаемся на экран входа.
async function doLogout() {
  await auth.logout()
  await progress.load()
  router.push('/login')
}

onMounted(() => {
  tree.load()
  progress.load()
  auth.load()
  document.addEventListener('visibilitychange', onVisibility)
  window.addEventListener('focus', autoRefresh)
})

onBeforeUnmount(() => {
  document.removeEventListener('visibilitychange', onVisibility)
  window.removeEventListener('focus', autoRefresh)
  clearTimeout(doneTimer)
})
</script>

<template>
  <div class="app">
    <header v-if="showTopbar" class="topbar">
      <RouterLink to="/" class="brand">
        <span class="brand-mark">CTF</span>
        <span class="brand-text">
          <b>Learning Tree</b>
          <i>интерактивный путь</i>
        </span>
      </RouterLink>

      <nav class="nav">
        <RouterLink v-for="n in nav" :key="n.to" :to="n.to" class="nav-link" active-class="active">
          <span class="nav-ico">{{ n.icon }}</span><span class="nav-lbl">{{ n.label }}</span>
        </RouterLink>
      </nav>

      <SearchBox />

      <RouterLink
        v-if="!auth.isLoggedIn"
        to="/login"
        class="user-chip guest"
        title="Войти или зарегистрироваться"
      >
        <span class="user-ico">👤</span><span class="user-lbl">Войти</span>
      </RouterLink>
      <div v-else class="user-chip" :title="`Вы вошли как ${auth.username}`">
        <span class="user-ico">👤</span><span class="user-lbl">{{ auth.username }}</span>
        <button class="logout-x" title="Выйти" aria-label="Выйти" @click="doLogout">⎋</button>
      </div>

      <button
        class="refresh-btn"
        :class="{ busy: refreshing, done: justRefreshed }"
        :disabled="refreshing"
        :title="justRefreshed ? 'Данные обновлены' : 'Обновить дерево и прогресс'"
        @click="refresh(true)"
      >
        <span class="refresh-ico" :class="{ spin: refreshing }">{{ justRefreshed ? '✓' : '↻' }}</span>
        <span class="refresh-lbl">{{ justRefreshed ? 'Обновлено' : 'Обновить' }}</span>
      </button>

      <div class="hud" :title="`Уровень ${progress.level} · ${progress.xp} XP`">
        <div class="hud-xp">
          <span class="hud-lvl">LVL {{ progress.level }}</span>
          <div class="hud-bar"><i :style="{ width: levelPct + '%' }"></i></div>
          <span class="hud-num mono">{{ progress.xp }} XP</span>
        </div>
        <div class="hud-streak" :title="`Серия чтения: ${progress.streak} дн.`">
          <span>🔥</span><b>{{ progress.streak }}</b>
        </div>
      </div>
    </header>

    <main class="content">
      <RouterView v-slot="{ Component }">
        <transition name="page" mode="out-in">
          <component :is="Component" :key="route.fullPath" />
        </transition>
      </RouterView>
    </main>

    <div v-if="tree.error" class="banner-error">
      Не удалось загрузить данные: {{ tree.error }}. Убедитесь, что бэкенд запущен на :8090.
    </div>
  </div>
</template>

<style scoped>
.app { display: flex; flex-direction: column; min-height: 100%; }

.topbar {
  position: sticky;
  top: 0;
  z-index: 40;
  height: var(--topbar-h);
  display: flex;
  align-items: center;
  gap: 18px;
  padding: 0 20px;
  min-width: 0;
  background: rgba(9, 14, 21, 0.82);
  backdrop-filter: blur(14px);
  border-bottom: 1px solid var(--border);
}

.brand { display: flex; align-items: center; gap: 11px; color: var(--text); text-decoration: none; }
.brand:hover { text-decoration: none; }
.brand-mark {
  display: grid;
  place-items: center;
  width: 36px; height: 36px;
  border-radius: var(--r);
  font-weight: 800;
  font-size: 12.5px;
  letter-spacing: .03em;
  color: #04121b;
  background: linear-gradient(135deg, #38bdf8, #818cf8);
  box-shadow: 0 3px 12px rgba(56,189,248,.25);
}
.brand-text { display: flex; flex-direction: column; line-height: 1.15; }
.brand-text b { font-size: 15px; }
.brand-text i { font-style: normal; font-size: 11px; color: var(--muted); }

.nav { display: flex; gap: 4px; }
.nav-link {
  display: inline-flex; align-items: center; gap: 7px;
  padding: 8px 13px; border-radius: var(--r);
  color: var(--text-soft); font-weight: 600; font-size: 14px;
  transition: background .15s, color .15s;
}
.nav-link:hover { background: var(--panel-2); color: var(--text); text-decoration: none; }
.nav-link.active { background: var(--panel-3); color: var(--text); box-shadow: inset 0 0 0 1px var(--border-strong); }
.nav-ico { font-size: 15px; }

.hud { margin-left: auto; display: flex; align-items: center; gap: 14px; }
.hud-xp { display: flex; flex-direction: column; gap: 3px; min-width: 150px; }
.hud-lvl { font-size: 11px; font-weight: 800; letter-spacing: .06em; color: var(--accent); }
.hud-bar { height: 5px; border-radius: 999px; background: var(--panel-3); overflow: hidden; }
.hud-bar > i { display: block; height: 100%; background: linear-gradient(90deg, #38bdf8, #818cf8); transition: width .5s ease; }
.hud-num { font-size: 11px; color: var(--muted); }
.hud-streak {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 6px 11px; border-radius: 999px;
  background: var(--panel-2); border: 1px solid var(--border);
  font-size: 14px;
}
.hud-streak b { color: var(--orange); }

/* --- аккаунт в топбаре --- */
.user-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 11px;
  border-radius: 999px;
  background: var(--panel-2);
  border: 1px solid var(--border);
  color: var(--text-soft);
  font-size: 13px;
  font-weight: 600;
  text-decoration: none;
  max-width: 170px;
}
.user-chip:hover { background: var(--panel-3); color: var(--text); text-decoration: none; }
.user-chip.guest { border-color: rgba(56,189,248,.35); color: #9ad9f5; }
.user-ico { font-size: 14px; }
.user-lbl { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.logout-x {
  display: grid;
  place-items: center;
  width: 20px; height: 20px;
  margin-left: 2px;
  padding: 0;
  border: none;
  border-radius: 999px;
  background: var(--panel-3);
  color: var(--muted);
  font: inherit;
  font-size: 12px;
  cursor: pointer;
}
.logout-x:hover { background: rgba(239,68,68,.2); color: #fecaca; }

.refresh-btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 7px 12px; border-radius: var(--r);
  background: var(--panel-2); border: 1px solid var(--border);
  color: var(--text-soft); font: inherit; font-size: 13px; font-weight: 600;
  cursor: pointer; transition: background .15s, color .15s, border-color .15s;
}
.refresh-btn:hover:not(:disabled) { background: var(--panel-3); color: var(--text); border-color: var(--border-strong); }
.refresh-btn:disabled { cursor: default; opacity: .85; }
.refresh-btn.done { color: var(--green); border-color: rgba(52,211,153,.45); }
.refresh-ico { font-size: 14px; line-height: 1; display: inline-block; }
.refresh-ico.spin { animation: refresh-spin .8s linear infinite; }
@keyframes refresh-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }

.content { flex: 1; min-height: 0; display: flex; flex-direction: column; }

.banner-error {
  position: fixed; bottom: 16px; left: 50%; transform: translateX(-50%);
  background: rgba(239,68,68,.14); border: 1px solid rgba(239,68,68,.4);
  color: #fecaca; padding: 10px 16px; border-radius: var(--r);
  font-size: 13px; z-index: 60;
}

.page-enter-active, .page-leave-active { transition: opacity .18s ease, transform .18s ease; }
.page-enter-from { opacity: 0; transform: translateY(6px); }
.page-leave-to { opacity: 0; }

@media (max-width: 860px) {
  .nav-lbl { display: none; }
  .hud-xp { min-width: 90px; }
  .brand-text { display: none; }
  .refresh-lbl { display: none; }
  .user-lbl { display: none; }
  .user-chip { padding: 6px 9px; }
}

/* Телефоны: максимально компактный топбар — бренд-иконка, иконки навигации,
   сжатый HUD, иконка поиска. Всё в одну строку, без горизонтального скролла. */
@media (max-width: 700px) {
  .topbar { gap: 6px; padding: 0 10px; }
  .brand { gap: 0; }
  .brand-mark { width: 32px; height: 32px; font-size: 11.5px; }
  .nav { gap: 0; }
  .nav-link { padding: 8px 9px; }
  .nav-ico { font-size: 17px; }
  /* HUD сжимается до «LVL n · 🔥n»: прогресс-бар и число XP прячем. */
  .hud { gap: 6px; }
  .hud-xp { min-width: 0; flex-direction: row; align-items: center; gap: 6px; }
  .hud-bar, .hud-num { display: none; }
  .hud-lvl { font-size: 10.5px; }
  .hud-streak { padding: 5px 8px; font-size: 13px; }
  .refresh-btn { padding: 7px 9px; }
}

/* Узкие телефоны (≤400px): прячем серию — остаётся только уровень. */
@media (max-width: 400px) {
  .hud-streak { display: none; }
  .nav-link { padding: 8px 7px; }
}
</style>
