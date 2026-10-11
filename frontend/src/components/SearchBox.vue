<script setup>
import { ref, watch, onBeforeUnmount, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api/client'

const router = useRouter()
const q = ref('')
const results = ref([])
const open = ref(false)
const loading = ref(false)
const active = ref(0)
// На телефоне поиск свёрнут в иконку и разворачивается по тапу в оверлей.
const expanded = ref(false)
const inputEl = ref(null)
let timer = null

function toggle() {
  expanded.value = !expanded.value
  if (expanded.value) {
    nextTick(() => inputEl.value && inputEl.value.focus())
  } else {
    open.value = false
  }
}

watch(q, (val) => {
  clearTimeout(timer)
  if (!val.trim()) { results.value = []; open.value = false; return }
  timer = setTimeout(run, 220)
})

async function run() {
  loading.value = true
  try {
    const r = await api.search(q.value)
    results.value = r.results || []
    open.value = true
    active.value = 0
  } catch (e) {
    results.value = []
  } finally {
    loading.value = false
  }
}

function go(item) {
  open.value = false
  expanded.value = false
  q.value = ''
  router.push('/lesson/' + item.id)
}

function onKey(e) {
  if (e.key === 'Escape') { open.value = false; expanded.value = false; return }
  if (!open.value || !results.value.length) return
  if (e.key === 'ArrowDown') { active.value = (active.value + 1) % results.value.length; e.preventDefault() }
  else if (e.key === 'ArrowUp') { active.value = (active.value - 1 + results.value.length) % results.value.length; e.preventDefault() }
  else if (e.key === 'Enter') { go(results.value[active.value]); e.preventDefault() }
}

function onBlur() { setTimeout(() => { open.value = false; expanded.value = false }, 180) }
onBeforeUnmount(() => clearTimeout(timer))
</script>

<template>
  <div class="search" :class="{ expanded }">
    <button
      class="s-toggle"
      type="button"
      title="Поиск по урокам"
      aria-label="Поиск по урокам"
      @click="toggle"
    >🔍</button>
    <span class="ico" aria-hidden="true">🔍</span>
    <input
      ref="inputEl"
      v-model="q"
      class="inp"
      type="text"
      placeholder="Поиск по урокам…"
      @keydown="onKey"
      @focus="q && (open = true)"
      @blur="onBlur"
    />
    <span v-if="loading" class="spin">⏳</span>

    <div v-if="open && (results.length || !loading)" class="drop">
      <button
        v-for="(r, i) in results"
        :key="r.id"
        class="item"
        :class="{ active: i === active }"
        @mousedown.prevent="go(r)"
        @mouseenter="active = i"
      >
        <div class="row1">
          <span class="t">{{ r.title }}</span>
          <span class="diff" :class="'diff-' + r.difficulty">{{ r.difficulty }}</span>
        </div>
        <div class="row2">
          <span class="cat">{{ r.category }}</span>
          <span v-if="r.summary" class="sum">{{ r.summary }}</span>
        </div>
      </button>
      <div v-if="!results.length" class="empty">Ничего не найдено</div>
    </div>
  </div>
</template>

<style scoped>
.search {
  position: relative;
  display: flex; align-items: center; gap: 8px;
  width: min(420px, 34vw);
  padding: 0 12px;
  height: 38px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: var(--r);
  transition: border-color .15s, box-shadow .15s;
}
.search:focus-within { border-color: var(--accent); box-shadow: var(--glow); }
.ico { font-size: 14px; opacity: .8; }
/* Кнопка-иконка поиска: видна только на телефонах (см. media-query ниже). */
.s-toggle {
  display: none;
  background: none; border: none; padding: 0; margin: 0;
  color: var(--text); font: inherit; font-size: 17px; line-height: 1;
  cursor: pointer;
}
.inp {
  flex: 1; background: none; border: none; outline: none;
  color: var(--text); font: inherit; font-size: 14px;
}
.inp::placeholder { color: var(--faint); }
.spin { animation: pulse 1s infinite; font-size: 13px; }

.drop {
  position: absolute; top: 46px; left: 0; right: 0;
  max-height: 420px; overflow-y: auto;
  background: var(--panel-2);
  border: 1px solid var(--border-strong);
  border-radius: var(--r);
  box-shadow: var(--shadow-lg);
  padding: 6px; z-index: 50;
}
.item {
  display: block; width: 100%; text-align: left;
  background: none; border: none; cursor: pointer;
  padding: 9px 11px; border-radius: var(--r-sm);
  color: var(--text); font: inherit;
}
.item.active, .item:hover { background: var(--panel-3); }
.row1 { display: flex; align-items: center; gap: 8px; }
.t { font-weight: 600; font-size: 14px; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.row2 { display: flex; gap: 8px; margin-top: 3px; font-size: 12px; color: var(--muted); }
.cat { text-transform: uppercase; letter-spacing: .04em; font-weight: 700; color: var(--accent); font-size: 10px; }
.sum { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.empty { padding: 14px; text-align: center; color: var(--muted); font-size: 13px; }
.diff { font-size: 10px; padding: 1px 7px; }

/* ---------- Телефоны: поиск — иконка, разворачивается в оверлей ---------- */
@media (max-width: 700px) {
  .search {
    width: 36px; height: 36px; padding: 0; gap: 0;
    justify-content: center;
    background: transparent; border-color: transparent;
  }
  .search .ico, .search .inp { display: none; }
  .search .s-toggle { display: grid; place-items: center; width: 36px; height: 36px; }

  /* Развёрнутый поиск: фиксированный оверлей на всю ширину экрана поверх бара. */
  .search.expanded {
    position: fixed; left: 8px; right: 8px; top: 8px;
    width: auto; height: 42px; padding: 0 12px; gap: 8px;
    justify-content: flex-start;
    background: var(--panel-2); border-color: var(--accent);
    box-shadow: var(--glow), var(--shadow-lg);
    z-index: 70;
  }
  .search.expanded .inp { display: block; }
  .search.expanded .s-toggle { display: none; }
  .search.expanded .drop { top: 48px; left: 0; right: 0; }
  /* 16px — иначе iOS зумит страницу при фокусе на поле поиска. */
  .search .inp { font-size: 16px; }
}
</style>
