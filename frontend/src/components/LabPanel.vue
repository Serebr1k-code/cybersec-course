<script setup>
// "Лаборатория" — the interactive terminal panel for lessons that carry a lab.
//
// The whole panel (and @xterm with it) is code-split: LessonView only renders
// it for lessons whose front-matter declares a `lab:` block, and the xterm
// engine is imported dynamically here so non-lab lessons never download it.
import { ref, computed, onMounted, onBeforeUnmount, nextTick } from 'vue'
import { api } from '../api/client'
import { createSession } from '../lab/session'

const props = defineProps({
  lessonId: { type: String, required: true },
  lab: { type: Object, required: true },
  // Инлайн-режим: терминал встроен в текст урока (компактнее и сворачивается),
  // а не отдельной панелью внизу.
  inline: { type: Boolean, default: false },
})

const emit = defineEmits(['solved'])

const termEl = ref(null)
const loading = ref(true)
const error = ref('')
const solved = ref(false)
const bundle = ref(null)
// Свёрнутый инлайн-терминал: текст урока остаётся читаемым, консоль
// разворачивается одним тапом. По умолчанию развёрнут.
const collapsed = ref(false)

let shell = null
let session = null

const toolset = computed(() => props.lab?.toolset || [])
const checkCmd = computed(() => props.lab?.check || '')
const title = computed(() => props.lab?.title || 'Практика в консоли')

function bundleId() { return props.lab?.bundle || props.lessonId }

function onSolved() {
  solved.value = true
  emit('solved')
}

// Разворачивание после сворачивания: xterm теряет размеры в скрытом узле,
// поэтому пересчитываем fit на следующем кадре.
async function toggleCollapsed() {
  collapsed.value = !collapsed.value
  if (!collapsed.value) {
    await nextTick()
    if (shell && shell.fit) { try { shell.fit.fit() } catch (e) { /* ignore */ } }
  }
}

async function mount() {
  loading.value = true
  error.value = ''
  try {
    const b = await api.lab(bundleId())
    bundle.value = b
    await nextTick()
    const { LabShell } = await import('../lab/LabShell')
    session = createSession({
      spec: props.lab,
      bundle: b,
      onEvent: (e) => { if (e.type === 'solved') onSolved() },
    })
    shell = new LabShell(termEl.value, session, { fontSize: 13.5 })
    shell.banner()
    shell.focus()
    loading.value = false
  } catch (e) {
    error.value = e.message || String(e)
    loading.value = false
  }
}

function hint() { if (shell) shell.runExternal('hint') }
function reset() {
  if (shell) { shell.dispose(); shell = null }
  solved.value = false
  mount()
}

onMounted(mount)
onBeforeUnmount(() => { if (shell) shell.dispose(); shell = null; session = null })
</script>

<template>
  <section class="lab-panel" :class="{ solved, inline, collapsed }">
    <header class="lab-head">
      <span class="lab-icon" aria-hidden="true">⌨</span>
      <div class="lab-titles">
        <div class="lab-title">{{ title }}</div>
        <div class="lab-sub">
          <span class="chip tool">shell</span>
          <span v-for="t in toolset" :key="t" class="chip tool">{{ t }}</span>
          <span v-if="checkCmd" class="lab-check">проверка: <code>check</code></span>
        </div>
      </div>
      <div class="lab-actions">
        <button class="btn btn-sm" type="button" @click="hint">Подсказка</button>
        <button class="btn btn-sm" type="button" @click="reset">Сброс</button>
        <button
          v-if="inline"
          class="btn btn-sm lab-collapse"
          type="button"
          :aria-expanded="!collapsed"
          :title="collapsed ? 'Развернуть терминал' : 'Свернуть терминал'"
          @click="toggleCollapsed"
        ><span aria-hidden="true">{{ collapsed ? '▸' : '▾' }}</span></button>
      </div>
    </header>

    <div v-show="!collapsed">
      <div v-if="solved" class="lab-solved" role="status">
        ✓ Лаборатория пройдена — условие выполнено.
      </div>

      <div class="lab-term-wrap">
        <div ref="termEl" class="lab-term" :aria-label="'Терминал лаборатории: ' + title"></div>
        <div v-if="loading" class="lab-overlay">Загрузка лаборатории…</div>
        <div v-else-if="error" class="lab-overlay err">Не удалось загрузить лабораторию: {{ error }}</div>
      </div>

      <footer class="lab-foot">
        Набери <code>help</code> — список инструментов. Проверить решение: <code>check</code>. Нужна подсказка: <code>hint</code>.
      </footer>
    </div>

    <div v-if="collapsed" class="lab-collapsed-hint">
      Терминал свёрнут. Нажми <button class="btn btn-sm" type="button" @click="toggleCollapsed">▸ развернуть</button>, чтобы продолжить.
    </div>
  </section>
</template>

<style scoped>
.lab-panel {
  margin: 18px 0;
  border: 1px solid var(--border-strong);
  border-radius: var(--r-lg);
  background: linear-gradient(180deg, var(--panel-2), var(--panel));
  overflow: hidden;
  box-shadow: var(--shadow);
}
.lab-panel.solved { border-color: var(--green-soft); }
/* Инлайн-режим: терминал встроен в поток текста на шаге «попробуй сам». */
.lab-panel.inline { margin: 20px 0; border-color: var(--accent-soft, var(--border-strong)); }
.lab-panel.inline .lab-head { background: var(--panel-2); }

.lab-head {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 14px;
  background: var(--panel-3);
  border-bottom: 1px solid var(--border);
}
.lab-icon { font-size: 18px; color: var(--accent); }
.lab-titles { flex: 1; min-width: 0; }
.lab-title { font-weight: 700; letter-spacing: -0.01em; }
.lab-sub { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-top: 3px; }
.chip.tool { font-size: 11px; padding: 1px 7px; border-radius: 999px; background: var(--elevated); color: var(--text-soft); border: 1px solid var(--border); }
.lab-check { font-size: 12px; color: var(--muted); }
.lab-check code, .lab-foot code { background: var(--elevated); padding: 1px 5px; border-radius: var(--r-xs); color: var(--accent); }
.lab-actions { display: flex; gap: 8px; }
.btn-sm { padding: 5px 10px; font-size: 13px; }

.lab-solved {
  padding: 8px 14px;
  background: rgba(34, 197, 94, 0.12);
  border-bottom: 1px solid var(--green-soft);
  color: var(--green);
  font-weight: 600;
  font-size: 14px;
}

.lab-term-wrap { position: relative; background: #0b111a; }
.lab-term { height: 420px; padding: 8px 4px 8px 10px; }
/* Инлайн-терминал компактнее: ~360px, прокручиваемый. */
.lab-panel.inline .lab-term { height: 360px; }
.lab-term :deep(.xterm) { height: 100%; }
.lab-collapsed-hint {
  padding: 10px 14px; color: var(--muted); font-size: 13px;
  display: flex; align-items: center; gap: 8px;
}
.lab-overlay {
  position: absolute; inset: 0;
  display: flex; align-items: center; justify-content: center;
  background: rgba(11, 17, 26, 0.82); color: var(--muted); font-size: 14px;
}
.lab-overlay.err { color: var(--red); }

.lab-foot { padding: 8px 14px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12.5px; }
</style>
