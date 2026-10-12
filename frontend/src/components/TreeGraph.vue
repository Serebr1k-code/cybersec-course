<script setup>
import { computed, ref, watch, nextTick, onMounted, onBeforeUnmount } from 'vue'
import LessonNode from './LessonNode.vue'
import { useProgressStore } from '../stores/progress'
import { radialLayout, NODE_D } from '../utils/radialLayout'

const props = defineProps({
  nodes: { type: Array, default: () => [] },   // узлы одной категории
  color: { type: String, default: '#38bdf8' },
  // id узла, чей путь от корня подсвечивается (последний открытый урок).
  focusId: { type: String, default: '' }
})

const progress = useProgressStore()

const MIN_SCALE = 0.05
const MAX_SCALE = 4

// Difficulty palette — the circle FILL (mirrors LessonNode.vue / main.css).
// A compact legend keeps the colour-only nodes understandable.
const DIFF_LEGEND = [
  { k: 'beginner', label: 'Новичок', c: '#22c55e' },
  { k: 'easy', label: 'Легко', c: '#84cc16' },
  { k: 'medium', label: 'Средне', c: '#eab308' },
  { k: 'hard', label: 'Сложно', c: '#f97316' },
  { k: 'expert', label: 'Эксперт', c: '#ef4444' }
]

// id свёрнутых узлов (шеврон): их поддеревья скрыты и не участвуют в раскладке.
const collapsed = ref(new Set())
// id узлов, раскрытых вручную (шеврон) — их поддеревья показываются независимо
// от прогресса и остаются открытыми, пока пользователь не свернёт их обратно.
const expanded = ref(new Set())
// «Развернуть всё»: показать ВСЁ дерево, игнорируя progressive reveal.
const showAll = ref(false)

// ---- progressive reveal (fog of war) -------------------------------------
// «Начат» = прочитана хотя бы одна секция ИЛИ урок отмечен пройденным.
function started(n) {
  return progress.lessonRatio(n.id, n.sections) > 0 || progress.isCompleted(n.id)
}

// Базовый набор progressive reveal: для каждого начатого узла — сам узел, ВЕСЬ
// его путь до корня и его ПРЯМЫЕ дети («следующие шаги»); плюс всегда первые
// ДВА уровня дерева (корень + его дети + внуки), чтобы с самого начала был
// виден обзор, а не только точка старта. Набор ancestor-closed: родитель любого
// видимого узла тоже видим.
const revealSet = computed(() => {
  const m = treeMeta()
  const vis = new Set()
  for (const n of props.nodes) {
    const d = m.depth[n.id]
    if (d !== undefined && d <= 2) vis.add(n.id)
  }
  for (const n of props.nodes) {
    if (!started(n)) continue
    vis.add(n.id)
    let p = m.parentOf[n.id]
    let guard = 0
    while (p && guard++ < 1000) { vis.add(p); p = m.parentOf[p] }
    for (const c of m.children.get(n.id) || []) vis.add(c)
  }
  return vis
})

// Итоговый набор видимых узлов: progressive reveal + поддеревья, раскрытые
// вручную; либо ВСЕ узлы при «Развернуть всё». Ручные сворачивания применяет
// сама раскладка (opts.collapsed).
const visibleSet = computed(() => {
  if (showAll.value) return new Set(props.nodes.map((n) => n.id))
  const m = treeMeta()
  const vis = new Set(revealSet.value)
  for (const id of expanded.value) {
    const stack = [id]
    let guard = 0
    while (stack.length && guard++ < 100000) {
      const cur = stack.pop()
      vis.add(cur)
      for (const c of m.children.get(cur) || []) stack.push(c)
    }
  }
  return vis
})

const layout = computed(() => radialLayout(props.nodes, { collapsed: collapsed.value, visible: visibleSet.value }))

const nodeById = computed(() => Object.fromEntries(props.nodes.map((n) => [n.id, n])))
const visibleNodes = computed(() => props.nodes.filter((n) => layout.value.pos[n.id]))

// Подсветка пути и затемнение — ТОЛЬКО по реальному наведению (hover).
// focusId (последний открытый урок) намеренно НЕ участвует в подсветке: иначе
// после возврата с урока на дерево его узел выглядел бы «наведённым» (путь от
// корня подсвечен, остальное затемнено). focusId управляет лишь камерой
// (см. applyDefaultView / focusNode), а не стилями узлов.
const hoverId = ref('')
const activeId = computed(() => hoverId.value || '')
const pathSet = computed(() => {
  const set = new Set()
  let id = activeId.value
  const up = layout.value.parentOf
  let guard = 0
  while (id && guard++ < 1000) { set.add(id); id = up[id] }
  return set
})

const edges = computed(() => layout.value.edges.map((e) => {
  const child = nodeById.value[e.to]
  const fromDone = progress.isCompleted(e.from)
  const toDone = progress.isCompleted(e.to)
  // Ребро окрашено по ПАРЕ состояний концов:
  //   both -> зелёное, one -> белое, none -> тусклое.
  const state = fromDone && toDone ? 'both' : (fromDone || toDone ? 'one' : 'none')
  return {
    ...e,
    ratio: child ? progress.lessonRatio(e.to, child.sections) : 0,
    fromDone,
    toDone,
    state,
    on: pathSet.value.has(e.from) && pathSet.value.has(e.to)
  }
}))
const edgeStroke = (s) => (s === 'both' ? '#22c55e' : s === 'one' ? '#e6edf3' : '#26384a')

// ---- camera (wheel zoom anchored at cursor + drag to pan) -----------------
const view = ref({ scale: 1, tx: 0, ty: 0 })
const focusTarget = ref('')
const wrap = ref(null)
let dragging = false, moved = false, sx = 0, sy = 0, stx = 0, sty = 0

function zoomAt(newScale, cx, cy) {
  const s = view.value.scale
  const ns = Math.max(MIN_SCALE, Math.min(MAX_SCALE, newScale))
  if (ns === s) return
  const tx = view.value.tx
  const ty = view.value.ty
  view.value.tx = cx - (ns / s) * (cx - tx)
  view.value.ty = cy - (ns / s) * (cy - ty)
  view.value.scale = ns
}
function canvasRect() {
  const el = wrap.value
  if (!el) return null
  const r = el.getBoundingClientRect()
  const cw = r.width || el.clientWidth || 0
  const ch = r.height || el.clientHeight || 0
  return { cw, ch }
}
function canvasCenter() {
  const r = canvasRect()
  return r ? { cx: r.cw / 2, cy: r.ch / 2 } : { cx: 0, cy: 0 }
}
function onWheel(e) {
  e.preventDefault()
  const el = wrap.value
  if (!el) { zoomAt(view.value.scale * (e.deltaY < 0 ? 1.12 : 0.89), 0, 0); return }
  const rect = el.getBoundingClientRect()
  const factor = e.deltaY < 0 ? 1.12 : 0.89
  zoomAt(view.value.scale * factor, e.clientX - rect.left, e.clientY - rect.top)
}
function onDown(e) {
  dragging = true; moved = false
  sx = e.clientX; sy = e.clientY; stx = view.value.tx; sty = view.value.ty
}
function onMove(e) {
  if (!dragging) return
  const dx = e.clientX - sx, dy = e.clientY - sy
  if (Math.abs(dx) > 4 || Math.abs(dy) > 4) moved = true
  view.value.tx = stx + dx
  view.value.ty = sty + dy
}
function onUp() { dragging = false }
function onCaptureClick(e) { if (moved) { e.preventDefault(); e.stopPropagation() } }

// ---- touch: один палец — панорама, два пальца — пинч-зум ---------------
// Мышь-события на тач-устройствах ненадёжны, поэтому добавляем touch-обработку.
let pinchDist = 0
function touchDist(t) {
  return Math.hypot(t[0].clientX - t[1].clientX, t[0].clientY - t[1].clientY)
}
function onTouchStart(e) {
  if (e.touches.length === 1) {
    dragging = true; moved = false
    sx = e.touches[0].clientX; sy = e.touches[0].clientY
    stx = view.value.tx; sty = view.value.ty
    pinchDist = 0
  } else if (e.touches.length >= 2) {
    dragging = false
    pinchDist = touchDist(e.touches)
  }
}
function onTouchMove(e) {
  const el = wrap.value
  if (!el) return
  if (e.touches.length === 1 && dragging) {
    const dx = e.touches[0].clientX - sx, dy = e.touches[0].clientY - sy
    if (Math.abs(dx) > 4 || Math.abs(dy) > 4) moved = true
    view.value.tx = stx + dx
    view.value.ty = sty + dy
    e.preventDefault()
  } else if (e.touches.length >= 2) {
    const d = touchDist(e.touches)
    if (pinchDist > 0 && d > 0) {
      const rect = el.getBoundingClientRect()
      const mx = (e.touches[0].clientX + e.touches[1].clientX) / 2 - rect.left
      const my = (e.touches[0].clientY + e.touches[1].clientY) / 2 - rect.top
      zoomAt(view.value.scale * (d / pinchDist), mx, my)
    }
    pinchDist = d
    e.preventDefault()
  }
}
function onTouchEnd(e) {
  if (e.touches.length === 0) { dragging = false; pinchDist = 0 }
  else if (e.touches.length === 1) {
    // Подняли один палец после пинча — продолжаем как перетаскивание.
    dragging = true; moved = true
    sx = e.touches[0].clientX; sy = e.touches[0].clientY
    stx = view.value.tx; sty = view.value.ty
    pinchDist = 0
  }
}

// ---- fit / focus ----------------------------------------------------------
// Масштаб+сдвиг так, чтобы ВСЯ категория помещалась в канвас с полями.
function fitScale() {
  const r = wrap.value ? canvasRect() : null
  if (!r || !r.cw || !r.ch) return 1
  const L = layout.value
  return Math.min(r.cw / L.w, r.ch / L.h) * 0.95
}
function fit() {
  const r = wrap.value ? canvasRect() : null
  if (!r || !r.cw || !r.ch) { view.value = { scale: 1, tx: 0, ty: 0 }; focusTarget.value = ''; return }
  const L = layout.value
  const s = Math.max(MIN_SCALE, Math.min(MAX_SCALE, fitScale()))
  view.value.scale = s
  view.value.tx = (r.cw - s * L.w) / 2
  view.value.ty = (r.ch - s * L.h) / 2
  focusTarget.value = ''
}
// Центрирует узел id (screen = tx + scale * p). false, если узла нет.
function focusNode(id, scale = 1) {
  const p = layout.value.pos[id]
  const r = wrap.value ? canvasRect() : null
  if (!p || !r || !r.cw || !r.ch) return false
  const s = Math.max(MIN_SCALE, Math.min(MAX_SCALE, scale))
  view.value.scale = s
  view.value.tx = r.cw / 2 - s * p.x
  view.value.ty = r.ch / 2 - s * p.y
  focusTarget.value = id
  return true
}
const centerNode = focusNode

// ---- default collapse / expand-all ---------------------------------------
// Полная структура категории (глубины + родители), независимо от сворачивания.
function treeMeta() {
  const byId = new Set(props.nodes.map((n) => n.id))
  const children = new Map()
  const parentOf = {}
  const roots = []
  for (const n of props.nodes) {
    const p = n.parent && byId.has(n.parent) ? n.parent : null
    parentOf[n.id] = p
    if (p) { if (!children.has(p)) children.set(p, []); children.get(p).push(n.id) }
    else roots.push(n.id)
  }
  const depth = {}
  const stack = roots.map((id) => [id, 0])
  while (stack.length) {
    const [id, d] = stack.pop()
    if (depth[id] !== undefined) continue
    depth[id] = d
    for (const c of children.get(id) || []) stack.push([c, d + 1])
  }
  return { children, parentOf, depth, roots }
}
// Первичный вид = progressive reveal (fog of war): показываем первые ДВА
// уровня дерева (корень + дети + внуки), а также начатые уроки, их путь от корня
// и их прямые дети. Ничего не скрыто навсегда — по мере чтения дерево
// проявляется само.
function applyDefaultView() {
  showAll.value = false
  collapsed.value = new Set()
  expanded.value = new Set()
  nextTick(fit)
}
// «Свернуть всё» возвращает к progressive-reveal виду по умолчанию.
function collapseAll() { applyDefaultView() }
// «Развернуть всё» — показать всё дерево целиком, игнорируя прогресс.
function expandAll() {
  showAll.value = true
  collapsed.value = new Set()
  expanded.value = new Set()
  nextTick(fit)
}
function zoomIn() { const { cx, cy } = canvasCenter(); zoomAt(view.value.scale * 1.15, cx, cy) }
function zoomOut() { const { cx, cy } = canvasCenter(); zoomAt(view.value.scale / 1.15, cx, cy) }

// Показаны ли сейчас все прямые дети узла (учитывая раскладку и fog-of-war).
function childrenShown(id) {
  const kids = treeMeta().children.get(id) || []
  if (!kids.length) return false
  return kids.every((c) => !!layout.value.pos[c])
}
// Состояние шеврона: «свёрнут», если у узла есть скрытые дети.
function nodeCollapsed(id) {
  return (treeMeta().children.get(id) || []).length > 0 && !childrenShown(id)
}
// Шеврон: если дети показаны — сворачиваем; если скрыты (fog-of-war) —
// раскрываем вручную; вручную раскрытое поддерево остаётся открытым.
function toggleCollapse(id) {
  const kids = treeMeta().children.get(id) || []
  if (!kids.length) return
  if (childrenShown(id)) {
    const c = new Set(collapsed.value); c.add(id); collapsed.value = c
    const e = new Set(expanded.value); e.delete(id); expanded.value = e
  } else {
    const c = new Set(collapsed.value); c.delete(id); collapsed.value = c
    const e = new Set(expanded.value); e.add(id); expanded.value = e
  }
  nextTick(fit)
}
function setHover(id) { hoverId.value = id || '' }

// ---- right-click context menu: toggle lesson completion -------------------
const menu = ref({ show: false, x: 0, y: 0, id: '' })
function openMenu(e, id) {
  const el = wrap.value
  const r = el ? el.getBoundingClientRect() : null
  menu.value = {
    show: true,
    x: r ? e.clientX - r.left : e.clientX,
    y: r ? e.clientY - r.top : e.clientY,
    id
  }
}
function closeMenu() { if (menu.value.show) menu.value = { ...menu.value, show: false } }
async function markNode(id, completed) {
  const target = id || menu.value.id
  closeMenu()
  if (!target) return
  try {
    await progress.setCompleted(target, completed)
  } catch (err) {
    console.warn('setCompleted failed', err)
  }
}
function onOutsideDown(e) {
  const t = e.target
  if (menu.value.show && !(t && t.closest && t.closest('.ctx-menu'))) closeMenu()
}
function onKeydown(e) { if (e.key === 'Escape') closeMenu() }

defineExpose({ fit, focusNode, centerNode, toggleCollapse, collapseAll, expandAll, visibleSet, layout })

// Категория сменилась — заново строим progressive-reveal вид.
watch(() => props.nodes, () => { nextTick(applyDefaultView) })
watch(() => props.focusId, () => nextTick(applyDefaultView))
// Набор видимых узлов изменился (прогресс / ручные раскрытия) — пересобираем
// раскладку и подгоняем вид, чтобы проявившееся поддерево было видно целиком.
watch(visibleSet, () => { if (!dragging) nextTick(fit) })

let ro = null
let roReady = false
onMounted(() => {
  window.addEventListener('mouseup', onUp)
  window.addEventListener('mousedown', onOutsideDown)
  window.addEventListener('keydown', onKeydown)
  if (typeof ResizeObserver !== 'undefined') {
    ro = new ResizeObserver(() => {
      // Первый колбэк приходит сразу после observe() — пропускаем его, иначе
      // он перезапишет первичный вид (fit всего дерева).
      if (!roReady) { roReady = true; return }
      if (!dragging) fit()
    })
    if (wrap.value) ro.observe(wrap.value)
  }
  nextTick(applyDefaultView)
})
onBeforeUnmount(() => {
  window.removeEventListener('mouseup', onUp)
  window.removeEventListener('mousedown', onOutsideDown)
  window.removeEventListener('keydown', onKeydown)
  if (ro) ro.disconnect()
})
</script>

<template>
  <div class="graph-wrap">
    <div class="controls">
      <button class="btn btn-sm" @click="zoomIn" title="Приблизить">＋</button>
      <button class="btn btn-sm" @click="zoomOut" title="Отдалить">－</button>
      <button class="btn btn-sm" @click="fit" title="Показать видимую часть дерева">⤢ Сброс</button>
      <button class="btn btn-sm" @click="collapseAll" title="Свернуть к пройденным и связанным с ними урокам">⊟ Свернуть всё</button>
      <button class="btn btn-sm" @click="expandAll" title="Показать всё дерево целиком">⊞ Развернуть всё</button>
      <span class="scale mono">{{ Math.round(view.scale * 100) }}%</span>
    </div>

    <div class="hint" title="Дерево проявляется по мере обучения">
      <span class="hint-ico">👁</span>
      Показываются первые 2 уровня + пройденные и связанные с ними уроки
    </div>

    <div class="legend" aria-hidden="true">
      <span class="lg" v-for="d in DIFF_LEGEND" :key="d.k">
        <i :style="{ background: d.c }"></i>{{ d.label }}
      </span>
    </div>

    <div
      ref="wrap"
      class="canvas"
      @wheel="onWheel"
      @mousedown="onDown"
      @mousemove="onMove"
      @mouseup="onUp"
      @touchstart.passive="onTouchStart"
      @touchmove="onTouchMove"
      @touchend="onTouchEnd"
      @touchcancel="onTouchEnd"
      @click.capture="onCaptureClick"
    >
      <div
        class="stage"
        :style="{
          width: layout.w + 'px',
          height: layout.h + 'px',
          transform: `translate(${view.tx}px, ${view.ty}px) scale(${view.scale})`
        }"
      >
        <svg class="edges" :width="layout.w" :height="layout.h">
          <path
            v-for="e in edges"
            :key="e.id"
            :d="e.d"
            :stroke="edgeStroke(e.state)"
            :stroke-width="e.on ? 2.6 : e.state !== 'none' ? 2.2 : 1.4"
            :opacity="activeId && !e.on ? 0.28 : 1"
            fill="none"
          />
        </svg>

        <div
          v-for="n in visibleNodes"
          :key="n.id"
          class="node-slot"
          :style="{ transform: `translate(${layout.pos[n.id].left}px, ${layout.pos[n.id].top}px)` }"
          @mouseenter="setHover(n.id)"
          @mouseleave="setHover('')"
          @contextmenu.prevent="openMenu($event, n.id)"
        >
          <LessonNode
            :node="n"
            :color="color"
            :ratio="progress.lessonRatio(n.id, n.sections)"
            :completed="progress.isCompleted(n.id)"
            :size="NODE_D"
            :zoom="view.scale"
            :has-children="layout.hasChildren[n.id]"
            :collapsed="nodeCollapsed(n.id)"
            :dimmed="!!activeId && !pathSet.has(n.id)"
            :onpath="pathSet.has(n.id)"
            @toggle="toggleCollapse"
          />
        </div>
      </div>
    </div>

    <div
      v-if="menu.show"
      class="ctx-menu"
      :style="{ left: menu.x + 'px', top: menu.y + 'px' }"
      @contextmenu.prevent
    >
      <button type="button" class="ctx-item" @click.stop="markNode(menu.id, true)">✓ Отметить пройденным</button>
      <button type="button" class="ctx-item" @click.stop="markNode(menu.id, false)">↺ Отметить непройденным</button>
    </div>
  </div>
</template>

<style scoped>
.graph-wrap { position: relative; flex: 1; min-height: 0; display: flex; }
.canvas {
  position: relative; flex: 1; overflow: hidden; cursor: grab;
  background-image: radial-gradient(rgba(120,150,180,.09) 1px, transparent 1px);
  background-size: 26px 26px;
  border-radius: var(--r-lg);
  /* Жесты обрабатываем сами (пан/пинч) — браузерный скролл на канвасе выключаем. */
  touch-action: none;
  -webkit-user-select: none; user-select: none;
}
.canvas:active { cursor: grabbing; }
.stage { position: absolute; top: 0; left: 0; transform-origin: 0 0; }
.edges { position: absolute; top: 0; left: 0; pointer-events: none; }
.node-slot { position: absolute; top: 0; left: 0; }

.controls {
  position: absolute; top: 12px; right: 14px; z-index: 10;
  display: flex; align-items: center; gap: 6px;
  background: rgba(15,23,34,.85); backdrop-filter: blur(8px);
  padding: 6px; border-radius: var(--r); border: 1px solid var(--border);
}
.scale { font-size: 12px; color: var(--muted); min-width: 42px; text-align: center; }

/* Подсказка о progressive reveal (fog of war) */
.hint {
  position: absolute; top: 12px; left: 14px; z-index: 10;
  display: flex; align-items: center; gap: 6px;
  max-width: 46%;
  padding: 5px 10px; border-radius: var(--r);
  background: rgba(15,23,34,.82); backdrop-filter: blur(8px);
  border: 1px solid var(--border);
  font-size: 11.5px; color: var(--muted); line-height: 1.3;
  pointer-events: none;
}
.hint-ico { font-size: 12px; }

/* Легенда сложностей — узлы-кружки окрашены по сложности (без текста). */
.legend {
  position: absolute; bottom: 12px; left: 14px; z-index: 10;
  display: flex; flex-wrap: wrap; gap: 10px;
  padding: 5px 10px; border-radius: var(--r);
  background: rgba(15, 23, 34, .82); backdrop-filter: blur(8px);
  border: 1px solid var(--border);
  font-size: 11px; color: var(--muted);
  pointer-events: none;
}
.lg { display: inline-flex; align-items: center; gap: 4px; }
.lg i { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }

/* Контекстное меню узла (правый клик): отметить/снять «пройден» */
.ctx-menu {
  position: absolute; z-index: 30; min-width: 196px;
  display: flex; flex-direction: column; gap: 2px; padding: 4px;
  background: var(--panel); border: 1px solid var(--border-strong);
  border-radius: var(--r); box-shadow: var(--shadow-lg);
}
.ctx-item {
  text-align: left; background: transparent; color: var(--text);
  border: 0; border-radius: 6px; padding: 7px 10px;
  font-size: 12.5px; font-weight: 600; cursor: pointer; white-space: nowrap;
}
.ctx-item:hover { background: var(--panel-3); color: var(--text); }

/* ---------- Телефоны/планшеты: компактные элементы управления канвасом ---------- */
@media (max-width: 900px) {
  .controls {
    top: 10px; left: 10px; right: 10px;
    flex-wrap: wrap; justify-content: flex-end;
    padding: 5px; gap: 4px;
  }
  .controls .btn { padding: 5px 9px; font-size: 12px; }
  .scale { min-width: 34px; font-size: 11px; }
  /* Подсказку уводим вниз, чтобы не пересекалась с кнопками. */
  .hint {
    top: auto; bottom: 10px; left: 10px; max-width: 74%;
    font-size: 10.5px; padding: 4px 8px;
  }
  /* Легенда делит нижний левый угол с подсказкой — на планшете/телефоне скрываем. */
  .legend { display: none; }
  .ctx-menu { min-width: 170px; }
}

/* ---------- Узкие телефоны (<=700px): полностью скрываем панель управления ----------
   Зум ＋/－, «Сброс», «Свернуть всё», «Развернуть всё» и процент масштаба только
   загромождают экран; на телефоне дерево управляется жестами (панорама одним
   пальцем + пинч-зум двумя). Легенда-подсказка тоже убирается, чтобы не занимать
   место. Это чисто CSS (display:none) — вся логика (zoom/fit/collapse/expand)
   остаётся и продолжает работать; на планшетах/десктопе (>700px) панель и
   подсказка видны как прежде. */
@media (max-width: 700px) {
  .controls,
  .legend,
  .hint { display: none; }
}
</style>
