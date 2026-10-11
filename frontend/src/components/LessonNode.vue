<script setup>
import { computed } from 'vue'
import { CARD_W, radialCardHeight } from '../utils/radialLayout'

const props = defineProps({
  node: { type: Object, required: true },
  ratio: { type: Number, default: 0 },
  completed: { type: Boolean, default: false },
  color: { type: String, default: '#38bdf8' },
  width: { type: Number, default: CARD_W },
  // 0 = derive the height from the title (nodeLayout.js) so long titles are
  // never clipped; a positive value overrides it (used by tests / callers).
  height: { type: Number, default: 0 },
  // radial interaction state
  collapsed: { type: Boolean, default: false },
  hasChildren: { type: Boolean, default: false },
  dimmed: { type: Boolean, default: false },
  onpath: { type: Boolean, default: false }
})
const emit = defineEmits(['toggle'])

const pct = computed(() => Math.round(Math.max(0, Math.min(1, props.ratio)) * 100))
// Content-driven height: taller cards for longer titles, but the title is
// capped at 3 lines (radialLayout.js) so cards stay compact (~40–60px).
// `min-height` lets the card grow to its content while the radial layout
// reserves the same value, so nothing overlaps and nothing is clipped.
const cardH = computed(() => props.height > 0 ? props.height : radialCardHeight(props.node))
const diffLabel = {
  beginner: 'Новичок', easy: 'Легко', medium: 'Средне', hard: 'Сложно', expert: 'Эксперт'
}
// Minimalist star rating (1–5) instead of a textual chip. Unknown/empty -> 1.
const DIFF_STARS = { beginner: 1, easy: 2, medium: 3, hard: 4, expert: 5 }
const diffStars = computed(() => DIFF_STARS[props.node.difficulty] || 1)
const starsText = computed(() => '★'.repeat(diffStars.value))
// Full difficulty name kept for the node tooltip / accessibility only.
const diffName = computed(() => diffLabel[props.node.difficulty] || 'Новичок')

// Compact human duration from the lesson's estimated minutes:
// 25 -> '25м', 60 -> '1ч', 90 -> '1ч 30м', 140 -> '2ч 20м'. Hidden when 0/absent.
function fmtDuration(minutes) {
  const total = Math.round(Number(minutes) || 0)
  if (total <= 0) return ''
  const h = Math.floor(total / 60)
  const m = total % 60
  if (h && m) return h + 'ч ' + m + 'м'
  if (h) return h + 'ч'
  return m + 'м'
}
const durText = computed(() => fmtDuration(
  props.node.estimated_minutes || props.node.estMinutes || 0
))
</script>

<template>
  <RouterLink
    :to="'/lesson/' + node.id"
    class="rnode"
    :class="{ done: completed, dim: dimmed, on: onpath, folded: collapsed, 'has-chev': hasChildren }"
    :style="{ '--cat': color, width: width + 'px', minHeight: cardH + 'px' }"
    :title="node.title + ' — ' + diffName"
  >
    <span class="fill" :style="{ width: pct + '%' }"></span>

    <span class="title">{{ node.title }}</span>

    <span class="meta">
      <span
        class="stars"
        :class="'d-' + node.difficulty"
        role="img"
        :aria-label="diffName"
        :title="diffName"
      >{{ starsText }}</span>
      <span v-if="durText" class="dur">{{ durText }}</span>
    </span>

    <span class="badge" v-if="completed">✓</span>

    <button
      v-if="hasChildren"
      type="button"
      class="chev"
      :class="{ closed: collapsed }"
      :title="collapsed ? 'Развернуть' : 'Свернуть'"
      @click.stop.prevent="emit('toggle', node.id)"
    >{{ collapsed ? '▸' : '▾' }}</button>
  </RouterLink>
</template>

<style scoped>
.rnode {
  position: relative;
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 2px;
  padding: 4px 8px;
  border-radius: 8px;
  background: var(--panel-2);
  border: 1px solid var(--border-strong);
  border-left: 3px solid var(--cat);
  color: var(--text);
  text-decoration: none;
  overflow: hidden;
  box-sizing: border-box;
  box-shadow: var(--shadow-sm);
  transition: opacity .16s ease, box-shadow .16s ease, border-color .16s ease, transform .12s ease;
}
.rnode:hover {
  text-decoration: none;
  transform: translateY(-1px);
  box-shadow: var(--shadow), 0 0 0 1px var(--cat);
  border-color: var(--cat);
}
.rnode.done { border-color: var(--cat); }
.rnode.on { box-shadow: var(--shadow), 0 0 0 2px var(--cat); z-index: 3; }
.rnode.dim { opacity: .16; }

/* Лёгкая зелёная заливка слева-направо по мере чтения */
.fill {
  position: absolute;
  inset: 0 auto 0 0;
  background: linear-gradient(90deg, rgba(22,163,74,.45), rgba(34,197,94,.26));
  transition: width .55s cubic-bezier(.2,.8,.2,1);
  pointer-events: none;
}
.rnode.done .fill { background: linear-gradient(90deg, rgba(22,163,74,.66), rgba(34,197,94,.42)); }

.title {
  position: relative;
  font-weight: 650; font-size: 11px; line-height: 1.15;
  display: -webkit-box; -webkit-box-orient: vertical;
  /* compact: at most 3 lines (matches RADIAL_MAX_LINES / radialCardHeight) */
  -webkit-line-clamp: 3; line-clamp: 3;
  overflow: hidden;
  overflow-wrap: anywhere;
}

.meta { position: relative; display: flex; align-items: center; gap: 4px; min-height: 11px; }
/* leave room for the collapse chevron pinned to the bottom-right corner */
.rnode.has-chev .meta { padding-right: 15px; }

/* Minimalist star rating — 1–5 ★, coloured by difficulty (no text label). */
.stars {
  flex: none;
  font-size: 9.5px; line-height: 1; letter-spacing: .5px;
  color: #4ade80; /* beginner default, also used for unknown difficulty */
  white-space: nowrap;
  text-shadow: 0 1px 2px rgba(0,0,0,.45);
}
.d-beginner { color: #4ade80; }
.d-easy { color: #38bdf8; }
.d-medium { color: #facc15; }
.d-hard { color: #fb923c; }
.d-expert { color: #f87171; }

.dur { flex: none; font-size: 9px; line-height: 1; color: var(--muted); white-space: nowrap; }

.badge {
  position: absolute; top: 2px; right: 3px;
  width: 13px; height: 13px; border-radius: 50%;
  display: grid; place-items: center;
  background: var(--green); color: #05210f; font-size: 8px; font-weight: 900;
  box-shadow: 0 0 8px rgba(34,197,94,.6);
}

.chev {
  position: absolute; bottom: 2px; right: 2px;
  width: 14px; height: 14px; padding: 0;
  display: grid; place-items: center;
  border-radius: 4px; cursor: pointer;
  background: rgba(10,16,24,.82); color: var(--muted);
  border: 1px solid var(--border-strong);
  font-size: 9px; line-height: 1;
}
.chev:hover { color: var(--text); border-color: var(--cat); }
.chev.closed { color: var(--cat); }
</style>
