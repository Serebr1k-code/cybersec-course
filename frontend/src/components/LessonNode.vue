<script setup>
import { computed } from 'vue'
import { NODE_D } from '../utils/radialLayout'

const props = defineProps({
  node: { type: Object, required: true },
  ratio: { type: Number, default: 0 },
  completed: { type: Boolean, default: false },
  // Category accent colour — used for the hover/path glow (the circle FILL is
  // driven by difficulty, see DIFF_COLORS).
  color: { type: String, default: '#38bdf8' },
  // Circle diameter in px (fixed by the layout so rings pack tightly).
  size: { type: Number, default: NODE_D },
  // Canvas zoom scale — the tooltip counter-scales with it so the title stays
  // readable at every zoom level (circles grow with zoom, the label does not
  // shrink).
  zoom: { type: Number, default: 1 },
  // radial interaction state
  collapsed: { type: Boolean, default: false },
  hasChildren: { type: Boolean, default: false },
  dimmed: { type: Boolean, default: false },
  onpath: { type: Boolean, default: false }
})
const emit = defineEmits(['toggle'])

// Difficulty drives the circle colour (same palette as the rest of the app).
const DIFF_COLORS = {
  beginner: '#22c55e', easy: '#84cc16', medium: '#eab308', hard: '#f97316', expert: '#ef4444'
}
const diffLabel = {
  beginner: 'Новичок', easy: 'Легко', medium: 'Средне', hard: 'Сложно', expert: 'Эксперт'
}
const diffColor = computed(() => DIFF_COLORS[props.node.difficulty] || DIFF_COLORS.beginner)
const diffName = computed(() => diffLabel[props.node.difficulty] || 'Новичок')

// Reading progress as a 0..1 fraction. A completed lesson is always full.
const frac = computed(() => props.completed ? 1 : Math.max(0, Math.min(1, props.ratio)))
const pct = computed(() => Math.round(frac.value * 100) + '%')

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

// Counter-scale the tooltip by 1/zoom so the label keeps a roughly CONSTANT
// on-screen size at every zoom level (circles grow/shrink with zoom, the title
// does not). Clamped so extreme zoom can't produce an absurd popover.
const tipScale = computed(() => {
  const z = Number(props.zoom) || 1
  return Math.min(8, Math.max(0.1, 1 / z))
})
</script>

<template>
  <RouterLink
    :to="'/lesson/' + node.id"
    class="rnode"
    :class="{ done: completed, dim: dimmed, on: onpath, folded: collapsed, 'has-chev': hasChildren }"
    :style="{ '--cat': color, '--diff': diffColor, '--pct': pct, '--d': size + 'px', '--tip-scale': tipScale }"
    :aria-label="node.title + ' — ' + diffName"
  >
    <!-- progress ring: green arc (read fraction) over a faint neutral track -->
    <span class="arc" aria-hidden="true"></span>
    <!-- difficulty-coloured disc with a subtle dark ring -->
    <span class="disc" aria-hidden="true"></span>
    <!-- completion: solid green check on top of the (full green) ring -->
    <span v-if="completed" class="check" aria-hidden="true">✓</span>

    <button
      v-if="hasChildren"
      type="button"
      class="chev"
      :class="{ closed: collapsed }"
      :title="collapsed ? 'Развернуть' : 'Свернуть'"
      @click.stop.prevent="emit('toggle', node.id)"
    >{{ collapsed ? '▸' : '▾' }}</button>

    <!-- hover tooltip: title + difficulty + duration (no text on the node face) -->
    <span class="tip" role="tooltip">
      <span class="tip-title">{{ node.title }}</span>
      <span class="tip-meta">
        <span class="tip-diff" :class="'td-' + (node.difficulty || 'beginner')">{{ diffName }}</span>
        <span v-if="durText" class="tip-dur">· {{ durText }}</span>
      </span>
    </span>
  </RouterLink>
</template>

<style scoped>
/* ---- the circle node ---------------------------------------------------- */
.rnode {
  position: relative;
  display: block;
  width: var(--d, 22px);
  height: var(--d, 22px);
  border-radius: 50%;
  box-sizing: border-box;
  text-decoration: none;
  --diff: #22c55e;
  --pct: 0%;
  --cat: #38bdf8;
  --tip-scale: 1;
  transition: opacity .16s ease, transform .12s ease, filter .16s ease;
}
.rnode:hover {
  text-decoration: none;
  transform: scale(1.18);
  z-index: 4;
}
.rnode.done { z-index: 2; }
.rnode.on { z-index: 3; filter: drop-shadow(0 0 6px var(--cat)); }
.rnode.dim { opacity: .16; }

/* Progress ring (conic gradient): read fraction green, rest a faint track. */
.arc {
  position: absolute; inset: 0; border-radius: 50%;
  background: conic-gradient(var(--green, #22c55e) var(--pct), rgba(120, 150, 180, .22) 0);
  pointer-events: none;
}
/* Difficulty-coloured disc with a subtle dark ring, inset to reveal the arc. */
.disc {
  position: absolute; inset: calc(var(--d, 22px) * 0.14); border-radius: 50%;
  background: var(--diff);
  border: 1px solid rgba(0, 0, 0, .6);
  box-shadow: inset 0 0 0 1px rgba(255, 255, 255, .14), 0 1px 3px rgba(0, 0, 0, .55);
  pointer-events: none;
}

/* Completion badge (solid green check). */
.check {
  position: absolute; top: -3px; right: -3px;
  width: 12px; height: 12px; border-radius: 50%;
  display: grid; place-items: center;
  background: var(--green, #22c55e); color: #05210f;
  font-size: 8px; font-weight: 900; line-height: 1;
  box-shadow: 0 0 0 1.5px rgba(7, 11, 17, .9), 0 0 6px rgba(34, 197, 94, .7);
  pointer-events: none;
}

/* Collapse chevron — tucked at the bottom-right, revealed on hover/fold. */
.chev {
  position: absolute; bottom: -6px; right: -6px;
  width: 13px; height: 13px; padding: 0;
  display: grid; place-items: center;
  border-radius: 50%; cursor: pointer;
  background: rgba(10, 16, 24, .92); color: var(--muted);
  border: 1px solid var(--border-strong);
  font-size: 8px; line-height: 1;
  opacity: 0; transition: opacity .14s ease;
}
.rnode:hover .chev, .rnode.folded .chev { opacity: 1; }
.chev:hover { color: var(--text); border-color: var(--cat); }
.chev.closed { color: var(--cat); }

/* ---- hover tooltip (title + difficulty + duration) ---------------------- */
.tip {
  position: absolute;
  left: 50%; bottom: calc(100% + 10px);
  transform: translate(-50%, 4px) scale(var(--tip-scale));
  transform-origin: bottom center;
  display: flex; flex-direction: column; gap: 2px;
  max-width: 240px; padding: 6px 9px;
  background: rgba(15, 23, 34, .97);
  border: 1px solid var(--border-strong);
  border-radius: var(--r);
  box-shadow: var(--shadow-lg);
  color: var(--text);
  font-size: 12px; line-height: 1.3;
  white-space: normal; text-align: left;
  opacity: 0; pointer-events: none;
  transition: opacity .12s ease, transform .12s ease;
  z-index: 6;
}
.rnode:hover .tip { opacity: 1; transform: translate(-50%, 0) scale(var(--tip-scale)); }
.tip-title { font-weight: 650; font-size: 12px; overflow-wrap: anywhere; }
.tip-meta { display: flex; align-items: center; gap: 5px; font-size: 10.5px; color: var(--muted); }
.tip-diff { font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
.td-beginner { color: #22c55e; }
.td-easy { color: #84cc16; }
.td-medium { color: #eab308; }
.td-hard { color: #f97316; }
.td-expert { color: #ef4444; }
</style>
