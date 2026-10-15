<script setup>
import { computed } from 'vue'
import { CARD_W, HUB_D, radialCardHeight, isHubNode } from '../utils/radialLayout'

const props = defineProps({
  node: { type: Object, required: true },
  ratio: { type: Number, default: 0 },
  completed: { type: Boolean, default: false },
  // Category accent colour — used for the hover / path glow.
  color: { type: String, default: '#38bdf8' },
  // REAL LESSON card width (px). Fixed by the layout so the rings pack tightly.
  width: { type: Number, default: CARD_W },
  // 0 = derive the card height from the title (radialCardHeight) so long titles
  // are never clipped; a positive value overrides it (the layout passes the
  // exact reserved height so the rendered card matches the reserved box).
  height: { type: Number, default: 0 },
  // HUB / CONNECTOR circle diameter (px). Only used when the node is a hub.
  size: { type: Number, default: HUB_D },
  // radial interaction state
  dimmed: { type: Boolean, default: false },
  onpath: { type: Boolean, default: false },
  // Waystone gate state for this node ({total, solved, locked, fill}) or null when
  // the node is not a waystone. A waystone renders as a distinct golden dark BLOCK
  // (never a hub circle or a lesson card); the block's gold fill sweeps left→right.
  gate: { type: Object, default: null }
})

const emit = defineEmits(['gate-open'])

// A hub / connector node (module / roadmap index page) renders as a plain small
// CIRCLE; a real lesson renders as a wide TEXT CARD.
const isHub = computed(() => isHubNode(props.node))

// ---- difficulty -----------------------------------------------------------
// Drives the card accent (left border + star colour) and the hub tooltip label.
const DIFF_COLORS = {
  beginner: '#22c55e', easy: '#84cc16', medium: '#eab308', hard: '#f97316', expert: '#ef4444'
}
const diffLabel = {
  beginner: 'Новичок', easy: 'Легко', medium: 'Средне', hard: 'Сложно', expert: 'Эксперт'
}
const diffColor = computed(() => DIFF_COLORS[props.node.difficulty] || DIFF_COLORS.beginner)
const diffName = computed(() => diffLabel[props.node.difficulty] || 'Новичок')
// Minimalist star rating (1–5) instead of a textual chip. Unknown/empty -> 1.
const DIFF_STARS = { beginner: 1, easy: 2, medium: 3, hard: 4, expert: 5 }
const diffStars = computed(() => DIFF_STARS[props.node.difficulty] || 1)
const starsText = computed(() => '★'.repeat(diffStars.value))

// ---- progress -------------------------------------------------------------
// Reading progress as a 0..1 fraction. A completed lesson is always full.
const frac = computed(() => props.completed ? 1 : Math.max(0, Math.min(1, props.ratio)))
const pct = computed(() => Math.round(frac.value * 100) + '%')

// Content-driven card height (matches the layout's reserved box). The rendered
// height is CLAMPED to this value (see the card style) so the card's real centre
// can never drift below the layout's reserved centre — the edge endpoints are
// drawn at the box CENTRE, so rendered height must equal the reserved height.
const cardH = computed(() => props.height > 0 ? props.height : radialCardHeight(props.node))

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

// ---- waystone gate --------------------------------------------------------
// A waystone is ALWAYS a distinct golden dark BLOCK — regardless of whether the
// node is a hub (module) or a real lesson card. Its face carries NO lock icon and
// NO "N/M" text: progress is communicated purely by the gold fill sweeping
// left→right (0/N = empty dark block, N/N = fully gold). `gate` is non-null
// exactly for waystone nodes (see TreeGraph.vue `nodeGate`).
const isWaystone = computed(() => !!props.gate)
const gateLocked = computed(() => !!(props.gate && props.gate.locked))
const gateSolvedN = computed(() => (props.gate && props.gate.solved) || 0)
const gateTotalN = computed(() => (props.gate && props.gate.total) || 0)
// Left→right fill fraction. Prefer the pre-computed `fill` (gateFillFraction);
// fall back to solved/total so a bare {total, solved, locked} gate still works.
const wsFill = computed(() => {
  const g = props.gate
  if (!g) return 0
  if (typeof g.fill === 'number') return Math.max(0, Math.min(1, g.fill))
  return g.total ? Math.max(0, Math.min(1, g.solved / g.total)) : 0
})
const wsFillPct = computed(() => Math.round(wsFill.value * 100) + '%')
// Block geometry: a readable BLOCK even where the layout reserved a tiny hub box.
const wsW = computed(() => Math.max(props.width || 0, 120))
const wsH = computed(() => Math.max(props.height || 0, 30))
const wsStyle = computed(() => ({
  '--cat': props.color,
  width: wsW.value + 'px',
  height: wsH.value + 'px'
}))
const wsTitle = computed(() => {
  if (!props.gate) return ''
  return gateLocked.value
    ? `Вейстоун: ветка заперта — решено ${gateSolvedN.value} из ${gateTotalN.value} задач. Нажмите, чтобы увидеть задачи.`
    : `Вейстоун открыт: все ${gateTotalN.value} задач решены`
})
// A locked waystone is NOT a link: clicking it opens the task-list popover
// (handled by TreeGraph) instead of navigating to the lesson.
function onGateClick(e) { emit('gate-open', e) }
</script>

<template>
  <RouterLink
    v-if="isWaystone && !gateLocked"
    :to="'/lesson/' + node.id"
    class="rnode ws open"
    :class="{ done: completed, dim: dimmed, on: onpath }"
    :style="wsStyle"
    :title="wsTitle"
    :aria-label="node.title"
  >
    <span class="ws-fill" :style="{ width: wsFillPct }"></span>
    <span class="title ws-label">{{ node.title }}</span>
  </RouterLink>

  <button
    v-else-if="isWaystone"
    type="button"
    class="rnode ws locked"
    :class="{ dim: dimmed, on: onpath }"
    :style="wsStyle"
    :title="wsTitle"
    :aria-label="wsTitle"
    @click="onGateClick"
  >
    <span class="ws-fill" :style="{ width: wsFillPct }"></span>
    <span class="title ws-label">{{ node.title }}</span>
  </button>

  <RouterLink
    v-else-if="isHub"
    :to="'/lesson/' + node.id"
    class="rnode hub"
    :class="{ done: completed, dim: dimmed, on: onpath }"
    :style="{ '--cat': color, '--d': size + 'px' }"
    :aria-label="node.title"
  >
    <span class="bullet" aria-hidden="true"></span>
  </RouterLink>

  <RouterLink
    v-else
    :to="'/lesson/' + node.id"
    class="rnode card"
    :class="{ done: completed, dim: dimmed, on: onpath }"
    :style="{ '--cat': color, '--diff': diffColor, width: width + 'px', height: cardH + 'px' }"
    :title="node.title + ' — ' + diffName"
  >
    <span class="fill" :style="{ width: pct }"></span>

    <span class="title">{{ node.title }}</span>

    <span class="meta">
      <span
        class="stars"
        :class="'d-' + (node.difficulty || 'beginner')"
        role="img"
        :aria-label="diffName"
        :title="diffName"
      >{{ starsText }}</span>
      <span v-if="durText" class="dur">{{ durText }}</span>
    </span>

    <span class="badge" v-if="completed">✓</span>
  </RouterLink>
</template>

<style scoped>
/* ================= HUB / CONNECTOR — plain small circle ================== */
/* The hub is a bare circle: NO text, NO hover tooltip, NO native title. The
   circle's rendered size MUST equal the layout's reserved square (--d) so its
   real centre lands exactly on the edge endpoint (the edge is drawn centre to
   centre). `box-sizing: border-box` keeps the 2px ring INSIDE that square. */
.rnode.hub {
  position: relative;
  display: block;
  width: var(--d, 18px);
  height: var(--d, 18px);
  border-radius: 50%;
  box-sizing: border-box;
  text-decoration: none;
  --cat: #38bdf8;
  transition: opacity .16s ease, transform .12s ease, filter .16s ease;
}
.rnode.hub:hover { text-decoration: none; transform: scale(1.22); z-index: 4; }
.rnode.hub.on { z-index: 3; filter: drop-shadow(0 0 6px var(--cat)); }
.rnode.hub.dim { opacity: .16; }

/* The empty bullet: a hollow ring in the category colour, faint inner fill.
   inset:0 + box-sizing:border-box => the ring is drawn INSIDE the 18px box, so
   the visible circle is exactly --d wide and its centre == the box centre. */
.bullet {
  position: absolute; inset: 0; border-radius: 50%;
  box-sizing: border-box;
  background: rgba(120, 150, 180, .14);
  border: 2px solid var(--cat);
  box-shadow: inset 0 0 0 1px rgba(0, 0, 0, .35), 0 1px 3px rgba(0, 0, 0, .5);
  pointer-events: none;
  transition: background .16s ease;
}
.rnode.hub:hover .bullet { background: color-mix(in srgb, var(--cat) 34%, transparent); }
.rnode.hub.done .bullet { border-color: var(--green, #22c55e); }

/* ================= REAL LESSON — readable text card ====================== */
.rnode.card {
  position: relative;
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 2px;
  padding: 4px 8px;
  border-radius: 8px;
  background: var(--panel-2);
  border: 1px solid var(--border-strong);
  border-left: 3px solid var(--diff, #22c55e);
  color: var(--text);
  text-decoration: none;
  overflow: hidden;
  box-sizing: border-box;
  box-shadow: var(--shadow-sm);
  transition: opacity .16s ease, box-shadow .16s ease, border-color .16s ease, transform .12s ease;
}
.rnode.card:hover {
  text-decoration: none;
  transform: translateY(-1px);
  box-shadow: var(--shadow), 0 0 0 1px var(--cat);
  border-color: var(--cat);
  border-left-color: var(--diff, #22c55e);
}
.rnode.card.done { border-color: var(--diff, #22c55e); }
.rnode.card.on { box-shadow: var(--shadow), 0 0 0 2px var(--cat); z-index: 3; }
.rnode.card.dim { opacity: .16; }

/* Light green fill left→right as the lesson is read. */
.fill {
  position: absolute;
  inset: 0 auto 0 0;
  background: linear-gradient(90deg, rgba(22,163,74,.45), rgba(34,197,94,.26));
  transition: width .55s cubic-bezier(.2,.8,.2,1);
  pointer-events: none;
}
.rnode.card.done .fill { background: linear-gradient(90deg, rgba(22,163,74,.66), rgba(34,197,94,.42)); }

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

/* ================= WAYSTONE GATE — golden dark block ====================== */
/* A waystone is NOT a lesson card nor a hub circle: it is a distinct BLOCK —
   solid dark charcoal with a warm gold edge. The face carries NO lock icon and
   NO "N/M" text; progress is shown purely by the gold fill sweeping left→right
   (0/N = empty dark block, N/N = fully gold). */
.rnode.ws {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 8px;
  border-radius: 6px;
  box-sizing: border-box;
  text-decoration: none;
  overflow: hidden;
  background: #14100a;               /* solid dark-charcoal block */
  border: 2px solid #a9791c;         /* warm gold edge */
  color: #f7d98a;
  cursor: pointer;
  box-shadow: inset 0 0 0 1px rgba(0, 0, 0, .6), 0 1px 4px rgba(0, 0, 0, .6);
  transition: opacity .16s ease, box-shadow .16s ease, border-color .16s ease, transform .12s ease;
}
.rnode.ws:hover {
  text-decoration: none;
  transform: translateY(-1px);
  border-color: #f5c542;
  box-shadow: inset 0 0 0 1px rgba(0, 0, 0, .6), 0 0 0 1px rgba(245, 197, 66, .5), 0 0 12px rgba(245, 197, 66, .35);
}
/* A full (unlocked) gate glows gold; a locked one keeps the darker edge. */
.rnode.ws.open { border-color: #f5c542; box-shadow: inset 0 0 0 1px rgba(0, 0, 0, .5), 0 0 10px rgba(245, 197, 66, .45); }
.rnode.ws.on { box-shadow: 0 0 0 2px var(--cat), inset 0 0 0 1px rgba(0, 0, 0, .5); z-index: 3; }
.rnode.ws.dim { opacity: .16; }
.rnode.ws:focus-visible { outline: 2px solid #f5c542; outline-offset: 2px; }

/* The left→right gold progress fill. */
.ws-fill {
  position: absolute;
  inset: 0 auto 0 0;
  background: linear-gradient(90deg, rgba(184, 134, 11, .85), rgba(245, 197, 66, .72));
  transition: width .5s cubic-bezier(.2, .8, .2, 1);
  pointer-events: none;
}
.rnode.ws.open .ws-fill { background: linear-gradient(90deg, #b8860b, #f5c542); }

/* The gate's label (reuses .title's compact sizing) in warm gold. */
.ws-label {
  position: relative;
  color: #f7d98a;
  font-weight: 700;
  text-align: center;
  text-shadow: 0 1px 2px rgba(0, 0, 0, .85);
}

</style>
