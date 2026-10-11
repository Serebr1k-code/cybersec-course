// Deterministic node sizing shared by the tree-graph layout (TreeGraph.vue)
// and the node component (LessonNode.vue).
//
// A lesson node has a FIXED width (224px) but its height must grow with the
// title so multi-line titles are never clipped. Because the graph layout
// reserves vertical space BEFORE the DOM is measured, the height has to be
// computed deterministically from the title string. The estimate below uses a
// word-aware greedy wrap with deliberately WIDE per-character widths, so it is
// never SMALLER than the real rendered height (an under-estimate would let
// rows overlap; a small over-estimate only adds a little padding).

export const NODE_W = 224          // fixed node width — keeps wrapping deterministic
export const NODE_GAP_Y = 20       // vertical gap between nodes in the same column

const LINE_H = 17                  // title line-height (13.5px font * 1.25)
const PAD = 26                     // vertical padding + border
const META_H = 22                  // gap + difficulty/dots meta row
const CONTENT_W = 186              // usable inner width of a 224px node (conservative)

// Per-character advance estimates at 13.5px/650 weight — rounded UP so the
// computed line count never comes out too low.
const W_SPACE = 4
const W_UPPER = 10                 // ASCII A-Z
const W_LOWER = 7.8                // ASCII a-z, 0-9
const W_CYR_UPPER = 10             // Cyrillic А-Я, Ё
const W_CYR_LOWER = 8              // Cyrillic а-я, ё
const W_OTHER = 7                  // punctuation, slashes, symbols

function charWidth(ch) {
  const c = ch.codePointAt(0)
  if (ch === ' ') return W_SPACE
  if (c >= 65 && c <= 90) return W_UPPER            // A-Z
  if ((c >= 97 && c <= 122) || (c >= 48 && c <= 57)) return W_LOWER // a-z 0-9
  if (c >= 0x410 && c <= 0x42F) return W_CYR_UPPER  // А-Я
  if (c >= 0x430 && c <= 0x44F) return W_CYR_LOWER  // а-я
  if (c === 0x401) return W_CYR_UPPER               // Ё
  if (c === 0x451) return W_CYR_LOWER               // ё
  return W_OTHER
}

export const MAX_LINES = 4         // hard cap on wrapped title lines
export const MIN_NODE_H = 56

// Word-aware greedy wrap: how many visual lines the title needs.
//
// Options (all optional — the defaults reproduce the original 224px-node
// behaviour so existing callers/tests are unaffected):
//   contentWidth  inner text width (default 186 = the 224px node)
//   maxLines      hard cap on the line count (default MAX_LINES)
//   scale         per-character width multiplier; the widths above are
//                 calibrated for a 13.5px font, so a smaller font (the radial
//                 card uses 11.5px) passes 11.5/13.5 to avoid over-estimating.
export function nodeLines(title, opts = {}) {
  const contentWidth = opts.contentWidth ?? CONTENT_W
  const maxLines = opts.maxLines ?? MAX_LINES
  const scale = opts.scale ?? 1
  const text = (title || '').trim()
  if (!text) return 1
  let lines = 1
  let cur = 0
  for (const word of text.split(/\s+/)) {
    let ww = 0
    for (const ch of word) ww += charWidth(ch) * scale
    if (cur === 0) {
      cur = ww
    } else if (cur + W_SPACE * scale + ww <= contentWidth) {
      cur += W_SPACE * scale + ww
    } else {
      lines++
      cur = ww
    }
    // a single word longer than a line still consumes extra lines
    while (cur > contentWidth) { lines++; cur -= contentWidth }
  }
  return Math.max(1, Math.min(maxLines, lines))
}

// Height reserved for a node: 1 line -> 65px, 2 -> 82px, 3 -> 99px, 4 -> 116px.
// The real rendered content is 62/79/96/113px, so every reservation keeps a
// small (+3px) margin — never clips and never lets same-column rows overlap.
// `opts` is forwarded to nodeLines so a narrower / smaller-font card reserves
// the correct height.
//
// `opts` may also override the box metrics for a COMPACT card (the radial tree
// card is much smaller than the 224px graph node):
//   pad        vertical padding + border (default PAD)
//   lineHeight per-line title height    (default LINE_H)
//   metaHeight height of the meta row   (default META_H)
//   minHeight  floor for the card       (default MIN_NODE_H)
// The defaults reproduce the original 224px-node behaviour, so existing
// callers/tests are unaffected.
export function nodeHeight(node, opts = {}) {
  const lines = nodeLines(node && node.title, opts)
  const pad = opts.pad ?? PAD
  const lineH = opts.lineHeight ?? LINE_H
  const metaH = opts.metaHeight ?? META_H
  const minH = opts.minHeight ?? MIN_NODE_H
  return Math.max(minH, pad + lines * lineH + metaH)
}
