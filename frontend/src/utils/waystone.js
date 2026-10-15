// Waystone gates ("вейстоуны") — pure helpers for the learning-tree gate mechanic.
//
// A waystone is a lesson whose front-matter carries `waystone: true` plus a list
// of `waystone_tasks` (lesson ids). While not every listed task is completed the
// waystone's whole DESCENDANT subtree stays locked: the tree's fog-of-war must
// not reveal it, even via "Развернуть всё" or a manual expansion. Once all tasks
// are done the branch opens.
//
// Everything here is a pure function of the /api/tree node list + a completion
// predicate, so it is trivially unit-testable and shared by TreeGraph.vue (the
// fog-of-war filter) and LessonNode.vue (the lock + N/M badge).

// A node is a waystone when the backend flagged it (model.TreeNode.waystone).
export function isWaystone(node) {
  return !!(node && node.waystone)
}

// The lesson ids that must be completed to open the gate (never null).
export function gateTasks(node) {
  const t = node && node.waystone_tasks
  if (!Array.isArray(t)) return []
  return t.filter((id) => typeof id === 'string' && id.length > 0)
}

// N — how many capstone tasks the gate requires.
export function gateTotal(node) {
  return gateTasks(node).length
}

// How many of the gate's tasks are already completed (0..N).
export function gateSolved(node, isCompleted) {
  const done = typeof isCompleted === 'function' ? isCompleted : () => false
  let n = 0
  for (const id of gateTasks(node)) if (done(id)) n++
  return n
}

// Fraction (0..1) of a gate's tasks already solved — drives the waystone block's
// left→right gold progress fill (0 = empty dark block, 1 = fully gold). A gate
// with no declared tasks is treated as 0 (an empty, inert block).
export function gateFillFraction(node, isCompleted) {
  const total = gateTotal(node)
  if (!total) return 0
  return Math.max(0, Math.min(1, gateSolved(node, isCompleted) / total))
}

// A waystone with NO tasks declared is inert (never locks) so a half-written
// gate can never dead-lock a branch. Otherwise it is open iff every task is done.
export function isGateUnlocked(node, isCompleted) {
  const tasks = gateTasks(node)
  if (!tasks.length) return true
  const done = typeof isCompleted === 'function' ? isCompleted : () => false
  return tasks.every((id) => done(id))
}

// True while the gate is actively blocking its subtree.
export function isGateLocked(node, isCompleted) {
  return isWaystone(node) && !isGateUnlocked(node, isCompleted)
}

// The set of node ids hidden behind a LOCKED waystone: every strict descendant of
// every locked waystone. The gate nodes themselves stay visible (they carry the
// lock indicator); only what lies BEYOND them is hidden. Returns a Set.
export function gatedIds(nodes, isCompleted) {
  const list = nodes || []
  const byId = new Set(list.map((n) => n.id))
  const children = new Map()
  for (const n of list) {
    const p = n.parent && byId.has(n.parent) ? n.parent : '__root__'
    if (!children.has(p)) children.set(p, [])
    children.get(p).push(n.id)
  }
  const out = new Set()
  for (const n of list) {
    if (!isGateLocked(n, isCompleted)) continue
    const stack = [...(children.get(n.id) || [])]
    let guard = 0
    while (stack.length && guard++ < 100000) {
      const id = stack.pop()
      if (out.has(id)) continue
      out.add(id)
      for (const c of children.get(id) || []) stack.push(c)
    }
  }
  return out
}

// True when any visible waystone is currently locked (drives the canvas hint).
export function hasLockedGate(nodes, isCompleted) {
  return (nodes || []).some((n) => isGateLocked(n, isCompleted))
}
