// Tab completion for the lab shell: command names, paths and (best-effort) the
// working directory of the token under the cursor.

import { normalizePath } from './vfs'

export function complete(input, ctx) {
  const frag = (input.match(/(\S*)$/) || ['', ''])[1]
  const head = input.slice(0, input.length - frag.length)
  const words = head.trim() === '' ? [] : head.trim().split(/\s+/)
  const isFirst = words.length === 0

  const out = new Set()

  if (isFirst) {
    for (const n of ctx.toolNames) if (n.startsWith(frag)) out.add(n)
  }

  const slash = frag.lastIndexOf('/')
  const dirPart = slash >= 0 ? frag.slice(0, slash + 1) : ''
  const namePart = slash >= 0 ? frag.slice(slash + 1) : frag
  const dirAbs = normalizePath(ctx.cwd, dirPart || '.')
  const entries = ctx.vfs.list(dirAbs) || []
  for (const e of entries) {
    if (namePart && !e.name.startsWith(namePart)) continue
    if (!namePart && e.name.startsWith('.')) continue
    out.add(dirPart + e.name + (e.type === 'dir' ? '/' : ''))
  }

  return [...out].sort()
}

/** Longest common prefix of a candidate list (used to extend the input). */
export function commonPrefix(items) {
  if (!items.length) return ''
  let p = items[0]
  for (const it of items) {
    let i = 0
    while (i < p.length && i < it.length && p[i] === it[i]) i++
    p = p.slice(0, i)
  }
  return p
}
