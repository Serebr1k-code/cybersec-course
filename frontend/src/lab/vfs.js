// In-memory virtual filesystem for the client-side lab shell.
//
// The lab never touches the real disk: every command operates on this tree so
// the student can freely create/delete/overwrite files without side effects.
// Files are stored as raw bytes (Uint8Array) so byte-level tools (`xxd`,
// `strings`, `base64`, `file`) work on genuine content.

const enc = new TextEncoder()
const dec = new TextDecoder('utf-8', { fatal: false })

export function encode(str) { return enc.encode(str) }
export function decode(bytes) { return dec.decode(bytes || new Uint8Array()) }

/** Collapse `.`/`..`/duplicate slashes and resolve `p` against `cwd`. */
export function normalizePath(cwd, p) {
  if (p === undefined || p === null || p === '') return cwd || '/'
  let abs = p.startsWith('/') ? p : (cwd === '/' ? '' : (cwd || '')) + '/' + p
  const parts = []
  for (const seg of abs.split('/')) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') { parts.pop(); continue }
    parts.push(seg)
  }
  return '/' + parts.join('/')
}

export function dirname(p) {
  const i = p.lastIndexOf('/')
  return i <= 0 ? '/' : p.slice(0, i)
}

export function basename(p) {
  const i = p.lastIndexOf('/')
  return i < 0 ? p : p.slice(i + 1)
}

function mkdirNode() { return { type: 'dir', children: new Map() } }
function fileNode(bytes, mode = 0o644) { return { type: 'file', bytes: bytes || new Uint8Array(), mode } }

export class VFS {
  constructor() { this.root = mkdirNode() }

  /** Build from a bundle seed: [{path, text|b64|dir, mode}]. */
  static fromSeed(seed = []) {
    const vfs = new VFS()
    for (const item of seed) {
      if (!item || !item.path) continue
      const abs = normalizePath('/', item.path)
      if (item.type === 'dir' || item.dir) {
        vfs.mkdir(abs, { parents: true })
        continue
      }
      vfs.mkdir(dirname(abs), { parents: true })
      const bytes = item.b64 != null ? b64ToBytes(item.b64) : encode(item.text != null ? item.text : '')
      vfs.writeFile(abs, bytes, { mode: item.mode })
    }
    return vfs
  }

  node(abs) {
    abs = normalizePath('/', abs)
    const parts = abs.split('/').filter(Boolean)
    let cur = this.root
    for (const seg of parts) {
      if (cur.type !== 'dir') return null
      const next = cur.children.get(seg)
      if (!next) return null
      cur = next
    }
    return cur
  }

  exists(abs) { return !!this.node(abs) }
  isDir(abs) { const n = this.node(abs); return !!n && n.type === 'dir' }
  isFile(abs) { const n = this.node(abs); return !!n && n.type === 'file' }

  readFile(abs) {
    const n = this.node(abs)
    return n && n.type === 'file' ? n.bytes : null
  }

  readText(abs) {
    const b = this.readFile(abs)
    return b == null ? null : decode(b)
  }

  writeFile(abs, bytes, opts = {}) {
    const parent = this.node(dirname(abs))
    if (!parent || parent.type !== 'dir') throw new Error(`no such directory: ${dirname(abs)}`)
    const name = basename(abs)
    const prev = parent.children.get(name)
    const mode = opts.mode != null ? parseInt(String(opts.mode), 8) : (prev?.mode ?? 0o644)
    parent.children.set(name, fileNode(bytes, mode))
  }

  /** Create a directory; with parents:true behaves like `mkdir -p`. */
  mkdir(abs, opts = {}) {
    abs = normalizePath('/', abs)
    const parts = abs.split('/').filter(Boolean)
    let cur = this.root
    for (let i = 0; i < parts.length; i++) {
      const seg = parts[i]
      let next = cur.children.get(seg)
      if (!next) {
        if (!opts.parents && i !== parts.length - 1) return false
        next = mkdirNode()
        cur.children.set(seg, next)
      } else if (next.type !== 'dir') {
        return false
      }
      cur = next
    }
    return true
  }

  remove(abs, opts = {}) {
    if (abs === '/') return false
    const parent = this.node(dirname(abs))
    if (!parent || parent.type !== 'dir') return false
    const name = basename(abs)
    const node = parent.children.get(name)
    if (!node) return false
    if (node.type === 'dir' && !opts.recursive) {
      if (node.children.size > 0) return false
    }
    parent.children.delete(name)
    return true
  }

  /** List a directory: [{name, type, node}]. */
  list(abs) {
    const n = this.node(abs)
    if (!n || n.type !== 'dir') return null
    const out = []
    for (const [name, node] of n.children) out.push({ name, type: node.type, node })
    out.sort((a, b) => a.name.localeCompare(b.name))
    return out
  }

  /** Walk every path under `abs` (files and dirs). */
  walk(abs, fn, base = abs) {
    const n = this.node(abs)
    if (!n) return
    if (n.type === 'file') { fn(abs, n); return }
    for (const [name, node] of n.children) {
      const child = (abs === '/' ? '' : abs) + '/' + name
      if (node.type === 'dir') { fn(child, node); this.walk(child, fn, base) }
      else fn(child, node)
    }
  }

  /**
   * Expand a shell glob pattern (`*`, `?`, `[...]`) against the tree, resolved
   * relative to `cwd`. Returns matching absolute paths (dirs and files).
   */
  glob(cwd, pattern) {
    const abs = normalizePath(cwd, pattern)
    if (!/[*?[]/.test(abs)) return this.exists(abs) ? [abs] : []
    const segs = abs.split('/').filter(Boolean)
    let frontier = ['/']
    for (const seg of segs) {
      const next = []
      const re = globToRegExp(seg)
      for (const dir of frontier) {
        if (seg === '**') {
          // recursive: every descendant dir + the dir itself
          const acc = []
          const collect = (p) => {
            acc.push(p)
            const l = this.list(p)
            if (l) for (const e of l) if (e.type === 'dir') collect((p === '/' ? '' : p) + '/' + e.name)
          }
          collect(dir)
          next.push(...acc)
          continue
        }
        const l = this.list(dir)
        if (!l) continue
        for (const e of l) if (re.test(e.name)) next.push((dir === '/' ? '' : dir) + '/' + e.name)
      }
      frontier = next
    }
    return frontier.sort()
  }
}

function globToRegExp(seg) {
  let re = '^'
  for (const ch of seg) {
    if (ch === '*') re += '[^/]*'
    else if (ch === '?') re += '[^/]'
    else if (ch === '[') re += '['
    else if (ch === ']') re += ']'
    else re += ch.replace(/[.+^${}()|\\]/g, '\\$&')
  }
  return new RegExp(re + '$')
}

// --- base64 helpers (work in browser and in Node/jsdom tests) --------------

export function b64ToBytes(b64) {
  let clean = String(b64).replace(/\s+/g, '')
  // Tolerate padding stripped by pipelines like `cut -d= -f2`.
  const pad = clean.length % 4
  if (pad) clean += '='.repeat(4 - pad)
  if (typeof atob === 'function') {
    const bin = atob(clean)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
  }
  /* c8 ignore next 3 -- Node fallback for tests without a DOM */
  return new Uint8Array(Buffer.from(clean, 'base64'))
}

export function bytesToB64(bytes) {
  if (typeof btoa === 'function') {
    let bin = ''
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
    return btoa(bin)
  }
  /* c8 ignore next 3 */
  return Buffer.from(bytes).toString('base64')
}
