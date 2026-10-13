// Coreutils for the lab shell. Every command is a real implementation operating
// on the virtual filesystem (not a canned transcript), so the student genuinely
// manipulates files: `grep` searches real bytes, `xxd` hex-dumps real bytes,
// `base64 -d` decodes real bytes, `dd` really slices.
//
// Signature: run(ctx, args, stdin) -> { stdout, stderr, code }
//   ctx   = { vfs, env, cwd, setCwd, history, spec, bundle, toolNames, shell }
//   args  = argv without the command name
//   stdin = string piped from the previous stage (or '' )

import { normalizePath, dirname, basename, encode, decode, b64ToBytes, bytesToB64 } from './vfs'

const OK = (stdout = '') => ({ stdout, stderr: '', code: 0 })
const FAIL = (stderr, code = 1) => ({ stdout: '', stderr, code })

// A fixed timestamp keeps `ls -l` deterministic (and test-friendly).
const LAB_MTIME = 'Jan  1 00:00'

export function parseArgs(args, valueFlags = []) {
  const flags = new Set()
  const values = {}
  const pos = []
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a === '--') { pos.push(...args.slice(i + 1)); break }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=')
      const name = eq >= 0 ? a.slice(0, eq) : a
      if (valueFlags.includes(name)) values[name] = eq >= 0 ? a.slice(eq + 1) : args[++i]
      else flags.add(name)
      continue
    }
    if (a.startsWith('-') && a.length > 1) {
      const body = a.slice(1)
      let j = 0
      while (j < body.length) {
        const ch = '-' + body[j]
        if (valueFlags.includes(ch)) { values[ch] = body.slice(j + 1) || args[++i]; j = body.length }
        else { flags.add(body[j]); j++ }
      }
      continue
    }
    pos.push(a)
  }
  return { flags, values, pos }
}

function num(v, dflt) { const n = parseInt(v, 10); return Number.isFinite(n) ? n : dflt }
function off(v) {
  if (v == null) return 0
  const s = String(v)
  return /^0x/i.test(s) ? parseInt(s, 16) : parseInt(s, 10) || 0
}

/** Resolve a list of path args (or a default) to existing files. */
function resolveFiles(ctx, paths, { defaultStdin = true } = {}) {
  const files = []
  const errors = []
  for (const p of paths) {
    if (p === '-') { files.push({ path: '-', stdin: true }); continue }
    const abs = normalizePath(ctx.cwd, p)
    if (ctx.vfs.isFile(abs)) files.push({ path: abs, bytes: ctx.vfs.readFile(abs) })
    else if (ctx.vfs.isDir(abs)) errors.push(`${p}: Is a directory`)
    else errors.push(`${p}: No such file or directory`)
  }
  if (!paths.length && defaultStdin) files.push({ path: '-', stdin: true })
  return { files, errors }
}

// --- magic bytes -----------------------------------------------------------

const MAGIC = [
  { b: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], desc: 'PNG image data', mime: 'image/png' },
  { b: [0xff, 0xd8, 0xff], desc: 'JPEG image data', mime: 'image/jpeg' },
  { b: [0x47, 0x49, 0x46, 0x38], desc: 'GIF image data', mime: 'image/gif' },
  { b: [0x25, 0x50, 0x44, 0x46], desc: 'PDF document', mime: 'application/pdf' },
  { b: [0x50, 0x4b, 0x03, 0x04], desc: 'Zip archive data', mime: 'application/zip' },
  { b: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], desc: 'RAR archive data', mime: 'application/x-rar' },
  { b: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], desc: '7-zip archive data', mime: 'application/x-7z-compressed' },
  { b: [0x1f, 0x8b, 0x08], desc: 'gzip compressed data', mime: 'application/gzip' },
  { b: [0x42, 0x5a, 0x68], desc: 'bzip2 compressed data', mime: 'application/x-bzip2' },
  { b: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], desc: 'XZ compressed data', mime: 'application/x-xz' },
  { b: [0x7f, 0x45, 0x4c, 0x46], desc: 'ELF', mime: 'application/x-executable' },
  { b: [0x4d, 0x5a], desc: 'PE32 executable (Windows)', mime: 'application/x-dosexec' },
  { b: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33], desc: 'SQLite 3.x database', mime: 'application/vnd.sqlite3' },
]

function startsWith(bytes, sig) {
  if (bytes.length < sig.length) return false
  for (let i = 0; i < sig.length; i++) if (bytes[i] !== sig[i]) return false
  return true
}

function isText(bytes) {
  if (!bytes.length) return true
  for (const b of bytes) {
    if (b === 0) return false
    if (b < 0x09 || (b > 0x0d && b < 0x20) || b === 0x7f) return false
  }
  return true
}

function identify(bytes) {
  const base = baseIdentify(bytes)
  if (base.desc === 'data' && zipAtEnd(bytes)) {
    return { desc: 'Zip archive, with extra data prepended', mime: 'application/zip' }
  }
  return base
}

/** Offset-0 magic + text/data heuristics (no polyglot/zip-at-end handling). */
function baseIdentify(bytes) {
  for (const m of MAGIC) if (startsWith(bytes, m.b)) return m
  if (startsWith(bytes, [0x23, 0x21])) return { desc: 'script text executable', mime: 'text/x-shellscript' }
  if (isText(bytes)) return { desc: 'ASCII text', mime: 'text/plain' }
  return { desc: 'data', mime: 'application/octet-stream' }
}

// A ZIP appended after other data is reported by real `file` as "Zip archive,
// with extra data prepended" (detected via the End Of Central Directory record
// near the end of the file). Mirrors that so lab output matches the real tool.
const ZIP_EOCD = [0x50, 0x4b, 0x05, 0x06]

function zipAtEnd(bytes) {
  if (bytes.length < 22) return false
  const from = Math.max(0, bytes.length - 65557)
  return indexOfBytes(bytes.slice(from), ZIP_EOCD) >= 0
}

/** All signatures present (for `file -k`), matching real `file -k` ordering. */
function findAll(bytes) {
  const out = []
  const base = baseIdentify(bytes)
  if (base.desc !== 'data' && base.desc !== 'ASCII text') out.push(base)
  if (zipAtEnd(bytes)) out.push({ desc: 'Zip archive, with extra data prepended', mime: 'application/zip' })
  if (!out.length) out.push(base)
  else out.push({ desc: 'data', mime: 'application/octet-stream' })
  return out
}

function indexOfBytes(hay, needle) {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer
    return i
  }
  return -1
}

// --- ls --------------------------------------------------------------------

function permString(node) {
  const t = node.type === 'dir' ? 'd' : '-'
  const m = node.type === 'dir' ? 0o755 : (node.mode || 0o644)
  const bits = (m & 0o777).toString(8).padStart(3, '0').split('').map((d) => {
    const n = parseInt(d, 8)
    return (n & 4 ? 'r' : '-') + (n & 2 ? 'w' : '-') + (n & 1 ? 'x' : '-')
  }).join('')
  return t + bits
}

function sizeOf(node) { return node.type === 'dir' ? 4096 : node.bytes.length }

function cmdLs(ctx, args) {
  const { flags, pos } = parseArgs(args)
  const showAll = flags.has('a') || flags.has('A')
  const long = flags.has('l')
  const human = flags.has('h')
  const targets = pos.length ? pos : ['.']
  const lines = []
  let multiple = targets.length > 1
  for (const t of targets) {
    const abs = normalizePath(ctx.cwd, t)
    const node = ctx.vfs.node(abs)
    if (!node) { lines.push(`ls: cannot access '${t}': No such file or directory`); continue }
    if (node.type === 'file') { lines.push(long ? longLine(basename(abs), node, human) : basename(abs)); continue }
    if (multiple) { if (lines.length) lines.push(''); lines.push(`${t}:`) }
    const entries = (ctx.vfs.list(abs) || []).filter((e) => showAll || !e.name.startsWith('.'))
    if (long) {
      if (showAll) lines.push(longLine('.', node, human), longLine('..', ctx.vfs.node(dirname(abs)) || node, human))
      for (const e of entries) lines.push(longLine(e.name, e.node, human))
    } else {
      const names = entries.map((e) => e.name + (e.type === 'dir' ? '/' : ''))
      lines.push(names.join('  '))
    }
  }
  return OK(lines.join('\n') + (lines.length ? '\n' : ''))
}

function longLine(name, node, human) {
  const size = sizeOf(node)
  const sz = human && size >= 1024 ? `${Math.round(size / 1024)}K` : String(size)
  return `${permString(node)} 1 student student ${sz.padStart(6)} ${LAB_MTIME} ${name}`
}

// --- cat -------------------------------------------------------------------

function cmdCat(ctx, args) {
  const { flags, pos } = parseArgs(args)
  const { files, errors } = resolveFiles(ctx, pos)
  let stdout = ''
  for (const f of files) {
    const text = f.stdin ? ctx.stdin : decode(f.bytes)
    if (!f.stdin && /[\u0000-\u0008\u000e-\u001f]/.test(text) && !flags.has('v')) {
      // Binary-ish: real cat would dump bytes; we keep it readable but warn.
      errors.push(`${basename(f.path)}: binary file — use xxd/strings`)
      continue
    }
    stdout += text
  }
  return { stdout, stderr: errors.map((e) => `cat: ${e}`).join('\n') + (errors.length ? '\n' : ''), code: errors.length ? 1 : 0 }
}

// --- echo ------------------------------------------------------------------

function expandVars(ctx, s) {
  return s.replace(/\$(\w+|\{[^}]*\})/g, (_, name) => {
    const key = name.startsWith('{') ? name.slice(1, -1) : name
    return ctx.env.get(key) ?? ''
  })
}

function cmdEcho(ctx, args) {
  const { flags, pos } = parseArgs(args)
  const text = pos.map((p) => expandVars(ctx, p)).join(' ')
  return OK(text + (flags.has('n') ? '' : '\n'))
}

// --- cd / pwd --------------------------------------------------------------

function cmdPwd(ctx) { return OK(ctx.cwd + '\n') }

function cmdCd(ctx, args) {
  const target = args[0] || ctx.env.get('HOME') || '/'
  const abs = normalizePath(ctx.cwd, expandVars(ctx, target))
  if (!ctx.vfs.isDir(abs)) return FAIL(`cd: ${target}: No such file or directory\n`)
  ctx.setCwd(abs)
  return OK()
}

// --- touch / mkdir / rm ----------------------------------------------------

function cmdTouch(ctx, args) {
  const { pos } = parseArgs(args)
  if (!pos.length) return FAIL('touch: missing file operand\n')
  let stderr = ''
  for (const p of pos) {
    const abs = normalizePath(ctx.cwd, p)
    if (!ctx.vfs.exists(abs)) {
      try { ctx.vfs.writeFile(abs, new Uint8Array()) } catch (e) { stderr += `touch: cannot touch '${p}': No such file or directory\n` }
    }
  }
  return { stdout: '', stderr, code: stderr ? 1 : 0 }
}

function cmdMkdir(ctx, args) {
  const { flags, pos } = parseArgs(args)
  if (!pos.length) return FAIL('mkdir: missing operand\n')
  let stderr = ''
  for (const p of pos) {
    const abs = normalizePath(ctx.cwd, p)
    if (!ctx.vfs.mkdir(abs, { parents: flags.has('p') })) stderr += `mkdir: cannot create directory '${p}': File exists or no such file or directory\n`
  }
  return { stdout: '', stderr, code: stderr ? 1 : 0 }
}

function cmdRm(ctx, args) {
  const { flags, pos } = parseArgs(args)
  if (!pos.length) return FAIL('rm: missing operand\n')
  const recursive = flags.has('r') || flags.has('R')
  let stderr = ''
  for (const p of pos) {
    const abs = normalizePath(ctx.cwd, p)
    if (abs === '/') { stderr += 'rm: it is dangerous to operate recursively on /\n'; continue }
    if (!ctx.vfs.exists(abs)) { if (!flags.has('f')) stderr += `rm: cannot remove '${p}': No such file or directory\n`; continue }
    if (!ctx.vfs.remove(abs, { recursive })) stderr += `rm: cannot remove '${p}': Is a directory (use -r)\n`
  }
  return { stdout: '', stderr, code: stderr ? 1 : 0 }
}

// --- grep ------------------------------------------------------------------

function compilePattern(pattern, pcre) {
  let src = pattern
  if (pcre) src = src.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
  // Escape regex metachars, keep it a literal substring unless -E-like used.
  const esc = src.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return new RegExp(esc, 'g')
}

function cmdGrep(ctx, args) {
  const { flags, pos } = parseArgs(args)
  if (!pos.length) return FAIL('grep: missing pattern\n')
  const pattern = pos[0]
  const targets = pos.slice(1)
  const ignoreCase = flags.has('i')
  const onlyMatch = flags.has('o')
  const withLineNo = flags.has('n')
  const withOffset = flags.has('b')
  const countOnly = flags.has('c')
  const invert = flags.has('v')
  const quiet = flags.has('q')
  const recursive = flags.has('r') || flags.has('R')

  let re = compilePattern(pattern, flags.has('P'))
  if (ignoreCase) re = new RegExp(re.source, re.flags + 'i')

  const sources = []
  if (recursive) {
    for (const t of (targets.length ? targets : ['.'])) {
      const abs = normalizePath(ctx.cwd, t)
      ctx.vfs.walk(abs, (p, node) => { if (node.type === 'file') sources.push({ path: p, bytes: node.bytes }) })
    }
  } else {
    const { files, errors } = resolveFiles(ctx, targets)
    for (const f of files) sources.push({ path: f.path, text: f.stdin ? (ctx.stdin ?? '') : decode(f.bytes), bytes: f.bytes })
    if (!files.length && errors.length) return FAIL(errors.map((e) => `grep: ${e}`).join('\n') + '\n')
  }

  const showName = sources.length > 1 || recursive
  const lines = []
  let matched = 0
  for (const s of sources) {
    const text = s.text != null ? s.text : decode(s.bytes)
    const parts = text.split('\n')
    let byteBase = 0
    let fileCount = 0
    for (let i = 0; i < parts.length; i++) {
      const line = parts[i]
      re.lastIndex = 0
      const hit = re.test(line)
      if (hit !== invert) {
        matched++
        fileCount++
        if (quiet) continue
        const prefix = (showName ? `${s.path}:` : '') + (withLineNo ? `${i + 1}:` : '') + (withOffset ? `${byteBase}:` : '')
        if (onlyMatch) {
          re.lastIndex = 0
          let m
          while ((m = re.exec(line)) !== null) { lines.push(prefix + m[0]); if (m.index === re.lastIndex) re.lastIndex++ }
        } else lines.push(prefix + line)
      }
      byteBase += encode(line).length + 1
    }
    if (countOnly && !quiet) lines.push((showName ? `${s.path}:` : '') + fileCount)
  }
  return { stdout: lines.length ? lines.join('\n') + '\n' : '', stderr: '', code: matched ? 0 : 1 }
}

// --- head / tail / wc ------------------------------------------------------

function readInput(ctx, pos) {
  const { files, errors } = resolveFiles(ctx, pos)
  let text = ''
  for (const f of files) text += f.stdin ? (ctx.stdin ?? '') : decode(f.bytes)
  return { text, errors }
}

function cmdHead(ctx, args) {
  const { values, pos } = parseArgs(args, ['-n'])
  const n = num(values['-n'] ?? values['--lines'], 10)
  const { text, errors } = readInput(ctx, pos)
  if (errors.length) return FAIL(errors.map((e) => `head: ${e}`).join('\n') + '\n')
  const lines = text.split('\n')
  if (lines.length && lines[lines.length - 1] === '') lines.pop()
  return OK(lines.slice(0, n).join('\n') + (lines.length ? '\n' : ''))
}

function cmdTail(ctx, args) {
  const { values, pos } = parseArgs(args, ['-n'])
  const n = num(values['-n'] ?? values['--lines'], 10)
  const { text, errors } = readInput(ctx, pos)
  if (errors.length) return FAIL(errors.map((e) => `tail: ${e}`).join('\n') + '\n')
  const lines = text.split('\n')
  if (lines.length && lines[lines.length - 1] === '') lines.pop()
  return OK(lines.slice(Math.max(0, lines.length - n)).join('\n') + (lines.length ? '\n' : ''))
}

function cmdWc(ctx, args) {
  const { flags, pos } = parseArgs(args)
  const { text, errors } = readInput(ctx, pos)
  if (errors.length) return FAIL(errors.map((e) => `wc: ${e}`).join('\n') + '\n')
  const bytes = encode(text).length
  const words = (text.match(/\S+/g) || []).length
  const lines = text === '' ? 0 : text.split('\n').length - (text.endsWith('\n') ? 1 : 0)
  const parts = []
  if (flags.has('l')) parts.push(String(lines))
  else if (flags.has('w')) parts.push(String(words))
  else if (flags.has('c')) parts.push(String(bytes))
  else parts.push(String(lines), String(words), String(bytes))
  return OK(parts.join(' ') + '\n')
}

// --- sort / uniq / cut -----------------------------------------------------

function cmdSort(ctx, args) {
  const { flags, pos } = parseArgs(args)
  const { text } = readInput(ctx, pos)
  const lines = text.split('\n')
  if (lines.length && lines[lines.length - 1] === '') lines.pop()
  lines.sort()
  if (flags.has('r')) lines.reverse()
  const out = []
  for (const l of lines) out.push(l)
  if (flags.has('u')) return OK([...new Set(out)].join('\n') + (out.length ? '\n' : ''))
  return OK(out.join('\n') + (out.length ? '\n' : ''))
}

function cmdUniq(ctx, args) {
  const { flags, pos } = parseArgs(args)
  const { text } = readInput(ctx, pos)
  const lines = text.split('\n')
  if (lines.length && lines[lines.length - 1] === '') lines.pop()
  const out = []
  for (const l of lines) if (!out.length || out[out.length - 1] !== l) out.push(l)
  if (flags.has('c')) {
    const counts = []
    for (const l of lines) {
      const last = counts[counts.length - 1]
      if (last && last.line === l) last.n++
      else counts.push({ line: l, n: 1 })
    }
    return OK(counts.map((c) => `${String(c.n).padStart(7)} ${c.line}`).join('\n') + (counts.length ? '\n' : ''))
  }
  return OK(out.join('\n') + (out.length ? '\n' : ''))
}

function cmdCut(ctx, args) {
  const { values, flags, pos } = parseArgs(args, ['-d', '-f'])
  const delim = values['-d'] ?? (flags.has('d') ? values['-d'] : ':')
  const f = values['-f'] ?? values['--fields'] ?? '1'
  const idxs = String(f).split(',').map((x) => parseInt(x, 10) - 1)
  const { text } = readInput(ctx, pos)
  const lines = text.split('\n')
  if (lines.length && lines[lines.length - 1] === '') lines.pop()
  const out = lines.map((l) => l.split(delim).filter((_, i) => idxs.includes(i)).join(delim))
  return OK(out.join('\n') + (out.length ? '\n' : ''))
}

// --- find ------------------------------------------------------------------

function cmdFind(ctx, args) {
  const pos = []
  const preds = []
  let i = 0
  while (i < args.length) {
    const a = args[i]
    if (a === '-name' || a === '-type' || a === '-maxdepth') { preds.push([a, args[++i]]); i++; continue }
    if (a === '-print' || a === '-print0') { preds.push([a, null]); i++; continue }
    if (a.startsWith('-')) { preds.push([a, null]); i++; continue }
    pos.push(a); i++
  }
  const roots = pos.length ? pos : ['.']
  const namePred = preds.find((p) => p[0] === '-name')
  const typePred = preds.find((p) => p[0] === '-type')
  const maxDepth = preds.find((p) => p[0] === '-maxdepth')
  const nul = preds.some((p) => p[0] === '-print0')
  const nameRe = namePred ? globNameRe(namePred[1]) : null
  const results = []
  for (const r of roots) {
    const abs = normalizePath(ctx.cwd, r)
    if (!ctx.vfs.exists(abs)) { return FAIL(`find: '${r}': No such file or directory\n`) }
    const baseDepth = abs === '/' ? 0 : abs.split('/').filter(Boolean).length
    const visit = (p) => {
      const depth = p === '/' ? 0 : p.split('/').filter(Boolean).length - baseDepth
      if (maxDepth && depth > num(maxDepth[1], 99)) return
      const node = ctx.vfs.node(p)
      if (!node) return
      const matchesType = !typePred || (typePred[1] === 'f' ? node.type === 'file' : node.type === 'dir')
      const matchesName = !nameRe || nameRe.test(basename(p))
      if ((namePred || typePred) ? (matchesType && matchesName) : true) results.push(p)
      if (node.type === 'dir') for (const [name] of node.children) visit((p === '/' ? '' : p) + '/' + name)
    }
    visit(abs)
  }
  const sep = nul ? '\0' : '\n'
  return OK(results.join(sep) + (results.length ? sep : ''))
}

function globNameRe(pat) {
  let re = '^'
  for (const ch of pat) {
    if (ch === '*') re += '.*'
    else if (ch === '?') re += '.'
    else re += ch.replace(/[.+^${}()|\\[\]]/g, '\\$&')
  }
  return new RegExp(re + '$')
}

// --- file / xxd / strings / base64 -----------------------------------------

function cmdFile(ctx, args) {
  const { flags, pos } = parseArgs(args)
  if (!pos.length) return FAIL('file: missing operand\n')
  const brief = flags.has('b')
  const mime = flags.has('i')
  const all = flags.has('k')
  const out = []
  for (const p of pos) {
    const abs = normalizePath(ctx.cwd, p)
    const bytes = ctx.vfs.readFile(abs)
    if (bytes == null) { out.push(`${p}: cannot open (No such file or directory)`); continue }
    const label = brief ? '' : `${p}: `
    if (all) {
      const found = findAll(bytes)
      const joined = found.map((m, idx) => (idx === 0 ? '' : '\\012- ') + (mime ? m.mime : m.desc)).join('')
      out.push(label + joined)
    } else {
      const m = identify(bytes)
      out.push(label + (mime ? m.mime : m.desc))
    }
  }
  return OK(out.join('\n') + '\n')
}

function cmdXxd(ctx, args) {
  const { values, flags, pos } = parseArgs(args, ['-l', '-s'])
  let bytes
  if (pos.length) {
    const abs = normalizePath(ctx.cwd, pos[0])
    bytes = ctx.vfs.readFile(abs)
    if (bytes == null) return FAIL(`xxd: ${pos[0]}: No such file or directory\n`)
  } else bytes = encode(ctx.stdin ?? '')
  const start = off(values['-s'] ?? 0)
  const len = values['-l'] != null ? num(values['-l'], bytes.length) : bytes.length
  const slice = bytes.slice(start, start + len)
  const lines = []
  for (let i = 0; i < slice.length; i += 16) {
    const chunk = slice.slice(i, i + 16)
    const groups = []
    for (let g = 0; g < 8; g++) {
      const b0 = chunk[g * 2]
      const b1 = chunk[g * 2 + 1]
      groups.push((b0 != null ? b0.toString(16).padStart(2, '0') : '  ') + (b1 != null ? b1.toString(16).padStart(2, '0') : '  '))
    }
    let ascii = ''
    for (const b of chunk) ascii += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.'
    const addr = (start + i).toString(16).padStart(8, '0')
    lines.push(`${addr}: ${groups.join(' ')}  ${ascii}`)
  }
  return OK(lines.join('\n') + (lines.length ? '\n' : ''))
}

function cmdStrings(ctx, args) {
  const { values, flags, pos } = parseArgs(args, ['-n'])
  const min = num(values['-n'] ?? values['--bytes'] ?? (flags.has('n') ? 4 : 4), 4)
  let bytes
  if (pos.length) {
    const abs = normalizePath(ctx.cwd, pos[0])
    bytes = ctx.vfs.readFile(abs)
    if (bytes == null) return FAIL(`strings: '${pos[0]}': No such file or directory\n`)
  } else bytes = encode(ctx.stdin ?? '')
  const found = []
  let run = ''
  for (const b of bytes) {
    if (b >= 0x20 && b <= 0x7e) run += String.fromCharCode(b)
    else { if (run.length >= min) found.push(run); run = '' }
  }
  if (run.length >= min) found.push(run)
  return OK(found.join('\n') + (found.length ? '\n' : ''))
}

function cmdBase64(ctx, args) {
  const { values, flags, pos } = parseArgs(args, ['-w'])
  const decodeMode = flags.has('d') || flags.has('D') || flags.has('--decode')
  let bytes
  if (pos.length) {
    const abs = normalizePath(ctx.cwd, pos[0])
    bytes = ctx.vfs.readFile(abs)
    if (bytes == null) return FAIL(`base64: ${pos[0]}: No such file or directory\n`)
  } else bytes = encode(ctx.stdin ?? '')
  if (decodeMode) {
    const text = decode(bytes).replace(/\s+/g, '')
    try {
      const out = b64ToBytes(text)
      return { stdout: decode(out), stderr: '', code: 0 }
    } catch (e) { return FAIL('base64: invalid input\n') }
  }
  const wrap = values['-w'] != null ? num(values['-w'], 76) : 76
  const enc = bytesToB64(bytes)
  if (wrap <= 0) return OK(enc + '\n')
  const lines = []
  for (let i = 0; i < enc.length; i += wrap) lines.push(enc.slice(i, i + wrap))
  return OK(lines.join('\n') + '\n')
}

// --- dd --------------------------------------------------------------------

function cmdDd(ctx, args) {
  const opts = {}
  for (const a of args) {
    const eq = a.indexOf('=')
    if (eq > 0) opts[a.slice(0, eq)] = a.slice(eq + 1)
  }
  const bs = num(opts.bs, 512)
  const count = opts.count != null ? num(opts.count, 0) : null
  const skip = num(opts.skip, 0)
  const seek = num(opts.seek, 0)
  const notrunc = (opts.conv || '').includes('notrunc')
  let src = new Uint8Array()
  if (opts.if) {
    const abs = normalizePath(ctx.cwd, opts.if)
    const b = ctx.vfs.readFile(abs)
    if (b == null) return FAIL(`dd: failed to open '${opts.if}': No such file or directory\n`)
    src = b
  } else src = encode(ctx.stdin ?? '')
  let start = skip * bs
  let len = count != null ? count * bs : src.length - start
  const slice = src.slice(start, start + len)
  if (!opts.of) return { stdout: '', stderr: '', code: 0 }
  const outAbs = normalizePath(ctx.cwd, opts.of)
  let outBytes = slice
  if (seek > 0 || notrunc) {
    const prev = ctx.vfs.readFile(outAbs) || new Uint8Array()
    const merged = new Uint8Array(Math.max(prev.length, seek * bs + slice.length))
    merged.set(prev, 0)
    merged.set(slice, seek * bs)
    outBytes = merged
  }
  try { ctx.vfs.writeFile(outAbs, outBytes) } catch (e) { return FAIL(`dd: failed to open '${opts.of}': No such file or directory\n`) }
  return { stdout: '', stderr: '', code: 0 }
}

// --- env / export / misc ---------------------------------------------------

function cmdEnv(ctx) {
  const lines = []
  for (const [k, v] of ctx.env) lines.push(`${k}=${v}`)
  return OK(lines.join('\n') + (lines.length ? '\n' : ''))
}

function cmdExport(ctx, args) {
  for (const a of args) {
    const eq = a.indexOf('=')
    if (eq > 0) ctx.env.set(a.slice(0, eq), a.slice(eq + 1))
  }
  return OK()
}

function cmdHistory(ctx) {
  const lines = ctx.history.map((h, i) => `${String(i + 1).padStart(5)}  ${h}`)
  return OK(lines.join('\n') + (lines.length ? '\n' : ''))
}

function cmdWhoami(ctx) { return OK((ctx.env.get('USER') || 'student') + '\n') }
function cmdHostname(ctx) { return OK((ctx.env.get('HOSTNAME') || 'lab') + '\n') }
function cmdId(ctx) { return OK(`uid=1000(${ctx.env.get('USER') || 'student'}) gid=1000(${ctx.env.get('USER') || 'student'}) groups=1000(${ctx.env.get('USER') || 'student'})\n`) }
function cmdUname(ctx, args) {
  const { flags } = parseArgs(args)
  return OK((flags.has('a') ? 'Linux lab 6.1.0-lab #1 SMP x86_64 GNU/Linux' : 'Linux') + '\n')
}
function cmdWhich(ctx, args) {
  const out = []
  for (const a of args) out.push(ctx.toolNames.includes(a) ? `/usr/bin/${a}` : `which: no ${a} in (/usr/bin)`)
  return OK(out.join('\n') + (out.length ? '\n' : ''))
}
function cmdSleep() { return OK() }

// --- registry --------------------------------------------------------------

export const COMMANDS = {
  ls: { help: 'ls [-la] [путь…] — список файлов в каталоге', run: cmdLs },
  cat: { help: 'cat <файл…> — вывести содержимое файлов', run: cmdCat },
  echo: { help: 'echo [-n] <текст…> — вывести текст (поддерживает $VAR)', run: cmdEcho },
  pwd: { help: 'pwd — показать текущий каталог', run: cmdPwd },
  cd: { help: 'cd [каталог] — сменить каталог', run: cmdCd },
  touch: { help: 'touch <файл…> — создать пустой файл', run: cmdTouch },
  mkdir: { help: 'mkdir [-p] <каталог…> — создать каталог', run: cmdMkdir },
  rm: { help: 'rm [-rf] <путь…> — удалить файлы/каталоги', run: cmdRm },
  grep: { help: 'grep [-inobcqvP] [-r] <шаблон> [файл…] — поиск строк (grep -aboP \'PK\\x03\\x04\' file)', run: cmdGrep },
  head: { help: 'head [-n N] [файл] — первые N строк (по умолчанию 10)', run: cmdHead },
  tail: { help: 'tail [-n N] [файл] — последние N строк (по умолчанию 10)', run: cmdTail },
  wc: { help: 'wc [-lwc] [файл] — число строк/слов/байт', run: cmdWc },
  sort: { help: 'sort [-ru] [файл] — сортировка строк', run: cmdSort },
  uniq: { help: 'uniq [-c] [файл] — убрать соседние дубликаты', run: cmdUniq },
  cut: { help: 'cut -d<разделитель> -f<N> [файл] — вырезать колонки', run: cmdCut },
  find: { help: 'find [путь] [-name шаблон] [-type f|d] [-maxdepth N] — поиск файлов', run: cmdFind },
  file: { help: 'file [-bik] <файл…> — определить тип по магическим байтам', run: cmdFile },
  xxd: { help: 'xxd [-l N] [-s OFF] <файл> — hex-дамп файла', run: cmdXxd },
  strings: { help: 'strings [-n N] <файл> — печатаемые строки (по умолчанию ≥4 символов)', run: cmdStrings },
  base64: { help: 'base64 [-d] [-w N] [файл] — кодировать/декодировать base64', run: cmdBase64 },
  dd: { help: 'dd if=FILE of=FILE bs=N count=N skip=N conv=notrunc — копирование байт', run: cmdDd },
  env: { help: 'env — показать переменные окружения', run: cmdEnv },
  export: { help: 'export VAR=значение — задать переменную окружения', run: cmdExport },
  history: { help: 'history — история команд', run: cmdHistory },
  whoami: { help: 'whoami — текущий пользователь', run: cmdWhoami },
  id: { help: 'id — идентификаторы пользователя', run: cmdId },
  hostname: { help: 'hostname — имя хоста', run: cmdHostname },
  uname: { help: 'uname [-a] — информация о системе', run: cmdUname },
  which: { help: 'which <команда…> — путь к команде', run: cmdWhich },
  sleep: { help: 'sleep <сек> — пауза (в лабе — мгновенно)', run: cmdSleep },
}

export const CORE_TOOL_NAMES = Object.keys(COMMANDS)

export { identify, findAll, parseArgs as parseFlags }
