// A small POSIX-ish shell parser: quoting, pipes, `&&`/`||`/`;`, redirects.
//
// tokenize() -> [{t:'word'|'op', v, fd?}]
// parse()    -> { chains:[{op, stages:[{argv, redirs:[{fd,mode,target}]}]}] }
//
// It intentionally covers the subset the lab needs (no subshells, no command
// substitution) while still being *real*: a pipeline actually runs each stage
// with the previous stage's stdout as stdin.

export function tokenize(line) {
  const tokens = []
  let cur = ''
  let quote = null
  let hasWord = false
  const flush = () => {
    if (hasWord) { tokens.push({ t: 'word', v: cur }); cur = ''; hasWord = false }
  }
  let i = 0
  while (i < line.length) {
    const c = line[i]
    if (quote) {
      if (c === quote) { quote = null; i++; continue }
      if (quote === '"' && c === '\\' && i + 1 < line.length) { cur += line[i + 1]; i += 2; continue }
      cur += c; i++; continue
    }
    if (c === "'" || c === '"') { quote = c; hasWord = true; i++; continue }
    if (c === '\\' && i + 1 < line.length) { cur += line[i + 1]; hasWord = true; i += 2; continue }
    if (c === ' ' || c === '\t') { flush(); i++; continue }

    const two = line.slice(i, i + 2)
    if (two === '&&' || two === '||' || two === '>>' || two === '<<' || two === '&>') {
      flush(); tokens.push({ t: 'op', v: two }); i += 2; continue
    }
    if (c === '|' || c === ';' || c === '<') {
      flush(); tokens.push({ t: 'op', v: c }); i++; continue
    }
    if (c === '>') {
      // `2>file` / `1>file` / `&>file` are fd redirects when written with no
      // space; `echo 2 > f` keeps `2` as a normal argument.
      let fd = null
      if (hasWord && (cur === '2' || cur === '1' || cur === '&')) { fd = cur; cur = ''; hasWord = false }
      else flush()
      tokens.push({ t: 'op', v: '>', fd })
      i++; continue
    }
    cur += c; hasWord = true; i++
  }
  flush()
  return tokens
}

export function parse(tokens) {
  const chains = []
  let cur = { op: null, stages: [] }
  let stage = { argv: [], redirs: [] }
  let pending = null // redirect awaiting its target

  const endStage = () => {
    if (stage.argv.length || stage.redirs.length) { cur.stages.push(stage); stage = { argv: [], redirs: [] } }
  }
  const endChain = () => {
    endStage()
    if (cur.stages.length) chains.push(cur)
    cur = { op: null, stages: [] }
  }

  for (const tk of tokens) {
    if (pending) {
      if (tk.t !== 'word') return { error: 'syntax error: expected filename after redirect' }
      stage.redirs.push({ ...pending, target: tk.v })
      pending = null
      continue
    }
    if (tk.t === 'op') {
      if (tk.v === '|') { endStage(); continue }
      if (tk.v === ';' || tk.v === '&&' || tk.v === '||') { endChain(); cur.op = tk.v; continue }
      if (tk.v === '>' || tk.v === '>>') { pending = { fd: tk.fd || '1', mode: tk.v === '>>' ? 'a' : 'w' }; continue }
      if (tk.v === '<') { pending = { fd: '0', mode: 'r' }; continue }
      if (tk.v === '&>') { pending = { fd: 'all', mode: 'w' }; continue }
      return { error: `unsupported operator: ${tk.v}` }
    }
    stage.argv.push(tk.v)
  }
  if (pending) return { error: 'syntax error: expected filename after redirect' }
  endChain()
  return { chains }
}

/** True when the line is only whitespace. */
export function isBlank(line) { return !line || line.trim() === '' }
