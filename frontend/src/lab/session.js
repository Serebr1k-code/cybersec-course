// The lab session: wires the virtual FS, the command registry and the
// fixture-replay tools into a runnable shell, and evaluates the lab's `check`
// predicate. Pure JS with no terminal dependency so it is unit-testable.

import { VFS, normalizePath, decode } from './vfs'
import { tokenize, parse, isBlank } from './shell'
import { COMMANDS, CORE_TOOL_NAMES } from './commands'
import { runTool } from './tools'

const HELP_INTRO = [
  'Лаборатория: встроенный шелл поверх виртуальной файловой системы.',
  'Работают конвейеры (|), перенаправления (> >>), && || ;, кавычки и глобы (*).',
  'Команды ядра:',
]

export function createSession({ spec = {}, bundle = {}, onEvent = () => {} } = {}) {
  const vfs = VFS.fromSeed(bundle.fs || [])
  const env = new Map(Object.entries({
    USER: 'student',
    HOME: '/home/student',
    SHELL: '/bin/labsh',
    PWD: '',
    HOSTNAME: bundle.hostname || 'lab',
    ...(bundle.env || {}),
  }))
  const vars = bundle.vars || {}
  const tools = Object.keys(bundle.tools || {})
  const toolNames = [...new Set([...CORE_TOOL_NAMES, ...tools, ...(spec.toolset || []), 'help', 'hint', 'check', 'clear'])].sort()

  let cwd = spec.workdir || bundle.workdir || '/home/student'
  if (!vfs.isDir(cwd)) { vfs.mkdir(cwd, { parents: true }) }
  const history = []
  let hintLevel = 0
  let solved = false

  const baseCtx = {
    vfs, env, spec, bundle, vars, toolNames, history,
    stdin: '',
    get cwd() { return cwd },
    setCwd: (p) => { cwd = p },
  }

  // --- variable + glob expansion -------------------------------------------

  function expandArg(arg) {
    const withVars = arg.replace(/\$(\w+|\{[^}]*\})/g, (_, n) => {
      const key = n.startsWith('{') ? n.slice(1, -1) : n
      return env.get(key) ?? ''
    })
    return withVars
  }

  function expandArgs(argv) {
    const out = []
    for (const a of argv) {
      const v = expandArg(a)
      if (/[*?[]/.test(v)) {
        const matches = vfs.glob(cwd, v)
        if (matches.length) { out.push(...matches); continue }
      }
      out.push(v)
    }
    return out
  }

  // --- dispatch ------------------------------------------------------------

  async function dispatch(name, args, stdin) {
    if (!name) return { stdout: '', stderr: '', code: 0 }
    if (name === 'help') return cmdHelp(args)
    if (name === 'clear') return { stdout: '', stderr: '', code: 0, clear: true }
    if (name === 'check') return runCheck()
    if (name === 'hint') return runHint(args)

    const cmd = COMMANDS[name]
    if (cmd) {
      if (args.includes('-h') || args.includes('--help')) return { stdout: cmd.help + '\n', stderr: '', code: 0 }
      baseCtx.stdin = stdin ?? ''
      try {
        const r = await cmd.run(baseCtx, args, stdin ?? '')
        return { stdout: r.stdout || '', stderr: r.stderr || '', code: r.code ?? 0 }
      } catch (e) {
        return { stdout: '', stderr: `${name}: ${e.message}\n`, code: 1 }
      }
    }

    const toolDef = bundle.tools?.[name]
    if (toolDef && (args.includes('-h') || args.includes('--help'))) {
      return { stdout: `${name} — ${toolDef.help || 'эмулируемый инструмент'}\n`, stderr: '', code: 0 }
    }
    const tool = runTool(baseCtx, name, args)
    if (tool) return tool
    if (tools.includes(name) || (spec.toolset || []).includes(name)) {
      return { stdout: '', stderr: `${name}: нет в этой лабе\n`, code: 127 }
    }
    return { stdout: '', stderr: `${name}: command not found\n`, code: 127 }
  }

  function cmdHelp(args) {
    if (args.length) {
      const c = COMMANDS[args[0]]
      if (c) return { stdout: `${args[0]} — ${c.help}\n`, stderr: '', code: 0 }
      const tool = bundle.tools?.[args[0]]
      if (tool) return { stdout: `${args[0]} — ${tool.help || 'эмулируемый инструмент'}\n`, stderr: '', code: 0 }
      return { stdout: '', stderr: `help: нет такой команды: ${args[0]}\n`, code: 1 }
    }
    const lines = [...HELP_INTRO]
    for (const n of CORE_TOOL_NAMES) lines.push(`  ${n.padEnd(9)} ${COMMANDS[n].help}`)
    if (tools.length) {
      lines.push('', 'Эмулируемые инструменты (вывод захвачен из реального запуска):')
      for (const n of tools) lines.push(`  ${n.padEnd(9)} ${bundle.tools[n].help || ''}`)
    }
    lines.push('', 'Лабораторные команды:', '  check     проверить, решена ли лаба', '  hint [N]  подсказка (слабая → сильнее)', '  clear     очистить экран')
    return { stdout: lines.join('\n') + '\n', stderr: '', code: 0 }
  }

  function runHint(args) {
    const hints = spec.hints || bundle.hints || []
    if (!hints.length) return { stdout: 'Подсказок нет — читай задание.\n', stderr: '', code: 0 }
    let idx
    if (args.length) idx = Math.max(1, parseInt(args[0], 10) || 1)
    else { hintLevel = Math.min(hintLevel + 1, hints.length); idx = hintLevel }
    const text = hints[Math.min(idx, hints.length) - 1]
    return { stdout: `Подсказка ${Math.min(idx, hints.length)}/${hints.length}: ${text}\n`, stderr: '', code: 0 }
  }

  async function runCheck() {
    if (solved) return { stdout: '✓ Лаба уже решена.\n', stderr: '', code: 0 }
    const checks = []
    if (spec.check) {
      const r = await exec(spec.check, { silent: true })
      checks.push({ label: `условие: ${spec.check}`, ok: r.code === 0 })
    }
    const exp = bundle.expect
    if (exp && exp.file) {
      const text = vfs.readText(normalizePath(cwd, exp.file))
      const ok = text == null ? false
        : (exp.contains != null ? text.includes(exp.contains) : text.trim() === exp.equals)
      checks.push({ label: `файл ${exp.file}`, ok })
    }
    if (!checks.length) return { stdout: '', stderr: 'check: у этой лабы не задано условие\n', code: 1 }
    const ok = checks.every((c) => c.ok)
    if (ok) {
      solved = true
      onEvent({ type: 'solved' })
      return { stdout: '✓ Готово! Условие лабы выполнено.\n', stderr: '', code: 0 }
    }
    const failed = checks.filter((c) => !c.ok).map((c) => c.label).join(', ')
    return { stdout: `✗ Пока не сходится (${failed}).\nПодсказка: набери \`hint\`.\n`, stderr: '', code: 1 }
  }

  // --- execution -----------------------------------------------------------

  async function runStage(stage, stdin) {
    const argv = expandArgs(stage.argv)
    let input = stdin
    for (const r of stage.redirs) {
      if (r.fd === '0') {
        const b = vfs.readFile(normalizePath(cwd, r.target))
        if (b != null) input = decode(b)
      }
    }
    const res = await dispatch(argv[0], argv.slice(1), input)
    let stdout = res.stdout
    let stderr = res.stderr
    for (const r of stage.redirs) {
      if (r.fd === '1' || r.fd === 'all') {
        try {
          const abs = normalizePath(cwd, r.target)
          if (r.mode === 'a') {
            const prev = vfs.readFile(abs) || new Uint8Array()
            const merged = new Uint8Array(prev.length + stdout.length)
            merged.set(prev, 0)
            merged.set(new TextEncoder().encode(stdout), prev.length)
            vfs.writeFile(abs, merged)
          } else {
            vfs.writeFile(abs, new TextEncoder().encode(stdout))
          }
          stdout = ''
        } catch (e) { stderr += `cannot write '${r.target}': No such file or directory\n` }
      }
      if (r.fd === '2' || r.fd === 'all') {
        try { vfs.writeFile(normalizePath(cwd, r.target), new TextEncoder().encode(stderr)) } catch (e) { /* ignore */ }
        stderr = ''
      }
    }
    return { stdout, stderr, code: res.code ?? 0, clear: res.clear }
  }

  async function runChain(chain) {
    let stdin = ''
    let result = { stdout: '', stderr: '', code: 0 }
    for (let i = 0; i < chain.stages.length; i++) {
      result = await runStage(chain.stages[i], stdin)
      if (result.clear) return result
      stdin = result.stdout
      // A failing stage in a pipeline still feeds downstream stages; only the
      // last stage's exit code is the pipeline's.
      if (i < chain.stages.length - 1) { result.stdout = ''; result.stderr = '' }
    }
    return result
  }

  /** Execute a full line. `opts.silent` suppresses history/events (for checks). */
  async function run(line, opts = {}) {
    const raw = line == null ? '' : String(line)
    if (isBlank(raw)) return { stdout: '', stderr: '', code: 0 }
    const tokens = tokenize(raw)
    const ast = parse(tokens)
    if (ast.error) return { stdout: '', stderr: `${ast.error}\n`, code: 2 }
    if (!opts.silent) {
      if (history[history.length - 1] !== raw) history.push(raw)
    }
    let last = { stdout: '', stderr: '', code: 0 }
    let out = ''
    let err = ''
    const parts = [] // ordered (stream, text) for faithful terminal output
    for (const chain of ast.chains) {
      if (chain.op === '&&' && last.code !== 0) continue
      if (chain.op === '||' && last.code === 0) continue
      const r = await runChain(chain)
      if (r.clear) return r
      // Every command in a `;`/`&&`/`||` list emits its own output in order.
      out += r.stdout
      err += r.stderr
      if (r.stdout) parts.push({ s: 'out', t: r.stdout })
      if (r.stderr) parts.push({ s: 'err', t: r.stderr })
      last = r
    }
    return { stdout: out, stderr: err, code: last.code, parts }
  }

  /** Run a command silently, returning only its exit code (used by `check`). */
  async function exec(line, opts = {}) {
    const r = await run(line, { silent: true, ...opts })
    return r
  }

  return {
    run,
    exec,
    /** A fresh session with the same spec/bundle (for a "reset" button). */
    reset: () => createSession({ spec, bundle, onEvent }),
    getState: () => ({ cwd, env: Object.fromEntries(env), history: [...history], solved, hintLevel }),
    get solved() { return solved },
    get cwd() { return cwd },
    helpText: () => cmdHelp([]).stdout,
    // Exposed for the terminal layer (tab completion, prompts).
    vfs,
    toolNames,
  }
}
