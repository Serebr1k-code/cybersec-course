// Fixture-backed external tools (nmap, curl, gobuster, …).
//
// Real network tools cannot run in the browser, so their output is captured
// ONCE from a real container (see tools/lab-record.sh) and replayed here. This
// is the only place the lab "fakes" anything, and it is honest about it: a
// tool/flag that is not part of the lab says so plainly instead of inventing
// output.
//
// Bundle shape:
//   "tools": {
//     "nmap": {
//       "help": "nmap [опции] <цель>",
//       "cases": [
//         { "match": "-sV\\s+\\{\\{target\\}\\}", "output": "…", "writes": ["-oN"] }
//       ],
//       "fallback": "…"
//     }
//   }
//
// `match` is a case-insensitive regex tested against the joined argv (after
// `{{var}}` substitution). First match wins. `writes` lists flags whose value is
// a filename: when such a flag is present the (same) output is written to that
// file in the virtual FS, so `grep`/`cat` on it works like the real tool.

import { normalizePath, encode } from './vfs'

export function substitute(str, vars = {}) {
  return String(str).replace(/\{\{(\w+)\}\}/g, (_, k) => (vars[k] != null ? String(vars[k]) : `{{${k}}}`))
}

function writeOutputs(ctx, args, spec, output) {
  for (const flag of spec.writes || []) {
    const i = args.indexOf(flag)
    if (i >= 0 && args[i + 1]) {
      const abs = normalizePath(ctx.cwd, args[i + 1])
      try { ctx.vfs.writeFile(abs, encode(output)) } catch (e) { /* parent dir missing */ }
    }
  }
}

/**
 * Replay a captured tool fixture. Returns null when the tool is not part of the
 * bundle (the caller then decides between "command not found" and an honest
 * "not in this lab" message).
 */
export function runTool(ctx, name, args) {
  const tool = ctx.bundle?.tools?.[name]
  if (!tool) return null
  const joined = substitute(args.join(' '), ctx.vars)
  for (const c of tool.cases || []) {
    let re
    try { re = new RegExp(substitute(c.match, ctx.vars), 'i') } catch (e) { continue }
    if (re.test(joined)) {
      const output = substitute(c.output || '', ctx.vars)
      writeOutputs(ctx, args, c, output)
      return { stdout: output, stderr: '', code: c.code || 0 }
    }
  }
  if (tool.fallback != null) {
    const output = substitute(tool.fallback, ctx.vars)
    writeOutputs(ctx, args, tool, output)
    return { stdout: output, stderr: '', code: 0 }
  }
  const examples = (tool.cases || []).map((c) => `  ${name} ${c.example || c.match}`).join('\n')
  return {
    stdout: '',
    stderr: `${name}: в этой лабе нет вывода для такого запуска.\n` +
      (examples ? `Доступные примеры:\n${examples}\n` : ''),
    code: 127,
  }
}

export function toolHelp(bundle, name) {
  const tool = bundle?.tools?.[name]
  return tool?.help || null
}
