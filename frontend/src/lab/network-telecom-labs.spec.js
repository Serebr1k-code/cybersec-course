import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the telecom (GSM/LTE) lab batch.
// Each entry loads the REAL fixture bundle from content/labs, replays the
// intended solution through the emulated tools (base64/grep/cut/cat are
// engine builtins), and asserts the lab's own `check` passes and the hidden
// `expect` is satisfied.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'

const LABS = [
  { id: 'network-gsm-2g',
    check: "grep -q 'nto{' answer.txt",
    solution: [
      'base64 -d intercept.b64 > intercept.txt',
      'grep mt-forwardSM intercept.txt',
      'grep mt-forwardSM intercept.txt > answer.txt',
    ] },
  { id: 'network-lte-4g',
    check: "grep -q 'nto{' answer.txt",
    solution: [
      'cat s6a.log',
      "grep 'value=' s6a.log",
      "grep 'Experimental-Result-Code' s6a.log | cut -d= -f2 | base64 -d > answer.txt",
    ] },
]

describe('network telecom labs solve end-to-end', () => {
  for (const { id, check, solution } of LABS) {
    it(id, async () => {
      const bundle = JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
      const spec = { kind: 'shell', workdir: WD, check, hints: ['a', 'b', 'c', 'd'] }
      const s = createSession({ spec, bundle })
      expect((await s.run('check')).stdout).toContain('не сходится')
      for (const cmd of solution) {
        const r = await s.run(cmd)
        expect(r.stderr, `${id}: ${cmd}`).not.toMatch(/command not found|нет в этой лабе/)
      }
      expect((await s.run('check')).stdout, `${id} check`).toContain('Готово')
      expect(s.solved).toBe(true)
    })
  }
})
