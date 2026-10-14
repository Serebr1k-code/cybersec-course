import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the OSINT gB gap batch B10: each entry loads
// the REAL fixture bundle from content/labs, mirrors the `lab:` block from the
// lesson front-matter, replays the intended solution with the emulated tools,
// and asserts the lab's own `check` predicate passes.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' answer.txt"

const LABS = [
  { id: 'osint-misp', solution: [
    'cat event.json',
    "grep domain event.json",
    "echo 'nto{m1sp_c0rr3l4t10n}' > answer.txt"] },
  { id: 'osint-stix-taxii', solution: [
    'cat bundle.json',
    'grep indicator bundle.json',
    "echo 'nto{st1x_t4x11_bundl3}' > answer.txt"] },
  { id: 'osint-apt-tracking', solution: [
    'cat campaigns.json',
    'cat actors.json',
    'grep ExampleStealer actors.json',
    "echo 'nto{4pt_4ttr1but10n}' > answer.txt"] },
  { id: 'osint-ransomware-leaks', solution: [
    'cat victims.json',
    'grep finance victims.json',
    "echo 'nto{r4ns0mw4r3_l34k_m0n}' > answer.txt"] },
]

describe('osint labs B10 solve end-to-end', () => {
  for (const { id, solution } of LABS) {
    it(id, async () => {
      const bundle = JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
      const spec = { kind: 'shell', workdir: WD, check: CHECK, hints: ['a', 'b', 'c'] }
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
