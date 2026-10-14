import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

function loadBundle(id) {
  const p = path.resolve(process.cwd(), `../content/labs/${id}.json`)
  return JSON.parse(fs.readFileSync(p, 'utf8'))
}
function session(spec, bundle) { return createSession({ spec, bundle }) }

function specFor(artifact) {
  return {
    kind: 'shell',
    workdir: '/home/student/task',
    files: ['task.md', artifact],
    check: "grep -q 'nto{' found.txt",
    hints: ['a', 'b', 'c'],
  }
}

const CASES = [
  { id: 'misc-pwntools-deep', artifact: 'exploit_notes.txt', flag: 'nto{pwnt00ls_r0p_4nd_pwn1o}' },
  { id: 'misc-scapy-deep', artifact: 'packets.txt', flag: 'nto{sc4py_p4ck3t_cr4ft}' },
  { id: 'misc-z3-deep', artifact: 'constraints.txt', flag: 'nto{z3_s0lv3r_c0nstr41nts}' },
  { id: 'misc-gdb-scripts', artifact: 'gdb_notes.txt', flag: 'nto{gdb_pyth0n_scr1pt1ng}' },
]

for (const c of CASES) {
  describe(`${c.id} lab`, () => {
    const bundle = loadBundle(c.id)
    const spec = specFor(c.artifact)

    it('seeds the artifact and task', async () => {
      const s = session(spec, bundle)
      const r = await s.run(`cat ${c.artifact}`)
      expect(r.stdout).toContain('flag:')
    })

    it('is not solved before writing found.txt', async () => {
      const s = session(spec, bundle)
      expect((await s.run('check')).code).toBe(1)
    })

    it('solves via grep + cut + base64 -d', async () => {
      const s = session(spec, bundle)
      await s.run(`grep flag ${c.artifact} | cut -d: -f2 | base64 -d > found.txt`)
      expect((await s.run('check')).code).toBe(0)
      expect(s.solved).toBe(true)
      expect((await s.run('cat found.txt')).stdout.trim()).toBe(c.flag)
    })
  })
}
