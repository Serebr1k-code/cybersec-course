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
  { id: 'misc-glibc-versions', artifact: 'versions.txt', flag: 'nto{gl1bc_tc4ch3_s4f3_l1nk1ng}' },
  { id: 'misc-musl-allocator', artifact: 'ldd.txt', flag: 'nto{musl_m4ll0c_n0_tc4ch3}' },
  { id: 'misc-windows-heap', artifact: 'heap.txt', flag: 'nto{w1nd0ws_lfh_4nd_h34p_sp4y}' },
  { id: 'misc-house-of', artifact: 'houses.txt', flag: 'nto{h0us3_0f_f0rc3_4nd_sp1r1t}' },
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
