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
  { id: 'misc-fsop', artifact: 'io.txt', flag: 'nto{fs0p_vt4bl3_0v3rwr1t3}' },
  { id: 'misc-rop-misc', artifact: 'rop.txt', flag: 'nto{r0p_ch41n_p0p_r3t}' },
  { id: 'misc-ret2dlresolve', artifact: 'dl.txt', flag: 'nto{r3t2dlr3s0lv3_n0_l1bc}' },
  { id: 'misc-sigreturn-misc', artifact: 'srop.txt', flag: 'nto{sr0p_s1gn4l_fr4m3_f0rg3}' },
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
