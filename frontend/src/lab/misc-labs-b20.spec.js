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
  { id: 'misc-regex-engines', artifact: 'patterns.txt', flag: 'nto{r3g3x_3ng1n3_pcrc_vs_r32}' },
  { id: 'misc-regex-catastrophic', artifact: 'redos.txt', flag: 'nto{r3d0s_c4t4str0ph1c_b4ckt4ck}' },
  { id: 'misc-grammar-parsing', artifact: 'grammar.txt', flag: 'nto{gr4mm4r_p4rs3r_p3g}' },
  { id: 'misc-vm-bytecode', artifact: 'bytecode.txt', flag: 'nto{vm_byt3c0d3_d1sp4tch_l00p}' },
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
