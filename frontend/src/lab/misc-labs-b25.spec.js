import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

function loadBundle(id) {
  const p = path.resolve(process.cwd(), `../content/labs/${id}.json`)
  return JSON.parse(fs.readFileSync(p, 'utf8'))
}
function session(spec, bundle) { return createSession({ spec, bundle }) }

function specFor(artifact, check = "grep -q 'nto{' found.txt") {
  return {
    kind: 'shell',
    workdir: '/home/student/task',
    files: ['task.md', artifact],
    check,
    hints: ['a', 'b', 'c'],
  }
}

// Batch b8-llm: model-level attack lessons (supply chain, poisoning, backdoor, privacy).
const CASES = [
  {
    id: 'misc-llm-supply-chain',
    artifact: 'pickle_dump.txt',
    flag: 'nto{p1ckl3_m0d3l_rce}',
    solve: "grep flag pickle_dump.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-data-poisoning',
    artifact: 'dataset_stats.txt',
    flag: 'nto{d4t4_p01s0n_tr1gg3r}',
    solve: "grep flag dataset_stats.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-backdoor-models',
    artifact: 'model_report.txt',
    flag: 'nto{m0d3l_b4ckd00r_tr1gg3r}',
    solve: "grep flag model_report.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-membership-inference',
    artifact: 'confidence_log.txt',
    flag: 'nto{m3mb3rsh1p_1nf3r3nc3}',
    solve: "grep flag confidence_log.txt | cut -d= -f2 | base64 -d > found.txt",
  },
]

for (const c of CASES) {
  describe(`${c.id} lab`, () => {
    const bundle = loadBundle(c.id)
    const spec = specFor(c.artifact)

    it('seeds the artifact and task', async () => {
      const s = session(spec, bundle)
      const r = await s.run(`cat ${c.artifact}`)
      expect(r.stdout.length).toBeGreaterThan(0)
    })

    it('is not solved before writing found.txt', async () => {
      const s = session(spec, bundle)
      expect((await s.run('check')).code).toBe(1)
    })

    it('solves with the documented pipeline', async () => {
      const s = session(spec, bundle)
      await s.run(c.solve)
      expect((await s.run('check')).code).toBe(0)
      expect(s.solved).toBe(true)
      expect((await s.run('cat found.txt')).stdout.trim()).toBe(c.flag)
    })
  })
}
