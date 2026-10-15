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

// Each case: bundle id, the seeded artifact, the flag, and the exact solution
// command a student would type (only core lab commands).
const CASES = [
  {
    id: 'misc-kernel-module',
    artifact: 'modinfo.txt',
    flag: 'nto{k3rn3l_m0dul3_1ntr0}',
    solve: "grep description modinfo.txt | cut -d: -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-namespace-deep',
    artifact: 'ns_report.txt',
    flag: 'nto{ns3nt3r_p1v0t_3sc4p3}',
    solve: "grep flag ns_report.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-seccomp-bpf-deep',
    artifact: 'seccomp_report.txt',
    flag: 'nto{s3cc0mp_bpf_f1lt3r}',
    solve: "grep flag seccomp_report.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-heap-misc',
    artifact: 'heap_dump.txt',
    flag: 'nto{glibc_tc4ch3_f4stb1n}',
    solve: "grep flag heap_dump.txt | cut -d= -f2 | base64 -d > found.txt",
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
