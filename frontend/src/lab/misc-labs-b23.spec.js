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

// Batch b8-kernel: kernel/systems deep-dive lessons. Each lab ships a text
// artifact with a base64 `flag=` field; the documented pipeline decodes it.
const CASES = [
  {
    id: 'misc-ebpf-deep',
    artifact: 'bpftool_prog_list.txt',
    flag: 'nto{ebpf_tr4c3p01nt_spy}',
    solve: "grep flag bpftool_prog_list.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-bpf-tracing',
    artifact: 'trace_output.txt',
    flag: 'nto{bpftr4c3_0p3nsno0p}',
    solve: "grep flag trace_output.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-io-uring',
    artifact: 'strace_io_uring.txt',
    flag: 'nto{10_ur1ng_sqpo11}',
    solve: "grep flag strace_io_uring.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-procfs-tricks',
    artifact: 'proc_dump.txt',
    flag: 'nto{pr0c_environ_l34k}',
    solve: "grep flag proc_dump.txt | cut -d= -f2 | base64 -d > found.txt",
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
