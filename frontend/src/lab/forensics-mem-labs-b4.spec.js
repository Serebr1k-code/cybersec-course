import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the forensics memory-forensics gap batch (FB-4).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'mem-acquisition', flag: 'nto{m3m_dump_r4w_4cqu1r3d}', hints: 4,
    solution: ['strings memdump.raw | grep nto > found.txt'] },
  { id: 'mem-linux', flag: 'nto{l1nux_m3m0ry_h1dd3n_pr0c}', hints: 4,
    solution: ['strings mem.lime | grep nto > found.txt'] },
  { id: 'mem-swap-pagefile', flag: 'nto{p4g3f1l3_l34k3d_s3cr3t}', hints: 4,
    solution: ['strings pagefile.sys | grep nto > found.txt'] },
  { id: 'mem-shellcode', flag: 'nto{sh3llc0d3_m4lf1nd_rwx}', hints: 4,
    solution: ['strings shellcode.bin | grep nto > found.txt'] },
]

describe.each(LABS)('forensics memory lab: $id', ({ id, flag, hints, solution }) => {
  const bundle = load(id)
  const spec = { kind: 'shell', workdir: WD, check: CHECK, hints: Array(hints).fill('h') }

  it('bundle + seed files are consistent with the lesson lab block', () => {
    expect(bundle.id).toBe(id)
    expect(bundle.workdir).toBe(WD)
    expect(bundle.fs.some((f) => f.path === `${WD}/task.md`)).toBe(true)
    expect(bundle.expect.file).toBe(`${WD}/found.txt`)
    expect(bundle.expect.contains).toBe(flag)
  })

  it('replays the intended solution and passes check', async () => {
    const s = createSession({ spec, bundle })
    expect((await s.run('check')).code).toBe(1)
    for (const cmd of solution) await s.run(cmd)
    expect((await s.run('check')).code).toBe(0)
  })
})
