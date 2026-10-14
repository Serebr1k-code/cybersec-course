import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the gB-forensics gap batch B8-D (config/services/boot).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'win-scheduled-tasks-deep', flag: 'nto{sch3d_t4sk_p3rs1st}', hints: 4,
    solution: ['grep nto UpdaterTask > found.txt'] },
  { id: 'win-service-artifacts', flag: 'nto{s3rv1c3_1m4g3p4th_p3rs1st}', hints: 4,
    solution: ['grep nto services.reg > found.txt'] },
  { id: 'win-wmi-persistence', flag: 'nto{wm1_subscr1pt10n_b1nd}', hints: 4,
    solution: ['grep nto wmi.txt > found.txt'] },
  { id: 'win-boot-config', flag: 'nto{bcd_t3sts1gn1ng_0n}', hints: 4,
    solution: ['grep nto bcd.txt > found.txt'] },
]

describe.each(LABS)('forensics win-config gap lab: $id', ({ id, flag, hints, solution }) => {
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
