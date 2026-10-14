import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the gB-forensics gap batch B8-E (log integrity & recovery).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'win-evtx-tampering', flag: 'nto{3vtx_t4mp3r_g4p}', hints: 4,
    solution: ['grep nto Security.evtx > found.txt'] },
  { id: 'win-registry-recovery', flag: 'nto{r3g_sl4ck_r3c0v3ry}', hints: 4,
    solution: ['grep nto SYSTEM > found.txt'] },
  { id: 'win-quarantine', flag: 'nto{qu4r4nt1n3_m3t4d4t4}', hints: 4,
    solution: ['grep nto quarantine.dat > found.txt'] },
  { id: 'win-windows-update', flag: 'nto{wu_p4tch_r0llb4ck}', hints: 4,
    solution: ['grep nto CBS.log > found.txt'] },
]

describe.each(LABS)('forensics win-resilience gap lab: $id', ({ id, flag, hints, solution }) => {
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
