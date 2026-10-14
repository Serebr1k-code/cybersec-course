import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the gB-forensics gap batch B8-B (deep execution artifacts).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'win-prefetch-deep', flag: 'nto{pr3f3tch_v0lum3_s3r14l}', hints: 4,
    solution: ['grep nto PSEXEC.EXE-1A2B3C4D.pf > found.txt'] },
  { id: 'win-appcompat-deep', flag: 'nto{sh1mc4ch3_p4th_f0und}', hints: 4,
    solution: ['grep nto SYSTEM > found.txt'] },
  { id: 'win-amcache-deep', flag: 'nto{4mc4ch3_sh4_h4sh}', hints: 4,
    solution: ['grep nto Amcache.hve > found.txt'] },
  { id: 'win-srum-deep', flag: 'nto{srum_n3tw0rk_3xf1l}', hints: 4,
    solution: ['grep nto SRUDB.dat > found.txt'] },
]

describe.each(LABS)('forensics win-execution gap lab: $id', ({ id, flag, hints, solution }) => {
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
