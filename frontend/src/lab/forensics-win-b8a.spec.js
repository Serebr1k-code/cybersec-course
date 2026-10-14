import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the gB-forensics gap batch B8-A (Windows user-activity artifacts).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'win-windows-search', flag: 'nto{wns34rch_3db_d3l3t3d}', hints: 4,
    solution: ['grep nto Windows.edb > found.txt'] },
  { id: 'win-activity-timeline', flag: 'nto{tim3l1n3_s3ss10n}', hints: 4,
    solution: ['grep nto ActivitiesCache.db > found.txt'] },
  { id: 'win-notification-db', flag: 'nto{wpnd_n0t1f_t0ast}', hints: 4,
    solution: ['grep nto wpndatabase.db > found.txt'] },
  { id: 'win-cortana-search', flag: 'nto{c0rt4n4_s34rch_1nt3nt}', hints: 4,
    solution: ['grep nto query.db > found.txt'] },
]

describe.each(LABS)('forensics win-activity gap lab: $id', ({ id, flag, hints, solution }) => {
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
