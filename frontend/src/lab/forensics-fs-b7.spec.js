import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the gB-forensics gap batch B7 (section A).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'fs-btrfs-snapshot', flag: 'nto{btrfs_sn4psh0t_g3n3r4t10n}', hints: 4,
    solution: ['strings server.img | grep nto > found.txt'] },
  { id: 'fs-zfs-arc-zil', flag: 'nto{zfs_z1l_ub3rbl0ck_txg}', hints: 4,
    solution: ['strings zpool.img | grep nto > found.txt'] },
  { id: 'fs-ntfs-logfile', flag: 'nto{ntfs_l0gfile_r3d0_und0}', hints: 4,
    solution: ['strings LogFile | grep nto > found.txt'] },
  { id: 'fs-ntfs-compression', flag: 'nto{ntfs_lznt1_w0f_sp4rs3}', hints: 4,
    solution: ['strings secret.dat | grep nto > found.txt'] },
]

describe.each(LABS)('forensics fs gap lab: $id', ({ id, flag, hints, solution }) => {
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
