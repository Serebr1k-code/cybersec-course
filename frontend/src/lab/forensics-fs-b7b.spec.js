import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the gB-forensics gap batch B7 (section A part 2).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'fs-timestamp-semantics', flag: 'nto{ntfs_s1_vs_fn_t1m3st0mp}', hints: 4,
    solution: ['strings mft.rec | grep nto > found.txt'] },
  { id: 'fs-ext4-deleted', flag: 'nto{ext4_1n0d3_dt1m3_jbd2}', hints: 4,
    solution: ['strings ext4.img | grep nto > found.txt'] },
  { id: 'fs-carving-fragmented', flag: 'nto{fr4gm3nt3d_c4rv1ng_sm4rt}', hints: 4,
    solution: ['strings dump.bin | grep nto > found.txt'] },
  { id: 'fs-luks-header', flag: 'nto{luks_h3ad3r_k3ysl0t_pbkdf2}', hints: 4,
    solution: ['strings luks.hdr | grep nto > found.txt'] },
  { id: 'fs-veracrypt-header', flag: 'nto{v3r4crypt_h1dd3n_v0lum3}', hints: 4,
    solution: ['strings vc.hdr | grep nto > found.txt'] },
  { id: 'fs-bitlocker-recovery', flag: 'nto{b1tl0ck3r_vmk_r3c0v3ry}', hints: 4,
    solution: ['strings fve.meta | grep nto > found.txt'] },
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
