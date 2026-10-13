import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the forensics/crypto lab batch (FC-8).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'forensics-yara-sigma', flag: 'nto{s1gm4_p0w3rsh3ll_3nc_d3t3ct3d}', hints: 4,
    solution: ['python3 extract.py | grep nto > found.txt'] },
  { id: 'forensics-plaso', flag: 'nto{sup3rt1m3l1n3_c0rr3l4t10n}', hints: 4,
    solution: ['python3 hunt.py --source FILE --after "2019-03-14 09:41:07" | grep nto > found.txt'] },
  { id: 'forensics-app-artifacts', flag: 'nto{d3l3t3d_but_r3c0v3r4bl3_msg}', hints: 4,
    solution: ['python3 carve.py | grep nto > found.txt'] },
  { id: 'forensics-fileless', flag: 'nto{f1l3l3ss_run_k3y_p3rs1st3nc3}', hints: 4,
    solution: ['python3 decode.py | grep nto > found.txt'] },
  { id: 'forensics-wmi', flag: 'nto{wm1_subscr1pt10n_p3rs1st3nc3}', hints: 4,
    solution: ['python3 parse_wmi.py | grep nto > found.txt'] },
  { id: 'forensics-network-deep', flag: 'nto{dns_3xf1l_v14_txt_r3c0n}', hints: 4,
    solution: ['python3 analyze.py | grep nto > found.txt'] },
  { id: 'forensics-apfs', flag: 'nto{4pfs_ch3ckp01nt_r3c0v3ry}', hints: 4,
    solution: ['python3 apfs_scan.py | grep nto > found.txt'] },
  { id: 'forensics-ransomware', flag: 'nto{ctr_n0nc3_r3us3_c4t4str0ph3}', hints: 4,
    solution: ['python3 decrypt.py | grep nto > found.txt'] },
  { id: 'crypto-mitm', flag: 'nto{2d3s_m1tm_1a2b_4c5d}', hints: 4,
    solution: ['python3 mitm.py | grep nto > found.txt'] },
  { id: 'crypto-sponge', flag: 'nto{sp0ng3_w34k_c4p4c1ty_c0ll1s10n}', hints: 4,
    solution: ['python3 collide.py | grep nto > found.txt'] },
]

describe.each(LABS)('forensics/crypto lab: $id', ({ id, flag, hints, solution }) => {
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
    expect((await s.run('check')).code).toBe(1) // not solved yet
    for (const cmd of solution) await s.run(cmd)
    expect((await s.run('check')).code).toBe(0)
  })
})
