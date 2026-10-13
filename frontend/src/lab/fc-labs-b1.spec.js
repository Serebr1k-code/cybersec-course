import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the forensics/crypto lab batch (FC-1).
// Loads the REAL fixture bundles from content/labs, replays the intended
// solution with the emulated tools, and asserts `check` passes.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'crypto-hash-forge', flag: 'nto{l3ngth_3xt3n510n_m4c_byp4ss}', hints: 4,
    solution: ['python3 forge.py | grep nto > found.txt'] },
  { id: 'crypto-merkle-tree', flag: 'nto{m3rkl3_dup_l34f_s3c0nd_pr31m4g3}', hints: 4,
    solution: ['python3 merkle.py | grep nto > found.txt'] },
  { id: 'crypto-python-random', flag: 'nto{04a4d8a5}', hints: 4,
    solution: ['python3 predict.py | grep nto > found.txt'] },
  { id: 'crypto-timing', flag: 'nto{tim1ng_s1d3_ch4nn3l_a3f9c1e0d2b7}', hints: 4,
    solution: ['python3 attack.py | grep nto > found.txt'] },
  { id: 'crypto-commitment', flag: 'nto{sch0rr_r3u53d_n0nc3}', hints: 4,
    solution: ['python3 recover.py | grep nto > found.txt'] },
  { id: 'crypto-invalid-curve', flag: 'nto{1nv4l1d_curv3_crt_r3c0v3ry}', hints: 4,
    solution: ['python3 crt.py | grep nto > found.txt'] },
  { id: 'crypto-homomorphic', flag: 'nto{p41ll13r_m4ll34b1l1ty_v0t3}', hints: 4,
    solution: ['python3 vote.py | grep nto > found.txt'] },
  { id: 'crypto-kerberos-crypto', flag: 'nto{krb5tgs_a3s256_pbkdf2_cr4ck3d}', hints: 4,
    solution: ['python3 crack.py | grep nto > found.txt'] },
  { id: 'forensics-tshark-deep', flag: 'nto{ftpl34k3d_cr3d5_1n_cl34r}', hints: 4,
    solution: ['tshark -r attack.pcap -Y \'ftp.request.command=="PASS"\' -T fields -e ftp.request.arg | grep nto > found.txt'] },
  { id: 'forensics-image-ela', flag: 'nto{ela_t4mp3r3d_r3g10n_96_96}', hints: 4,
    solution: ['python3 ela.py | grep nto > found.txt'] },
  { id: 'forensics-usb-deep', flag: 'nto{4C530001120523116345}', hints: 4,
    solution: ['python3 usb_correlate.py | grep nto > found.txt'] },
  { id: 'forensics-jumplists-srum', flag: 'nto{srum_chrome.exe_524288000}', hints: 4,
    solution: ['python3 investigate.py | grep nto > found.txt'] },
  { id: 'forensics-ntfs-mft', flag: 'nto{mft_r3s1d3nt_d4t4_r3c0v3r3d}', hints: 4,
    solution: ['python3 parse_mft.py | grep nto > found.txt'] },
  { id: 'forensics-memory-malware', flag: 'nto{m4lf1nd_rwx_1nj3ct3d_b34c0n}', hints: 4,
    solution: ['python3 malfind.py | grep nto > found.txt'] },
  { id: 'forensics-python-tooling', flag: 'nto{c4rv3d_z1p_fr0m_d1sk_1m4g3}', hints: 4,
    solution: ['python3 carve.py | grep nto > found.txt'] },
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
