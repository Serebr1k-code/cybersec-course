import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the crypto module-hub capstone batch (CR-13).
// Loads the REAL fixture bundles from content/labs, replays the intended
// solution with the emulated tools, and asserts `check` passes (and that a
// wrong answer is rejected).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'crypto-applied-protocols', flag: 'nto{sh4m1r_l4gr4ng3_r3c0v3rs_s3cr3t}', hints: 4,
    solution: ['cat shares.txt', 'python3 shamir.py | grep nto > found.txt'] },
  { id: 'crypto-ecc-attacks', flag: 'nto{3cds4_n0nc3_r3us3_r3c0v3rs_k3y}', hints: 4,
    solution: ['cat sig1.txt', 'python3 ecdsa_reuse.py | grep nto > found.txt'] },
  { id: 'crypto-ecc-advanced-curves', flag: 'nto{sm00th_0rd3r_p0hl1g_h3llm4n}', hints: 4,
    solution: ['cat curve.txt', 'python3 pohlig.py | grep nto > found.txt'] },
  { id: 'crypto-math-advanced', flag: 'nto{qu4dr4t1c_r3s1du3_crt_sqrt}', hints: 4,
    solution: ['cat params.txt', 'python3 sqrtmod.py | grep nto > found.txt'] },
  { id: 'crypto-modern-constructions', flag: 'nto{m0d3rn_h0m0m0rph1c_4dd1t10n}', hints: 4,
    solution: ['cat pubkey.txt ct.txt', 'python3 hom.py | grep nto > found.txt'] },
  { id: 'crypto-pki-signatures', flag: 'nto{bl1nd_rs4_s1gn4tur3_unbl1nd3d}', hints: 4,
    solution: ['cat blind.txt', 'python3 blind.py | grep nto > found.txt'] },
  { id: 'crypto-real-world', flag: 'nto{pmk1d_cr4ck3d_n0_h4ndsh4k3}', hints: 4,
    solution: ['cat pmkid.hc22000', 'hashcat -m 22000 pmkid.hc22000 wordlist.txt | grep nto > found.txt'] },
  { id: 'crypto-rsa-advanced-attacks', flag: 'nto{h4st4d_br04dc4st_3_r3c1p13nts}', hints: 4,
    solution: ['cat recipients.txt', 'python3 hastad.py | grep nto > found.txt'] },
  { id: 'crypto-rsa-coppersmith-path', flag: 'nto{fr4nkl1n_r31t3r_p4th_r3c0v3rs}', hints: 4,
    solution: ['cat fr.txt', 'python3 fr.py | grep nto > found.txt'] },
  { id: 'crypto-rsa-implementation-attacks', flag: 'nto{rs4_crt_f4ult_gcd_f4ct0rs_n}', hints: 4,
    solution: ['cat fault.txt', 'python3 fault.py | grep nto > found.txt'] },
  { id: 'crypto-symmetric-advanced', flag: 'nto{xts_tw34k_r3us3_l34ks_s3ct0r}', hints: 4,
    solution: ['cat sectors.txt', 'python3 xts.py | grep nto > found.txt'] },
  { id: 'crypto-symmetric-core', flag: 'nto{symm3tr1c_c0r3_k3ystr34m_r3us3}', hints: 4,
    solution: ['cat msgs.txt', 'python3 otp_reuse.py | grep nto > found.txt'] },
]

describe.each(LABS)('crypto hub capstone lab: $id', ({ id, flag, hints, solution }) => {
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

  it('rejects a wrong answer', async () => {
    const s = createSession({ spec, bundle })
    await s.run("echo 'nto{wrong_flag}' > found.txt")
    expect((await s.run('check')).code).toBe(1)
  })
})
