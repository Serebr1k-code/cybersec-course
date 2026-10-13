import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the forensics/crypto lab batch (FC-9).
// Loads the REAL fixture bundles from content/labs, replays the intended
// solution with the emulated tools, and asserts `check` passes.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'forensics-anti-forensics', flag: 'nto{t1m3st0mp3d_4nd_w1p3d}', hints: 4,
    solution: ['python3 anti_detect.py', 'strings disk.raw | grep nto > found.txt'] },
  { id: 'forensics-malware-yara', flag: 'nto{dr0pp3r_c2_3v1l_tld}', hints: 4,
    solution: ['strings -n 6 sample.exe | grep nto > found.txt'] },
  { id: 'forensics-memory-injection', flag: 'nto{m4lf1nd_rwx_sh3llc0d3}', hints: 4,
    solution: ['python3 malfind_carve.py | grep nto > found.txt'] },
  { id: 'forensics-memory-keys', flag: 'nto{ls4ss_s3cr3ts_1n_r4m}', hints: 4,
    solution: ['vol -f mem_keys.raw windows.lsadump | grep nto > found.txt'] },
  { id: 'forensics-cobaltstrike', flag: 'nto{cs_b34c0n_w4t3rm4rk_31337}', hints: 4,
    solution: ['python3 cs_parse.py pid.4120.dmp | grep nto > found.txt'] },
  { id: 'forensics-macos-artifacts', flag: 'nto{m4c0s_p3rs1st3nc3_pl1st}', hints: 4,
    solution: ['cat evil/run.sh | grep nto > found.txt'] },
  { id: 'forensics-chain-custody', flag: 'nto{ch41n_0f_cust0dy_1nt4ct}', hints: 4,
    solution: ['python3 custody_verify.py | grep nto > found.txt'] },
  { id: 'forensics-attack-mapping', flag: 'nto{4tt4ck_k1ll_ch41n_m4pp3d}', hints: 4,
    solution: ['python3 attack_map_run.py | grep nto > found.txt'] },
  { id: 'crypto-rsa-advanced', flag: 'nto{fr4nkl1n_r31t3r_gcd_m4st3r}', hints: 4,
    solution: ['python3 solve.py | grep nto > found.txt'] },
  { id: 'crypto-cache-attacks', flag: 'nto{c4ch3_l34k_r3c0v3r}', hints: 4,
    solution: ['python3 cache_recover.py | grep nto > found.txt'] },
  { id: 'crypto-zk-proofs', flag: 'nto{sch0rr_r3us3d_n0nc3}', hints: 4,
    solution: ['python3 zk_recover.py | grep nto > found.txt'] },
  { id: 'crypto-disk-encryption', flag: 'nto{luks_w34k_p4ssphr4s3}', hints: 4,
    solution: ['python3 luks_crack.py | grep nto > found.txt'] },
  { id: 'crypto-post-quantum', flag: 'nto{k3m_r3us3_m4ny_t1m3_p4d}', hints: 4,
    solution: ['python3 pq_solve.py | grep nto > found.txt'] },
  { id: 'crypto-edwards', flag: 'nto{3dw4rd5_c0f4ct0r_sm4ll_0rd3r}', hints: 4,
    solution: ['python3 ed_verify.py | grep nto > found.txt'] },
  { id: 'crypto-threshold-mpc', flag: 'nto{sh4m1r_thr3sh0ld_r3c0nstruct}', hints: 4,
    solution: ['python3 shamir_recover.py | grep nto > found.txt'] },
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

  it('rejects a wrong answer', async () => {
    const s = createSession({ spec, bundle })
    await s.run("echo 'nto{wrong_flag}' > found.txt")
    expect((await s.run('check')).code).toBe(1)
  })
})
