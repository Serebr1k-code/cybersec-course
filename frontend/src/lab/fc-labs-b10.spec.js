import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the forensics/crypto lab batch (FC-10).
// Loads the REAL fixture bundles from content/labs, replays the intended
// solution with the emulated tools, and asserts `check` passes.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'forensics-write-blockers', flag: 'nto{wr1t3_bl0ck3r_r0_1m4g3_h4sh3d}', hints: 4,
    solution: ['sha256sum -c disk.img.sha256', 'strings disk.img | grep nto > found.txt'] },
  { id: 'forensics-live-forensics', flag: 'nto{v0l4t1l3_0rd3r_0f_c0ll3ct10n}', hints: 4,
    solution: ['cat netstat.txt', 'ps auxww | grep nto > found.txt'] },
  { id: 'forensics-ir-nist', flag: 'nto{n1st_800_61_p0st_1nc1d3nt}', hints: 4,
    solution: ['python3 ir_report.py | grep nto > found.txt'] },
  { id: 'forensics-evidence-handling', flag: 'nto{3v1d3nc3_t4mp3r_d3t3ct3d}', hints: 4,
    solution: ['python3 evidence_check.py | grep nto > found.txt'] },
  { id: 'forensics-autopsy', flag: 'nto{4ut0psy_1ng3st_k3yw0rd_h1t}', hints: 4,
    solution: ['mmls usb.E01', 'fls -r usb.E01', 'icat usb.E01 4 | grep nto > found.txt'] },
  { id: 'forensics-windows-execution', flag: 'nto{pr3f3tch_p4th_3x3cut10n}', hints: 4,
    solution: ['python3 pf_parse.py | grep nto > found.txt'] },
  { id: 'forensics-containers', flag: 'nto{d0ck3r_l4y3r_wh1t30ut_tr4c3}', hints: 4,
    solution: ['docker history miner', 'grep -r nto overlay > found.txt'] },
  { id: 'forensics-cloud', flag: 'nto{cl0udtr41l_cr34t34cc3ssk3y}', hints: 4,
    solution: ['grep CreateAccessKey cloudtrail.json', 'grep nto cloudtrail.json > found.txt'] },
  { id: 'forensics-mobile-android', flag: 'nto{andr01d_app_sql1t3_s3cr3t}', hints: 4,
    solution: ['sqlite3 msgstore.db ".tables"', 'strings msgstore.db | grep nto > found.txt'] },
  { id: 'forensics-k8s', flag: 'nto{k8s_4ud1t_p0d_3x3c_s3cr3t}', hints: 4,
    solution: ['grep -i anonymous audit.log', 'grep nto audit.log > found.txt'] },
  { id: 'crypto-signature-schemes', flag: 'nto{3cds4_n0nc3_r3us3_k3y_r3c0v3r3d}', hints: 4,
    solution: ['python3 recover_key.py | grep nto > found.txt'] },
  { id: 'crypto-ntru', flag: 'nto{ntru_l4tt1c3_k3y_r3c0v3r3d}', hints: 4,
    solution: ['python3 ntru_solve.py | grep nto > found.txt'] },
  { id: 'crypto-whitebox', flag: 'nto{wh1t3b0x_dfa_k3y_3xtr4ct3d}', hints: 4,
    solution: ['python3 wb_solve.py | grep nto > found.txt'] },
  { id: 'crypto-pairing', flag: 'nto{p41r1ng_bls_s1gn4tur3_v4l1d}', hints: 4,
    solution: ['python3 pairing_verify.py | grep nto > found.txt'] },
  { id: 'crypto-rsa-coppersmith-deep', flag: 'nto{c0pp3r5m1th_sm4ll_r00t_r3c0v3r3d}', hints: 4,
    solution: ['python3 solve.py | grep nto > found.txt'] },
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
