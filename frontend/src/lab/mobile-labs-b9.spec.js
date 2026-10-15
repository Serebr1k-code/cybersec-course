import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the MOB-GAP-9 batch
// (Android network/API deep + keys/crypto + screen/input privacy).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'mobile-android-ssl-pinning-native', flag: 'nto{n4t1v3_p1nn1ng_byp4ss3d}',
    solution: ['grep nto pinning_log.txt > found.txt'] },
  { id: 'mobile-android-cert-transparency', flag: 'nto{ct_l0g_m1ss1ng_c3rt}',
    solution: ['grep nto ct_logs.txt > found.txt'] },
  { id: 'mobile-android-pinning-deep', flag: 'nto{mult1_l4y3r_p1nn1ng_d0wn}',
    solution: ['grep nto bypass_notes.txt > found.txt'] },
  { id: 'mobile-android-oauth', flag: 'nto{0auth_r3d1r3ct_h1j4ck}',
    solution: ['grep nto oauth_flow.txt > found.txt'] },
  { id: 'mobile-android-jwt-mobile', flag: 'nto{jwt_n0n3_4lg_4cc3pt3d}',
    solution: ['grep nto jwt_tokens.txt > found.txt'] },
  { id: 'mobile-android-api-graphql', flag: 'nto{gr4phql_1ntr0sp3ct10n_0p3n}',
    solution: ['grep nto graphql_schema.txt > found.txt'] },
  { id: 'mobile-android-api-versioning', flag: 'nto{0ld_4p1_v1_4uth_byp4ss}',
    solution: ['grep nto api_versions.txt > found.txt'] },
  { id: 'mobile-android-ratelimit-bypass', flag: 'nto{r4t3l1m1t_h34d3r_sp00f}',
    solution: ['grep nto ratelimit_headers.txt > found.txt'] },
  { id: 'mobile-android-keystore-deep', flag: 'nto{k3yst0r3_k3y_3xtr4ct3d}',
    solution: ['grep nto keystore_dump.txt > found.txt'] },
  { id: 'mobile-android-biometric-prompt', flag: 'nto{b10m3tr1c_c4llb4ck_byp4ss}',
    solution: ['grep nto biometric_log.txt > found.txt'] },
  { id: 'mobile-android-random', flag: 'nto{s3cur3r4nd0m_s33d_0v3rr1d3}',
    solution: ['grep nto random_seeds.txt > found.txt'] },
  { id: 'mobile-android-keygen-errors', flag: 'nto{w34k_k3y_s1z3_4cc3pt3d}',
    solution: ['grep nto keygen_report.txt > found.txt'] },
  { id: 'mobile-android-screenshots', flag: 'nto{fl4g_s3cur3_n0t_s3t}',
    solution: ['grep nto window_flags.txt > found.txt'] },
  { id: 'mobile-android-screen-record', flag: 'nto{m3d14pr0j3ct10n_ungu4rd3d}',
    solution: ['grep nto mediaprojection.txt > found.txt'] },
  { id: 'mobile-android-ime', flag: 'nto{1m3_k3yl0gg1ng_3n4bl3d}',
    solution: ['grep nto ime_log.txt > found.txt'] },
]

describe.each(LABS)('mobile b9 lab: $id', ({ id, flag, solution }) => {
  const bundle = load(id)
  const spec = { kind: 'shell', workdir: WD, check: CHECK, hints: ['h', 'h', 'h'] }

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
