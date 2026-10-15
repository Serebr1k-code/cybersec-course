import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the MOB-GAP-11 batch
// (Binder/IPC deep + device-trust + ART formats).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'mobile-android-ipc-binder', flag: 'nto{b0und_s3rv1c3_exp0rt3d_n0_p3rm}',
    solution: ['grep nto decoded/AndroidManifest.xml > found.txt'] },
  { id: 'mobile-android-bound-service', flag: 'nto{b1nd3r_tr4nsf3r_w1th0ut_p3rm}',
    solution: ['grep nto manifest_snippet.txt > found.txt'] },
  { id: 'mobile-android-aidl', flag: 'nto{4idl_p4rcel_c0nfus10n}',
    solution: ['grep nto onTransact.txt > found.txt'] },
  { id: 'mobile-android-messenger-ipc', flag: 'nto{m3ss3ng3r_n0_c4ll3r_ch3ck}',
    solution: ['grep nto SyncService.txt > found.txt'] },
  { id: 'mobile-android-device-trust', flag: 'nto{d3v1c3_trust_w34k_l1nk}',
    solution: ['grep nto device_report.txt > found.txt'] },
  { id: 'mobile-android-lockscreen', flag: 'nto{l0ckscr33n_4db_trust3d}',
    solution: ['grep nto device_config.txt > found.txt'] },
  { id: 'mobile-android-factory-reset', flag: 'nto{frp_p3rs1st_p4rt1t10n}',
    solution: ['grep nto frp_state.txt > found.txt'] },
  { id: 'mobile-android-fbe-fde', flag: 'nto{fbe_w34k_p1n_0ffl1n3_brut3}',
    solution: ['grep nto fbe_keys.txt > found.txt'] },
  { id: 'mobile-android-art-formats', flag: 'nto{4rt_0at_vd3x_d1s}',
    solution: ['grep nto oat_dir.txt > found.txt'] },
  { id: 'mobile-android-odex-vdex', flag: 'nto{vdex_c0nt41ns_d3x}',
    solution: ['grep nto art_listing.txt > found.txt'] },
  { id: 'mobile-android-odex-unpack', flag: 'nto{vdex3xtr4ct0r_r3c0v3r_d3x}',
    solution: ['grep nto extract_log.txt > found.txt'] },
  { id: 'mobile-android-instant-apps', flag: 'nto{1nst4nt_4pp_unv3r1f13d_l1nk}',
    solution: ['grep nto applinks.txt > found.txt'] },
  { id: 'mobile-android-privesc', flag: 'nto{pr1v3sc_w0rld_wr1t4bl3_sys}',
    solution: ['grep nto privesc_notes.txt > found.txt'] },
  { id: 'mobile-android-persistence', flag: 'nto{p3rs1st_b00t_c0mpl3t3d}',
    solution: ['grep nto persist_mechs.txt > found.txt'] },
  { id: 'mobile-android-system-app', flag: 'nto{syst3m_pr1v4pp_pl4tf0rm_s1gn}',
    solution: ['grep nto privapp_perms.txt > found.txt'] },
  { id: 'mobile-android-strongbox-deep', flag: 'nto{str0ngb0x_t1t4n_m_k3y}',
    solution: ['grep nto strongbox.txt > found.txt'] },
  { id: 'mobile-android-art-internals', flag: 'nto{4rt_gc_c0mp1l3r_1nt3rn4ls}',
    solution: ['grep nto art_internals.txt > found.txt'] },
  { id: 'mobile-android-jit', flag: 'nto{j1t_pr0f1l3_gu1d3d_0pt}',
    solution: ['grep nto jit_profile.txt > found.txt'] },
]

describe.each(LABS)('mobile b11 lab: $id', ({ id, flag, solution }) => {
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
