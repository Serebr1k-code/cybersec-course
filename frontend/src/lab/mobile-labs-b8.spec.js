import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the MOB-GAP-8 batch (forensics + enterprise/MDM).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'mobile-whatsapp-forensics', flag: 'nto{wh4ts4pp_msgst0r3_d3crypt3d}',
    solution: ['grep nto chats.txt > found.txt'] },
  { id: 'mobile-telegram-forensics', flag: 'nto{t3l3gr4m_c4ch3_db_pl41nt3xt}',
    solution: ['grep nto cache4_rows.txt > found.txt'] },
  { id: 'mobile-signal-forensics', flag: 'nto{s1gn4l_sqlc1ph3r_k3y_r3c0v3r3d}',
    solution: ['grep nto signal_db_dump.txt > found.txt'] },
  { id: 'mobile-browser-forensics', flag: 'nto{chr0m3_h1st0ry_d3l3t3d_r0ws}',
    solution: ['grep nto history_rows.txt > found.txt'] },
  { id: 'mobile-android-timeline', flag: 'nto{4ndr01d_t1m3l1n3_c0rr3l4t3d}',
    solution: ['sort -n events.csv | grep nto > found.txt'] },
  { id: 'mobile-android-tombstone', flag: 'nto{t0mbst0n3_n4t1v3_cr4sh_s1g}',
    solution: ['grep nto tombstone_00 > found.txt'] },
  { id: 'mobile-android-anr', flag: 'nto{4nr_m41n_thr34d_bl0ck3d}',
    solution: ['grep nto traces.txt > found.txt'] },
  { id: 'mobile-android-bugreport', flag: 'nto{bugr3p0rt_b4tt3ry_st4ts_dump}',
    solution: ['grep nto bugreport.txt > found.txt'] },
  { id: 'mobile-android-enterprise', flag: 'nto{4ndr01d_3nt3rpr1s3_p0l1cy_byp4ss}',
    solution: ['grep nto device_policy.txt > found.txt'] },
  { id: 'mobile-android-work-profile', flag: 'nto{w0rk_pr0f1l3_d4t4_l34k}',
    solution: ['grep nto profiles.txt > found.txt'] },
  { id: 'mobile-android-kiosk', flag: 'nto{k10sk_m0d3_3sc4p3_c0nf1rm3d}',
    solution: ['grep nto locktask.txt > found.txt'] },
  { id: 'mobile-android-zero-touch', flag: 'nto{z3r0_t0uch_3nr0llm3nt_t0k3n}',
    solution: ['grep nto notes.txt > found.txt'] },
]

describe.each(LABS)('mobile b8 lab: $id', ({ id, flag, solution }) => {
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
