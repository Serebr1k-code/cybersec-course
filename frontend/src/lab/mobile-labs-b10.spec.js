import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the MOB-GAP-10 batch
// (radio / telecom / IoT-companion companions).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'mobile-ble-reversing', flag: 'nto{bl3_pr0t0c0l_r3v3rs3d}',
    solution: ['grep nto ble_capture.txt > found.txt'] },
  { id: 'mobile-ble-gatt-deep', flag: 'nto{g4tt_wr1t4bl3_ch4r4ct3r1st1c}',
    solution: ['grep nto gatt_table.txt > found.txt'] },
  { id: 'mobile-nfc-payment', flag: 'nto{nfc_4pdu_r3l4y_d3t3ct3d}',
    solution: ['grep nto apdu_trace.txt > found.txt'] },
  { id: 'mobile-uwb', flag: 'nto{uwb_r4ng1ng_sp00f3d}',
    solution: ['grep nto uwb_ranging.csv > found.txt'] },
  { id: 'mobile-thread-matter', flag: 'nto{m4tt3r_c0mm1ss10n1ng_p4ssc0d3}',
    solution: ['grep nto matter_commission.txt > found.txt'] },
  { id: 'mobile-sim-toolkit', flag: 'nto{stk_pr04ct1v3_c0mm4nd}',
    solution: ['grep nto stk_menu.txt > found.txt'] },
  { id: 'mobile-esim-provisioning', flag: 'nto{3s1m_rsp_pr0f1l3_4ct1v4t3d}',
    solution: ['grep nto lpa_log.txt > found.txt'] },
  { id: 'mobile-cellular-proto', flag: 'nto{n4s_4tt4ch_r3qu3st_d3c0d3d}',
    solution: ['grep nto nas_log.txt > found.txt'] },
  { id: 'mobile-imsi-catcher', flag: 'nto{1ms1_c4tch3r_d3t3ct3d}',
    solution: ['grep nto cell_info.txt > found.txt'] },
  { id: 'mobile-sms-otp', flag: 'nto{sm5_0tp_1nt3rc3pt3d}',
    solution: ['grep nto sms_pdu.txt > found.txt'] },
  { id: 'mobile-sim-swap', flag: 'nto{s1m_sw4p_p0rt0ut_fr4ud}',
    solution: ['grep nto sim_swap_events.txt > found.txt'] },
  { id: 'mobile-wearable-deep', flag: 'nto{w34r4bl3_d4t4_l4y3r_l34k}',
    solution: ['grep nto wearable_sync.txt > found.txt'] },
  { id: 'mobile-auto-companion', flag: 'nto{c4r_c0mp4n10n_4p1_t0k3n}',
    solution: ['grep nto car_api_log.txt > found.txt'] },
  { id: 'mobile-drone-app', flag: 'nto{dr0n3_t3l3m3try_1nt3rc3pt3d}',
    solution: ['grep nto drone_telemetry.txt > found.txt'] },
]

describe.each(LABS)('mobile b10 lab: $id', ({ id, flag, solution }) => {
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
