import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for reversing gap batch b15.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: "reversing-riscv-advanced", flag: "nto{r1scv_c0mpress3d_1nstr}", hints: 4,
    solution: ["strings -n 5 riscv.elf > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-mips-delay-slots", flag: "nto{m1ps_d3l4y_sl0t_tr4p}", hints: 4,
    solution: ["strings -n 5 mips.elf > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-powerpc", flag: "nto{ppc_b1g_3nd14n_l1nk_r3g}", hints: 4,
    solution: ["strings -n 5 ppc.elf > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-sparc", flag: "nto{sp4rc_w1nd0ws_d3l4y}", hints: 4,
    solution: ["strings -n 5 sparc.elf > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-s390x", flag: "nto{s390x_c1sc_v4r1abl3_l3n}", hints: 4,
    solution: ["strings -n 5 s390x.elf > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-superh", flag: "nto{superh_16b1t_f1x3d}", hints: 4,
    solution: ["strings -n 5 sh4.elf > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-android-root-detect", flag: "nto{r00t_d3t3ct_byp4ss3d}", hints: 4,
    solution: ["strings -n 5 libdetect.so > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-android-smali-dex-edit", flag: "nto{sm4l1_p4tch_r3turn_tru3}", hints: 4,
    solution: ["strings -n 5 classes.dex > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-android-dynamic-instrumentation", flag: "nto{fr1d4_h00k_j4v4_n4t1v3}", hints: 4,
    solution: ["strings -n 5 hook.js > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-android-native-symbols", flag: "nto{jni_r3g1st3rn4t1v3s_symb0ls}", hints: 4,
    solution: ["strings -n 5 libnative.so > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-dex-internals", flag: "nto{d3x_h34d3r_p00ls_mult1d3x}", hints: 4,
    solution: ["strings -n 5 classes.dex > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-oat-art", flag: "nto{oat_art_vd3x_qu1ck3n}", hints: 4,
    solution: ["strings -n 5 base.vdex > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-apk-structure", flag: "nto{apk_4n4t0my_spl1t_s1gn3d}", hints: 4,
    solution: ["unzip -p app.apk assets/notes.txt > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-win-com-rpc", flag: "nto{rpc_m1dl_stub_1nt3rf4c3}", hints: 4,
    solution: ["strings -n 6 rpcserver.exe > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-win-drivers-irp", flag: "nto{10ctl_d1sp4tch_arb1tr4ry_wr1t3}", hints: 4,
    solution: ["strings -n 5 vulndrv.sys > out.txt", "grep nto out.txt > found.txt"],
  },
]

describe.each(LABS)('reversing b15 lab: $id', ({ id, flag, hints, solution }) => {
  const bundle = load(id)
  const spec = { kind: 'shell', workdir: WD, check: CHECK, hints: Array(hints).fill('h') }

  it('bundle + seed files are consistent', () => {
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
