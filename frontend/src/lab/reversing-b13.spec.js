import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for lab batch reversing-b13.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: "reversing-c2-beacon-config", flag: "nto{b33f_c4f3_x0r_k3y_2e}", hints: 4,
    solution: ["python3 beacon_conf.py beacon.exe > conf.txt", "grep nto conf.txt > found.txt"],
  },
  {
    id: "reversing-process-injection", flag: "nto{cr34t3r3m0t3thr34d_1nj3ct10n}", hints: 4,
    solution: ["strings -n 6 inject.exe > s.txt", "grep nto s.txt > found.txt"],
  },
  {
    id: "reversing-shellcode-loaders", flag: "nto{d0nut_st4g3_r3fl3ct1v3}", hints: 4,
    solution: ["xxd -l 32 payload.bin", "strings -n 5 payload.bin | grep nto > found.txt"],
  },
  {
    id: "reversing-unity-il2cpp", flag: "nto{1l2cpp_m3t4d4t4_str1ngs}", hints: 4,
    solution: ["strings -n 5 global-metadata.dat | grep nto > found.txt"],
  },
  {
    id: "reversing-android-packers", flag: "nto{unp4ck3d_d3x_b4ngcl3}", hints: 4,
    solution: ["frida-dexdump -U -f com.example.app", "strings -n 5 classes.dex | grep nto > found.txt"],
  },
  {
    id: "reversing-fuzzing-aflpp", flag: "nto{aflpp_c0v3r4g3_m4g1c_0xdead}", hints: 4,
    solution: ["ls -la out/default/crashes", "strings -n 5 out/default/crashes/crash_0000 | grep nto > found.txt"],
  },
  {
    id: "reversing-hybrid-fuzzing", flag: "nto{c0ncol1c_s0lv3d_c0nst4nt}", hints: 4,
    solution: ["cat solution.b64", "base64 -d solution.b64 > found.txt"],
  },
  {
    id: "reversing-asm-arm64", flag: "nto{4rm64_csel_k3y_ch3ck}", hints: 4,
    solution: ["xxd -l 20 libsample.so", "objdump -d libsample.so", "strings -n 5 libsample.so | grep nto > found.txt"],
  },
  {
    id: "reversing-win-syscalls-ssn", flag: "nto{h3lls_g4t3_ssn_0x18}", hints: 4,
    solution: ["xxd -l 32 implant.exe", "strings -n 5 implant.exe | grep nto > found.txt"],
  },
]

describe.each(LABS)('lab batch reversing-b13: $id', ({ id, flag, hints, solution }) => {
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
    expect((await s.run('check')).code).toBe(1)
    for (const cmd of solution) await s.run(cmd)
    expect((await s.run('check')).code).toBe(0)
  })
})
