import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for reversing gap batch b16.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: "reversing-6502-8bit", flag: "nto{r0m_h4ck_6502_4sm}", hints: 4,
    solution: ["strings -n 5 game.nes > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-avr-8bit", flag: "nto{avr_h4rv4rd_lpm_str1ng}", hints: 4,
    solution: ["strings -n 5 firmware.elf > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-beam-erlang", flag: "nto{beam_bytecode_4t0ms}", hints: 4,
    solution: ["strings -n 5 module.beam > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-ada-fortran", flag: "nto{f0rtr4n_c0lumn_m4j0r}", hints: 4,
    solution: ["strings -n 5 solver > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-apt-tooling", flag: "nto{apt_1mpl4nt_c0mm4nds}", hints: 4,
    solution: ["strings -n 5 implant.exe > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-banker-infostealer", flag: "nto{b4nk3r_w3b1nj3ct_h00k}", hints: 4,
    solution: ["strings -n 5 banker.dll > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-botnet-loader", flag: "nto{dga_s33d_r3c0v3r}", hints: 4,
    solution: ["strings -n 5 loader > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-bindiff-diaphora-advanced", flag: "nto{p4tch_d1ff_b0unds_ch3ck}", hints: 4,
    solution: ["strings -n 5 libfoo_v2.so > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-cfg-recovery", flag: "nto{cfg_r3c0v3ry_d1sp4tch3r}", hints: 4,
    solution: ["strings -n 5 obf.elf > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-capstone-keystone", flag: "nto{c4pst0n3_k3yst0n3_un1c0rn}", hints: 4,
    solution: ["strings -n 5 engine.elf > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-cfg-guard-cet", flag: "nto{cf1_3ndbr64_sh4d0w_stack}", hints: 4,
    solution: ["strings -n 5 hardened.exe > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-bootloader-uboot", flag: "nto{ub00t_env_b00targs_r3v}", hints: 4,
    solution: ["strings -n 5 u-boot.bin > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-baseband-modem", flag: "nto{b4s3b4nd_f1rmw4r3_c2}", hints: 4,
    solution: ["strings -n 5 modem.mbn > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-bluetooth-l2cap", flag: "nto{ble_l2c4p_g4tt_r3v}", hints: 4,
    solution: ["strings -n 5 ble_capture.pcap > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-archive-formats", flag: "nto{arch1v3_z1p_crypt_r3v}", hints: 4,
    solution: ["strings -n 5 sample.zip > out.txt", "grep nto out.txt > found.txt"],
  },
]

describe.each(LABS)('reversing b16 lab: $id', ({ id, flag, hints, solution }) => {
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
