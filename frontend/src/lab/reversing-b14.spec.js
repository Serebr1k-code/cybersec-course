import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for reversing gap batch b14.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: "reversing-win-peb-teb", flag: "nto{ntdll_unh00k_by_hand}", hints: 4,
    solution: ["python3 walk_peb.py peb.bin > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-win-api-hooking", flag: "nto{1nline_h00k_d3t3ct3d}", hints: 4,
    solution: ["python3 find_hook.py hooks.bin > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-win-seh-cpp", flag: "nto{rtt1_vt4bl3_cl4ss_r3c0v3ry}", hints: 4,
    solution: ["python3 parse_rtti.py classes.bin > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-linux-kernel-modules", flag: "nto{lkm_kpr0b3_g3td3nts_h00k}", hints: 4,
    solution: ["python3 scan_lkm.py suspicious.ko > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-macos-kexts", flag: "nto{k3xt_10k1t_p3rs0n4l1t13s}", hints: 4,
    solution: ["python3 kext_info.py Sample.kext > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-smm-uefi", flag: "nto{uefi_dx3_dr1v3r_f0und}", hints: 4,
    solution: ["python3 scan_uefi.py firmware.bin > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-objc-runtime", flag: "nto{0bjc_m3th0d_l1st_r3c0v3ry}", hints: 4,
    solution: ["python3 objc_meta.py app.bin > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-ios-arm64e-pac", flag: "nto{pac1bsp_aut1bsp_r3tab}", hints: 4,
    solution: ["python3 scan_pac.py func.bin > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-binary-ninja", flag: "nto{bnil_hl1l_aut0m4t10n}", hints: 4,
    solution: ["python3 bn_script.py target.bin > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-hexrays-microcode", flag: "nto{m1cr0c0d3_c0nst_f0ld1ng}", hints: 4,
    solution: ["python3 mc_dump.py target.bin > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-ghidra-pcode-emulator", flag: "nto{pcode_3mul4t10n_d30bfusc4t10n}", hints: 4,
    solution: ["python3 emulate_pcode.py target.bin > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-anti-disassembly", flag: "nto{0v3rl4pp1ng_byt3s_d1s4sm}", hints: 4,
    solution: ["python3 fix_disasm.py blob.bin > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-string-obfuscation", flag: "nto{x0r_str1ngs_d3crypt3d}", hints: 4,
    solution: ["python3 decstrings.py strings.bin > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-fuzzing-libfuzzer-honggfuzz", flag: "nto{l1bfuzz3r_4s4n_4rt1f4ct}", hints: 4,
    solution: ["python3 read_artifact.py crash-xxxx > out.txt", "grep nto out.txt > found.txt"],
  },
  {
    id: "reversing-kernel-fuzzing", flag: "nto{kcov_kasan_slab_uaf}", hints: 4,
    solution: ["python3 parse_syz.py crash.log > out.txt", "grep nto out.txt > found.txt"],
  },
]

describe.each(LABS)('reversing b14 lab: $id', ({ id, flag, hints, solution }) => {
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
