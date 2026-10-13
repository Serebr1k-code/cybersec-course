import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

const ROOT = path.resolve(process.cwd(), '../content/labs')
const load = (id) => JSON.parse(fs.readFileSync(path.join(ROOT, id + '.json'), 'utf8'))

const LABS = {
  'reversing-static-tools': {
    flag: 'nto{str1ngs_1s_th3_f1rst_st3p}',
    steps: ['strings sample | grep nto > found.txt'],
  },
  'reversing-static-targets': {
    flag: 'nto{str1pp3d_b1n4ry_n0_sym6ols}',
    steps: ['strings target | grep nto > found.txt'],
  },
  'reversing-architectures': {
    flag: 'nto{4arch64_n0t_x86}',
    steps: ['python3 disasm.py blob.bin', 'python3 xor.py enc.hex 0x42 > found.txt'],
  },
  'reversing-mod-file-formats': {
    flag: 'nto{3lf_s3ct10n_h3ad3rs}',
    steps: ['readelf -p .flagdata hello | grep nto > found.txt'],
  },
  'reversing-mod-linking': {
    flag: 'nto{dyn4m1c_l1nk3r_n33ds_l1bc}',
    steps: ['readelf -d dyn', 'strings dyn | grep nto > found.txt'],
  },
  'reversing-elf-instrumentation': {
    flag: 'nto{1nstrum3nt4t10n_and_p4tch}',
    steps: ['strings crackme6', 'crackme6 0p3n_s3s4m3 > found.txt'],
  },
  'reversing-obfuscation': {
    flag: 'nto{0bfusc4t3d_c0ntr0l_fl0w}',
    steps: ['obf st4t3_m4ch1n3_0k > found.txt'],
  },
  'reversing-obfuscation-mba': {
    flag: 'nto{mba_s1mpl1f13d_by_z3}',
    steps: ['python3 mba.py > found.txt'],
  },
  'reversing-self-modifying': {
    flag: 'nto{s3lf_m0d1fy1ng_c0d3_d3crypt3d}',
    steps: ['gdb -batch -ex "b unlock" -ex run -ex finish -ex "x/s &flagbuf" smc > found.txt'],
  },
  'reversing-packing-upx': {
    flag: 'nto{upx_l1k3_stub_str1pp3d}',
    steps: ['dd if=packed.bin of=unpacked bs=1 skip=16', 'file unpacked', 'strings unpacked | grep nto > found.txt'],
  },
  'reversing-packers-custom': {
    flag: 'nto{cust0m_x0r_p4ck3r_0x5a}',
    steps: ['python3 xor.py crypt.hex 0x5a > found.txt'],
  },
  'reversing-malware-static': {
    flag: 'nto{c2_p4n3l_mut3x_3xf1l}',
    steps: ['strings malware | grep nto > found.txt'],
  },
  'reversing-time-travel': {
    flag: 'nto{t1m3_tr4v3l_r3v3rs3_d3bug}',
    steps: ['gdb -batch -ex "b build" -ex run -ex finish -ex "x/s &ttbuf" tt > found.txt'],
  },
  'reversing-unicorn-emulation': {
    flag: 'nto{un1c0rn_cpu_3mul4t10n}',
    steps: ['python3 emu.py > found.txt'],
  },
  'reversing-symbolic-core': {
    flag: 'nto{z3_symb0l1c_s0lv3r_c0r3}',
    steps: ['python3 solve.py', 'crackme15 cQNW] > found.txt'],
  },
  'reversing-symbolic-tools': {
    flag: 'nto{z3_symb0l1c_t00lch41n}',
    steps: ['python3 sym.py', 'crackme16 cQNW] > found.txt'],
  },
  'reversing-wasm': {
    flag: 'nto{w4sm_d4t4_s3ct10n_p4rs3d}',
    steps: ['xxd -l 16 mod.wasm', 'python3 wasm.py mod.wasm > found.txt'],
  },
  'reversing-taint-analysis': {
    flag: 'nto{t41nt_tr4ck1ng_t0_th3_s1nk}',
    steps: ['python3 taint.py trace.txt > found.txt'],
  },
  'reversing-devirtualization': {
    flag: 'nto{d3v1rtu4l1z3d_vm_byt3c0d3}',
    steps: ['python3 vm.py prog.vmbc > found.txt'],
  },
  'reversing-firmware-basics': {
    flag: 'nto{f1rmw4r3_squ4shfs_c4rv3d}',
    steps: ['binwalk firmware.bin', 'dd if=firmware.bin of=root.sqfs bs=1 skip=24', 'strings root.sqfs | grep nto > found.txt'],
  },
}

describe('reversing labs end-to-end', () => {
  for (const [id, spec] of Object.entries(LABS)) {
    it(`${id} solves`, async () => {
      const bundle = load(id)
      const lab = {
        kind: 'shell', workdir: bundle.workdir, files: [],
        check: `grep -q '${spec.flag}' found.txt`, hints: ['a', 'b', 'c'],
      }
      const s = createSession({ spec: lab, bundle })
      for (const step of spec.steps) {
        const r = await s.run(step)
        expect(r.stderr, `${id}: ${step} -> ${r.stderr}`).not.toContain('command not found')
        expect(r.stderr, `${id}: ${step} -> ${r.stderr}`).not.toContain('нет в этой лабе')
      }
      const c = await s.run('check')
      expect(c.stdout, `${id}: check=${c.stdout}`).toContain('✓')
      expect(c.stdout).not.toContain('✗')
    })
  }
})
