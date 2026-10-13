import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

const ROOT = path.resolve(process.cwd(), '../content/labs')
const load = (id) => JSON.parse(fs.readFileSync(path.join(ROOT, id + '.json'), 'utf8'))

const LABS = {
  'reversing-game-anticheat': { flag: 'nto{4nt1_ch34t_1nt3gr1ty_gu4rd}', steps: ['strings ac | grep bnRv | base64 -d > found.txt'] },
  'reversing-game-anticheat-advanced': { flag: 'nto{hyp3rv1s0r_d3t3ct10n_byp4ss}', steps: ['strings acdrv.sys | grep nto > found.txt'] },
  'reversing-drm': { flag: 'nto{k3yg3n_crc32_x0r_dr34m}', steps: ['python3 keygen.py', 'liccheck F92302A8 | grep nto > found.txt'] },
  'reversing-commercial-protectors': { flag: 'nto{vmp0_s3ct10ns_4r3_4_g1v34w4y}', steps: ['readelf -S vmp_like | grep vmp', 'strings vmp_like | grep nto > found.txt'] },
  'reversing-jit-analysis': { flag: 'nto{j1t_c0d3_1n_rwx_m3m0ry}', steps: ['gdb -batch -ex "x/40i 0x7ffff7ff1000" jit_dump.bin | grep nto > found.txt'] },
  'reversing-windows-debuggers': { flag: 'nto{w1ndbg_4n4lyz3_cr4sh_dump}', steps: ['strings target.exe | grep nto > found.txt'] },
  'reversing-rust-go': { flag: 'nto{g0_st4t1c_4nd_sym6ols}', steps: ['strings gobin.rodata | grep nto > found.txt'] },
  'reversing-go-advanced': { flag: 'nto{pclnt4b_r3c0v3rs_sym6ols}', steps: ['strings gobin2.rodata | grep bnRv | base64 -d > found.txt'] },
  'reversing-rust-advanced': { flag: 'nto{rust_d3m4ngl1ng_4nd_p4n1c}', steps: ['strings rustbin.rodata | grep nto > found.txt'] },
  'reversing-managed-dotnet-java': { flag: 'nto{j4v4_byt3c0d3_r3v3rs3d}', steps: ['javap -c -p License | grep nto > found.txt'] },
  'reversing-mod-emerging': { flag: 'nto{3m3rg1ng_m4lw4r3_c0nf1g_3xf1l}', steps: ['strings dropper.bin | grep bnRv | base64 -d > found.txt'] },
  'reversing-mod-managed': { flag: 'nto{pyth0n_byt3c0d3_c0nst4nts}', steps: ['strings secret.pyc | grep nto > found.txt'] },
  'reversing-module-symbolic': { flag: 'nto{symb0l1c_3mul4t10n_d1sp4tch3r}', steps: ['python3 solve.py', 'crackme s3cr3t | grep nto > found.txt'] },
  'reversing-firmware': { flag: 'nto{u_b00t_squ4shfs_s3cr3t}', steps: ['binwalk firmware.bin', 'dd if=firmware.bin of=root.sqfs bs=1 skip=65', 'strings root.sqfs | grep nto > found.txt'] },
  'reversing-firmware-emulation': { flag: 'nto{f1rmw4r3_3mul4t3d_unic0rn}', steps: ['python3 emu.py | grep nto > found.txt'] },
}

describe('reversing batch3 end-to-end', () => {
  for (const [id, spec] of Object.entries(LABS)) {
    it(`${id} solves`, async () => {
      const bundle = load(id)
      const lab = { kind: 'shell', workdir: bundle.workdir, files: [], check: `grep -q '${spec.flag}' found.txt`, hints: ['a','b','c'] }
      const s = createSession({ spec: lab, bundle })
      const neg = await s.run('check')
      expect(neg.stdout, `${id}: negative check`).not.toContain('✓')
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
