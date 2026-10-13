import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

const ROOT = path.resolve(process.cwd(), '../content/labs')
const load = (id) => JSON.parse(fs.readFileSync(path.join(ROOT, id + '.json'), 'utf8'))

const LABS = {
  'reversing-jvm-bytecode-deep': { flag: 'nto{jvm_byt3c0d3_0p3nc0d3}', steps: ['strings Hello.class | grep nto > found.txt'] },
  'reversing-java-advanced': { flag: 'nto{0bfusc4t3d_n4m3s_n0t_s3cur3}', steps: ['javap -c -p Obf | grep nto > found.txt'] },
  'reversing-aot-native': { flag: 'nto{aot_n4t1v3_managed_sym6ols}', steps: ['file Check.exe.so', 'nm Check.exe.so | grep Check', 'readelf --file-header Check.exe.so', 'strings Check.exe.so | grep nto > found.txt'] },
  'reversing-android-native': { flag: 'nto{jni_n4m3_m4pp1ng_arm64}', steps: ['readelf --file-header libnative.so', 'nm -D libnative.so | grep Java', 'strings libnative.so | grep nto > found.txt'] },
}

describe('reversing batch B11 end-to-end', () => {
  for (const [id, spec] of Object.entries(LABS)) {
    it(`${id} solves`, async () => {
      const bundle = load(id)
      const lab = { kind: 'shell', workdir: bundle.workdir, files: [], check: `grep -q '${spec.flag}' found.txt`, hints: ['a', 'b', 'c'] }
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
