import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

const ROOT = path.resolve(process.cwd(), '../content/labs')
const load = (id) => JSON.parse(fs.readFileSync(path.join(ROOT, id + '.json'), 'utf8'))

// Kernel hub/module pages: orientation labs backed by real kernel fixtures.
const LABS = {
  'pwn-kernel-core': { steps: ['grep SMEP cr4_bits.txt', 'cat cr4_bits.txt'], answer: 'nto{cr4_smep_bit=20}' },
  'pwn-kernel-modern': { steps: ['grep init_cred system.map'], answer: 'nto{init_cred=0xffffffff838140c0}' },
  'pwn-kernel-subsystems': { steps: ['grep bpf unistd_64.h'], answer: 'nto{bpf=321}' },
}

describe('pwn kernel hub labs end-to-end', () => {
  for (const [id, spec] of Object.entries(LABS)) {
    it(`${id} solves`, async () => {
      const bundle = load(id)
      expect(bundle.expect.contains).toBe(spec.answer)
      const lab = {
        kind: 'shell', workdir: bundle.workdir, files: [],
        check: `grep -q '${spec.answer}' answer.txt`, hints: ['a', 'b', 'c'],
      }
      const s = createSession({ spec: lab, bundle })
      for (const step of spec.steps) {
        const r = await s.run(step)
        expect(r.stderr, `${id}: ${step} -> ${r.stderr}`).not.toContain('command not found')
        expect(r.stderr, `${id}: ${step} -> ${r.stderr}`).not.toContain('нет в этой лабе')
      }
      await s.run('echo wrong > answer.txt')
      const bad = await s.run('check')
      expect(bad.stdout).not.toContain('✓')
      await s.run(`echo ${spec.answer} > answer.txt`)
      const c = await s.run('check')
      expect(c.stdout, `${id}: check=${c.stdout}`).toContain('✓')
      expect(c.stdout).not.toContain('✗')
    })
  }
})
