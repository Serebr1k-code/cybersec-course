import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

const ROOT = path.resolve(process.cwd(), '../content/labs')
const load = (id) => JSON.parse(fs.readFileSync(path.join(ROOT, id + '.json'), 'utf8'))

const LABS = {
  'pwn-pwntools': { steps: ['python3 solve.py', 'nm vuln'], answer: 'win=0x401167' },
  'pwn-custom-allocator': { steps: ['objdump -d alloc', 'cat run.txt'], answer: 'hdr=0x10' },
  'pwn-house-of-force': { steps: ['cat run.txt', 'cat libc.strings'], answer: 'size=0xffffffffffffffff' },
  'pwn-house-botcake': { steps: ['cat trace.txt'], answer: 'merged=0x221' },
  'pwn-house-einherjar': { steps: ['cat trace.txt'], answer: 'prev_size=0x410' },
  'pwn-house-lore': { steps: ['cat run.txt'], answer: 'bin=0xe' },
  'pwn-house-roman': { steps: ['cat libc.maps.txt', 'cat libc.syms'], answer: 'bits=12' },
  'pwn-house-water': { steps: ['nm -D libc.syms'], answer: 'list_all=0x1e8480' },
  'pwn-house-corrosion': { steps: ['xxd largebin.bin'], answer: 'bk_nextsize=0x28' },
  'pwn-chunk-overlap': { steps: ['objdump -d overlap', 'cat run.txt'], answer: 'size=0xe1' },
  'pwn-malloc-consolidation': { steps: ['objdump -d consol', 'cat run.txt'], answer: 'merged=0x841' },
  'pwn-largebin-attack': { steps: ['objdump -d largebin', 'cat run.txt'], answer: 'threshold=0x400' },
  'pwn-heap-uaf': { steps: ['objdump -d uaf', 'cat run.txt'], answer: 'reuse=yes' },
  'pwn-io-stdout': { steps: ['readelf -sW libc.sym'], answer: 'system=0x53b00' },
  'pwn-ret2vdso': { steps: ['objdump -d vdso.bin', 'cat maps.txt'], answer: 'gadget=0x111b' },
}

describe('pwn labs batch B6 end-to-end', () => {
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
