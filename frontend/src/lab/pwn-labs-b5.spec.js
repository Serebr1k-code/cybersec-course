import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

const ROOT = path.resolve(process.cwd(), '../content/labs')
const load = (id) => JSON.parse(fs.readFileSync(path.join(ROOT, id + '.json'), 'utf8'))

// id -> { steps: tool commands that must replay, answer: exact hidden value }
const LABS = {
  'pwn-buffer-overflow-core': { steps: ['cat out.txt', 'objdump -d fmt'], answer: 'offset=6' },
  'pwn-heap-corruption': { steps: ['cat corrupt.gdb.txt'], answer: 'top=0x4141414141414141' },
  'pwn-heap-primitives': { steps: ['cat consol.gdb.txt'], answer: 'merged=0x861' },
  'pwn-mitigations-bypass': {
    steps: ['readelf -d a', 'readelf -d b', 'readelf --file-header c', 'readelf -s a'],
    answer: 'fullrelro=a',
  },
  'pwn-race-conditions': { steps: ['cat toctou.c'], answer: 'pattern=access-open' },
  'pwn-signal-handlers': { steps: ['xxd frame.bin', 'cat frame.hex.txt'], answer: 'rip_off=0xa8' },
  'pwn-rop-techniques': {
    steps: ['objdump -d rop', 'nm rop', 'cat rop.ropgadget.txt'],
    answer: 'pop_rdi=0x401111',
  },
  'pwn-rop-exotic': { steps: ['xxd vdso.bin', 'cat vdso.hex.txt'], answer: 'off=0x111b' },
  'pwn-methodology-analysis': { steps: ['cat asan.log', 'cat crash.c'], answer: 'bug=heap-buffer-overflow' },
  'pwn-methodology-env': { steps: ['readelf --file-header arm.o', 'readelf -s arm.o'], answer: 'arrch64' },
  'pwn-methodology-realworld': { steps: ['cat vuln.c', 'cat fixed.c'], answer: 'fix=size_t' },
  'pwn-modern-houses': { steps: ['cat largebin.gdb.txt', 'cat largebin.c'], answer: 'bk_nextsize=0x405000' },
  'pwn-emulation': { steps: ['xxd blob.bin', 'cat emu.log'], answer: 'eax=0x48' },
  'pwn-heap-bin-attacks': { steps: ['cat spirit.gdb.txt', 'cat spirit.c'], answer: 'fake=0x404050' },
  'pwn-heap-house': { steps: ['cat force.gdb.txt', 'cat force.c'], answer: 'top=0xffffffffffffffff' },
}

describe('pwn labs batch 5 end-to-end', () => {
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
      // a wrong answer must NOT satisfy check
      await s.run('echo wrong > answer.txt')
      const bad = await s.run('check')
      expect(bad.stdout).not.toContain('✓')
      // the real answer does
      await s.run(`echo ${spec.answer} > answer.txt`)
      const c = await s.run('check')
      expect(c.stdout, `${id}: check=${c.stdout}`).toContain('✓')
      expect(c.stdout).not.toContain('✗')
    })
  }
})
