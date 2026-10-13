import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

const ROOT = path.resolve(process.cwd(), '../content/labs')
const load = (id) => JSON.parse(fs.readFileSync(path.join(ROOT, id + '.json'), 'utf8'))

// id -> { steps: commands that must replay, answer: exact hidden value }
const LABS = {
  'pwn-fastbin-dup': { steps: ['grep fastbin fastbin.gdb.txt', 'xxd fastbin.bin'], answer: 'dup=0x404060' },
  'pwn-heap-tcache': { steps: ['grep fd tcache.gdb.txt', 'xxd tcache.bin'], answer: 'next=0x404100' },
  'pwn-tcache-stashing': { steps: ['grep count stashing.gdb.txt'], answer: 'stashed=2' },
  'pwn-unsafe-unlink': { steps: ['grep unlink unlink.gdb.txt', 'xxd chunks.bin'], answer: 'write=0x4040b8' },
  'pwn-heap-qemu-debug': { steps: ['grep top heap.gdb.txt'], answer: 'top=0x405100' },
  'pwn-fs-advanced': { steps: ['cat run.txt', 'objdump -d fmt', 'readelf -r fmt'], answer: 'offset=6' },
  'pwn-stack-clash': { steps: ['objdump -d clash'], answer: 'size=0x100008' },
  'pwn-async-signal-race': { steps: ['nm sig', 'objdump -d sig'], answer: 'bad=printf' },
  'pwn-ctf-recipe': { steps: ['objdump -d vuln', 'nm vuln'], answer: 'offset=72' },
  'pwn-methodology': { steps: ['readelf -s meth', 'readelf --file-header meth', 'nm meth'], answer: 'canary=yes' },
  'pwn-nday': { steps: ['cat vuln.c', 'cat fixed.c'], answer: 'size=64' },
  'pwn-dirtycred': { steps: ['xxd cred.bin'], answer: 'euid_off=0x14' },
  'pwn-emulation-hooks': { steps: ['cat hooks.log', 'xxd blob.bin'], answer: 'insns=4' },
  'pwn-unicorn-emulation': { steps: ['cat emu.log', 'xxd blob.bin'], answer: 'eax=0x26' },
  'pwn-io-str-overflow': { steps: ['cat libc.syms'], answer: 'str_overflow=0x92110' },
}

describe('pwn labs batch 4 end-to-end', () => {
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
