import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

const ROOT = path.resolve(process.cwd(), '../content/labs')
const load = (id) => JSON.parse(fs.readFileSync(path.join(ROOT, id + '.json'), 'utf8'))

// id -> { steps: tool commands that must replay, answer: exact hidden value }
const LABS = {
  'pwn-rop': {
    steps: ['file vuln', 'nm vuln', 'objdump -d vuln'],
    answer: 'win=0x401030',
  },
  'pwn-shellcode-advanced': {
    steps: ['file egg', 'objdump -d egg'],
    answer: 'probe=0x21',
  },
  'pwn-signal-frame-forgery': {
    steps: ['grep rsp setcontext.txt'],
    answer: 'gadget=0x4408d',
  },
  'pwn-fsop': {
    steps: ['nm -D libc.syms'],
    answer: 'stdout=0x1e8580',
  },
  'pwn-vtable-check-bypass': {
    steps: ['nm -D libc.syms', 'readelf -SW libc.sections'],
    answer: 'file_jumps=0x1e6030',
  },
  'pwn-cet-cfi': {
    steps: ['objdump -d cet', 'readelf -n cet'],
    answer: 'f3 0f 1e fa',
  },
  'pwn-cpp-exploitation': {
    steps: ['nm -C vt', 'objdump -d vt'],
    answer: 'vtable=0x403fe8',
  },
  'pwn-toctou': {
    steps: ['objdump -d toctou'],
    answer: 'check=0x15',
  },
  'pwn-thread-races': {
    steps: ['nm race', 'objdump -d race'],
    answer: 'shared=0x403000',
  },
  'pwn-race-widening': {
    steps: ['objdump -d widen'],
    answer: 'sleep=0x23',
  },
  'pwn-dirty-pipe': {
    steps: ['xxd pipe_buffer.bin', 'cat exploit.c'],
    answer: 'flags_off=0x18',
  },
  'pwn-sandbox-escape': {
    steps: ['xxd filter.bpf', 'python3 seccomp.py filter.bpf'],
    answer: 'allowed=0,1,2,60',
  },
  'pwn-rust-go-exploit': {
    steps: ['nm go.syms', 'cat go.buildinfo'],
    answer: 'main_main=0x489420',
  },
  'pwn-calloc': {
    steps: ['nm -D libc.syms'],
    answer: 'calloc=0xa7d70',
  },
  'pwn-mmap-exploitation': {
    steps: ['objdump -d mmapchunk', 'xxd chunk.bin'],
    answer: 'mmap=0x9',
  },
}

describe('pwn labs batch 3 end-to-end', () => {
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
