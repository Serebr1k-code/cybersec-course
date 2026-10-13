import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'

const LABS = [
  { id: 'pwn-heap-fengshui', check: "grep -q 'leak=0x7ffff7f7ceb8' answer.txt",
    solution: ['gdb fengshui', 'echo leak=0x7ffff7f7ceb8 > answer.txt'] },
  { id: 'pwn-seccomp-srop', check: "grep -q 'blocked_syscall=execve' answer.txt",
    solution: ['objdump -s -j .data chall', 'echo blocked_syscall=execve > answer.txt'] },
  { id: 'pwn-exit-handlers', check: "grep -q 'first_handler=bye2' answer.txt",
    solution: ['cat exith.out', 'echo first_handler=bye2 > answer.txt'] },
  { id: 'pwn-io-leak', check: "grep -q 'leak=0x7ffff7f7ceb8' answer.txt",
    solution: ['cat leak.gdb.txt', 'echo leak=0x7ffff7f7ceb8 > answer.txt'] },
  { id: 'pwn-io-wfile', check: "grep -q 'wfile_jumps=0x1e6228' answer.txt",
    solution: ['readelf -sW libc.so.6', 'echo wfile_jumps=0x1e6228 > answer.txt'] },
  { id: 'pwn-asan-ubsan', check: "grep -q 'asan=heap-buffer-overflow' answer.txt",
    solution: ['cat asan.out', 'echo asan=heap-buffer-overflow > answer.txt'] },
  { id: 'pwn-house-modern', check: "grep -q 'technique=House_of_Apple_2' answer.txt",
    solution: ['cat house.gdb.txt', 'echo technique=House_of_Apple_2 > answer.txt'] },
  { id: 'pwn-arm64-basics', check: "grep -q 'machine=AArch64' answer.txt",
    solution: ['readelf --file-header arm64.elf', 'echo machine=AArch64 > answer.txt'] },
  { id: 'pwn-arm64-heap', check: "grep -q 'ptr_size=8' answer.txt",
    solution: ['readelf --file-header arm64heap.elf', 'echo ptr_size=8 > answer.txt'] },
  { id: 'pwn-mips', check: "grep -q 'endianness=big' answer.txt",
    solution: ['readelf --file-header mips.elf', 'echo endianness=big > answer.txt'] },
  { id: 'pwn-riscv', check: "grep -q 'machine=RISC-V' answer.txt",
    solution: ['readelf --file-header riscv.elf', 'echo machine=RISC-V > answer.txt'] },
  { id: 'pwn-macos', check: "grep -q 'magic=0xfeedfacf' answer.txt",
    solution: ['cat mac.txt', 'echo magic=0xfeedfacf > answer.txt'] },
  { id: 'pwn-windows-intro', check: "grep -q 'format=PE32' answer.txt",
    solution: ['objdump -f winvuln.exe', 'echo format=PE32 > answer.txt'] },
  { id: 'pwn-windows-heap', check: "grep -q 'alloc_api=malloc' answer.txt",
    solution: ['objdump -p winheap.exe', 'echo alloc_api=malloc > answer.txt'] },
  { id: 'pwn-windows-kernel', check: "grep -q 'ioctl=0x222003' answer.txt",
    solution: ['objdump -d hevd.exe', 'echo ioctl=0x222003 > answer.txt'] },
]

describe('pwn lab batch (A+B) solve end-to-end', () => {
  for (const { id, check, solution } of LABS) {
    it(id, async () => {
      const bundle = JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
      const spec = { kind: 'shell', workdir: WD, check, hints: ['a', 'b', 'c'] }
      const s = createSession({ spec, bundle })
      expect((await s.run('check')).stdout).toContain('не сходится')
      for (const cmd of solution) {
        const r = await s.run(cmd)
        expect(r.stderr, `${id}: ${cmd}`).not.toMatch(/command not found|нет в этой лабе/)
      }
      expect((await s.run('check')).stdout, `${id} check`).toContain('Готово')
      expect(s.solved).toBe(true)
    })
  }
})
