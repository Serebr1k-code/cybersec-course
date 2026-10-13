import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'

// Each lab: the exact front-matter check predicate + a solution path that must
// solve it, plus a replay-tool invocation that must not error.
const LABS = [
  { id: 'pwn-kernel-intro', check: "grep -q 'ioctl=0x1337' answer.txt",
    probe: ['file vuln.ko', 'readelf -sW vuln.ko', 'objdump -d vuln.ko'],
    solution: ['grep 1337 vuln.objdump.txt', 'echo ioctl=0x1337 > answer.txt'] },
  { id: 'pwn-kernel-heap', check: "grep -q 'seq_ops_cache=kmalloc-32' answer.txt",
    probe: ['cat slab-list.txt'],
    solution: ['echo seq_ops_cache=kmalloc-32 > answer.txt'] },
  { id: 'pwn-kernel-smep-smap', check: "grep -q 'cr4_clean=0x70ef0' answer.txt",
    probe: ['grep smep cpuinfo.txt', 'cat cr4.txt'],
    solution: ['echo cr4_clean=0x70ef0 > answer.txt'] },
  { id: 'pwn-kernel-rop', check: "grep -q 'pop_rdi=0x401036' answer.txt",
    probe: ['ROPgadget --binary ./vmlinux --only "pop|ret"', 'cat vmlinux.ropgadget.txt'],
    solution: ['echo pop_rdi=0x401036 > answer.txt'] },
  { id: 'pwn-kernel-pipe-buffer', check: "grep -q 'victim_cache=kmalloc-1k' answer.txt",
    probe: ['cat slab-list.txt', 'cat pipe-max-size.txt'],
    solution: ['echo victim_cache=kmalloc-1k > answer.txt'] },
  { id: 'pwn-kernel-ebpf', check: "grep -q 'unprivileged_bpf=2' answer.txt",
    probe: ['readelf --file-header bpfprog.o', 'cat unprivileged_bpf_disabled.txt'],
    solution: ['echo unprivileged_bpf=2 > answer.txt'] },
  { id: 'pwn-kernel-userfaultfd', check: "grep -q 'unprivileged_userfaultfd=0' answer.txt",
    probe: ['cat unprivileged_userfaultfd.txt'],
    solution: ['echo unprivileged_userfaultfd=0 > answer.txt'] },
  { id: 'pwn-kernel-nftables', check: "grep -q 'userns_clone=1' answer.txt",
    probe: ['cat unprivileged_userns_clone.txt'],
    solution: ['echo userns_clone=1 > answer.txt'] },
  { id: 'pwn-kernel-io_uring', check: "grep -q 'io_uring_disabled=2' answer.txt",
    probe: ['cat io_uring_disabled.txt'],
    solution: ['echo io_uring_disabled=2 > answer.txt'] },
  { id: 'pwn-kernel-cross-cache', check: "grep -q 'cred_cache=cred' answer.txt",
    probe: ['cat slab-list.txt'],
    solution: ['echo cred_cache=cred > answer.txt'] },
]

describe('pwn kernel labs (KB) solve end-to-end', () => {
  for (const { id, check, probe, solution } of LABS) {
    it(id, async () => {
      const bundle = JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
      const spec = { kind: 'shell', workdir: WD, check, hints: ['a', 'b', 'c'] }
      const s = createSession({ spec, bundle })
      expect((await s.run('check')).stdout).toContain('не сходится')
      for (const cmd of probe) {
        const r = await s.run(cmd)
        expect(r.stderr, `${id} probe: ${cmd}`).not.toMatch(/command not found|нет в этой лабе/)
      }
      for (const cmd of solution) {
        const r = await s.run(cmd)
        expect(r.stderr, `${id}: ${cmd}`).not.toMatch(/command not found|нет в этой лабе/)
      }
      expect((await s.run('check')).stdout, `${id} check`).toContain('Готово')
      expect(s.solved).toBe(true)
    })
  }
})
