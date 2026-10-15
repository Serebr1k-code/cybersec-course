import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

function loadBundle(id) {
  const p = path.resolve(process.cwd(), `../content/labs/${id}.json`)
  return JSON.parse(fs.readFileSync(p, 'utf8'))
}
function session(spec, bundle) { return createSession({ spec, bundle }) }

function specFor(artifact, check = "grep -q 'nto{' found.txt") {
  return {
    kind: 'shell',
    workdir: '/home/student/task',
    files: ['task.md', artifact],
    check,
    hints: ['a', 'b', 'c'],
  }
}

// Each case: bundle id, the seeded artifact, the flag, and the exact solution
// command a student would type (only core lab commands).
const CASES = [
  {
    id: 'misc-kernel-module',
    artifact: 'modinfo.txt',
    flag: 'nto{k3rn3l_m0dul3_1ntr0}',
    solve: "grep description modinfo.txt | cut -d: -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-namespace-deep',
    artifact: 'ns_report.txt',
    flag: 'nto{ns3nt3r_p1v0t_3sc4p3}',
    solve: "grep flag ns_report.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-seccomp-bpf-deep',
    artifact: 'seccomp_report.txt',
    flag: 'nto{s3cc0mp_bpf_f1lt3r}',
    solve: "grep flag seccomp_report.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-heap-misc',
    artifact: 'heap_dump.txt',
    flag: 'nto{glibc_tc4ch3_f4stb1n}',
    solve: "grep flag heap_dump.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-llm-tokenizer',
    artifact: 'tokens.txt',
    flag: 'nto{t0k3n_smuggl1ng_bp3}',
    solve: "grep flag tokens.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-llm-tool-abuse',
    artifact: 'agent_trace.txt',
    flag: 'nto{t00l_c4ll_4bus3}',
    solve: "grep flag agent_trace.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-prompt-leak',
    artifact: 'chat.txt',
    flag: 'nto{syst3m_pr0mpt_l34k}',
    solve: "grep flag chat.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-antlr-parser',
    artifact: 'parse_tree.txt',
    flag: 'nto{4ntlr_gr4mm4r_4mb1gu1ty}',
    solve: "grep flag parse_tree.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-lexer-tricks',
    artifact: 'lexer_diff.txt',
    flag: 'nto{l3x3r_p4rs3r_d1ff}',
    solve: "grep flag lexer_diff.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-llvm-ir',
    artifact: 'module.ll',
    flag: 'nto{llvm_1r_p4ss_0pt}',
    solve: "grep flag module.ll | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-radare2',
    artifact: 'r2_session.txt',
    flag: 'nto{r2_4n4lys1s_p4th}',
    solve: "grep flag r2_session.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-cyberchef',
    artifact: 'blob.txt',
    flag: 'nto{cyb3rch3f_r3c1p3}',
    solve: "base64 -d blob.txt > found.txt",
  },
  {
    id: 'misc-kata-containers',
    artifact: 'kata_config.txt',
    flag: 'nto{k4t4_4g3nt_3sc4p3}',
    solve: "grep flag kata_config.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-crun-podman',
    artifact: 'podman_inspect.txt',
    flag: 'nto{crun_r00tl3ss_3sc4p3}',
    solve: "grep flag podman_inspect.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-barcode-formats',
    artifact: 'barcode.txt',
    flag: 'nto{c0d3_128_b4rc0d3}',
    solve: "grep flag barcode.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-esolang-whitespace-deep',
    artifact: 'ws_hex.txt',
    flag: 'nto{wh1t3sp4c3_d33p}',
    solve: "grep flag ws_hex.txt | cut -d= -f2 | base64 -d > found.txt",
  },
]

for (const c of CASES) {
  describe(`${c.id} lab`, () => {
    const bundle = loadBundle(c.id)
    const spec = specFor(c.artifact)

    it('seeds the artifact and task', async () => {
      const s = session(spec, bundle)
      const r = await s.run(`cat ${c.artifact}`)
      expect(r.stdout.length).toBeGreaterThan(0)
    })

    it('is not solved before writing found.txt', async () => {
      const s = session(spec, bundle)
      expect((await s.run('check')).code).toBe(1)
    })

    it('solves with the documented pipeline', async () => {
      const s = session(spec, bundle)
      await s.run(c.solve)
      expect((await s.run('check')).code).toBe(0)
      expect(s.solved).toBe(true)
      expect((await s.run('cat found.txt')).stdout.trim()).toBe(c.flag)
    })
  })
}
