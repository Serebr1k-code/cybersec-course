import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the CLOUD AI/ML lab batch (B15):
// cloud-llm-prompt-injection, cloud-ai-model-theft, cloud-ai-supply-chain,
// cloud-rag-security, cloud-ai-agent-abuse.
const dir = path.resolve(process.cwd(), '../content/labs')

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: 'cloud-llm-prompt-injection',
    wd: '/home/student/llm',
    flag: 'nto{1nd1r3ct_pr0mpt_1nj3ct10n}',
    check: "grep -q 'nto{' found.txt",
    solution: [`grep nto notes.md > found.txt`],
  },
  {
    id: 'cloud-ai-model-theft',
    wd: '/home/student/model',
    flag: 'nto{m0d3l_w31ghts_1n_publ1c_buck3t}',
    check: "grep -q 'nto{' found.txt",
    solution: [`grep nto notes.md > found.txt`],
  },
  {
    id: 'cloud-ai-supply-chain',
    wd: '/home/student/aisc',
    flag: 'nto{p1ckl3_m0d3l_rce_0n_l04d}',
    check: "grep -q 'nto{' found.txt",
    solution: [`grep nto notes.md > found.txt`],
  },
  {
    id: 'cloud-rag-security',
    wd: '/home/student/rag',
    flag: 'nto{r4g_publ1c_s34rch_l34k}',
    check: "grep -q 'nto{' found.txt",
    solution: [`grep nto notes.md > found.txt`],
  },
  {
    id: 'cloud-ai-agent-abuse',
    wd: '/home/student/agent',
    flag: 'nto{4g3nt_full_4ut0n0my_p4ssr0l3}',
    check: "grep -q 'nto{' found.txt",
    solution: [`grep nto notes.md > found.txt`],
  },
]

describe.each(LABS)('cloud AI lab B15: $id', ({ id, wd, flag, check, solution }) => {
  const bundle = load(id)
  const spec = { kind: 'shell', workdir: wd, check, hints: ['h', 'h'] }

  it('bundle + seed files are consistent with the lesson lab block', () => {
    expect(bundle.id).toBe(id)
    expect(bundle.workdir).toBe(wd)
    expect(bundle.fs.some((f) => f.path === `${wd}/task.md`)).toBe(true)
    expect(bundle.expect.file).toBe(`${wd}/found.txt`)
    expect(bundle.expect.contains).toBe(flag)
  })

  it('replays the intended solution and passes check', async () => {
    const s = createSession({ spec, bundle })
    expect((await s.run('check')).code).toBe(1)
    for (const cmd of solution) await s.run(cmd)
    expect((await s.run('check')).code).toBe(0)
  })

  it('check fails on an empty/negative solution', async () => {
    const s = createSession({ spec, bundle })
    await s.run(`echo nope > found.txt`)
    expect((await s.run('check')).code).toBe(1)
  })
})
