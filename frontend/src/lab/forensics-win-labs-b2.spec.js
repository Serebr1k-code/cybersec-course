import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the forensics Windows persistence/telemetry
// gap batch (FB-2).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'win-powershell-transcript', flag: 'nto{p0w3rsh3ll_tr4nscr1pt_l34k}', hints: 4,
    solution: ['grep nto PowerShell_transcript.txt > found.txt'] },
  { id: 'win-sysmon-tuning', flag: 'nto{sysm0n_ch41n_0f_c4us3}', hints: 4,
    solution: ['strings Sysmon.evtx | grep nto > found.txt'] },
  { id: 'win-ifeo', flag: 'nto{1fe0_s3thc_b4ckd00r}', hints: 4,
    solution: ['strings SOFTWARE | grep nto > found.txt'] },
  { id: 'win-com-hijack', flag: 'nto{c0m_h1j4ck_hkcu_cls1d}', hints: 4,
    solution: ['strings NTUSER.DAT | grep nto > found.txt'] },
]

describe.each(LABS)('forensics windows persistence lab: $id', ({ id, flag, hints, solution }) => {
  const bundle = load(id)
  const spec = { kind: 'shell', workdir: WD, check: CHECK, hints: Array(hints).fill('h') }

  it('bundle + seed files are consistent with the lesson lab block', () => {
    expect(bundle.id).toBe(id)
    expect(bundle.workdir).toBe(WD)
    expect(bundle.fs.some((f) => f.path === `${WD}/task.md`)).toBe(true)
    expect(bundle.expect.file).toBe(`${WD}/found.txt`)
    expect(bundle.expect.contains).toBe(flag)
  })

  it('replays the intended solution and passes check', async () => {
    const s = createSession({ spec, bundle })
    expect((await s.run('check')).code).toBe(1)
    for (const cmd of solution) await s.run(cmd)
    expect((await s.run('check')).code).toBe(0)
  })
})
