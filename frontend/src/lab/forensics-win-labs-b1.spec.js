import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the forensics Windows-artifact gap batch (FB-1).
// Loads the REAL fixture bundles from content/labs, replays the intended
// solution with the emulated tools, and asserts `check` passes.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'win-dpapi', flag: 'nto{dp4p1_m4st3rk3y_ch41n}', hints: 4,
    solution: ['base64 -d secret.b64 | grep nto > found.txt'] },
  { id: 'win-ntds', flag: 'nto{ntds_d1t_p3k_unl0ck3d}', hints: 4,
    solution: ['strings ntds.dit | grep nto > found.txt'] },
  { id: 'win-rdp-artifacts', flag: 'nto{rdp_b1tm4p_c4ch3_r3c0v3ry}', hints: 4,
    solution: ['strings Cache0000.bin | grep nto > found.txt'] },
  { id: 'win-lsa-secrets', flag: 'nto{ls4_s3cr3ts_svc_p4ss}', hints: 4,
    solution: ['strings SECURITY | grep nto > found.txt'] },
]

describe.each(LABS)('forensics windows lab: $id', ({ id, flag, hints, solution }) => {
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
    expect((await s.run('check')).code).toBe(1) // not solved yet
    for (const cmd of solution) await s.run(cmd)
    expect((await s.run('check')).code).toBe(0)
  })
})
