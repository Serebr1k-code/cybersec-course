import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the forensics malware-analysis gap batch (FB-6).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'mal-static', flag: 'nto{st4t1c_str1ngs_4n4lys1s}', hints: 4,
    solution: ['strings invoice.exe | grep nto > found.txt'] },
  { id: 'mal-unpacking', flag: 'nto{upx_unp4ck3d_st4g3}', hints: 4,
    solution: ['strings unpacked.bin | grep nto > found.txt'] },
  { id: 'mal-config-extraction', flag: 'nto{c2_c0nf1g_3xtr4ct3d}', hints: 4,
    solution: ['grep nto beacon.cfg > found.txt'] },
  { id: 'mal-dotnet', flag: 'nto{d0tn3t_d3c0mp1l3d}', hints: 4,
    solution: ['strings update.exe | grep nto > found.txt'] },
]

describe.each(LABS)('forensics malware lab: $id', ({ id, flag, hints, solution }) => {
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
