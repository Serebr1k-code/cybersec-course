import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the forensics Linux-artifact gap batch (FB-3).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'linux-proc-forensics', flag: 'nto{pr0c_cmdl1n3_nul_byt3s}', hints: 4,
    solution: ['strings cmdline.bin | grep nto > found.txt'] },
  { id: 'linux-ssh-artifacts', flag: 'nto{ssh_p3rs1st3nc3_by_k3y}', hints: 4,
    solution: ['grep nto authorized_keys > found.txt'] },
  { id: 'linux-systemd-persistence', flag: 'nto{systemd_un1t_p3rs1st3nc3}', hints: 4,
    solution: ['strings systemd-networkd-helper | grep nto > found.txt'] },
  { id: 'linux-shell-history', flag: 'nto{b4sh_h1st0ry_t1m3st4mp}', hints: 4,
    solution: ['grep nto .bash_history > found.txt'] },
]

describe.each(LABS)('forensics linux lab: $id', ({ id, flag, hints, solution }) => {
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
