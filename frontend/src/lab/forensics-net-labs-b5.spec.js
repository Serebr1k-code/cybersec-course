import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the forensics network-forensics gap batch (FB-5).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'net-kerberos', flag: 'nto{g0ld3n_t1ck3t_t1ll_2036}', hints: 4,
    solution: ['grep nto kerberos.txt > found.txt'] },
  { id: 'net-dns', flag: 'nto{dns_tunn3l_3xf1ltr4t10n}', hints: 4,
    solution: ['grep nto dns_log.txt > found.txt'] },
  { id: 'net-c2-reversing', flag: 'nto{c2_pr0t0c0l_r3v3rs3d}', hints: 4,
    solution: ['base64 -d c2_payload.b64 | grep nto > found.txt'] },
  { id: 'net-tcp-reassembly', flag: 'nto{tcp_r34ss3mbly_obj3ct}', hints: 4,
    solution: ['strings stream7.raw | grep nto > found.txt'] },
]

describe.each(LABS)('forensics network lab: $id', ({ id, flag, hints, solution }) => {
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
