import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for lab batch osint-b10.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: "osint-intro", flag: "nto{wh01s_dns_crt_sh_p4ss1v3_r3c0n}", hints: 4,
    solution: ["dig +short example.com TXT > found.txt"],
  },
  {
    id: "osint-people-search", flag: "nto{gr4v4t4r_md5_p1v0t_t0_1d3nt1ty}", hints: 4,
    solution: ["curl -s \"https://api.github.com/search/users?q=katie+konans\" > found.txt"],
  },
  {
    id: "osint-social-linkedin", flag: "nto{l1nk3d1n_0rg_m4p_3m41l_p4tt3rn}", hints: 4,
    solution: ["curl -s -A \"Mozilla/5.0\" \"https://www.linkedin.com/in/devops-nasa/\" > found.txt"],
  },
]

describe.each(LABS)('lab batch osint-b10: $id', ({ id, flag, hints, solution }) => {
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
