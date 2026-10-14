import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the CLOUD networking lab batch (B17):
// vpc-peering, privatelink, vpn-hybrid, dns-deep, load-balancer-attacks,
// egress-control.
const dir = path.resolve(process.cwd(), '../content/labs')

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'cloud-vpc-peering', wd: '/home/student/peer', flag: 'nto{vpc_p33r1ng_l4t3r4l_p4th}' },
  { id: 'cloud-privatelink', wd: '/home/student/pl', flag: 'nto{pr1v4t3l1nk_3ndp01nt_br1dg3}' },
  { id: 'cloud-vpn-hybrid', wd: '/home/student/hybrid', flag: 'nto{hybr1d_vpn_t0_0npr3m}' },
  { id: 'cloud-dns-deep', wd: '/home/student/dns', flag: 'nto{d4ngl1ng_cn4m3_t4k30v3r}' },
  { id: 'cloud-load-balancer-attacks', wd: '/home/student/lb', flag: 'nto{lb_xff_byp4ss_t0_4dm1n}' },
  { id: 'cloud-egress-control', wd: '/home/student/egress', flag: 'nto{3gr3ss_byp4ss_4ll0w3d_s3rv1c3}' },
]

describe.each(LABS)('cloud network lab B17: $id', ({ id, wd, flag }) => {
  const bundle = load(id)
  const check = "grep -q 'nto{' found.txt"
  const spec = { kind: 'shell', workdir: wd, check, hints: ['h', 'h'] }

  it('bundle + seed files are consistent with the lesson lab block', () => {
    expect(bundle.id).toBe(id)
    expect(bundle.workdir).toBe(wd)
    expect(bundle.fs.some((f) => f.path === `${wd}/task.md`)).toBe(true)
    expect(bundle.expect.file).toBe(`${wd}/found.txt`)
    expect(bundle.expect.contains).toBe(flag)
  })

  it('replays the intended solution and passes check', async () => {
    const s = createSession({ spec, bundle })
    expect((await s.run('check')).code).toBe(1)
    await s.run(`grep nto notes.md > found.txt`)
    expect((await s.run('check')).code).toBe(0)
  })

  it('check fails on an empty/negative solution', async () => {
    const s = createSession({ spec, bundle })
    await s.run(`echo nope > found.txt`)
    expect((await s.run('check')).code).toBe(1)
  })
})
