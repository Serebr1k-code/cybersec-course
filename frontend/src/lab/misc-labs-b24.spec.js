import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

function loadBundle(id) {
  const p = path.resolve(process.cwd(), `../content/labs/${id}.json`)
  return JSON.parse(fs.readFileSync(p, 'utf8'))
}
function session(spec, bundle) { return createSession({ spec, bundle }) }

function specFor(artifact, check = "grep -q 'nto{' found.txt") {
  return {
    kind: 'shell',
    workdir: '/home/student/task',
    files: ['task.md', artifact],
    check,
    hints: ['a', 'b', 'c'],
  }
}

// Batch b8-iso: kernel isolation lessons (cgroups, Landlock, netfilter, MAC).
const CASES = [
  {
    id: 'misc-cgroup-v2',
    artifact: 'cgroup_dump.txt',
    flag: 'nto{cgr0up_v2_m3m0ry_m4x}',
    solve: "grep flag cgroup_dump.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-landlock',
    artifact: 'landlock_ruleset.txt',
    flag: 'nto{l4ndl0ck_wh1t3l1st}',
    solve: "grep flag landlock_ruleset.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-netfilter',
    artifact: 'nft_ruleset.txt',
    flag: 'nto{nft4bl3s_rul3s3t}',
    solve: "grep flag nft_ruleset.txt | cut -d= -f2 | base64 -d > found.txt",
  },
  {
    id: 'misc-selinux-apparmor',
    artifact: 'selinux_status.txt',
    flag: 'nto{s3l1nux_typ3_c0nt3xt}',
    solve: "grep flag selinux_status.txt | cut -d= -f2 | base64 -d > found.txt",
  },
]

for (const c of CASES) {
  describe(`${c.id} lab`, () => {
    const bundle = loadBundle(c.id)
    const spec = specFor(c.artifact)

    it('seeds the artifact and task', async () => {
      const s = session(spec, bundle)
      const r = await s.run(`cat ${c.artifact}`)
      expect(r.stdout.length).toBeGreaterThan(0)
    })

    it('is not solved before writing found.txt', async () => {
      const s = session(spec, bundle)
      expect((await s.run('check')).code).toBe(1)
    })

    it('solves with the documented pipeline', async () => {
      const s = session(spec, bundle)
      await s.run(c.solve)
      expect((await s.run('check')).code).toBe(0)
      expect(s.solved).toBe(true)
      expect((await s.run('cat found.txt')).stdout.trim()).toBe(c.flag)
    })
  })
}
