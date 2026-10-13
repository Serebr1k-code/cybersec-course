import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the CLOUD labs batch B14 (part 2):
// cloud-kubernetes-rbac, cloud-cicd-secrets, cloud-logging-detection, cloud-supply-chain.
const dir = path.resolve(process.cwd(), '../content/labs')

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: 'cloud-kubernetes-rbac',
    wd: '/home/student/k8s',
    flag: 'nto{kubernetes_rbac_2_cluster4dm1n}',
    check: "grep -q 'nto{' found.txt",
    solution: [
      `kubectl auth can-i --list`,
      `kubectl get secrets -A`,
      `kubectl get secret cluster-admin-token -n kube-system -o jsonpath='{.data.token}' | base64 -d > found.txt`,
    ],
  },
  {
    id: 'cloud-cicd-secrets',
    wd: '/home/student/cicd',
    flag: 'nto{pr_t4rg3t_s3cr3ts_byp4ss_m4sk1ng}',
    check: "grep -q 'nto{' found.txt",
    solution: [`base64 -d exfil.b64 > found.txt`],
  },
  {
    id: 'cloud-logging-detection',
    wd: '/home/student/trail',
    flag: 'nto{cust0m_us3r4g3nt_1s_4_r3df14g}',
    check: "grep -q 'nto{' found.txt",
    solution: [`grep userAgent cloudtrail.json`, `grep nto cloudtrail.json > found.txt`],
  },
  {
    id: 'cloud-supply-chain',
    wd: '/home/student/supply',
    flag: 'nto{1nt3rn4l_p4ck4g3_h4rdc0d3d_s3cr3t}',
    check: "grep -q 'nto{' found.txt",
    solution: [
      `grep resolved package-lock.json`,
      `grep nto acme-auth-utils/index.js > found.txt`,
    ],
  },
]

describe.each(LABS)('cloud lab B14b: $id', ({ id, wd, flag, check, solution }) => {
  const bundle = load(id)
  const spec = { kind: 'shell', workdir: wd, check, hints: ['h', 'h', 'h', 'h'] }

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
    for (const cmd of solution) await s.run(cmd)
    expect((await s.run('check')).code).toBe(0)
  })

  it('check fails on an empty/negative solution', async () => {
    const s = createSession({ spec, bundle })
    await s.run(`echo nope > found.txt`)
    expect((await s.run('check')).code).toBe(1)
  })
})
