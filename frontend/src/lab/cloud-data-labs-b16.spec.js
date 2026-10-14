import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the CLOUD data/analytics lab batch (B16):
// snowflake, databricks, kafka-msk, airflow-dag, dbt-looker, data-lake,
// streaming-exfil.
const dir = path.resolve(process.cwd(), '../content/labs')

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'cloud-snowflake', wd: '/home/student/snow', flag: 'nto{sn0wfl4k3_acc0unt4dm1n_k3y}' },
  { id: 'cloud-databricks', wd: '/home/student/dbx', flag: 'nto{d4t4br1cks_t0k3n_clust3r_r0l3}' },
  { id: 'cloud-kafka-msk', wd: '/home/student/kafka', flag: 'nto{k4fk4_w1ldc4rd_4cl_r34d_wr1t3}' },
  { id: 'cloud-airflow-dag', wd: '/home/student/airflow', flag: 'nto{41rfl0w_d4g_rce_c0nn3ct10ns}' },
  { id: 'cloud-dbt-looker', wd: '/home/student/dbt', flag: 'nto{dbt_pr0f1l3_cr3d5_wh_tr4nsf0rm3r}' },
  { id: 'cloud-data-lake', wd: '/home/student/lake', flag: 'nto{d4t4l4k3_s3_byp4ss_l4k3f0rm4t10n}' },
  { id: 'cloud-streaming-exfil', wd: '/home/student/exfil', flag: 'nto{str34m1ng_exf1l_k1n3s1s_tunn3l}' },
]

describe.each(LABS)('cloud data lab B16: $id', ({ id, wd, flag }) => {
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
