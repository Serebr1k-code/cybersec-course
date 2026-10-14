import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for lab batch crypto-b15 (symmetric/stream/PRNG gaps).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: "crypto-algebraic-cube", flag: "nto{cub3_sum_r3v34ls_th3_sup3rp0ly}", hints: 4,
    solution: ["python3 cube.py > found.txt"],
  },
  {
    id: "crypto-related-key-attacks", flag: "nto{r3l4t3d_k3y_l1n34r_sch3dul3_br34ks}", hints: 4,
    solution: ["python3 rk.py > found.txt"],
  },
  {
    id: "crypto-gsm-a5-3g", flag: "nto{45_1_m4j0r1ty_cl0ck1ng_1s_w34k}", hints: 4,
    solution: ["python3 a51.py > found.txt"],
  },
  {
    id: "crypto-algebraic-attacks-stream", flag: "nto{f4st_c0rr3l4t10n_r3c0v3rs_lfsr_s33d}", hints: 4,
    solution: ["python3 corr.py > found.txt"],
  },
  {
    id: "crypto-drbg-backdoors", flag: "nto{du4l_3c_drbg_b4ckd00r_r3c0v3rs_st4t3}", hints: 5,
    solution: ["python3 dual_ec.py > found.txt"],
  },
  {
    id: "crypto-hardware-rng", flag: "nto{w34k_trng_b14s_d3t3ct3d_by_m0n0b1t}", hints: 4,
    solution: ["python3 trng.py > found.txt"],
  },
]

describe.each(LABS)('lab batch crypto-b15: $id', ({ id, flag, hints, solution }) => {
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
