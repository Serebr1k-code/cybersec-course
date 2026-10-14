import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for lab batch crypto-b16 (hashes/MAC gaps).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: "crypto-sha2-sha3-internals", flag: "nto{l3ngth_3xt3ns10n_m3rkl3_d4mg4rd_fl4w}", hints: 4,
    solution: ["python3 ext.py > found.txt"],
  },
  {
    id: "crypto-blake-ripemd-whirlpool", flag: "nto{bl4k3_2_k3y3d_m0d3_1s_bu1lt_1n}", hints: 4,
    solution: ["python3 blake.py > found.txt"],
  },
  {
    id: "crypto-hash-preimage-herding", flag: "nto{j0ux_mult1c0ll1s10n_2_pow_k_m3ss4g3s}", hints: 4,
    solution: ["python3 multicoll.py > found.txt"],
  },
  {
    id: "crypto-hash-mitm", flag: "nto{b1rthd4y_c0ll1s10n_2_p0w_n_0v3r_2}", hints: 4,
    solution: ["python3 birthday.py > found.txt"],
  },
  {
    id: "crypto-mac-wc-umac", flag: "nto{w3gm4n_c4rt3r_0n3_t1m3_k3y_r3us3_br34ks}", hints: 4,
    solution: ["python3 wc.py > found.txt"],
  },
  {
    id: "crypto-aead-gmac-poly1305-deep", flag: "nto{gh4sh_f0rb1dd3n_4tt4ck_r3c0v3rs_h}", hints: 4,
    solution: ["python3 ghash.py > found.txt"],
  },
  {
    id: "crypto-password-hashing-engineering", flag: "nto{c0st_p4r4m3t3rs_4nd_pepp3r_m4tt3r}", hints: 4,
    solution: ["python3 kdf.py > found.txt"],
  },
]

describe.each(LABS)('lab batch crypto-b16: $id', ({ id, flag, hints, solution }) => {
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
