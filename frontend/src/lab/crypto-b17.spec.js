import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for lab batch crypto-b17 (RSA implementation gaps).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: "crypto-rsa-roca-bateman", flag: "nto{r0c4_d3t3ct10n_v14_sm4ll_subgr0up}", hints: 4,
    solution: ["python3 roca.py > found.txt"],
  },
  {
    id: "crypto-rsa-oaep-manger-deep", flag: "nto{1b1t_0r4cl3_b1n4ry_s34rch_r3c0v3rs_m}", hints: 4,
    solution: ["python3 oracle.py > found.txt"],
  },
  {
    id: "crypto-rsa-signature-forgery", flag: "nto{bl31ch3nb4ch3r_06_e3_l4x_p4dd1ng_f0rg3}", hints: 4,
    solution: ["python3 forge.py > found.txt"],
  },
  {
    id: "crypto-rsa-crt-fault-deep", flag: "nto{b3llc0r3_crt_f4ult_gcd_r3v34ls_p}", hints: 4,
    solution: ["python3 bellcore.py > found.txt"],
  },
]

describe.each(LABS)('lab batch crypto-b17: $id', ({ id, flag, hints, solution }) => {
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
