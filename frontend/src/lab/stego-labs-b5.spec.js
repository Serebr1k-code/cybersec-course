import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the stego lab batch (STEGO-5).
// Loads the REAL fixture bundles from content/labs, replays the intended
// solution with the emulated tools, and asserts `check` passes.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'stego-intro', flag: 'nto{p1p3l1n3_str1ngs_th3n_3x1f}', hints: 4,
    solution: ['strings mystery.png | grep nto > found.txt'] },
  { id: 'stego-advanced', flag: 'nto{pr1v4t3_chunk_sp3c_r34d1ng}', hints: 4,
    solution: ['python3 chunk.py | grep nto > found.txt'] },
  { id: 'stego-media-basics', flag: 'nto{lsb_b4s1cs_1mg_4ud10}', hints: 4,
    solution: ['python3 extract.py | grep nto > found.txt'] },
  { id: 'stego-media-carriers', flag: 'nto{z3r0_w1dth_c4rr13r}', hints: 4,
    solution: ['python3 zw.py | grep nto > found.txt'] },
  { id: 'stego-analysis-advanced', flag: 'nto{ch1_squ4r3_d3t3ct5_lsb}', hints: 4,
    solution: ['python3 chi.py | grep nto > found.txt'] },
  { id: 'stego-tooling', flag: 'nto{zst3g_ch4nn3l_sw33p}', hints: 4,
    solution: ['zsteg -a secret.png | grep nto > found.txt'] },
  { id: 'stego-image-techniques', flag: 'nto{t3xt_chunk_1n_png}', hints: 4,
    solution: ['strings image.png | grep nto > found.txt'] },
  { id: 'stego-bit-manipulation', flag: 'nto{b1tpl4n3_1_1snt_lsb}', hints: 4,
    solution: ['python3 plane.py | grep nto > found.txt'] },
  { id: 'stego-document-carriers', flag: 'nto{d0cx_z1p_h1dd3n_p4rt}', hints: 4,
    solution: ['strings report.docx | grep nto > found.txt'] },
  { id: 'stego-binary-carriers', flag: 'nto{3lf_0v3rl4y_4pp3nd3d}', hints: 4,
    solution: ['strings program | grep nto > found.txt'] },
  { id: 'stego-blockchain', flag: 'nto{0p_r3turn_b1tco1n}', hints: 4,
    solution: ['python3 opret.py | grep nto > found.txt'] },
  { id: 'stego-capacity-theory', flag: 'nto{ch4nn3l_c4p4c1ty_b0und}', hints: 4,
    solution: ['python3 capacity.py | grep nto > found.txt'] },
  { id: 'stego-code', flag: 'nto{c0d3_wh1t3sp4c3_ch4nn3l}', hints: 4,
    solution: ['python3 ws.py | grep nto > found.txt'] },
  { id: 'stego-deep-learning', flag: 'nto{n3ur4l_3nc0d3r_d3c0d3r}', hints: 4,
    solution: ['python3 nn.py | grep nto > found.txt'] },
  { id: 'stego-physical', flag: 'nto{p4p3r_r3l13f_m1cr0p3rf}', hints: 4,
    solution: ['python3 relief.py | grep nto > found.txt'] },
]

describe.each(LABS)('stego lab: $id', ({ id, flag, hints, solution }) => {
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
    expect((await s.run('check')).code).toBe(1) // not solved yet
    for (const cmd of solution) await s.run(cmd)
    expect((await s.run('check')).code).toBe(0)
  })

  it('rejects a wrong answer', async () => {
    const s = createSession({ spec, bundle })
    await s.run("echo 'nto{wrong_flag}' > found.txt")
    expect((await s.run('check')).code).toBe(1)
  })
})
