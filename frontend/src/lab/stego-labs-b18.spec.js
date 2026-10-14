import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the stego lab batch (STEGO-18):
// RDH/theory + frequency-domain + audio-embed + video (motion/subtitle).
// Loads the REAL fixture bundles from content/labs, replays the intended
// solution with the emulated tools, and asserts `check` passes.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'stego-reversible-data-hiding', flag: 'nto{r3v3rs1bl3_1nt4ct_c0v3r}', hints: 3,
    solution: ['python3 rdh.py | grep nto > found.txt'] },
  { id: 'stego-difference-expansion', flag: 'nto{d1ff3r3nc3_3xp4ns10n}', hints: 3,
    solution: ['python3 de.py | grep nto > found.txt'] },
  { id: 'stego-histogram-shifting', flag: 'nto{h1st0gr4m_sh1ft_p41r}', hints: 3,
    solution: ['python3 hs.py | grep nto > found.txt'] },
  { id: 'stego-ecc', flag: 'nto{ecc_pr0t3ct5_b1t5}', hints: 3,
    solution: ['python3 ecc.py | grep nto > found.txt'] },
  { id: 'stego-minimum-distortion', flag: 'nto{m1n_c0st_3mb3dd1ng}', hints: 3,
    solution: ['python3 mindist.py | grep nto > found.txt'] },
  { id: 'stego-wet-paper-codes', flag: 'nto{w3t_p4p3r_c0d3}', hints: 3,
    solution: ['python3 wetpaper.py | grep nto > found.txt'] },
  { id: 'stego-security-models', flag: 'nto{c4ch1n_cr1t3r10n}', hints: 3,
    solution: ['python3 kld.py | grep nto > found.txt'] },
  { id: 'stego-matrix-embedding', flag: 'nto{h4mm1ng_m4tr1x_3mb3d}', hints: 3,
    solution: ['python3 hamming.py | grep nto > found.txt'] },
  { id: 'stego-dct-qim', flag: 'nto{dct_q1m_qu4nt1z3}', hints: 3,
    solution: ['python3 qim.py | grep nto > found.txt'] },
  { id: 'stego-dft-domain', flag: 'nto{dft_l0g_p0l4r_d0m41n}', hints: 3,
    solution: ['python3 dft.py | grep nto > found.txt'] },
  { id: 'stego-svd', flag: 'nto{svd_s1ngul4r_v4lu3s}', hints: 3,
    solution: ['python3 svd.py | grep nto > found.txt'] },
  { id: 'stego-chaos', flag: 'nto{ch40s_m4p_k3ystr34m}', hints: 3,
    solution: ['python3 chaos.py | grep nto > found.txt'] },
  { id: 'stego-id3-tags', flag: 'nto{1d3v2_4p1c_c0v3r}', hints: 3,
    solution: ['python3 id3.py | grep nto > found.txt'] },
  { id: 'stego-audio-qim', flag: 'nto{4ud10_q1m_s4mpl3}', hints: 3,
    solution: ['python3 audioqim.py | grep nto > found.txt'] },
  { id: 'stego-audio-watermark', flag: 'nto{4ud10s34l_w4t3rm4rk}', hints: 3,
    solution: ['python3 watermark.py | grep nto > found.txt'] },
  { id: 'stego-speech-lpc', flag: 'nto{lpc_f0rm4nt_c0d3r}', hints: 3,
    solution: ['python3 lpc.py | grep nto > found.txt'] },
  { id: 'stego-h264-mv', flag: 'nto{h264_m0t10n_v3ct0r}', hints: 3,
    solution: ['python3 mvec.py | grep nto > found.txt'] },
  { id: 'stego-subtitle-srt', flag: 'nto{srt_t1m1ng_c0v3rt}', hints: 3,
    solution: ['python3 subs.py | grep nto > found.txt'] },
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
