import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the stego lab batch (STEGO-4).
// Loads the REAL fixture bundles from content/labs, replays the intended
// solution with the emulated tools, and asserts `check` passes.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'stego-printer-dots', flag: 'nto{pr1nt3r_m1c_sn_48291}', hints: 4,
    solution: ['python3 decode.py | grep nto > found.txt'] },
  { id: 'stego-qr-hidden', flag: 'nto{qr_lsb_l4y3r_2nd_ch4nn3l}', hints: 4,
    solution: ['python3 lsb.py | grep nto > found.txt'] },
  { id: 'stego-heic-avif', flag: 'nto{h31c_1sobmmff_b0x3s}', hints: 4,
    solution: ['strings IMG_0001.heic | grep nto > found.txt'] },
  { id: 'stego-fonts', flag: 'nto{f0nt_n4m3_t4bl3_glyf}', hints: 4,
    solution: ['python3 name.py | grep nto > found.txt'] },
  { id: 'stego-text-font', flag: 'nto{k3rn1ng_c0d3s_th3_d1ff}', hints: 4,
    solution: ['python3 kern.py | grep nto > found.txt'] },
  { id: 'stego-tool-stegsolve', flag: 'nto{r_ch4nn3l_b1t0_pl4n3}', hints: 4,
    solution: ['python3 lsb.py | grep nto > found.txt'] },
  { id: 'stego-tool-jsteg-cloakify', flag: 'nto{st3gh1d3_w1th_p4ssw0rd}', hints: 4,
    solution: ['python3 extract.py | grep nto > found.txt'] },
  { id: 'stego-raw-photo', flag: 'nto{r4w_m4k3rn0t3_n3f}', hints: 4,
    solution: ['python3 extract.py | grep nto > found.txt'] },
  { id: 'stego-watermarking', flag: 'nto{fr4g1l3_lsb_w4t3rm4rk}', hints: 4,
    solution: ['python3 wm.py | grep nto > found.txt'] },
  { id: 'stego-video-motion', flag: 'nto{m0t10n_v3ct0r_c0d3c}', hints: 4,
    solution: ['python3 mv.py | grep nto > found.txt'] },
  { id: 'stego-video-audio-mux', flag: 'nto{h1dd3n_subt1tl3_tr4ck}', hints: 4,
    solution: ['python3 tracks.py | grep nto > found.txt'] },
  { id: 'stego-covert-voip', flag: 'nto{rtp_ssrc_c0v3rt_ch4nn3l}', hints: 4,
    solution: ['python3 ssrc.py | grep nto > found.txt'] },
  { id: 'stego-adaptive', flag: 'nto{4d4pt1v3_3dg3_c0st}', hints: 4,
    solution: ['python3 edge.py | grep nto > found.txt'] },
  { id: 'stego-f5', flag: 'nto{f5_m4tr1x_c0d1ng}', hints: 4,
    solution: ['python3 f5.py | grep nto > found.txt'] },
  { id: 'stego-video-frames', flag: 'nto{v1d30_h1dd3n_fr4m3}', hints: 4,
    solution: ['zbarimg frames/00217.png | grep nto > found.txt'] },
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
