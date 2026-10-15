import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

function loadBundle(id) {
  const p = path.resolve(process.cwd(), `../content/labs/${id}.json`)
  return JSON.parse(fs.readFileSync(p, 'utf8'))
}
function session(spec, bundle) { return createSession({ spec, bundle }) }

function specFor(files) {
  return {
    kind: 'shell',
    workdir: '/home/student/task',
    files: ['task.md', ...files],
    check: "grep -q 'nto{' found.txt",
    hints: ['a', 'b', 'c'],
  }
}

const CASES = [
  { id: 'misc-timing-attacks', artifact: 'timing.log', flag: 'nto{t1m1ng_l34k_0n_c0mp4r3}' },
  { id: 'misc-prng-attacks', artifact: 'prng.log', flag: 'nto{mt19937_st4t3_r3c0v3r3d}' },
  { id: 'misc-crypto-sidechannel', artifact: 'sidechannel.log', flag: 'nto{k0ch3r_0n3_t4bl3_s1d3_ch4nn3l}' },
  { id: 'misc-crt-fault', artifact: 'crt.log', flag: 'nto{crt_f4ult_f4ct0rs_n}' },
  { id: 'misc-symbolic-exec', artifact: 'symbolic.log', flag: 'nto{4ngr_f0und_th3_p4th}' },
  { id: 'misc-concolic', artifact: 'concolic.log', flag: 'nto{c0nc0l1c_g3n3r4t3d_1nput}' },
  { id: 'misc-sat-solving', artifact: 'sat.log', flag: 'nto{s4t_s0lv3r_unr4v3ls_w1r3s}' },
  { id: 'misc-fuzzing-misc', artifact: 'fuzzing.log', flag: 'nto{4fl_c0v3r4g3_f0und_cr4sh}' },
  { id: 'misc-info-theory', artifact: 'info.log', flag: 'nto{3ntr0py_0f_4_p4ssw0rd}' },
  { id: 'misc-linear-algebra', artifact: 'linear.log', flag: 'nto{gf2_l1n34r_syst3m_s0lv3d}' },
  { id: 'misc-markov-chains', artifact: 'markov.log', flag: 'nto{m4rk0v_st4t10n4ry_d1str1but10n}' },
  { id: 'misc-numerical-methods', artifact: 'numerical.log', flag: 'nto{numer1c4l_dr1ft_b3tw33n_fl04ts}' },
]

for (const c of CASES) {
  describe(`${c.id} lab`, () => {
    const bundle = loadBundle(c.id)
    const spec = specFor([c.artifact])

    it('seeds the artifact and task', async () => {
      const s = session(spec, bundle)
      const r = await s.run(`cat ${c.artifact}`)
      expect(r.stdout).toContain('flag:')
    })

    it('is not solved before writing found.txt', async () => {
      const s = session(spec, bundle)
      expect((await s.run('check')).code).toBe(1)
    })

    it('solves via cut + base64 -d', async () => {
      const s = session(spec, bundle)
      await s.run(`grep flag ${c.artifact} | cut -d: -f2 | base64 -d > found.txt`)
      expect((await s.run('check')).code).toBe(0)
      expect(s.solved).toBe(true)
      expect((await s.run('cat found.txt')).stdout.trim()).toBe(c.flag)
    })
  })
}
