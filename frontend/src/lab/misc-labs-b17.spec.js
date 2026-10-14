import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

function loadBundle(id) {
  const p = path.resolve(process.cwd(), `../content/labs/${id}.json`)
  return JSON.parse(fs.readFileSync(p, 'utf8'))
}
function session(spec, bundle) { return createSession({ spec, bundle }) }

function specFor(id, files) {
  return {
    kind: 'shell',
    workdir: '/home/student/task',
    files: ['task.md', ...files],
    check: "grep -q 'nto{' found.txt",
    hints: ['a', 'b', 'c'],
  }
}

const CASES = [
  { id: 'misc-cairo-starknet', artifact: 'storage.txt', flag: 'nto{c41r0_f3lt_0v3rfl0w}' },
  { id: 'misc-move-sui', artifact: 'objects.txt', flag: 'nto{m0v3_c4p4b1l1ty_c0nfus10n}' },
  { id: 'misc-cosmos-wasm', artifact: 'state.txt', flag: 'nto{c0smw4sm_1bc_4ck_c0nfus10n}' },
  { id: 'misc-rust-solana', artifact: 'accounts.txt', flag: 'nto{s0l4n4_4cc0unt_c0nfus10n}' },
  { id: 'misc-yul-assembly', artifact: 'bytecode.hex', flag: 'nto{yul_d1rty_b1ts_4nd_fr33_ptr}' },
  { id: 'misc-upgradeable-proxy', artifact: 'storage.txt', flag: 'nto{uups_un1n1t14l1z3d_1mpl}' },
  { id: 'misc-erc-standards', artifact: 'token.log', flag: 'nto{erc721_c4llb4ck_r33ntr4ncy}' },
  { id: 'misc-defi-mev-deep', artifact: 'mempool.txt', flag: 'nto{m3v_s4ndw1ch_n0_sl1pp4g3}' },
  { id: 'misc-bitcoin-script', artifact: 'witness.txt', flag: 'nto{ord1n4ls_h1d3_1n_w1tn3ss}' },
  { id: 'misc-ctf-web3-meta', artifact: 'contract.txt', flag: 'nto{w3b3_ctf_m3th0d0l0gy}' },
  { id: 'misc-markdown-render', artifact: 'render.log', flag: 'nto{m4rkdown_r3nd3r_j4v4scr1pt_sch3m3}' },
  { id: 'misc-html-parser-diff', artifact: 'mxss.log', flag: 'nto{mxss_noscript_mut4t10n}' },
  { id: 'misc-html-email', artifact: 'mail.eml', flag: 'nto{html3m41l_css_3xf1ltr4t10n}' },
  { id: 'misc-plexus-parser', artifact: 'waf.log', flag: 'nto{pars3r_d1ff_d0ubl3_d3c0d3}' },
  { id: 'misc-srt-subtitle', artifact: 'subs.srt', flag: 'nto{srt_t1m1ng_c0v3rt_ch4nn3l}' },
  { id: 'misc-ebml-matroska', artifact: 'tree.txt', flag: 'nto{ebml_v1nt_h1dd3n_3l3m3nt}' },
  { id: 'misc-midi-misc', artifact: 'events.txt', flag: 'nto{m1d1_m3t4_3v3nt_fl4g}' },
  { id: 'misc-pcap-misc', artifact: 'capture.txt', flag: 'nto{pcap_cust0m_pr0t0c0l_r3c0v3r}' },
]

for (const c of CASES) {
  describe(`${c.id} lab`, () => {
    const bundle = loadBundle(c.id)
    const spec = specFor(c.id, [c.artifact])

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
