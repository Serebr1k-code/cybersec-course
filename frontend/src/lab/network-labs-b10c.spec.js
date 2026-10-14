import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the network lab batch B10c (12 labs):
// classic wire protocols (HTTP/1.1, SOCKS5, Telnet, TFTP), access/AAA
// (RADIUS, TACACS+, r-services, PPP) and transport alternatives
// (IPv4/TCP options, SCTP, DCCP).
// Each entry loads the REAL fixture bundle from content/labs, replays the
// intended solution through the emulated tools, and asserts that the
// extraction yields the flag AND the lab's own `check` + hidden `expect` pass.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' answer.txt"

const LABS = [
  { id: 'network-http1-deep', extract:
      'tshark -r http1.pcap -q -z follow,tcp,ascii,0 | grep X-Token | cut -d: -f2 | base64 -d',
    flag: 'nto{http1_chunk3d_5muggl3}',
    steps: ['tshark -r http1.pcap -q -z follow,tcp,ascii,0'] },
  { id: 'network-socks5-protocol', extract: 'grep dst: socks.log | cut -d: -f2 | base64 -d',
    flag: 'nto{s0ck5_c0nn3ct_1nt3rn4l}', steps: ['cat socks.log'] },
  { id: 'network-telnet-protocol', extract: 'grep val: telnet.log | cut -d: -f2 | base64 -d',
    flag: 'nto{t3ln3t_1ac_n4w5_0pt}', steps: ['cat telnet.log'] },
  { id: 'network-tftp-protocol', extract: 'grep data: tftp.log | cut -d: -f2 | base64 -d',
    flag: 'nto{tftp_blk5iz3_0pt10n}', steps: ['cat tftp.log'] },
  { id: 'network-radius-protocol', extract: 'grep Reply-Message radius.log | cut -d: -f2 | base64 -d',
    flag: 'nto{r4d1u5_r3ply_m3ss4g3}', steps: ['cat radius.log'] },
  { id: 'network-tacacs', extract: 'grep body: tacacs.log | cut -d: -f2 | base64 -d',
    flag: 'nto{t4c4c5_5h4r3d_53cr3t}', steps: ['cat tacacs.log'] },
  { id: 'network-xinetd-rservices', extract: 'grep host: rlogin.log | cut -d: -f2 | base64 -d',
    flag: 'nto{r5h_r00t_3qu1v_7ru57}', steps: ['cat rlogin.log'] },
  { id: 'network-ppp-lcp', extract: 'grep opt: ppp.log | cut -d: -f2 | base64 -d',
    flag: 'nto{ppp_lcp_4uth_d0wngr4d3}', steps: ['cat ppp.log'] },
  { id: 'network-ipv4-options', extract: 'grep data: ipv4.log | cut -d: -f2 | base64 -d',
    flag: 'nto{1pv4_l5rr_5rc_r0ut3}', steps: ['cat ipv4.log'] },
  { id: 'network-tcp-options', extract: 'grep val: tcp.log | cut -d: -f2 | base64 -d',
    flag: 'nto{tcp_0pt10n5_mptcp}', steps: ['cat tcp.log'] },
  { id: 'network-sctp', extract: 'grep payload: sctp.log | cut -d: -f2 | base64 -d',
    flag: 'nto{5ctp_chunk_d4t4}', steps: ['cat sctp.log'] },
  { id: 'network-dccp', extract: 'grep feature: dccp.log | cut -d: -f2 | base64 -d',
    flag: 'nto{dccp_f34tur3_n3g0t}', steps: ['cat dccp.log'] },
]

describe('network labs batch B10c solve end-to-end', () => {
  for (const { id, extract, flag, steps } of LABS) {
    it(id, async () => {
      const bundle = JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
      const spec = { kind: 'shell', workdir: WD, check: CHECK, hints: ['a', 'b', 'c'] }
      const s = createSession({ spec, bundle })
      expect((await s.run('check')).stdout).toContain('не сходится')
      for (const cmd of steps) {
        const r = await s.run(cmd)
        expect(r.stderr, `${id}: ${cmd}`).not.toMatch(/command not found|нет в этой лабе/)
      }
      const ex = await s.run(extract)
      expect(ex.stderr, `${id} extract: ${extract}`).not.toMatch(/command not found|нет в этой лабе/)
      expect(ex.stdout, `${id} extract stdout`).toContain(flag)
      const w = await s.run(`echo ${flag} > answer.txt`)
      expect(w.stderr, `${id} write`).not.toMatch(/command not found/)
      expect((await s.run('check')).stdout, `${id} check`).toContain('Готово')
      expect(s.solved).toBe(true)
    })
  }
})
