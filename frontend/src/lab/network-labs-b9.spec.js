import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the second NETWORK lab batch (12 labs).
// Each entry loads the REAL fixture bundle from content/labs, replays the
// intended solution through the emulated tools, and asserts the lab's own
// `check` + hidden `expect` both pass. Fixtures are captured from real
// tshark/dig/curl runs (pcaps crafted with scapy).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'

const LABS = [
  { id: 'network-dns-attacks',
    check: "grep -q 'nto{' answer.txt",
    solution: [
      'tshark -r dns.pcap',
      "tshark -r dns.pcap -Y dns -T fields -e ip.src -e dns.qry.name -e dns.a",
      'tshark -r dns.pcap -q -z follow,tcp,ascii,0',
      'echo nto{dns_c4ch3_p01s0n_sp00f3d} > answer.txt',
    ] },
  { id: 'network-dnssec',
    check: "grep -q 'nto{' answer.txt",
    solution: [
      'dig +dnssec bank.example A @1.1.1.1',
      'dig +dnssec bank.example A @127.0.0.1',
      'dig +dnssec bank.example TXT @127.0.0.1',
      'echo nto{dnssec_str1p_d0wngr4d3} > answer.txt',
    ] },
  { id: 'network-doh-dot',
    check: "grep -q 'cloudflare-dns.com' answer.txt",
    solution: [
      'tshark -r doh.pcap',
      'tshark -r doh.pcap -Y tls.handshake.extensions_server_name -T fields -e ip.src -e tcp.dstport -e tls.handshake.extensions_server_name',
      'echo cloudflare-dns.com > answer.txt',
    ] },
  { id: 'network-service-enum',
    check: "grep -q 'nto{' answer.txt",
    solution: [
      'nmap -sV -p 445,3389,389,88,135,1433,5985 10.10.10.10',
      "nxc smb 10.10.10.10 -u '' -p '' --rid-brute",
      'ldapsearch -x -H ldap://10.10.10.10 -b "dc=corp,dc=local"',
      'echo nto{ld4p_4n0n_b1nd_svc_backup} > answer.txt',
    ] },
  { id: 'network-ssh-tunnel',
    check: "grep -q 'nto{' answer.txt",
    solution: [
      'ssh -N -L 8080:10.0.0.5:8080 analyst@bastion',
      'ss -ltnp',
      'curl http://127.0.0.1:8080/',
      'echo nto{ssh_L_f0rw4rd_p1v0t} > answer.txt',
    ] },
  { id: 'network-socks-http-connect',
    check: "grep -q 'nto{' answer.txt",
    solution: [
      'xxd socks5-greeting.bin',
      'curl --socks5 127.0.0.1:1080 http://intranet.corp.local/',
      'echo nto{s0cks5_pr0xy_p1v0t} > answer.txt',
    ] },
  { id: 'network-proxy-cdn-waf',
    check: "grep -q 'nto{' answer.txt",
    solution: [
      'curl -sI https://shop.example.com',
      'curl --resolve shop.example.com:443:198.51.100.77 https://shop.example.com/',
      'echo nto{cdn_byp4ss_0r1g1n_f0und} > answer.txt',
    ] },
  { id: 'network-firewall-evasion',
    check: "grep -q 'nto{' answer.txt",
    solution: [
      'nmap -sA -Pn -p445 10.10.20.5',
      'nmap -f --mtu 8 -g 53 -Pn -p445 10.10.20.5',
      'nmap --data-length 200 -g 53 -Pn -p445,8080 10.10.20.5',
      'curl http://10.10.20.5:8080/',
      'echo nto{fr4g_byp4ss_3gr3ss} > answer.txt',
    ] },
  { id: 'network-tls-fingerprint',
    check: "grep -q 'nto{' answer.txt",
    solution: [
      'tshark -r tls.pcap',
      'tshark -r tls.pcap -Y tls.handshake.extensions_server_name -T fields -e ip.src -e tls.handshake.extensions_server_name -e tls.handshake.ja3',
      'grep 5d24a8 ja3-intel.txt',
      'echo nto{ja3_c2_b34c0n_m4tch} > answer.txt',
    ] },
  { id: 'network-telnet-rservices',
    check: "grep -q 'nto{' answer.txt",
    solution: [
      'tshark -r telnet.pcap',
      'tshark -r telnet.pcap -q -z follow,tcp,ascii,0',
      'echo nto{t3ln3t_cl3rt3xt_l34k} > answer.txt',
    ] },
  { id: 'network-nfs',
    check: "grep -q 'nto{' answer.txt",
    solution: [
      'showmount -e 10.0.0.20',
      'rpcinfo -p 10.0.0.20',
      'cat exports/srv_export/flag.txt',
      'echo nto{nfs_n0_r00t_squ4sh_0wn3d} > answer.txt',
    ] },
  { id: 'network-wpad-proxy',
    check: "grep -q 'nto{' answer.txt",
    solution: [
      'tshark -r wpad.pcap',
      'tshark -r wpad.pcap -Y llmnr -T fields -e ip.src -e ip.dst -e dns.qry.name -e dns.a',
      'tshark -r wpad.pcap -q -z follow,tcp,ascii,0',
      'echo nto{wpad_p4c_m1tm_pr0xy} > answer.txt',
    ] },
]

describe('network labs batch B9 solve end-to-end', () => {
  for (const { id, check, solution } of LABS) {
    it(id, async () => {
      const bundle = JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
      const spec = { kind: 'shell', workdir: WD, check, hints: ['a', 'b', 'c'] }
      const s = createSession({ spec, bundle })
      expect((await s.run('check')).stdout).toContain('не сходится')
      for (const cmd of solution) {
        const r = await s.run(cmd)
        expect(r.stderr, `${id}: ${cmd}`).not.toMatch(/command not found|нет в этой лабе/)
      }
      expect((await s.run('check')).stdout, `${id} check`).toContain('Готово')
      expect(s.solved).toBe(true)
    })
  }
})
