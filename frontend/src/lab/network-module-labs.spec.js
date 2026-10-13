import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the network module-page lab batch.
// Each entry loads the REAL fixture bundle from content/labs, replays the
// intended solution through the emulated tools, and asserts the lab's own
// `check` + hidden `expect` both pass. Packet fixtures are pcaps crafted with
// scapy (LLDP system description, VLAN-tagged frame, ICMP payload, DNS TXT)
// and dissected with real tshark 4.6; Bluetooth SDP is a replay of sdptool.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'

const LABS = [
  { id: 'network-module-l2',
    check: "grep -q 'nto{l2_0ld_sw1tch_1s_0wn3d}' answer.txt",
    solution: [
      'tshark -r l2.pcap -nn',
      'tshark -r l2.pcap -Y lldp -T fields -e lldp.tlv.system.name -e lldp.tlv.system.desc',
      'echo nto{l2_0ld_sw1tch_1s_0wn3d} > answer.txt',
    ] },
  { id: 'network-module-ip',
    check: "grep -q 'nto{1cmp_3xf1l_4nd_c0v3rt_ch4nn3l}' answer.txt",
    solution: [
      'tshark -r icmp.pcap -nn',
      "tshark -r icmp.pcap -Y 'icmp.type==8' -T fields -e ip.src -e ip.ttl -e data.data",
      'strings icmp.pcap | grep nto > answer.txt',
    ] },
  { id: 'network-module-dns',
    check: "grep -q 'nto{dns_txt_1s_4_tr34sur3_m4p}' answer.txt",
    solution: [
      'dig example.com A +short',
      'tshark -r dns.pcap -nn',
      'dig vault.corp.local TXT +short > answer.txt',
    ] },
  { id: 'network-bluetooth',
    check: "grep -q 'nto{blu3t00th_0b3x_push_ch9}' answer.txt",
    solution: [
      'hcitool scan',
      'sdptool browse 00:1A:7D:DA:71:13 | grep nto > answer.txt',
    ] },
  { id: 'network-module-analysis',
    check: "grep -q 'nto{b34c0n_c2_3xf1l_0v3r_http}' answer.txt",
    solution: [
      "nfdump -r nfcapd.202610110000 'host 10.0.0.5' -s dstip/bytes -n 5",
      'cat suricata/fast.log',
      'cat zeek/conn.log',
      'tshark -r capture.pcap -q -z follow,tcp,ascii,0 | grep nto > answer.txt',
    ] },
  { id: 'network-module-appprotos',
    check: "grep -q 'nto{pr0t0c0l_h13r4rchy_0dd_p0rt}' answer.txt",
    solution: [
      'tshark -r cap.pcap -q -z io,phs',
      'tshark -r cap.pcap -T fields -e tls.handshake.extensions_server_name',
      'tshark -r cap.pcap -Y http.request -T fields -e tcp.dstport -e http.host -e http.request.uri > answer.txt',
    ] },
  { id: 'network-module-routing',
    check: "grep -q 'nto{bgp_pr3f1x_h1j4ck_0r1g1n_65002}' answer.txt",
    solution: [
      'ip route get 10.20.30.40',
      "vtysh -c 'show bgp summary'",
      "vtysh -c 'show bgp ipv4 unicast 198.51.100.0/24'",
      'whois AS65002 | grep nto > answer.txt',
    ] },
  { id: 'network-module-services',
    check: "grep -q 'nto{mqtt_0p3n_br0k3r_l34k}' answer.txt",
    solution: [
      'nmap -sV -p 21,23,1883,3389,5900 10.0.0.1',
      "mosquitto_sub -t 'home/#' -C 5 | grep nto > answer.txt",
    ] },
  { id: 'network-module-tunnel',
    check: "grep -q 'nto{ssh_tunn3l_t0_h1dd3n_s3gm3nt}' answer.txt",
    solution: [
      "ssh user@10.10.10.5 'ip route; nmap -sn 10.10.20.0/24'",
      'proxychains4 nmap -sT -Pn -p 22,80 10.10.20.7',
      'proxychains4 curl -s http://10.10.20.7/ | grep nto > answer.txt',
    ] },
  { id: 'network-module-vpn',
    check: "grep -q 'nto{1k3_v3nd0r_1d_4ggr3ss1v3}' answer.txt",
    solution: [
      'nmap -sU -p 500,4500,1194,51820 203.0.113.10',
      'tshark -r ike.pcap -nn',
      'strings ike.pcap | grep nto > answer.txt',
    ] },
  { id: 'network-module-wireless',
    check: "grep -q 'nto{r0gu3_4p_h1dd3n_ss1d}' answer.txt",
    solution: [
      'airmon-ng start wlan0',
      'airodump-ng wlan0mon',
      'wash -i wlan0mon',
      'tshark -r wifi.pcap -nn | grep nto > answer.txt',
    ] },
  { id: 'network-tools',
    check: "grep -q 'nto{nc_b4nn3r_gr4b_4444}' answer.txt",
    solution: [
      'masscan 10.10.10.0/24 -p1-65535 --rate 1000',
      'nmap -sV -p 22,80,4444 10.10.10.5',
      'nc 10.10.10.5 4444 | grep nto > answer.txt',
    ] },
]

describe('network module labs solve end-to-end', () => {
  for (const { id, check, solution } of LABS) {
    it(id, async () => {
      const bundle = JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
      const spec = { kind: 'shell', workdir: WD, check, hints: ['a', 'b', 'c', 'd'] }
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
