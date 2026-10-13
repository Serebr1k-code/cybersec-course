import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the network lab batch B10 (12 labs).
// Each entry loads the REAL fixture bundle from content/labs, replays the
// intended solution through the emulated tools, and asserts the lab's own
// `check` + hidden `expect` both pass. Fixtures are captured from real
// tshark runs (pcaps crafted with scapy) and real nmap runs.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'

const LABS = [
  { id: 'network-tls-attacks',
    check: "grep -q 'TLSv1.0' answer.txt",
    solution: [
      'nmap -Pn -p 1010 --script ssl-enum-ciphers tls-v1-0.badssl.com',
      'echo TLSv1.0 > answer.txt',
    ] },
  { id: 'network-ldap-attacks',
    check: "grep -q 'SQLsvc_2024!' answer.txt",
    solution: [
      'tshark -r ldap.pcap -nn',
      'tshark -r ldap.pcap -V',
      'echo SQLsvc_2024! > answer.txt',
    ] },
  { id: 'network-ntp-attacks',
    check: "grep -q '203.0.113.66' answer.txt",
    solution: [
      'tshark -r ntp-amp.pcap -nn',
      'echo 203.0.113.66 > answer.txt',
    ] },
  { id: 'network-netbios-llmnr',
    check: "grep -q 'fileshare' answer.txt",
    solution: [
      'tshark -r llmnr.pcap -nn',
      'echo fileshare > answer.txt',
    ] },
  { id: 'network-radius-8021x',
    check: "grep -q 'alice' answer.txt",
    solution: [
      'tshark -r radius.pcap -nn',
      'tshark -r radius.pcap -T fields -e radius.User_Name -e radius.code',
      'echo alice > answer.txt',
    ] },
  { id: 'network-gre-vxlan',
    check: "grep -q '100' answer.txt",
    solution: [
      'tshark -r vxlan.pcap -nn',
      'tshark -r vxlan.pcap -T fields -e vxlan.vni -e ip.src -e ip.dst',
      'echo 100 > answer.txt',
    ] },
  { id: 'network-ipv6-tunneling',
    check: "grep -q '2001:db8::2' answer.txt",
    solution: [
      'tshark -r tunnel.pcap -nn',
      'tshark -r tunnel.pcap -T fields -e ipv6.src -e ipv6.dst',
      'echo 2001:db8::2 > answer.txt',
    ] },
  { id: 'network-mdns-ssdp',
    check: "grep -q 'upnp:rootdevice' answer.txt",
    solution: [
      'tshark -r discovery.pcap -nn',
      'tshark -r discovery.pcap -V',
      'echo upnp:rootdevice > answer.txt',
    ] },
  { id: 'network-mpls-vrf',
    check: "grep -q '1600' answer.txt",
    solution: [
      'tshark -r mpls.pcap -nn',
      'tshark -r mpls.pcap -T fields -e mpls.label -e ip.src -e ip.dst',
      'echo 1600 > answer.txt',
    ] },
  { id: 'network-rip-eigrp',
    check: "grep -q '10.1.1.0' answer.txt",
    solution: [
      'tshark -r rip.pcap -nn',
      'tshark -r rip.pcap -T fields -e rip.ip -e rip.netmask -e rip.metric',
      'echo 10.1.1.0 > answer.txt',
    ] },
  { id: 'network-dhcpv6',
    check: "grep -q '0001000100000000001122334455' answer.txt",
    solution: [
      'tshark -r dhcp6.pcap -nn',
      'tshark -r dhcp6.pcap -V',
      'tshark -r dhcp6.pcap -T fields -e dhcpv6.xid -e dhcpv6.duid.bytes',
      'echo 0001000100000000001122334455 > answer.txt',
    ] },
  { id: 'network-ids-suricata',
    check: "grep -q '203.0.113.45' answer.txt",
    solution: [
      'cat fast.log',
      "grep 'ET SCAN' fast.log",
      'echo 203.0.113.45 > answer.txt',
    ] },
]

describe('network labs batch B10 solve end-to-end', () => {
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
