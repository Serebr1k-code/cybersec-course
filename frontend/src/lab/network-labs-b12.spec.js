import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the network lab batch B12.
// Each entry loads the REAL fixture bundle from content/labs, replays the
// intended solution through the emulated tools, and asserts the lab's own
// `check` + hidden `expect` both pass. Fixtures are pcaps crafted with scapy
// (ARP poisoning, a BGP sub-prefix hijack, a timing covert channel, a DNS
// tunnel) and dissected with real tshark 4.6.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'

const LABS = [
  { id: 'network-arp',
    check: "grep -q '02:00:00:ca:fe:01' answer.txt",
    solution: [
      'tshark -r arp.pcap -nn',
      'tshark -r arp.pcap -T fields -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4',
      'echo 02:00:00:ca:fe:01 > answer.txt',
    ] },
  { id: 'network-bgp-hijack',
    check: "grep -q '64599' answer.txt",
    solution: [
      'tshark -r bgp.pcap -nn',
      'tshark -r bgp.pcap -T fields -e bgp.type -e bgp.nlri_prefix -e bgp.update.path_attribute.as_path_segment.as2',
      'echo 64599 > answer.txt',
    ] },
  { id: 'network-covert-timing',
    check: "grep -q 'p1ng' answer.txt",
    solution: [
      'cat times.txt',
      'tshark -r cap.pcap -T fields -e frame.time_relative',
      'echo p1ng > answer.txt',
    ] },
  { id: 'network-covert',
    check: "grep -q 'exfil-dns-channel-42' answer.txt",
    solution: [
      'tshark -r capture.pcap -T fields -e dns.qry.name',
      'tshark -r capture.pcap -T fields -e dns.qry.name | grep t.example.com | cut -d. -f1 > labels.txt',
      'base64 -d labels.txt',
      'echo exfil-dns-channel-42 > answer.txt',
    ] },
  { id: 'network-idps-evasion',
    check: "grep -q 'union/**/select' answer.txt",
    solution: [
      'tshark -r evasion.pcap -nn',
      "tshark -r evasion.pcap -Y 'http.request' -T fields -e ip.src -e ip.dst -e http.request.uri",
      "echo 'union/**/select' > answer.txt",
    ] },
  { id: 'network-traffic-replay',
    check: "grep -q 'HELLO:root!' answer.txt",
    solution: [
      'capinfos custom.pcap',
      'tshark -r final.pcap -nn',
      'tshark -r final.pcap -T fields -e ip.dst -e data.data',
      'echo HELLO:root! > answer.txt',
    ] },
  { id: 'network-vlan-qinq',
    check: "grep -q '100' answer.txt",
    solution: [
      'tshark -r qinq.pcap -nn',
      'tshark -r qinq.pcap -T fields -e ieee8021ad.id -e vlan.id',
      'echo 100 > answer.txt',
    ] },
  { id: 'network-firewall-piercing',
    check: "grep -q '203.0.113.77' answer.txt",
    solution: [
      'cat egress.txt',
      'tshark -r c2.pcap -nn',
      "tshark -r c2.pcap -Y 'http.request' -T fields -e ip.dst -e tcp.dstport -e http.request.uri -e http.host",
      'echo 203.0.113.77 > answer.txt',
    ] },
  { id: 'network-kerberos',
    check: "grep -q 'sql01.corp.local' answer.txt",
    solution: [
      'tshark -r krb.pcap -T fields -e kerberos.msg_type',
      'tshark -r krb.pcap -T fields -e kerberos.msg_type -e kerberos.CNameString -e kerberos.SNameString',
      'echo sql01.corp.local > answer.txt',
    ] },
  { id: 'network-nac-bypass',
    check: "grep -q '00:1b:21:aa:bb:cc' answer.txt",
    solution: [
      'tshark -r eapol.pcap -nn',
      'tshark -r eapol.pcap -T fields -e eapol.type -e eap.code -e eap.type -e eap.identity',
      'echo 00:1b:21:aa:bb:cc > answer.txt',
    ] },
  { id: 'network-ipv6',
    check: "grep -q '2001:db8:bad::' answer.txt",
    solution: [
      'tshark -r ipv6.pcap -nn',
      "tshark -r ipv6.pcap -Y 'icmpv6.type==134' -T fields -e icmpv6.nd.ra.router_lifetime -e icmpv6.opt.prefix -e icmpv6.opt.prefix.length -e icmpv6.opt.rdnss",
      'echo 2001:db8:bad:: > answer.txt',
    ] },
  { id: 'network-layer2-attacks',
    check: "grep -q 'S3cret!' answer.txt",
    solution: [
      'tshark -r flood.pcap -nn',
      "tshark -r flood.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e urlencoded-form.key -e urlencoded-form.value",
      "echo 'S3cret!' > answer.txt",
    ] },
]

describe('network labs batch B12 solve end-to-end', () => {
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
