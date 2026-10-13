import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the network lab batch B11 (12 labs).
// Each entry loads the REAL fixture bundle from content/labs, replays the
// intended solution through the emulated tools, and asserts the lab's own
// `check` + hidden `expect` both pass. Fixtures are captured from real tshark
// runs over pcaps crafted with scapy, plus real Zeek TSV logs.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'

const LABS = [
  { id: 'network-lldp-cdp',
    check: "grep -q 'core-sw-01' answer.txt",
    solution: [
      'tshark -r discovery.pcap -nn',
      'tshark -r discovery.pcap -T fields -e lldp.tlv.system.name -e cdp.deviceid',
      'echo core-sw-01 > answer.txt',
    ] },
  { id: 'network-mitm',
    check: "grep -q 'Str1pped-2-plain' answer.txt",
    solution: [
      'tshark -r mitm.pcap -nn',
      'tshark -r mitm.pcap -T fields -e urlencoded-form.key -e urlencoded-form.value',
      'echo Str1pped-2-plain > answer.txt',
    ] },
  { id: 'network-netflow',
    check: "grep -q '198.51.100.66' answer.txt",
    solution: [
      'tshark -r netflow.pcap -nn',
      'tshark -r netflow.pcap -T fields -e cflow.srcaddr -e cflow.dstaddr -e cflow.dstport -e cflow.octets',
      'echo 198.51.100.66 > answer.txt',
    ] },
  { id: 'network-ntlm-relay',
    check: "grep -q 'svc_backup' answer.txt",
    solution: [
      'tshark -r ntlm.pcap -nn',
      'tshark -r ntlm.pcap -T fields -e ntlmssp.auth.username -e ntlmssp.auth.domain',
      'echo svc_backup > answer.txt',
    ] },
  { id: 'network-pppoe',
    check: "grep -q 'S3cretPPP' answer.txt",
    solution: [
      'tshark -r pppoe.pcap -nn',
      'tshark -r pppoe.pcap -V',
      'echo S3cretPPP > answer.txt',
    ] },
  { id: 'network-sstp-l2tp',
    check: "grep -q 'branch-office-01' answer.txt",
    solution: [
      'tshark -r l2tp.pcap -nn',
      'tshark -r l2tp.pcap -T fields -e l2tp.tunnel -e l2tp.avp.host_name',
      'echo branch-office-01 > answer.txt',
    ] },
  { id: 'network-stp-deep',
    check: "grep -q '02:00:00:de:ad:01' answer.txt",
    solution: [
      'tshark -r stp.pcap -nn',
      'tshark -r stp.pcap -T fields -e stp.root.prio -e stp.root.hw',
      'echo 02:00:00:de:ad:01 > answer.txt',
    ] },
  { id: 'network-tor',
    check: "grep -q 'TorRelayFrankfurt' answer.txt",
    solution: [
      'tshark -r tor.pcap -T fields -e ip.dst -e tcp.dstport',
      'grep 185.220.101 relays.txt',
      'echo TorRelayFrankfurt > answer.txt',
    ] },
  { id: 'network-vlan-hopping',
    check: "grep -q '666' answer.txt",
    solution: [
      'tshark -r vlan.pcap -nn',
      'tshark -r vlan.pcap -T fields -e vlan.id',
      'echo 666 > answer.txt',
    ] },
  { id: 'network-vnc-rdp',
    check: "grep -q '003.008' answer.txt",
    solution: [
      'tshark -r vnc.pcap -nn',
      'tshark -r vnc.pcap -T fields -e vnc.server_proto_ver -e vnc.security_type',
      'echo 003.008 > answer.txt',
    ] },
  { id: 'network-zeek',
    check: "grep -q '10.0.0.66' answer.txt",
    solution: [
      'cat notice.log',
      'grep Scan notice.log',
      'grep 203.0.113.9 conn.log',
      'echo 10.0.0.66 > answer.txt',
    ] },
  { id: 'network-arp-deep',
    check: "grep -q '02:00:00:de:ad:01' answer.txt",
    solution: [
      'tshark -r arp.pcap -nn',
      'tshark -r arp.pcap -T fields -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4',
      'echo 02:00:00:de:ad:01 > answer.txt',
    ] },
]

describe('network labs batch B11 solve end-to-end', () => {
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
