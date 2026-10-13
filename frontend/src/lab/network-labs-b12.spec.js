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
