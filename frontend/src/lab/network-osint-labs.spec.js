import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the NETWORK and OSINT labs: each entry loads
// the REAL fixture bundle from content/labs, mirrors the `lab:` block from the
// lesson front-matter, replays the intended solution with the emulated tools,
// and asserts `check` passes. If a lab stops being solvable in the engine, this
// fails. (Fixtures are captured from real tshark/curl/openssl runs.)
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q '' answer.txt"

const LABS = [
  { id: 'network-ipsec-ike', solution: [
    'tshark -r ike.pcap -Y isakmp -T fields -e isakmp.version -e isakmp.exchangetype',
    "tshark -r ike.pcap -Y 'isakmp.exchangetype==4' -T fields -e isakmp.version -e isakmp.exchangetype -e isakmp.id.data.fqdn",
    'echo client@corp.local > answer.txt'] },
  { id: 'network-openvpn', solution: [
    'tshark -r vpn.pcap -T fields -e openvpn.opcode', 'echo 7 > answer.txt'] },
  { id: 'network-wireguard', solution: [
    'tshark -r vpn.pcap -T fields -e wg.type', 'echo 4 > answer.txt'] },
  { id: 'network-quic', solution: [
    'tshark -r q.pcap -Y quic -T fields -e quic.long.packet_type',
    "tshark -r q.pcap -Y 'quic.long.packet_type==0' -T fields -e quic.dcid",
    'echo 5c8a3f1e2b4d > answer.txt'] },
  { id: 'network-http2-attacks', solution: [
    'tshark -r h2.pcap', 'tshark -r h2.pcap -T fields -e http2.type', 'echo 3 > answer.txt'] },
  { id: 'network-db-protocols', solution: [
    'tshark -r pg.pcap -Y pgsql -T fields -e pgsql.parameter_name -e pgsql.parameter_value',
    'echo postgres > answer.txt'] },
  { id: 'network-usb-pcap', solution: [
    'tshark -r usb.pcap -T fields -e usb.device_address -e usb.endpoint_address',
    'tshark -r usb.pcap -T fields -e usb.capdata', 'cat keymap.txt', 'echo flag > answer.txt'] },
  { id: 'network-protocol-reversing', solution: [
    'tshark -r custom.pcap -z follow,tcp,ascii,0', 'echo XPRT > answer.txt'] },
  { id: 'network-frag-attacks', solution: [
    "tshark -r frag.pcap -Y 'ip.flags.mf==1 || ip.frag_offset>0' -T fields -e ip.id -e ip.flags.mf -e ip.frag_offset -e ip.len",
    'echo 0x3039 > answer.txt'] },
  { id: 'network-icmp-deep', solution: [
    'tshark -r icmp.pcap -Y icmp -T fields -e icmp.type', 'echo 3 > answer.txt'] },
  { id: 'network-udp-deep', solution: [
    'tshark -r amp.pcap -Y dns -T fields -e ip.src -e ip.dst -e udp.length -e dns.qry.name',
    'echo 2078 > answer.txt'] },
  { id: 'network-tcp-hijacking', solution: [
    "tshark -o tcp.relative_sequence_numbers:FALSE -r hijack.pcap -Y 'tcp.port==23' -T fields -e ip.src -e tcp.seq -e tcp.ack -e tcp.len",
    'echo 1020 > answer.txt'] },
  { id: 'osint-wellknown-files', solution: [
    'curl -s https://app.example.com/robots.txt',
    'curl -s https://app.example.com/robots.txt | grep Disallow',
    'echo /api/internal/ > answer.txt'] },
  { id: 'osint-url-analysis', solution: [
    'cat url.txt', 'cut -d@ -f2 url.txt', 'cut -d@ -f2 url.txt | cut -d: -f1',
    'echo example.com.evil.example > answer.txt'] },
  { id: 'osint-cdn-origin', solution: [
    'tshark -r dns.pcap -Y dns -T fields -e ip.src -e ip.dst -e dns.qry.name -e dns.a',
    'curl -sI https://api.example.com', 'echo 203.0.113.10 > answer.txt'] },
  { id: 'osint-tls-fingerprint', solution: [
    'openssl x509 -in cert.pem -noout -subject -issuer -dates -ext subjectAltName',
    'echo origin.example.com > answer.txt'] },
  { id: 'osint-tracking-ids', solution: [
    'curl -s https://app.example.com/',
    'curl -s https://app.example.com/ | grep -i UA-', 'echo UA-241659-3 > answer.txt'] },
]

describe('network + osint labs solve end-to-end', () => {
  for (const { id, solution } of LABS) {
    it(id, async () => {
      const bundle = JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
      const spec = { kind: 'shell', workdir: WD, check: CHECK, hints: ['a', 'b', 'c'] }
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
