import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the network lab batch B13.
// Each entry loads the REAL fixture bundle from content/labs, replays the
// intended solution through the emulated tools, and asserts the lab's own
// `check` + hidden `expect` both pass. Fixtures are pcaps crafted with scapy
// (TCP handshake, Ethernet/VLAN, HTTP, MQTT, OSPF hello, an 802.11 beacon,
// a WPA2 4-way handshake, a WPA3 SAE exchange, an evil-twin pair, an
// 802.15.4/Zigbee frame, a BLE HCI/ATT exchange) plus a MIFARE Classic dump;
// all dissected with real tshark 4.6.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'

const LABS = [
  { id: 'network-tcpip',
    check: "grep -q '443' answer.txt",
    solution: [
      'tshark -r tcpip.pcap -nn',
      'tshark -r tcpip.pcap -T fields -e ip.src -e tcp.srcport -e tcp.dstport -e tcp.flags',
      'echo 443 > answer.txt',
    ] },
  { id: 'network-ethernet',
    check: "grep -q '02:aa:bb:cc:dd:ee' answer.txt",
    solution: [
      'tshark -r ethernet.pcap -nn',
      'tshark -r ethernet.pcap -T fields -e eth.src -e eth.dst -e eth.type -e vlan.id',
      'echo 02:aa:bb:cc:dd:ee > answer.txt',
    ] },
  { id: 'network-intro',
    check: "grep -q 'example.com' answer.txt",
    solution: [
      'tshark -r http.pcap -nn',
      "tshark -r http.pcap -Y 'http.request' -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri -e http.user_agent",
      'echo example.com > answer.txt',
    ] },
  { id: 'network-iot-messaging',
    check: "grep -q 'home/livingroom/temp' answer.txt",
    solution: [
      'tshark -r mqtt.pcap -nn',
      'tshark -r mqtt.pcap -T fields -e mqtt.msgtype -e mqtt.clientid -e mqtt.topic',
      'echo home/livingroom/temp > answer.txt',
    ] },
  { id: 'network-routing',
    check: "grep -q '2.2.2.2' answer.txt",
    solution: [
      'tshark -r ospf.pcap -nn',
      'tshark -r ospf.pcap -T fields -e ospf.msg -e ospf.srcrouter -e ospf.area_id -e ospf.hello.hello_interval -e ospf.hello.designated_router',
      'echo 2.2.2.2 > answer.txt',
    ] },
  { id: 'network-wireless-80211',
    check: "grep -q 'HomeWiFi' answer.txt",
    solution: [
      'tshark -r wifi.pcap -nn',
      'tshark -r wifi.pcap -T fields -e wlan.bssid -e wlan.ssid -e wlan.ds.current_channel',
      'echo HomeWiFi > answer.txt',
    ] },
  { id: 'network-wpa2-attacks',
    check: "grep -q 'aa:bb:cc:11:22:33' answer.txt",
    solution: [
      'tshark -r eapol.pcap -nn',
      'tshark -r eapol.pcap -T fields -e wlan.bssid -e wlan.ta -e eapol.type -e eapol.keydes.replay_counter',
      'echo aa:bb:cc:11:22:33 > answer.txt',
    ] },
  { id: 'network-wpa3',
    check: "grep -q 'SAE' answer.txt",
    solution: [
      'tshark -r wpa3.pcap -nn',
      'tshark -r wpa3.pcap -T fields -e wlan.fixed.auth.alg -e wlan.fixed.sae_message_type',
      'echo SAE > answer.txt',
    ] },
  { id: 'network-evil-twin',
    check: "grep -q 'de:ad:be:ef:00:01' answer.txt",
    solution: [
      'tshark -r eviltwin.pcap -nn',
      'tshark -r eviltwin.pcap -T fields -e wlan.bssid -e wlan.ssid -e wlan.fixed.capabilities.privacy',
      'echo de:ad:be:ef:00:01 > answer.txt',
    ] },
  { id: 'network-zigbee-zwave',
    check: "grep -q '0x1a2b' answer.txt",
    solution: [
      'tshark -r zigbee.pcap -nn',
      'tshark -r zigbee.pcap -T fields -e wpan.dst_pan -e wpan.src16 -e zbee_aps.cluster -e zbee_aps.profile',
      'echo 0x1a2b > answer.txt',
    ] },
  { id: 'network-ble-attacks',
    check: "grep -q 'AcmeTag-7' answer.txt",
    solution: [
      'tshark -r ble.pcap -nn',
      'tshark -r ble.pcap -T fields -e btatt.opcode -e btatt.handle -e btatt.value',
      'echo AcmeTag-7 > answer.txt',
    ] },
  { id: 'network-nfc-rfid',
    check: "grep -q '04:a1:b2:c3' answer.txt",
    solution: [
      'ls -la',
      'xxd -l 32 card.mfd',
      'echo 04:a1:b2:c3 > answer.txt',
    ] },
]

describe('network labs batch B13 solve end-to-end', () => {
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
