import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the OSINT lab batch B7: each entry loads the
// REAL fixture bundle from content/labs, mirrors the `lab:` block from the
// lesson front-matter, replays the intended solution with the emulated tools,
// and asserts the lab's own `check` predicate passes. If a lab stops being
// solvable in the engine, this fails. (Fixtures replay real curl/jq/exiftool/
// theHarvester/Companies House / mempool.space / PatentsView / FAA formats.)
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' answer.txt"

const LABS = [
  { id: 'osint-business-registry', solution: [
    'curl -s "https://api.company-information.service.gov.uk/search/companies?q=Example"',
    'curl -s "https://api.company-information.service.gov.uk/company/09876543/officers"',
    'curl -s "https://api.company-information.service.gov.uk/company/09876543/persons-with-significant-control"',
    'curl -s "https://api.company-information.service.gov.uk/company/11223344/persons-with-significant-control"',
    "echo 'nto{b3n3f1c14l_0wn3r_unch41n3d}' > answer.txt"] },
  { id: 'osint-blockchain', solution: [
    'curl -s "https://mempool.space/api/address/bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"',
    'curl -s "https://mempool.space/api/address/bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh/txs"',
    'curl -s "https://api.blockchair.com/bitcoin/dashboards/address/bc1qdest9k5l0p3rq7v2n8s4m6h1t3w9x0z5c7b2d4e6"',
    "echo 'nto{kyc_p01nt_0n_3xch4ng3}' > answer.txt"] },
  { id: 'osint-patents', solution: [
    'curl -s "https://search.patentsview.org/api/v1/patent/?q=Example+Inc" > patents.json',
    "jq -r '.patents[].patent_title' patents.json",
    "echo 'nto{f3d3r4t3d_l34rn1ng_3dg3}' > answer.txt"] },
  { id: 'osint-flight', solution: [
    'curl -s "https://api.adsb.lol/v2/hex/a1b2c3"',
    'curl -s "https://opensky-network.org/api/flights/aircraft?icao24=a1b2c3&begin=1700000000&end=1700086400"',
    'curl -s "https://registry.faa.gov/aircraftinquiry/Search/NNumberResult?nNumberTxt=N550GD"',
    "echo 'nto{faa_r3g1stry_0wn3r_sh3ll}' > answer.txt"] },
  { id: 'osint-maritime', solution: [
    'curl -s "https://api.vesselfinder.com/vessels?userkey=demo&imo=9300000"',
    'curl -s "https://api.vesselfinder.com/vessels?userkey=demo&imo=9300000&extended=1"',
    "echo 'nto{0ffsh0r3_0wn3r_4ttr1but3d}' > answer.txt"] },
  { id: 'osint-paste-sites', solution: [
    'curl -s "https://psbdmp.ws/api/v3/search/example.com"',
    'curl -s "https://psbdmp.ws/api/v3/dump/bXk2pQ1a" > dump.json',
    "jq -r '.data.text' dump.json",
    "echo 'nto{p4st3_l34k_d3t3ct3d}' > answer.txt"] },
  { id: 'osint-custom-tooling', solution: [
    'cat recon.py',
    'python3 recon.py example.com crtsh_example.json',
    "echo 'nto{p1p3l1n3_n0rm4l1z3d_3nt1ty}' > answer.txt"] },
  { id: 'osint-automation', solution: [
    'theHarvester -d example.com -b all -f harvest.txt',
    'grep nto harvest.txt',
    "echo 'nto{aut0m4t3d_h4rv3st_fl4g}' > answer.txt"] },
  { id: 'osint-verification', solution: [
    'exiftool viral.jpg',
    'exiftool -XMP:all viral.jpg',
    "echo 'nto{v1r4l_ph0t0_r3us3d_2020}' > answer.txt"] },
  { id: 'osint-vehicle', solution: [
    'curl -s "https://vpic.nhtsa.dot.gov/api/vehicles/decodevin/1HGCM82633A004352?format=json" > vin.json',
    'jq -r \'.Results[] | select(.Value!="") | "\\(.Variable): \\(.Value)"\' vin.json',
    "echo 'nto{v1n_d3c0d3d_0wn3r_s34rch}' > answer.txt"] },
  { id: 'osint-advanced-dorking', solution: [
    'googler --json -n 20 "site:example.com (filetype:env OR filetype:ini)"',
    'curl -sI "https://example.com/.env"',
    'curl -sI "https://example.com/old-config.php"',
    'curl -s "https://example.com/.env"',
    "echo 'nto{d0rk_200_c0nf1rm3d}' > answer.txt"] },
  { id: 'osint-browser-fingerprint', solution: [
    'curl -s "https://tls.browserleaks.com/json"',
    'curl -sI "https://example.com"',
    "echo 'nto{j43_f1ng3rpr1nt_m1sm4tch}' > answer.txt"] },
]

describe('osint labs B7 solve end-to-end', () => {
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
