import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the OSINT lab batch B6: each entry loads the
// REAL fixture bundle from content/labs, mirrors the `lab:` block from the
// lesson front-matter, replays the intended solution with the emulated tools,
// and asserts the lab's own `check` predicate passes. If a lab stops being
// solvable in the engine, this fails. (Fixtures captured from real
// curl/jq/python3/EDGAR/Overpass/Censys/urlscan/Wayback runs.)
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' answer.txt"

const LABS = [
  { id: 'osint-chronolocation', solution: [
    'cat shadow.txt',
    'python3 sun.py',
    'python3 sun.py 09:40',
    "echo 'nto{sh4d0w_4z1muth_0940}' > answer.txt"] },
  { id: 'osint-geo-tools', solution: [
    'cat overpass.json',
    "jq -r '.elements[] | select(.tags.man_made==\"surveillance\") | .tags.operator' overpass.json",
    "echo 'nto{0v3rp455_surv3ll4nc3_n0d3}' > answer.txt"] },
  { id: 'osint-sec-filings', solution: [
    'grep 10-K filings.json',
    'curl -s "https://www.sec.gov/Archives/edgar/data/1234567/000123456725000042/ex21.htm"',
    "echo 'nto{3x1b1t21_subs1d14ry_l1st}' > answer.txt"] },
  { id: 'osint-threat-intel', solution: [
    'cat stix.json',
    "jq -r '.objects[] | select(.type==\"indicator\") | .pattern' stix.json",
    "echo 'nto{st1x_1nd1c4t0r_t3rm}' > answer.txt"] },
  { id: 'osint-infrastructure', solution: [
    'cat censys.json',
    "jq '{names:[.result.services[].tls.certificates.leaf_data.names[]?]}' censys.json",
    "echo 'nto{c3nsys_s4n_3num}' > answer.txt"] },
  { id: 'osint-search-engines', solution: [
    'cat urlscan.json',
    "jq -r '.results[].page.url' urlscan.json",
    "echo 'nto{urlsc4n_p1v0t_d0m41n}' > answer.txt"] },
  { id: 'osint-ai-assisted', solution: [
    'cat llm_output.json',
    'python3 validate.py llm_output.json',
    "echo 'nto{llm_v4l1d4t3_3nt1ty}' > answer.txt"] },
  { id: 'osint-maltego', solution: [
    'python3 transform.py example.com crtsh_example.json',
    "echo 'nto{tr4nsf0rm_p1v0t_gr4ph}' > answer.txt"] },
  { id: 'osint-shadow-analysis', solution: [
    'cat measurements.txt',
    'python3 pysolar.py',
    'python3 pysolar.py 15',
    "echo 'nto{sh4d0w_3l3v45_4z225}' > answer.txt"] },
  { id: 'osint-public-records', solution: [
    'cat gleif.json',
    "jq -r '.data[].attributes.ultimateParent.entity.legalName' gleif.json",
    "echo 'nto{r3g1stry_ub0_ch41n}' > answer.txt"] },
  { id: 'osint-search-vertical', solution: [
    'cat cdx.json',
    "jq -r '.[] | .[2]' cdx.json",
    "echo 'nto{cdx_4rch1v3_p1v0t}' > answer.txt"] },
  { id: 'osint-reporting', solution: [
    'sha256sum -c page.sha256',
    'cat page.html',
    "echo 'nto{3v1d3nc3_h4sh_m1sm4tch}' > answer.txt"] },
]

describe('osint labs B6 solve end-to-end', () => {
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
