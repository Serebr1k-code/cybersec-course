import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the OSINT lab batch B6: each entry loads the
// REAL fixture bundle from content/labs, mirrors the `lab:` block from the
// lesson front-matter, replays the intended solution with the emulated tools,
// and asserts the lab's own `check` predicate passes. If a lab stops being
// solvable in the engine, this fails. (Fixtures captured from real
// curl/jq/python3/EDGAR/Overpass runs.)
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
