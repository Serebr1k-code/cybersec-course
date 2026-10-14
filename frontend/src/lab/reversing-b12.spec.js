import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for lab batch reversing-b12.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  {
    id: "reversing-kernel-drivers", flag: "nto{k0_10ctl_0x8004a10c_s3cr3t}", hints: 4,
    solution: ["strings -n 6 vboxnetflt.ko > found.txt"],
  },
  {
    id: "reversing-embedded-rtos", flag: "nto{c0rt3x_m4_thum8_fnv_l1c3ns3}", hints: 4,
    solution: ["strings -n 4 firmware.bin > found.txt"],
  },
  {
    id: "reversing-mobile-malware", flag: "nto{uncr4ck4bl3_4ndr01d_d3x_s3cr3t}", hints: 4,
    solution: ["strings -n 5 uncrack1.apk > found.txt"],
  },
]

describe.each(LABS)('lab batch reversing-b12: $id', ({ id, flag, hints, solution }) => {
  const bundle = load(id)
  const spec = { kind: 'shell', workdir: WD, check: CHECK, hints: Array(hints).fill('h') }

  it('bundle + seed files are consistent with the lesson lab block', () => {
    expect(bundle.id).toBe(id)
    expect(bundle.workdir).toBe(WD)
    expect(bundle.fs.some((f) => f.path === `${WD}/task.md`)).toBe(true)
    expect(bundle.expect.file).toBe(`${WD}/found.txt`)
    expect(bundle.expect.contains).toBe(flag)
  })

  it('replays the intended solution and passes check', async () => {
    const s = createSession({ spec, bundle })
    expect((await s.run('check')).code).toBe(1)
    for (const cmd of solution) await s.run(cmd)
    expect((await s.run('check')).code).toBe(0)
  })
})
