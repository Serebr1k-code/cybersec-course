import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the stego TEXT/UNICODE lab batch (STEGO-4 txt1):
// snow (trailing whitespace), homoglyph alphabets, Unicode Tags block, bidi controls.
// Loads the REAL fixture bundles from content/labs, replays the intended solution
// with the emulated tools, and asserts `check` passes.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'stego-snow', flag: 'nto{sn0w_tr41l1ng_sp4c3}', hints: 3,
    solution: ['python3 snow.py | grep nto > found.txt'] },
  { id: 'stego-homoglyph', flag: 'nto{h0m0glyph_4lph4b3t}', hints: 3,
    solution: ['python3 homoglyph.py | grep nto > found.txt'] },
  { id: 'stego-unicode-tags', flag: 'nto{unicode_tags_block}', hints: 4,
    solution: ['python3 tags.py | grep nto > found.txt'] },
  { id: 'stego-bidi-control', flag: 'nto{b1d1_c0ntr0l_byt3s}', hints: 3,
    solution: ['python3 bidi.py | grep nto > found.txt'] },
]

describe.each(LABS)('stego text-unicode lab: $id', ({ id, flag, hints, solution }) => {
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
    expect((await s.run('check')).code).toBe(1) // not solved yet
    for (const cmd of solution) await s.run(cmd)
    expect((await s.run('check')).code).toBe(0)
  })

  it('rejects a wrong answer', async () => {
    const s = createSession({ spec, bundle })
    await s.run("echo 'nto{wrong_flag}' > found.txt")
    expect((await s.run('check')).code).toBe(1)
  })
})
