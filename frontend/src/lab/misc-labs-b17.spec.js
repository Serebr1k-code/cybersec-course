import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

function loadBundle(id) {
  const p = path.resolve(process.cwd(), `../content/labs/${id}.json`)
  return JSON.parse(fs.readFileSync(p, 'utf8'))
}
function session(spec, bundle) { return createSession({ spec, bundle }) }

function specFor(id, files) {
  return {
    kind: 'shell',
    workdir: '/home/student/task',
    files: ['task.md', ...files],
    check: "grep -q 'nto{' found.txt",
    hints: ['a', 'b', 'c'],
  }
}

const CASES = [
  { id: 'misc-cairo-starknet', artifact: 'storage.txt', flag: 'nto{c41r0_f3lt_0v3rfl0w}' },
  { id: 'misc-move-sui', artifact: 'objects.txt', flag: 'nto{m0v3_c4p4b1l1ty_c0nfus10n}' },
  { id: 'misc-cosmos-wasm', artifact: 'state.txt', flag: 'nto{c0smw4sm_1bc_4ck_c0nfus10n}' },
  { id: 'misc-rust-solana', artifact: 'accounts.txt', flag: 'nto{s0l4n4_4cc0unt_c0nfus10n}' },
]

for (const c of CASES) {
  describe(`${c.id} lab`, () => {
    const bundle = loadBundle(c.id)
    const spec = specFor(c.id, [c.artifact])

    it('seeds the artifact and task', async () => {
      const s = session(spec, bundle)
      const r = await s.run(`cat ${c.artifact}`)
      expect(r.stdout).toContain('flag:')
    })

    it('is not solved before writing found.txt', async () => {
      const s = session(spec, bundle)
      expect((await s.run('check')).code).toBe(1)
    })

    it('solves via cut + base64 -d', async () => {
      const s = session(spec, bundle)
      await s.run(`grep flag ${c.artifact} | cut -d: -f2 | base64 -d > found.txt`)
      expect((await s.run('check')).code).toBe(0)
      expect(s.solved).toBe(true)
      expect((await s.run('cat found.txt')).stdout.trim()).toBe(c.flag)
    })
  })
}
