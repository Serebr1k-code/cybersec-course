import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

const ROOT = path.resolve(process.cwd(), '../content/labs')
const load = (id) => JSON.parse(fs.readFileSync(path.join(ROOT, id + '.json'), 'utf8'))

const LABS = {
  'pwn-browser': { steps: ['cat debugprint.txt'], answer: 'type=JS_OBJECT_TYPE' },
  'pwn-musl': { steps: ['readelf -d chall'], answer: 'needed=0' },
  'pwn-symbolic-angr': { steps: ['python3 solve.py'], answer: 'x=1337' },
  'pwn-qemu-user': { steps: ['readelf --file-header armvuln'], answer: 'machine=ARM' },
  'pwn-qiling-emulation': { steps: ['python3 emulate.py'], answer: 'syscall=4004' },
}

describe('pwn labs batch B7 end-to-end (browser/musl/symbolic/qemu/qiling)', () => {
  for (const [id, spec] of Object.entries(LABS)) {
    it(`${id} solves`, async () => {
      const bundle = load(id)
      expect(bundle.expect.contains).toBe(spec.answer)
      const lab = {
        kind: 'shell', workdir: bundle.workdir, files: [],
        check: `grep -q '${spec.answer}' answer.txt`, hints: ['a', 'b', 'c'],
      }
      const s = createSession({ spec: lab, bundle })
      for (const step of spec.steps) {
        const r = await s.run(step)
        expect(r.stderr, `${id}: ${step} -> ${r.stderr}`).not.toContain('command not found')
        expect(r.stderr, `${id}: ${step} -> ${r.stderr}`).not.toContain('нет в этой лабе')
      }
      await s.run('echo wrong > answer.txt')
      const bad = await s.run('check')
      expect(bad.stdout).not.toContain('✓')
      await s.run(`echo ${spec.answer} > answer.txt`)
      const c = await s.run('check')
      expect(c.stdout, `${id}: check=${c.stdout}`).toContain('✓')
      expect(c.stdout).not.toContain('✗')
    })
  }
})
