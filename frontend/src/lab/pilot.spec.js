import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end test of the PILOT lab: loads the real fixture bundle from
// content/labs and replays the intended solution with the emulated tools.
const bundlePath = path.resolve(process.cwd(), '../content/labs/forensics-file-magic.json')
const bundle = JSON.parse(fs.readFileSync(bundlePath, 'utf8'))

const FLAG = 'nto{m4g1c_byt3s_d0nt_l13}'

// Mirrors the `lab:` block in content/forensics/02-file-magic.md.
const LAB = {
  kind: 'shell',
  workdir: '/home/student/task',
  files: ['task.md', 'evidence.dat', 'notes.txt'],
  check: "grep -q 'nto{' found.txt",
  hints: ['a', 'b', 'c', 'd'],
}

function session() { return createSession({ spec: LAB, bundle }) }

describe('pilot lab: forensics-file-magic', () => {
  it('seeds the task files', async () => {
    const s = session()
    const r = await s.run('ls')
    expect(r.stdout).toContain('evidence.dat')
    expect(r.stdout).toContain('notes.txt')
    expect(r.stdout).toContain('task.md')
  })

  it('reports the polyglot exactly like real file(1)', async () => {
    const s = session()
    expect((await s.run('file evidence.dat')).stdout).toBe('evidence.dat: Zip archive, with extra data prepended\n')
    expect((await s.run('file -k evidence.dat')).stdout).toBe('evidence.dat: Zip archive, with extra data prepended\\012- data\n')
  })

  it('shows the broken PNG signature in xxd', async () => {
    const s = session()
    const r = await s.run('xxd -l 16 evidence.dat')
    expect(r.stdout).toContain('8950 4e47 0a0d 1a0a')
    expect(r.stdout).toContain('.PNG')
  })

  it('solves the lab with the intended pipeline', async () => {
    const s = session()
    const r = await s.run('strings evidence.dat | grep flag_base64 | cut -d= -f2 | base64 -d')
    expect(r.stdout.trim()).toBe(FLAG)
  })

  it('find is not fooled by the extension (flag is not in the name)', async () => {
    const s = session()
    const r = await s.run('find . -type f')
    expect(r.stdout).toContain('/home/student/task/evidence.dat')
  })

  it('replays the captured unzip fixture', async () => {
    const s = session()
    const r = await s.run('unzip -l evidence.dat')
    expect(r.stdout).toContain('readme.txt')
    expect(r.stdout).toContain('extra bytes at beginning')
    const p = await s.run('unzip -p evidence.dat readme.txt')
    expect(p.stdout).toContain('decoy')
  })

  it('passes check only once the flag is written to found.txt', async () => {
    const s = session()
    expect((await s.run('check')).code).toBe(1)
    await s.run('strings evidence.dat | grep flag_base64 | cut -d= -f2 | base64 -d > found.txt')
    const r = await s.run('check')
    expect(r.code).toBe(0)
    expect(r.stdout).toContain('Готово')
    expect(s.solved).toBe(true)
  })

  it('the check predicate from front-matter also passes', async () => {
    const s = session()
    await s.run(`echo ${FLAG} > found.txt`)
    expect((await s.run(LAB.check)).code).toBe(0)
  })
})
