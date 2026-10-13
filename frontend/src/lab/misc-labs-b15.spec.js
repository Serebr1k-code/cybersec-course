import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

function loadBundle(id) {
  const p = path.resolve(process.cwd(), `../content/labs/${id}.json`)
  return JSON.parse(fs.readFileSync(p, 'utf8'))
}
function session(spec, bundle) { return createSession({ spec, bundle }) }

// Mirrors the `lab:` blocks in content/misc/misc-intro.md and
// content/misc/misc-esolang-malbolge.md.
const INTRO = {
  kind: 'shell',
  workdir: '/home/student/task',
  files: ['task.md', 'mystery'],
  check: "grep -q 'nto{' found.txt",
  hints: ['a', 'b', 'c'],
}
const MALBOLGE = {
  kind: 'shell',
  workdir: '/home/student/task',
  files: ['task.md', 'hello.mal', 'flag.mal'],
  check: "grep -q 'nto{' found.txt",
  hints: ['a', 'b', 'c'],
}

describe('misc-intro lab', () => {
  const bundle = loadBundle('misc-intro')
  const FLAG = 'nto{m1sc_1s_ab0ut_patterns_and_curiosity}'

  it('seeds the task files', async () => {
    const s = session(INTRO, bundle)
    const r = await s.run('ls')
    expect(r.stdout).toContain('mystery')
    expect(r.stdout).toContain('task.md')
  })

  it('identifies the file as ASCII text', async () => {
    const s = session(INTRO, bundle)
    expect((await s.run('file mystery')).stdout).toContain('ASCII text')
  })

  it('decodes the base64 payload', async () => {
    const s = session(INTRO, bundle)
    const r = await s.run('base64 -d mystery')
    expect(r.stdout.trim()).toBe(FLAG)
  })

  it('solves with the intended pipeline', async () => {
    const s = session(INTRO, bundle)
    expect((await s.run('check')).code).toBe(1)
    await s.run('base64 -d mystery > found.txt')
    const r = await s.run('check')
    expect(r.code).toBe(0)
    expect(s.solved).toBe(true)
  })
})

describe('misc-esolang-malbolge lab', () => {
  const bundle = loadBundle('misc-esolang-malbolge')
  const FLAG = 'nto{m4lb0lg3_1s_4ctu4lly_3mul4t4bl3}'

  it('runs the canonical Hello World', async () => {
    const s = session(MALBOLGE, bundle)
    expect((await s.run('malbolge hello.mal')).stdout).toBe('Hello World!')
  })

  it('runs the flag program and prints the flag', async () => {
    const s = session(MALBOLGE, bundle)
    expect((await s.run('malbolge flag.mal')).stdout).toBe(FLAG)
  })

  it('honestly reports unknown files', async () => {
    const s = session(MALBOLGE, bundle)
    const r = await s.run('malbolge nope.mal')
    expect(r.stdout).toContain('доступно')
  })

  it('solves only after the flag is written to found.txt', async () => {
    const s = session(MALBOLGE, bundle)
    expect((await s.run('check')).code).toBe(1)
    await s.run('malbolge flag.mal > found.txt')
    expect((await s.run('check')).code).toBe(0)
    expect(s.solved).toBe(true)
  })
})
