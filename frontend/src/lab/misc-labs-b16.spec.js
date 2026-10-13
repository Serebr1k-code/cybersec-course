import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

function loadBundle(id) {
  const p = path.resolve(process.cwd(), `../content/labs/${id}.json`)
  return JSON.parse(fs.readFileSync(p, 'utf8'))
}
function session(spec, bundle) { return createSession({ spec, bundle }) }

const SHAKESPEARE = {
  kind: 'shell',
  workdir: '/home/student/task',
  files: ['task.md', 'hello.spl', 'flag.spl'],
  check: "grep -q 'nto{' found.txt",
  hints: ['a', 'b', 'c'],
}

describe('misc-esolang-shakespeare lab', () => {
  const bundle = loadBundle('misc-esolang-shakespeare')
  const FLAG = 'nto{sh4k3sp34r3_sp34ks_1n_c0d3}'

  it('runs the hello play', async () => {
    const s = session(SHAKESPEARE, bundle)
    expect((await s.run('shakespeare run hello.spl')).stdout).toBe('Hello World!')
  })

  it('runs the flag play', async () => {
    const s = session(SHAKESPEARE, bundle)
    expect((await s.run('shakespeare run flag.spl')).stdout).toBe(FLAG)
  })

  it('honestly reports unknown plays', async () => {
    const s = session(SHAKESPEARE, bundle)
    expect((await s.run('shakespeare run nope.spl')).stdout).toContain('доступно')
  })

  it('solves after writing the flag', async () => {
    const s = session(SHAKESPEARE, bundle)
    expect((await s.run('check')).code).toBe(1)
    await s.run('shakespeare run flag.spl > found.txt')
    expect((await s.run('check')).code).toBe(0)
    expect(s.solved).toBe(true)
  })
})
