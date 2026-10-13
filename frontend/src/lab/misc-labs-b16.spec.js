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

const INTERCAL = {
  kind: 'shell',
  workdir: '/home/student/task',
  files: ['task.md', 'hello.i', 'flag.i'],
  check: "grep -q 'nto{' found.txt",
  hints: ['a', 'b', 'c'],
}

describe('misc-esolang-intercal lab', () => {
  const bundle = loadBundle('misc-esolang-intercal')
  const FLAG = 'nto{1nt3rc4l_pl34s3_4nd_c0m3fr0m}'

  it('runs the reference hello program', async () => {
    const s = session(INTERCAL, bundle)
    expect((await s.run('ick hello.i')).stdout).toBe('hello, world\n')
  })

  it('runs the flag program', async () => {
    const s = session(INTERCAL, bundle)
    expect((await s.run('ick flag.i')).stdout).toBe(FLAG)
  })

  it('solves after writing the flag', async () => {
    const s = session(INTERCAL, bundle)
    expect((await s.run('check')).code).toBe(1)
    await s.run('ick flag.i > found.txt')
    expect((await s.run('check')).code).toBe(0)
    expect(s.solved).toBe(true)
  })
})
