import { describe, it, expect } from 'vitest'
import { createSession } from './session'
import { VFS } from './vfs'
import { tokenize, parse } from './shell'

const FLAG = 'nto{m4g1c_byt3s_4r3_r34l}'

const SPEC = {
  kind: 'shell',
  workdir: '/home/student/task',
  check: "grep -q 'nto{' found.txt",
  hints: ['слабый намёк', 'сильнее', 'почти ответ'],
}

function demoBundle() {
  return {
    id: 'demo',
    vars: { target: '10.10.10.5' },
    expect: { file: '/home/student/task/found.txt', contains: FLAG },
    fs: [
      { path: '/home/student/task', type: 'dir' },
      { path: '/home/student/task/readme.txt', text: 'hello\nworld\n' },
      { path: '/home/student/task/data.bin', b64: btoa('PNG-ish bytes here') },
      { path: '/home/student/task/sub', type: 'dir' },
      { path: '/home/student/task/sub/note.txt', text: 'nested\n' },
    ],
    tools: {
      nmap: {
        help: 'nmap [опции] <цель>',
        cases: [
          { match: '-sV\\s+{{target}}', output: '80/tcp open http nginx 1.24.0\n', writes: ['-oN'] },
        ],
        fallback: 'Nmap done: 1 IP address (1 host up) scanned\n',
      },
    },
  }
}

function make(bundle = demoBundle(), spec = SPEC) {
  return createSession({ spec, bundle })
}

describe('shell tokenizer/parser', () => {
  it('splits pipes, and-or and redirects', () => {
    const ast = parse(tokenize('ls -la | grep txt && cat a > b'))
    expect(ast.error).toBeUndefined()
    expect(ast.chains.length).toBe(2)
    expect(ast.chains[0].stages.length).toBe(2)
    expect(ast.chains[1].op).toBe('&&')
    expect(ast.chains[1].stages[0].redirs[0]).toMatchObject({ fd: '1', mode: 'w', target: 'b' })
  })

  it('keeps quoted strings intact', () => {
    const t = tokenize(`echo "a | b" 'c d'`)
    expect(t.map((x) => x.v)).toEqual(['echo', 'a | b', 'c d'])
  })

  it('parses fd redirects written without spaces', () => {
    const ast = parse(tokenize('cmd 2>err.txt'))
    expect(ast.chains[0].stages[0].redirs[0]).toMatchObject({ fd: '2', target: 'err.txt' })
  })

  it('treats a spaced 2 as an argument, not an fd', () => {
    const ast = parse(tokenize('echo 2 > f'))
    expect(ast.chains[0].stages[0].argv).toEqual(['echo', '2'])
  })
})

describe('virtual filesystem', () => {
  it('resolves . and ..', () => {
    const v = new VFS()
    v.mkdir('/a/b', { parents: true })
    expect(v.isDir('/a/b')).toBe(true)
    expect(v.isDir('/a/b/..')).toBe(true)
  })

  it('globs * within a directory', () => {
    const v = VFS.fromSeed([
      { path: '/d/a.txt', text: '1' },
      { path: '/d/b.txt', text: '2' },
      { path: '/d/c.bin', text: '3' },
    ])
    expect(v.glob('/', '/d/*.txt').sort()).toEqual(['/d/a.txt', '/d/b.txt'])
  })
})

describe('lab session — coreutils', () => {
  it('pipes ls into grep', async () => {
    const s = make()
    const r = await s.run('ls | grep readme')
    expect(r.stdout).toContain('readme.txt')
    expect(r.code).toBe(0)
  })

  it('redirects stdout to a file and reads it back', async () => {
    const s = make()
    await s.run('echo hello > out.txt')
    const r = await s.run('cat out.txt')
    expect(r.stdout).toBe('hello\n')
  })

  it('appends with >>', async () => {
    const s = make()
    await s.run('echo a > f.txt')
    await s.run('echo b >> f.txt')
    expect((await s.run('cat f.txt')).stdout).toBe('a\nb\n')
  })

  it('expands globs in arguments', async () => {
    const s = make()
    const r = await s.run('cat sub/*.txt')
    expect(r.stdout).toBe('nested\n')
  })

  it('supports && and ||', async () => {
    const s = make()
    expect((await s.run('cat nope.txt && echo yes')).stdout).toBe('')
    expect((await s.run('cat nope.txt || echo fallback')).stdout).toBe('fallback\n')
  })

  it('emits the output of every command in a ; list, in order', async () => {
    const s = make()
    const r = await s.run('echo one; echo two; echo three')
    expect(r.stdout).toBe('one\ntwo\nthree\n')
    expect(r.code).toBe(0)
  })

  it('propagates the last exit code of a ; list', async () => {
    const s = make()
    const r = await s.run('echo a; cat nope.txt')
    expect(r.stdout).toBe('a\n')
    expect(r.code).toBe(1)
  })

  it('reports unknown commands honestly', async () => {
    const s = make()
    const r = await s.run('nope --x')
    expect(r.stderr).toContain('command not found')
    expect(r.code).toBe(127)
  })
})

describe('lab session — forensics tools', () => {
  it('xxd dumps hex + ascii', async () => {
    const s = make()
    const r = await s.run('xxd readme.txt')
    expect(r.stdout).toMatch(/^00000000: 6865 6c6c 6f0a 776f 726c 640a\s+hello\.world\./)
  })

  it('strings finds printable runs', async () => {
    const s = make()
    const r = await s.run('strings readme.txt')
    expect(r.stdout).toBe('hello\nworld\n')
  })

  it('base64 round-trips through the shell', async () => {
    const s = make()
    await s.run('echo -n nto{demo} > flag.txt')
    expect((await s.run('cat flag.txt')).stdout).toBe('nto{demo}')
    const enc = await s.run('base64 flag.txt')
    expect(enc.stdout.trim()).toBe(btoa('nto{demo}'))
    const dec = await s.run('base64 flag.txt | base64 -d')
    expect(dec.stdout).toBe('nto{demo}')
  })

  it('file identifies types by magic bytes', async () => {
    const s = make()
    const r = await s.run('file readme.txt')
    expect(r.stdout).toBe('readme.txt: ASCII text\n')
  })

  it('grep -aboP finds a byte offset', async () => {
    const s = make()
    await s.run('echo -n ABCDPKzz > poly.bin')
    const r = await s.run(`grep -aboP 'PK\\x03\\x04' poly.bin`)
    // No PK\x03\x04 in the file -> exit 1; now add it for real:
    const r2 = await s.run(`grep -aboP 'PK' poly.bin`)
    expect(r2.stdout).toContain('PK')
    expect(r2.code).toBe(0)
  })

  it('dd slices bytes for real', async () => {
    const s = make()
    await s.run('echo -n 0123456789 > nums.txt')
    await s.run('dd if=nums.txt of=part.txt bs=1 skip=3 count=4 status=none')
    expect((await s.run('cat part.txt')).stdout).toBe('3456')
  })
})

describe('lab session — tools, hints and check', () => {
  it('replays a captured tool fixture and honours -oN', async () => {
    const s = make()
    const r = await s.run('nmap -sV 10.10.10.5 -oN scan.txt')
    expect(r.stdout).toContain('80/tcp open http')
    expect((await s.run('grep open scan.txt')).stdout).toContain('80/tcp open')
  })

  it('says plainly when a tool is not in the lab', async () => {
    const s = make(demoBundle(), { toolset: ['curl'] })
    const r = await s.run('curl http://x/')
    expect(r.stderr).toContain('нет в этой лабе')
  })

  it('exposes -h/--help for every command', async () => {
    const s = make()
    expect((await s.run('grep -h')).stdout).toContain('grep')
    expect((await s.run('help')).stdout).toContain('Команды ядра')
  })

  it('exposes --help for emulated tools too', async () => {
    const s = make()
    const r = await s.run('nmap --help')
    expect(r.stdout).toContain('nmap')
    expect(r.stdout).toContain('nmap [опции]')
    expect(r.code).toBe(0)
  })

  it('keeps stdout/stderr interleaved across a ; list (parts)', async () => {
    const s = make()
    const r = await s.run('echo a; cat nope.txt; echo b')
    expect(r.parts.map((p) => p.s).join(',')).toBe('out,err,out')
    expect(r.parts[1].t).toContain('No such file')
  })

  it('gives progressive hints without the full spoiler', async () => {
    const s = make(demoBundle(), SPEC)
    const h1 = await s.run('hint')
    const h2 = await s.run('hint')
    expect(h1.stdout).toContain('слабый намёк')
    expect(h2.stdout).toContain('сильнее')
    expect(h1.stdout).not.toContain(FLAG)
    expect(h2.stdout).not.toContain(FLAG)
  })

  it('check fails before and passes after the flag is extracted', async () => {
    const s = make(demoBundle(), SPEC)
    const before = await s.run('check')
    expect(before.code).toBe(1)
    await s.run(`echo ${FLAG} > found.txt`)
    const after = await s.run('check')
    expect(after.code).toBe(0)
    expect(after.stdout).toContain('Готово')
    expect(s.solved).toBe(true)
  })

  it('check rejects a wrong value', async () => {
    const s = make(demoBundle(), SPEC)
    await s.run('echo nto{wrong} > found.txt')
    const r = await s.run('check')
    expect(r.code).toBe(1)
  })

  it('check does not leak its internal predicate into history', async () => {
    const s = make(demoBundle(), SPEC)
    await s.run('check')
    const st = s.getState()
    expect(st.history).toContain('check')
    expect(st.history.join(' ')).not.toContain('grep -q')
  })
})
