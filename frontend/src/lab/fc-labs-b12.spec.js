import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the forensics/crypto lab batch (FC-12).
// Loads the REAL fixture bundles from content/labs, replays the intended
// solution with the emulated tools, and asserts `check` passes.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'forensics-intro', flag: 'nto{m4g1c_byt3s_d0nt_l13}', hints: 4,
    solution: ['unzip -l invoice.bin', 'unzip -p invoice.bin update.ps1 > update.ps1',
      'cat update.ps1', 'base64 -d update.ps1 > dec.txt', 'grep nto dec.txt > found.txt'] },
  { id: 'forensics-volatility-deep', flag: 'nto{p4g3_3x3c_1n_m3m0ry}', hints: 4,
    solution: ['vol -f mem.raw windows.pslist', 'vol -f mem.raw windows.netscan',
      'vol -f mem.raw windows.malfind --pid 4120 | grep nto > found.txt'] },
  { id: 'forensics-memory-symbols', flag: 'nto{symb0ls_unl0ck_th3_k3rn3l}', hints: 4,
    solution: ['vol -f linux.mem banners', 'vol -f linux.mem linux.pslist',
      'dwarf2json linux --system-map System.map-5.15.0-91-generic --elf vmlinux-5.15.0-91-generic > symbols/linux/5.15.0-91-generic.json',
      'vol -f linux.mem --symbol-dirs symbols linux.pslist',
      'vol -f linux.mem --symbol-dirs symbols linux.dmesg | grep nto > found.txt'] },
  { id: 'forensics-btrfs-zfs', flag: 'nto{c0w_sn4psh0t_k33ps_d3l3t3d_f1l3s}', hints: 4,
    solution: ['xxd -s 0x10000 -l 16 disk.img', 'btrfs restore -l disk.img',
      'strings disk.img | grep nto > found.txt'] },
  { id: 'forensics-vm', flag: 'nto{d3lt4_ch41n_r3v34ls_pr10r_st4t3}', hints: 4,
    solution: ['file web.vmdk', 'qemu-img info web-000001.vmdk', 'cat web.vmsd',
      'grep nto web.vmsd > found.txt'] },
  { id: 'forensics-mobile-extraction', flag: 'nto{andr01d_b4ckup_l34ks_msgst0r3}', hints: 4,
    solution: ['adb devices -l', 'adb shell pm list packages',
      'sqlite3 apps/org.thoughtcrime.securesms/databases/msgstore.db ".tables"',
      'sqlite3 apps/org.thoughtcrime.securesms/databases/msgstore.db "SELECT body FROM message" | grep nto > found.txt'] },
]

describe.each(LABS)('forensics/crypto lab: $id', ({ id, flag, hints, solution }) => {
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
