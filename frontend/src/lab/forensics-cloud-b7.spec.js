import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the gB-forensics gap batch B7 (cloud K + macOS D + mobile E).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'cloud-m365-ual', flag: 'nto{m365_ual_1nb0xrul3_b3c}', hints: 4,
    solution: ['grep nto ual.log > found.txt'] },
  { id: 'cloud-okta', flag: 'nto{okta_syst3m_l0g_mf4_push}', hints: 4,
    solution: ['grep nto okta.log > found.txt'] },
  { id: 'cloud-salesforce', flag: 'nto{sal3sf0rc3_3v3ntl0g_3xf1l}', hints: 4,
    solution: ['grep nto sf.log > found.txt'] },
  { id: 'cloud-iam', flag: 'nto{cloud1am_cr3at3acc3ssk3y}', hints: 4,
    solution: ['grep nto cloudtrail.log > found.txt'] },
  { id: 'macos-keychain', flag: 'nto{mac0s_k3ych41n_g3np_db}', hints: 4,
    solution: ['strings login.keychain-db | grep nto > found.txt'] },
  { id: 'macos-tcc', flag: 'nto{mac0s_tcc_fulld1sk4cc3ss}', hints: 4,
    solution: ['strings TCC.db | grep nto > found.txt'] },
  { id: 'macos-unified-log-deep', flag: 'nto{mac0s_un1f13d_l0g_trac3v3}', hints: 4,
    solution: ['strings system.logarchive | grep nto > found.txt'] },
  { id: 'mobile-android-fbe', flag: 'nto{andr01d_fb3_k3yst0r3_bfu}', hints: 4,
    solution: ['strings fbe.meta | grep nto > found.txt'] },
  { id: 'mobile-ios-unifiedlog', flag: 'nto{10s_un1f13d_l0g_tr4c3v3}', hints: 4,
    solution: ['strings ios.logarchive | grep nto > found.txt'] },
]

describe.each(LABS)('forensics cloud/mac/mobile gap lab: $id', ({ id, flag, hints, solution }) => {
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
