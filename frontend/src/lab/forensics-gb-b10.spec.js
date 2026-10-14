import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the gB-forensics gap batch B10
// (macOS/Linux deep artifacts, mobile backups, malware, network, tooling).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'macos-persistence', flag: 'nto{l4unch4g3nt_p3rs1st3nc3}', hints: 4,
    solution: ['grep nto com.apple.softwareupdated.plist > found.txt'] },
  { id: 'macos-knowledgec', flag: 'nto{kn0wl3dg3c_us4g3}', hints: 4,
    solution: ['grep nto knowledgeC_dump.txt > found.txt'] },
  { id: 'macos-quarantine-deep', flag: 'nto{qu4r4nt1n3_0r1g1n}', hints: 4,
    solution: ['grep nto QuarantineEventsV2.txt > found.txt'] },
  { id: 'linux-auditd-deep', flag: 'nto{4ud1td_execv3_tr4c3}', hints: 4,
    solution: ['grep nto audit.log > found.txt'] },
  { id: 'linux-journald-binary', flag: 'nto{j0urn4ld_b1n4ry}', hints: 4,
    solution: ['grep nto journal_export.txt > found.txt'] },
  { id: 'forensics-ios-backup', flag: 'nto{1os_b4ckup_m4n1f3st}', hints: 4,
    solution: ['grep nto Manifest_dump.txt > found.txt'] },
  { id: 'mobile-android-backup', flag: 'nto{4ndr01d_4b_b4ckup}', hints: 4,
    solution: ['grep nto backup.ab > found.txt'] },
  { id: 'mal-dynamic-sandbox', flag: 'nto{s4ndb0x_b3h4v10r}', hints: 4,
    solution: ['grep nto report.txt > found.txt'] },
  { id: 'mal-shellcode', flag: 'nto{sh3llc0d3_3mul4t10n}', hints: 4,
    solution: ['grep nto sc_strings.txt > found.txt'] },
  { id: 'net-http2-3', flag: 'nto{http2_hpack_fr4m3s}', hints: 4,
    solution: ['grep nto h2_stream.txt > found.txt'] },
  { id: 'net-flow-beaconing', flag: 'nto{b34c0n1ng_p3r10d1c}', hints: 4,
    solution: ['grep nto flows.txt > found.txt'] },
  { id: 'tool-eric-zimmerman', flag: 'nto{ez_t00ls_pecmd}', hints: 4,
    solution: ['grep nto PECmd_out.csv > found.txt'] },
  { id: 'tool-kape', flag: 'nto{k4p3_tr14g3_c0ll3ct10n}', hints: 4,
    solution: ['grep nto kape_collection.txt > found.txt'] },
]

describe.each(LABS)('forensics gap lab B10: $id', ({ id, flag, hints, solution }) => {
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
