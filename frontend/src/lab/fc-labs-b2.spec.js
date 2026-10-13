import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the forensics/crypto lab batch FC-2.
// Loads the REAL fixture bundles from content/labs, replays the intended
// solution with the emulated tools, and asserts `check` passes.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'crypto-rsa-padding', flag: 'nto{pkcs1_v15_3_s1gn4tur3_f0rg3ry}', script: 'forge.py' },
  { id: 'crypto-rsa-bleichenbacher', flag: 'nto{bl31ch3nb4ch3r_p4dd1ng_0r4cl3}', script: 'bleich.py' },
  { id: 'crypto-ecdsa-advanced', flag: 'nto{p0hl1g_h3llm4n_sm00th_0rd3r_ad3c0c0de}', script: 'pohlig.py' },
  { id: 'crypto-wifi-wpa', flag: 'nto{wpa2_psk_sunshine2024}', script: 'crack.py' },
  { id: 'crypto-continued-fractions', flag: 'nto{w13n3r_5m4ll_d_c0nt1nu3d_fr4ct10n5}', script: 'wiener.py' },
  { id: 'crypto-ccm-aead', flag: 'nto{cbc_m4c_l3ngth_3xt3n510n_f0rg3ry}', script: 'forge.py' },
  { id: 'crypto-php-mtrand', flag: 'nto{4212541441_134231623}', script: 'java_random.py' },
  { id: 'forensics-registry-hives', flag: 'nto{s4m_h1v3_us3r_h4sh3s_r3c0v3r3d}', script: 'parse_hive.py' },
  { id: 'forensics-ext4-journal', flag: 'nto{ext4_1n0d3_3xt3nt_tr33_w4lk3d}', script: 'ext4_walk.py' },
  { id: 'forensics-evtx-deep', flag: 'nto{sysmon_pr0c3ss_cr34t3_p0w3rsh3ll}', script: 'parse_evtx.py' },
  { id: 'forensics-email-pst', flag: 'nto{pst_4tt4chm3nt_b64_d3c0d3d}', script: 'parse_eml.py' },
  { id: 'forensics-disk-encryption', flag: 'nto{luks1_aes_xts-plain64_64_sha256}', script: 'parse_luks.py' },
  { id: 'forensics-usn', flag: 'nto{usnjrnl_r3n4m3_p41r_r3c0v3r3d}', script: 'parse_usn.py' },
  { id: 'forensics-shellbags', flag: 'nto{us3r4ss1st_r0t13_sh3llb4g}', script: 'parse_userassist.py' },
  { id: 'forensics-tls-decrypt', flag: 'nto{tls12_k3yl0g_r3c0rd_d3crypt3d}', script: 'decrypt_tls.py' },
]

describe.each(LABS)('forensics/crypto lab: $id', ({ id, flag, script }) => {
  const bundle = load(id)
  const spec = { kind: 'shell', workdir: WD, check: CHECK, hints: ['h', 'h', 'h', 'h'] }

  it('bundle + seed files are consistent with the lesson lab block', () => {
    expect(bundle.id).toBe(id)
    expect(bundle.workdir).toBe(WD)
    expect(bundle.fs.some((f) => f.path === `${WD}/task.md`)).toBe(true)
    expect(bundle.fs.some((f) => f.path === `${WD}/${script}`)).toBe(true)
    expect(bundle.expect.file).toBe(`${WD}/found.txt`)
    expect(bundle.expect.contains).toBe(flag)
  })

  it('replays the intended solution and passes check', async () => {
    const s = createSession({ spec, bundle })
    expect((await s.run('check')).code).toBe(1) // not solved yet
    await s.run(`python3 ${script} | grep nto > found.txt`)
    expect((await s.run('check')).code).toBe(0)
  })

  it('does not pass check without the flag file', async () => {
    const s = createSession({ spec, bundle })
    await s.run('echo nope > found.txt')
    expect((await s.run('check')).code).toBe(1)
  })
})
