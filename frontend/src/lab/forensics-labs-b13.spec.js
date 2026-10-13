import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the forensics lab batch (B13).
// Loads the REAL fixture bundles from content/labs, replays the intended
// solution through the emulated shell/tools, and asserts the lab's own `check`
// + hidden `expect` both pass (and that a wrong answer is rejected).
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

const LABS = [
  { id: 'forensics-reporting', flag: 'nto{ch41n_0f_cust0dy_pr0v3s_1nt3gr1ty}', hints: 4,
    check: "grep -q 'nto{ch41n_0f_cust0dy_pr0v3s_1nt3gr1ty}' answer.txt",
    solution: ['sha256sum srv.img', 'mmls srv.img', 'fls -o 2048 srv.img',
      'icat -o 2048 srv.img 13 > export.csv', 'grep nto export.csv > answer.txt'] },
  { id: 'forensics-mobile', flag: 'nto{andr01d_b4ckup_l34ks_s3ss10n_t0k3n}', hints: 4,
    check: "grep -q 'nto{andr01d_b4ckup_l34ks_s3ss10n_t0k3n}' answer.txt",
    solution: ['java -jar abe.jar unpack backup.ab backup.tar',
      'sqlite3 ext/apps/com.whatsapp/db/msgstore.db ".tables"',
      'sqlite3 ext/apps/com.whatsapp/db/msgstore.db "SELECT key_remote_jid, data FROM messages ORDER BY timestamp DESC LIMIT 3"',
      'exiftool -gps:all ext/shared/DCIM/Camera/IMG_20240112_101133.jpg',
      'grep nto ext/shared/shared_prefs/com.whatsapp_preferences.xml > answer.txt'] },
  { id: 'forensics-fs-structure', flag: 'nto{mbr_55aa_p4rt1t10n_t4bl3}', hints: 4,
    check: "grep -q 'nto{mbr_55aa_p4rt1t10n_t4bl3}' answer.txt",
    solution: ['xxd -l 512 disk.img', 'mmls disk.img', 'xxd -s 0x800 -l 16 disk.img',
      'strings disk.img | grep nto > answer.txt'] },
  { id: 'forensics-fs-internals', flag: 'nto{3xt4_j0urn4l_r3c0v3rs_d3l3t3d}', hints: 4,
    check: "grep -q 'nto{3xt4_j0urn4l_r3c0v3rs_d3l3t3d}' answer.txt",
    solution: ['xxd -s 0x438 -l 2 ext4.img', 'dumpe2fs ext4.img',
      'debugfs -R "lsdel" ext4.img', 'debugfs -R "cat /secret.txt" ext4.img > out.txt',
      'grep nto out.txt > answer.txt'] },
  { id: 'forensics-img-encryption', flag: 'nto{luks_h34d3r_l34ks_th3_l4b3l}', hints: 4,
    check: "grep -q 'nto{luks_h34d3r_l34ks_th3_l4b3l}' answer.txt",
    solution: ['xxd -l 16 luks.img', 'cryptsetup luksDump luks.img > dump.txt',
      'grep nto dump.txt > answer.txt'] },
  { id: 'forensics-img-captures', flag: 'nto{l1v3_sn4psh0t_pc4p_c4ptur3s_s3cr3ts}', hints: 4,
    check: "grep -q 'nto{l1v3_sn4psh0t_pc4p_c4ptur3s_s3cr3ts}' answer.txt",
    solution: ['vol -f mem.raw windows.pslist', 'tshark -r capture.pcap -nn',
      'tshark -r capture.pcap -q -z follow,tcp,ascii,0',
      'strings capture.pcap | grep nto > answer.txt'] },
  { id: 'forensics-img-mobile', flag: 'nto{andr01d_sp4rs3_1mg3_chip_0ff}', hints: 4,
    check: "grep -q 'nto{andr01d_sp4rs3_1mg3_chip_0ff}' answer.txt",
    solution: ['xxd -l 4 userdata.img', 'simg2img userdata.img userdata.raw',
      'strings userdata.img | grep nto > answer.txt'] },
  { id: 'forensics-win-registry', flag: 'nto{r3g_run_k3y_p3rs1st3nc3_f0und}', hints: 4,
    check: "grep -q 'nto{r3g_run_k3y_p3rs1st3nc3_f0und}' answer.txt",
    solution: ['xxd -l 4 SOFTWARE', 'rip.pl -r SOFTWARE -p soft_run > run.txt',
      'grep nto run.txt > answer.txt'] },
  { id: 'forensics-win-logs', flag: 'nto{3vtx_4624_l0g0n_typ3_10}', hints: 4,
    check: "grep -q 'nto{3vtx_4624_l0g0n_typ3_10}' answer.txt",
    solution: ['xxd -l 7 Security.evtx', 'evtx_dump.py Security.evtx -o events.json',
      'grep nto events.json > answer.txt'] },
  { id: 'forensics-win-misc', flag: 'nto{l1nux_4rt1f4cts_4nd_4nt1_f0r3ns1cs}', hints: 4,
    check: "grep -q 'nto{l1nux_4rt1f4cts_4nd_4nt1_f0r3ns1cs}' answer.txt",
    solution: ['cat home/analyst/.bash_history', 'cat var/log/auth.log', 'ls -la tmp',
      'cat tmp/.hidden_backdoor.sh', 'grep nto tmp/.hidden_backdoor.sh > answer.txt'] },
  { id: 'forensics-fs-family', flag: 'nto{f4t32_d3l3t3d_clust3r_r3c0v3ry}', hints: 4,
    check: "grep -q 'nto{f4t32_d3l3t3d_clust3r_r3c0v3ry}' answer.txt",
    solution: ['xxd -l 16 card.img', 'fsstat card.img', 'fls -r card.img',
      'strings card.img | grep nto > answer.txt'] },
  { id: 'forensics-tooling', flag: 'nto{y4r4_4ut0m4t3d_tr14g3_m4tch}', hints: 4,
    check: "grep -q 'nto{y4r4_4ut0m4t3d_tr14g3_m4tch}' answer.txt",
    solution: ['cat rules.yar', 'yara rules.yar sample.bin > yara.txt',
      'grep nto yara.txt > answer.txt'] },
]

describe.each(LABS)('forensics lab B13: $id', ({ id, flag, hints, check, solution }) => {
  const bundle = load(id)
  const spec = { kind: 'shell', workdir: WD, check, hints: Array(hints).fill('h') }

  it('bundle + seed files are consistent with the lesson lab block', () => {
    expect(bundle.id).toBe(id)
    expect(bundle.workdir).toBe(WD)
    expect(bundle.fs.some((f) => f.path === `${WD}/task.md`)).toBe(true)
    expect(bundle.expect.file).toBe(`${WD}/answer.txt`)
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
    await s.run("echo 'nto{wrong_flag}' > answer.txt")
    expect((await s.run('check')).code).toBe(1)
  })
})
