import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the DISCONNECTED-LAB retrofit:
// ~50 gB lessons carried one generic placeholder lab (`cat evidence.txt;
// grep nto`). Each was replaced with a topic-specific lab on the lesson's
// own artefact; this spec replays each intended solution against the REAL
// lab engine and asserts the published `check` passes.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'

function load(id) { return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8')) }

const LABS = [
  { id: "tool-cyberchef", flag: "nto{cyberchef_b4se64_th3n_1t5_cl34r}", solution: ["base64 -d cyberchef_input.txt > answer.txt"] },
  { id: "tool-osquery", flag: "nto{osquery_f0und_th3_0utl13r}", solution: ["grep nto osquery_processes.json > answer.txt"] },
  { id: "tool-plaso-deep", flag: "nto{plaso_runkey_p3rs1st3nc3}", solution: ["grep nto plaso_timeline.csv > answer.txt"] },
  { id: "tool-regripper", flag: "nto{regripper_runk3y_4ut0st4rt}", solution: ["grep nto regripper_report.txt > answer.txt"] },
  { id: "tool-hindsight", flag: "nto{hindsight_susp1c10us_d0wnl04d}", solution: ["grep nto history_export.csv > answer.txt"] },
  { id: "tool-bulk-extractor", flag: "nto{bulk_extractor_c2_b34c0n}", solution: ["grep nto bulk_extractor_url.txt > answer.txt"] },
  { id: "tool-dfir-orc", flag: "nto{dfir_orc_scht4sk_1mp4ct}", solution: ["grep nto orc_collect.csv > answer.txt"] },
  { id: "tool-fiwalk", flag: "nto{fiwalk_d3l3t3d_mft_3ntry}", solution: ["grep nto fiwalk_files.xml > answer.txt"] },
  { id: "tool-ntfs-tools", flag: "nto{ntfs_mft_r3c0rd_88}", solution: ["grep nto mft_entries.txt > answer.txt"] },
  { id: "tool-velociraptor", flag: "nto{velociraptor_vql_hunt_h1t}", solution: ["grep nto vql_results.json > answer.txt"] },
  { id: "tool-magnet-axiom", flag: "nto{axiom_c0rr3l4t3d_usb}", solution: ["grep nto axiom_artifacts.csv > answer.txt"] },
  { id: "tool-cellebrite", flag: "nto{cellebrite_ffs_3xtr4ct10n}", solution: ["grep nto cellebrite_extraction.txt > answer.txt"] },
  { id: "tool-ftk-encase", flag: "nto{ftk_b00km4rk_h1gh_sc0r3}", solution: ["grep nto ftk_bookmarks.txt > answer.txt"] },
  { id: "tool-grr", flag: "nto{grr_fl0w_susp1c10us}", solution: ["grep nto grr_flows.json > answer.txt"] },
  { id: "tool-xways", flag: "nto{xways_c4rv3d_z1p_0ffs3t}", solution: ["grep nto xways_events.txt > answer.txt"] },
  { id: "spec-gps", flag: "nto{gps_sp00f3d_f1x}", solution: ["grep nto gps_track.nmea > answer.txt"] },
  { id: "spec-drone", flag: "nto{drone_g30f3nc3_br34ch}", solution: ["grep nto drone_flightlog.csv > answer.txt"] },
  { id: "spec-dvr-camera", flag: "nto{dvr_d3l3t3d_s3gm3nt}", solution: ["grep nto dvr_records.txt > answer.txt"] },
  { id: "spec-ics", flag: "nto{plc_un4uth0r1z3d_wr1t3}", solution: ["grep nto plc_logs.txt > answer.txt"] },
  { id: "spec-medical-device", flag: "nto{med1c4l_d0s3_0v3rr1d3}", solution: ["grep nto infusion_log.txt > answer.txt"] },
  { id: "spec-smarttv", flag: "nto{smarttv_s1d3l04d3d_4pp}", solution: ["grep nto smarttv_apps.txt > answer.txt"] },
  { id: "spec-console", flag: "nto{c0ns0l3_s4v3_exf1l}", solution: ["grep nto console_storage.txt > answer.txt"] },
  { id: "spec-crypto-wallet", flag: "nto{hw_w4ll3t_s33d_l34k}", solution: ["grep nto wallet_seed_parts.txt > answer.txt"] },
  { id: "spec-automotive", flag: "nto{ecu_c4n_m4squ3r4d3}", solution: ["grep nto ecu_can_log.txt > answer.txt"] },
  { id: "macos-imessage", flag: "nto{imessage_1n_c0mmun1c4t10}", solution: ["grep nto imessage_chat.txt > answer.txt"] },
  { id: "macos-spotlight", flag: "nto{spotlight_st0r3_m3t4d4t4}", solution: ["grep nto spotlight_store.txt > answer.txt"] },
  { id: "macos-timemachine", flag: "nto{timemachine_d3l3t3d_f1l3}", solution: ["grep nto timemachine_snapshots.txt > answer.txt"] },
  { id: "mal-botnet-panel", flag: "nto{botn3t_p4n3l_3xf1l_cmd}", solution: ["grep nto botnet_panel.log > answer.txt"] },
  { id: "mal-emulation", flag: "nto{3mul4t10n_4p1_tr4c3}", solution: ["grep nto emulation_trace.txt > answer.txt"] },
  { id: "mal-firmware-malware", flag: "nto{uefi_b00tk1t_1mpl4nt}", solution: ["grep nto uefi_strings.txt > answer.txt"] },
  { id: "media-3d-model", flag: "nto{3d_m0d3l_3mb3dd3d_d4t4}", solution: ["grep nto model_meta.txt > answer.txt"] },
  { id: "media-audio-forensics", flag: "nto{w4v_c0mm3nt_chunk_d4t4}", solution: ["grep nto wav_chunks.txt > answer.txt"] },
  { id: "media-deepfake", flag: "nto{d33pf4k3_synth3t1c_m3t4}", solution: ["grep nto media_report.csv > answer.txt"] },
  { id: "media-provenance", flag: "nto{c2pa_pr0v3n4nc3_tr41l}", solution: ["grep nto c2pa_manifest.json > answer.txt"] },
  { id: "fs-apfs-snapshot", flag: "nto{apfs_sn4psh0t_r3c0v3ry}", solution: ["grep nto apfs_snapshots.txt > answer.txt"] },
  { id: "fs-mdadm", flag: "nto{mdadm_ra1d_4ss3mbly}", solution: ["grep nto mdadm_scan.txt > answer.txt"] },
  { id: "fs-tpm", flag: "nto{tpm_pcr7_s3cur3b00t_ch4ng3}", solution: ["grep nto tpm_pcrs.txt > answer.txt"] },
  { id: "cloud-cicd", flag: "nto{cicd_p1p3l1n3_s3cr3t_l34k}", solution: ["grep nto cicd_pipeline.log > answer.txt"] },
  { id: "cloud-iac-state", flag: "nto{iac_st4t3_dr1ft_publ1c}", solution: ["grep nto iac_state_drift.csv > answer.txt"] },
  { id: "cloud-vm-hypervisor", flag: "nto{cl0ud_vm_sn4psh0t_m3t4}", solution: ["grep nto hypervisor_vm_metadata.txt > answer.txt"] },
  { id: "doc-rtf", flag: "nto{rtf_0bj3ct_3xpl01t}", solution: ["grep nto rtf_objects.txt > answer.txt"] },
  { id: "mem-registry-hives", flag: "nto{m3m_r3g1stry_h1v3_c4rv3}", solution: ["grep nto mem_hives.txt > answer.txt"] },
  { id: "net-ics-scada", flag: "nto{sc4da_m0dbus_1ntrus10n}", solution: ["grep nto scada_protocol.log > answer.txt"] },
  { id: "forensics-cloud-serverless", flag: "nto{s3rv3rl3ss_un4uth_1nv0k3}", solution: ["grep nto lambda_invoke.log > answer.txt"] },
  { id: "forensics-ios-backup", flag: "nto{1os_b4ckup_m4n1f3st_d4t4}", solution: ["grep nto ios_backup_files.txt > answer.txt"] },
  { id: "media-qr-barcode", flag: "nto{qr_b4rc0d3_p4yl04d}", solution: ["grep nto qr_barcodes.txt > answer.txt"] },
  { id: "web-oracle-db", flag: "nto{or4cl3_4ud1t_d4t4_pump}", solution: ["grep nto oracle_audit.txt > answer.txt"] },
  { id: "mobile-android-notifications", flag: "nto{andr01d_n0t1f1c4t10n_l34k}", solution: ["grep nto android_notifications.txt > answer.txt"] },
  { id: "mobile-ios-keychain-deep", flag: "nto{1os_k3ych41n_g3n3r1c_p4ssw0rd}", solution: ["grep nto ios_keychain_items.txt > answer.txt"] },
  { id: "mobile-ios-location", flag: "nto{1os_l0c4t10n_h1st0ry_p1n}", solution: ["grep nto ios_location.txt > answer.txt"] },
  { id: "mobile-ios-urlscheme", flag: "nto{url_sch3m3_h1j4ck}", solution: ["grep nto url_scheme_registry.txt > answer.txt"] },
  { id: "mobile-automation", flag: "nto{mobsf_h4rdc0d3d_s3cr3t}", solution: ["grep nto mobsf_report.json > answer.txt"] },
  { id: "mobile-frida-dexdump", flag: "nto{frida_d3xdump_unp4ck3d}", solution: ["grep nto dexdump_output.txt > answer.txt"] },
  { id: "mobile-frida-scripting", flag: "nto{frida_h00k_c4ptur3d}", solution: ["grep nto frida_hooks.log > answer.txt"] },
  { id: "mobile-ios-cycript", flag: "nto{cycript_runt1m3_1ntr0sp3ct10n}", solution: ["grep nto cycript_session.txt > answer.txt"] },
  { id: "mobile-objection", flag: "nto{objection_ssl_p1nn1ng_byp4ss}", solution: ["grep nto objection_console.log > answer.txt"] },
  { id: "mobile-universal-links", flag: "nto{un1v3rs4l_l1nks_h1j4ck}", solution: ["grep nto universal_links.txt > answer.txt"] },
]

describe.each(LABS)('disconnected-lab retrofit: $id', ({ id, flag, solution }) => {
  const bundle = load(id)
  const spec = { kind: 'shell', workdir: WD, check: `grep -q 'nto{' answer.txt`, hints: ['h', 'h', 'h'] }

  it('bundle matches the published contract', () => {
    expect(bundle.id).toBe(id)
    expect(bundle.workdir).toBe(WD)
    expect(bundle.fs.some((f) => f.path === `${WD}/task.md`)).toBe(true)
    expect(bundle.expect.file).toBe(`${WD}/answer.txt`)
    expect(bundle.expect.contains).toBe(flag)
  })

  it('replays the intended solution and passes check', async () => {
    const s = createSession({ spec, bundle })
    expect((await s.run('check')).code).toBe(1)
    for (const cmd of solution) await s.run(cmd)
    expect((await s.run('check')).code).toBe(0)
  })
})
