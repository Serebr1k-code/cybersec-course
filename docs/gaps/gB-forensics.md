# Gap analysis (pass B) — `content/forensics`

Inventory: **127 md lessons** (see `grep -h '^title:' content/forensics/*.md`).
Verdict: **STRONG** — filesystems (FAT/exFAT/XFS/HFS+/ext4/NTFS/Btrfs/ZFS/APFS), Windows artifacts (registry/EVTX/USN/Shellbags/SRUM/ShimCache/LNK/VSS/persistence), Linux/macOS, memory (Volatility3), network (PCAP/Suricata/Zeek/TLS), mobile (Android/iOS), cloud (AWS/Azure/GCP), containers/K8s, disk imaging, encryption (LUKS/BitLocker/VeraCrypt/FileVault), malware (YARA/Cobalt Strike/ransomware), timeline (plaso/Timesketch), IR (NIST), anti-forensics.
This pass lists **~190 candidate NEW lessons** not covered by any existing title. Tagged by subcategory. `<proposed-id> — <short title>`.

## A. Disk, filesystem & storage
- fs-refs — ReFS (Resilient File System) forensics
- fs-udf-iso — UDF / ISO9660 forensics
- fs-f2fs — F2FS (Android flash) forensics
- fs-squashfs — SquashFS (embedded) forensics
- fs-jffs2-ubifs — JFFS2 / UBIFS flash filesystems
- fs-nilfs-minix — NILFS / Minix / exotic filesystems
- fs-cifs-smb — SMB/CIFS share forensics
- fs-nfs — NFS share forensics
- fs-cloud-sync — Cloud-sync client (Dropbox/OneDrive/GDrive) artifacts
- fs-ssd-trim — SSD / TRIM / wear-leveling forensics
- fs-hpa-dco — HPA / DCO hidden disk areas
- fs-bad-sectors — Bad-sector & sector-reallocation forensics
- fs-san-nas — SAN / NAS device forensics
- fs-mdadm — Software RAID (mdadm) reconstruction deep
- fs-tpm — TPM / measured-boot forensics
- fs-carving-fragmented — Advanced carving of fragmented files
- fs-ntfs-compression — NTFS compression & sparse-file forensics
- fs-ntfs-logfile — $LogFile / transaction journal deep
- fs-ext4-deleted — ext4 deleted-inode & extent recovery
- fs-btrfs-snapshot — Btrfs snapshot / subvolume forensics
- fs-zfs-arc-zil — ZFS ARC / ZIL / SLOG forensics
- fs-apfs-snapshot — APFS snapshot / checkpoint forensics
- fs-apfs-encryption — APFS encryption & keybag forensics
- fs-fat-slack — FAT volume-slack & cluster-chain forensics
- fs-timestamp-semantics — $STANDARD_INFO vs $FILE_NAME timestamp semantics
- fs-bitlocker-recovery — BitLocker recovery-key / TPM-sealed forensics
- fs-veracrypt-header — VeraCrypt header & hidden-volume forensics
- fs-luks-header — LUKS header & key-slot forensics

## B. Windows artifacts
- win-dpapi — DPAPI masterkeys / CREDHIST forensics
- win-credential-vault — Credential Manager / Windows Vault
- win-rdp-artifacts — RDP bitmap cache & RDP event logs
- win-dns-cache — DNS client cache & DNS Client logs
- win-windows-search — Windows Search (Windows.edb) forensics
- win-activity-timeline — Windows Timeline (ActivitiesCache.db)
- win-notification-db — Notification / Action Center DB
- win-cortana-search — Cortana / search-history artifacts
- win-wer — Windows Error Reporting (WER) artifacts
- win-ntds — NTDS.dit & AD database forensics
- win-sysvol-gpo — SYSVOL / GPO forensic analysis
- win-com-hijack — COM hijacking artifacts
- win-ifeo — IFEO / AppInit_DLLs / AppCertDLLs
- win-print-spooler — Print spooler & print-job forensics
- win-winrm-logs — WinRM / WSMan event logs
- win-smb-artifacts — SMB server/client-side artifacts
- win-edr-logs — EDR/AV product log forensics (CrowdStrike/S1/MDE)
- win-sysmon-tuning — Sysmon configuration & event tuning
- win-srum-deep — SRUM ESE deep parsing
- win-amcache-deep — Amcache ESE deep parsing
- win-appcompat-deep — AppCompatCache / ShimCache deep
- win-powershell-transcript — PowerShell transcription & module logging
- win-scheduled-tasks-deep — Task Scheduler deep artifacts
- win-service-artifacts — Service creation/change forensics
- win-boot-config — BCD / UEFI boot forensics
- win-prefetch-deep — Prefetch parsing & volume serials
- win-evtx-tampering — EVTX tampering / gap detection
- win-registry-recovery — Registry hive slack & transaction recovery
- win-quarantine — AV quarantine vault analysis
- win-windows-update — Windows Update / servicing-stack logs
- win-lsa-secrets — LSA secrets & cached-credential forensics
- win-wmi-persistence — WMI repository persistence deep
- win-app-compat — Application Compatibility cache (extend)

## C. Linux artifacts
- linux-proc-forensics — /proc & /sys live forensics
- linux-ssh-artifacts — SSH known_hosts/authorized_keys/lastlog/wtmp
- linux-systemd-persistence — systemd units/timers persistence
- linux-ebpf-forensics — eBPF-based observability & forensics
- linux-auditd-deep — auditd rules & audit-log analysis deep
- linux-journald-binary — journald binary-log analysis
- linux-package-logs — apt/dpkg/yum/rpm history forensics
- linux-container-escape — Container-escape artifacts
- linux-kernel-modules — Loadable kernel module forensics
- linux-shell-history — bash/zsh/fish history & timestamp forensics
- linux-syslog-rsyslog — syslog/rsyslog pipeline forensics
- linux-file-timestamps — atime/mtime/ctime/crtime forensics
- linux-deleted-open — Deleted-but-open file recovery via /proc
- linux-network-artifacts — lsof/ss/netstat connection forensics
- linux-selinux-apparmor — SELinux / AppArmor denial forensics
- linux-accounts-sudo — passwd/shadow/sudoers/group forensics
- linux-sshd-logs — sshd auth & session forensics
- linux-initramfs — initramfs/initrd forensics

## D. macOS & Apple
- macos-keychain — Keychain forensics
- macos-knowledgec — knowledgeC.db usage forensics
- macos-tcc — TCC.db privacy-consent forensics
- macos-xprotect — XProtect / Gatekeeper / MRT logs
- macos-persistence — LaunchAgents/Daemons persistence
- macos-launchservices — LaunchServices & quarantine DB
- macos-spotlight — Spotlight index forensics
- macos-unified-log-deep — Unified logging deep (logarchive)
- macos-timemachine — Time Machine forensics
- macos-notification-db — Notification Center DB forensics
- macos-memory — macOS memory forensics
- macos-apple-silicon — Apple Silicon / SEP / Secure Enclave forensics
- macos-imessage — iMessage / SMS (chat.db) forensics
- macos-safari — Safari history/downloads forensics
- macos-icloud — iCloud / CloudKit local artifacts
- macos-quarantine-deep — quarantine events deep parsing
- macos-install-logs — Install.log & package-receipt forensics

## E. Mobile
- mobile-android-fbe — Android File-Based Encryption & Keystore
- mobile-android-strongbox — Android Keystore / StrongBox / hardware-backed keys
- mobile-ios-unifiedlog — iOS Unified Logs forensics
- mobile-ios-keychain-deep — iOS keychain deep parsing
- mobile-sim-usim — SIM / USIM card forensics
- mobile-baseband — Baseband / IMSI-catcher artifacts
- mobile-gms — Google Play Services / GMS artifacts
- mobile-android-notifications — Android notification history
- mobile-android-location — Android location history
- mobile-ios-location — iOS location (Cache.sqlite, routined)
- mobile-whatsapp — WhatsApp forensics deep
- mobile-signal-telegram — Signal / Telegram forensics
- mobile-chipoff-jtag — Chip-off / JTAG / ISP extraction
- mobile-ufed-workflow — Cellebrite UFED / AXIOM workflow
- mobile-android-backup — Android backup (adb/AB) forensics
- mobile-ios-backup — iOS backup (iTunes/Finder) forensics deep
- mobile-app-reversing — Mobile app reversing for forensics
- mobile-jailbreak-artifacts — Jailbreak / root artifacts
- mobile-cloud-sync — Mobile cloud (iCloud/Google) acquisition
- mobile-screen-lock — Screen-lock bypass & BFU/AFU states

## F. Memory forensics
- mem-linux — Linux memory forensics (Volatility3 Linux)
- mem-macos — macOS memory forensics
- mem-acquisition — Memory acquisition (WinPmem, LiME, AVML, DumpIt)
- mem-swap-pagefile — Swap / pagefile analysis
- mem-kernel-hooks — SSDT/IDT/kernel-hook detection
- mem-dkom — DKOM & hidden-process detection
- mem-kernel-modules — Kernel-module analysis from memory
- mem-network — Network-connection recovery from memory
- mem-registry-hives — Registry-hive recovery from memory
- mem-timelining — Memory timeline construction
- mem-dyld-cache — Mach-O / dyld shared cache in memory
- mem-shellcode — Shellcode detection & disassembly in memory
- mem-credential-deep — Credential extraction deep (extend mem-keys)

## G. Network forensics
- net-kerberos — Kerberos ticket (Golden/Silver) forensics
- net-smb — SMB protocol forensics
- net-dns — DNS forensics & tunneling detection
- net-dhcp — DHCP lease forensics
- net-arp-mac — ARP / MAC & layer-2 forensics
- net-http2-3 — HTTP/2 & HTTP/3 forensic analysis
- net-ics-scada — ICS/SCADA protocol forensics (Modbus/DNP3)
- net-iot-protocols — MQTT / CoAP / IoT protocol forensics
- net-voip — VoIP / RTP forensics
- net-vpn — VPN / tunnel traffic analysis
- net-c2-reversing — C2 protocol reverse engineering
- net-tcp-reassembly — TCP reassembly & file extraction
- net-flow-beaconing — Flow analysis & beaconing detection
- net-wireless-80211 — Wi-Fi / 802.11 capture forensics
- net-cloud-vpcflow — VPC Flow Logs / cloud network forensics
- net-firewall-proxy — Firewall / proxy log forensics
- net-tls-decrypt-deep — TLS decryption deep (keylog/SSLKEYLOGFILE)

## H. Malware & code analysis
- mal-static — Static malware analysis workflow
- mal-dynamic-sandbox — Dynamic / sandbox analysis (Cuckoo/CAPE)
- mal-unpacking — Unpacking & packer/crypter analysis
- mal-shellcode — Shellcode analysis & emulation
- mal-dotnet — .NET malware analysis (dnSpy/de4dot)
- mal-go-rust — Go / Rust malware analysis
- mal-linux-malware — Linux malware analysis
- mal-macos-malware — macOS malware analysis
- mal-mobile-malware — Mobile malware analysis
- mal-obfuscation — Obfuscation / deobfuscation techniques
- mal-config-extraction — Malware config extraction deep
- mal-botnet-panel — Botnet / C2-panel analysis
- mal-script-js — JavaScript / script-malware analysis
- mal-anti-analysis — Anti-analysis / anti-VM / anti-debug
- mal-ioc-enrichment — IOC extraction & threat-intel enrichment
- mal-emulation — Emulation-based analysis (Qiling/Speakeasy)
- mal-firmware-malware — Firmware/BIOS malware analysis

## I. Timeline & correlation
- tl-cross-artifact — Cross-artifact correlation
- tl-entity-resolution — Entity resolution & deduplication
- tl-timezone-dst — Timezone & DST handling in timelines
- tl-clock-skew — Clock skew / drift correction
- tl-visualization — Timeline visualization (Timesketch deep)
- tl-provenance — Artifact provenance & confidence scoring

## J. Anti-forensics & counter-forensics
- af-secure-delete — Secure deletion & file-wiping detection
- af-encryption-hiding — Encryption/container hiding of evidence
- af-vm-detection — VM / sandbox evasion artifacts
- af-artifact-destruction — Artifact destruction & recovery
- af-metadata-scrubbing — Metadata scrubbing & detection
- af-trail-obfuscation — Trail-obfuscation techniques
- af-detection-methodology — Detecting anti-forensic activity
- af-timestomping-deep — Timestomping detection deep (extend)

## K. Cloud, containers & CI/CD
- cloud-m365-ual — M365 / Office 365 Unified Audit Log forensics
- cloud-okta — Okta / IdP authentication forensics
- cloud-google-workspace — Google Workspace audit forensics
- cloud-salesforce — Salesforce / SaaS audit forensics
- cloud-serverless — Serverless (Lambda/Functions) forensics
- cloud-storage — S3 / Blob / GCS storage forensics
- cloud-iam — Cloud IAM / identity forensics
- cloud-container-runtime — Container-runtime forensics (Falco/eBPF)
- cloud-vm-hypervisor — Cloud VM / hypervisor forensics
- cloud-cicd — CI/CD pipeline forensics
- cloud-iac-state — IaC / Terraform state-file forensics
- cloud-secrets-manager — Secrets-manager access forensics

## L. Web, app & database
- web-webshell — Webshell detection & forensics
- web-server-logs — IIS / Apache / Nginx log analysis
- web-waf-cdn — WAF / CDN log forensics
- web-cms — CMS (WordPress etc.) forensics
- web-java-appserver — Java app-server (Tomcat) forensics
- web-api-gateway — API-gateway / access-log forensics
- web-elasticsearch — Elasticsearch / NoSQL forensics
- web-oracle-db — Oracle database forensics
- web-mongodb-redis — MongoDB / Redis forensics
- web-jenkins-cicd — Jenkins / CI forensics
- web-git-repo — Git repository forensics

## M. Documents & media
- doc-ooxml-internals — OOXML internals (revisions/comments/track-changes)
- doc-odf — OpenDocument forensics
- doc-rtf — RTF forensics
- doc-xps — XPS/OXPS forensics
- media-video-forensics — Video forensics & frame analysis
- media-audio-forensics — Audio forensics (ENF, voice, splicing)
- media-deepfake — Deepfake / synthetic-media detection
- media-provenance — C2PA / media-provenance forensics
- media-qr-barcode — QR / barcode forensics
- media-3d-model — 3D-model / CAD forensics
- media-printer — Printer / document-authenticity forensics

## N. Specialized / niche
- spec-automotive — Automotive / vehicle forensics (CAN, infotainment)
- spec-drone — Drone / UAV forensics
- spec-iot — IoT device forensics
- spec-ics — ICS / SCADA forensics
- spec-console — Game-console forensics
- spec-smarttv — Smart-TV forensics
- spec-crypto-wallet — Cryptocurrency / wallet forensics
- spec-gps — GPS / navigation-device forensics
- spec-wearable — Wearable / smartwatch forensics
- spec-medical-device — Medical-device forensics
- spec-satellite — Satellite / spacecraft forensics
- spec-dvr-camera — DVR / IP-camera / CCTV forensics
- spec-pos — POS / ATM / payment-terminal forensics

## O. Incident response & process
- ir-picerl — SANS PICERL IR lifecycle
- ir-threat-hunting — Threat-hunting methodology
- ir-tabletop — IR tabletop exercises
- ir-containment-eradication — Containment / eradication / recovery
- ir-root-cause — Root-cause analysis
- ir-triage-collection — Triage collection (KAPE/Velociraptor)
- ir-soar-automation — SOAR & automated IR
- ir-forensic-readiness — Forensic readiness & preparation
- ir-communication — Incident communication & escalation
- ir-legal-regulatory — Legal / regulatory aspects (GDPR, breach notice)
- ir-mitre-attack — MITRE ATT&CK mapping (extend)
- ir-purple-team — Purple-team / detection validation

## P. Tools & platforms
- tool-eric-zimmerman — Eric Zimmerman tools suite
- tool-kape — KAPE triage collection
- tool-velociraptor — Velociraptor DFIR
- tool-osquery — osquery forensics
- tool-cyberchef — CyberChef for forensics
- tool-magnet-axiom — Magnet AXIOM
- tool-cellebrite — Cellebrite UFED / Physical Analyzer
- tool-xways — X-Ways Forensics
- tool-ftk-encase — FTK / EnCase
- tool-grr — GRR Rapid Response
- tool-dfir-orc — DFIR ORC / artifact collection
- tool-regripper — RegRipper registry parsing
- tool-hindsight — Hindsight browser forensics
- tool-bulk-extractor — bulk_extractor
- tool-fiwalk — fiwalk / DFXML
- tool-ntfs-tools — ntfs-3g / nTFS / MFTECmd
- tool-plaso-deep — plaso/log2timeline deep (extend)
