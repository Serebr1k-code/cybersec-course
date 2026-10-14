# Content Gap Backlog — consolidated, verified, collision-free

Provenance: consolidated from the independent per-category gap analyses (cloud, hardware,
network, osint, web, pwn, misc, mobile, stego, forensics, crypto, reversing) produced by the
recon pass, then **every proposed id was checked against the live tree** (`content/<cat>/<id>.md`).
Result: **0 collisions** — all entries below are genuinely missing.

Legend for the lab column:
- `+lab`  — hands-on, console-simulatable in the lab JS engine; author a lab (`content/labs/<id>.json`)
- `~lab`  — lab optional/partial (UI-, SaaS-, or physics-bound; may need replay fixtures)
- `-lab`  — conceptual/no console surface (skip lab)

Authoring rules: LESSON_TEMPLATE style (running example, terms-before-use, command+output,
`## Квиз` + `## Где пригодится` + `## Куда дальше`), Russian, ≥1200 real content words.
Before authoring ANY id below, re-verify `content/<cat>/<id>.md` does not already exist.

Totals: web 35 · network 30 · osint 32 · misc 25 · mobile 26 · pwn 32 · crypto 19 · stego 18 ·
forensics 16 · reversing 22 · hardware 20 · cloud 31 = **306 proposed lessons**.

---

## web (existing 186 — CMS/framework & appliance exploitation is the big hole)

- web-wordpress — WordPress core/plugin/theme vulns, xmlrpc, wp-cron, user enum `+lab`
- web-drupal — Drupalgeddon, SA-CORE, form API `+lab`
- web-joomla — Joomla component/module RCE `+lab`
- web-magento — Magento (Adobe Commerce) RCE & card skimmers `+lab`
- web-laravel — Laravel debug/ignition, .env, signed URLs `+lab`
- web-django — Django DEBUG, SECRET_KEY, admin, template injection `+lab`
- web-spring-boot — Spring Boot Actuator, heapdump, env, jolokia `+lab`
- web-nextjs — Next.js SSR/SSRF, middleware auth bypass, `__NEXT_DATA__` `+lab`
- web-coldfusion — ColdFusion CVE-2023-26360/CFC/RDS `+lab`
- web-sharepoint — SharePoint ToolShell, workflow, `_layouts` `+lab`
- web-exchange — ProxyLogon/ProxyShell/ProxyNotShell `+lab`
- web-confluence — Confluence CVE-2023-22515/22527 OGNL `+lab`
- web-jira — Jira CVE-2019-8449 / SSRF / templates `+lab`
- web-weblogic — WebLogic T3/IIOP deser (CVE-2019-2725/2020-14882) `+lab`
- web-grafana — Grafana path traversal CVE-2021-43798, plugins `+lab`
- web-gitlab — GitLab app-layer (exif, GraphQL, CI vars) `+lab`
- web-keycloak — Keycloak SSO misconfig, admin console, CVE-2023-0264 `~lab`
- web-shiro — Apache Shiro rememberMe deserialization (CVE-2016-4437) `+lab`
- web-fastjson — Fastjson/JXPath/Jackson gadget autotype `+lab`
- web-tomcat-manager — Tomcat manager deploy WAR, AJP Ghostcat `+lab`
- web-elastic-kibana — Kibana CVE-2019-7609, console RCE `+lab`
- web-vmware-vcenter — vCenter CVE-2021-21972/22005 `+lab`
- web-citrix — Citrix ADC/NetScaler CVE-2023-3519/4966 `+lab`
- web-f5-bigip — F5 BIG-IP iControl REST CVE-2022-1388 `+lab`
- web-zabbix — Zabbix CVE-2022-23131/23134 session/SQLi `+lab`
- web-phpmyadmin — phpMyAdmin CVE-2018-12613 LFI→RCE `+lab`
- web-sonarqube — SonarQube CVE-2020-27986/anon admin `+lab`
- web-jupyter — Jupyter Notebook unauth RCE `+lab`
- web-k8s-dashboard — Kubernetes Dashboard skip-login RCE `+lab`
- web-rabbitmq-mgmt — RabbitMQ management default creds / definitions `+lab`
- web-dependency-confusion — npm/pip/Composer dependency confusion `+lab`
- web-npm-supply-chain — typosquat / malicious package / postinstall `+lab`
- web-salesforce — Salesforce Aura/Apex misconfig `~lab`
- web-servicenow — ServiceNow portal/ACL bypass `~lab`
- web-sap-netweaver — SAP NetWeaver ICM CVE-2017-9844 / RECON `~lab`

## network (existing 115 — telecom/RF, automotive, deep ICS, modern DC fabrics)

- network-5g-nr — 5G NR/core, NAS, GTP-U, registration hijack `+lab`
- network-gtp — GTP-C/GTP-U tunneling, GSN abuse `+lab`
- network-diameter — Diameter AAA (S6a/S6d), IMSI leak `+lab`
- network-sm — telecom Session Management / signaling (SMS/SS7 surface) `+lab`
- network-sdr-basics — SDR capture, IQ, waterfall, decode `~lab`
- network-can-bus — CAN frame crafting, arbitration, injection on wire `+lab`
- network-uds — ISO-TP + UDS diagnostic services over CAN `+lab`
- network-lin-bus — LIN bus framing/master-slave `~lab`
- network-tsn — Time-Sensitive Networking / 802.1Qbv `~lab`
- network-ptp — Precision Time Protocol (IEEE 1588) attacks `+lab`
- network-ospf-deep — OSPF adjacency, LSA injection, MD5 auth bypass `+lab`
- network-isis — IS-IS adjacency/LSP attacks `+lab`
- network-bgp-deep — BGP attribute manipulation beyond hijack `+lab`
- network-srv6 — Segment Routing v6 SID attacks `+lab`
- network-evpn — EVPN/VXLAN control-plane attacks `+lab`
- network-macsec — MACsec 802.1AE key/rollover attacks `~lab`
- network-dhcp-snooping — DHCP snooping/option-82/rogue bypass `+lab`
- network-rtsp-onvif — RTSP/ONVIF camera enum & auth bypass `+lab`
- network-bacnet — BACnet/IP object read/write `+lab`
- network-iec104 — IEC 60870-5-104 command injection `+lab`
- network-iec61850 — IEC 61850 MMS/GOOSE spoofing `+lab`
- network-s7comm — Siemens S7comm read/write/stop `+lab`
- network-ethercat — EtherCAT telegram injection `~lab`
- network-someip — SOME/IP service discovery & injection `~lab`
- network-doip — DNP3 over IP (transport detail) `+lab`
- network-dds — DDS/RTPS pub-sub discovery abuse `~lab`
- network-amqp — AMQP 0-9-1 broker abuse `+lab`
- network-stomp — STOMP messaging attacks `+lab`
- network-xmpp — XMPP federation/JID enum `+lab`
- network-ntcip — NTCIP traffic-controller protocol `~lab`

## osint (existing 122 — platform breadth, deep records, infra/SaaS enum, geospatial)

- osint-threads — Meta Threads enumeration `+lab`
- osint-bluesky — Bluesky/AT-protocol OSINT `+lab`
- osint-signal — Signal footprint / number linkage `~lab`
- osint-whatsapp — WhatsApp business/profile enum `~lab`
- osint-wechat — WeChat official-account & ID OSINT `~lab`
- osint-line — LINE ID/group OSINT `~lab`
- osint-snapchat — Snapchat Snap Map / handle enum `~lab`
- osint-pinterest — Pinterest board/interest mapping `~lab`
- osint-gaming — Steam/Xbox/PSN gamertag pivot `+lab`
- osint-roblox — Roblox user/group enum `+lab`
- osint-strava — Strava heatmap & route de-anonymization `+lab`
- osint-github-actions-recon — CI workflow/secret leakage from Actions `+lab`
- osint-adsb — ADS-B aircraft tracking (ICAO hex) `+lab`
- osint-ais — AIS maritime vessel tracking `+lab`
- osint-wigle — WiGLE Wi-Fi geolocation mapping `+lab`
- osint-imei — IMEI/TAC device identification `+lab`
- osint-pgp-keyserver — PGP keyserver graph (`+lab`)
- osint-ssh-fingerprint — SSH host-key fingerprint correlation `+lab`
- osint-okta-enum — Okta tenant/user enumeration `+lab`
- osint-m365-enum — Microsoft 365 tenant & user enum `+lab`
- osint-google-workspace-enum — Google Workspace tenant enum `+lab`
- osint-azure-tenant — Azure AD tenant discovery `+lab`
- osint-kubernetes-enum — K8s API/cluster enumeration `+lab`
- osint-crunchbase — Crunchbase funding/people OSINT `~lab`
- osint-opencorporates — OpenCorporates entity graph `+lab`
- osint-court-records — Court/pacer records search `+lab`
- osint-property-records — Property/cadastral records `+lab`
- osint-voter-records — Voter registration records `+lab`
- osint-sanctions — Sanctions/PEP list screening `+lab`
- osint-offshore-leaks — Offshore leaks / ICIJ datasets `+lab`
- osint-voice-cloning — Voice-clone detection & attribution `~lab`
- osint-attribution — Threat-actor attribution methodology `~lab`

## misc (existing 108 — data formats, LLM, sandboxes, quantum, CTF meta)

- misc-evm-internals — EVM bytecode/storage internals `+lab`
- misc-protobuf-deep — Protobuf wire format & fuzzing `+lab`
- misc-msgpack-cbor — MessagePack/CBOR decoding attacks `+lab`
- misc-asn1-deep — ASN.1 BER/DER parsing bugs `+lab`
- misc-ntfs-forensics — NTFS/MFT/ADS/artifacts in CTF `+lab`
- misc-disk-forensics — disk image triage in misc CTF `+lab`
- misc-file-carving — carving with scalpel/foremost/binwalk `+lab`
- misc-llm-rag — RAG pipeline attacks & data poisoning `+lab`
- misc-llm-guardrails — guardrail bypass taxonomy `+lab`
- misc-llm-multimodal — multimodal (image/audio) prompt injection `+lab`
- misc-sandbox-php — PHP disable_functions / open_basedir escapes `+lab`
- misc-sandbox-java — Java SecurityManager / module escapes `+lab`
- misc-sandbox-go — Go plugin/unsafe sandbox escapes `+lab`
- misc-sandbox-rust — Rust sandbox escapes `+lab`
- misc-sandbox-deno — Deno permission-model escapes `+lab`
- misc-sandbox-v8 — V8 sandbox/isolate escapes `+lab`
- misc-gvisor — gVisor syscall-emulation escapes `+lab`
- misc-firecracker — Firecracker microVM escape surface `+lab`
- misc-quantum-computing — quantum computing for CTF `~lab`
- misc-zkp-ctf — ZK-proof CTF challenges `+lab`
- misc-hardware-wallet — hardware-wallet CTF/attacks `~lab`
- misc-social-engineering — SE playbook for CTF/red team `~lab`
- misc-phishing-kits — phishing kit analysis & reverse `+lab`
- misc-fileless-lotl — fileless / living-off-the-land techniques `+lab`
- misc-edr-evasion — EDR evasion primitives `~lab`

## mobile (existing 116 — Android IPC/system, iOS internals, cross-platform)

- mobile-android-pendingintent — PendingIntent hijack/mutability `+lab`
- mobile-android-accessibility — accessibility-service abuse `+lab`
- mobile-android-device-admin — device-admin API abuse `+lab`
- mobile-android-notification-listener — notification-listener abuse `+lab`
- mobile-android-selinux — Android SELinux policy bypass `~lab`
- mobile-android-verified-boot — verified boot / AVB chain `~lab`
- mobile-android-kernel-exploit — Android kernel exploitation `~lab`
- mobile-android-overlay-attack — tapjacking/overlay attacks `+lab`
- mobile-android-mediaprojection — MediaProjection screen-capture abuse `+lab`
- mobile-android-vpnservice — VpnService traffic interception `+lab`
- mobile-android-play-integrity — Play Integrity API bypass `~lab`
- mobile-ios-code-signing — iOS code signing / provisioning `+lab`
- mobile-ios-entitlements — entitlement abuse & task_for_pid `+lab`
- mobile-ios-app-attest — App Attest / DeviceCheck bypass `~lab`
- mobile-ios-mach-ports — Mach ports / XPC IPC exploitation `+lab`
- mobile-ios-xpc — iOS XPC service attacks `+lab`
- mobile-ios-webkit — iOS WebKit/JSC exploitation `~lab`
- mobile-ios-app-clip — App Clip abuse `~lab`
- mobile-pwa — PWA security (service worker, storage) `+lab`
- mobile-capacitor — Capacitor hybrid-app security `+lab`
- mobile-cordova — Cordova/PhoneGap plugin security `+lab`
- mobile-unity — Unity IL2CPP mobile reversing `+lab`
- mobile-xamarin — Xamarin/.NET mobile reversing `+lab`
- mobile-android-things — Android Things/IoT Android `~lab`
- mobile-chromeos — ChromeOS/ARC security `~lab`
- mobile-esim — eSIM/eUICC profile attacks `~lab`

## pwn (existing 123 — architectures, allocators, exotic targets, fuzzing)

- pwn-x86-32 — 32-bit x86 exploitation `+lab`
- pwn-arm32 — ARM32 exploitation `+lab`
- pwn-arm-pac — ARM pointer authentication (PAC) bypass `+lab`
- pwn-arm-mte — ARM Memory Tagging Extension bypass `+lab`
- pwn-powerpc — PowerPC exploitation `+lab`
- pwn-sparc — SPARC exploitation `+lab`
- pwn-s390x — s390x (big-endian) exploitation `+lab`
- pwn-avr-embedded — AVR/embedded exploitation `~lab`
- pwn-wasm-pwn — WebAssembly memory-corruption `+lab`
- pwn-jemalloc — jemalloc exploitation `+lab`
- pwn-tcmalloc — tcmalloc exploitation `+lab`
- pwn-android-scudo — Android Scudo allocator `+lab`
- pwn-partitionalloc — PartitionAlloc exploitation `+lab`
- pwn-dlmalloc — dlmalloc/older glibc `+lab`
- pwn-hardened-allocators — hardened allocator bypasses `+lab`
- pwn-house-of-spirit — House of Spirit `+lab`
- pwn-house-of-husk — House of Husk `+lab`
- pwn-house-of-orange — House of Orange `+lab`
- pwn-house-of-mind — House of Mind `+lab`
- pwn-house-of-storm — House of Storm `+lab`
- pwn-jit-exploitation — JIT spray / RWX abuse `+lab`
- pwn-browser-v8 — V8 browser exploitation `~lab`
- pwn-hypervisor — hypervisor exploitation `~lab`
- pwn-qemu-escape — QEMU escape `~lab`
- pwn-gpu-cuda — GPU/CUDA exploitation `~lab`
- pwn-firmware-pwn — firmware exploitation `~lab`
- pwn-iot-pwn — IoT device exploitation `~lab`
- pwn-wifi-pwn — Wi-Fi stack exploitation `~lab`
- pwn-rtos-pwn — RTOS exploitation `~lab`
- pwn-afl-deep — AFL++ advanced (persistent, cmplog) `+lab`
- pwn-libfuzzer — libFuzzer harnesses `+lab`
- pwn-differential-fuzzing — differential fuzzing `+lab`

## crypto (existing 123 — post-quantum, MPC/PSI, ZK systems, side-channel)

- crypto-pq-kem — post-quantum KEMs (Kyber/ML-KEM) `+lab`
- crypto-pq-hash-based — hash-based signatures (SPHINCS+) `+lab`
- crypto-pq-multivariate — multivariate PQ signatures `+lab`
- crypto-pq-migration — PQ migration / hybrid deployment `~lab`
- crypto-hybrid-pq — hybrid classical+PQ key exchange `+lab`
- crypto-psi — private set intersection `+lab`
- crypto-oblivious-transfer — oblivious transfer protocols `+lab`
- crypto-garbled-circuits — garbled circuits / 2PC `+lab`
- crypto-differential-privacy — DP mechanisms `+lab`
- crypto-zk-bulletproofs — Bulletproofs range proofs `+lab`
- crypto-zk-groth16 — Groth16 proving system `+lab`
- crypto-zk-circom — Circom/snarkjs circuits `+lab`
- crypto-kzg — KZG commitments `+lab`
- crypto-bls — BLS signatures & aggregation `+lab`
- crypto-secp256k1 — secp256k1 attacks `+lab`
- crypto-brainpool — Brainpool curve attacks `+lab`
- crypto-speculative-execution — Spectre/Meltdown crypto key recovery `~lab`
- crypto-dma-attacks — DMA/Thunderbolt crypto attacks `~lab`
- crypto-quantum-grover — Grover search impact on symmetric crypto `~lab`

## stego (existing 115 — modern content-adaptive embedding & watermarking)

- stego-rd — randomization/rich-model steganalysis `+lab`
- stego-hugo — HUGO embedding `+lab`
- stego-wow — WOW (Wavelet Obtained Weights) `+lab`
- stego-suniward — S-UNIWARD `+lab`
- stego-juniward — J-UNIWARD (JPEG) `+lab`
- stego-hill — HILL embedding `+lab`
- stego-rich-model — rich-model feature sets `+lab`
- stego-srm — Spatial Rich Model features `+lab`
- stego-cost-function — cost-function design `+lab`
- stego-print-source — printer/scanner source identification `~lab`
- stego-ipv6-covert — IPv6 covert channels `+lab`
- stego-ntp-covert — NTP covert channel `+lab`
- stego-nft — NFT/metadata steganography `~lab`
- stego-gan — GAN-based steganography `+lab`
- stego-adversarial — adversarial steganography `+lab`
- stego-robust-watermark — robust watermarking `+lab`
- stego-drm — DRM watermark extraction `~lab`
- stego-hardware-covert — hardware covert channels `~lab`

## forensics (existing 127 — DFIR tooling, niche domains, process)

- forensics-velociraptor — Velociraptor hunting/artifacts `+lab`
- forensics-osquery — osquery live triage `+lab`
- forensics-threat-hunting — hypothesis-driven hunting `~lab`
- forensics-sigma-rule-writing — writing Sigma rules `+lab`
- forensics-yara-rule-writing — writing YARA rules `+lab`
- forensics-iot — IoT/embedded forensics `~lab`
- forensics-drone — drone/UAS forensics `~lab`
- forensics-vehicle — vehicle/infotainment forensics `~lab`
- forensics-ics — ICS/SCADA forensics `~lab`
- forensics-serverless — serverless/FaaS forensics `~lab`
- forensics-expert-witness — expert-witness report/testimony `-lab`
- forensics-court-testimony — court testimony & deposition `-lab`
- forensics-corporate-investigation — corporate/HR investigation process `-lab`
- forensics-anti-forensics-deep — advanced anti-forensics `+lab`
- forensics-apt — APT intrusion analysis `~lab`
- forensics-microservices — microservice/container-mesh forensics `~lab`

## reversing (existing 127 — architectures, embedded, ML/FGPA, new runtimes)

- reversing-riscv — RISC-V reversing `+lab`
- reversing-sparc — SPARC reversing `+lab`
- reversing-powerpc — PowerPC reversing `+lab`
- reversing-s390x — s390x mainframe reversing `+lab`
- reversing-xtensa — Xtensa (ESP32) reversing `+lab`
- reversing-avr — AVR reversing `+lab`
- reversing-gpu-shaders — GPU shader reversing `~lab`
- reversing-ml-models — ONNX/PyTorch model reversing `+lab`
- reversing-fpga-bitstream — FPGA bitstream reversing `~lab`
- reversing-intel-me — Intel ME firmware `~lab`
- reversing-amd-psp — AMD PSP firmware `~lab`
- reversing-bmc — BMC/IPMI firmware `~lab`
- reversing-baseband — baseband/modem firmware `~lab`
- reversing-smartnic — SmartNIC/DPU firmware `~lab`
- reversing-electron — Electron app reversing `+lab`
- reversing-browser-extensions — browser-extension reversing `+lab`
- reversing-office-macros — Office macro/VBA reversing `+lab`
- reversing-zig — Zig binary reversing `+lab`
- reversing-kotlin-native — Kotlin/Native reversing `+lab`
- reversing-dart-aot — Dart AOT reversing `+lab`
- reversing-lua-bytecode — Lua bytecode reversing `+lab`
- reversing-ruby-bytecode — Ruby bytecode reversing `+lab`

## hardware (existing 117 — Wi-Fi/RF offensive, hardware-tooling, safety/industrial)

- hardware-wifi — Wi-Fi hardware/offensive overview `~lab`
- hardware-wifi-deauth — deauth/disassoc attacks `~lab`
- hardware-wifi-pmkid — PMKID clientless attack `~lab`
- hardware-wifi-wpa3-sae — WPA3-SAE/Dragonblood `~lab`
- hardware-wifi-karma — Karma/evil-twin with hardware `~lab`
- hardware-bluetooth-mesh — Bluetooth Mesh attacks `~lab`
- hardware-thread-matter — Thread/Matter smart-home protocol `~lab`
- hardware-lorawan — LoRaWAN network attacks `~lab`
- hardware-esim — eSIM/eUICC hardware attacks `~lab`
- hardware-nfc-emulation — NFC card emulation (Proxmark/Chameleon) `~lab`
- hardware-proxmark — Proxmark3 workflows `~lab`
- hardware-chameleon — Chameleon Mini/Tiny workflows `~lab`
- hardware-flipper — Flipper Zero workflows `~lab`
- hardware-jtagulator — JTAGulator pin discovery `~lab`
- hardware-gliw — ChipWhisperer/GLIW fault injection `~lab`
- hardware-chipwhisperer — ChipWhisperer side-channel setup `~lab`
- hardware-plc-redteam — PLC red-team engagement `~lab`
- hardware-hmi — HMI panel exploitation `~lab`
- hardware-safety-instrumented — SIS/safety-instrumented systems `~lab`
- hardware-quantum-hw — quantum hardware attack surface `-lab`

## cloud (existing 123 — SaaS identity, provider breadth, PaaS/serverless)

- cloud-okta — Okta tenant/identity attacks `~lab`
- cloud-okta-deep — Okta deep (OIDC apps, MFA, policies) `~lab`
- cloud-m365 — Microsoft 365 tenant attacks `~lab`
- cloud-m365-entra — Entra ID / Azure AD identity attacks `+lab`
- cloud-google-workspace — Google Workspace attacks `~lab`
- cloud-saml-federation — SAML federation abuse `+lab`
- cloud-mfa-bypass — MFA bypass techniques `+lab`
- cloud-prt-attacks — Primary Refresh Token attacks `~lab`
- cloud-saas-enum — SaaS tenant/user enumeration `+lab`
- cloud-oci — Oracle Cloud Infrastructure security `~lab`
- cloud-alibaba — Alibaba Cloud (Aliyun) security `~lab`
- cloud-ibm-cloud — IBM Cloud security `~lab`
- cloud-digitalocean — DigitalOcean security `+lab`
- cloud-linode — Linode/Akamai security `~lab`
- cloud-vultr — Vultr security `~lab`
- cloud-hetzner — Hetzner security `~lab`
- cloud-fly-io — Fly.io security `~lab`
- cloud-railway — Railway security `~lab`
- cloud-vercel — Vercel security `~lab`
- cloud-netlify — Netlify security `~lab`
- cloud-cloudflare-workers — Cloudflare Workers security `~lab`
- cloud-supabase — Supabase security `~lab`
- cloud-aws-apprunner — AWS App Runner security `~lab`
- cloud-azure-container-apps — Azure Container Apps security `~lab`
- cloud-gcp-cloudrun — GCP Cloud Run security `~lab`
- cloud-terraform-cloud — Terraform Cloud/state attacks `~lab`
- cloud-pulumi — Pulumi IaC security `~lab`
- cloud-crossplane — Crossplane security `~lab`
- cloud-datadog — Datadog SaaS security `~lab`
- cloud-snowflake — Snowflake data-cloud attacks `~lab`
- cloud-salesforce-saas — Salesforce SaaS security `~lab`

---

## Reconciliation with the raw per-category lists (`docs/gaps/gB-*.md`)

The full independent gap analyses landed as 12 raw files (`gB-cloud.md` … `gB-web.md`,
~2500 candidate items total). Those are the **authoritative raw backlog**; this file is the
curated, collision-checked **MISSING core** (306). Two input formats were found:

- **Format A** (bare bullets): `gB-cloud, gB-forensics, gB-hardware, gB-misc, gB-mobile,
  gB-network, gB-osint, gB-stego` — cloud 215, forensics 253, hardware 156, misc 305,
  mobile 330, network 152, osint 153, stego 185 candidates.
- **Format B** (`[MISSING]`/`[THIN]` markers): `gB-web, gB-crypto, gB-pwn, gB-reversing` —
  web 259 MISSING/1 THIN, crypto 125/12, pwn 179/1, reversing 174/9.

**`[THIN]` ≠ new lesson.** Format-B files tag 23 entries `[THIN]` — the lesson file already
exists and needs *deepening* to ≥1200 real words, not authoring. Collision scan of Format B
found 20 such ids already present (crypto 12, reversing 8): e.g. `crypto-classical-deep`,
`crypto-tls-attacks`, `crypto-hd-wallets`, `reversing-ransomware`, `reversing-intel-pt`,
`reversing-python-bytecode`. Authoring agents must treat those as **deepen** tasks (see the
crypto/stego thin-lesson deepen work already in flight), never as new files.

**Zero collisions** were found among this file's 306 MISSING ids — author those first; then
work the remaining ~2000 Format-A/MISSING items from the raw `gB-*.md` files (they are
unchecked for collisions, so re-verify each `content/<cat>/<id>.md` before writing).
