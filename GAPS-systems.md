# GAPS-systems.md — Curriculum Gap Audit: hardware / network / cloud / mobile / misc

Read-only audit. No lessons written. Inventory from frontmatter `id`+`title`, diffed against a
canonical expert syllabus per domain.

## Summary table

| Category  | Existing | Missing topics identified | Coverage | Verdict |
|-----------|---------:|--------------------------:|---------:|---------|
| hardware  | 12       | 30                        | ~45%     | Strong for 12; missing PCB/logic/EM side, CAN, fault-injection depth |
| network   | 12       | 34                        | ~40%     | Solid core; missing wireless (802.11), routing attacks, IPv6 depth |
| cloud     | 12       | 28                        | ~50%     | Good AWS-centric core; thin on Azure/GCP specifics, container escapes deep |
| mobile    | 13       | 30                        | ~45%     | Android-strong; iOS thin; missing platform-agnostic ATO chains |
| misc      | 12       | 22                        | ~50%     | Fine as "misc"; some topics belong to other categories |

**Bottom line:** these categories are smaller by nature but still leave real gaps. Realistic
authored-lesson targets: **hardware +20, network +28, cloud +22, mobile +24, misc +12.**

---

## HARDWARE (12 existing)

Existing: intro, uart, spi, i2c, jtag, rf, rfid-nfc, sidechannel, firmware-extract,
firmware-emulation, crypto, iot-network.

### Missing hardware topics

| proposed id | title | parent | diff | why |
|---|---|---|---|---|
| hardware-logic-analysis | Logic analysis & signal decoding (Saleae, sigrok) | hardware-intro | medium | Prereq for all bus work |
| hardware-pcb-reversing | PCB reversing & trace mapping | hardware-intro | hard | — |
| hardware-multimeter-scope | Multimeter/oscilloscope basics for HW | hardware-intro | easy | — |
| hardware-fault-injection | Voltage/clock glitching & fault injection deep | hardware-sidechannel | expert | Existing sidechannel is intro |
| hardware-em-sidechannel | EM side-channel (DPA/SPA) | hardware-sidechannel | expert | — |
| hardware-secure-boot | Secure boot bypass (U-Boot, verified boot) | hardware-firmware-emulation | expert | — |
| hardware-flash-dumping | Flash dumping variants (eMMC, NAND, NAND-bad-blocks) | hardware-spi | hard | — |
| hardware-jtag-deep | JTAG/SWD deep: boundary scan, debug-lock bypass | hardware-jtag | expert | — |
| hardware-swd-advanced | SWD advanced & CoreSight | hardware-jtag | expert | — |
| hardware-can-bus | CAN bus & automotive (OBD-II, UDS) | hardware-iot-network | hard | Absent; big domain |
| hardware-rs232-rs485 | RS-232/RS-485 & industrial serial | hardware-uart | medium | — |
| hardware-onewire | 1-Wire, Modbus, industrial protocols | hardware-i2c | medium | — |
| hardware-can-uds | UDS diagnostics & ECU reversing | hardware-can-bus | expert | — |
| hardware-bluetooth | Bluetooth/BLE deep (sniffing, pairing, GATT) | hardware-rf | hard | Existing RF is broad |
| hardware-zigbee-zwave | Zigbee/Z-Wave sniffing & replay | hardware-rf | expert | — |
| hardware-subghz | Sub-GHz replay/rolljam (Keeloq, rolling codes) | hardware-rf | hard | — |
| hardware-rtl-sdr | RTL-SDR/GNU Radio workflow | hardware-rf | medium | — |
| hardware-smartcard | Smart-card / ISO7816 attacks | hardware-rfid-nfc | expert | — |
| hardware-mifare-deep | Mifare Classic cryptanalysis (nested, hardnested) | hardware-rfid-nfc | expert | Existing is intro |
| hardware-emv | EMV / payment-card attacks | hardware-rfid-nfc | expert | — |
| hardware-iot-firmware-diff | Firmware diffing & CVE hunting | hardware-firmware-extract | hard | — |
| hardware-iot-cloud | IoT cloud/MQTT attack surface | hardware-iot-network | medium | — |
| hardware-mqtt-coap | MQTT/CoAP protocol attacks | hardware-iot-network | medium | — |
| hardware-hardware-trojan | Hardware trojans & supply chain | hardware-intro | expert | — |
| hardware-nfc-relay | NFC relay & contactless attacks | hardware-rfid-nfc | hard | — |
| hardware-rfid-clone | RFID cloning (125kHz, HID Prox) | hardware-rfid-nfc | easy | — |
| hardware-embedded-debug | Embedded debug interfaces (ETM, trace) | hardware-jtag | expert | — |
| hardware-rtos | RTOS reversing & memory analysis | hardware-firmware-emulation | hard | — |
| hardware-uefi | UEFI/BIOS attack surface | hardware-firmware-extract | expert | — |
| hardware-scada | SCADA/ICS protocols (Modbus, DNP3, S7) | hardware-iot-network | expert | — |

Top-10 highest value: hardware-can-bus, hardware-bluetooth, hardware-fault-injection,
hardware-secure-boot, hardware-mifare-deep, hardware-can-uds, hardware-logic-analysis,
hardware-scada, hardware-em-sidechannel, hardware-iot-cloud.

---

## NETWORK (12 existing)

Existing: intro, tcpip, tcpdump, wireshark, pcap-analysis, portscan, arp, mitm,
tls-inspection, protocol-reversing, covert, firewall-evasion.

### Missing network topics

| proposed id | title | parent | diff | why |
|---|---|---|---|---|
| network-wireless-80211 | 802.11 Wi-Fi: WPA2/WPA3, handshake, PMKID, evil twin | network-mitm | hard | Entire wireless domain absent |
| network-wpa3 | WPA3/SAE & Dragonblood | network-wireless-80211 | expert | — |
| network-evil-twin | Evil twin, captive portal & rogue AP | network-wireless-80211 | medium | — |
| network-arp-deep | ARP spoofing deep & detection | network-arp | medium | Existing is broad |
| network-dns-attacks | DNS attacks: spoofing, cache poisoning, tunneling, rebinding | network-arp | hard | DNS covered only as spoof partner |
| network-dnssec | DNSSEC & validation bypass | network-dns-attacks | expert | — |
| network-dhcp | DHCP attacks & rogue DHCP | network-mitm | medium | — |
| network-ipv6 | IPv6 deep: SLAAC, ND, RA, tunneling | network-firewall-evasion | hard | Existing mentions IPv6 only |
| network-routing | Routing attacks: BGP hijack, OSPF/EIGRP injection | network-intro | expert | — |
| network-vlan-hopping | VLAN hopping, 802.1Q, DTP | network-mitm | hard | — |
| network-layer2-attacks | L2 attacks: STP, MAC flooding, port security | network-mitm | hard | — |
| network-nac-bypass | NAC/802.1X bypass | network-mitm | expert | — |
| network-idps-evasion | IDS/IPS evasion deep (fragmentation, obfuscation) | network-firewall-evasion | expert | — |
| network-nmap-deep | Nmap deep: NSE, timing, OS fingerprint, evasion | network-portscan | medium | — |
| network-masscan | Masscan & large-scale scanning | network-portscan | medium | — |
| network-service-enum | Service enumeration deep (SMB, SNMP, RDP, LDAP) | network-portscan | hard | Bridges to infra |
| network-snmp | SNMP enumeration & abuse | network-portscan | medium | — |
| network-kerberos | Kerberos protocol attacks (network view) | network-protocol-reversing | expert | Bridges to AD |
| network-ntlm-relay | NTLM relay & coercion (network view) | network-mitm | expert | — |
| network-pppoe | PPPoE/PPTP/VPN protocols | network-intro | medium | — |
| network-wireguard | WireGuard/IPsec analysis | network-intro | hard | — |
| network-openvpn | OpenVPN protocol analysis | network-intro | medium | — |
| network-ssh-tunnel | SSH tunneling & port forwarding | network-covert | medium | — |
| network-tor | Tor & anonymizing networks | network-covert | medium | — |
| network-dns-tunnel | DNS tunneling deep (iodine, dnscat2) | network-covert | hard | Existing is survey |
| network-icmp-tunnel | ICMP & protocol tunneling | network-covert | medium | — |
| network-covert-timing | Timing/covert channels | network-covert | hard | — |
| network-traffic-analysis-ctf | CTF traffic analysis workflow | network-pcap-analysis | medium | — |
| network-usb-pcap | USB/serial capture analysis | network-pcap-analysis | hard | — |
| network-voip | VoIP/SIP analysis | network-protocol-reversing | hard | — |
| network-scada-protocols | ICS protocols on the wire | network-protocol-reversing | expert | — |
| network-quic | QUIC/HTTP3 analysis | network-tls-inspection | expert | — |
| network-tls-attacks | TLS attacks: downgrade, Heartbleed, POODLE, BEAST | network-tls-inspection | expert | — |
| network-firewall-piercing | Firewall piercing & reverse shells | network-firewall-evasion | hard | — |

Top-10 highest value: network-wireless-80211, network-dns-attacks, network-ipv6,
network-kerberos, network-ntlm-relay, network-vlan-hopping, network-tls-attacks,
network-dns-tunnel, network-routing, network-idps-evasion.

---

## CLOUD (12 existing)

Existing: fundamentals, iam-basics, privesc-iam, storage-s3, metadata-ssrf, containers-docker,
kubernetes-rbac, serverless, cicd-secrets, credential-hunting, logging-detection, supply-chain.

### Missing cloud topics

| proposed id | title | parent | diff | why |
|---|---|---|---|---|
| cloud-azure-basics | Azure fundamentals & attack surface | cloud-fundamentals | medium | Only AWS-centric today |
| cloud-azure-iam | Azure AD/Entra ID & RBAC abuse | cloud-iam-basics | hard | — |
| cloud-azure-managed-identity | Azure managed identity & IMDS abuse | cloud-metadata-ssrf | expert | — |
| cloud-gcp-basics | GCP fundamentals & attack surface | cloud-fundamentals | medium | — |
| cloud-gcp-iam | GCP IAM & service-account impersonation | cloud-iam-basics | hard | — |
| cloud-assume-role | Cross-account role chaining & confused deputy | cloud-privesc-iam | expert | — |
| cloud-ssrf-to-cloud | SSRF → cloud takeover chains (AWS/Azure/GCP) | cloud-metadata-ssrf | expert | — |
| cloud-eks-aks-gke | Managed Kubernetes (EKS/AKS/GKE) attacks | cloud-kubernetes-rbac | expert | — |
| cloud-kubernetes-escape | Kubernetes escape deep (hostPath, privileged, nsenter) | cloud-containers-docker | expert | Existing is RBAC-focused |
| cloud-docker-socket | Docker socket exposure & escapes | cloud-containers-docker | hard | — |
| cloud-container-runtime | containerd/CRI-O/runc CVEs (runc escape) | cloud-containers-docker | expert | — |
| cloud-k8s-admission | K8s admission controllers, OPA, pod-security bypass | cloud-kubernetes-rbac | expert | — |
| cloud-k8s-secrets | K8s secrets, etcd, service-account token theft | cloud-kubernetes-rbac | hard | — |
| cloud-serverless-injection | Serverless event-source injection deep (Lambda/SQS/API GW) | cloud-serverless | hard | — |
| cloud-lambda-privesc | Lambda role privesc & layer poisoning | cloud-serverless | expert | — |
| cloud-cicd-github-actions | GitHub Actions abuse (workflow injection, OIDC) | cloud-cicd-secrets | hard | — |
| cloud-cicd-jenkins | Jenkins/GitLab CI exploitation | cloud-cicd-secrets | hard | — |
| cloud-oidc-federation | OIDC federation & trust-policy abuse | cloud-cicd-secrets | expert | — |
| cloud-secrets-manager | Secrets Manager/Key Vault/KMS abuse | cloud-credential-hunting | hard | — |
| cloud-terraform | Terraform/IaC state & drift abuse | cloud-supply-chain | hard | — |
| cloud-cloudformation | CloudFormation/ARM template abuse | cloud-supply-chain | expert | — |
| cloud-s3-deep | S3 deep: ACLs, bucket policies, presigned URL abuse | cloud-storage-s3 | medium | — |
| cloud-database-exposure | Exposed RDS/Cosmos/Cloud SQL | cloud-storage-s3 | medium | — |
| cloud-cloudtrail-evasion | CloudTrail/GuardDuty evasion & OPSEC | cloud-logging-detection | expert | — |
| cloud-post-exploit | Cloud post-exploitation & persistence | cloud-privesc-iam | expert | — |
| cloud-aws-organizations | AWS Organizations/SCP & multi-account | cloud-iam-basics | hard | — |
| cloud-ec2-ssrf | EC2/IMDSv2 bypass & SSRF | cloud-metadata-ssrf | hard | — |
| cloud-container-forensics | Cloud/container forensics | cloud-logging-detection | hard | Bridges to forensics |

Top-10 highest value: cloud-azure-basics, cloud-gcp-basics, cloud-kubernetes-escape,
cloud-assume-role, cloud-cicd-github-actions, cloud-ssrf-to-cloud, cloud-secrets-manager,
cloud-docker-socket, cloud-lambda-privesc, cloud-cloudtrail-evasion.

---

## MOBILE (13 existing)

Existing: intro, android-anatomy, static-analysis, dynamic-frida, ssl-pinning,
root-detection, insecure-storage, exported-components, intents-deeplinks, webview,
obfuscation, api-testing, ios-basics.

### Missing mobile topics

| proposed id | title | parent | diff | why |
|---|---|---|---|---|
| mobile-android-native | Android native/JNI reversing & .so analysis | mobile-static-analysis | hard | Java-only today |
| mobile-android-packers | Android packers & anti-tamper (ProGuard/R8 deep) | mobile-obfuscation | expert | — |
| mobile-android-instrumentation | Frida deep: RPC, script dev, memory patching | mobile-dynamic-frida | hard | Existing is intro |
| mobile-objection | Objection deep & runtime manipulation | mobile-dynamic-frida | medium | — |
| mobile-ios-static | iOS static analysis (class-dump, Hopper, Swift) | mobile-ios-basics | hard | — |
| mobile-ios-dynamic | iOS dynamic analysis & Frida on iOS | mobile-ios-basics | expert | — |
| mobile-ios-keychain | iOS keychain & data protection | mobile-ios-basics | hard | — |
| mobile-ios-jailbreak | Jailbreak detection bypass | mobile-ios-basics | hard | — |
| mobile-flutter | Flutter/React-Native app reversing | mobile-static-analysis | hard | Increasingly common |
| mobile-crossplatform | Cross-platform frameworks (Cordova, Xamarin) | mobile-static-analysis | medium | — |
| mobile-cert-pinning-deep | Certificate pinning deep (OkHttp, TrustKit, native) | mobile-ssl-pinning | expert | Existing is intro |
| mobile-mitm-burp | Mobile MITM setup (Burp/mitmproxy, system CA) | mobile-ssl-pinning | medium | — |
| mobile-frida-detection | Anti-Frida/anti-debug bypass deep | mobile-root-detection | hard | — |
| mobile-integrity | Root/integrity/SafetyNet bypass | mobile-root-detection | hard | — |
| mobile-backup | App backup extraction & ADB abuse | mobile-insecure-storage | medium | — |
| mobile-keystore | Android Keystore & hardware-backed keys | mobile-insecure-storage | hard | — |
| mobile-deeplink-deep | Deep-link / intent-redirect ATO chains | mobile-intents-deeplinks | hard | — |
| mobile-exported-provider | Content-provider path traversal & SQLi | mobile-exported-components | hard | — |
| mobile-webview-deep | WebView deep: JS bridges, file access, URL spoofing | mobile-webview | hard | — |
| mobile-notifications | Push-notification & FCM abuse | mobile-api-testing | medium | — |
| mobile-api-bola | Mobile BOLA/IDOR chains & device binding | mobile-api-testing | hard | — |
| mobile-account-takeover | Mobile ATO chains (OTP bypass, SIM swap) | mobile-api-testing | expert | — |
| mobile-hardcoded-secrets | Hardcoded secrets & API-key hunting | mobile-static-analysis | easy | — |
| mobile-tls-pinning-bypass | TLS pinning bypass via patching/Frida scripts | mobile-ssl-pinning | hard | — |
| mobile-frida-scripting | Frida scripting for automation | mobile-dynamic-frida | medium | — |
| mobile-android-binder | Android Binder/IPC attacks | mobile-exported-components | expert | — |
| mobile-ios-urlscheme | iOS URL schemes & universal links | mobile-ios-basics | medium | — |
| mobile-automation | Mobile testing automation (MobSF, CI) | mobile-intro | medium | — |
| mobile-malware | Mobile malware analysis | mobile-intro | hard | — |
| mobile-wearable-iot | Wearable/companion-app attack surface | mobile-intro | expert | — |

Top-10 highest value: mobile-android-native, mobile-ios-dynamic, mobile-frida-detection,
mobile-cert-pinning-deep, mobile-account-takeover, mobile-exported-provider,
mobile-deeplink-deep, mobile-android-instrumentation, mobile-flutter, mobile-keystore.

---

## MISC (12 existing)

Existing: intro, encoding, esolang, regex, programming, python-ctf, pwntools-bash, git-forensics,
jails, sandbox, web-logic, prompt-injection.

### Missing misc topics

| proposed id | title | parent | diff | why |
|---|---|---|---|---|
| misc-bash-jails-deep | Bash jail escape deep (restricted shell, rbash) | misc-jails | hard | Existing is Python-centric |
| misc-python-sandbox | Python sandbox escape deep (audit hooks, ctypes) | misc-sandbox | expert | — |
| misc-nodejs-sandbox | Node.js vm/require sandbox escape | misc-sandbox | hard | — |
| misc-lua-sandbox | Lua sandbox escape | misc-sandbox | hard | — |
| misc-ruby-sandbox | Ruby sandbox & deserialization | misc-sandbox | expert | — |
| misc-perl-tricks | Perl/awk/sed CTF tricks | misc-regex | medium | — |
| misc-arithmetic | Big-number & arbitrary-precision puzzles | misc-programming | medium | — |
| misc-graph-theory | Graph/pathfinding CTF problems | misc-programming | hard | — |
| misc-dynamic-programming | DP & optimization puzzles | misc-programming | hard | — |
| misc-number-theory-misc | Misc number-theory puzzles | misc-programming | medium | — |
| misc-image-misc | Image/pixel puzzles (PIL, OCR) | misc-encoding | medium | — |
| misc-pdf-misc | PDF/OCR misc tasks | misc-encoding | medium | — |
| misc-audio-misc | Audio misc tasks (spectrograms) | misc-encoding | medium | Overlaps stego |
| misc-git-advanced | Advanced git forensics (reflog, packfiles, dangling) | misc-git-forensics | hard | — |
| misc-docker-misc | Docker/K8s misc escape | misc-sandbox | hard | — |
| misc-regex-dos | ReDoS & regex engine abuse | misc-regex | hard | — |
| misc-unicode | Unicode normalization & homoglyph tricks | misc-encoding | medium | — |
| misc-time | Time/race/date puzzles | misc-web-logic | medium | — |
| misc-llm-jailbreak | LLM jailbreaks & prompt-injection deep | misc-prompt-injection | hard | Existing is intro |
| misc-ai-misc | AI/ML misc tasks (adversarial) | misc-prompt-injection | expert | — |
| misc-binary-misc | Binary/byte puzzles (XOR, bit ops) | misc-encoding | medium | — |
| misc-crypto-misc | Misc crypto one-liners | misc-encoding | medium | Overlaps crypto |

Top-10 highest value: misc-python-sandbox, misc-git-advanced, misc-nodejs-sandbox,
misc-llm-jailbreak, misc-docker-misc, misc-lua-sandbox, misc-bash-jails-deep,
misc-regex-dos, misc-unicode, misc-graph-theory.

---

## Honesty note
Counts are distinct canonical topics; several merge (all *-sandbox → 2 lessons; all
programming sub-topics → 2–3). Realistic authored-lesson targets: **hardware +18, network +26,
cloud +20, mobile +22, misc +10.**
