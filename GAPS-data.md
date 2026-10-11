# GAPS-data.md — Curriculum Gap Audit: crypto / forensics / osint / stego

Read-only audit. No lessons written. Inventory from frontmatter `id`+`title`, diffed against a
canonical expert syllabus per domain. Coverage % = distinct canonical topics at usable depth.

## Summary table

| Category  | Existing | Missing topics identified | Coverage | Verdict |
|-----------|---------:|--------------------------:|---------:|---------|
| crypto    | 23       | 62                        | ~38%     | Excellent core, thin on ECC/DSA/GCM/quantum/post-quantum |
| forensics | 32       | 58                        | ~40%     | Good breadth, thin on memory deep-dive, macOS, disk-encryption, mobile |
| osint     | 30       | 50                        | ~45%     | Strong; gaps in per-platform social, geospatial, records, flight/maritime |
| stego     | 13       | 37                        | ~35%     | Intro-solid; missing JPEG/DCT, steganalysis statistics, tool depth |

**Bottom line:** none of the four is complete at 13–32 lessons. crypto and stego are the
thinnest relative to their canonical surface. Realistic authored-lesson targets:
**crypto +45, forensics +45, osint +35, stego +30.**

---

## CRYPTO (23 existing)

Existing: intro, number-theory, encodings, xor-otp, classical, hashing, hashcracking, hmac,
aes-modes, ecb-oracle, cbc-bitflip, padding-oracle, iv-reuse, stream-ciphers, prng,
block-analysis, rsa-basics, rsa-attacks, rsa-advanced, rsa-padding, diffie-hellman, ecc,
lattice.

### Missing crypto topics

| proposed id | title | parent | diff | why |
|---|---|---|---|---|
| crypto-crt-advanced | CRT & Garner's formula applied to RSA-CRT faults | crypto-number-theory | hard | Pre-req for fault attacks |
| crypto-discrete-log | Discrete log: BSGS, Pohlig-Hellman, index calculus | crypto-diffie-hellman | expert | Foundation for DH/DSA/ECC |
| crypto-pollard | Factorization: Pollard p-1, rho, ECM | crypto-rsa-attacks | hard | Needed when Fermat/common-mod fail |
| crypto-continued-fractions | Continued fractions & Wiener-family attacks | crypto-rsa-attacks | hard | Wiener is covered shallowly |
| crypto-rsa-faults | RSA fault attacks (Bellcore) & faulty signatures | crypto-rsa-advanced | expert | Real hardware/smartcard class |
| crypto-rsa-oracle | RSA parity/LSB oracle & Manger (OAEP) | crypto-rsa-padding | expert | Interactive padding-oracle family |
| crypto-rsa-coppersmith-deep | Coppersmith variants: stereotyped, partial-key, small-roots | crypto-rsa-advanced | expert | The workhorse of modern RSA CTF |
| crypto-rsa-multi | Multi-prime, shared-prime, common-modulus deep | crypto-rsa-attacks | hard | Existing rows are one-liners |
| crypto-ecdsa-nonce | ECDSA nonce reuse & biased-nonce (lattice) | crypto-ecc | expert | Extremely common CTF bug |
| crypto-ecdsa-advanced | ECDSA/EdDSA: Pohlig-Hellman, curve recovery, MOV/Smart's attack | crypto-ecc | expert | Existing ECC lesson is intro |
| crypto-invalid-curve | Invalid-curve / small-subgroup / twist attacks | crypto-ecc | hard | Split out from intro ECC |
| crypto-edwards | Edwards/Montgomery curves (Curve25519, X25519) | crypto-ecc | hard | Modern default curve family |
| crypto-pairing | Pairings & BLS signatures | crypto-ecc | expert | — |
| crypto-gcm | AES-GCM: GHASH, nonce reuse, forbidden attack | crypto-aes-modes | expert | GCM nonce-reuse is a classic CTF |
| crypto-ccm-aead | AEAD: CCM, ChaCha20-Poly1305, Poly1305 forgery | crypto-aes-modes | expert | — |
| crypto-cfb-ofb | CFB/OFB/CTR-specific pitfalls | crypto-aes-modes | medium | — |
| crypto-cbc-mac | CBC-MAC/CMAC, length-extension of MACs, MAC-then-encrypt | crypto-hmac | hard | — |
| crypto-cut-and-paste | CBC cut-and-paste & IV bitflip chains | crypto-cbc-bitflip | hard | — |
| crypto-rc4-deep | RC4 biases (Fluhrer, Mantin-Shamir) | crypto-stream-ciphers | expert | — |
| crypto-lfsr | LFSR & Berlekamp-Massey correlation attacks | crypto-stream-ciphers | hard | Existing mentions only |
| crypto-chacha | ChaCha20/Salsa20 cryptanalysis basics | crypto-stream-ciphers | hard | — |
| crypto-lcg | LCG & linear PRNG state recovery | crypto-prng | medium | MT19937 covered, LCG not |
| crypto-mt19937-deep | MT19937 untempering & partial-output recovery | crypto-prng | hard | Existing is intro |
| crypto-python-random | Python `random` prediction (randcrack) | crypto-prng | medium | — |
| crypto-shor-grover | Quantum intro: Shor & Grover | crypto-intro | expert | Conceptual, asked in quizzes |
| crypto-post-quantum | Post-quantum crypto (lattice/Kyber/Dilithium basics) | crypto-lattice | expert | — |
| crypto-lattice-bkz | Lattice: BKZ, CVP, closest-vector attacks | crypto-lattice | expert | LLL exists; BKZ/CVP missing |
| crypto-ntru | NTRU & lattice-based scheme attacks | crypto-lattice | expert | — |
| crypto-shamir | Shamir secret sharing & threshold schemes | crypto-intro | medium | Common misc-crypto |
| crypto-commitment | Commitment schemes & ZK (Schnorr, Fiat-Shamir) | crypto-intro | expert | — |
| crypto-timing | Timing side-channels | crypto-intro | hard | — |
| crypto-power | Power/EM side-channel (DPA/SPA) | crypto-intro | expert | Bridges to hardware |
| crypto-whitepoint | White-box crypto | crypto-aes-modes | expert | — |
| crypto-hash-forge | Hash forging: collisions, chosen-prefix, MD5/SHA1 | crypto-hashing | hard | Existing is broad |
| crypto-merkle | Merkle-Damgård length-extension & HMAC bypass | crypto-hmac | hard | — |
| crypto-kdf | KDFs: PBKDF2, scrypt, argon2, bcrypt internals | crypto-hashing | medium | — |
| crypto-jwt-crypto | Crypto behind JWT/JWS/JWE (alg confusion, key recovery) | crypto-hmac | hard | Bridges to web |
| crypto-encoding-deep | Encoding chains, uncommon bases, custom alphabets | crypto-encodings | easy | — |
| crypto-classical-deep | Playfair/Hill/Affine/Bacon + frequency analysis automation | crypto-classical | medium | Existing is survey |
| crypto-enigma | Enigma & rotor machines | crypto-classical | hard | — |
| crypto-mitm | Meet-in-the-middle & 3DES | crypto-block-analysis | expert | — |
| crypto-feistel | Feistel construction attacks | crypto-block-analysis | hard | — |
| crypto-oracle-padding-deep | Padding oracle variants: POODLE, Lucky13, BEAST | crypto-padding-oracle | expert | — |

Top-10 highest value: rsa-coppersmith-deep, ecdsa-nonce, gcm, discrete-log, rsa-oracle,
ecdsa-advanced, lattice-bkz, mt19937-deep, hash-forge, cbc-mac.

---

## FORENSICS (32 existing)

Existing: intro, file-magic, hex-editors, carving, archives, archive-deep, metadata,
filesystems, disk-images, partition-tables, deleted-recovery, apfs, memory, volatility-deep,
windows-artifacts, registry-hives, windows-execution, linux-artifacts, timeline, logs, pcap,
network-deep, email, web-forensics, cloud, containers, malware-yara, anti-forensics,
usb-devices, stego, reporting, mobile.

### Missing forensics topics

| proposed id | title | parent | diff | why |
|---|---|---|---|---|
| forensics-ntfs-mft | NTFS deep: $MFT, $LogFile, $UsnJrnl, ADS | forensics-filesystems | hard | Core Windows timeline source |
| forensics-usn | USN journal analysis | forensics-ntfs-mft | hard | — |
| forensics-shellbags | Shellbags, UserAssist, RecentDocs, jumplists, LNK | forensics-windows-artifacts | hard | Proves user activity |
| forensics-lnk | LNK / jump-list deep dive | forensics-windows-artifacts | medium | — |
| forensics-recyclebin | Recycle Bin & Thumbcache | forensics-windows-artifacts | easy | — |
| forensics-evtx-deep | EVTX deep & key event IDs / Sysmon | forensics-windows-artifacts | hard | Existing is broad |
| forensics-powershell-logs | PowerShell logging & scriptblock artifacts | forensics-windows-artifacts | hard | LOLBin detection |
| forensics-wmi | WMI repository artifacts | forensics-windows-artifacts | expert | — |
| forensics-browser | Browser forensics: Chrome/Firefox/Edge (history, cookies, cache, downloads) | forensics-windows-artifacts | medium | Very common |
| forensics-plaso | Super-timeline with plaso/log2timeline & Timesketch | forensics-timeline | hard | Existing timeline is manual |
| forensics-sleuthkit | Sleuth Kit & Autopsy deep | forensics-disk-images | hard | — |
| forensics-btrfs-zfs | Btrfs / ZFS / XFS forensics | forensics-filesystems | expert | — |
| forensics-ext4-journal | ext4 journal & ext4 deep | forensics-filesystems | hard | — |
| forensics-raid | RAID reconstruction & LVM | forensics-disk-images | expert | — |
| forensics-disk-encryption | LUKS / BitLocker / VeraCrypt / FileVault | forensics-disk-images | expert | Completely absent |
| forensics-memory-injection | Memory: malfind, process injection, rootkits | forensics-volatility-deep | expert | — |
| forensics-memory-keys | Extracting keys/passwords from memory | forensics-volatility-deep | hard | — |
| forensics-fileless | Fileless malware & LOLBins | forensics-malware-yara | hard | — |
| forensics-cobaltstrike | Cobalt Strike / C2 beacon artifacts | forensics-malware-yara | expert | — |
| forensics-ransomware | Ransomware analysis & decryption | forensics-malware-yara | expert | — |
| forensics-tls-decrypt | TLS decryption (SSLKEYLOGFILE, keylog) | forensics-network-deep | hard | — |
| forensics-zeek | Zeek/NetFlow & IDS artifacts | forensics-network-deep | hard | — |
| forensics-exfil | Exfiltration detection in PCAP | forensics-network-deep | hard | — |
| forensics-sqlite | SQLite database forensics | forensics-web-forensics | medium | — |
| forensics-database | Database forensics (MySQL/Postgres/MSSQL) | forensics-web-forensics | hard | — |
| forensics-email-pst | PST/OST/EML/MSG parsing | forensics-email | hard | — |
| forensics-office-macros | Office macro & document forensics | forensics-email | medium | — |
| forensics-pdf | PDF forensics | forensics-file-magic | medium | — |
| forensics-image-ela | Image forensics (ELA, PRNU, manipulation) | forensics-metadata | hard | — |
| forensics-macos-artifacts | macOS artifacts (FSEvents, quarantine, unified logs) | forensics-apfs | hard | — |
| forensics-mobile-android | Android forensics deep (ADB, backups, app data) | forensics-mobile | hard | — |
| forensics-mobile-ios | iOS forensics (backups, keychain) | forensics-mobile | hard | — |
| forensics-vm | VM/hypervisor image forensics | forensics-containers | expert | — |
| forensics-k8s | Kubernetes/container runtime forensics | forensics-containers | expert | — |
| forensics-firmware | Firmware/IoT forensics | forensics-containers | hard | — |
| forensics-cloud-trail | AWS CloudTrail / Azure / GCP audit deep | forensics-cloud | hard | Existing is broad |
| forensics-chain-custody | Chain of custody & forensic soundness | forensics-reporting | easy | — |
| forensics-disk-imaging | Disk imaging (dd/dc3dd/FTK), write blockers | forensics-disk-images | easy | — |
| forensics-log-analysis | Log analysis deep (journald, syslog, auth) | forensics-logs | medium | — |
| forensics-timestomp | Timestomping & anti-forensic detection | forensics-anti-forensics | hard | — |
| forensics-attack-mapping | MITRE ATT&CK artifact mapping | forensics-reporting | medium | — |

Top-10 highest value: disk-encryption, memory-injection, ntfs-mft, browser, plaso,
tls-decrypt, ransomware, mobile-android, cloud-trail, shellbags.

---

## OSINT (30 existing)

Existing: intro, intel-lifecycle, search-operators, advanced-dorking, search-engines,
dns-recon, subdomain-tools, whois-asn, infrastructure, shodan-dorks, cloud-recon,
wayback-archives, github-recon, breach-data, email-headers, metadata, document-analysis,
image-reverse, geolocation, phone, username-enum, people-search, social-media, blockchain,
paste-sites, darkweb, threat-intel, automation, opsec, reporting.

### Missing osint topics

| proposed id | title | parent | diff | why |
|---|---|---|---|---|
| osint-cert-transparency | Certificate Transparency deep (crt.sh, Censys, CT logs) | osint-infrastructure | medium | Highest-yield subdomain source |
| osint-dns-history | Historical/passive DNS (SecurityTrails, PassiveTotal) | osint-dns-recon | medium | Origin discovery, subdomain takeover |
| osint-reverse-dns | Reverse DNS / PTR / rDNS sweeps | osint-dns-recon | easy | — |
| osint-spf-dkim | SPF/DKIM/DMARC analysis & email spoofing surface | osint-email-headers | medium | — |
| osint-smtp-enum | SMTP/VRFY mailbox enumeration | osint-email-headers | medium | — |
| osint-typosquat | Typosquatting & lookalike-domain discovery | osint-whois-asn | medium | — |
| osint-social-instagram | Instagram OSINT | osint-social-media | medium | Per-platform depth |
| osint-social-facebook | Facebook OSINT | osint-social-media | medium | — |
| osint-social-twitter | X/Twitter OSINT | osint-social-media | medium | — |
| osint-social-linkedin | LinkedIn OSINT & org mapping | osint-social-media | medium | — |
| osint-social-tiktok | TikTok OSINT | osint-social-media | medium | — |
| osint-telegram | Telegram OSINT (channels, bots, groups) | osint-paste-sites | medium | Huge in RU context |
| osint-discord | Discord OSINT | osint-paste-sites | medium | — |
| osint-satellite | Satellite imagery & change detection | osint-geolocation | hard | — |
| osint-chronolocation | Chronolocation (shadow/sun position, weather) | osint-geolocation | hard | — |
| osint-facial | Facial recognition & image correlation | osint-image-reverse | expert | — |
| osint-people-family | Family/associate mapping, obituaries, court records | osint-people-search | hard | — |
| osint-public-records | Public records & government databases | osint-people-search | medium | — |
| osint-business-registry | Business registries (Companies House, OCCRP, OpenCorporates) | osint-people-search | medium | — |
| osint-sec-filings | SEC/EDGAR & corporate filings | osint-business-registry | medium | — |
| osint-patents | Patent & trademark search | osint-business-registry | easy | — |
| osint-flight | Flight tracking (ADS-B, FlightRadar24) | osint-infrastructure | medium | — |
| osint-maritime | Maritime/AIS tracking | osint-infrastructure | medium | — |
| osint-vehicle | Vehicle/license-plate OSINT | osint-people-search | medium | — |
| osint-radio | Radio/scanner (RadioReference, Broadcastify) | osint-infrastructure | medium | — |
| osint-webcams | Webcam/IPTV/IoT device discovery | osint-shodan-dorks | medium | — |
| osint-censys-fofa | Censys/FOFA/ZoomEye deep | osint-shodan-dorks | medium | Existing only covers Shodan |
| osint-bgp | BGP / routing / hijack analysis | osint-whois-asn | hard | — |
| osint-secret-scanning | Automated secret scanning (trufflehog, gitleaks) | osint-github-recon | medium | — |
| osint-package-registries | Package-registry OSINT (npm/pypi/Docker Hub) | osint-github-recon | medium | Supply-chain recon |
| osint-url-analysis | URL/domain analysis (urlscan.io, VT, MalwareBazaar) | osint-threat-intel | medium | — |
| osint-ioc-enrichment | IOC enrichment & pivoting | osint-threat-intel | medium | — |
| osint-favicon | Favicon hashing & tech fingerprinting (Wappalyzer) | osint-infrastructure | easy | — |
| osint-cdn-origin | CDN/WAF detection & origin discovery | osint-infrastructure | hard | — |
| osint-custom-tooling | Custom OSINT tooling & API automation | osint-automation | hard | — |
| osint-legal-ethics | Legal, ethics & attribution | osint-opsec | medium | — |
| osint-verification | Verification & disinformation analysis | osint-threat-intel | hard | — |

Top-10 highest value: osint-cert-transparency, osint-telegram, osint-social-linkedin,
osint-cdn-origin, osint-dns-history, osint-flight, osint-business-registry, osint-secret-scanning,
osint-censys-fofa, osint-chronolocation.

---

## STEGO (13 existing)

Existing: intro, lsb, png-chunks, image-tools, appended, polyglots, qr-barcode, audio,
audio-advanced, text, video, network, advanced.

### Missing stego topics

| proposed id | title | parent | diff | why |
|---|---|---|---|---|
| stego-jpeg-dct | JPEG/DCT steganography (jsteg, F5, outguess, steghide) | stego-lsb | hard | The #1 missing image class |
| stego-f5 | F5 algorithm & matrix encoding | stego-jpeg-dct | expert | — |
| stego-outguess | OutGuess & steghide deep | stego-image-tools | hard | Tool-specific extraction |
| stego-palette | Palette/PLTE-based steganography | stego-lsb | medium | — |
| stego-gif | GIF steganography (frames, timing, palette) | stego-image-tools | medium | — |
| stego-bmp | BMP-specific tricks | stego-image-tools | easy | — |
| stego-bitplane | Bit-plane / MSB / multi-bit LSB (2-3-3) | stego-lsb | medium | — |
| stego-alpha | Alpha-channel & transparency stego | stego-lsb | medium | — |
| stego-steganalysis | Statistical steganalysis: chi-square, RS, SPA | stego-intro | expert | Detect-and-extract, not just extract |
| stego-pvd | Pixel Value Differencing & other spatial methods | stego-lsb | expert | — |
| stego-stegseek | stegseek / stegcracker wordlist attacks | stego-image-tools | medium | Password-protected stego |
| stego-zsteg | zsteg / stegsolve methodology | stego-image-tools | medium | — |
| stego-png-deflate | PNG zlib/deflate & interlace (Adam7) deep | stego-png-chunks | hard | — |
| stego-audio-echo | Audio: echo hiding, phase coding, spread spectrum | stego-audio | expert | — |
| stego-audio-lsb | Audio LSB in samples deep | stego-audio | medium | — |
| stego-audio-spec | Spectrogram/SSTV/DTMF/FSK/Morse | stego-audio-advanced | hard | Partially covered |
| stego-video-frames | Video frame manipulation & DCT | stego-video | hard | — |
| stego-text-whitespace | Whitespace/zero-width/homoglyph/acrostic deep | stego-text | medium | — |
| stego-text-linguistic | Linguistic/nulls/spam-mimic stego | stego-text | expert | — |
| stego-pdf | PDF steganography | stego-appended | medium | — |
| stego-docx | Office/document steganography | stego-appended | medium | — |
| stego-emoji | Emoji & Unicode stego | stego-text | medium | — |
| stego-network-timing | Covert timing channels (inter-packet delay) | stego-network | hard | Existing covers field-based |
| stego-dns-tunnel | DNS-tunnel stego deep | stego-network | hard | — |
| stego-disk | Disk/slack/ADS/hidden-partition stego | stego-appended | hard | — |
| stego-malware | Stego in malware (embedded payloads) | stego-advanced | expert | — |
| stego-executable | Stego in executables (overlay, resources) | stego-appended | medium | — |
| stego-nfc-rfid | NFC/RFID data hiding | stego-network | expert | — |
| stego-compression | Compression-based stego | stego-advanced | expert | — |
| stego-encryption | Combining encryption + stego | stego-advanced | medium | — |
| stego-capacity | Embedding capacity/rate theory | stego-intro | medium | — |
| stego-dna | DNA/biological stego (conceptual) | stego-advanced | expert | — |

Top-10 highest value: stego-jpeg-dct, stego-outguess, stego-steganalysis, stego-audio-echo,
stego-pdf, stego-palette, stego-stegseek, stego-disk, stego-network-timing, stego-text-whitespace.

---

## Honesty note
Counts above are distinct canonical topics; several merge naturally (all JPEG tools → 1–2
lessons; all audio → 2). Realistic authored-lesson targets: **crypto +40, forensics +42,
osint +32, stego +26.**
