# content/crypto — MISSING/THIN lesson candidates (second independent pass, gB)

Inventory: **123** md files.
Verdict: **STRONG** — classical, block/stream ciphers, modes, hashes, MACs, PRNG, RSA (all major attacks), ECC, DH, lattices, Coppersmith, side-channels, ZK/SNARK/STARK, FHE, MPC, secret sharing, PAKE, post-quantum, quantum (Shor/Grover/QKD), and protocols (TLS/SSH/Signal/Noise/Wi-Fi/Kerberos/JWT/PKI) are all present.
Gaps are in: *symmetric-cipher breadth & cryptanalysis families*, *real-world protocol implementations (WebAuthn/OIDC/EMV/DNSSEC)*, *blockchain/HD-wallet crypto depth*, *hardware & microarchitectural side-channels*, *crypto tooling (Sage/PARI/sympy)*, *PQ alternatives (Falcon/multivariate)*, *RNG/entropy engineering*, and *CTF tooling/automation*.

Legend: `[MISSING]` = no lesson; `[THIN]` = a related lesson exists but the specific angle is absent/too shallow.

## Classical & historical
- [MISSING] `crypto-classical-polybius-bifid` — Polybius square, Bifid/Trifid, Nihilist, ADFGX/ADFGVX
- [MISSING] `crypto-classical-transposition-deep` — Транспозиции: route, Myszkowski, двойная, turning grille, Scytale
- [MISSING] `crypto-classical-multi-table` — Porta, Beaufort, Gronsfeld, Autokey, running-key, VIC-шифр
- [MISSING] `crypto-classical-homophonic-book` — Гомофонические подстановки и book/NULL-шифры
- [MISSING] `crypto-classical-solitaire-chaocipher` — Solitaire (Pontifex), Chaocipher, Bazeries
- [MISSING] `crypto-classical-statistics` — Kasiski, индекс совпадений, Friedman, авточастотный анализ
- [MISSING] `crypto-historical-machines` — Lorenz SZ40/42, Purple, Colossus, SIGSALY, Navajo code talkers
- [THIN] `crypto-classical-deep` — уже есть; [THIN] добавить автоматизацию и скрипты (pycipher, simon singh)

## Symmetric ciphers & cryptanalysis families
- [MISSING] `crypto-des-3des-deep` — DES/3DES: S-boxes, ключевое расписание, differential на DES
- [MISSING] `crypto-aes-structure` — AES изнутри: S-box/GF(2^8), key schedule, MixColumns-математика
- [MISSING] `crypto-impossible-boomerang` — Impossible differential, boomerang, rectangle-атаки
- [MISSING] `crypto-truncated-differential` — Truncated/дифференциально-линейный и zero-correlation криптоанализ
- [MISSING] `crypto-algebraic-cube` — Алгебраические и cube-атаки (Gröbner, SAT-based)
- [MISSING] `crypto-slide-rotational` — Slide, rotational и reflection-атаки на блочные шифры
- [MISSING] `crypto-related-key-attacks` — Related-key и known/chosen-key атаки
- [MISSING] `crypto-aes-key-schedule-attacks` — Атаки на расписание ключей (AES/DES)
- [MISSING] `crypto-lightweight-ciphers` — Легковесные шифры: PRESENT, Speck/Simon, GIFT, ASCON
- [MISSING] `crypto-regional-ciphers` — Национальные шифры: SM4, GOST/Магма, ARIA, Camellia, SEED
- [MISSING] `crypto-block-cipher-modes-siv` — Nonce-misuse-resistant режимы: SIV, GCM-SIV, OCB, EAX
- [MISSING] `crypto-tweakable-deep` — Tweakable-шифры и конструкция (Threefish, XEX/Adiantum)
- [MISSING] `crypto-feistel-advanced` — Feistel advanced: unbalanced, Luby-Rackoff, тип-1/2/3

## Stream ciphers & PRNG engineering
- [MISSING] `crypto-gsm-a5-3g` — Мобильные потоковые: A5/1, A5/2, KASUMI, SNOW 3G, ZUC
- [MISSING] `crypto-lfsr-e0-trivium` — E0 (Bluetooth), Trivium, Grain, SNOW, корреляционные атаки
- [MISSING] `crypto-algebraic-attacks-stream` — Быстрая корреляция, алгебраические и guess-and-determine атаки
- [MISSING] `crypto-prng-glibc-xorshift` — glibc rand, xorshift, PCG, splitmix и восстановление состояния
- [MISSING] `crypto-drbg-backdoors` — DRBG: CTR-DRBG/Hash-DRBG, Dual_EC_DRBG и бэкдоры
- [MISSING] `crypto-rng-entropy` — Энтропия, источники случайности, /dev/urandom, seed-recovery
- [MISSING] `crypto-hardware-rng` — Аппаратные RNG (RDSEED, TRNG) и их уязвимости
- [MISSING] `crypto-rng-cves` — Реальные RNG-баги (Debian OpenSSL, Android SecureRandom, ROCA)
- [THIN] `crypto-mt19937-deep` — уже есть; [THIN] добавить MT-на-нативных (C++/PHP) и частичные выходы

## Hashes, MACs & password hashing
- [MISSING] `crypto-sha2-sha3-internals` — SHA-2/SHA-3 изнутри: compression, permutation, rate/capacity
- [MISSING] `crypto-blake-ripemd-whirlpool` — BLAKE2/BLAKE3, RIPEMD, Whirlpool, SM3, GOST-hash
- [MISSING] `crypto-hash-preimage-herding` — Preimage/second-preimage, herding, multicollisions
- [MISSING] `crypto-hash-mitm` — Meet-in-the-middle и birthday-атаки на хэши
- [MISSING] `crypto-mac-wc-umac` — Wegman-Carter, UMAC, KMAC и универсальное хэширование
- [MISSING] `crypto-aead-gmac-poly1305-deep` — GMAC/Poly1305 изнутри и подделка (forbidden/partitioning oracle)
- [MISSING] `crypto-password-hashing-engineering` — Инженерия KDF: cost-параметры, pepper, параллелизм, Argon2 modes
- [THIN] `crypto-hash-forge` — уже есть; [THIN] добавить chosen-prefix collision и PDF/PS-эксплойты

## RSA (advanced/implementation)
- [MISSING] `crypto-rsa-roca-bateman` — ROCA (CVE-2017-15361), De Laurentis, Bateman и weak-key detection
- [MISSING] `crypto-rsa-oaep-manger-deep` — OAEP/Manger изнутри и полный chain восстановления
- [MISSING] `crypto-rsa-signature-forgery` — Подделка подписей: Bleichenbacher '06, e=3, PKCS#1 v1.5
- [MISSING] `crypto-rsa-crt-fault-deep` — Атаки по ошибкам RSA-CRT (Bellcore) и их детект
- [MISSING] `crypto-rsa-side-channel-remote` — Удалённые side-channel атаки на RSA (timing, Manger oracle)
- [MISSING] `crypto-rsa-keygen-mistakes` — Ошибки генерации ключей: shared primes, слабая энтропия, gcd-batch
- [THIN] `crypto-rsa-coppersmith-deep` — уже есть; [THIN] добавить multivariate Coppersmith и modular-корни

## ECC, DH & discrete log
- [MISSING] `crypto-ecc-anomalous-smart` — Аномальные кривые и атака Smart/Semaev
- [MISSING] `crypto-ecc-mov-freyruck` — MOV/Frey-Rück и спаривательные атаки на ECDLP
- [MISSING] `crypto-ecc-twist-attacks` — Twist-атаки, invalid-curve в ECDH-реализациях, point validation
- [MISSING] `crypto-ecc-fault-attacks` — Fault-атаки на ECC (safe-error, C-safe-error)
- [MISSING] `crypto-secp256k1-bitcoin` — secp256k1 и Bitcoin-специфика (uncompressed/compressed, Taproot)
- [MISSING] `crypto-dh-parameter-validation` — Валидация параметров DH: safe primes, q-order, RFC-ошибки
- [MISSING] `crypto-discrete-log-advanced` — Продвинутый DLP: NFS/index calculus, function fields
- [THIN] `crypto-ecdsa-advanced` — уже есть; [THIN] добавить curve-recovery из сигнатур и biased-nonce advanced

## Lattices, number theory & hard problems
- [MISSING] `crypto-lattice-tooling-fpylll` — fpylll/Sage-инструменты: BKZ-параметры, reduction-практика
- [MISSING] `crypto-knapsack-subset-sum` — Knapsack/подмножество-суммы и LLL-атаки (Merkle-Hellman)
- [MISSING] `crypto-hidden-number-problem` — Hidden Number Problem, ECDSA/DH через LLL
- [MISSING] `crypto-babai-cvp` — Babai rounding/nearest plane, CVP/SVP-практика
- [MISSING] `crypto-modular-square-roots` — Извлечение квадратных корней, Tonelli-Shanks, p≡3 mod 4
- [MISSING] `crypto-nt-probability-stats` — Вероятность/статистика для крипто (birthday, Марков, энтропия)
- [MISSING] `crypto-nt-p-adic` — p-адические числа, подъём Гензеля и их применение
- [MISSING] `crypto-nt-elliptic-pairing-math` — Weil/Tate-спаривания: математика и вычисление

## Protocols (real-world implementations)
- [MISSING] `crypto-webauthn-fido2` — WebAuthn/FIDO2/passkeys: attestation, CBOR, COSE, origin binding
- [MISSING] `crypto-oauth-oidc-crypto` — OAuth2/OIDC: JWT/JWE, PKCE, ID-token, key confusion
- [MISSING] `crypto-saml-crypto` — SAML: XML-DSig, canonicalization, XML-signature wrapping
- [MISSING] `crypto-dnssec-dns-crypto` — DNSSEC: RRSIG, DS-chain, NSEC/NSEC3, zone-walking
- [MISSING] `crypto-email-crypto-dkim` — SPF/DKIM/DMARC/ARC и S/MIME/PGP-подписи
- [MISSING] `crypto-ipsec-ike` — IPsec/IKEv2: SA, PSK-vs-cert, известные ошибки
- [MISSING] `crypto-openvpn-wireguard-advanced` — OpenVPN/WireGuard advanced: обфускация, ротация ключей
- [MISSING] `crypto-bluetooth-ble-pairing` — Bluetooth/BLE pairing: LE Legacy, LE Secure Connections, MITM
- [MISSING] `crypto-emv-payment` — EMV/платёжные протоколы: ARQC, DDA/CDA, contactless-атаки
- [MISSING] `crypto-nfc-mifare` — MIFARE/ISO14443 crypto (Crypto1, DESFire) и клонирование
- [MISSING] `crypto-tls13-quic` — TLS 1.3/QUIC: 0-RTT, PSK, ECH, key-update, tlsfuzzer
- [MISSING] `crypto-tls-real-bugs` — Реальные баги: ROBOT, DROWN, FREAK, Sweet32, Raccoon, Lucky13
- [MISSING] `crypto-tor-onion-crypto` — Tor: onion-service crypto, hidden-service v3, rendezvous
- [MISSING] `crypto-totp-hotp-scram` — TOTP/HOTP, SCRAM, Digest/NTLM и их подделка
- [MISSING] `crypto-hsm-pkcs11` — HSM/PKCS#11/TPM: интерфейсы, атаки, key-attestation
- [MISSING] `crypto-age-minisign` — Современные утилиты: age, minisign, signify, NaCl/libsodium
- [THIN] `crypto-tls-attacks` — уже есть; [THIN] добавить certificate-transparency/OCSP/ACME

## ZK, MPC, FHE & advanced constructions
- [MISSING] `crypto-bulletproofs-range-proofs` — Bulletproofs, range-proofs, set-membership
- [MISSING] `crypto-halo2-marlin-sonic` — Halo2/Marlin/Sonic и рекурсивные SNARK-ы
- [MISSING] `crypto-zk-rollup-evm` — zkEVM, zk-rollups и доказательства исполнения
- [MISSING] `crypto-fiat-shamir-weak` — Weak Fiat-Shamir и атаки на non-interactive proofs
- [MISSING] `crypto-garbled-circuits-ot` — Garbled circuits, oblivious transfer, PSI
- [MISSING] `crypto-mpc-in-the-head` — MPC-in-the-head, Ligero/Aurora и пост-квантовые ZK
- [MISSING] `crypto-mpc-2pc-libraries` — 2PC/MPC-библиотеки (MP-SPDZ, ABY) и их уязвимости
- [MISSING] `crypto-threshold-signatures` — Threshold-подписи: FROST, GG18/GG20, DKG-протоколы
- [MISSING] `crypto-fhe-schemes-deep` — BFV/BGV/CKKS/TFHE изнутри: шум, bootstrapping, параметры
- [MISSING] `crypto-fhe-attacks` — Атаки на FHE/гомоморфные схемы и параметрические ошибки
- [THIN] `crypto-threshold-mpc` — уже есть; [THIN] добавить secure-aggregation и federated-crypto

## Post-quantum & quantum
- [MISSING] `crypto-pq-falcon-rainbow` — Falcon, Rainbow/HFE (multivariate) и их атаки
- [MISSING] `crypto-pq-bike-hqc` — BIKE/HQC (code-based, не McEliece) и NIST-финалисты
- [MISSING] `crypto-pq-sidh-attack` — Атака Кастана на SIDH/SIKE и её последствия
- [MISSING] `crypto-pq-lattice-attacks` — Атаки на LWE/Kyber: primal/dual, BKZ, sparse-secret
- [MISSING] `crypto-pq-hybrid-migration` — Гибридный обмен ключей и миграция на PQC в TLS/SSH
- [MISSING] `crypto-pq-ctf` — PQ-задачи на CTF: Kyber/Dilithium/NTRU в бою
- [MISSING] `crypto-quantum-gates-circuits` — Квантовые гейты/схемы, Qiskit, квантовое моделирование
- [MISSING] `crypto-quantum-error-correction` — Квантовая коррекция ошибок и отказоустойчивость
- [MISSING] `crypto-quantum-annealing` — Квантовый отжиг и его крипто-последствия
- [THIN] `crypto-shor-grover` — уже есть; [THIN] добавить ресурсные оценки и практические квантовые атаки

## Side-channels (hardware & microarchitectural)
- [MISSING] `crypto-sidechannel-dpa-cpa` — DPA/CPA advanced: preprocessing, template attacks
- [MISSING] `crypto-sidechannel-ml` — ML-based side-channel (нейросети на трассах)
- [MISSING] `crypto-sidechannel-acoustic-thermal` — Акустические/тепловые/оптические утечки
- [MISSING] `crypto-sidechannel-glitching` — Voltage/clock/EM glitching, laser fault injection
- [MISSING] `crypto-sidechannel-rowhammer` — Rowhammer, DRAM-утечки и крипто-последствия
- [MISSING] `crypto-sidechannel-spectre-meltdown` — Spectre/Meltdown/Hertzbleed/Plundervolt в крипто
- [MISSING] `crypto-sidechannel-remote-timing` — Удалённые timing-атаки на TLS/сеть (Lucky13, Raccoon)
- [MISSING] `crypto-sidechannel-coldboot-dma` — Cold-boot, DMA-атаки и извлечение ключей из памяти
- [MISSING] `crypto-sidechannel-tvla` — TVLA (test vector leakage assessment) и оценка утечек
- [THIN] `crypto-cache-attacks` — уже есть; [THIN] добавить remote-cache и cloud-co-residency

## Blockchain & cryptocurrency crypto
- [MISSING] `crypto-bitcoin-schnorr-musig` — Schnorr/BIP340, Taproot, MuSig, threshold-schnorr
- [MISSING] `crypto-multisig-scripts` — Multisig, P2SH/P2WSH, скрипты и их баги
- [MISSING] `crypto-wallet-cracking` — Взлом кошельков: weak seeds, keystore, brainwallet
- [MISSING] `crypto-ethereum-keystore` — Ethereum keystore/scrypt, BIP44-пути, HD-derivation
- [MISSING] `crypto-smart-contract-crypto` — Криптография смарт-контрактов (keccak, ecrecover, signatures)
- [MISSING] `crypto-blockchain-forensics` — Blockchain-форензика и deanonymization
- [MISSING] `crypto-vanity-address-attacks` — Vanity-адреса, слабая энтропия и коллизии
- [THIN] `crypto-hd-wallets` — уже есть; [THIN] добавить multi-chain derivation и hardware-wallet-атаки

## Encoding, tooling & engineering
- [MISSING] `crypto-tooling-sage` — SageMath/PARI-GP/sympy/gmpy2 для крипто-CTF
- [MISSING] `crypto-tooling-pycryptodome` — Практические библиотеки: pycryptodome, cryptography, pyca, z3
- [MISSING] `crypto-tooling-cracking-rules` — hashcat-правила, маски, PRINCE, distributed/GPU-кластеры
- [MISSING] `crypto-tooling-fpga-hpc` — FPGA/HPC-крекинг и облачный GPU (crackstation, cloud)
- [MISSING] `crypto-encoding-esoteric` — Esoteric-кодировки: Morse, Baudot, Punycode, UTF-7, esolang
- [MISSING] `crypto-constant-time` — Constant-time программирование и предотвращение timing-утечек
- [MISSING] `crypto-secure-coding` — Безопасное использование crypto-API (CWE-327/328/330, misuse)
- [MISSING] `crypto-key-management` — Управление ключами: rotation, escrow, derivation, secret-management
- [MISSING] `crypto-static-analysis-crypto` — Поиск крипто-ошибок в коде (semgrep, CryptoGuard, CodeQL)
- [MISSING] `crypto-fips-standards` — NIST/FIPS/SP800, сертификация и соответствие
- [MISSING] `crypto-ctf-recipe` — CTF-рецепты крипто: классификация задач и стратегии
- [MISSING] `crypto-drive-css-aacs` — DRM-крипто: DVD CSS, AACS, HDCP и их взлом
- [MISSING] `crypto-satellite-tetra` — Спутниковые/радио-крипто: TETRA, DMR, DVB, GPS-спуфинг
- [MISSING] `crypto-post-crypto-world` — Крипто-агильность и подготовка к квантовому переходу
- [MISSING] `crypto-hardware-tokens` — Аппаратные токены (YubiKey, Nitrokey) и их крипто-интерфейсы
- [MISSING] `crypto-formal-verification` — Формальная верификация крипто-протоколов (ProVerif, Tamarin)
- [MISSING] `crypto-protocol-design-pitfalls` — Ошибки проектирования протоколов и их разбор
- [THIN] `crypto-encodings`/`crypto-encoding-deep` — уже есть; [THIN] добавить кастомные алфавиты и многослойные

---

## Ranked TOP 25 gaps (crypto)
1. `crypto-webauthn-fido2` — современная аутентификация без пароля
2. `crypto-tls13-quic` — актуальный транспорт
3. `crypto-sidechannel-spectre-meltdown` — микроархитектурные крипто-утечки
4. `crypto-tooling-sage` — базовый инструмент крипто-CTF
5. `crypto-pq-falcon-rainbow` — завершение PQ-картины
6. `crypto-bitcoin-schnorr-musig` — Schnorr/Taproot
7. `crypto-rsa-roca-bateman` — real-world weak-key detection
8. `crypto-sidechannel-glitching` — аппаратные fault-атаки
9. `crypto-threshold-signatures` — FROST/GG20
10. `crypto-oauth-oidc-crypto` — JWT/OIDC в бою
11. `crypto-ctf-recipe` — методология крипто-CTF
12. `crypto-totp-hotp-scram` — распространённые протоколы аутентификации
13. `crypto-constant-time` — предотвращение timing-утечек
14. `crypto-dnssec-dns-crypto` — DNSSEC-цепочки
15. `crypto-emv-payment` — платёжные протоколы
16. `crypto-aes-structure` — AES изнутри
17. `crypto-block-cipher-modes-siv` — misuse-resistant режимы
18. `crypto-bulletproofs-range-proofs` — ZK-практика
19. `crypto-lattice-tooling-fpylll` — практические решётки
20. `crypto-hsm-pkcs11` — аппаратное хранение ключей
21. `crypto-sidechannel-rowhammer` — Rowhammer-крипто
22. `crypto-pq-hybrid-migration` — миграция на PQC
23. `crypto-tooling-cracking-rules` — продвинутый крекинг
24. `crypto-rng-entropy` — инженерия случайности
25. `crypto-ctf-recipe` / `crypto-formal-verification` — верификация протоколов
