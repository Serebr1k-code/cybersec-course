# content/misc — GAP ANALYSIS (independent pass B)

Inventory: 108 md files (91 content lessons + 17 module/hub pages). Verdict: **STRONG**
(deep sandboxes/jails, esolangs, file formats, algorithms, blockchain basics, LLM basics).
Below: MAXIMUM list of MISSING topics (base/standard + niche/advanced/exotic).
One bullet = one proposed lesson. `<proposed-id> — <title>`.

## Квантовые вычисления и пост-квантовая криптография
- misc-quantum-crypto — Квантовые вычисления и пост-квантовая криптография в CTF
- misc-lattice-crypto — Решёточная криптография (LWE, NTRU) в задачах
- misc-qkd — Квантовое распределение ключей: протоколы и атаки
- misc-grover-shor — Grover и Shor: как ломают RSA/ECC
- misc-quantum-oracle — Квантовые оракулы и алгоритм Саймона
- misc-pqc-migration — Переход на пост-квантовые схемы (Kyber, Dilithium)
- misc-qiskit-cirq — Qiskit/Cirq: моделирование квантовых схем

## Блокчейн и Web3 (продвинутое)
- misc-evm-internals — Внутренности EVM: opcodes, gas, storage layout
- misc-solana-ctf — Solana и Anchor: PDA, account confusion, CPI
- misc-cairo-starknet — Cairo/StarkNet: felt-арифметика и уязвимости
- misc-zk-circuits — ZK-схемы (Circom, Groth16): атаки на доказательства
- misc-flash-loan — Flash loan и манипуляции оракулами
- misc-oracle-manipulation — Оракулы цен и их атаки
- misc-defi-mev-deep — Продвинутый MEV: sandwich, backrun, JIT
- misc-bitcoin-script — Bitcoin Script, SegWit и Ordinals
- misc-signature-replay — Подписи, permit и replay в Web3
- misc-rust-solana — Rust в Solana-контрактах: аудит
- misc-move-sui — Move/Sui: ресурсная модель и уязвимости
- misc-cosmos-wasm — Cosmos и CosmWasm-контракты
- misc-yul-assembly — Yul/assembly-оптимизации и их баги
- misc-upgradeable-proxy — Прокси-паттерны (UUPS, diamond) и их баги
- misc-erc-standards — Тонкости ERC-20/721/1155 и нестандарты
- misc-ctf-web3-meta — Методология Web3-CTF и разведка контрактов

## Сериализация данных и парсинг
- misc-protobuf — Protobuf: varint, схемы, обратный разбор
- misc-msgpack-cbor — MessagePack, CBOR, BSON: парсинг и атаки
- misc-asn1-der — ASN.1/DER: разбор и уязвимости
- misc-avro-thrift — Avro и Thrift: схемы и десериализация
- misc-toml-ini — TOML/INI: парсеры и трюки
- misc-csv-injection — CSV injection и формульные атаки
- misc-markdown-render — Markdown-рендер: mXSS и парсер-диффы
- misc-html-parser-diff — Диффы HTML-парсеров и mXSS
- misc-html-email — HTML-письма: парсинг и CSS-эксфильтрация
- misc-ical-vcard — iCalendar/vCard: парсинг и уязвимости
- misc-srt-subtitle — SRT/VTT/ASS: парсинг и инъекции
- misc-ndjson-lines — NDJSON/line-delimited: потоковый разбор
- misc-ebml-matroska — EBML/Matroska: структура и разбор
- misc-plexus-parser — Парсер-диффы и обход валидации

## Форматы файлов и медиа (углублённо)
- misc-font-parsing — Шрифты (TTF/OTF/WOFF): таблицы, глифы, эксплойты
- misc-exif-deep — EXIF/IPTC/XMP: метаданные и GPS
- misc-sqlite-forensics — SQLite: WAL, freelist, восстановление удалённого
- misc-nbt-anvil — Minecraft NBT/Anvil: форматы и модификации
- misc-savegame-formats — Форматы сохранений игр: разбор и редактирование
- misc-3d-model-formats — 3D-форматы (STL/OBJ/GLTF): разбор
- misc-ebook-formats — EPUB/MOBI: разбор и DRM
- misc-office-macro — OOXML-макросы и вложенные объекты
- misc-archive-nested — Вложенные архивы и zip-bombs
- misc-disk-image-misc — Образы дисков: MBR/GPT, разделы, loopback
- misc-carving-misc — Carving файлов из raw-данных
- misc-midi-misc — MIDI: события, sysex, каналы
- misc-pcap-misc — PCAP в misc: разбор нестандартных протоколов
- misc-compound-doc — Legacy OLE/Compound File: структура
- misc-postscript-misc — PostScript/PJL: разбор и инъекции
- misc-dwg-misc — CAD-форматы (DWG/DXF): разбор
- misc-mobile-format-misc — APK/IPA как контейнеры в misc-задачах

## Ядро, системы и изоляция (углублённо)
- misc-syscall-fuzzing — Фаззинг syscalls (syzkaller) в CTF
- misc-kernel-module — Разбор kernel-модулей и ioctl
- misc-ebpf-deep — eBPF: программы, карты, верификатор, побег
- misc-io-uring — io_uring: уязвимости и эксплойт
- misc-vdso-vvar — vDSO/vvar: подмена и атаки
- misc-procfs-tricks — /proc и /sys: утечки и трюки
- misc-netfilter — Netfilter/nftables: правила и обход
- misc-seccomp-bpf-deep — seccomp-BPF: фильтры и обход
- misc-namespace-deep — namespaces: user/pid/net и побеги
- misc-cgroup-v2 — cgroups v2: изоляция и побеги
- misc-landlock — Landlock LSM: песочницы
- misc-fuse-misc — FUSE: файловые системы в userland
- misc-tty-pty — TTY/pty: инъекции и побеги
- misc-signal-tricks — Сигналы: перехват, seccomp, ptrace
- misc-ptrace-debug — ptrace: отладка, инъекции, анти-отладка
- misc-selinux-apparmor — SELinux/AppArmor: профили и обход
- misc-uefi-secureboot — UEFI/Secure Boot в misc-задачах
- misc-initramfs — initramfs/initrd: распаковка и модификация
- misc-kexec-livepatch — kexec и livepatch: подмена ядра
- misc-bpf-tracing — bpftrace/perf: трассировка и атаки
- misc-numa-misc — NUMA и топология памяти
- misc-ksm-thp — KSM/THP: дедупликация памяти и атаки

## Память и аллокаторы
- misc-heap-misc — Heap-эксплуатация в misc (glibc)
- misc-glibc-versions — Различия glibc: tcache, safe-linking, hooks
- misc-musl-allocator — musl malloc: внутренности и эксплойт
- misc-windows-heap — Windows heap: LFH и эксплойты
- misc-aslr-bypass — Обход ASLR: утечки и частичные перезаписи
- misc-cfi-bypass — CFI/CET/Shadow Stack: обход
- misc-memory-forensics-misc — Анализ дампов памяти в misc
- misc-rop-misc — ROP/JOP-цепочки в misc-задачах
- misc-sigreturn-misc — SROP и signal-return-ориентированное программирование
- misc-ret2dlresolve — ret2dlresolve и динамическая линковка
- misc-fsop — FSOP: подмена FILE-структур
- misc-house-of — House of X-техники (force, spirit, einherjar)

## Сетевые протоколы и сервисы
- misc-websocket-misc — WebSocket: фреймы, маскирование, атаки
- misc-quic-misc — QUIC/HTTP3: разбор и атаки
- misc-mqtt-misc — MQTT: брокеры, топики, утечки
- misc-coap-misc — CoAP: протокол IoT и атаки
- misc-modbus-misc — Modbus/ICS-протоколы в misc
- misc-grpc-misc — gRPC: protobuf-фреймы и отражение
- misc-dns-misc — DNS в misc: туннели, rebinding, exfil
- misc-ntp-misc — NTP: amplification и подделка
- misc-ssdp-upnp — SSDP/UPnP: обнаружение и атаки
- misc-mdns-zeroconf — mDNS/ZeroConf: спуфинг
- misc-smb-protocol — SMB в misc: разбор пакетов
- misc-tls-fingerprint — JA3/JA4: фингерпринтинг и обход
- misc-raw-sockets — Raw sockets и scapy для задач
- misc-can-bus — CAN-шина: кадры и инъекции
- misc-serial-uart — UART и последовательные протоколы
- misc-ipv6-misc — IPv6 в misc: туннели, RA, ND
- misc-rdp-protocol — RDP-протокол: разбор и атаки
- misc-kerberos-misc — Kerberos-пакеты в misc-задачах
- misc-ipsec-misc — IPsec/IKE: разбор и атаки
- misc-openvpn-wireguard — VPN-протоколы: разбор handshake

## Игры, эмуляторы и хардвар
- misc-gameboy-rom — Game Boy ROM: разбор и патч
- misc-nes-rom — NES ROM: мапперы и хаки
- misc-chess-engine — Шахматные движки: UCI и взлом
- misc-emulator-dev — Разработка эмуляторов и их уязвимости
- misc-save-state — Save states: разбор и манипуляции
- misc-tas-speedrun — TAS/скоростное прохождение: инструменты
- misc-anti-cheat — Анти-читы: обход и обнаружение
- misc-game-network — Игровые сетевые протоколы и читы
- misc-retro-console — Ретро-консоли и картриджи
- misc-firmware-extract — Извлечение прошивок (binwalk, unblob)
- misc-usb-misc — USB: дескрипторы и HID-инъекции
- misc-bluetooth-misc — Bluetooth в misc-задачах
- misc-nfc-rfid-misc — NFC/RFID в misc-задачах
- misc-ir-remote — ИК-пульты и сигналы
- misc-gps-nmea — GPS/NMEA-парсинг и спуфинг
- misc-lora-misc — LoRa/LoRaWAN в CTF
- misc-zigbee-misc — Zigbee: кадры и атаки
- misc-zwave-misc — Z-Wave: разбор и атаки
- misc-jtag-swd-misc — JTAG/SWD в misc-задачах
- misc-logic-analyzer — Логические анализаторы и декодирование

## Случайность, время и гонки
- misc-prng-attacks — PRNG-атаки: MT19937, LCG, xorshift
- misc-timing-attacks — Timing-атаки и сравнение строк
- misc-race-conditions — Гонки в misc (TOCTOU)
- misc-fork-bomb — fork-bomb и исчерпание ресурсов
- misc-entropy-misc — Энтропия и /dev/urandom в задачах
- misc-clock-skew — Часовые пояса, tzdata и skew
- misc-leap-second — Високосные секунды и даты-края
- misc-y2k38 — Переполнение времени (2038) в задачах

## Криптография в misc (углублённо)
- misc-modern-cipher-misc — AES/ChaCha в misc-задачах
- misc-hash-collision — Коллизии хешей (MD5, SHA-1, chosen-prefix)
- misc-length-extension — Length-extension атаки на хеши
- misc-mac-forgery — CBC-MAC/CMAC/GMAC: подделка
- misc-padding-oracle — Padding oracle в misc
- misc-stream-nonce — Повтор nonce и XOR-утечки
- misc-rsa-misc — RSA в misc: Wiener, Coppersmith, общие модули
- misc-ecc-misc — ECC в misc: invalid curve, twist
- misc-dh-misc — Diffie-Hellman: small subgroup, invalid key
- misc-crt-fault — CRT-fault атаки на подпись
- misc-crypto-sidechannel — Крипто-побочные каналы (Kocher)
- misc-hash-cracking-misc — Взлом хешей: режимы и оптимизация
- misc-password-hashing — Алгоритмы паролей (bcrypt, argon2) в задачах
- misc-homomorphic — Гомоморфное шифрование: задачи и атаки
- misc-secret-sharing — Разделение секрета (Shamir, SSS)
- misc-mpc-misc — MPC-протоколы и их утечки
- misc-caesar-morse-bacon — Морзе, Бэкон, Полибий и классика
- misc-musical-book-cipher — Музыкальные и книжные шифры

## Регулярные выражения и парсинг языков
- misc-regex-engines — Движки регексов: PCRE/RE2/Oniguruma
- misc-regex-catastrophic — Катастрофический backtracking (ReDoS deep)
- misc-grammar-parsing — Грамматики и парсер-генераторы
- misc-antlr-parser — ANTLR/PEG: разбор кастомных языков
- misc-interpreter-write — Написать интерпретатор для задачи
- misc-compiler-ctf — Компилятор/транспайлер в CTF
- misc-vm-bytecode — Кастомные VM и байткод-задачи
- misc-turing-machine — Машина Тьюринга и автоматы
- misc-lexer-tricks — Лексеры и обход токенизации
- misc-grammar-injection — Инъекции через грамматики и DSL

## Математика и вычисления (углублённо)
- misc-fft-convolution — FFT и свёртки в задачах
- misc-linear-algebra — Линейная алгебра над GF(2)/полями
- misc-poly-gf — Полиномы над конечными полями
- misc-lattice-reduction — LLL и решёточные редукции
- misc-sat-solving — SAT-солверы и кодирование
- misc-cp-sat — CP-SAT/OR-Tools: оптимизация
- misc-markov-chains — Цепи Маркова и случайные блуждания
- misc-probability — Вероятностные задачи и Monte-Carlo
- misc-numerical-methods — Численные методы и точность
- misc-optimization — Оптимизация и линейное программирование
- misc-info-theory — Теория информации и энтропия
- misc-error-correcting — Помехоустойчивые коды (Hamming, RS)
- misc-compression-algos — Алгоритмы сжатия и их взлом
- misc-huffman-arithmetic — Хаффман/арифметическое кодирование
- misc-game-theory — Теория игр и стратегии
- misc-combinatorics — Комбинаторика и перечисление
- misc-bitmask-dp — Битмаски и DP по подмножествам
- misc-string-algorithms — Строковые алгоритмы (KMP, Z, suffix)
- misc-sqrt-decomposition — sqrt-декомпозиция и Mo
- misc-fft-ntt — NTT и модульная арифметика

## ML/AI и LLM (углублённо)
- misc-llm-rag — RAG: отравление, извлечение, обход guardrails
- misc-llm-guardrails — Guardrails и их обход
- misc-multimodal-llm — Мультимодальные LLM: атаки на vision
- misc-prompt-leak — Утечка системного промпта
- misc-llm-tool-abuse — Злоупотребление tool-use и function calling
- misc-agentic-escape — Побег агентных систем
- misc-mcp-security — MCP: безопасность серверов и тулов
- misc-model-extraction — Извлечение модели (model stealing)
- misc-adversarial-examples — Adversarial-примеры и патчи
- misc-data-poisoning — Отравление обучающих данных
- misc-backdoor-models — Бэкдоры в моделях
- misc-membership-inference — Membership inference
- misc-llm-supply-chain — Supply chain LLM (pickle, safetensors)
- misc-pickle-ml — Pickle-десериализация ML-моделей
- misc-diffusion-attacks — Диффузионные модели: атаки
- misc-voice-deepfake — Голосовые дипфейки и детекция
- misc-ai-watermark — Водяные знаки AI-контента
- misc-llm-tokenizer — Токенизаторы и их атаки
- misc-jailbreak-encoding — Кодирование для обхода фильтров (base64, ciphers)
- misc-ai-prompt-injection-misc — Прямые и косвенные prompt injection

## Песочницы и рантаймы (углублённо)
- misc-php-sandbox — PHP sandbox escape (disable_functions)
- misc-java-sandbox — Java sandbox/SecurityManager обход
- misc-go-sandbox — Go-песочницы и unsafe
- misc-rust-sandbox — Rust unsafe и песочницы
- misc-deno-bun — Deno/Bun: песочницы и права
- misc-gvisor — gVisor: внутренности и побег
- misc-firecracker — Firecracker microVM: изоляция и побег
- misc-qemu-escape — QEMU/VMM escape
- misc-kata-containers — Kata Containers: побег
- misc-crun-podman — crun/podman: побег из контейнера
- misc-lxc-incus — LXC/Incus: изоляция и побег
- misc-wasm-deep — WASM: валидатор, sandbox, эксплойты
- misc-wasmtime-wasmer — WASM-рантаймы: уязвимости
- misc-llvm-ir — LLVM IR: разбор и оптимизации
- misc-jit-spray — JIT-спрей и эксплуатация
- misc-v8-internals — V8: интерпретатор, JIT, эксплойты
- misc-spidermonkey — SpiderMonkey/JavaScriptCore internals
- misc-lua-c-api — Lua C-API и песочницы
- misc-ruby-gvl — Ruby GVL и потоки в песочницах
- misc-perl-taint — Perl taint-режим и его обход
- misc-tcl-safe — Tcl safe-interp и побег
- misc-sqlite-ext — SQLite-расширения и песочницы

## Web-уязвимости в misc
- misc-http2-smuggling — HTTP/2 в misc
- misc-cache-poison-misc — Cache poisoning в misc
- misc-ssti-misc — SSTI в misc
- misc-prototype-pollution — Prototype pollution
- misc-nosql-misc — NoSQL-инъекции в misc
- misc-graphql-misc — GraphQL в misc
- misc-deser-misc — Десериализация в misc (Java/PHP/Python)
- misc-xxe-misc — XXE в misc
- misc-ldap-misc — LDAP-инъекции
- misc-xpath-misc — XPath-инъекции
- misc-crlf-injection — CRLF/header-инъекции
- misc-open-redirect-misc — Open redirect в misc-задачах

## Кодировки, обфускация и текст
- misc-quine — Квины и саморепликация
- misc-code-golf — Code golf
- misc-unicode-exploits — Unicode-эксплойты (bidi, Trojan Source)
- misc-homoglyph — Гомоглифы и confusable
- misc-bidi-attack — Trojan Source и bidi-контрол
- misc-terminal-escape — ANSI-escape инъекции
- misc-filename-tricks — Трюки с именами файлов
- misc-env-tricks — Переменные окружения и их абуз
- misc-locale-tricks — Локали и ICU
- misc-fp-precision — Числа с плавающей точкой и их баги
- misc-integer-overflow — Переполнения целых
- misc-bit-manipulation — Бит-манипуляции
- misc-endianness — Порядок байтов
- misc-base-conversion — Системы счисления и конверсии
- misc-text-compression — Текстовые компрессоры (smaz, shrinker)
- misc-braille-semaphore — Брайль, семафор, другие алфавиты
- misc-captcha-solve — Решение CAPTCHA
- misc-ocr-deep — OCR: Tesseract, предобработка
- misc-qr-damaged — Повреждённые QR/штрихкоды
- misc-barcode-formats — Форматы штрихкодов: генерация и чтение

## Эзотерические языки (доп.)
- misc-esolang-lolcode — LOLCODE и интерпретация
- misc-esolang-brainfuck-deep — Brainfuck-оптимизация и гольф
- misc-esolang-cow — Cow, Ook! и производные
- misc-esolang-piet-deep — Piet: компиляция изображений
- misc-esolang-chef — Chef и двумерные кулинарные языки
- misc-esolang-false — FALSE и стековые эзотерики
- misc-esolang-malbolge-deep — Malbolge: генерация программ
- misc-esolang-whitespace-deep — Whitespace: инструменты
- misc-esolang-jsfuck-deep — JSFuck/jjencode/AAencode deep
- misc-esolang-befunge-deep — Befunge: 3D и funge-98
- misc-esolang-sha-256 — SHA-256 как эзотерический язык
- misc-esolang-rockstar — Rockstar и прочие шуточные
- misc-esoteric-golf — Эзотерический гольф и минимализм

## Инструменты и автоматизация
- misc-pwntools-deep — pwntools: продвинутые приёмы
- misc-scapy-deep — scapy: конструирование пакетов
- misc-cyberchef — CyberChef: рецепты и автоматизация
- misc-z3-deep — Z3: продвинутое моделирование
- misc-sage-misc — SageMath для misc-задач
- misc-scripting-bash-deep — Bash-скриптинг для задач
- misc-parallel-tools — GNU parallel и xargs
- misc-gdb-scripts — GDB-скрипты и автоматизация
- misc-radare2 — radare2/rizin для misc
- misc-binwalk-deep — binwalk/unblob: извлечение
- misc-yara-misc — YARA-правила для задач
- misc-docker-tooling — Docker для воспроизводимых задач
- misc-nix-reproducible — Nix/воспроизводимость
- misc-jupyter-ctf — Jupyter/ноутбуки для анализа

## Разное и общее
- misc-misc-methodology-deep — Углублённая методология misc-CTF
- misc-teaming — Командная работа в CTF
- misc-hint-reading — Разбор условий и скрытых подсказок
- misc-scoring-strategy — Стратегия набора очков
- misc-custom-format-rev — Реверс кастомных форматов
- misc-spec-reading — Чтение RFC/спецификаций
- misc-differential-analysis — Дифференциальный анализ
- misc-fuzzing-misc — Фаззинг для misc-задач
- misc-symbolic-exec — Символьное исполнение (angr, KLEE)
- misc-concolic — Коколическое тестирование
- misc-decompiler-misc — Декомпиляторы (Ghidra, IDA) в misc
- misc-patcher-misc — Патчинг бинарей и рантайма
- misc-anti-analysis — Анти-анализ и обход
- misc-time-based-puzzles — Задачи с таймингом
- misc-multistage — Многоэтапные цепочки задач
- misc-file-format-detection — Определение форматов по содержимому
- misc-entropy-analysis — Энтропийный анализ данных
- misc-data-recovery — Восстановление данных
- misc-flag-formats — Форматы флагов и их поиск
- misc-writeup-methodology — Как писать райтапы
