# content/reversing — MISSING/THIN lesson candidates (second independent pass, gB)

Inventory: **127** md files (includes ~13 `reversing-mod-*` / `reversing-module-*` hub/module pages).
Verdict: **STRONG** — covers debuggers, decompilers, symbolic/DBI, formats, packers/protectors, mobile, firmware, kernel, anti-analysis, and major language runtimes. Gaps are in *breadth of architectures*, *deep Windows/Apple internals*, *malware-family tradecraft*, *fuzzing/hybrid analysis*, *VM/bytecode runtimes*, and *AI/ML + hardware-chip reversing*.

Legend: `[MISSING]` = no lesson; `[THIN]` = a related lesson exists but the specific angle is absent/too shallow.

## Architectures & ISA breadth
- [MISSING] `reversing-asm-arm64` — ARM64/AArch64 ассемблер вручную (registers, AAPCS64, addressing modes, NEON/SVE)
- [MISSING] `reversing-asm-arm32` — ARM32/Thumb и режимы переключения (Thumb-2, IT-блоки)
- [MISSING] `reversing-riscv-advanced` — RISC-V advanced: расширения, компрессия, привилегированные режимы
- [MISSING] `reversing-powerpc` — Реверс PowerPC/POWER (big-endian, AltiVec, ABI)
- [MISSING] `reversing-sparc` — Реверс SPARC (register windows, delay slots)
- [MISSING] `reversing-mips-delay-slots` — MIPS advanced: branch delay slots, MIPS16/microMIPS, HI/LO
- [MISSING] `reversing-s390x` — Реверс IBM z/Architecture (s390x): CISC, instructions formats
- [MISSING] `reversing-avr-8bit` — Реверс AVR / 8-bit MCU (ATmega, Harvard architecture, GPIO)
- [MISSING] `reversing-xtensa` — Реверс Xtensa (ESP32) и проприетарные DSP-ядра
- [MISSING] `reversing-superh` — Реверс SuperH (SH-2/SH-4) — Sega/embedded
- [MISSING] `reversing-6502-8bit` — Реверс 6502/Z80 и ретро-платформ (NES/C64/Game Boy)
- [MISSING] `reversing-endianness-pitfalls` — Endianness, unaligned access и ловушки чтения структур
- [MISSING] `reversing-fpu-simd` — Векторные/FPU-инструкции: SSE/AVX, NEON, SVE в дизассемблере
- [THIN] `reversing-gpu-shaders` — Реверс GPU-шейдеров и compute-ядер (SPIR-V, DXBC, PTX)

## Executable / container formats
- [MISSING] `reversing-coff-omf` — Реверс COFF/OMF/ar и объектных файлов (.obj/.o/.lib)
- [MISSING] `reversing-intel-hex-srec` — Форматы прошивок Intel HEX, SREC, TI-TXT и конвертация
- [MISSING] `reversing-dyld-shared-cache` — dyld shared cache: извлечение и анализ системных библиотек macOS/iOS
- [MISSING] `reversing-fat-binaries` — Fat/universal binaries (Mach-O fat, lipo) и многоплатформенные образы
- [MISSING] `reversing-dex-internals` — DEX изнутри: заголовки, пулы, bytecode, multidex, compact DEX
- [MISSING] `reversing-oat-art` — Android OAT/ART: AOT-компиляция, vdex, ART-байткод и профили
- [MISSING] `reversing-apk-structure` — Анатомия APK/AAB/IPA: манифест, ресурсы, split-APK, подписи
- [MISSING] `reversing-pe-net-metadata` — Метаданные .NET в PE: CLR-заголовки, #~ streams, tokens
- [MISSING] `reversing-msi-installers` — Реверс MSI/InstallShield/NSIS/Inno-установщиков
- [MISSING] `reversing-elf-notes-abi` — ELF notes, GNU properties, ABI-теги и их роль
- [MISSING] `reversing-wasm-advanced` — WASM advanced: компонентная модель, WIT, SIMD, memory64
- [MISSING] `reversing-archive-formats` — Архивные/контейнерные форматы в malware (zip-крипт, 7z, CAB, RAR)
- [MISSING] `reversing-pdf-js-reversing` — Реверс вредоносного PDF (JS, шрифты, уязвимые фильтры)
- [MISSING] `reversing-office-macros` — Реверс VBA/макросов и OLE-структур (docx/xlsm, VBA stomping)

## Language runtimes & bytecode
- [MISSING] `reversing-v8-bytecode` — Реверс V8: Ignition bytecode, TurboFan IR, snapshots, code cache
- [MISSING] `reversing-jsc-spidermonkey` — Реверс JavaScriptCore/SpiderMonkey и обфускации JS-движков
- [MISSING] `reversing-hermes-flutter` — Реверс Hermes bytecode (React Native) и Dart/Flutter AOT
- [MISSING] `reversing-dotnet-aot-readytorun` — .NET ReadyToRun/AOT и native-образы (R2R, NativeAOT)
- [MISSING] `reversing-graalvm-native` — Реверс GraalVM native-image (substrate)
- [MISSING] `reversing-luajit-bytecode` — Реверс LuaJIT bytecode и trace-компиляции
- [MISSING] `reversing-beam-erlang` — Реверс Erlang/Elixir BEAM-байткода
- [MISSING] `reversing-yarv-ruby` — Реверс Ruby YARV bytecode (iseq) и обфускаций
- [MISSING] `reversing-php-opcode` — Реверс PHP opcode/opcache и обфусцированного PHP
- [MISSING] `reversing-perl-python-advanced` — Реверс Perl-байткода и продвинутых Python-обфускаций (pyarmor)
- [MISSING] `reversing-kotlin-native` — Реверс Kotlin/Native и Kotlin Multiplatform
- [MISSING] `reversing-swift-demangle-advanced` — Swift advanced: mangling, метаданные типов, протоколы witness tables
- [MISSING] `reversing-dlang-nim-zig` — Реверс D/Nim/Zig/Odin-бинарников
- [MISSING] `reversing-haskell-ocaml` — Реверс Haskell/OCaml (thunks, runtime, GHC-ABI)
- [MISSING] `reversing-ada-fortran` — Реверс Ada/Fortran и научного HPC-кода
- [THIN] `reversing-jvm-bytecode-deep` — уже есть; добавить invokedynamic, method handles, StackMapTable, module-info
- [THIN] `reversing-python-bytecode` — уже есть; добавить .pyc версии, marshal, bytecode VM-обфускации (pyc)

## Windows internals
- [MISSING] `reversing-win-syscalls-ssn` — Windows syscalls: SSN, stub-паттерны, direct/indirect syscalls
- [MISSING] `reversing-win-peb-teb` — PEB/TEB, LDR-структуры и ручной обход загрузчика
- [MISSING] `reversing-win-api-hooking` — Реверс хуков: IAT/inline/veh/trampoline и их снятие
- [MISSING] `reversing-win-com-rpc` — Реверс COM/RPC/DCOM: IDL, интерфейсы, MIDL-стабы
- [MISSING] `reversing-win-pdb-dwarf` — PDB/DWARF, восстановление символов, публичные символы MS
- [MISSING] `reversing-win-seh-cpp` — Реверс C++-исключений: SEH, EH unwind, RTTI, vtable
- [MISSING] `reversing-win-drivers-irp` — Реверс Windows-драйверов: IRP, dispatch, IOCTL-фаззинг
- [MISSING] `reversing-win-registry-services` — Реверс служб, планировщика задач и autorun-механизмов
- [MISSING] `reversing-win-signed-code` — Authenticode, каталоги, обход проверки подписи

## macOS / iOS / Apple
- [MISSING] `reversing-macos-codesign-entitlements` — Код-сайнинг, entitlements, hardened runtime macOS
- [MISSING] `reversing-objc-runtime` — Objective-C runtime: objc_msgSend, class-метаданные, swizzling
- [MISSING] `reversing-ios-arm64e-pac` — ARM64e и Pointer Authentication (PAC) на iOS
- [MISSING] `reversing-ios-xnu-kernel` — Реверс ядра XNU и kext/dext
- [MISSING] `reversing-ios-jailbreak-detect` — Jailbreak/root-detection и её обход (iOS)
- [MISSING] `reversing-ios-appattest` — App Attest/DeviceCheck и целостность приложения
- [MISSING] `reversing-macos-notarization` — Notarization/Gatekeeper и обход нотаризации

## Android / mobile
- [MISSING] `reversing-android-root-detect` — Root/emulator/frida-detection на Android и её обход
- [MISSING] `reversing-android-smali-dex-edit` — Правка smali/DEX и repackaging (apktool, baksmali)
- [MISSING] `reversing-android-packers` — Android-упаковщики (Bangcle, Legu, Tencent) и распаковка
- [MISSING] `reversing-android-dynamic-instrumentation` — Динамическая инструментация Android (frida, xposed, zygisk)
- [MISSING] `reversing-android-native-symbols` — Восстановление символов .so, JNI-регистрация, anti-hook
- [MISSING] `reversing-mobile-tls-pinning` — SSL-pinning и её обход (Android/iOS)
- [MISSING] `reversing-mobile-keystore` — Android Keystore / iOS Keychain: извлечение секретов
- [MISSING] `reversing-ios-ipa-swiftui` — Реверс SwiftUI/Combine приложений

## Malware analysis (families & tradecraft)
- [MISSING] `reversing-c2-beacon-config` — Извлечение конфигов C2-биконов (Cobalt Strike, Sliver, Mythic)
- [MISSING] `reversing-malleable-c2` — Malleable C2-профили и реверс C2-протокола
- [MISSING] `reversing-shellcode-loaders` — Реверс загрузчиков shellcode (donut, sRDI, PE2Shellcode)
- [MISSING] `reversing-process-injection` — Реверс техник инъекций (hollowing, APC, early-bird, mapping)
- [MISSING] `reversing-powershell-deobfuscation` — Деобфускация PowerShell (Invoke-Obfuscation, AMSI-обход)
- [MISSING] `reversing-dotnet-malware` — Реверс .NET-малвари (dnSpy, ConfuserEx, стабы)
- [MISSING] `reversing-ransomware-family` — Реверс ransomware-семейств и анализ крипто-схемы
- [MISSING] `reversing-banker-infostealer` — Реверс infostealer/банкеров (webinjects, hooking)
- [MISSING] `reversing-botnet-loader` — Реверс botnet-загрузчиков и DGA (domain generation algorithms)
- [MISSING] `reversing-apt-tooling` — Реверс APT-инструментария и TTP-маппинг (MITRE ATT&CK)
- [MISSING] `reversing-lolbins` — Реверс LOLBins/lofl и abusе встроенных утилит
- [MISSING] `reversing-malware-anti-analysis` — Malware anti-analysis: anti-debug/anti-VM/anti-sandbox в бою
- [MISSING] `reversing-unpacking-vmprotect-malware` — Распаковка VMProtect/Themida-малвари
- [MISSING] `reversing-config-extraction-yara` — Извлечение IOC и генерация YARA/Sigma из бинарника
- [MISSING] `reversing-memory-forensics` — Реверс через дампы памяти (Volatility, in-memory malware)
- [MISSING] `reversing-firmware-malware` — Реверс прошивочных имплантов (LoJax, BlackLotus/UEFI)
- [MISSING] `reversing-wiper-destructive` — Реверс вайперов и деструктивного ПО
- [MISSING] `reversing-ransomware-key-recovery` — уже есть `reversing-ransomware`; [THIN] добавить восстановление ключей и NoCry-подходы

## Dynamic analysis, debugging & tracing
- [MISSING] `reversing-gdb-python-api` — GDB Python API и автоматизация отладки
- [MISSING] `reversing-windbg-extensions` — WinDbg extensions и скриптование (pykd, JS)
- [MISSING] `reversing-ftrace-perf-uprobes` — Реверс через ftrace/perf/uprobes/USDT на Linux
- [MISSING] `reversing-ebpf-tracing-tools` — bpftrace/bcc для реверса и трассировки
- [MISSING] `reversing-snapshot-fuzzing` — Snapshot-фаззинг (nyx, kAFL) и его применение в реверсе
- [MISSING] `reversing-ptrace-advanced` — ptrace advanced: syscall-stops, PTRACE_SEIZE, remote syscalls
- [MISSING] `reversing-wine-wsl` — Реверс в Wine/WSL/эмуляторах Windows API
- [MISSING] `reversing-core-dump-analysis` — Анализ core dump и post-mortem реверс
- [MISSING] `reversing-live-memory-patching` — Runtime-патчинг в памяти и горячие правки
- [MISSING] `reversing-instrumentation-frameworks` — Сравнение Frida/DynamoRIO/Pin/QBDI/eBPF по задачам
- [THIN] `reversing-intel-pt` / `reversing-hardware-trace` — [THIN] добавить decoding (libipt), perf-интеграцию, ARM ETM-трейсы в проде

## Static analysis, decompilation & tooling
- [MISSING] `reversing-binary-ninja` — Binary Ninja: BNIL, HLIL, скриптование API
- [MISSING] `reversing-hexrays-microcode` — Hex-Rays microcode: устройство и оптимизации
- [MISSING] `reversing-ghidra-pcode-emulator` — Эмулятор P-Code в Ghidra для деобфускации
- [MISSING] `reversing-decompiler-internals` — Внутренности декомпилятора: SSA, variable recovery, type inference
- [MISSING] `reversing-type-recovery` — Восстановление типов и структур (Retypd, HexRays)
- [MISSING] `reversing-signature-flirt-lumina` — FLIRT/Lumina/FunctionID: сигнатуры и matching
- [MISSING] `reversing-bindiff-diaphora-advanced` — Продвинутый бинарный диффинг (BinDiff, Diaphora, patch-diff)
- [MISSING] `reversing-capstone-keystone` — Программный дизасм/ассембл: Capstone, Keystone, Unicorn как стек
- [MISSING] `reversing-radare2-scripting` — Автоматизация radare2/rizin: r2pipe, сценарии
- [MISSING] `reversing-cfg-recovery` — Восстановление графа потока управления (CFG) и его сложности
- [MISSING] `reversing-symbolic-exec-recipe-advanced` — уже есть `reversing-symbolic-recipe`; [THIN] добавить масштабные binary-задачи и symcc

## Symbolic execution, fuzzing & program analysis
- [MISSING] `reversing-fuzzing-aflpp` — Coverage-guided фаззинг: AFL++ (persistent, cmplog, custom mutators)
- [MISSING] `reversing-fuzzing-libfuzzer-honggfuzz` — libFuzzer/Honggfuzz и интеграция с sanitizers
- [MISSING] `reversing-hybrid-fuzzing` — Гибридный фаззинг (concolic + coverage, symcc, QSYM)
- [MISSING] `reversing-directed-fuzzing` — Направленный фаззинг и достижение конкретных путей
- [MISSING] `reversing-structure-aware-fuzzing` — Structure-aware / grammar-фаззинг (protobuf, JSON, форматы)
- [MISSING] `reversing-kernel-fuzzing` — Фаззинг ядра (syzkaller, KASAN, KCOV)
- [MISSING] `reversing-symbolic-miasm-bap` — Miasm/BAP/angr-альтернативы и сравнение IR
- [MISSING] `reversing-klee-s2e` — KLEE/S2E и символьное исполнение системного уровня
- [MISSING] `reversing-program-slicing` — Программные срезы и data-flow analysis для реверса
- [MISSING] `reversing-triton-advanced` — Triton advanced: AST-символика, taint, callback-API

## Anti-analysis, obfuscation, packers & protectors
- [MISSING] `reversing-anti-disassembly` — Anti-disassembly: overlapping/junk bytes, bogus flow, opaque
- [MISSING] `reversing-string-obfuscation` — Строковые обфускации: stack-strings, XOR, API hashing
- [MISSING] `reversing-ollvm-tigress` — OLLVM/Tigress/Hikari и деобфускация их выходов
- [MISSING] `reversing-movfuscator` — Movfuscator и mov-only деобфускация
- [MISSING] `reversing-virtualization-custom` — Кастомные VM-протекторы: девиртуализация handler-ов
- [MISSING] `reversing-tls-callbacks` — TLS-callbacks, DllMain-трюки и раннее исполнение
- [MISSING] `reversing-self-decrypting-code` — Саморасшифровывающийся код и многослойные стабы
- [MISSING] `reversing-metamorphism` — Метаморфизм/полиморфизм и нормализация кода
- [MISSING] `reversing-jit-obfuscation` — JIT-обфускация (VMProtect-подобная в runtime)
- [MISSING] `reversing-cfg-guard-cet` — CFG/Control-Flow Guard и Intel CET как препятствие реверсу
- [MISSING] `reversing-license-schemes` — Лицензионные схемы: hardware-id, offline-активация, floating license
- [THIN] `reversing-commercial-protectors` — [THIN] добавить пошаговую распаковку каждого (Themida/Enigma/Obsidium)

## Kernel, hypervisor & low-level
- [MISSING] `reversing-linux-kernel-modules` — Реверс LKM: symbol-версии, kprobes, ftrace-hooks
- [MISSING] `reversing-rootkit-techniques` — Реверс руткитов: DKOM, SSDT, syscall-патчинг, eBPF-руткиты
- [MISSING] `reversing-macos-kexts` — Реверс kext/dext macOS
- [MISSING] `reversing-hypervisor-esxi` — Реверс ESXi/KVM/Hyper-V и гипервизорных руткитов
- [MISSING] `reversing-smm-uefi` — Реверс SMM/UEFI DXE-драйверов и прошивочных имплантов
- [MISSING] `reversing-trustzone-tee` — Реверс TrustZone/TEE (OP-TEE, Trusty) и secure world
- [MISSING] `reversing-secure-boot-chain` — Реверс цепочки доверия: Secure Boot, измеряемая загрузка
- [MISSING] `reversing-microcode-firmware` — Реверс микрокода/CPU-микроархитектуры (ME/PSP)

## Firmware, embedded & hardware
- [MISSING] `reversing-bootloader-uboot` — Реверс загрузчиков (U-Boot, coreboot, Barebox)
- [MISSING] `reversing-rtos-zephyr-vxworks` — Реверс Zephyr/VxWorks/ThreadX (кроме FreeRTOS)
- [MISSING] `reversing-embedded-linux-iot` — Реверс embedded-Linux и IoT-прошивок (buildroot, openwrt)
- [MISSING] `reversing-fpga-bitstream` — Реверс FPGA-битстримов и HDL (Verilog/VHDL)
- [MISSING] `reversing-chip-decapping` — Инвазивный реверс: decapping, die-shot, ROM-извлечение
- [MISSING] `reversing-baseband-modem` — Реверс baseband/модемной прошивки
- [MISSING] `reversing-obd-j1939-doip` — Реверс автомобильных протоколов сверх CAN/UDS (J1939, DoIP, FlexRay, LIN)
- [MISSING] `reversing-ics-scada-protocols` — Реверс ICS/SCADA-протоколов (Modbus, DNP3, IEC 61850, EtherNet/IP)
- [MISSING] `reversing-radio-sdr-protocols` — Реверс радио-протоколов (кроме базового SDR): LoRa, Zigbee, BLE
- [MISSING] `reversing-smartcard-emv` — Реверс смарт-карт/EMV (APDU, JavaCard, GlobalPlatform)

## Protocols, formats & data
- [MISSING] `reversing-json-xml-binary` — Реверс бинарных сериализаций: msgpack, CBOR, BSON, Avro, ASN.1
- [MISSING] `reversing-game-netcode` — Реверс игрового netcode и реплеев
- [MISSING] `reversing-db-file-formats` — Реверс файлов БД и хранилищ (SQLite, LevelDB, LMDB, ESE)
- [MISSING] `reversing-custom-vm-formats` — Реверс кастомных контейнеров/VM-образов и скриптовых байткодов
- [MISSING] `reversing-messaging-protocols` — Реверс MQTT/AMQP/CoAP/Kafka-протоколов
- [MISSING] `reversing-bluetooth-l2cap` — Реверс BLE/L2CAP/GATT-стеков и трейсинга
- [THIN] `reversing-protocols` — [THIN] добавить TLS-record, QUIC, HTTP/2-3 на уровне бинарного парсинга

## Games, DRM & anti-cheat
- [MISSING] `reversing-unity-il2cpp` — Реверс Unity IL2CPP и Mono-игр (Il2CppDumper)
- [MISSING] `reversing-unreal-engine` — Реверс Unreal Engine (пакеты, Blueprints, UAsset)
- [MISSING] `reversing-steam-drm` — Реверс Steam DRM/Steamworks и обход
- [MISSING] `reversing-eac-battleye` — Реверс ядерных античитов (EAC, BattlEye) — user/kernel
- [MISSING] `reversing-anticheat-emulation` — Эмуляция античит-проверок и обход в песочнице
- [MISSING] `reversing-cheat-driver` — Реверс и анализ читерских драйверов
- [MISSING] `reversing-denuvo-advanced` — Denuvo advanced: VM-девиртуализация и anti-debug в бою

## AI / ML & emerging
- [MISSING] `reversing-ml-models` — Реверс ML-моделей (ONNX, TFLite, safetensors, PyTorch)
- [MISSING] `reversing-model-extraction` — Извлечение модели/весов и watermarking
- [MISSING] `reversing-neural-obfuscation` — Обфускация через нейросети и её реверс
- [MISSING] `reversing-quantum-binaries` — Реверс квантовых/FPGA-гибридных бинарников
- [MISSING] `reversing-supply-chain-artifacts` — Реверс артефактов supply-chain (npm/pypi/maven, typosquat)

## Methodology, tooling & workflow
- [MISSING] `reversing-workflow-automation` — Автоматизация реверс-workflow (headless, CI, batch)
- [MISSING] `reversing-collaboration-knowledge` — Совместный реверс: базы знаний, symbol-sharing, аннотации
- [MISSING] `reversing-legal-ethics` — Правовые/этические границы реверса и ответственное раскрытие
- [MISSING] `reversing-ctf-pwn-recon` — Реверс как recon для pwn: определение митигаций и векторов
- [MISSING] `reversing-compiler-optimizations` — Понимание оптимизаций компилятора (inlining, LTO, vectorization)
- [MISSING] `reversing-devirtualization-languages` — Девиртуализация интерпретаторов (Python/JS/PHP VM)
- [MISSING] `reversing-time-constrained` — Реверс под давлением времени (CTF/IR): приоритизация
- [MISSING] `reversing-reporting-remediation` — Отчётность по реверс-находкам и ремедиация
- [MISSING] `reversing-embedded-debug-probes` — OpenOCD/Black Magic/J-Link и скриптовый реверс на живом железе
- [MISSING] `reversing-side-channel-firmware` — Side-channel/glitching в реверсе прошивок (кроме базового)
- [MISSING] `reversing-hardware-schematic-recon` — Recon по плате: чтение схем, datasheet, pinout

---

## Ranked TOP 25 gaps (reversing)
1. `reversing-malware-static`/dynamic already exist → **`reversing-c2-beacon-config`** (highest practical value for blue/red)
2. `reversing-win-syscalls-ssn` — direct/indirect syscalls, EDREvasion
3. `reversing-process-injection` — family of injection techniques
4. `reversing-asm-arm64` — AArch64 manual reading (mobile/embedded demand)
5. `reversing-unity-il2cpp` — huge game-RE demand
6. `reversing-fuzzing-aflpp` — coverage-guided fuzzing foundation
7. `reversing-ios-arm64e-pac` — PAC on modern iOS
8. `reversing-android-packers` — real-world Android RE
9. `reversing-dotnet-malware` — .NET malware is dominant
10. `reversing-powershell-deobfuscation` — ubiquitous in IR
11. `reversing-codesign-entitlements` (macOS) — Apple RE core
12. `reversing-decompiler-internals` — understand the tools
13. `reversing-v8-bytecode` — browser/JS RE
14. `reversing-hybrid-fuzzing` — modern bug-finding
15. `reversing-ollvm-tigress` — obfuscation families
16. `reversing-rootkit-techniques` — kernel RE
17. `reversing-obd-j1939-doip` — automotive breadth
18. `reversing-ics-scada-protocols` — ICS/OT
19. `reversing-hermes-flutter` — mobile JS/Dart RE
20. `reversing-binary-ninja` — tooling breadth
21. `reversing-shellcode-loaders` — loader RE
22. `reversing-ml-models` — emerging AI RE
23. `reversing-dyld-shared-cache` — Apple system libs
24. `reversing-kernel-fuzzing` — syzkaller/KCOV
25. `reversing-smm-uefi` — firmware implants (BlackLotus-class)
