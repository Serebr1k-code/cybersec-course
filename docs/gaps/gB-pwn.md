# Pwn — missing / thin lesson topics (gap pass gB, independent second pass)

Inventory at time of analysis: **123 lessons** in `content/pwn/*.md`.
Verdict: **STRONG** on glibc heap (chunks, tcache, house-of-*, FSOP, IO_FILE), stack/ROP family,
format string, kernel core (SMEP/SMAP, SLUB, eBPF, io_uring, nftables), Windows heap/intro,
macOS intro, MIPS/RISC-V/ARM64 basics, emulation (Unicorn/Qiling/qemu-user), fuzzing (AFL/libFuzzer/honggfuzz),
symbolic exec (angr), Rust/Go, musl, static binaries, CTF recipes.

Gaps are concentrated in **architecture breadth** (32-bit, PAC/MTE, embedded ISAs), **non-glibc allocators**
(jemalloc/tcmalloc/Scudo/PartitionAlloc/Apple malloc), **kernel breadth** (macOS/iOS/Android/Windows deeper,
data-only, KASLR), **browser/JIT depth** (V8/JSC/SpiderMonkey, sandbox escape), **real-world CVE exploitation**,
**VM/hypervisor escape**, **DBI & advanced analysis**, **language runtimes** (CPython/JVM/.NET/PHP/Lua/Ruby),
**hardware/embedded**, and **side channels / transient execution**.

Legend: `[MISSING]` = no lesson covers it; `[THIN]` = covered only as a sub-section inside a broader lesson.

---

## 1. Architectures

- `[MISSING]` `pwn-x86-32` — 32-bit x86 exploitation: cdecl, ret2libc i386, mmap, stack layout
- `[MISSING]` `pwn-arm32` — ARM32 (AArch32): AAPCS, Thumb, mode switching, gadgets
- `[MISSING]` `pwn-arm-pac` — ARM Pointer Authentication (PAC): signing, gadgets, PAC bypass
- `[MISSING]` `pwn-arm-mte` — ARM MTE (Memory Tagging Extension): tagging, bypass techniques
- `[MISSING]` `pwn-powerpc` — PowerPC (32/64): ABI, GOT/TOC, ROP
- `[MISSING]` `pwn-sparc` — SPARC exploitation: register windows, ROP
- `[MISSING]` `pwn-s390x` — IBM Z s390x: ABI, exploitation basics
- `[MISSING]` `pwn-sh4` — SuperH (SH-4) exploitation
- `[MISSING]` `pwn-avr-mcu` — AVR/MSP430/8051 embedded MCU exploitation
- `[MISSING]` `pwn-xtensa` — Xtensa/ESP32 exploitation
- `[MISSING]` `pwn-riscv64` — RISC-V 64 deep (extends existing RISC-V basics)
- `[MISSING]` `pwn-wasm` — WebAssembly pwn: memory corruption, sandbox escape
- `[MISSING]` `pwn-aarch64-deep` — ARM64/AArch64 deep exploitation (extends basics)
- `[MISSING]` `pwn-mips64` — MIPS64 (extends existing MIPS)

## 2. Allocators (non-glibc)

- `[MISSING]` `pwn-jemalloc` — jemalloc internals and exploitation
- `[MISSING]` `pwn-tcmalloc` — tcmalloc internals and exploitation
- `[MISSING]` `pwn-macos-malloc` — macOS malloc zones (nano/tiny/small/large)
- `[MISSING]` `pwn-android-scudo` — Android Scudo allocator exploitation
- `[MISSING]` `pwn-partitionalloc` — Chrome PartitionAlloc (and MiraclePtr bypass)
- `[MISSING]` `pwn-hardened-malloc` — GrapheneOS hardened_malloc
- `[MISSING]` `pwn-mimalloc` — mimalloc exploitation
- `[MISSING]` `pwn-dlmalloc` — dlmalloc / legacy ptmalloc
- `[MISSING]` `pwn-windows-segment-heap` — Windows Segment Heap deep (extends existing)
- `[MISSING]` `pwn-kernel-slab-allocators` — SLAB/SLUB/SLOB comparison and targeting

## 3. Kernel breadth

- `[MISSING]` `pwn-macos-kernel` — macOS/XNU kernel exploitation (kext, IOKit)
- `[MISSING]` `pwn-ios-kernel` — iOS kernel exploitation (PAC, KTRR, PPL)
- `[MISSING]` `pwn-android-kernel` — Android kernel exploitation (GKI, SELinux)
- `[MISSING]` `pwn-freebsd-kernel` — FreeBSD kernel exploitation
- `[MISSING]` `pwn-kaslr-bypass` — KASLR bypass techniques
- `[MISSING]` `pwn-kpti-bypass` — KPTI/Meltdown mitigation bypass
- `[MISSING]` `pwn-dirty-pagetable` — Dirty Pagetable page-table technique
- `[MISSING]` `pwn-kernel-data-only` — Data-only kernel attacks
- `[MISSING]` `pwn-kernel-info-leak` — Kernel info-leak primitives
- `[MISSING]` `pwn-usb-raw-gadget` — USB stack exploitation (raw-gadget)
- `[MISSING]` `pwn-wifi-driver` — Wi-Fi driver / mac80211 exploitation
- `[MISSING]` `pwn-block-layer` — Block-layer / filesystem driver exploitation
- `[MISSING]` `pwn-kctf` — kernelCTF methodology and targets
- `[MISSING]` `pwn-bpf-verifier` — eBPF verifier bug exploitation (extends eBPF)
- `[MISSING]` `pwn-msg-msg` — msg_msg / System V IPC kernel primitives (extends kernel intro)
- `[MISSING]` `pwn-kernel-heap-spray` — Kernel heap spray and object replacement

## 4. Windows exploitation

- `[MISSING]` `pwn-windows-rop` — Windows x64 ROP deep (gadget finding, CFG-aware)
- `[MISSING]` `pwn-windows-aslr-bypass` — Windows ASLR bypass / info leaks
- `[MISSING]` `pwn-windows-cfg-cet` — Windows CFG/XFG/CET bypass
- `[MISSING]` `pwn-windows-driver` — Windows driver exploitation (HEVD-style, IOCTL)
- `[MISSING]` `pwn-windows-pool` — Windows kernel pool (paged/non-paged, Big Pool)
- `[MISSING]` `pwn-windows-token-stealing` — Token stealing and privesc primitives
- `[MISSING]` `pwn-windows-iop` — I/O ring and undocumented kernel primitives
- `[MISSING]` `pwn-hyperv-escape` — Hyper-V VM escape
- `[MISSING]` `pwn-vbs-hvci` — VBS/HVCI bypass
- `[MISSING]` `pwn-ppl-wdac` — PPL / WDAC / Code Integrity bypass
- `[MISSING]` `pwn-windows-lfh-deep` — LFH deep (extends Windows heap)

## 5. macOS / iOS userspace

- `[MISSING]` `pwn-macos-arm64` — Apple Silicon (arm64e) exploitation
- `[MISSING]` `pwn-macos-sandbox` — macOS sandbox escape
- `[MISSING]` `pwn-macos-hardened-runtime` — Hardened runtime / library-validation bypass
- `[MISSING]` `pwn-ios-pac` — iOS PAC / PPL bypass
- `[MISSING]` `pwn-ios-sandbox` — iOS sandbox escape
- `[MISSING]` `pwn-baseband` — Baseband/firmware exploitation

## 6. Browser & JIT

- `[MISSING]` `pwn-v8` — V8 exploitation deep (map/type confusion, typer, wasm)
- `[MISSING]` `pwn-spidermonkey` — SpiderMonkey exploitation
- `[MISSING]` `pwn-jsc` — JavaScriptCore exploitation
- `[MISSING]` `pwn-jit-spray` — JIT spraying and JIT-specific bugs
- `[MISSING]` `pwn-browser-sandbox` — Chrome/Firefox renderer sandbox escape
- `[MISSING]` `pwn-browser-ipc-mojo` — Browser IPC / Mojo exploitation
- `[MISSING]` `pwn-browser-dom` — DOM/Blink type confusion
- `[MISSING]` `pwn-wasm-browser` — WASM in-browser exploitation
- `[MISSING]` `pwn-browser-gc` — GC/rope/optimizer bug classes

## 7. Mitigations & bypass depth

- `[MISSING]` `pwn-relro-bypass` — RELRO/FULL RELRO bypass
- `[MISSING]` `pwn-fortify-bypass` — FORTIFY_SOURCE bypass
- `[MISSING]` `pwn-cet-shadow-stack` — CET/shadow-stack bypass (extends existing)
- `[MISSING]` `pwn-cfi-bypass` — CFI/CFG bypass (extends existing)
- `[MISSING]` `pwn-sanitizer-bypass` — ASan/MSan/UBSan bypass engineering (extends ASan)
- `[MISSING]` `pwn-stack-protector-deep` — Stack canary/SSP deep bypass
- `[MISSING]` `pwn-safe-linking-deep` — Safe-linking bypass (extends glibc mitigations)
- `[MISSING]` `pwn-memory-tagging` — Software memory tagging (HWASan/MTE) bypass

## 8. Exploitation primitives & techniques

- `[MISSING]` `pwn-jop` — Jump-Oriented Programming
- `[MISSING]` `pwn-cop` — Call-Oriented Programming
- `[MISSING]` `pwn-dop` — Data-Oriented Programming
- `[MISSING]` `pwn-coop` — Counterfeit Object-Oriented Programming
- `[MISSING]` `pwn-data-only-attacks` — Data-only attacks (no control flow)
- `[MISSING]` `pwn-info-leak-primitives` — Info-leak primitive taxonomy
- `[MISSING]` `pwn-uninitialized-memory` — Uninitialized-memory exploitation
- `[MISSING]` `pwn-refcount-bugs` — Reference-count / lifetime bugs
- `[MISSING]` `pwn-null-deref` — Null-pointer-deref exploitation (mmap_min_addr bypass)
- `[MISSING]` `pwn-type-confusion` — Type-confusion exploitation (general)
- `[MISSING]` `pwn-vtable-hijack` — vtable hijacking (extends C++)
- `[MISSING]` `pwn-rop-automation` — ROP-chain automation (ROPgadget/ropper scripting)
- `[MISSING]` `pwn-shellcode-windows` — Windows shellcode (PEB walk, syscalls)
- `[MISSING]` `pwn-shellcode-arm` — ARM/AArch64 shellcode
- `[MISSING]` `pwn-shellcode-staged` — Staged/multi-stage shellcode
- `[MISSING]` `pwn-blinding` — Blind exploitation without a binary/leak

## 9. Fuzzing & vulnerability discovery

- `[MISSING]` `pwn-syzkaller` — syzkaller kernel fuzzing
- `[MISSING]` `pwn-structure-aware-fuzz` — Structure-aware / grammar fuzzing
- `[MISSING]` `pwn-differential-fuzz` — Differential fuzzing
- `[MISSING]` `pwn-fuzz-harness` — Fuzzing harness design and corpus building
- `[MISSING]` `pwn-oss-fuzz` — OSS-Fuzz integration workflow
- `[MISSING]` `pwn-coverage-instrumentation` — Coverage instrumentation (sancov, LCOV, AFL)
- `[MISSING]` `pwn-mutation-strategies` — Mutation strategies and dictionaries
- `[MISSING]` `pwn-hybrid-fuzz` — Hybrid fuzzing (fuzz + concolic)

## 10. Symbolic / concolic execution

- `[MISSING]` `pwn-z3-smt` — Z3/SMT solving for exploitation
- `[MISSING]` `pwn-klee` — KLEE symbolic execution
- `[MISSING]` `pwn-triton` — Triton DBA framework
- `[MISSING]` `pwn-manticore` — Manticore symbolic execution
- `[MISSING]` `pwn-concolic` — Concolic execution (S2E, angr-deeper)
- `[MISSING]` `pwn-angr-deep` — angr advanced (extends existing angr)

## 11. DBI, emulation & analysis

- `[MISSING]` `pwn-dynamorio` — DynamoRIO instrumentation
- `[MISSING]` `pwn-intel-pin` — Intel PIN
- `[MISSING]` `pwn-frida-exploit` — Frida for exploitation and instrumentation
- `[MISSING]` `pwn-qemu-tcg` — QEMU TCG internals and custom devices
- `[MISSING]` `pwn-instrumentation-frameworks` — DBI framework comparison and use
- `[MISSING]` `pwn-patch-diffing` — Patch diffing for n-day (extends existing n-day)
- `[MISSING]` `pwn-bindiff-diaphora` — Binary diffing (BinDiff/Diaphora)
- `[MISSING]` `pwn-decompiler-exploit-dev` — Decompiler-assisted exploit development
- `[MISSING]` `pwn-symbolic-diff` — Symbolic program diffing

## 12. Real-world CVE exploitation

- `[MISSING]` `pwn-sudo-baron-samedit` — CVE-2021-3156 sudo heap overflow
- `[MISSING]` `pwn-pwnkit` — CVE-2021-4034 polkit pkexec
- `[MISSING]` `pwn-dirty-cow` — CVE-2016-5195 Dirty COW
- `[MISSING]` `pwn-looney-tunables` — CVE-2023-4911 glibc ld.so
- `[MISSING]` `pwn-overlayfs-escape` — CVE-2021-3493 / CVE-2023-0386 overlayfs
- `[MISSING]` `pwn-nftables-cve` — CVE-2023-32233 / CVE-2024-1086 nf_tables
- `[MISSING]` `pwn-netfilter-cve` — CVE-2022-0185 / CVE-2022-2588 netfilter
- `[MISSING]` `pwn-io-uring-cve` — io_uring CVEs
- `[MISSING]` `pwn-kernel-cve-roundup` — Recent Linux kernel CVEs (Sequoia, etc.)
- `[MISSING]` `pwn-windows-cve-roundup` — Windows CVEs (CLFS, PrintNightmare, etc.)
- `[MISSING]` `pwn-eternalblue` — MS17-010 EternalBlue
- `[MISSING]` `pwn-zerologon` — CVE-2020-1472 Zerologon
- `[MISSING]` `pwn-container-escape-cve` — runc/Docker escape CVEs
- `[MISSING]` `pwn-k8s-escape-cve` — Kubernetes escape CVEs

## 13. VM / hypervisor & sandbox escape

- `[MISSING]` `pwn-qemu-escape` — QEMU VM escape (device emulation bugs)
- `[MISSING]` `pwn-vmware-escape` — VMware Workstation/ESXi escape
- `[MISSING]` `pwn-virtualbox-escape` — VirtualBox escape
- `[MISSING]` `pwn-firecracker-escape` — Firecracker/microVM escape
- `[MISSING]` `pwn-gvisor-escape` — gVisor sandbox escape
- `[MISSING]` `pwn-chrome-sandbox` — Chrome sandbox escape
- `[MISSING]` `pwn-firefox-sandbox` — Firefox content sandbox escape
- `[MISSING]` `pwn-nsjail-seccomp` — seccomp/nsjail escape (extends existing)

## 14. Language & runtime exploitation

- `[MISSING]` `pwn-cpython-internals` — CPython internals exploitation (PyObject, refcount)
- `[MISSING]` `pwn-jvm` — JVM exploitation (bytecode, JIT, unsafe)
- `[MISSING]` `pwn-dotnet-runtime` — .NET runtime exploitation
- `[MISSING]` `pwn-php-internals` — PHP internals memory corruption (Zend)
- `[MISSING]` `pwn-lua` — Lua interpreter exploitation
- `[MISSING]` `pwn-ruby` — Ruby VM exploitation
- `[MISSING]` `pwn-perl` — Perl interpreter exploitation
- `[MISSING]` `pwn-objective-c-swift` — Objective-C/Swift exploitation
- `[MISSING]` `pwn-nodejs-runtime` — Node.js/V8-runtime native exploitation
- `[MISSING]` `pwn-go-runtime-deep` — Go runtime deep (extends Rust/Go)
- `[MISSING]` `pwn-rust-unsafe` — Rust unsafe/UB exploitation (extends Rust/Go)

## 15. Hardware & embedded

- `[MISSING]` `pwn-firmware-exploit` — Firmware exploitation (embedded ROP)
- `[MISSING]` `pwn-iot-exploitation` — IoT device exploitation workflow
- `[MISSING]` `pwn-automotive-ecu` — Automotive ECU / CAN exploitation
- `[MISSING]` `pwn-fpga-bitstream` — FPGA/bitstream attacks
- `[MISSING]` `pwn-embedded-trustzone` — TrustZone / secure-world exploitation

## 16. Side channels & transient execution

- `[MISSING]` `pwn-spectre` — Spectre exploitation and gadgets
- `[MISSING]` `pwn-meltdown` — Meltdown and variants
- `[MISSING]` `pwn-transient-execution` — Transient-execution attack taxonomy
- `[MISSING]` `pwn-cache-timing` — Cache-timing side channels
- `[MISSING]` `pwn-side-channel-assisted` — Side-channel-assisted exploitation
- `[MISSING]` `pwn-microarch-attacks` — Microarchitectural attack primitives (MDS, etc.)

## 17. Remote / network exploitation

- `[MISSING]` `pwn-remote-exploitation` — Remote exploitation methodology
- `[MISSING]` `pwn-network-protocol` — Network-protocol parsers (HTTP/DNS/SMB parsing bugs)
- `[MISSING]` `pwn-pre-auth-rce` — Pre-auth RCE classes and targets
- `[MISSING]` `pwn-http-parser-bugs` — HTTP parser differential/memory bugs
- `[MISSING]` `pwn-exploit-reliability` — Exploit reliability and brute-force (fork servers)

## 18. CTF recipes — additional

- `[MISSING]` `pwn-heap-ctf-recipe` — Heap CTF recipe index
- `[MISSING]` `pwn-kernel-ctf-recipe` — Kernel CTF recipe index
- `[MISSING]` `pwn-browser-ctf-recipe` — Browser/JIT CTF recipe index
- `[MISSING]` `pwn-vm-escape-ctf` — VM-escape CTF recipe
- `[MISSING]` `pwn-misc-ctf` — Misc pwn (custom VMs, interpreters, weird ABIs)
- `[MISSING]` `pwn-asan-ctf` — ASan-instrumented CTF challenges

## 19. Misc / exotic

- `[MISSING]` `pwn-compiler-miscompilation` — Compiler miscompilation bugs
- `[MISSING]` `pwn-memory-safety-model` — Memory-safety model and taxonomy
- `[MISSING]` `pwn-gc-bugs` — GC/allocator interaction bugs
- `[MISSING]` `pwn-stack-migration` — Stack migration/clash deep (extends existing)
- `[MISSING]` `pwn-return-to-csu-deep` — ret2csu / ret2dlresolve engineering (extends existing)
- `[MISSING]` `pwn-partial-relro` — Partial-RELRO / GOT overwrite deep (extends existing)
- `[MISSING]` `pwn-nonx-stack` — Non-exec stack bypass (extends NX)
- `[MISSING]` `pwn-exploit-dev-workflow` — End-to-end exploit-dev workflow / toolchain
- `[MISSING]` `pwn-symbol-restoration` — Symbol restoration / binary recovery for stripped targets
- `[MISSING]` `pwn-ctf-remote-harness` — Remote harness interaction and reliability

---

## Summary

- Total candidate topics: **~180**
- Highest-value blocks (by impact & distinctness): architectures (§1), non-glibc allocators (§2),
  kernel breadth (§3), Windows deep (§4), browser/JIT (§6), real-world CVEs (§12), VM/hypervisor escape (§13),
  language runtimes (§14).
- Suggested authoring order: §12 → §1 → §6 → §2 → §14 → §3 → §4 → §13 → §9/§10/§11 → remainder.
