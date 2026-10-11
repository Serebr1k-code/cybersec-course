---
id: reversing-architectures
title: "Реверс других архитектур: ARM, MIPS, RISC-V"
category: reversing
parent: reversing-asm
difficulty: medium
order: 2
tags: [reversing, arm, mips, riscv, endianness, cross-arch, qemu]
prerequisites: [reversing-asm]
useful_for:
  - "CTF Reversing"
  - "Реверс прошивок и IoT"
  - "Анализ ARM/MIPS malware"
estimated_minutes: 50
summary: "Чтение ARM/AArch64, MIPS и RISC-V: регистры, соглашения вызова, особенности, эмуляция."
---
Настоящий реверсер рано или поздно выходит за пределы x86: роутер на MIPS, прошивка на ARM
Cortex-M, IoT-устройство на ARM64, микроконтроллер на RISC-V, игровая консоль на PowerPC. Каждая
архитектура имеет свою систему команд (ISA), соглашения о вызовах (calling conventions), порядок
байт (endianness) и особенности. Этот урок — про то, как ориентироваться в разных архитектурах,
читать ассемблер и использовать Ghidra/IDA/QEMU для кросс-архитектурного анализа.

## Зачем знать архитектуры

- **IoT/embedded**: ARM (Cortex-A/M), MIPS — доминируют в прошивках и роутерах.
- **Мобильные**: ARM64 (AArch64) — iOS/Android.
- **Современные ISA**: RISC-V набирает обороты в embedded.
- **Игровые консоли**: PowerPC (старые), ARM64 (новые), x86 (ПК).
- **CTF**: часто дают бинарник под нестандартную архитектуру, чтобы проверить навык.

Знание хотя бы ARM и MIPS многократно расширяет круг решаемых задач.

## RISC vs CISC

- **CISC (x86/x64)**: сложные инструкции, переменная длина, много адресаций, память — операнд.
- **RISC (ARM, MIPS, RISC-V, PPC)**: фиксированная длина инструкции (обычно 4 байта), операции над
  регистрами, load/store-архитектура (память доступна только через `ldr`/`str`), много регистров.

RISC-код выглядит «чище»: каждая инструкция проста, их больше. Анализ часто легче, чем у x86.

## ARM и ARM64 (AArch64)

**ARM (32-bit, AArch32):**
- 16 регистров: `r0–r15` (`r13`=SP, `r14`=LR, `r15`=PC). Регистр `PC` читается явно.
- Условное исполнение почти каждой инструкции: `ADDEQ`, `SUBNE`, `BXLE`.
- Thumb-режим: сжатые 16-битные инструкции.
- Calling convention (AAPCS): аргументы в `r0–r3`, остальные на стеке, возврат в `r0`; `LR` хранит
  адрес возврата, `BL` — вызов с сохранением `LR`.

**ARM64 (AArch64):**
- 31 регистр общего назначения `x0–x30` (и `w0–w30` для 32-бит), `sp`, `xzr` (ноль).
- Аргументы: `x0–x7`, возврат в `x0`; `x29`=FP, `x30`=LR.
- Нет условного исполнения (кроме ветвлений `b.eq`, `csel`); фиксированная длина 4 байта.
- Инструкции: `ldr`, `str`, `mov`, `add`, `sub`, `bl`, `ret`, `cmp`, `b.eq`, `adrp`/`add`.

Пример ARM64-функции:
```asm
check:
    stp x29, x30, [sp, #-16]!     ; сохранить FP/LR
    mov x29, sp
    ldrb w1, [x0]                 ; первый байт
    cmp w1, #0x41                 ; 'A'
    b.ne fail
    mov w0, #1
    ldp x29, x30, [sp], #16
    ret
fail:
    mov w0, #0
    ret
```

## MIPS

- 32 регистра `$0–$31` (`$zero`, `$a0–$a3` аргументы, `$v0–$v1` возврат, `$t0–$t9` временные,
  `$s0–$s7` сохраняемые, `$ra` адрес возврата, `$sp` стек, `$gp` глобальный указатель).
- **Delay slots**: инструкция после ветвления выполняется **до** перехода. Критично для анализа:
  ```asm
  jal  sub_401000     ; вызов
  move $a0, $s0       ; delay slot — выполнится ДО входа в функцию
  ```
- Два варианта endianness (обычно big-endian в MIPS-роутерах, little-endian в MIPSEL).
- `lui`/`ori` формируют 32-битные константы.

## RISC-V и PowerPC

**RISC-V:**
- 32 регистра `x0–x31` (`zero`, `ra`, `sp`, `a0–a7`, `t0–t6`, `s0–s11`).
- Инструкции: `lw`, `sw`, `add`, `addi`, `beq`, `jal`, `jalr`, `lui`.
- Набирает популярность в embedded/академии; Ghidra поддерживает хорошо.

**PowerPC:**
- 32 GPR `r0–r31`, регистры условий `cr0–cr7`, `lr`, `ctr`.
- Использовался в Xbox 360/PS3/Wii; сегодня встречается реже.
- Инструкции: `lwz`, `stw`, `addi`, `b`, `bl`, `cmpwi`, `bc`.

## Сравнительная таблица: calling conventions

| Архитектура | Аргументы | Возврат | Стек/LR | Особенность |
|---|---|---|---|---|
| x86 cdecl | стек | eax | ebp/esp | caller cleanup |
| x64 SysV | rdi,rsi,rdx,rcx,r8,r9 | rax | rbp/rsp | Linux/macOS |
| x64 Win64 | rcx,rdx,r8,r9 | rax | rbp/rsp | shadow space 32B |
| ARM32 | r0–r3 | r0 | LR (r14) | условное исполнение |
| ARM64 | x0–x7 | x0 | x29/x30 | фиксированная длина |
| MIPS | $a0–$a3 | $v0 | $ra | delay slots |
| RISC-V | a0–a7 | a0 | ra | load/store |
| PowerPC | r3–r10 | r3 | LR | cr-регистры |

## Инструменты кросс-архитектурного анализа

**Ghidra** — поддерживает десятки архитектур из коробки:
```text
File → Import → выбрать language (ARM:LE:32:v8, MIPS:BE:32:default, ...)
```
Для raw-бинарников (прошивки) — `Import → Raw Binary`, задать base address и language.

**IDA** — нужны модули процессоров (в стандартной поставке ARM/MIPS/PPC есть).

**radare2/rizin**:
```bash
r2 -a arm -b 32 -m 0x8000 firmware.bin
r2 -a mips -b 32 -e cfg.big_endian=true -m 0x400000 router.bin
```

**QEMU** — для запуска и эмуляции:
```bash
# user-mode: запустить ARM-бинарник на x86-хосте
qemu-arm ./arm_binary
qemu-aarch64 -L /usr/aarch64-linux-gnu ./arm64_binary
qemu-mips -L /usr/mips-linux-gnu ./mips_binary
# с отладкой
qemu-aarch64 -g 1234 ./arm64_binary     # gdb-стаб на :1234
```
Затем `gdb-multiarch`:
```bash
gdb-multiarch ./arm64_binary -ex "set architecture aarch64" \
  -ex "target remote :1234"
```

**Unicorn** — эмуляция без ОС (для прошивок и функций):
```python
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
```

## Разобранный пример: прошивка роутера (MIPS big-endian)

Дано: дамп `firmware.bin` от роутера. Нужно найти обработчик веб-запроса.

**Шаг 1. Определить архитектуру.** `binwalk -A firmware.bin` и `file` показывают MIPS. Уточняем
endianness по байтам (`die` или `rabin2 -I`).

**Шаг 2. Найти ELF/образ.** `binwalk firmware.bin` → извлечь разделы:
```bash
binwalk -e firmware.bin
```
Ищем бинарники (`/bin/busybox`, `httpd`).

**Шаг 3. Загрузить в Ghidra.** `Raw Binary`, language `MIPS:BE:32:default`, base — адрес из заголовка
(например, `0x400000`). Для ELF-файлов Ghidra определит сама.

**Шаг 4. Найти интересное.** Строки (`Search → For Strings`) → `POST /`, `password`, `system`.
Xref на строку `system` → функция, вызывающая shell.

**Шаг 5. Проверить на эмуляции.** Запустить `httpd` через `qemu-mips` с `-L` на нужный sysroot, либо
эмулировать конкретную функцию через Unicorn/QEMU-user.

**Шаг 6. Вывод.** Найти command injection: строка из запроса попадает в `system()` без фильтрации —
классическая уязвимость прошивок.

## Крайние случаи и подводные камни

- **Endianness.** MIPS/PPC бывают big-endian — неверный выбор даёт «мусор» в дизассемблере. Проверяйте
  оба варианта.
- **Thumb/ARM режим.** ARM32-бинарник может быть в Thumb; Ghidra/IDA обычно определяют, но иногда
  нужно указать вручную.
- **Delay slots (MIPS/PPC).** Инструкция после ветвления выполняется первой — легко ошибиться в логике.
- **Fixed-length alignment.** На RISC-архитектурах инструкции выровнены по 4 байта — смещения важны.
- **Raw-бинарники.** Прошивки без ELF-заголовков: нужен правильный base address и language, иначе
  адреса не совпадут.
- **Syscalls.** Номера и механизм отличаются (`svc`/`ecall`/`syscall`); для эмуляции нужен корректный
  sysroot (`-L`).
- **Unicorn без ОС.** Периферия (MMIO) не эмулируется — нужно писать хуки на обращения к устройствам.
- **Отсутствие символов.** Прошивки обычно strip'нуты — опирайтесь на строки и паттерны.

## Что дальше / решение

1. Определить архитектуру и endianness (`file`, `die`, `binwalk`).
2. Загрузить в Ghidra/IDA/radare2 с правильным language.
3. Для запуска — QEMU-user (+sysroot) или Unicorn.
4. Найти интересные функции через строки/импорты/системные вызовы.
5. Учесть особенности ISA (delay slots, Thumb, фиксированная длина).
6. Проверить гипотезы динамически.

Принцип: **архитектура меняет синтаксис, но не логику**. Опыт x86 переносится: те же циклы, проверки,
вызовы. Нужно лишь выучить регистры и calling convention.

## Справочная таблица: язык Ghidra

| Архитектура | Ghidra language |
|---|---|
| x86 32 | `x86:LE:32:default` |
| x86 64 | `x86:LE:64:default` |
| ARM 32 LE | `ARM:LE:32:v8` |
| ARM 32 BE | `ARM:BE:32:v8` |
| AArch64 | `AARCH64:LE:64:v8A` |
| MIPS BE | `MIPS:BE:32:default` |
| MIPS LE | `MIPS:LE:32:default` |
| RISC-V 32 | `RISCV:LE:32:RV32I` |
| PowerPC BE | `PowerPC:BE:32:default` |

## Как читать незнакомый ассемблер

Оказавшись перед новой ISA, действуйте системно:

1. **Выпишите регистры и их роли** (аргументы, возврат, стек, временные). Это 80% понимания.
2. **Определите calling convention** — где аргументы, где возврат.
3. **Найдите пролог/эпилог функции** — сохранение регистров, выделение стека. По ним определяются
   границы функций.
4. **Разберите простые функции** (например, `strlen`, `strcmp`) — они дадут шаблоны.
5. **Используйте декомпилятор** — Ghidra/IDA переведут в псевдо-C, что снимает синтаксический барьер.

Сравнение «одного и того же» кода на разных ISA (проверка `x == 5`):

```asm
; x86-64
cmp     edi, 5
je      ok

; ARM64
cmp     w0, #5
b.eq    ok

; MIPS (обратите внимание на delay slot)
li      $t0, 5
beq     $a0, $t0, ok
nop                          ; delay slot

; RISC-V
li      a1, 5
beq     a0, a1, ok
```

Как только вы видите «сравнение + условный переход», логика читается одинаково на любой архитектуре.

## Эмуляция прошивки: sysroot и хуки

Запуск embedded-бинарника на x86-хосте через QEMU-user требует правильной среды:

```bash
# поставить кросс-библиотеки для ARM
sudo apt install libc6-armhf-cross
qemu-arm -L /usr/arm-linux-gnueabihf ./busybox
```

Для MIPS/AArch64 — соответствующие `libc6-*-cross` и `-L` на sysroot. Если бинарник требует
периферии (NVRAM, GPIO), QEMU-user не эмулирует MMIO — тогда:

- **Unicorn** + хуки на обращения к адресам периферии:
```python
def on_mem(mu, access, addr, size, value, user):
    if addr == 0x10000000:      # UART
        return
    # обработать или вернуть значение регистра
mu.hook_add(UC_HOOK_MEM_READ, on_mem)
```
- **QEMU-system** с виртуальной платой (например, `-M virt` для ARM) — ближе к реальности.
- **Firmadyne** / **FirmAE** — автоматизированные фреймворки для запуска прошивок.

## Соглашения и ABI: что важно на практике

- **Shadow space (Win64).** При вызове функции в Windows x64 caller резервирует 32 байта на стеке —
  это видно в прологе (`sub rsp, 0x28`).
- **Red zone (SysV x64).** Листовые функции могут использовать 128 байт ниже `rsp` без выделения стека.
- **Variadic функции.** В ARM64 аргументы передаются по-разному для `...` (стек + регистры).
- **Big-endian значения.** В MIPS/PPC константы в листинге выглядят «перевёрнутыми» — помните об этом.
- **ARM Thumb interworking.** Переход между ARM и Thumb через младший бит адреса (`bx`/`blx`).

Понимание этих деталей помогает не ошибаться при чтении листинга и корректно эмулировать вызовы.

## Отчёт по кросс-архитектурному анализу

Фиксируйте: архитектуру и endianness, используемый language в Ghidra/IDA, точку входа, способ запуска
(QEMU/Unicorn + параметры), найденные уязвимости/ключи и итоговый PoC. Для embedded это критично —
воспроизводимость эмуляции сложна, и точные команды экономят время следующему исследователю.

## Квиз

```quiz
- question: "Где в AArch64 хранится адрес возврата из функции?"
  options:
    - "На стеке, как в x86"
    - "В регистре `X30` (LR)"
    - "В `X29` (FP)"
    - "В `SP`"
  answer: 1
- question: "Что такое delay slot в MIPS?"
  options:
    - "Задержка перед запуском программы"
    - "Инструкция после перехода, которая выполняется всегда"
    - "Пропуск такта процессора"
    - "Место хранения аргументов"
  answer: 1
- question: "Какая связка используется для отладки ARM-бинарника на x86-хосте?"
  options:
    - "`gdb` + `strace`"
    - "`qemu-aarch64 -g <port>` + `gdb-multiarch`"
    - "`valgrind` + `objdump`"
    - "`x64dbg` + `Wine`"
  answer: 1
- question: "Какое поле `readelf -h` укажет на big-endian?"
  options:
    - "`Type:`"
    - "`Machine:`"
    - "`Data: 2's complement, big endian`"
    - "`Entry point`"
  answer: 2
- question: "Как в RISC-V передаётся первый аргумент функции?"
  options:
    - "`t0`"
    - "`sp`"
    - "`a0`"
    - "`ra`"
  answer: 2
```

## Где пригодится

- **CTF Reversing:** задачи с ARM/MIPS/RISC-V бинарниками — частая проверка «умеете ли вы вне x86».
- **Malware analysis:** ARM/MIPS IoT-ботнеты (Mirai-подобные) и Android-native библиотеки.
- **Пентест IoT:** разбор прошивок роутеров и камер (MIPS/ARM), поиск бэкдоров.
- **Работа:** embedded-разработка, аудит firmware, безопасность мобильных платформ.
- **Собес:** понимание разных ABI и умение читать не-x86 ассемблер отличает senior-кандидата.
