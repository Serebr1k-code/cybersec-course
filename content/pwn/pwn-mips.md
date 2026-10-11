---
id: pwn-mips
title: "MIPS pwn: регистры, соглашения и эксплуатация"
category: pwn
parent: pwn-arm64-basics
difficulty: hard
order: 1
tags: [pwn, mips, embedded, router, iot]
prerequisites: [pwn-arm64-basics, pwn-rop, pwn-calling-conventions]
useful_for:
  - "CTF Pwn — embedded/IoT"
  - "Реверс прошивок роутеров"
estimated_minutes: 60
summary: "Эксплуатация MIPS-бинарей (частый формат роутеров/IoT): регистры, delay slots, соглашения вызовов, ROP и особенности endianness."
---
MIPS pwn — эксплуатация бинарей под MIPS, одной из старейших RISC-архитектур, широко распространённой в роутерах, IoT-устройствах и встраиваемых системах. MIPS имеет уникальные особенности: **delay slots** (инструкция после перехода выполняется всегда), разделение `$ra` и стека, endianness (обычно big-endian в embedded, little-endian в некоторых), и соглашение о вызовах O32/N32/N64. Эксплуатация MIPS-устройств — важный навык для IoT-пентеста. В этом уроке — регистры, delay slots, ROP, ret2win и практические примеры под qemu-user.

## Регистры MIPS

MIPS имеет 32 регистра (`$0`–`$31`), из которых `$0`/`$zero` всегда ноль. Символические имена:

| Регистр | Имя | Роль |
|---|---|---|
| `$0` | `zero` | ноль |
| `$1` | `at` | ассемблерный временный |
| `$2`–`$3` | `v0`–`v1` | возврат |
| `$4`–`$7` | `a0`–`a3` | аргументы |
| `$8`–`$15` | `t0`–`t7` | временные |
| `$16`–`$23` | `s0`–`s7` | сохраняемые |
| `$24`–`$25` | `t8`–`t9` | временные |
| `$26`–`$27` | `k0`–`k1` | ядро |
| `$28` | `gp` | global pointer |
| `$29` | `sp` | stack pointer |
| `$30` | `fp`/`s8` | frame pointer |
| `$31` | `ra` | адрес возврата |

Аргументы — `$a0`–`$a3` (4 штуки), возврат — `$v0`. Адрес возврата — `$ra` (`$31`).

## Delay slots

Уникальная особенность MIPS: инструкция, следующая сразу за переходом (`jal`, `jr`, `b`), выполняется **всегда** — это delay slot. При построении ROP это критично: после `jr $ra` выполнится ещё одна инструкция, прежде чем управление уйдёт. Часто в delay slot стоит `nop` или полезная инструкция. При переполнении вы должны учитывать delay slot при планировании цепочки. Это отличает MIPS от других архитектур и часто сбивает новичков.

## Поиск offset и гаджетов

```bash
mips-linux-gnu-objdump -d ./chall
ROPgadget --binary ./chall | grep "jr"       # jr $ra
ROPgadget --binary ./chall | grep "lw"
```

Гаджеты MIPS: `lw $ra, off($sp); jr $ra; nop`, `lw $a0, off($sp); ...`. Часто функции имеют эпилог `lw $ra, N($sp); jr $ra`, что даёт `lw $ra`-гаджет.

## Разобранный пример: ret2win

```python
from pwn import *
context.binary = elf = ELF('./chall')
context.arch = 'mips'
context.endian = 'big'
p = process('./chall')
offset = cyclic_find(0x61616161)
win = elf.symbols['win']
p.sendline(flat(b'A'*offset, win))
p.interactive()
```

Учтите endianness: для big-endian используйте `context.endian = 'big'`. Переполнение перезаписывает сохранённый `$ra`.

## ROP на MIPS

Цепочка: установить `$a0` и вызвать функцию. Гаджеты `lw $a0, off($sp); lw $ra, off($sp); jr $ra; nop` загружают аргумент и возврат. Пример:

```python
rop  = flat(
    lw_a0_ra,
    binsh_addr,
    system_addr
)
```

Порядок зависит от гаджета; проверяйте в gdb. Для 4+ аргументов используйте гаджеты на `$a1`–`$a3`.

## Endianness и разрядность

MIPS бывает big-endian (BE, распространён в embedded) и little-endian (LE). В pwntools: `context.endian = 'big'`/`'little'`. Разрядность: MIPS32 (32-бит) и MIPS64 (64-бит). Большинство IoT-устройств — MIPS32 BE. Учитывайте это при вычислении offset и упаковке адресов.

## Отладка под qemu-user

```bash
qemu-mips -g 1234 ./chall          # big-endian
qemu-mipsel -g 1234 ./chall        # little-endian
gdb-multiarch ./chall -ex 'set architecture mips' -ex 'target remote :1234'
```

Смотрите `$ra`, `$sp`, `$a0`. Команда `x/10wx $sp` покажет стек.

## Частые ошибки

- **Игнорирование delay slot.** Инструкция после перехода выполняется.
- **Неверный endian.** BE vs LE — упаковка адресов различается.
- **Разрядность.** MIPS32 vs MIPS64.
- **Регистр `$gp`.** Некоторые функции требуют корректного `$gp`.
- **Архитектура в gdb.** `set architecture mips` (и endian).

## Справочные таблицы

| Аргумент | Регистр |
|---|---|
| 1 | `$a0` |
| 2 | `$a1` |
| 3 | `$a2` |
| 4 | `$a3` |

| Syscall | Регистр |
|---|---|
| номер | `$v0` |
| арг. 1 | `$a0` |

## Что дальше / решение

Дальше: `pwn-riscv`, `pwn-arm64-basics`, `pwn-qemu-user`, `pwn-calling-conventions`. Практический алгоритм: (1) определите endianness и разрядность; (2) найдите уязвимость и offset до `$ra`; (3) найдите `lw`/`jr`-гаджеты, учитывая delay slots; (4) соберите цепочку с `$a0`/`$ra`; (5) отлаживайте под qemu-user + gdb-multiarch. MIPS — классика IoT-эксплуатации; этот навык востребован при тестировании роутеров и встраиваемых устройств.
## Полный разбор MIPS ROP с delay slots

Разберём сквозной пример. Дано: MIPS32 BE-бинарь с переполнением, есть `system` и `"/bin/sh"`. Цель — вызвать `system("/bin/sh")`. Шаги: (1) найти offset до `$ra` (cyclic + gdb: `info registers $ra`, `x/20wx $sp`); (2) найти гаджет `lw $a0, N($sp); lw $ra, M($sp); jr $ra; nop`; (3) выяснить `N` и `M`; (4) собрать payload: по смещению `N` — `binsh_addr` (для `$a0`), по `M` — `system_addr` (для `$ra`); (5) учесть delay slot — инструкция `nop` после `jr` выполнится, но она безвредна. Отправляем payload. Проверяем в gdb: `b *system`, `info registers $a0 $ra`. Delay slots — главная особенность MIPS: после каждого перехода выполняется следующая инструкция, что нужно учитывать при построении цепочки.

## Shellcode на MIPS

Для shellcode на MIPS нужны syscalls: `execve` (номер 4011 на Linux MIPS o32), регистры `$v0` — номер, `$a0`–`$a3` — аргументы, инструкция `syscall`. MIPS shellcode должен учитывать delay slots и кэш инструкций (при самомодификации нужен `cacheflush`). Пример (упрощённо): загрузить `$v0 = 4011`, `$a0 = "/bin/sh"`, `$a1 = 0`, `$a2 = 0`, `syscall`. Для ROP-цепочки вместо shellcode используйте вызов `system`/`execve` через гаджеты. Endianness влияет на байты строки и адресов — будьте внимательны.

## Особенности embedded MIPS и endianness

Большинство IoT-роутеров используют MIPS32 **big-endian** (`mips`), но встречается и little-endian (`mipsel`). В pwntools задавайте `context.endian`. Также часто встречается статическая линковка (без libc) и musl. Для ret2win достаточно найти `win`; для ROP — гаджеты. Некоторые устройства используют `$gp` (global pointer) для доступа к данным; если функция использует `$gp`, его нужно корректно установить (обычно он уже валиден при входе). Учитывайте это при построении цепочки.

## Итог

MIPS pwn — классика IoT-эксплуатации. Ключевые особенности: delay slots, endianness, `$ra` на стеке, syscall ABI. Освоив MIPS, вы сможете эксплуатировать роутеры и встраиваемые устройства, которые составляют значительную часть IoT. Начните с ret2win, затем ROP, затем heap (на MIPS тоже работает glibc, если динамическая линковка). Практикуйтесь под qemu-user с gdb-multiarch.
## Расширенные приёмы MIPS

Помимо базового ROP, в MIPS есть важные тонкости. **Branch delay slots** влияют на каждый переход: после `jr $ra` выполняется следующая инструкция. Часто она `nop`, но иногда полезна (например, загружает регистр) — используйте это. **SROP** на MIPS возможен через `sigreturn` (номер 4119 на o32), восстанавливающий контекст из `sigframe` — мощный приём. **ret2csu**-аналог использует эпилоги функций (`lw $ra; lw $s0..; jr $ra`). В embedded часто нет ASLR (или он слабый), что упрощает эксплуатацию. Учитывайте **cache coherence**: если вы исполняете самомодифицирующийся shellcode, может понадобиться `cacheflush`. Изучайте конкретную сборку и не переносите гаджеты между endianness/разрядностями.

## Практика и ресурсы

Начните с ret2win под qemu-mips, затем ROP, затем SROP. Изучайте writeup'ы по MIPS/IoT (роутеры, IP-камеры) и задачи с CTF (например, Real World CTF). Инструменты: `gdb-multiarch`, `pwndbg`, `ROPgadget`, `qemu-mips`/`qemu-mipsel`. Помните про endianness и delay slots — это отличает MIPS от других архитектур. Практикуйтесь на embedded-образах и постепенно осваивайте эту важную для IoT архитектуру.

## Список syscall-номеров и пример ORW

Для ORW на MIPS o32: номер в `$v0`, аргументы в `$a0`–`$a3`, инструкция `syscall`. Номера: `open` = 4005, `read` = 4003, `write` = 4004, `execve` = 4011, `sigreturn` = 4119. Цепочка: загрузить `$v0` и аргументы через гаджеты, выполнить `syscall` (с учётом delay slot). После каждого `syscall` результат в `$v0`. Для seccomp-задач используйте ORW: открыть флаг, прочитать, записать. SROP через `sigreturn` восстанавливает контекст из `sigframe` — мощный приём при нехватке гаджетов. Изучите структуру `sigcontext` для MIPS и соберите SROP-цепочку.


## Практика: ROP с delay slots

Соберите цепочку: (1) offset до `$ra`; (2) гаджет `lw $a0, N($sp); lw $ra, M($sp); jr $ra; nop`; (3) payload: по `N` — `binsh_addr`, по `M` — `system_addr`; (4) учтите delay slot. Проверьте в gdb (`b *system`, `info registers $a0 $ra`). Для ORW — syscall-номера (`open`=4005, `read`=4003, `write`=4004), регистры `$v0`/`$a0`–`$a3`, `syscall`. Для SROP — `sigreturn` (4119). Практикуйтесь под qemu-mips/qemu-mipsel. MIPS — классика IoT; этот навык востребован при тестировании роутеров.


## Практика: syscalls и ORW на MIPS

Для ORW на MIPS o32: номер в `$v0` (open=4005, read=4003, write=4004), аргументы в `$a0`–`$a3`, `syscall` (с delay slot). Соберите цепочку: открыть флаг, прочитать, записать в stdout. Проверяйте в gdb. Для SROP — `sigreturn` (4119). Практикуйтесь под qemu-mips/qemu-mipsel. MIPS — классика IoT (роутеры, камеры); навык востребован в embedded-пентесте. Помните про endianness (BE/LE) и delay slots.


## Заключение по MIPS

MIPS — классика IoT (роутеры, камеры). Ключевые особенности: delay slots, endianness, `$ra` на стеке, syscall ABI. Освойте ROP и ORW/SROP. Практикуйтесь под qemu-mips/qemu-mipsel. MIPS-эксплуатация востребована в embedded-пентесте; она требует учёта архитектурных тонкостей, но логика та же.

## Квиз

```quiz
- question: "Какая инструкция в MIPS исполняется сразу после ветвления/перехода?"
  options:
    - "Инструкция в delay slot"
    - "nop"
    - "syscall"
    - "lw"
  answer: 0
  explanation: "MIPS исполняет следующую за ветвлением инструкцию (delay slot) до самого перехода."
- question: "Какой регистр хранит адрес возврата в MIPS?"
  options:
    - "$ra"
    - "$sp"
    - "$a0"
    - "$v0"
  answer: 0
  explanation: "$ra — return address, аналог RIP/PC для захвата потока управления."
- question: "Какая команда запускает little-endian MIPS-бинарь?"
  options:
    - "qemu-mipsel"
    - "qemu-mips"
    - "qemu-arm"
    - "qemu-x86_64"
  answer: 0
  explanation: "mipsel — little-endian MIPS; qemu-mips — big-endian."
- question: "Почему в embedded часто возможен ret2shellcode?"
  options:
    - "Стек исполняем (нет NX) и адреса фиксированы (нет ASLR)"
    - "MIPS не поддерживает ROP"
    - "Есть tcache"
    - "Работает KPTI"
  answer: 0
  explanation: "Старые прошивки часто без NX/ASLR, что позволяет исполнять shellcode со стека."
- question: "В каком регистре MIPS передаётся номер системного вызова?"
  options:
    - "$v0"
    - "$a0"
    - "$t9"
    - "$ra"
  answer: 0
  explanation: "В MIPS o32 номер syscall кладётся в $v0, аргументы — в $a0..$a3."
```

## Где пригодится

- **CTF:** Pwn — embedded/IoT-задачи, реверс прошивок.
- **Bug bounty:** эксплуатация роутеров и IoT-устройств.
- **Пентест:** анализ встраиваемых устройств.
- **Работа:** security research embedded, firmware analysis.
