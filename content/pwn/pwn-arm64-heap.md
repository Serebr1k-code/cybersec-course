---
id: pwn-arm64-heap
title: "ARM64 heap exploitation"
category: pwn
parent: pwn-arm64-basics
difficulty: expert
order: 3
tags: [pwn, arm64, heap, glibc, aarch64]
prerequisites: [pwn-arm64-basics, pwn-heap-basics, pwn-heap-tcache]
useful_for:
  - "CTF Pwn — ARM64 heap"
  - "Разработка эксплойтов"
estimated_minutes: 60
summary: "Особенности heap-эксплуатации на AArch64: тот же glibc, но другие указатели, безопасность и типичные цели (TLS, function pointers)."
---
ARM64 heap exploitation — эксплуатация кучи glibc на 64-битной ARM (AArch64). Хотя glibc на ARM64 использует те же механизмы (tcache, fastbin, unsortedbin, safe-linking), есть архитектурные отличия: размеры структур, выравнивание, syscalls (`svc #0`), а также особенности сборки glibc для ARM. В этом уроке — устройство heap на ARM64, отличия от x86-64, типовые атаки (tcache poisoning, House of Botcake, FSOP) и практические примеры под qemu-user.

## Что одинаково и что отличается

Механизмы glibc (tcache, bins, safe-linking) одинаковы на всех архитектурах — это часть libc, а не процессора. Различия: (1) **размеры указателей** — 8 байт, как на x86-64; (2) **выравнивание** — 16 байт; (3) **syscalls** — `svc #0` вместо `syscall`, регистры `x8` (номер), `x0`–`x5` (аргументы); (4) **гаджеты** — `ldp`/`ldr` вместо `pop`; (5) **конкретные смещения** в glibc зависят от сборки (ARM-версия). Эксплуатационная логика та же: groom → leak → poison → FSOP.

## Смещения и утечки

Смещения символов (`__free_hook`, `main_arena`, `_IO_2_1_stdout_`) зависят от сборки glibc для ARM64. Используйте `libc-database` с ARM-сборками или приложенную libc. Утечки (unsortedbin `bk` → `main_arena`) работают так же. Проверяйте смещения в gdb.

## Типовые атаки

- **Tcache poisoning.** Как на x86-64; под safe-linking нужна heap-утечка.
- **House of Botcake.** Double-free обход `key` — не зависит от архитектуры.
- **Largebin attack.** Произвольная запись — работает.
- **FSOP.** `_IO_FILE`/vtable — смещения ARM-специфичны, но логика та же.
- **House of Orange.** Переполнение top → unsortedbin → FSOP.

## ROP и вызовы на ARM64

Для FSOP/ROP на ARM64 нужны гаджеты `ldp x0, x1, [sp], #16; ret`, `ldr x0, [sp, #N]; ret`, `ldp x29, x30, [sp], #16; ret`. Вызов функции: `x0`–`x7` — аргументы, `ret` — `br x30`. Syscall: `x8` — номер, `x0`–`x5` — аргументы, `svc #0`. Для `execve("/bin/sh", 0, 0)`: `x8 = 221`, `x0 = binsh`, `x1 = 0`, `x2 = 0`.

## Разобранный пример: tcache poisoning

```python
from pwn import *
context.binary = elf = ELF('./chall')
context.arch = 'aarch64'
libc = ELF('./libc.so.6', checksec=False)
p = process('./chall')

# 1) leak libc через unsortedbin (заполнить tcache)
# 2) leak heap (safe-linking)
# 3) poison tcache -> target
# 4) alloc target -> arbitrary write
```

Логика идентична x86-64; отличия только в смещениях и гаджетах.

## Отладка под qemu-user

```bash
qemu-aarch64 -g 1234 ./chall
gdb-multiarch ./chall -ex 'set architecture aarch64' -ex 'target remote :1234'
```

Используйте pwndbg (он поддерживает AArch64) для `bins`, `vis_heap_chunks`, `heap`. Смотрите `x30`, `sp`, `x0`.

## Отличия от x86-64 и подводные камни

- **Смещения glibc.** ARM-сборка отличается — не переносите адреса с x86-64.
- **Гаджеты.** `ldp`/`ldr` вместо `pop`; ищите их в ARM-libc.
- **Syscall ABI.** `x8`/`x0`–`x5`, `svc #0`.
- **Выравнивание.** 16 байт.
- **PAC/BTI.** На arm64e/современных ARM могут быть включены — учитывайте.

## Справочные таблицы

| Механизм | Отличие ARM64 |
|---|---|
| tcache | нет |
| safe-linking | нет |
| гаджеты | `ldp`/`ldr` |
| syscall | `svc #0` |

| Syscall | Регистр |
|---|---|
| номер | `x8` |
| арг. 1 | `x0` |
| арг. 2 | `x1` |

## Что дальше / решение

Дальше: `pwn-arm64-basics`, `pwn-heap-tcache`, `pwn-fsop`, `pwn-glibc-mitigations`. Практический алгоритм: (1) определите версию glibc для ARM; (2) проведите groom и получите утечки; (3) выберите атаку (poisoning/Botcake/FSOP); (4) найдите ARM-гаджеты; (5) отлаживайте под qemu-user. ARM64 heap — актуальная область (облачные серверы, мобильные); логика та же, что на x86-64, но смещения и гаджеты ARM-специфичны.
## Полный разбор ARM64 heap-эксплойта

Разберём сквозной пример. Дано: AArch64-бинарь с heap-меню, glibc (ARM-сборка), tcache и safe-linking. Цель — получить shell. Шаги: (1) определите версию glibc и загрузите ARM-сборку; (2) проведите groom: заполните tcache, получите утечку libc через unsortedbin (`bk` → `main_arena`); (3) получите heap-утечку (через show освобождённого чанка); (4) выполните tcache poisoning с учётом safe-linking (маскировка `next`); (5) аллоцируйте чанк по цели (`__free_hook` на старых glibc или `_IO_2_1_stdout_`/`__exit_funcs` на новых); (6) запишите `system`/поддельную структуру; (7) триггерните. Логика идентична x86-64; отличия — в смещениях (ARM-сборка glibc) и гаджетах (`ldp`/`ldr`). Проверяйте в gdb: `bins`, `vis_heap_chunks`, `p &__free_hook`.

## FSOP на ARM64

FSOP работает так же, как на x86-64: подделка `_IO_FILE` и vtable, триггер через `exit`/`fflush`. Отличия: смещения полей `_IO_FILE` могут немного отличаться (выравнивание), а vtable должна лежать в libc (проверка `_IO_vtable_check`). Для финального вызова нужны ARM-гаджеты, если вы строите ROP. На glibc < 2.34 можно записать `system` в `__free_hook` и вызвать `free("/bin/sh")` — проще. На новых — FSOP через `_IO_wfile_jumps` (House of Apple). Всегда сверяйте смещения с ARM-сборкой glibc.

## Отладка и инструменты

`gdb-multiarch` с `set architecture aarch64` + pwndbg — основной инструмент. `qemu-aarch64 -g 1234 ./chall` запускает бинарь. pwndbg поддерживает AArch64 и показывает `bins`, `heap`, `vis_heap_chunks`. Для утечек и смещений используйте приложенную libc или `libc-database` с ARM-сборками. Логируйте адреса и проверяйте каждый шаг. Помните про выравнивание 16 байт и syscall ABI (`x8`/`x0`–`x5`).

## Итог

ARM64 heap — актуальная область: облачные серверы на Graviton, мобильные устройства, Apple Silicon. Механизмы glibc те же, но смещения и гаджеты ARM-специфичны. Освоив heap-эксплуатацию на ARM64, вы сможете работать с современными платформами. Начните с tcache poisoning на учебной задаче, затем переходите к Botcake, largebin и FSOP. Практикуйтесь под qemu-user с pwndbg.
## Расширенные приёмы ARM64 heap

Помимо tcache poisoning и FSOP, на ARM64 применимы все современные heap-техники: **House of Botcake** (double-free), **tcache stashing unlink**, **largebin attack**, **House of Orange**, **House of Apple**. Механизмы glibc не зависят от архитектуры, поэтому логика та же; меняются только смещения (ARM-сборка) и гаджеты. Для финального исполнения на ARM64 используйте SROP или ROP с `ldp`-гаджетами. **Safe-linking** работает идентично x86-64 (маскировка `ptr ^ (pos >> 12)`), поэтому нужна heap-утечка. **Хуки** (`__free_hook`) существуют до glibc 2.34 и на ARM64 — используйте их для простого финала. Изучайте ARM-сборки glibc и сверяйте смещения в gdb.

## Практика и ресурсы

Начните с tcache poisoning на учебной AArch64-задаче, затем Botcake, largebin, FSOP. Изучайте writeup'ы по ARM64 heap (например, задачи с Google CTF, PlaidCTF, а также Android-эксплойты). Инструменты: `gdb-multiarch`, `pwndbg` (поддерживает AArch64), `qemu-aarch64`, `libc-database` с ARM-сборками. Помните, что облачные серверы (Graviton) и мобильные устройства используют ARM64, поэтому этот навык востребован. Практикуйтесь и сверяйте каждый шаг в gdb.

## Полный список техник и соответствие x86-64

Все современные heap-техники применимы на ARM64 без изменений в логике: tcache poisoning, fastbin dup, unsafe unlink, House of Lore/Einherjar/Force/Orange/Botcake, tcache stashing, largebin attack, FSOP, House of Apple/Kiwi/Emma/God. Меняются только смещения (ARM-сборка glibc) и гаджеты (`ldp`/`ldr`). Для финального исполнения используйте SROP (syscall 139, `rt_sigreturn`) — он позволяет установить все регистры из поддельного `sigframe` одной инструкцией, что упрощает вызов `execve`. Проверяйте смещения в ARM-сборке glibc через `libc-database` и gdb. Практикуйтесь на учебных AArch64-задачах, постепенно переходя от poisoning к FSOP и largebin.


## Специфика heap на Apple Silicon и в облаке

На Apple Silicon (arm64e) включён PAC, который усложняет финальное исполнение (ROP через подписанные указатели). В облаке (AWS Graviton) PAC нет, поэтому heap-эксплойты переносятся с x86-64 почти напрямую (меняются смещения и гаджеты). Для финального вызова используйте SROP (`rt_sigreturn`, syscall 139) или `ldp`-гаджеты. На glibc < 2.34 записывайте `system` в `__free_hook` и вызывайте `free("/bin/sh")` — простой финал. На новых — FSOP через `_IO_wfile_jumps`. Всегда сверяйте смещения ARM-сборки glibc и проверяйте в gdb (`p &__free_hook`, `p &main_arena`). Практикуйтесь на AArch64-задачах, постепенно переходя от poisoning к FSOP и largebin.


## Практика: FSOP на AArch64

Для FSOP на AArch64: (1) получите утечки libc/heap; (2) подделайте `_IO_FILE` в контролируемом чанке; (3) выберите vtable (`_IO_str_jumps` на старых, `_IO_wfile_jumps` на новых); (4) подставьте `system`; (5) свяжите с `_IO_list_all`; (6) триггерните `exit`. Смещения полей `_IO_FILE` сверяйте с ARM-сборкой. Для финального вызова используйте ARM-гаджеты (`ldp`). На glibc < 2.34 проще записать `system` в `__free_hook` и вызвать `free("/bin/sh")`. Проверяйте в gdb (`p &__free_hook`, `b _IO_flush_all_lockp`). Практикуйтесь, постепенно усложняя.


## Заключение по ARM64 heap

ARM64 heap использует те же механизмы glibc, но с иными смещениями и гаджетами. Освойте tcache poisoning, Botcake, largebin, FSOP под AArch64. Для финала — `__free_hook` (старые glibc) или FSOP/SROP. Проверяйте смещения ARM-сборки в gdb. Практикуйтесь под qemu-aarch64 с pwndbg. Эта область востребована (Graviton, мобильные); логика переносится с x86-64, меняются детали.


## Финальные рекомендации

ARM64 heap: те же механизмы glibc, иные смещения/гаджеты. Освойте poisoning/Botcake/largebin/FSOP, используйте SROP/`__free_hook` для финала, сверяйте смещения ARM-сборки. Практикуйтесь под qemu-aarch64 с pwndbg. Область востребована в облаке и на мобильных.

## Квиз

```quiz
- question: "Какой аллокатор используется в ARM64-биначах на Linux?"
  options:
    - "Тот же glibc malloc (tcache/unsorted/large bins)"
    - "Специальный ARM-аллокатор"
    - "SLUB"
    - "Jemalloc"
  answer: 0
  explanation: "glibc одинаков на всех Linux-архитектурах, поэтому heap-примитивы переносятся."
- question: "Какая защита ARM64 подписывает указатели возврата?"
  options:
    - "PAC (Pointer Authentication)"
    - "SMEP"
    - "KPTI"
    - "safe-linking"
  answer: 0
  explanation: "PAC добавляет криптоподпись к указателям (в т.ч. LR), усложняя ROP."
- question: "Почему на новых glibc не целятся в __free_hook?"
  options:
    - "Хуки удалены с glibc 2.34"
    - "Он находится в read-only"
    - "Он не существует на ARM64"
    - "Он зашифрован"
  answer: 0
  explanation: "После удаления хуков цели сместились на FSOP/TLS/exit-путь."
- question: "Какая защита ARM64 обнаружит UAF/overflow через теги памяти?"
  options:
    - "MTE (Memory Tagging Extension)"
    - "PAC"
    - "BTI"
    - "KPTI"
  answer: 0
  explanation: "MTE помечает память тегами и ловит несоответствия при доступе."
- question: "Чему равен safe-linking маскированный next-указатель tcache?"
  options:
    - "(addr >> 12) ^ ptr_addr"
    - "addr ^ 0xdead"
    - "addr + 0x10"
    - "addr & 0xfff"
  answer: 0
  explanation: "С 2.32 tcache fd = (next >> 12) ^ адрес самого поля; нужно размаскировать."
```

## Где пригодится

- **CTF:** Pwn — ARM64 heap-задачи (эмуляция через qemu).
- **Bug bounty:** Android/ARM-сервисы.
- **Пентест:** embedded/ARM-платформы.
- **Работа:** security research ARM.
