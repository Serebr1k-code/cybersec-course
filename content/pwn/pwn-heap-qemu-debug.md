---
id: pwn-heap-qemu-debug
title: "Отладка heap в qemu/gdb-multiarch"
category: pwn
parent: pwn-methodology-env
difficulty: medium
order: 2
tags: [pwn, gdb, qemu, debugging, cross-arch]
prerequisites: [pwn-methodology, pwn-gdb-pwndbg, pwn-qemu-user]
useful_for:
  - "CTF Pwn — cross-arch heap"
  - "Разработка эксплойтов"
estimated_minutes: 50
summary: "Как отлаживать heap-эксплойты на не-x86 архитектурах: gdb-multiarch, qemu -g, pwndbg/gef для ARM/MIPS/RISC-V и типичные проблемы."
---
Отладка heap в qemu/gdb-multiarch — это работа с кросс-архитектурными бинарями, где нужно анализировать кучу. Для ARM/MIPS/RISC-V бинарей под qemu-user отладка glibc-heap требует знания целевой libc, символов и структур, а также умения пользоваться gdb-multiarch и pwndbg. В этом уроке — сетап, поиск символов, анализ бинов, типовые команды и практические примеры.

## Сетап отладки

```bash
qemu-aarch64 -g 1234 -L ./sysroot ./chall
gdb-multiarch ./chall
(gdb) set architecture aarch64
(gdb) target remote :1234
(gdb) b *main
(gdb) c
```

Для heap-анализа нужны символы целевой libc. Если libc приложена, загрузите её: `set solib-search-path ./sysroot`, `add-symbol-file ./libc.so.6`. pwndbg поддерживает AArch64 и показывает `bins`, `heap`, `vis_heap_chunks`. Если символы отсутствуют, анализируйте структуры вручную.

## Поиск символов и структур

Символы glibc (`main_arena`, `__free_hook`, `_IO_2_1_stdout_`) — ключ к heap-эксплуатации. В gdb: `p &main_arena`, `p &__free_hook`, `p &_IO_2_1_stdout_`. Если символов нет (stripped libc), найдите их через смещения (из `libc-database` для целевой архитектуры) или анализом. Для целевой архитектуры смещения отличаются от x86-64 — не переносите.

## Анализ бинов и чанков

```bash
(gdb) bins                # tcache/fastbin/smallbin/unsortedbin
(gdb) heap                # сводка
(gdb) vis_heap_chunks 20  # визуализация
(gdb) p *(struct malloc_chunk*)<addr>
```

pwndbg понимает AArch64. Смотрите `fd`/`bk`/`size`/`key`. Для safe-linking проверяйте маскировку `next`. Убедитесь, что размеры и выравнивание (16 байт) совпадают с ожиданиями.

## Отладка кросс-архитектурных эксплойтов

```python
from pwn import *
context.binary = elf = ELF('./chall')
context.arch = 'aarch64'
p = gdb.debug(['qemu-aarch64', '-g', '1234', '-L', './sysroot', './chall'],
              gdbscript='set architecture aarch64\ntarget remote :1234\nb *main\nc')
```

Используйте `gdb.debug` с qemu. Логируйте адреса и проверяйте в `info proc mappings`. Помните, что qemu-user может эмулировать syscall'ы иначе, чем ядро, — учитывайте при отладке.

## Разобранный пример: heap UAF под qemu

```python
# 1) запустить под qemu с gdb
# 2) найти адрес освобождённого чанка
# 3) посмотреть bins: чанк в tcache/fastbin?
# 4) проверить safe-linking (next замаскирован?)
# 5) спланировать poisoning
```

В gdb: `bins` покажет, где чанк; `x/4gx addr` — его поля. Для safe-linking вычислите `pos >> 12` и маскировку.

## Частые ошибки

- **Не та архитектура.** `set architecture`.
- **Нет символов.** Загрузите libc или используйте смещения.
- **Неверный sysroot.** Библиотеки не найдены.
- **Перенос смещений.** ARM/MIPS отличаются от x86-64.
- **qemu-специфика.** Syscall'ы эмулируются.

## Справочные таблицы

| Команда | Назначение |
|---|---|
| `set architecture` | целевая arch |
| `target remote` | подключение |
| `bins` | бины |
| `vis_heap_chunks` | чанки |
| `info proc mappings` | карта |

| Архитектура | gdb arch |
|---|---|
| ARM64 | `aarch64` |
| MIPS | `mips` |
| RISC-V | `riscv:rv64` |

## Что дальше / решение

Дальше: `pwn-qemu-user`, `pwn-arm64-heap`, `pwn-heap-tcache`, `pwn-mips`. Практический алгоритм: (1) запустите под qemu с `-g`; (2) подключитесь gdb-multiarch с нужной arch; (3) загрузите символы целевой libc; (4) анализируйте бины/чанки; (5) отлаживайте эксплойт. Кросс-архитектурная отладка heap требует инструментов и терпения, но навык критичен для embedded и ARM-целей.

## Практические рекомендации

Начните с простых heap-задач под qemu-aarch64, отработайте `bins`/`vis_heap_chunks`. Загружайте символы libc для удобства. Помните о различиях смещений между архитектурами. Практикуйтесь на учебных задачах и ведите заметки. Кросс-архитектурная отладка — важный навык для современного pwn.
## Полный разбор отладки heap под qemu-aarch64

Разберём сквозной пример. Дано: AArch64-бинарь с heap UAF, приложена libc. Цель — понять раскладку и спланировать poisoning. Шаги: (1) подготовьте sysroot: скопируйте `libc.so.6` и `ld-linux-aarch64.so.1` в `./sysroot/lib/`; (2) запустите `qemu-aarch64 -g 1234 -L ./sysroot ./chall`; (3) подключитесь `gdb-multiarch ./chall -ex 'set architecture aarch64' -ex 'target remote :1234'`; (4) загрузите символы libc: `set sysroot ./sysroot`, `sharedlibrary` (gdb подтянет libc); (5) поставьте точки на `malloc`/`free`; (6) выполните аллокации/освобождения в бинаре, наблюдая `bins`; (7) найдите освобождённый чанк и его поля; (8) проверьте safe-linking (замаскирован ли `next`); (9) спланируйте poisoning. В gdb: `bins`, `vis_heap_chunks 20`, `x/4gx addr`, `p &main_arena`.

## Символы и смещения для ARM libc

Символы glibc на ARM64 отличаются от x86-64 по смещениям. Если libc приложена, загрузите её в gdb (`add-symbol-file`/`sharedlibrary`) — символы подтянутся. Если stripped, используйте `libc-database` с ARM-сборками или анализируйте вручную. Ключевые символы: `main_arena`, `__free_hook` (до 2.34), `_IO_2_1_stdout_`, `_IO_list_all`. Для safe-linking вычислите `pos >> 12` (pos — адрес поля `next`). Проверяйте в gdb: `p &main_arena`, `p &__free_hook`. Не переносите смещения с x86-64 — они другие.

## Практические советы по отладке

(1) Привязывайте процесс к одному CPU (`sched_setaffinity`) — для стабильности heap. (2) Используйте `set follow-fork-mode child`, если сервис форкает. (3) Логируйте адреса и проверяйте их в `info proc mappings`. (4) Для tcache используйте `tcache` в pwndbg (покажет counts/entries). (5) Помните, что qemu-user эмулирует syscall'ы — `brk`/`mmap` могут вести себя иначе, чем на реальном ядре. (6) Увеличивайте таймауты (эмуляция медленнее). (7) Сверяйте выравнивание (16 байт). Практикуйтесь на учебных задачах, ведите заметки по структурам и смещениям. Кросс-архитектурная отладка — навык, который окупается в embedded и ARM-облачных задачах.
## Расширенный разбор: heap на ARM64 под qemu

Дополним пример. Для tcache-анализа на AArch64 важно знать раскладку `tcache_perthread_struct`: counts (2 байта на бин) и entries (8 байт на бин). В gdb (pwndbg): `tcache` покажет counts/entries; `vis_heap_chunks` — чанки. Safe-linking на AArch64 работает так же: `next = ptr ^ (pos >> 12)`. Для утечки heap-базы используйте `show` освобождённого чанка. Проверьте, что `pos` (адрес поля `next`) вычислен верно. Для `main_arena` смещение зависит от ARM-сборки — найдите в gdb (`p &main_arena`). Помните про выравнивание 16 байт: размеры чанков кратны 0x10, и это влияет на бин. Практикуйтесь на учебной AArch64-задаче, отрабатывая `bins`/`vis_heap_chunks`/`tcache`. Логируйте адреса и сверяйте с `info proc mappings`.

## Работа с sysroot и отладчиком

Подготовка sysroot: скопируйте целевые `libc.so.6`, `ld-linux-aarch64.so.1` (или MIPS/RISC-V аналоги) в `./sysroot/lib/` и `./sysroot/lib/ld-*.so`. Флаг `-L ./sysroot` укажет qemu искать там. В gdb: `set sysroot ./sysroot`, `set solib-search-path ./sysroot/lib`, `sharedlibrary` — подтянет символы. Если libc stripped, используйте `libc-database` (ARM/MIPS-сборки) для смещений. Для MIPS/RISC-V аналогично, но с их загрузчиками. Проверяйте, что бинарь запускается: `qemu-aarch64 -L ./sysroot ./chall`. Если падает с «not found», проверьте зависимости (`readelf -d`). Отладка без символов сложнее — используйте анализ структур вручную и `x/`-дампы. Терпение и систематичность.

## Итог

Кросс-архитектурная отладка heap требует правильного sysroot, символов и инструментов (gdb-multiarch, pwndbg). Освоив её, вы сможете эксплуатировать ARM/MIPS/RISC-V цели — от embedded до облачных. Практикуйтесь на учебных задачах, ведите заметки по смещениям и структурам. Помните, что qemu-user — приближение; реальное устройство может отличаться. Всегда проверяйте поведение и логируйте.


## Работа с разными архитектурами: MIPS и RISC-V

Для MIPS под qemu отладка аналогична ARM64, но с учётом endianness и delay slots: используйте `qemu-mips`/`qemu-mipsel` и `set architecture mips`. Для RISC-V — `qemu-riscv64` и `set architecture riscv:rv64`. В каждом случае загружайте целевую libc в gdb и анализируйте `bins`/`vis_heap_chunks`. Помните, что смещения glibc специфичны для каждой архитектуры: `main_arena`, `__free_hook`, `_IO_2_1_stdout_` расположены по-разному. Для утечек используйте `show` освобождённого чанка; для safe-linking — маскировку `next`. Практикуйтесь на учебных задачах каждой архитектуры, чтобы привыкнуть к инструментам и структурам. Ведите заметки по смещениям — это сэкономит время в будущем. Кросс-архитектурная отладка heap — навык, который открывает embedded и облачные ARM/MIPS/RISC-V цели.


## Отладка tcache и safe-linking на AArch64

Для tcache на AArch64: `tcache` в pwndbg покажет counts и entries; `vis_heap_chunks` — чанки. Safe-linking маскирует `next` как `ptr ^ (pos >> 12)`, где `pos` — адрес поля `next`. Для poisoning нужна heap-утечка: прочитайте `show` освобождённого чанка. Проверьте, что `pos` вычислен верно (адрес поля внутри чанка). Для `main_arena` смещение ARM-специфично — найдите в gdb (`p &main_arena`). Выравнивание 16 байт влияет на бин. Практикуйтесь на учебной AArch64-задаче, логируя адреса и сверяя с `info proc mappings`. Это основа кросс-архитектурной heap-эксплуатации.


## Сравнение с нативной отладкой

Кросс-архитектурная отладка отличается от нативной: нет удобных расширений для всех архитектур, эмуляция медленнее, syscall'ы транслируются. Поэтому чаще полагайтесь на ручной анализ (`x/`, `p`, `info proc mappings`) и логирование. Проверяйте, что структуры glibc соответствуют целевой сборке (смещения ARM/MIPS отличаются). Для сложных случаев используйте символы libc и `ptype`. Помните, что qemu-user — приближение: реальное устройство может иметь иной ASLR/libc. Всегда тестируйте на максимально близком окружении. Терпение и систематичность — ключ.


## Финальные рекомендации

Кросс-архитектурная отладка heap требует sysroot, символов и gdb-multiarch. Анализируйте `bins`/`vis_heap_chunks`, сверяйте смещения с целевой libc, учитывайте safe-linking и выравнивание. Практикуйтесь на ARM/MIPS/RISC-V задачах, ведите заметки. Этот навык открывает embedded и облачные цели.


## Дополнительные советы

Для сложных кросс-архитектурных heap-задач используйте `libc-database` с ARM/MIPS-сборками для смещений, если libc не приложена. Проверяйте раскладку через `info proc mappings` и сверяйте с ожиданиями. Логируйте адреса на каждом шаге. Практикуйтесь на учебных задачах, постепенно усложняя (tcache → Botcake → FSOP).

## Квиз

```quiz
- question: "Какой отладчик нужен для ARM/MIPS/RISC-V бинарей?"
  options:
    - "gdb-multiarch"
    - "обычный gdb без флагов"
    - "ollydbg"
    - "x64dbg"
  answer: 0
  explanation: "gdb-multiarch поддерживает множество архитектур; нужен set architecture."
- question: "Как заставить qemu-user ждать отладчик?"
  options:
    - "Запустить с флагом -g <порт> и подключиться target remote"
    - "Использовать ptrace"
    - "Запустить gdbserver в госте"
    - "Флагом -d"
  answer: 0
  explanation: "qemu-user предоставляет gdbstub на порту, указанном в -g."
- question: "Почему важно выполнить set architecture?"
  options:
    - "Иначе регистры и дизассембляция будут неверными"
    - "Иначе не включится ASLR"
    - "Иначе не будет heap"
    - "Это необязательно"
  answer: 0
  explanation: "Без указания ISA gdb неверно интерпретирует код и регистры."
- question: "Какой регистр содержит первый аргумент в AArch64?"
  options:
    - "x0"
    - "a0"
    - "rdi"
    - "r0"
  answer: 0
  explanation: "В AArch64 аргументы передаются в x0..x7 (a0 = x0)."
- question: "Что подгружает set sysroot ./rootfs?"
  options:
    - "Символы и библиотеки гостя (libc, ld.so) для корректного разбора"
    - "Ядро гостя"
    - "Настройки ASLR"
    - "BPF-программы"
  answer: 0
  explanation: "sysroot даёт gdb доступ к гостевым библиотекам и их символам."
```

## Где пригодится

- **CTF:** Pwn — cross-arch heap-задачи (отладка).
- **Bug bounty:** анализ embedded/ARM-бинарей.
- **Пентест:** реверс и отладка на не-x86.
- **Работа:** security research, разработка эксплойтов.
