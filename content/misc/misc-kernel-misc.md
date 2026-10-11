---
id: misc-kernel-misc
title: "Kernel misc: syscalls, /proc и eBPF"
category: misc
parent: misc-games-systems
difficulty: expert
order: 4
tags: [kernel, syscalls, proc, ebpf, strace, seccomp, linux]
prerequisites: [misc-games-systems]
useful_for:
  - "CTF Misc/pwn категория"
  - "Низкоуровневая безопасность Linux"
  - "Наблюдаемость и eBPF"
estimated_minutes: 32
summary: "strace/ltrace, чтение /proc и /sys, syscall-ABI, seccomp-фильтры, eBPF и tracefs, а также типовые задачи про ядро и песочницы."
---

Уровень ядра — последний слой, куда спускается misc. Здесь задача может быть про перехват syscalls, про чтение состояния процесса из `/proc`, про обход seccomp-фильтра или про написание eBPF-программы. Даже без «настоящего» kernel exploit понимание этого слоя решает массу задач.

## strace и ltrace

`strace` показывает **системные вызовы** процесса, `ltrace` — вызовы библиотечных функций.

```bash
strace -f -e trace=openat,read,write ./binary
# openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
# read(3, "root:x:0:0:...", 4096) = 1234

ltrace ./binary
# strlen("flag") = 4
# strcmp("wrong", "flag") = -1
```

Полезные флаги: `-f` (за детьми), `-s 256` (длиннее строки), `-tt` (таймстемпы), `-c` (сводка), `-o file` (в файл).

## /proc и /sys

`/proc` — окно в ядро и процессы:

| Путь | Что даёт |
|------|----------|
| `/proc/self/maps` | карта памяти процесса |
| `/proc/self/environ` | переменные окружения |
| `/proc/self/fd/` | открытые файловые дескрипторы |
| `/proc/self/cmdline` | аргументы запуска |
| `/proc/sys/kernel/*` | tunables (randomize_va_space, yama) |
| `/proc/kallsyms` | адреса символов ядра (если разрешено) |

```bash
cat /proc/self/maps | head
# 55d2...-55d2... r-xp 00000000 08:01 1234 /usr/bin/cat
cat /proc/self/status | grep -E 'Seccomp|Cap'
# Seccomp: 2
```

`Seccomp: 2` означает активный фильтр — важный сигнал в задачах про sandbox.

## Syscall ABI

На x86-64 номер syscall кладётся в `rax`, аргументы — в `rdi, rsi, rdx, r10, r8, r9`, вызов — `syscall`. На aarch64 — `x8` и `x0..x5`, `svc #0`.

```nasm
; write(1, msg, len)
mov rax, 1        ; SYS_write
mov rdi, 1        ; fd = stdout
lea rsi, [msg]
mov rdx, len
syscall
```

Список номеров — `/usr/include/asm/unistd_64.h` или `ausyscall --dump`. В CTF это нужно, когда в бинаре нет libc (static/stripped) и вызовы идут напрямую.

## seccomp-фильтры

seccomp (secure computing) ограничивает доступные syscalls. Фильтр — BPF-программа, возвращающая `ALLOW`/`ERRNO`/`KILL`. Проверить:

```bash
grep Seccomp /proc/self/status
# Seccomp: 2
seccomp-tools dump ./binary
# line  CODE  JT  JF  K
# 0000: 0x20 0x00 0x00 0x00000004  A = arch
# 0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007
# ...
# 0009: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0011
# 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
# 0011: 0x06 0x00 0x00 0x00050000  return ERRNO(0)
```

`seccomp-tools dump` (Ruby gem) — обязательный инструмент. Часто в задачах «запрещён execve, но разрешён openat/read/write» → надо прочитать флаг через openat+read+write, а не запускать shell.

## eBPF и tracefs

eBPF позволяет исполнять проверенные программы в ядре. Для трассировки используют `bpftrace`:

```bash
bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'
# cat /etc/passwd
```

`bpftrace` — высокоуровневый язык; под капотом — eBPF-байткод. В задачах про «kernel misc» может потребоваться:

- посчитать, какие syscalls вызывает процесс (`bpftrace -e 'tracepoint:syscalls:sys_enter_* { @[probe] = count(); }'`);
- перехватить `read` и подменить данные;
- прочитать `tracefs`: `/sys/kernel/tracing/`.

## Полный разобранный пример

Задача: бинарь читает флаг и печатает «nope». strace показывает:

```bash
strace -e trace=openat,read,write ./chall
# openat(AT_FDCWD, "flag.txt", O_RDONLY) = 3
# read(3, "flag{...}", 64) = 33
# write(1, "nope\n", 5) = 5
```

Флаг уже прочитан, но не выведён. Патчим `write` через `gdb`:

```bash
gdb ./chall
(gdb) break write
(gdb) run
(gdb) x/s $rsi      # смотрим, что выводится
(gdb) set $rsi = <адрес флага из read>
(gdb) continue
```

## Частые ошибки и подводные камни

- Забывать `-f` в strace — не видно дочерних процессов.
- Путать `/proc/self` (свой процесс) и `/proc/<pid>`.
- Считать, что seccomp блокирует только `execve` — фильтр может ограничивать и `open`/`read`.
- Пытаться читать `/proc/kallsyms` без прав — увидите нули (`kptr_restrict`).
- Забывать про arch-check в seccomp (фильтр под x86_64 не сработает под aarch64).

## Что дальше / решение

Установите `seccomp-tools`, `strace`, `bpftrace` и прогоните учебные sandbox-бинари. Разберите фильтры в pwn-задачах (часто seccomp = «ORW: open-read-write»). Дальше — `misc-seccomp-escape` (обход фильтров) и pwn-ветка про shellcode.

## Справочная таблица

| Задача | Инструмент |
|--------|-----------|
| Трассировка syscalls | `strace -f` |
| Трассировка библиотек | `ltrace` |
| Дамп seccomp | `seccomp-tools dump` |
| eBPF-трассировка | `bpftrace` |
| Состояние процесса | `/proc/<pid>/*` |
| Номера syscalls | `ausyscall --dump` |
| Карта памяти | `/proc/self/maps` |

## Дополнительная теория: устройство syscall и ABI

Системный вызов — это переход из user space в kernel space. На x86-64 инструкция `syscall` использует регистры: `rax` — номер, `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` — аргументы, возврат в `rax` (отрицательное значение — `-errno`). На aarch64 — `x8` и `x0..x5`, инструкция `svc #0`. Понимание ABI критично, когда в бинаре нет libc: shellcode и статические бинари вызывают syscalls напрямую, и надо правильно разложить аргументы по регистрам. Ошибка в регистре (`r10` вместо `rdx` для четвёртого аргумента) — частая причина «не работает».

Есть также **vDSO** — отображённая ядром библиотека, ускоряющая некоторые вызовы (`gettimeofday`, `clock_gettime`) без перехода в ядро. И **syscall-таблицы**: номера зависят от архитектуры и ABI (x86_64, x32, i386 — разные). В CTF это используется в seccomp-обходах: фильтр настроен на x86_64, а вызов через i386 (`int 0x80`) имеет другие номера и может не попасть под правило.

## /proc как интерфейс ядра

`/proc` — это не файлы на диске, а окно в ядро. Помимо `/proc/<pid>/*`, есть глобальные узлы: `/proc/kallsyms` (адреса символов ядра), `/proc/kcore` (образ памяти ядра), `/proc/sys/*` (tunables), `/proc/modules` (загруженные модули), `/proc/self/mountinfo` (точки монтирования). В задачах про sandbox важно: доступен ли `/proc/<pid>/root` (корень процесса), `/proc/<pid>/mem` (чтение памяти другого процесса), `/proc/sys/kernel/core_pattern` (программа обработки крашей — вектор побега из контейнера).

`/sys` даёт доступ к устройствам и подсистемам (`/sys/kernel/`, `/sys/fs/cgroup/`). Запись в некоторые узлы требует прав и может менять поведение ядра. В CTF «kernel misc» иногда сводится к чтению правильного узла `/proc` или `/sys`, а не к настоящей эксплуатации ядра.

## Разбор ошибок и отладка

Если `strace` «ничего не показывает» — возможно, бинарь статический и делает syscalls напрямую (это нормально, strace их видит) или использует `ptrace`-защиту (тогда strace не прицепится). Если `seccomp-tools dump` не работает — нужен root или бинарь без setuid-сброса. Если `bpftrace` ругается на права — проверьте `kernel.unprivileged_bpf_disabled`. Если `/proc/kallsyms` показывает нули — `kptr_restrict=2`. Если программа ведёт себя иначе под strace — возможно, она детектит ptrace (анти-отладка). В таких случаях используйте `ltrace` или запуск под `gdb` с `catch syscall`.

## Практический разбор: чтение seccomp и построение ORW

Дана pwn-задача: бинарь с фильтром. Первый шаг — дамп:

```bash
seccomp-tools dump ./chall
```

Читаем: `open`, `read`, `write` разрешены, `execve` — KILL. Значит, shell не получить, но флаг можно прочитать. Строим ORW-шеллкод в pwntools:

```python
from pwn import *
context.arch = 'amd64'
sc = shellcraft.open('flag.txt')
sc += shellcraft.read('rax', 'rsp', 0x100)
sc += shellcraft.write(1, 'rsp', 0x100)
print(asm(sc).hex())
```

Если `open` тоже запрещён, а разрешён `openat` — меняем вызов:

```python
sc = shellcraft.openat(0, 'flag.txt', 0)  # AT_FDCWD
```

Дальше встраиваем шеллкод в эксплойт (обычно через переполнение буфера или ROP-цепочку, вызывающую `mprotect`+shellcode). Проверяем локально под тем же фильтром: запускаем бинарь, подаём payload, читаем флаг. Если получаем `SIGSYS` — значит, вызвали запрещённый syscall; сверяемся с дампом. Этот цикл «дамп → подбор разрешённых syscalls → ORW → проверка» решает большинство sandbox-задач.

## Квиз

```quiz
- question: "Что показывает strace?"
  options:
    - "Системные вызовы процесса"
    - "Только сетевой трафик"
    - "Содержимое диска"
    - "Загрузку CPU"
  answer: 0
  explanation: "strace перехватывает syscalls; ltrace — библиотечные вызовы."
- question: "Что означает `Seccomp: 2` в /proc/self/status?"
  options:
    - "Активен seccomp-фильтр (режим filter)"
    - "Процесс в спящем режиме"
    - "Включён ASLR"
    - "Открыто 2 файла"
  answer: 0
  explanation: "Режим 2 — filter, реально ограничивающий syscalls."
- question: "Чем дампится seccomp-фильтр бинаря?"
  options:
    - "seccomp-tools dump ./binary"
    - "nmap -sV"
    - "objdump -d"
    - "readelf -a"
  answer: 0
  explanation: "seccomp-tools показывает BPF-программу фильтра."
- question: "В каком регистре на x86-64 передаётся номер syscall?"
  options:
    - "rax"
    - "rdi"
    - "rsp"
    - "rip"
  answer: 0
  explanation: "rax — номер, rdi/rsi/rdx/r10/r8/r9 — аргументы."
- question: "Что такое bpftrace?"
  options:
    - "Высокоуровневый инструмент трассировки на eBPF"
    - "Компилятор C"
    - "Отладчик ядра Windows"
    - "Пакетный менеджер"
  answer: 0
  explanation: "bpftrace компилирует скрипты в eBPF-программы."
```

## Где пригодится

- **CTF:** misc/pwn-задачи про sandbox, seccomp, syscalls.
- **Работа:** наблюдаемость (eBPF), диагностика Linux-сервисов.
- **Malware analysis:** понимание syscall-поведения.
- **Контейнеры:** seccomp — основа изоляции Docker/K8s.
