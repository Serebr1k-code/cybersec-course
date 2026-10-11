---
id: pwn-static-no-libc
title: "Эксплуатация статических бинарей без libc"
category: pwn
parent: pwn-ret2libc
difficulty: expert
order: 3
tags: [static, no-libc, rop, syscall, orw, ret2dlresolve]
prerequisites: [pwn-rop, pwn-ret2libc, pwn-got-plt, pwn-ret2dlresolve]
useful_for:
  - "CTF Pwn категория"
  - "Vulnerability research"
estimated_minutes: 65
summary: "Статический бинарь не даёт libc-гаджетов: строим ROP на гаджетах самого бинаря, используем syscall/ORW, ret2dlresolve и внутренние функции как mini-libc."
---
Эксплуатация статических бинарей без libc — это задача, где у вас нет динамически подключаемой libc, и все функции (включая `system`) либо вкомпилированы, либо отсутствуют. Статические бинари часто встречаются в embedded, CTF и musl-сборках. Отсутствие libc-утечки меняет стратегию: вместо ret2libc используются syscall-гаджеты (`syscall; ret`), `ret2dlresolve` (для динамических, но здесь не применимо), `ret2csu` (для загрузки регистров) и SROP. В этом уроке — приёмы эксплуатации статических бинарей: ORW через syscall, ret2csu, SROP, поиск syscall-гаджетов и практические примеры.

## Проблема отсутствия libc

В динамическом бинаре `system` есть в libc, и вы утекаете её адрес. В статическом — libc вкомпилирована в бинарь, поэтому `system` может быть доступна по фиксированному адресу (если PIE выключен) или по смещению (если PIE включён). Проверьте: `nm ./chall | grep -E "system|execve"`, `objdump -d | grep system`. Если `system` есть, можно вызвать её напрямую. Если нет (например, musl), используйте syscall-гаджеты для `execve` или ORW.

## Syscall-гаджеты и ORW

В статическом бинаре часто есть гаджет `syscall; ret` (или `int 0x80; ret` для 32-бит). Имея его, вы строите ORW-цепочку: `open("flag")`, `read`, `write`. Нужны гаджеты для загрузки `rax` (номер syscall), `rdi`, `rsi`, `rdx`. Пример:

```python
from pwn import *
context.binary = elf = ELF('./chall')
rop = ROP(elf)
pop_rax = rop.find_gadget(['pop rax','ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi','ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx','ret'])[0]
syscall = rop.find_gadget(['syscall','ret'])[0]
buf = elf.bss(0x200)
# openat(AT_FDCWD, "flag", 0)
chain  = flat(pop_rax, 2, pop_rdi, flag_addr, pop_rsi, 0, pop_rdx, 0, syscall)
# read(3, buf, 0x100)
chain += flat(pop_rax, 0, pop_rdi, 3, pop_rsi, buf, pop_rdx, 0x100, syscall)
# write(1, buf, 0x100)
chain += flat(pop_rax, 1, pop_rdi, 1, pop_rsi, buf, pop_rdx, 0x100, syscall)
```

## ret2csu

Если гаджетов на некоторые регистры нет, используйте `ret2csu` — код в `__libc_csu_init`, который загружает `rsi`, `rdx` и вызывает указатель. Это стандартный приём для статических/динамических бинарей с ограниченными гаджетами. `ret2csu` требует двух этапов: первый настраивает регистры, второй вызывает функцию. Подробнее — в уроке `pwn-ret2csu`.

## SROP

SROP (sigreturn-oriented programming) использует syscall `rt_sigreturn` (15 на x86-64) для восстановления **всех** регистров из поддельного `sigframe` на стеке. Если у вас есть гаджет `syscall; ret` и возможность записать фрейм, вы можете установить `rax`, `rdi`, `rsi`, `rdx`, `rip`, `rsp` разом. SROP идеален для статических бинарей, где мало гаджетов:

```python
frame = SigreturnFrame()
frame.rax = 59          # execve
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall
payload = flat(b'A'*offset, pop_rax, 15, syscall, frame)
```

## Разобранный пример: static + syscall

```python
from pwn import *
context.binary = elf = ELF('./chall')
p = process('./chall')
# утечка (если PIE) или фиксированные адреса
rop = ROP(elf)
# ... построить ORW или SROP ...
p.sendline(payload)
p.interactive()
```

## Частые ошибки

- **PIE включён.** Нужна утечка базы.
- **Нет `system`.** Используйте syscall/ORW.
- **Нет гаджетов на регистры.** Используйте ret2csu/SROP.
- **Номер syscall.** Проверьте ABI (x86-64: `rax`).
- **Стек не выровнен.** Добавьте `ret`.

## Справочные таблицы

| Syscall | x86-64 номер |
|---|---|
| read | 0 |
| write | 1 |
| open | 2 |
| execve | 59 |
| rt_sigreturn | 15 |

| Приём | Когда |
|---|---|
| ret2syscall | есть `syscall`-гаджет |
| ret2csu | нет гаджетов на rsi/rdx |
| SROP | мало гаджетов |
| ret2dlresolve | динамический бинарь |

## Что дальше / решение

Дальше: `pwn-ret2csu`, `pwn-seccomp-srop`, `pwn-musl`, `pwn-rop`. Практический алгоритм: (1) проверьте, есть ли `system`/`execve` в бинаре; (2) найдите `syscall`-гаджет; (3) постройте ORW или SROP; (4) при нехватке гаджетов используйте ret2csu; (5) обойдите PIE утечкой. Статические бинари — частое явление в embedded и CTF; умение работать без libc расширяет ваш арсенал.
## Полный разбор статического бинаря с PIE

Разберём сквозной пример. Дано: статический 64-битный бинарь с PIE и переполнением стека. libc вкомпилирована, `system` может присутствовать, но адреса рандомизированы. Шаги: (1) проверяем `checksec` — PIE on; (2) ищем `syscall; ret`-гаджет и гаджеты на регистры (`pop rax`, `pop rdi`, `pop rsi`, `pop rdx`); (3) получаем утечку базы PIE (например, через формат-строку или неинициализированную память); (4) строим ORW-цепочку: `openat`/`open`, `read`, `write`; (5) отправляем. Если утечки нет, используйте **partial overwrite** — перезапишите только младшие байты адреса возврата, направив его в известную точку (например, `main` или `syscall`-гаджет), так как младшие 12 бит фиксированы. Это классический приём для PIE без утечки.

## SROP подробно

SROP (sigreturn-oriented programming) особенно полезен для статических бинарей, где мало гаджетов. Идея: если у вас есть гаджет `syscall; ret` и способ установить `rax = 15` (`rt_sigreturn`), вы можете вызвать `rt_sigreturn`, который восстановит **все** регистры из поддельного `sigframe` на стеке. Это даёт контроль над `rax`, `rdi`, `rsi`, `rdx`, `rip`, `rsp` одним вызовом. Схема: (1) найти `syscall; ret`; (2) установить `rax = 15` (через `pop rax` или `read` в известное место); (3) выполнить `syscall` — сработает `rt_sigreturn`; (4) в `sigframe` задать `rip = syscall`, `rax = 59` (`execve`), `rdi = "/bin/sh"`; (5) отправить. Это стандартный маршрут для статических бинарей без достаточных гаджетов.

## ret2csu и ORW-комбинации

`ret2csu` использует код в `__libc_csu_init` (есть в статических бинарях с glibc), который загружает `rbx`, `rbp`, `r12`–`r15` и вызывает `[r15 + rbx*8]`. С его помощью можно установить `rsi`/`rdx` (через `r14`/`r13`) и вызвать функцию. Это дополняет ORW, когда нет прямых `pop rsi`/`pop rdx`. Комбинируйте: `ret2csu` для установки регистров, `syscall` для ORW. Изучите раскладку `__libc_csu_init` в вашем бинаре (`objdump -d | grep csu`). Помните, что `ret2csu` требует двух этапов (настройка + вызов), что усложняет цепочку, но расширяет возможности.

## Практические рекомендации

Начните с определения: статический ли бинарь (`file`, `ldd`), есть ли PIE, есть ли `system`. Если `system` есть и PIE off — ret2libc-подобный вызов. Если PIE on — утечка или partial overwrite. Если `system` нет — ORW через syscall. При нехватке гаджетов — ret2csu/SROP. Всегда проверяйте `seccomp-tools dump` (если есть песочница). Практикуйтесь на задачах с musl и glibc static. Статические бинари — частое явление в embedded, и умение работать без libc критично.
## Разбор статического бинаря с musl

Musl-сборки часто статические и используются в Alpine/Docker. Особенности: (1) `mallocng` (свой аллокатор) вместо glibc — heap-эксплойты отличаются; (2) отсутствуют `__free_hook` и glibc-специфичные символы; (3) `system` может отсутствовать — используйте syscall. Для ROP в musl-статическом бинаре ищите `syscall; ret` и гаджеты на регистры. ORW через syscall работает как обычно. Для heap-задач изучайте `mallocng` (структуры, метаданные). Musl встречается в Docker-образах (Alpine), поэтому навык полезен для контейнерной эксплуатации. См. также урок `pwn-musl`.

## Partial overwrite без утечки

Когда PIE включён, но утечки нет, используйте partial overwrite: перезапишите только младшие 1–2 байта адреса возврата. Младшие 12 бит адреса фиксированы (страничное выравнивание), поэтому можно направить поток в известную точку (например, `main`, `syscall`-гаджет или функцию в том же регионе). Это работает, если целевой адрес находится на той же странице или рядом. Для этого вычислите младшие байты целевого адреса и перезапишите только их. Приём эффективен в статических PIE-бинарях, где много кода и удобных целей. Проверяйте в gdb, что перезапись попадает в нужную точку.

## Практические рекомендации

Определите: статический ли бинарь, PIE, наличие `system`. Если `system` есть и PIE off — прямой вызов. Если PIE on — утечка или partial overwrite. Если `system` нет — ORW. При нехватке гаджетов — ret2csu/SROP. Всегда проверяйте seccomp. Для musl изучайте mallocng. Практикуйтесь на задачах с glibc static и musl static. Статические бинари — частое явление, и умение работать без libc-утечки критично. Держите шаблоны ORW/SROP под рукой — они экономят время.


## Практика: ORW-цепочка

Соберите ORW: (1) найдите `syscall; ret`; (2) гаджеты `pop rax`/`pop rdi`/`pop rsi`/`pop rdx`; (3) `openat(AT_FDCWD, "flag", 0)` (257) или `open("flag",0)` (2); (4) `read(3, buf, 0x100)` (0); (5) `write(1, buf, 0x100)` (1); (6) буфер в `.bss`. Проверяйте в gdb. При нехватке гаджетов — ret2csu/SROP. Практикуйтесь на статических glibc/musl бинарях. Умение работать без libc критично для embedded и CTF.


## Практика: ret2csu и SROP

При нехватке гаджетов используйте ret2csu (`__libc_csu_init`) для загрузки `rsi`/`rdx`. Для SROP — `syscall` + `rt_sigreturn` (15) + поддельный фрейм. Соберите ORW/SROP и проверьте. Практикуйтесь на статических glibc/musl бинарях. Умение работать без libc критично для embedded и CTF. Держите шаблоны ORW/SROP под рукой.

## Квиз

```quiz
- question: "Почему в статическом бинаре нет ret2libc?"
  options:
    - "libc внутри бинаря; нет отдельного libc и утечки её базы"
    - "Статика запрещает ROP"
    - "Нет стека"
    - "Нет syscalls"
  answer: 0
  explanation: "В статике libc слинкована внутрь; гаджеты берутся из бинаря."
- question: "Какой приём используют вместо вызова system в статике?"
  options:
    - "ret2syscall (execve через syscall)"
    - "FSOP"
    - "tcache poisoning"
    - "unsorted attack"
  answer: 0
  explanation: "Строят цепочку с syscall execve/ORW."
- question: "Что делать, если execve запрещён seccomp?"
  options:
    - "Использовать ORW (open/read/write)"
    - "Отключить seccomp"
    - "Снять canary"
    - "Расширить tcache"
  answer: 0
  explanation: "ORW читает флаг без execve."
- question: "Где искать строку /bin/sh в статике?"
  options:
    - "strings -a -t x ./binary | grep /bin/sh"
    - "ldd"
    - "nm"
    - "readelf -h"
  answer: 0
  explanation: "Строка часто присутствует; strings даёт её адрес."
- question: "Чем static-pie отличается от обычной статики?"
  options:
    - "Адреса рандомизированы (нужна база)"
    - "Нет syscalls"
    - "Нет гаджетов"
    - "Он динамический"
  answer: 0
  explanation: "static-pie рандомизирует базу, поэтому нужна утечка."
```

## Где пригодится

- **CTF:** Pwn — статические бинари.
- **Bug bounty:** IoT/embedded (часто статика).
- **Пентест:** разработка эксплойтов.
- **Работа:** exploit development.
