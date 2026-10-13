---
id: pwn-mitigations
title: "Защиты: NX, ASLR, PIE, canary и их обход"
category: pwn
parent: pwn-ret2libc
difficulty: medium
order: 1
tags: [nx, aslr, pie, canary, relro, bypass]
prerequisites: [pwn-ret2libc]
useful_for:
  - "CTF Pwn категория"
  - "Оценка эксплуатируемости"
  - "Secure coding"
estimated_minutes: 40
summary: "Систематизируем современные бинарные защиты и практические техники их обхода: leak, brute-force, canary leak, PIE base recovery."
lab:
  kind: shell
  title: "Практика: какие защиты включены"
  toolset: [core, readelf, file]
  workdir: /home/student/task
  files: [task.md, passcheck, hardened]
  check: "grep -q 'RELRO=full' answer.txt"
  hints:
    - "PIE видно по типу файла: `readelf -h hardened` (EXEC против DYN)."
    - "NX — это сегмент `GNU_STACK`: `readelf -l hardened`, смотри флаги (RW или RWE)."
    - "RELRO full = в `readelf -d hardened` есть `BIND_NOW` и `GNU_RELRO`; canary — символ `__stack_chk_fail` в `readelf -s hardened`."
---

## Вопрос, с которого всё начинается

Ты нашёл переполнение. Но прежде чем писать эксплойт, нужно понять, **что нам помешает**. Включена канарейка — она уронит процесс раньше, чем мы вернёмся по адресу. Включён PIE — мы не знаем адресов. NX — shellcode на стеке не запустится.

Каждая защита меняет план атаки. Сегодня соберём карту: что бывает и как это обходить.

## Наш пример: смотрим на chall

```bash
$ checksec --file=./chall
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

`checksec` — первая команда при встрече с бинарём. Из её вывода сразу строится план:

- **Canary found** → нужна утечка канарейки или обход.
- **NX enabled** → shellcode не пройдёт, нужен ROP.
- **PIE enabled** → нужна утечка базы кода.
- **Partial RELRO** → GOT ещё записываем.

То же самое из pwntools: `ELF('./chall').checksec()`.

## Шаг 1. NX / DEP: неисполняемая память

**NX** помечает стек и кучу как `rw-` (читаемо-записываемо, но **не исполняемо**). Shellcode, залитый на стек, не запустится.

Проверить: `readelf -l ./chall | grep GNU_STACK` — строка `RW` без `E`.

**Обход:** ROP/ret2libc — мы не запускаем новый код, а собираем программу из существующих инструкций.

## Шаг 2. ASLR: рандомизация адресов

Ядро случайно размещает libc, стек и кучу при каждом запуске. Даже зная оффсет `system`, ты не знаешь, куда прыгать.

Проверить: `cat /proc/sys/kernel/randomize_va_space` (`2` = полный ASLR).

**Обход:** утечка любого адреса и вычисление базы:

```python
libc.address = leak - libc.symbols['puts']
```

Именно это делает ret2libc из прошлого урока.

## Шаг 3. PIE: рандомизация самого бинаря

Обычный бинарь грузится по фиксированному адресу `0x400000`, поэтому `main` известен. **PIE** (Position-Independent Executable) сдвигает весь образ на случайную базу — адреса кода тоже неизвестны.

Проверить: `readelf -h ./chall | grep Type` — `DYN` вместо `EXEC`.

**Обход:** утечка базы кода (например, через `%p` или чтение адреса из `.text`) либо **partial overwrite** — перезапись младших байт адреса в пределах той же страницы. Подробно — в `pwn-pie-bypass`.

## Шаг 4. Canary: защита стека

**Canary** — случайное значение, которое компилятор кладёт перед сохранённым адресом возврата. Перед `ret` программа проверяет, не изменилось ли оно; если да — вызывает `__stack_chk_fail` и завершается.

Проверить: `readelf -s ./chall | grep stack_chk`.

**Обход:**

- **Утечка.** Прочитать канарейку (например, через `%p` или `puts` без нулевого байта) и подставить её обратно в payload.
- **Брутфорс** — только на сервере, который **форкает**: при `fork` канарейка не меняется, и её можно подобрать побайтово.
- **Не трогать канарейку** — найти другой примитив записи.

Подробно — в `pwn-canary-bypass`.

## Шаг 5. RELRO: защита GOT

**RELRO** управляет тем, можно ли писать в GOT:

| RELRO | GOT | Что доступно |
|---|---|---|
| No | writable, ленивый резолв | перезапись GOT |
| Partial | writable (частично) | перезапись GOT |
| Full | read-only | hooks, FSOP, `__exit_funcs` |

Full RELRO разрешает все символы на старте (`BIND_NOW`) и переводит GOT в read-only. **Обход:** `__free_hook`/`__malloc_hook` (до glibc 2.34), `_IO_2_1_stdout_`, `__exit_funcs`, `.fini_array`.

## Шаг 6. FORTIFY, CET и seccomp

**FORTIFY_SOURCE** заменяет опасные функции (`strcpy`, `sprintf`) на проверяющие версии (`__strcpy_chk`). Обход — найти функцию без проверки (например, `read`) или подобрать размер так, чтобы проверка не сработала. При `-O0` проверки часто отсутствуют вовсе.

**CET** (Intel Control-flow Enforcement) вводит shadow stack (проверяет `ret`) и IBT (проверяет косвенные переходы) — классический ROP ломается. Обход — JOP/COOP, подмена shadow stack. На большинстве CTF выключен.

**seccomp** — фильтр системных вызовов: может запретить `execve`, `open`, `fork`. Тогда `system` бесполезен. Проверяется так:

```bash
$ seccomp-tools dump ./chall
```

```text
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007
 ...
```

**Обход:** ORW (`open`/`read`/`write`), если разрешены; SROP, если гаджетов мало. Если `open` тоже запрещён, а флаг уже открыт в fd 3 — читай его через `read`/`sendfile`.

## Шаг 7. Комбинированные защиты

| Комбинация | Техника |
|---|---|
| NX only | ROP/ret2libc |
| NX + ASLR | утечка + ROP |
| NX + PIE + ASLR | two-stage leak |
| + canary | утечка canary |
| + Full RELRO | FSOP/hooks |
| + seccomp | ORW/SROP |
| + CET | JOP/COOP |

Митигации не абсолютны: каждая имеет обход, а их комбинация лишь **удлиняет цепочку**. Единственная защита без универсального userland-обхода — корректно настроенный CET, но он редок.

## Как митигации включаются

Понимание флагов помогает и при реверсе, и при подготовке окружения:

| Митигация | Включить | Отключить |
|---|---|---|
| Canary | `-fstack-protector-all` | `-fno-stack-protector` |
| NX | `-z noexecstack` | `-z execstack` |
| PIE | `-pie -fPIC` | `-no-pie` |
| Full RELRO | `-z relro -z now` | `-z norelro` |
| FORTIFY | `-D_FORTIFY_SOURCE=2` | без define |
| CET | `-fcf-protection=full` | `-fcf-protection=none` |

Для отладки удобно пересобрать бинарь с `-no-pie -fno-stack-protector -z execstack -z norelro`, отработать логику, а затем вернуть митигации и заняться их обходом.

## Продвинутые митигации: CFI, MTE, LAM

Помимо классических защит современные системы добавляют: **CFI** (Control Flow Integrity) — проверка легитимности косвенных вызовов и переходов; **MTE** (Memory Tagging Extension) на ARM64 — тегирование памяти, которое ловит UAF; **LAM** (Linear Address Masking) на x86 — маскирование адресов. CFI ограничивает набор целей для `call`/`jmp`, поэтому JOP/COOP становится сложнее. MTE делает heap-эксплуатацию значительно труднее: обращение по «устаревшему» указателю вызывает fault. На CTF эти митигации встречаются редко, но в реальных браузерах и мобильных ОС — постоянно.

## На что смотреть дальше

- **`checksec` может врать** при статической линковке — перепроверяй `readelf`.
- **Partial RELRO ≠ writable всё.** `.got.plt` writable, а `.got` может быть read-only.
- **FORTIFY зависит от оптимизации** — при `-O0` проверок нет.
- **seccomp может разрешать `openat`**, но не `open` — читай дамп внимательно.
- **ASLR можно выключить локально** (`echo 0 > /proc/sys/kernel/randomize_va_space`), но не на удалённой цели.

## Что мы теперь знаем

- `checksec` — первая команда; из неё строится план.
- NX → ROP; ASLR → утечка базы; PIE → утечка кода или partial overwrite.
- Canary → утечка или брутфорс на форкающем сервере.
- Full RELRO → цель не GOT, а hooks/FSOP/`.fini_array`.
- seccomp → ORW/SROP; CET → JOP/COOP.

## Квиз

Проверь себя.

```quiz
- question: "Почему младший байт stack canary всегда `\\x00`?"
  options:
    - "Для выравнивания"
    - "Чтобы строковые функции обрывались и не раскрывали canary"
    - "Это случайно"
    - "Так требует NX"
  answer: 1
  explanation: "Нулевой байт заставляет строковые функции останавливаться и не печатать канарейку."
- question: "Когда brute-force canary реалистичен?"
  options:
    - "Всегда"
    - "Когда сервер форкается на каждый коннект и canary общий"
    - "Только при No PIE"
    - "Только при Full RELRO"
  answer: 1
  explanation: "При fork канарейка не меняется между соединениями, её можно подобрать побайтово."
- question: "Что даёт partial overwrite при PIE?"
  options:
    - "Полный контроль над адресом"
    - "Смена младших 1–2 байт адреса возврата в пределах той же страницы"
    - "Обход NX"
    - "Отключение ASLR"
  answer: 1
  explanation: "Младшие байты не рандомизируются, поэтому их можно переписать без утечки."
- question: "Чем обходят NX?"
  options:
    - "Shellcode на стеке"
    - "ROP / ret2libc"
    - "Отключением ASLR"
    - "Canary"
  answer: 1
  explanation: "NX запрещает исполнять данные; ROP собирает код из существующих инструкций."
- question: "Что нужно при Full RELRO вместо перезаписи GOT?"
  options:
    - "Писать в GOT всё равно"
    - "Использовать FSOP / exit handlers / heap-структуры"
    - "Отключить RELRO"
    - "Shellcode"
  answer: 1
  explanation: "Full RELRO делает GOT read-only; цели смещаются на FSOP, хуки и exit-обработчики."
```

## Куда дальше

Мы разобрали карту защит. Дальше логично углубиться в каждую: `pwn-canary-bypass` (канарейка), `pwn-pie-bypass` (база кода), `pwn-seccomp-srop` (фильтр syscall). А пока главное: **каждая защита имеет обход, и `checksec` за минуту говорит, какой именно тебе понадобится.**

## Где пригодится

- **CTF Pwn:** checksec-«алфавит» и выбор техники обхода — обязательный навык.
- **Bug bounty:** оценка реальной эксплуатируемости memory corruption (есть ли leak, можно ли обойти canary).
- **Работа:** рекомендации по компиляции (`-fstack-protector-strong`, PIE, Full RELRO, CET) как меры защиты.
- **Исследования:** анализ современных эксплойтов, где комбинируются несколько обходов.
