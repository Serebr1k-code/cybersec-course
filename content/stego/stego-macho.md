---
id: stego-macho
title: "Mach-O: load-команды, LC_NOTE и padding"
category: stego
parent: stego-module-binary-adv
difficulty: medium
order: 4
tags: [stego, macho, macos, lc-note, load-command, binary]
prerequisites: [stego-elf-notes]
useful_for:
  - "CTF Stego: macOS-бинарники"
  - "Форензика: анализ Mach-O улик"
  - "Blue team: закладки в подписанных бинарниках"
estimated_minutes: 16
summary: "Структура Mach-O: заголовок (magic 0xfeedfacf) и цепочка load-команд. LC_NOTE с произвольной заметкой, padding команд, строковые сегменты и fat-binary как носители."
lab:
  kind: shell
  title: "Практика: разбор LC_NOTE"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, macho, macho.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Magic 64-битного Mach-O — 0xfeedfacf."
    - "ncmds — по смещению 0x10, команды начинаются с 0x20."
    - "`python3 macho.py` идёт по командам и печатает данные LC_NOTE."
    - "`python3 macho.py | grep nto > found.txt`."
---

## Вопрос, с которого всё начинается
Mach-O — формат исполняемых файлов macOS. Внутри — заголовок и цепочка
**load-команд**: сегменты, символы, подпись. Среди них есть `LC_NOTE` — команда
для произвольной «заметки» (её использует, например, отладчик). Данные в ней
могут быть любыми, и система их не проверяет. Ты получил Mach-O с `LC_NOTE` —
как достать содержимое?

## Наш пример
Возьмём `macho` — 64-битный Mach-O с одной командой `LC_NOTE`. Разберём
заголовок и пройдём по load-командам.

## Шаг 1: заголовок Mach-O
Первые 32 байта 64-битного Mach-O (`mach_header_64`):
- `magic` — `0xfeedfacf` (little-endian);
- `cputype`, `cpusubtype`;
- `filetype`;
- `ncmds` — число load-команд;
- `sizeofcmds` — суммарный размер;
- `flags`, `reserved`.

Всё little-endian. После заголовка (смещение 32) начинается первая load-команда.

## Шаг 2: разбор load-команд
Каждая команда: `[cmd(4)][cmdsize(4)][тело]`. Команды выровнены по 4/8 байт.
Интересующие нас:
- `LC_SEGMENT_64` (0x19) — сегменты `__TEXT`, `__DATA`;
- `LC_SYMTAB` (0x02) — таблица символов;
- `LC_CODE_SIGNATURE` (0x1d) — подпись;
- `LC_NOTE` (0x31) — заметка: `data_owner[16]`, `offset(8)`, `size(8)`.

## Шаг 3: LC_NOTE
Структура `note_command`:
`[cmd=0x31(4)][cmdsize=40(4)][data_owner(16)][offset(8)][size(8)]`.
`data_owner` — строка владельца, `offset` — смещение данных в файле, `size` —
длина. Данные — произвольные.

```python
import struct
d = open('macho','rb').read()
ncmds = struct.unpack_from('<I', d, 0x10)[0]
p = 0x20
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from('<II', d, p)
    if cmd == 0x31:
        owner = d[p+8:p+24].split(b'\x00')[0].decode()
        off, size = struct.unpack_from('<QQ', d, p+24)
        print(owner, d[off:off+size].decode())
    p += cmdsize
```

Вывод:

```
stego nto{macho_lc_note}
```

## Шаг 4: где ещё прячут данные в Mach-O
- **`LC_NOTE`** — штатная произвольная заметка.
- **Padding load-команд** — выравнивание создаёт свободные байты.
- **`__cstring`/`__const`** — строковые сегменты, неиспользуемые строки.
- **Fat/universal binary** — несколько архитектур в одном файле, между ними
  padding.
- **Code signature** — данные подписи (её можно не проверять).

## Шаг 5: инструменты
- `otool -l macho` — список load-команд.
- `otool -h macho` — заголовок.
- `lipo -info macho` — архитектуры fat-файла.
- `nm`, `strings`, `binwalk` — вспомогательно.

## Что мы теперь знаем
- Mach-O: заголовок (magic 0xfeedfacf) и цепочка load-команд.
- `LC_NOTE` хранит произвольную заметку с владельцем, offset и size.
- Padding команд, строковые сегменты и fat-padding — дополнительные каналы.
- `otool -l` — основной инструмент разбора.

## Квиз

Проверь себя.

```quiz
- question: "Как называется структура, идущая после заголовка Mach-O?"
  options:
    - "Load-команды (сегменты, символы, подпись)"
    - "Секции ELF"
    - "Чанки PNG"
    - "Записи tar"
  answer: 0
  explanation: "Заголовок + цепочка load-команд — основа Mach-O."
- question: "Что хранит LC_NOTE?"
  options:
    - "Владельца, offset и size произвольной заметки"
    - "Пароль"
    - "Исходный код"
    - "Сжатую картинку"
  answer: 0
  explanation: "note_command: data_owner[16], offset, size."
- question: "Какова магия 64-битного Mach-O (little-endian)?"
  options:
    - "0xfeedfacf"
    - "0x7f454c46"
    - "0x89504e47"
    - "0x504b0304"
  answer: 0
  explanation: "mach_header_64 magic = 0xfeedfacf."
- question: "Какая команда выведет load-команды?"
  options:
    - "otool -l macho"
    - "readelf -a macho"
    - "objdump -d macho"
    - "file macho"
  answer: 0
  explanation: "otool -l печатает load-команды Mach-O."
```

## Куда дальше
Бинарные форматы разобраны. Дальше — инструментальные приёмы: CyberChef, binwalk
и decision-tree для CTF. А пока запомни: в любом контейнере есть «служебное»
поле, которое никто не проверяет.

## Где пригодится
- **CTF:** задачи с macOS-бинарниками.
- **Форензика:** анализ Mach-O улик.
- **Blue team:** закладки в подписанных бинарниках.
