---
id: stego-elf-notes
title: "ELF: overlay после конца файла и note-секции"
category: stego
parent: stego-module-binary-adv
difficulty: medium
order: 3
tags: [stego, elf, overlay, note-section, binary, readelf]
prerequisites: [stego-docker-layers]
useful_for:
  - "CTF Stego: бинарники и странный хвост"
  - "Форензика: данные в исполняемых уликах"
  - "Blue team: детект закладок в бинарниках"
estimated_minutes: 16
summary: "Структура ELF: заголовок, таблицы секций/сегментов, note-секции. Overlay после конца файла, произвольные note-записи, .comment и padding как каналы."
lab:
  kind: shell
  title: "Практика: overlay за концом ELF"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, bin, elf.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Магия ELF — `\x7fELF`."
    - "e_shoff — 8 байт по смещению 0x28 (64-бит)."
    - "`python3 elf.py` вычисляет конец и печатает overlay."
    - "`python3 elf.py | grep nto > found.txt`."
---

## Вопрос, с которого всё начинается
Бинарник ELF (Linux) — это заголовок, секции, сегменты. Ты запускаешь его,
работает. Но у ELF есть note-секции (`.note.*`) для произвольных «заметок»
(например, build-id), а также возможность **дописать данные после конца файла**
(overlay). Ни то, ни другое на работу не влияет — идеальное место для закладки.

## Наш пример
Возьмём `bin` — ELF-файл с данными, дописанными после последней секции. Найдём
overlay.

## Шаг 1: ELF-заголовок
Первые байты ELF:
- `7f 45 4c 46` — магия `\x7fELF`;
- класс (`01` = 32-bit, `02` = 64-bit);
- порядок байт (`01` = little-endian);
- версия;
- `e_shoff` (смещение таблицы секций), `e_shnum` (число секций),
  `e_shentsize` (размер записи) — в фиксированных смещениях.

Для 64-битного ELF: `e_shoff` — по смещению `0x28`, `e_shentsize` — `0x3a`,
`e_shnum` — `0x3c`.

## Шаг 2: overlay
«Конец ELF» — это максимум из конца таблицы секций (`e_shoff + e_shnum*e_shentsize`)
и конца таблицы сегментов. Всё, что лежит после, — overlay. Загрузчик его
игнорирует, но байты на месте. Простейшая закладка:

```python
import struct
d = open('bin','rb').read()
e_shoff = struct.unpack_from('<Q', d, 0x28)[0]
e_shnum = struct.unpack_from('<H', d, 0x3c)[0]
e_shentsize = struct.unpack_from('<H', d, 0x3a)[0]
end = e_shoff + e_shnum * e_shentsize
print(d[end:])
```

Вывод:

```
b'nto{elf_overlay_appended}\x00'
```

## Шаг 3: note-секции
Формат записи `.note`:
`[namesz(4)][descsz(4)][type(4)][name][desc][padding]`. Тип `NT_GNU_BUILD_ID`
(3) содержит build-id. Тип можно задать произвольный, а `desc` — произвольной
длины. `readelf -n bin` покажет заметки.

## Шаг 4: другие каналы в ELF
- **Секция `.comment`** — строки компилятора, легко дополнить.
- **Padding секций** — выравнивание до границы, туда помещаются данные.
- **Строковые таблицы** (`.strtab`, `.dynstr`) — строки, которые не используются.
- **Неиспользуемые символы** в таблице символов.
- **Заголовок** — поля `e_ident[7..15]` (padding) и зарезервированные байты.

## Шаг 5: инструменты
- `readelf -a bin` — заголовки, секции, заметки.
- `objdump -s -j .note.gnu.build-id bin` — содержимое заметки.
- `binwalk bin` — поиск встроенных/дописанных данных.
- `python3` + `struct` — ручной разбор.

## Что мы теперь знаем
- ELF: заголовок, таблицы секций/сегментов, секции, overlay.
- Overlay после конца ELF не влияет на работу, но хранит данные.
- Note-секции — штатное место для произвольных «заметок».
- `readelf` и `binwalk` — основные инструменты.

## Квиз

Проверь себя.

```quiz
- question: "Что такое overlay в ELF?"
  options:
    - "Данные, дописанные после конца ELF-структуры"
    - "Секция .text"
    - "Точка входа"
    - "Динамическая библиотека"
  answer: 0
  explanation: "Overlay лежит за пределами таблиц и игнорируется загрузчиком."
- question: "Как определить конец ELF-структуры?"
  options:
    - "Максимум из конца таблицы секций и таблицы сегментов"
    - "По размеру файла"
    - "По первой строке"
    - "По точке входа"
  answer: 0
  explanation: "Overlay начинается после последней легитимной структуры."
- question: "Что хранит note-секция?"
  options:
    - "Заметки вида namesz/descsz/type + name + desc"
    - "Исходный код"
    - "Пароли"
    - "Картинки"
  answer: 0
  explanation: "Например, NT_GNU_BUILD_ID — build-id."
- question: "Какая команда покажет заметки ELF?"
  options:
    - "readelf -n bin"
    - "ls -l bin"
    - "cat bin"
    - "file bin"
  answer: 0
  explanation: "readelf -n выводит содержимое note-секций."
```

## Куда дальше
ELF разобран. Родственный формат — Mach-O (macOS), где данные прячут в
load-командах LC_NOTE. О нём — в следующем уроке.

## Где пригодится
- **CTF:** задачи с бинарниками и «странным» хвостом.
- **Форензика:** поиск данных в исполняемых уликах.
- **Blue team:** детект закладок в бинарниках.
