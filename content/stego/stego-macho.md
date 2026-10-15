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

## Полный разбор Mach-O

Mach-O начинается с заголовка `mach_header_64` (magic `0xFEEDFACF` для 64-бит LE, `0xCFFAEDFE` для BE). В заголовке — `cputype`, `cpusubtype`, `filetype`, `ncmds` (число load-команд), `sizeofcmds`. Сразу после заголовка идут **load-команды** — структуры, описывающие сегменты, символы, компоновку.

```bash
otool -h bin                 # заголовок
otool -l bin | head -80      # load-команды
jtool2 -l bin                # альтернатива
```

Каждая load-команда имеет `cmd` и `cmdsize`. Основные: `LC_SEGMENT_64` (сегмент с секциями), `LC_SYMTAB` (таблица символов), `LC_DYSYMTAB`, `LC_LOAD_DYLIB` (зависимости), `LC_UUID`, `LC_CODE_SIGNATURE`, и `LC_NOTE` (произвольная заметка). Разбор ведут, перебирая команды и проверяя, что сумма `cmdsize` не превышает `sizeofcmds` — расхождение означает лишние/поддельные команды.

Каналы сокрытия: данные в padding между секциями, данные после конца последнего сегмента (overlay), нестандартные `LC_NOTE` с произвольным содержимым, данные в неиспользуемых секциях (`__TEXT,__const` с лишним содержимым), строки в таблице символов, на которые нет ссылок.

## LC_NOTE и другие каналы

`LC_NOTE` — load-команда, изначально предназначенная для прикрепления произвольных заметок к бинарю (используется отладчиками). Формат: `data_owner` (16 байт — идентификатор владельца), `offset`, `size`. Владелец может быть произвольной строкой, а данные — произвольными. Это прямой аналог ELF-заметок и очевидный канал стего.

```bash
otool -l bin | grep -A4 LC_NOTE
xxd -s <offset> -l <size> bin
```

Другие каналы Mach-O: **__TEXT,__cstring** (строковые константы) — лишние строки; **__DATA,__data** — неиспользуемые данные; **code signature** — область подписи, иногда с padding; **fat binary** (universal) — несколько архитектур в одном файле, и неиспользуемая архитектура может нести данные; **overlay** — байты после конца последнего сегмента.

Отдельно — **fat/universal binaries**: заголовок `0xCAFEBABE`, таблица архитектур (смещения и размеры каждой). Если в таблице есть запись с нулевым/странным размером или смещение за пределы файла — там канал. Разбирают `lipo -info`, `otool -f`.

## Инструменты и практика

Инструменты: `otool` (заголовок, load-команды, дизассемблер), `jtool2`/`jtool` (мощнее, показывает больше), `lipo` (fat binaries), `codesign` (подпись), `nm` (символы), `strings`, `binwalk` (вложенное/overlay), `xxd` (байты). Для ручного разбора — `python3` + `struct` (структуры Mach-O описаны в `<mach-o/loader.h>`).

```bash
file bin && otool -hv bin
lipo -info bin
nm -m bin | head
binwalk bin
```

Порядок разбора: заголовок → load-команды (проверка сумм) → сегменты/секции → overlay → заметки → таблица символов → fat-таблица. Аномалия размера/смещения на любом уровне — сигнал.

Практический вывод: Mach-O концептуально близок ELF, но load-команды заменяют program headers, а `LC_NOTE` — аналог note-секций. Освоив ELF, ты быстро читаешь Mach-O; разница в деталях структур, но подход «сверху вниз с поиском аномалий» работает и здесь.

## Практика: разбор fat binary

Universal (fat) binary содержит несколько архитектур. Заголовок — `0xCAFEBABE` (big-endian), затем число архитектур и таблица записей: `cputype`, `cpusubtype`, `offset`, `size`, `align`.

```bash
lipo -info bin
python3 - <<PY
import struct
d = open("bin","rb").read()
if d[:4] == b"\xca\xfe\xba\xbe":
    n = struct.unpack_from(">I", d, 4)[0]
    for i in range(n):
        cputype, cpusub, off, size, al = struct.unpack_from(">iiIII", d, 8+i*20)
        print(hex(cputype), "off", hex(off), "size", size)
PY
```

Если `offset+size` выходит за пределы файла или размер аномален — канал. Каждую архитектуру можно вырезать (`lipo -thin`) и разбирать отдельно; неиспользуемая архитектура иногда несёт данные.

## Итог по Mach-O

Mach-O: заголовок + load-команды (аналог program headers) + сегменты/секции. Каналы: overlay, `LC_NOTE`, padding, неиспользуемые секции/символы, fat-таблица. Инструменты: `otool`, `jtool2`, `lipo`, `nm`, `binwalk`. Подход тот же, что для ELF: сверху вниз, с поиском аномалий размеров.

## Расширенный разбор: где искать в Mach-O

Помимо `LC_NOTE`, в Mach-O есть несколько мест для данных. Первый — **overlay** (байты после последнего сегмента). Второй — **padding** между секциями (выравнивание). Третий — **неиспользуемые секции**: `__TEXT,__cstring` (строковые константы) может содержать лишние строки, `__DATA,__data` — лишние данные.

Четвёртый — **таблица символов** (`LC_SYMTAB`): символы, на которые никто не ссылается. Пятый — **строка идентификатора** (`LC_UUID`): 16 байт, обычно уникальный, но можно подменить/использовать. Шестой — **code signature** (`LC_CODE_SIGNATURE`): область подписи, иногда с padding, куда можно дописать данные (но подпись сломается).

Седьмой — **fat/universal binary**: неиспользуемая архитектура целиком. Восьмой — **load-команды с нестандартными `cmdsize`** или лишними записями. Девятый — **версии и флаги** в заголовке (редко, но бывает).

```bash
otool -l bin | grep -E "LC_|segname|sectname|size"
nm -m bin | wc -l
binwalk bin
```

Порядок разбора: заголовок → сумма `cmdsize` против `sizeofcmds` (аномалия = лишние команды) → сегменты/секции (границы и padding) → overlay → заметки → символы → fat-таблица. Инструменты: `otool`, `jtool2`, `lipo`, `nm`, `codesign`, `binwalk`, `python3`+`struct`.

## Итог по Mach-O

Mach-O концептуально близок ELF: заголовок, структуры-описатели (load-команды вместо program headers), сегменты/секции, overlay. Каналы сокрытия те же: overlay, заметки (`LC_NOTE`), padding, неиспользуемые секции/символы, fat-таблица. Инструменты — `otool`/`jtool2`/`lipo`. Подход «сверху вниз с поиском аномалий размеров» работает для всех бинарных контейнеров.

## Дополнительные приёмы разбора Mach-O

Есть несколько тонкостей. Первая — **dylib-ссылки** (`LC_LOAD_DYLIB`): список зависимостей, среди которых может быть нестандартная (например, путь к файлу, содержащему данные в имени). Вторая — **rpaths** (`LC_RPATH`): пути поиска библиотек, тоже могут нести данные. Третья — **функциональные флаги** в заголовке (`flags`): нестандартные комбинации.

Четвёртая — **секция `__LINKEDIT`**: служебные данные (символы, строки, подпись), которые могут содержать лишнее. Пятая — **отладочные секции** (`__DWARF`): отладочная информация часто остаётся в бинарях и содержит пути, имена, а иногда и вставленные данные.

Шестая — **LC_FUNCTION_STARTS** и подобные таблицы: массивы смещений, куда можно дописать значения. Седьмая — **LC_DATA_IN_CODE**: описатели данных внутри кода, тоже расширяемы.

```bash
otool -L bin
otool -l bin | grep -A2 LC_RPATH
size -m bin
```

Практика: сравни сумму `cmdsize` всех load-команд с `sizeofcmds` из заголовка; аномалия означает лишние команды. Проверь границы каждого сегмента и наличие overlay. Инструменты: `otool`, `jtool2`, `nm`, `size`, `codesign`, `binwalk`.

## Резюме по Mach-O

Mach-O: заголовок, load-команды, сегменты/секции, overlay. Каналы: overlay, `LC_NOTE`, padding, неиспользуемые секции/символы, fat-таблица, отладочные секции. Инструменты: `otool`, `jtool2`, `lipo`, `nm`, `binwalk`.

## Финальные замечания по Mach-O

Mach-O близок ELF, но load-команды играют роль program headers, а `LC_NOTE` — note-секций. Каналы те же: overlay, заметки, padding, неиспользуемые секции/символы, fat-таблица. Инструменты — `otool`, `jtool2`, `lipo`, `nm`, `binwalk`. Подход «сверху вниз с поиском аномалий размеров» работает и здесь.

## Ещё раз о fat-бинарниках

Universal (fat) binary — контейнер с несколькими архитектурами. Заголовок `0xCAFEBABE`, таблица `[cputype, cpusubtype, offset, size, align]`. Проверь, что `offset+size` каждого среза внутри файла; аномалия — канал. Вырежи нужную архитектуру `lipo -thin` и разбирай отдельно; неиспользуемый срез может нести данные.

## Что мы теперь знаем
- Mach-O: заголовок (magic 0xfeedfacf) и цепочка load-команд.
- `LC_NOTE` хранит произвольную заметку с владельцем, offset и size.
- Padding команд, строковые сегменты и fat-padding — дополнительные каналы.
- `otool -l` — основной инструмент разбора.

## Практика: разбор Mach-O через otool и Python

Структуру удобно смотреть `otool`/`llvm-otool`, а нестандартные сегменты — скриптом:

```
$ otool -l binary | grep -A3 LC_SEGMENT | head
Load command 0
      cmd LC_SEGMENT_64
  cmdsize 72
  segname __TEXT
$ python3 - <<'EOF'
import struct
d = open('binary','rb').read()
magic = d[:4]
print('magic', magic.hex())          # cffaedfe = 64-bit LE
# число load-команд и их размер
ncmds, sizeofcmds = struct.unpack_from('<II', d, 16)
print('ncmds', ncmds, 'sizeofcmds', sizeofcmds)
off = 32
for _ in range(ncmds):
    cmd, size = struct.unpack_from('<II', d, off)
    print(hex(cmd), size)
    off += size
EOF
magic cffaedfe
ncmds 16 sizeofcmds 1456
0x19 72
0x2 24
```

Неизвестные `cmd` (не из стандартного списка) и «лишние» байты между командами — повод
копнуть.

## Практика: LC_NOTE и fat binary

`LC_NOTE` (`0x31`) официально хранит произвольные заметки (используется отладчиками), но
может нести и данные:

```
$ python3 - <<'EOF'
d = open('binary','rb').read()
i = d.find(b'LC_NOTE')
print('found at', i, d[i:i+64])
EOF
found at 4821 b'LC_NOTE...nto{macho_note}...'
```

Fat binary — это «контейнер» из нескольких Mach-O (x86_64 + arm64). Каждый срез надо
разбирать отдельно:

```
$ lipo -info binary
Architectures in the fat file: binary are: x86_64 arm64
$ lipo -thin arm64 binary -output arm64.bin
```

Данные можно спрятать только в одном срезе — второй будет выглядеть чисто.

## Если не сработало

- **`otool` не установлен.** На Linux используйте `llvm-objdump`/`llvm-readobj` или
  `MachOView` на macOS.
- **Секция «padding» пуста.** Проверьте все срезы fat-файла и trailing-данные после последней
  секции.
- **Файл подписан.** Подпись может покрывать не всё тело; проверьте `codesign -dvvv` и
  области, не входящие в хеш подписи.

## Ограничение: подпись и нотаризация

Современный macOS проверяет подпись и нотаризацию. Изменённый Mach-O не запустится без
снятия защиты (`codesign --remove-signature`), поэтому в реальных атаках данные прячут в
частях, не входящих в подпись, — их и надо искать в первую очередь.

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
