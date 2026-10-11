---
id: reversing-file-formats
title: "Форматы исполняемых файлов: ELF, PE, Mach-O"
category: reversing
parent: reversing-asm
difficulty: easy
order: 1
tags: [reversing, elf, pe, macho, sections, segments, headers, lief]
prerequisites: [reversing-asm]
useful_for:
  - "CTF Reversing"
  - "Malware analysis"
  - "Анализ бинарников всех ОС"
estimated_minutes: 45
summary: "Устройство ELF/PE/Mach-O: заголовки, секции и сегменты, импорты, инструменты разбора."
---
Реверс начинается не с инструкций, а с **контейнера**: прежде чем разбирать код, нужно понять, как
устроен файл, где лежит код, данные, импорты, и что ищет загрузчик. Умение читать форматы
исполняемых файлов (PE, ELF, Mach-O) и разбирать **кастомные форматы данных** (сохранения, конфиги,
пакеты ресурсов) — базовый навык, без которого анализ упирается в стену. Этот урок — про структуру
основных форматов, инструменты их разбора и методологию вскрытия неизвестных форматов.

## Зачем понимать формат

Формат определяет **карту** бинарника:

- Где код (`.text`), где данные (`.data`/`.rodata`), где импорты и экспорты.
- Как загрузчик находит точку входа и релокации.
- Какие секции подозрительны (высокая энтропия → упаковка; нестандартные имена → packer).

Понимая формат, вы можете:
- быстро находить нужные функции через импорты/экспорты;
- замечать аномалии (манипуляции с заголовками — частый трюк malware);
- патчить файл (изменить точку входа, секцию, флаги).

## PE: Portable Executable (Windows)

Структура сверху вниз:

```text
DOS header (MZ) → e_lfanew → NT headers
  ├─ File header (Machine, NumberOfSections, ...)
  └─ Optional header (EntryPoint RVA, ImageBase, DataDirectories)
Section headers (.text .rdata .data .rsrc ...)
Sections (raw data)
```

Ключевые понятия:

- **RVA vs VA.** `RVA` — смещение от `ImageBase`; `VA = ImageBase + RVA`. В файле адреса хранятся
  как RVA, в памяти — как VA.
- **Import Address Table (IAT).** Список импортируемых функций; заполняется загрузчиком.
- **Export Table.** Экспортируемые функции (для DLL).
- **Data Directories.** 16 каталогов: Import, Export, Resource, Relocation, TLS, Debug и др.
- **TLS callbacks.** Код, выполняющийся до точки входа — популярное место для anti-debug/распаковки.

Инструменты:
```bash
rabin2 -I ./target.exe         # заголовки
rabin2 -i ./target.exe         # импорты
rabin2 -E ./target.exe         # экспорты
rabin2 -S ./target.exe         # секции + энтропия
objdump -x ./target.exe        # всё
pefile (python)                # скриптовый доступ
```

```python
import pefile
pe = pefile.PE("target.exe")
print("EP:", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
for s in pe.sections:
    print(s.Name.rstrip(b"\x00"), hex(s.VirtualAddress), hex(s.Misc_VirtualSize))
for imp in pe.DIRECTORY_ENTRY_IMPORT:
    print(imp.dll.decode(), [i.name for i in imp.imports if i.name])
```

## ELF: Executable and Linkable Format (Linux)

Структура:

```text
ELF header (e_ident, e_type, e_machine, e_entry, ...)
Program headers (сегменты, для загрузки в память)
Section headers (.text .data .rodata .got .plt .symtab ...)
Sections / Segments
```

Ключевые понятия:

- **Program headers** описывают **сегменты** (для рантайма), section headers — **секции** (для линковки/анализа).
- **`.got`/`.plt`** — механизм ленивого связывания (lazy binding): первый вызов внешней функции идёт
  через PLT-трамплин, который резолвит адрес через GOT. Это важно для реверса вызовов libc.
- **`e_entry`** — точка входа (обычно `_start`).
- **Динамические символы** — `.dynsym`/`.dynstr` (импорт/экспорт), `.symtab` (может быть удалён strip'ом).
- **Relocations** — `.rela.dyn`, `.rela.plt`.

Инструменты:
```bash
readelf -h ./target            # заголовок
readelf -l ./target            # program headers (сегменты)
readelf -S ./target            # секции
readelf -s ./target            # символы
readelf -d ./target            # динамические записи
readelf -r ./target            # релокации
objdump -d -M intel ./target   # дизассемблер
rabin2 -I ./target             # сводка
nm -D ./target                 # динамические символы
```

## Mach-O: формат macOS/iOS

Структура: **Mach-O header → load commands → segments (__TEXT, __DATA, __LINKEDIT)**. Отличия:

- **Fat/Universal binary** — несколько архитектур в одном файле (`lipo`).
- **Load commands** — вместо секций таблица команд (`LC_SEGMENT_64`, `LC_SYMTAB`, `LC_DYLD_INFO`).
- **Символы** обрабатываются через dyld shared cache (для системных библиотек).

Инструменты:
```bash
otool -h ./target        # заголовок
otool -l ./target        # load commands
otool -L ./target        # линкованные библиотеки
lipo -info ./target      # архитектуры
nm -m ./target           # символы
jtool2 -l ./target       # расширенный просмотр
```

## Сравнительная таблица форматов

| Понятие | PE | ELF | Mach-O |
|---|---|---|---|
| Заголовок | DOS + NT | ELF header | Mach header |
| Единица загрузки | секции | сегменты | segments |
| Точка входа | `AddressOfEntryPoint` | `e_entry` | `LC_MAIN` |
| Импорты | IAT | `.got`/`.plt` | `LC_DYLD_INFO` |
| Экспорты | Export Table | `.dynsym` | `LC_SYMTAB` |
| Релокации | `.reloc` | `.rela.*` | `LC_DYLD_INFO` |
| Инструмент | pefile/rabin2 | readelf/rabin2 | otool/jtool2 |

## Разобранный пример: разбор PE-структуры скриптом

Дано: `suspect.exe`. Нужно понять, куда указывает точка входа и какие секции подозрительны.

```python
import pefile, math
pe = pefile.PE("suspect.exe")
ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
print("EntryPoint RVA:", hex(ep))
for s in pe.sections:
    name = s.Name.rstrip(b"\x00").decode(errors="replace")
    data = s.get_data()
    if data:
        from collections import Counter
        c = Counter(data); n = len(data)
        ent = -sum((v/n)*math.log2(v/n) for v in c.values())
    else:
        ent = 0
    print(f"{name:8s} RVA={s.VirtualAddress:#x} size={s.Misc_VirtualSize:#x} ent={ent:.2f}")
```

Ожидаемый вывод для упакованного файла:
```text
EntryPoint RVA: 0x1a000
UPX0     RVA=0x1000  size=0x2f000 ent=0.00
UPX1     RVA=0x30000 size=0xa000  ent=7.94
.rsrc    RVA=0x3a000 size=0x1000  ent=3.12
```

Вывод: секция `UPX1` с энтропией 7.94 — сжатый код; `UPX0` пустая (заполняется при распаковке);
точка входа в `UPX1`. Файл упакован — переходим к распаковке.

## Разобранный пример: кастомный формат данных

Дано: игра хранит сохранение в `save.dat`, файл бинарный. Нужно понять структуру.

**Шаг 1. Первый взгляд.**
```bash
file save.dat
xxd save.dat | head -20
```
```text
00000000: 5341 5645 0100 0000 0c00 0000 0000 0000  SAVE............
00000010: 4865 726f 0000 0000 0000 0000 0000 0000  Hero............
```
Видим magic `SAVE`, версию `01 00 00 00`, затем `0c 00 00 00` (вероятно, длина или счётчик),
затем ASCII `Hero`.

**Шаг 2. Гипотеза структуры.**
```c
struct save {
    char magic[4];      // "SAVE"
    uint32_t version;   // 1
    uint32_t name_len;  // 12
    char name[];        // "Hero"
    ...
};
```

**Шаг 3. Проверка через hex-анализ.** Ищем повторяющиеся поля, паттерны длин (следующая строка
начинается через `name_len` байт), проверяем little-endian.

**Шаг 4. Скрипт-парсер.**
```python
import struct
data = open("save.dat","rb").read()
off = 0
magic, ver, name_len = struct.unpack_from("<4sII", data, off); off += 12
name = data[off:off+name_len]; off += name_len
print(magic, ver, name_len, name)
```
Дальше расширяем структуру по мере распознавания полей.

**Шаг 5. Автоматизация.** Инструменты `kaitai` (DSL для форматов), `010 Editor` (шаблоны),
`binwalk`/`foremost` (поиск вложенных форматов).

## Инструменты для неизвестных форматов

| Инструмент | Назначение |
|---|---|
| `binwalk` / `foremost` | поиск вложенных форматов, carve |
| `xxd` / `hexdump` | hex-просмотр |
| `Kaitai Struct` | декларативное описание формата |
| `010 Editor` | шаблоны (BT) для форматов |
| `file` / `magic` | определение типа |
| `strings -a -e l` | строки (UTF-16 для Windows) |
| `rabin2`/`pefile`/`lief` | парсинг исполняемых |
| `HxD` | ручной hex-редактор |

## Крайние случаи и подводные камни

- **Не доверяйте заголовкам.** Malware часто правит `e_lfanew`, `NumberOfSections`, размеры секций,
  чтобы сбить парсеры. Сверяйте несколько источников (rabin2 + objdump + pefile).
- **Strip'нутые бинарники.** В ELF нет `.symtab` — опирайтесь на `.dynsym`, строки, PLT.
- **Packed/custom sections.** Секция может называться как угодно (`.vmp0`, `.tElock`), а её
  содержимое — шифроваться.
- **Overlay (PE).** Данные после последней секции — популярное место для полезной нагрузки/архивов.
  Проверяйте `binwalk` на оверлей.
- **Endianness.** В кастомных форматах порядок байт может быть big-endian — не полагайтесь на x86-привычку.
- **Сжатие внутри формата.** Поле может быть zlib/gzip-блоком — ищите `78 9c`, `1f 8b` и т.п.
- **Выравнивание.** Секции/поля выравниваются (PE — `FileAlignment`/`SectionAlignment`), учитывайте
  это при ручном парсинге.
- **Anti-forensics.** Заголовки могут быть зашифрованы до распаковки — сначала снять packer.

## Что дальше / решение

1. Определить формат: `file`, magic, первые байты (`MZ`, `\x7fELF`, `\xcf\xfa\xed\xfe`).
2. Разобрать заголовки инструментами (`rabin2`, `readelf`, `pefile`, `otool`).
3. Найти код (entry point, секции с кодом), импорты/экспорты, строки.
4. Проверить энтропию и нестандартные секции — нет ли упаковки.
5. Для кастомных данных — гипотеза структуры → hex-анализ → парсер-скрипт → Kaitai.
6. Проверить overlay и вложенные форматы.

Приём: **формат — это карта**. Потратив 10 минут на её чтение, вы экономите часы блуждания по коду.

## Справочная таблица: что искать в заголовках

| Признак | Значение | Что означает |
|---|---|---|
| `MZ` | PE | Windows-исполняемый |
| `\x7fELF` | ELF | Linux/Unix |
| `\xcf\xfa\xed\xfe` | Mach-O 64 LE | macOS/iOS |
| Высокая энтропия секции | >7.0 | сжатие/шифрование |
| Секции `UPX0/1`, `.vmp*` | packer | нужно распаковать |
| Overlay данные | после секций | вложенный архив/пейлоад |
| Пустой `.text` | аномалия | код в другой секции |
| TLS callbacks | anti-debug | выполняется до entry |

## Квиз

```quiz
- question: "Чем сегмент отличается от секции в ELF?"
  options:
    - "Сегмент — это данные, секция — это код"
    - "Сегмент используется загрузчиком (отображение в память), секция — линкером/аналитиком"
    - "Сегменты бывают только в PE"
    - "Это синонимы"
  answer: 1
- question: "Какая команда покажет таблицу импортируемых функций PE-файла через LIEF?"
  options:
    - "`readelf -d target.exe`"
    - "`otool -L target.exe`"
    - "`python3 -c "import lief; print(lief.parse('target.exe').imports)"`"
    - "`nm target.exe`"
  answer: 2
- question: "Что означает `ET_DYN` в `readelf -h`?"
  options:
    - "Объектный файл `.o`"
    - "Позиционно-независимый код (PIE) или разделяемая библиотека"
    - "Core-дамп"
    - "Статически слинкованный бинарник с фиксированными адресами"
  answer: 1
- question: "Почему код может быть невидим для `objdump -d`?"
  options:
    - "Он лежит в исполняемом сегменте без соответствующей `.text`-секции"
    - "objdump не поддерживает x86-64"
    - "objdump показывает только данные"
    - "Он зашифрован UPX"
  answer: 0
- question: "Какой заголовок является первым в PE-файле?"
  options:
    - "PE header (`PE\0\0`)"
    - "DOS header (`MZ`)"
    - "COFF header"
    - "ELF header"
  answer: 1
```

## Где пригодится

- **CTF Reversing:** быстрая навигация по бинарнику, поиск скрытых сегментов и нестандартных структур.
- **Malware analysis:** определение упаковщика, анализ секций (энтропия, подозрительные имена), извлечение ресурсов.
- **Vuln research:** поиск кода в нестандартных сегментах прошивок и патчей.
- **Работа (RE-команда):** автоматизация разбора через LIEF/pefile в пайплайнах.
- **Собес:** вопросы про ELF-заголовок, PLT/GOT, различия ELF/PE — база RE-интервью.
