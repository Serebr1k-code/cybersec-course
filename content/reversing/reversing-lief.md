---
id: reversing-lief
title: "Программный патчинг ELF/PE: LIEF"
category: reversing
parent: reversing-patching
difficulty: medium
order: 1
tags: [reversing, lief, patching, elf, pe, macho, scripting]
prerequisites: [reversing-patching, reversing-file-formats]
useful_for:
  - "CTF Reversing"
  - "Automation / tooling"
  - "Malware research"
estimated_minutes: 55
summary: "LIEF для программного разбора и модификации ELF/PE/Mach-O: секции, импорты, патч кода, инъекция."
---
LIEF (Library to Instrument Executable Formats) — библиотека с Python- и C++-интерфейсом для разбора и **модификации** исполняемых форматов: ELF, PE, Mach-O, а также DEX/OAT/ART и архивов. Там, где нужно программно (а не руками в hex-редакторе) поправить байты, добавить секцию, переписать импорты или восстановить символы, LIEF незаменим. Он лежит в основе многих инструментов автоматического патчинга и распаковки. В этом уроке — установка, разбор всех ключевых структур и рабочие скрипты патчинга ELF/PE.

## Зачем LIEF и чем он отличается от readelf/objdump

Утилиты `readelf`, `objdump`, `pefile`, `nm` умеют читать метаданные, но не предназначены для **пересборки** файла. LIEF умеет и то и другое: разобрать файл в объектную модель, изменить её и записать обратно корректный бинарь. Это позволяет автоматизировать то, что обычно делают вручную: заменить строку, пропатчить проверку, добавить импорт, поменять точку входа, вставить новую секцию с кодом. LIEF работает с ELF, PE, Mach-O единообразным API, что удобно для кросс-платформенных скриптов.

## Установка и базовый разбор

```bash
pip install lief
python3 -c "import lief; print(lief.__version__)"
```

Базовый разбор ELF:

```python
import lief
b = lief.parse("/bin/ls")
print(b.header.machine_type)        # ARCH.X86_64
print(b.entrypoint, hex(b.entrypoint))
for s in b.sections:
    print(f"{s.name:20} va={s.virtual_address:#x} size={s.size:#x}")
for imp in b.imported_functions[:5]:
    print(imp)
```

Для PE API почти идентичен: `lief.parse("sample.exe")`, `b.header.machine`, `b.sections`, `b.imports`, `b.exported_functions`. У Mach-O — `b.header.cpu_type`, `b.segments`. Флаг `lief.parse(path, config)` позволяет включить `parse_imports`, `parse_relocations`, `parse_resources` и другие опции, влияющие на полноту разбора и скорость.

## Работа с секциями и сегментами

Секции можно перечислять, читать их содержимое и модифицировать:

```python
import lief
b = lief.parse("crackme")
text = b.get_section(".text")
data = bytes(text.content)
print(len(data), data[:16].hex())
text.content = list(data)          # присвоение нового содержимого
b.write("crackme_patched")
```

Добавление секции в ELF:

```python
seg = lief.ELF.Segment()
seg.type = lief.ELF.SEGMENT_TYPES.LOAD
seg.flags = lief.ELF.SEGMENT_FLAGS.R | lief.ELF.SEGMENT_FLAGS.X
sec = lief.ELF.Section(".mycode")
sec.content = list(b"\x90" * 16)
sec.flags = lief.ELF.SECTION_FLAGS.ALLOC | lief.ELF.SECTION_FLAGS.EXECINSTR
b.add(sec, loaded=True)            # loaded=True — привязать к сегменту
b.write("out.elf")
```

В PE аналогично работают `b.add_section(lief.PE.Section(".new"))`, `b.remove_section(name)`, а `b.sections` даёт доступ к `virtual_address`, `sizeof_raw_data`, `characteristics`.

## Патчинг кода: обход проверки

Классический сценарий CTF — заменить условный переход. Находим смещение инструкции (через Ghidra/objdump) и патчим байты:

```python
import lief
b = lief.parse("checker")
off = 0x1234
b.patch_address(off, [0x90, 0x90])          # NOP два байта
b.write("checker_nop")
```

Для PE `patch_address` принимает виртуальный адрес (RVA). Чтобы заменить `jne` на `je`, меняют один байт: `b.patch_address(off, [0x74])`. Если нужно вставить больше кода, чем есть места, патчат по секции `.text` и сдвигают целевую функцию, либо используют code cave (пустое место в секции) и прыжок туда.

## Импорты, экспорты и символы

LIEF позволяет добавлять и удалять импорты, что полезно для инъекции вызовов:

```python
import lief
b = lief.parse("target")
b.add_library("libc.so.6")
b.add_import("system")               # ELF
b.write("target_mod")
```

Для PE добавление импорта:

```python
import lief
b = lief.parse("app.exe")
b.add_library("user32.dll")
b.add_import("MessageBoxA", ["user32.dll"])
```

Экспорты перечисляются через `b.exported_functions` (имена), `b.exported_symbols` (объекты). Символы можно переименовывать (`sym.name = "new_name"`) — удобно для восстановления читаемых имён после стрипа, если известна таблица. `b.symbols` даёт все символы ELF, включая динамические.

## Восстановление символов и работа со стрипнутыми бинарями

После `strip` остаются `.dynsym` (динамические символы) и, для Go/Rust, встроенные таблицы. LIEF не восстанавливает имена магически, но позволяет **добавить** символы обратно:

```python
import lief
b = lief.parse("stripped")
sym = lief.ELF.Symbol()
sym.name = "my_function"
sym.value = 0x1149
sym.type = lief.ELF.SYMBOL_TYPES.FUNC
b.add_dynamic_symbol(sym)         # добавить в .dynsym
b.write("with_syms")
```

Это удобно, когда вы разметили функции вручную или через FLIRT-сигнатуры и хотите сохранить результат в бинаре, чтобы дальше работать в других инструментах.

## Модификация PE: точка входа, TLS, ресуры

PE-специфика включает работу с точкой входа, каталогами и ресурсами:

```python
import lief
b = lief.parse("sample.exe")
b.optional_header.addressof_entrypoint = 0x1500     # новая точка входа
print(b.has_tls, b.tls)
b.write("sample_mod.exe")
```

Ресурсы доступны через `b.resources_manager` (итерация `b.resources`), их можно заменять иконки/манифесты. Каталоги данных (`b.data_directories`) показывают RVA/размеры каталогов импорта, экспорта, релокаций, TLS и т.д.

## Проверка результата и целостность

После любой записи обязательно проверяйте, что файл остался валидным и исполняемым:

```bash
file out.elf
readelf -h out.elf
chmod +x out.elf && ./out.elf
```

LIEF имеет встроенную проверку: `lief.is_elf(path)`, `lief.is_pe(path)`, а также `b.write()` вернёт `OK`/`NOT_FOUND`/`ERROR`. Для PE поле контрольной суммы (`optional_header.checksum`) LIEF пересчитывает автоматически. Для ELF убедитесь, что изменённые секции попали в `LOAD`-сегмент, иначе изменения не отобразятся в памяти и бинарь упадёт.

## Полный разбор: патч лицензионной проверки

**Шаг 1 — найти проверку.** В Ghidra находим функцию, возвращающую `0/1`, и адрес условного перехода. **Шаг 2 — записать исходные байты** (чтобы иметь возможность отката). **Шаг 3 — пропатчить:**

```python
import lief
b = lief.parse("licensed")
va = 0x4011a7
b.patch_address(va, [0x90, 0x90, 0x90, 0x90, 0x90, 0x90])  # NOP jz
b.write("licensed_patched")
print("patched at", hex(va))
```

**Шаг 4 — проверить:** запустить, убедиться, что проверка больше не срабатывает. Если бинарь проверяет свою целостность (см. anti-tamper), простой патч вызовет срабатывание защиты — тогда правят саму функцию проверки или её вызывающего.

## Ограничения и подводные камни

- **Пересборка сложных форматов:** добавление секций может сломать выравнивание; проверяйте `readelf`/запуск.
- **Релокации:** при вставке кода в ELF учитывайте, что PIE-бинарь требует релокаций; `patch_address` работает по RVA, а не по файловому смещению.
- **Порядок байт:** `content` — список байт, а не строка; используйте `list(b"...")`.
- **Анти-тампер:** хеш-проверки кода обнаружат патч; патчить нужно и проверку.
- **Версии API:** LIEF меняет API между мажорными версиями; проверяйте документацию под свою версию.

## Шпаргалка по LIEF

| Задача | Код |
|---|---|
| Разобрать файл | `lief.parse(path)` |
| Тип формата | `lief.is_elf/is_pe/is_macho(path)` |
| Секция | `b.get_section(".text")` |
| Патч байтов | `b.patch_address(va, [..])` |
| Запись | `b.write("out")` |
| Добавить секцию | `b.add(sec)` / `b.add_section(sec)` |
| Добавить импорт | `b.add_import("system")` |
| Символы | `b.symbols`, `b.add_dynamic_symbol` |
| Точка входа | `b.entrypoint` |
| Сегменты | `b.segments` |

## Что дальше / решение

Рабочий процесс: разобрать бинарь (`lief.parse`), изучить секции и точку входа, найти цель патча в дизассемблере, применить `patch_address`, записать и проверить на запуске. Для инъекции кода добавьте секцию и перепишите точку входа на неё. Дальше осваивайте PE-специфику (TLS-колбэки, релокации, ресурсы) и автоматизацию распаковки — LIEF часто комбинируют с эмуляторами (Unicorn) для снятия дампа расшифрованного кода.

## Инъекция кода: добавление секции и правка entrypoint

Помимо патча существующего кода, LIEF позволяет добавить новую секцию с произвольным кодом и перенаправить на неё точку входа. Это основа «патчинга с инъекцией», когда нужно выполнить дополнительный код (логгер, распаковщик, хук), а затем вернуться к оригиналу. Порядок действий: создать `lief.ELF.Section`, задать флаги `ALLOC | EXECINSTR`, добавить её как загружаемую (`add(sec, loaded=True)`), записать байты кода, сохранить старую точку входа и пропатчить её на новую. В конце новой секции ставится прыжок на оригинальную точку входа. Для PE используется `b.add_section(section)` и правка `optional_header.addressof_entrypoint`. Обязательно проверяйте выравнивание (`section.alignment`) — неправильное выравнивание ломает загрузку. После сборки запустите `readelf -l`/`objdump -h` и сам бинарь.

## Разбор Mach-O и DEX

Помимо ELF/PE, LIEF поддерживает Mach-O (macOS/iOS) и DEX (Android). Для Mach-O: `b.header.cpu_type`, `b.segments`, `b.libraries` (список dylib), `b.imported_functions`. Для DEX: `lief.DEX.parse("classes.dex")`, доступ к классам (`b.classes`), методам (`method.code`), строкам (`b.strings`). Это позволяет автоматизировать анализ Android-приложений: искать подозрительные вызовы, патчить байткод, извлекать строки. Единый API LIEF даёт возможность писать кросс-платформенные скрипты, работающие с ELF, PE, Mach-O и DEX одним кодом.

## Автоматизация: скрипт пакетного патчинга

Типичная задача — пропатчить много бинарей по одному правилу (например, отключить проверку в серии крэкми). Скрипт обходит каталог, для каждого файла ищет сигнатуру байтов, патчит и сохраняет:

```python
import lief, glob
PATTERN = bytes.fromhex("4885c07405")
REPL    = bytes.fromhex("4885c09090")     # jz -> nop
for path in glob.glob("samples/*"):
    if not lief.is_elf(path): continue
    b = lief.parse(path)
    text = b.get_section(".text")
    data = bytes(text.content)
    idx = data.find(PATTERN)
    if idx != -1:
        va = text.virtual_address + idx
        b.patch_address(va, list(REPL))
        b.write(path + ".patched")
        print("patched", path, hex(va))
```

Такой подход сочетает LIEF с поиском сигнатур — быстрый и воспроизводимый.

## Сравнение LIEF с pefile/pwntools

`pefile` умеет только читать PE (для разбора и анализа), но не пересобирать файл корректно. `pwntools` (ELF/PE-модули) даёт удобное чтение/запись байтов, патч по смещению и даже сборку, но не управляет структурами секций/сегментов на уровне объектной модели. LIEF же предоставляет полноценную **пересборку**: добавление/удаление секций, импортов, символов, правку заголовков. Поэтому LIEF применяют для инструментов (распаковщики, инъекторы, анализаторы), а `pwntools` — для быстрых одноразовых патчей в эксплойтах.

| Инструмент | Чтение | Патч байтов | Пересборка структур |
|---|---|---|---|
| readelf/objdump | да | нет | нет |
| pefile | да (PE) | частично | нет |
| pwntools | да | да | частично |
| LIEF | да | да | да (секции, импорты, символы) |

## Квиз

```quiz
- question: "Что делает LIEF?"
  options:
    - "Разбирает и модифицирует ELF/PE/Mach-O программно"
    - "Отлаживает процессы"
    - "Сканирует порты"
    - "Запускает malware"
  answer: 0
  explanation: "LIEF — библиотека для парсинга и патчинга исполняемых форматов."
- question: "Как преобразовать виртуальный адрес в смещение файла?"
  options:
    - "elf.virtual_address_to_offset(va)"
    - "elf.entrypoint"
    - "elf.sections"
    - "elf.header"
  answer: 0
  explanation: "Функция даёт file offset для патча."
- question: "Как пропатчить байты кода?"
  options:
    - "elf.patch_address(addr, bytes)"
    - "elf.write"
    - "elf.parse"
    - "elf.add"
  answer: 0
  explanation: "patch_address записывает байты по VA/offset."
- question: "Почему патч может сломать запуск на Windows/macOS?"
  options:
    - "Ломается цифровая подпись"
    - "Меняется архитектура"
    - "Теряются секции"
    - "Меняется ASLR"
  answer: 0
  explanation: "Подписанные бинари отказываются запускаться после модификации."
- question: "Как обойти проверку лицензии патчем?"
  options:
    - "Заменить начало функции на mov eax,1; ret"
    - "Добавить NOP в main"
    - "Изменить entrypoint"
    - "Удалить секцию"
  answer: 0
  explanation: "Функция-проверка принудительно возвращает успех."
```

## Где пригодится

- **CTF:** Reversing — автопатчинг крэкми.
- **Automation:** массовая модификация бинарей.
- **Malware research:** разбор/патч образцов.
- **Работа:** tooling, binary rewriting.
