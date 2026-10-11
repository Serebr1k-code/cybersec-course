---
id: stego-executable
title: "Стеганография в исполняемых файлах: overlay, ресурсы, секции"
category: stego
parent: stego-binary-carriers
difficulty: medium
order: 2
tags: [stego, executable, pe, elf, overlay, resources, sections]
prerequisites: [stego-appended]
useful_for:
  - "CTF Stego/Reversing — PE/ELF-носители"
  - "Malware analysis: скрытые полезные нагрузки"
  - "Forensics: данные в бинарниках"
estimated_minutes: 35
summary: "Как прячут данные в PE/ELF: overlay после конца образа, ресурсы, неиспользуемые/пустые секции, дописанные архивы, иконы и строковые ресурсы; практическое извлечение."
---

Исполняемые файлы (PE для Windows, ELF для Linux) — удобный контейнер: у них есть «официальные» секции (код, данные, ресурсы) и «пустоты» (overlay после конца образа, неиспользуемые байты, padding). Данные можно спрятать в overlay, в ресурсах, в пустых/дополнительных секциях, в иконах и строковых ресурсах, а также дописать архив/картинку после конца файла.

## PE (Windows)

```bash
file suspect.exe
# overlay: данные после последней секции
python3 -c "import pefile; pe=pefile.PE('suspect.exe'); print(hex(pe.get_overlay_data_start_offset()))"
pefile suspect.exe | grep -i "sections\|overlay"   # или
# извлечь overlay
python3 -c "import pefile; pe=pefile.PE('suspect.exe'); open('overlay.bin','wb').write(pe.get_overlay_data())"
# ресурсы
wrestool -l suspect.exe
wrestool -x -t 10 -o icons suspect.exe     # иконки (RCDATA/тип 10)
strings -a suspect.exe | grep -iE "flag|http|key" | head
```

Инструменты: `pe-bear`, `CFF Explorer`, `Resource Hacker`, `pestudio`.

## ELF (Linux)

```bash
readelf -S suspect.elf          # секции
readelf -l suspect.elf          # сегменты
# секции с подозрительными именами/нулевым размером
objdump -h suspect.elf
strings -a suspect.elf | tail -50
# дописанные данные
binwalk suspect.elf
```

Каналы: overlay после последнего сегмента, `.comment`, неиспользуемые байты в `.text`/`.data`, дополнительные секции, дописанные архивы.

## Общие приёмы

- **Overlay:** данные после конца образа (часто ZIP/PNG/флаг).
- **Ресурсы/иконки:** в PE `wrestool -x`; в ELF — `.rodata`/встроенные файлы.
- **Пустые секции:** секция с нулевым/аномальным размером может нести данные.
- **DLL/соседние файлы:** нагрузка в рядом лежащем файле.
- **Appended archive:** `binwalk -e`.

## Разобранный пример

CTF: `challenge.exe`. Пентестер:
1. `python3 -c "...get_overlay_data()"` → извлекает overlay.
2. `file overlay.bin` → PNG.
3. В PNG — zsteg → флаг. Или overlay — ZIP с флагом.

## Частые ошибки

- Не проверять overlay (данные после конца образа).
- Игнорировать ресурсы (иконки, RCDATA, диалоги).
- Не смотреть секции с аномальными именами/размерами.
- Забывать про `binwalk` (дописанные форматы).

## Что делать дальше

- **Overlay найден** → определите тип (`file`) и разберите.
- **Ресурсы** → `wrestool -x`, смотрите все типы.
- **Подозрительная секция** → дампните её и проверьте.
- **Пусто** → строки, метаданные, debug-инфо.

## Форматы и где лежат данные (карта)

| Формат | Структура | Каналы сокрытия |
|--------|-----------|-----------------|
| PE (Windows) | MZ-заголовок + секции | overlay, ресурсы, пустые секции, `.reloc`, debug |
| ELF (Linux) | заголовок + секции/сегменты | overlay, `.comment`, доп. секции, `.rodata` |
| Mach-O (macOS) | заголовок + load commands | load commands, доп. сегменты, resources |
| .NET | PE + CLI-метаданные | resources, embedded assembly, user strings |
| APK/JAR | ZIP-архив | лишние файлы, classes.dex, resources |

Общий принцип: ищите данные **за пределами** того, что загружается в память — overlay, ресурсы, «мусорные» секции.

## PE: overlay и ресурсы по шагам

```bash
file suspect.exe
# Overlay = данные после конца образа (последней секции)
python3 -c "import pefile; pe=pefile.PE('suspect.exe'); print(hex(pe.get_overlay_data_start_offset()))"
python3 -c "import pefile; pe=pefile.PE('suspect.exe'); open('overlay.bin','wb').write(pe.get_overlay_data())"
file overlay.bin && binwalk overlay.bin
# Секции: имена, размеры, энтропия (высокая энтропия = упаковано/зашифровано)
python3 -c "import pefile; pe=pefile.PE('suspect.exe'); [print(s.Name.rstrip(b'\\x00').decode(errors='replace'), hex(s.SizeOfRawData), round(s.get_entropy(),2)) for s in pe.sections]"
# Ресурсы (иконки, RCDATA, диалоги, строки)
wrestool -l suspect.exe
wrestool -x -t 10 -o icons/ suspect.exe      # RCDATA/иконки
strings -a suspect.exe | grep -iE 'flag|http|key|pass' | head
```

GUI: `pe-bear`, `CFF Explorer`, `Resource Hacker`, `pestudio` (энтропия, overlay, ресурсы).

## ELF: секции, сегменты, хвост

```bash
file suspect.elf
readelf -S suspect.elf            # таблица секций
readelf -l suspect.elf            # сегменты (PT_LOAD)
objdump -h suspect.elf            # заголовки секций
# секции с аномальными именами/размерами/энтропией
readelf -x .comment suspect.elf   # дамп конкретной секции
strings -a suspect.elf | tail -50
# overlay: смещение после последнего PT_LOAD-сегмента
readelf -l suspect.elf | grep LOAD
binwalk suspect.elf               # дописанные форматы
```

Каналы ELF: overlay после последнего сегмента, `.comment`/`.note`, неиспользуемые байты в `.text`/`.data`, дополнительные секции, appended ZIP/PNG.

## Общие приёмы (таблица)

| Приём | Что делает | Команда |
|-------|-----------|---------|
| Overlay | данные после конца образа | `pefile.get_overlay_data()` / `readelf -l` |
| Ресурсы | иконки/RCDATA/строки (PE) | `wrestool -x` |
| Пустые секции | секция с аномальным размером | `readelf -S`/`pefile` |
| Энтропия | упаковка/шифрование | `pefile`/`binwalk -E` |
| Appended | дописанный архив/картинка | `binwalk -e` |
| Соседние файлы | нагрузка в DLL/.so | листинг каталога |
| Debug-инфо | PDB/DWARF пути, имена | `readelf --debug-dump` |

## Инструменты (полный набор)

| Инструмент | Назначение | Пример |
|------------|-----------|--------|
| `pefile` (pip) | разбор PE, overlay | см. выше |
| `wrestool`/`icotool` | ресурсы PE | `wrestool -l x.exe` |
| `readelf`/`objdump` | секции ELF | `readelf -S x.elf` |
| `binwalk` | встроенные форматы | `binwalk x.exe` |
| `strings` | текст | `strings -a x` |
| `pe-bear`/`CFF Explorer`/`Resource Hacker` | GUI-разбор PE | — |
| `pestudio` | энтропия/overlay/импорты | — |
| `upx -d` | распаковка UPX | `upx -d x.exe` |

## Разобранные примеры

**1. Overlay.** `get_overlay_data()` → `file overlay.bin` → PNG → `zsteg` → флаг.

**2. Ресурсы.** `wrestool -x -t 10` извлекает иконку, в её пикселях — QR/текст.

**3. Пустая секция.** `readelf -S` показывает секцию с размером 0 и странным именем; дамп по смещению даёт флаг.

## Частые ошибки и отладка

- **Не проверять overlay** — самый частый канал.
- **Игнорировать ресурсы** (иконки/RCDATA/диалоги).
- **Не смотреть энтропию** — высокая = упаковано, нужен `upx -d`.
- **Забывать про `binwalk`** (дописанные форматы).
- **Отладка:** если overlay пуст — проверьте все секции, ресурсы, debug-инфо; если энтропия высока — распакуйте.

## Что делать дальше / дерево решений

1. `file` → формат. Overlay? → извлеките и `file`/`binwalk`.
2. Ресурсы (PE)? → `wrestool -x` по всем типам.
3. Секции/энтропия аномальны? → дамп секции / `upx -d`.
4. Ничего → `strings`, debug-инфо, соседние файлы.
5. Всё чисто → `binwalk -e` на хвост.

## Шпаргалка: конвейер по бинарнику

```bash
file x                                   # PE/ELF/Mach-O
# PE: overlay + ресурсы
python3 -c "import pefile;pe=pefile.PE('x');print(hex(pe.get_overlay_data_start_offset()))"
wrestool -l x
# ELF: секции + хвост
readelf -S x; readelf -l x | grep LOAD
# общее
strings -a x | tail -40
binwalk x
```

Рабочий процесс: определите формат (`file`), затем проверьте overlay (данные за концом образа) — это самый частый канал; далее ресурсы (PE) и аномальные/пустые секции (энтропия). Если энтропия высокой секции близка к 8 — вероятно упаковано, попробуйте `upx -d` или дамп в рантайме. Не забывайте про debug-инфо (пути PDB/DWARF) и соседние файлы (DLL/.so). В отчёте фиксируйте: формат, канал (overlay/ресурсы/секция), смещение и результат.

## Что проверять в отчёте

Для воспроизводимости фиксируйте: формат (PE/ELF/Mach-O), точный канал (overlay после секции N, ресурс типа RCDATA, секция `.name` по смещению X, хвост после PT_LOAD), извлечённый артефакт (имя/тип/размер) и цепочку дальнейшего разбора (например, overlay → PNG → zsteg). Укажите, была ли секция упакована (энтропия) и потребовалась ли распаковка (`upx -d`). Это позволит другому аналитику повторить извлечение и подтвердить находку.

## Квиз

```quiz
- question: "Что такое overlay в исполняемом файле?"
  options:
    - "Данные после конца образа (последней секции)"
    - "Заголовок файла"
    - "Таблица импорта"
    - "Подпись"
  answer: 0
  explanation: "Overlay лежит за пределами описанных секций/сегментов."
- question: "Каким инструментом извлечь ресурсы PE?"
  options:
    - "wrestool"
    - "zsteg"
    - "mutool"
    - "jadx"
  answer: 0
  explanation: "wrestool перечисляет и извлекает ресурсы PE."
- question: "Чем посмотреть секции ELF?"
  options:
    - "readelf -S / objdump -h"
    - "exiftool"
    - "strings"
    - "file"
  answer: 0
  explanation: "readelf/objdump показывают таблицу секций."
- question: "Где ещё прячут данные в бинарнике?"
  options:
    - "В ресурсах, иконках, пустых секциях"
    - "Только в заголовке"
    - "Только в подписи"
    - "Только в имени"
  answer: 0
  explanation: "Ресурсы и аномальные секции — частые каналы."
- question: "Какая команда находит дописанные форматы?"
  options:
    - "binwalk"
    - "nm"
    - "ldd"
    - "chmod"
  answer: 0
  explanation: "binwalk сканирует сигнатуры внутри файла."
```

## Где пригодится

- **CTF Stego/Reversing:** PE/ELF-носители.
- **Malware analysis:** скрытые нагрузки.
- **Forensics:** данные в бинарниках.
- **Работа:** анализ подозрительных исполняемых файлов.
