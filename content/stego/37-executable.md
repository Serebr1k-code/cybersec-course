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
lab:
  kind: shell
  title: "Практика: overlay после ELF"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, notes.txt, sample.elf, overlay.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Запусти `python3 overlay.py`."
    - "Конец сегментов — max(p_offset+p_filesz)."
    - "Всё после — overlay с base64."
    - "`python3 overlay.py | grep nto > found.txt`."

---

## Вопрос, с которого всё начинается

Тебе дали `challenge.exe` — программу. Она запускается и что-то делает. Флаг спрятан внутри. Но это не картинка и не архив — это **исполняемый файл**, у которого есть код, данные и ресурсы.

Хорошая новость: у исполняемых файлов есть «пустоты», которые загрузчик в память не берёт, — там и прячут данные. Разберём на конкретном PE.

## Наш пример: challenge.exe

Начнём с определения формата.

```
$ file challenge.exe
challenge.exe: PE32+ executable (GUI) x86-64, for MS Windows
```

PE — формат Windows-исполняемых файлов. У него есть «официальные» секции (код `.text`, данные `.data`, ресурсы `.rsrc`) и то, что лежит **за** ними — **overlay**.

## Шаг 1: overlay — данные после конца образа

**Overlay** — это данные после последней секции. Загрузчик их игнорирует, но они физически есть в файле. Это самый частый канал в executable-задачах.

Извлечём overlay через `pefile` (Python):

```
$ python3 -c "import pefile; pe=pefile.PE('challenge.exe'); print(hex(pe.get_overlay_data_start_offset()))"
0x4200
$ python3 -c "import pefile; pe=pefile.PE('challenge.exe'); open('overlay.bin','wb').write(pe.get_overlay_data())"
$ file overlay.bin
overlay.bin: PNG image data, 64 x 64
```

Overlay оказался PNG-картинкой. Дальше — обычный стего-пайплайн:

```
$ zsteg overlay.bin | grep -i flag
b1,rgb,lsb,xy .. text: "flag{overlay_png}"
```

Флаг найден. Маршрут: overlay → PNG → `zsteg`.

## Шаг 2: ресурсы PE

В PE есть **ресурсы**: иконки, диалоги, строки, RCDATA. Их перечисляет и извлекает `wrestool`:

```
$ wrestool -l challenge.exe
--type=10 [type=icon offset=0 size=1234]
--type=10 [type=icon offset=1234 size=567]
$ wrestool -x -t 10 -o icons/ challenge.exe
$ file icons/*
```

Иконки — частый носитель: в пикселях картинки может быть QR или текст. Также проверь строки:

```
$ strings -a challenge.exe | grep -iE 'flag|http|key|pass' | head
```

## Шаг 3: ELF — секции и хвост

Для Linux-бинарников (`ELF`) логика та же, но инструменты другие. Посмотрим секции:

```
$ file suspect.elf
suspect.elf: ELF 64-bit LSB pie executable, x86-64
$ readelf -S suspect.elf          # таблица секций
$ readelf -l suspect.elf | grep LOAD   # сегменты
$ objdump -h suspect.elf
```

Каналы ELF: overlay после последнего `PT_LOAD`-сегмента, `.comment`/`.note`, неиспользуемые байты в `.text`/`.data`, дополнительные секции. Хвост и вложенное ищет `binwalk`:

```
$ binwalk suspect.elf
```

## Шаг 4: пустые и аномальные секции

Секция с нулевым или аномальным размером может нести данные. Смотрим имена и энтропию:

```
$ python3 -c "import pefile; pe=pefile.PE('challenge.exe'); [print(s.Name.rstrip(b'\x00').decode(errors='replace'), hex(s.SizeOfRawData), round(s.get_entropy(),2)) for s in pe.sections]"
.text 0x1000 6.2
.rdata 0x800 5.1
.rsrc 0x400 7.9
```

Высокая энтропия (~7.9) у `.rsrc` — признак, что там упакованные или сжатые данные. Если энтропия всей программы высока — вероятно, она упакована (UPX), и нужен `upx -d challenge.exe`.

## Шаг 5: общие приёмы

| Приём | Что делает | Команда |
|---|---|---|
| Overlay | данные после конца образа | `pefile.get_overlay_data()` / `readelf -l` |
| Ресурсы | иконки/RCDATA/строки (PE) | `wrestool -x` |
| Пустые секции | секция с аномальным размером | `readelf -S`/`pefile` |
| Энтропия | упаковка/шифрование | `pefile`/`binwalk -E` |
| Appended | дописанный архив/картинка | `binwalk -e` |
| Debug-инфо | PDB/DWARF пути, имена | `readelf --debug-dump` |

## Шаг 6: конвейер по бинарнику

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

## Если не сработало

- Не проверяй overlay — самая частая ошибка (данные за концом образа).
- Не игнорируй ресурсы (иконки/RCDATA/диалоги).
- Смотри энтропию: высокая = упаковано, нужен `upx -d`.
- Не забудь `binwalk` (дописанные форматы).
- Отладка: overlay пуст — проверь все секции, ресурсы, debug-инфо; энтропия высока — распакуй.

## Что мы теперь знаем

1. Overlay — данные после последней секции, не загружаются в память.
2. Ресурсы PE (иконки, RCDATA) извлекает `wrestool`.
3. ELF: секции/сегменты, `.comment`, доп. секции, хвост.
4. Энтропия секции подсказывает упаковку/шифрование.
5. `binwalk` находит встроенные форматы и в хвосте.

## Шаг 7: полный набор инструментов

| Инструмент | Назначение | Пример |
|---|---|---|
| `pefile` (pip) | разбор PE, overlay | `pefile.PE('x.exe')` |
| `wrestool`/`icotool` | ресурсы PE | `wrestool -l x.exe` |
| `readelf`/`objdump` | секции ELF | `readelf -S x.elf` |
| `binwalk` | встроенные форматы | `binwalk x.exe` |
| `strings` | текст | `strings -a x` |
| `pe-bear`/`CFF Explorer`/`Resource Hacker` | GUI-разбор PE | — |
| `pestudio` | энтропия/overlay/импорты | — |
| `upx -d` | распаковка UPX | `upx -d x.exe` |

## Шаг 8: разобранные сценарии

**1. Overlay.** `get_overlay_data()` → `file overlay.bin` → PNG → `zsteg` → флаг.

**2. Ресурсы.** `wrestool -x -t 10` извлекает иконку, в её пикселях — QR/текст.

**3. Пустая секция.** `readelf -S` показывает секцию с размером 0 и странным именем; дамп по смещению даёт флаг.

## Шаг 9: что фиксировать в отчёте

Для воспроизводимости укажи: формат (PE/ELF/Mach-O), точный канал (overlay после секции N, ресурс типа RCDATA, секция `.name` по смещению X, хвост после `PT_LOAD`), извлечённый артефакт (имя/тип/размер), цепочку дальнейшего разбора и потребовалась ли распаковка (`upx -d`). Это позволит другому аналитику повторить извлечение.

## Шаг 10: карта форматов и каналов

| Формат | Структура | Каналы сокрытия |
|---|---|---|
| PE (Windows) | MZ-заголовок + секции | overlay, ресурсы, пустые секции, `.reloc`, debug |
| ELF (Linux) | заголовок + секции/сегменты | overlay, `.comment`, доп. секции, `.rodata` |
| Mach-O (macOS) | заголовок + load commands | load commands, доп. сегменты, resources |
| .NET | PE + CLI-метаданные | resources, embedded assembly, user strings |
| APK/JAR | ZIP-архив | лишние файлы, classes.dex, resources |

Общий принцип: ищи данные **за пределами** того, что загружается в память — overlay, ресурсы, «мусорные» секции. Если энтропия секции близка к 8 — вероятно упаковано, попробуй `upx -d` или дамп в рантайме.

## Почему overlay — самый частый приём

У PE и ELF есть «карта» образа: заголовки описывают, сколько байт занимает код, данные и таблицы, и где они лежат. Всё, что **после** этой карты, загрузчик не читает — программа работает как обычно. Эта область называется **overlay**. Спрятать туда файл проще простого: дописать байты в конец, и бинарник продолжит запускаться. Поэтому overlay — приём номер один и в CTF, и в реальных малварях.

Найти overlay можно, сравнив фактический размер файла с размером, который описывает заголовок. В PE сумма `PointerToRawData + SizeOfRawData` по секциям даёт конец образа; всё дальше — overlay. В ELF аналогично смотрят на конец последней секции/сегмента. Дальше overlay либо сам является файлом (архив, изображение, PE внутри PE), либо содержит встроенный файл по известной сигнатуре (`PK\x03\x04` для ZIP, `\x89PNG` и т.д.).

Второй частый канал — **ресурсы PE**: иконки, строки, диалоги хранятся в отдельной секции `.rsrc`; туда можно положить данные под видом ресурса. Третий — **пустые/неиспользуемые секции** и «дыры» между секциями (padding), куда можно записать байты, не ломая выравнивание. Все три приёма объединяет одно: они используют **несоответствие между «заявленной» и «фактической» структурой файла**.

## Частые вопросы

**Как быстро найти overlay?** `binwalk`, `foremost`, `pe-frame`/`pev`, либо вручную: сравните размер файла с концом последней секции из `objdump -h`/`pefile`.

**Может ли overlay сломать программу?** Обычно нет: загрузчик читает только описанные секции. Но подписанные бинарники overlay может испортить — проверка подписи покроет и его.

**Что искать внутри overlay?** Прогоните `binwalk -e` и `strings`: сигнатуры архивов, изображений, второго PE/ELF, base64-текста.

**Как быть с ELF?** Смотрите `readelf -S`, конец последней секции; `binwalk` и `strings -a` дают то же. Иногда данные прячут в `.comment` или `.note`.

## Квиз

Проверь себя.

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
    - "`wrestool`"
    - "`zsteg`"
    - "`mutool`"
    - "`jadx`"
  answer: 0
  explanation: "wrestool перечисляет и извлекает ресурсы PE."
- question: "Чем посмотреть секции ELF?"
  options:
    - "`readelf -S` / `objdump -h`"
    - "`exiftool`"
    - "`strings`"
    - "`file`"
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
    - "`binwalk`"
    - "`nm`"
    - "`ldd`"
    - "`chmod`"
  answer: 0
  explanation: "binwalk сканирует сигнатуры внутри файла."
```

## Куда дальше

Дальше — **тайминговые covert-каналы**: данные прячут не в файле, а во времени между сетевыми пакетами. А пока запомни: в исполняемом файле первым делом проверь overlay за последней секцией.

## Где пригодится

- **CTF (Stego/Reversing):** PE/ELF-носители.
- **Malware-анализ:** скрытые полезные нагрузки.
- **Forensics:** данные в бинарниках.
- **Работа:** анализ подозрительных исполняемых файлов.
