---
id: forensics-lnk
title: "LNK и Jump Lists: глубокий разбор"
category: forensics
parent: forensics-win-execution
difficulty: medium
order: 1
tags: [lnk, jumplists, shellitems, windows, dfir, recent]
prerequisites: [forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 35
summary: "Формат LNK и автоматических/пользовательских Jump Lists: Shell Item ID Lists, MAC-времена, доказательство доступа к файлам на локальных и съёмных дисках."
---
LNK-файлы (ярлыки Windows) и Jump Lists — одни из самых информативных артефактов. Они доказывают, что пользователь открывал файл, и содержат не только путь, но и серийный номер тома, размер, MAC-времена целевого объекта. Ярлык остаётся даже после удаления целевого файла, что делает его бесценным в расследовании. Этот урок — про формат LNK, Shell Item ID Lists, Jump Lists и их разбор.

## Где лежат LNK

| Путь | Что содержит |
|------|-------------|
| `%APPDATA%\Microsoft\Windows\Recent\` | недавние файлы/папки |
| `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` | автоматические Jump Lists (по приложению) |
| `%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\` | пользовательские Jump Lists |
| `%APPDATA%\Microsoft\Office\Recent\` | недавние документы Office |
| Рабочий стол, меню «Пуск» | пользовательские ярлыки |

`Recent` хранит `.lnk` для каждого открытого файла; имя ярлыка — это имя целевого файла, что удобно для быстрого поиска.

## Формат LNK

LNK — бинарный формат (MS-SHLLINK). Ключевые структуры:

- **ShellLinkHeader** (76 байт): `HeaderSize`, `LinkCLSID` (`00021401-...`), флаги, атрибуты файла, времена (creation/access/write), размер целевого файла.
- **LinkTargetIDList** — список Shell Item ID (путь), переменной длины.
- **LinkInfo** — локальный путь, объём, серийный номер тома.
- **StringData** — `NAME_STRING`, `RELATIVE_PATH`, `WORKING_DIR`, `COMMAND_LINE_ARGUMENTS`, `ICON_LOCATION`.
- **ExtraData** — блоки, включая `TrackerDataBlock` (машина, где создан ярлык).

```bash
$ xxd -l 32 file.lnk
00000000: 4c00 0000 0114 0200 0000 00c0 0000 0046  L..............F
```

`4C 00 00 00` = HeaderSize (76), `01 14 02 00` — LinkCLSID начало.

## Разбор с LECmd

`LECmd` (Eric Zimmerman) — стандарт для LNK.

```bash
$ LECmd.exe -f file.lnk
$ LECmd.exe -d "%APPDATA%\Microsoft\Windows\Recent" --csv out --csvf lnk.csv
$ LECmd.exe -d Recent --csv out --csvf lnk.csv --html out --htmlf lnk.html
```

Пример вывода:

```
Source file: C:\Users\bob\AppData\Roaming\Microsoft\Windows\Recent\secret.docx.lnk
Target: C:\Users\bob\Documents\secret.docx
Target created: 2024-02-20 10:00:00
Target modified: 2024-02-25 14:30:00
Target accessed: 2024-03-01 12:05:00
Volume serial: 4C53-0001
Volume label: BACKUP
Drive type: Removable
Relative path: ..\..\..\Users\bob\Documents\secret.docx
```

Поле `Drive type: Removable` + `Volume serial` связывает файл со съёмным носителем.

## Jump Lists

Jump Lists — списки недавних файлов приложения (например, Word, Notepad, 7-Zip). Автоматические (`AutomaticDestinations`) — файлы `*.automaticDestinations-ms`, пользовательские (`CustomDestinations`) — `*.customDestinations-ms`. Формат — OLE-контейнер со встроенными LNK (streams).

```bash
$ JLECmd.exe -d "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations" --csv out --csvf jl.csv
$ JLECmd.exe -f 1b4dd67f29cb1962.automaticDestinations-ms
```

Пример:

```
AppId: 1b4dd67f29cb1962 (Word)
Entry: secret.docx
Path: C:\Users\bob\Documents\secret.docx
Created: 2024-02-20 10:00:00
Modified: 2024-02-25 14:30:00
Accessed: 2024-03-01 12:05:00
```

AppId идентифицирует приложение; таблица AppId → приложение есть в документации (например, `1b4dd67f...` = Word).

## Shell Item ID Lists и путь

Путь в LNK/Jump List — это список Shell Items: элементы файловой системы, сетевые, MTP, «Корзина». Каждый элемент несёт тип и данные. Это позволяет восстанавливать путь даже для удалённых каталогов.

```bash
# LECmd показывает расшифрованный путь
$ LECmd.exe -d Recent --csv out --csvf lnk.csv
# в CSV: Relative Path, Working Directory, Arguments, Volume Serial
```

## Что доказывают LNK

| Факт | Поле |
|------|------|
| Файл открывался | наличие `.lnk` |
| Где лежал | `Relative Path`/`LinkInfo` |
| На каком носителе | `Volume Serial`/`Drive type` |
| Когда открыт | MAC целевого + время создания LNK |
| С какой программой | Jump List AppId |
| С какими аргументами | `COMMAND_LINE_ARGUMENTS` |

## Разобранный пример

Нужно доказать, что пользователь открывал файл с флешки.

```bash
# 1. LNK в Recent
$ LECmd.exe -d Recent --csv out --csvf lnk.csv
$ grep -i 'E:\\' out/lnk.csv
secret.docx, E:\backup\secret.docx, Volume Serial: 4C53-0001, Drive: Removable
# 2. Сопоставить с USB
$ rip.pl -r SYSTEM -p usb | grep 4C53
USBSTOR\Disk&Ven_SanDisk... S/N ...
# 3. Jump List подтверждает программу
$ JLECmd.exe -d AutomaticDestinations --csv out --csvf jl.csv
$ grep -i secret out/jl.csv
secret.docx (AppId 1b4dd67f29cb1962 = Word)
```

## Справочная таблица

| Артефакт | Инструмент |
|----------|-----------|
| LNK | `LECmd`, `lnk-parser` |
| Jump Lists | `JLECmd` |
| OLE-структура | `oletools` |
| Volume Serial | `MountedDevices` (реестр) |
| Shell Item | `LECmd` (расшифровка) |

## Частые ошибки

- **Смотреть только `Recent`** — Jump Lists дают больше контекста.
- **Игнорировать Volume Serial** — он связывает файл с носителем.
- **Путать MAC LNK и MAC цели** — в LNK хранятся оба.
- **Не проверять аргументы** — `COMMAND_LINE_ARGUMENTS` может содержать URL/пути.
- **Считать LNK мусором** — это прямое доказательство доступа.
- **Забывать про удалённые ярлыки** — искать в unallocated.

## Что дальше / решение

Конвейер: `LECmd` (LNK) → `JLECmd` (Jump Lists) → сопоставить Volume Serial с USB-артефактами → свести с Shellbags/UserAssist. Связка: `forensics-usb-devices` (USB), `forensics-shellbags` (папки), `forensics-windows-execution` (запуск), `forensics-timeline` (хронология).

## Парсеры и практика разбора

| Инструмент | Назначение |
|-----------|-----------|
| `LECmd` | LNK → CSV/JSON/HTML |
| `JLECmd` | Jump Lists |
| `lnk-parser` (Python) | программный разбор |
| `oletools` (`olevba`/`oleid`) | OLE-структура Jump Lists |
| `WxTCmd` | Windows Timeline (ActivitiesCache.db) |

```bash
# массовый разбор всех LNK в дереве
$ LECmd.exe -d C:\Users --csv out --csvf all_lnk.csv --recurse
# только удалённые цели
$ awk -F, '$0 ~ /not exist/ {print}' out/all_lnk.csv | head
# Jump Lists с HTML-отчётом
$ JLECmd.exe -d AutomaticDestinations --csv out --html out_html
```

`WxTCmd` разбирает Windows Timeline (`ActivitiesCache.db`) — ещё один источник истории открытых файлов и приложений, связанный с LNK/Jump Lists.

## Анти-форензика и целостность LNK

LNK-файлы можно удалить, но они часто остаются в unallocated или в теневых копиях. Также полезно проверять **несоответствие** MAC-времен целевого файла и времени создания ярлыка: если ярлык создан раньше целевого файла — это аномалия (возможный timestomp).

```bash
# восстановить удалённый LNK из unallocated
$ blkls -o 2048 disk.img | grep -aboP 'L\x00\x00\x00\x01\x14\x02\x00'
# проверка времен
$ LECmd.exe -f file.lnk | grep -iE 'Target (created|modified|accessed)|Source created'
```

Помните, что LNK-времена хранятся в UTC, а FAT-времена целевого файла (если он на FAT-носителе) — в локальном времени; учитывайте это при сведении.

## Итоговый практический конвейер

Полный разбор LNK/Jump Lists: (1) `LECmd.exe -d Recent --csv` — все ярлыки с путями и серийниками; (2) `JLECmd.exe -d AutomaticDestinations --csv` — недавние файлы по приложениям; (3) `WxTCmd` — Windows Timeline; (4) сопоставление Volume Serial с `MountedDevices`/USBSTOR; (5) сведение с Shellbags и UserAssist. Так вы получаете доказуемую картину: какой файл, на каком носителе, какой программой и когда открывался.

## Квиз

```quiz
- question: "Какой блок LNK хранит MAC-времена целевого файла?"
  options:
    - "LinkInfo"
    - "StringData"
    - "Shell Item (тип 0x31/0x32)"
    - "Header"
  answer: 2
- question: "Что означает DriveType: Removable в разборе LNK?"
  options:
    - "цель — сетевой диск"
    - "цель находилась на съёмном носителе (USB)"
    - "цель — папка"
    - "цель удалена"
  answer: 1
- question: "Где хранятся автоматические Jump Lists?"
  options:
    - "Recent\\*.lnk"
    - "Recent\\AutomaticDestinations\\*.automaticDestinations-ms"
    - "Recent\\CustomDestinations"
    - "Prefetch"
  answer: 1
- question: "Какой Shell Item тип указывает на сетевой путь вида \\\\host\\share?"
  options:
    - "0x31"
    - "0x2E / 0x2A"
    - "0x74"
    - "0x1F"
  answer: 1
- question: "Почему одного DriveType недостаточно для привязки к конкретному USB?"
  options:
    - "DriveType всегда пуст"
    - "нужен серийный номер тома, сверяемый с USBSTOR/MountedDevices"
    - "DriveType меняется каждый день"
    - "USB не логируется"
  answer: 1
```

## Где пригодится

- **CTF:** задачи «кто открывал файл» и «с какой флешки украли данные».
- **DFIR:** доказательство доступа к документам и носителям.
- **Threat Hunting:** поиск обращений к сетевым шарам из LNK (`\\host\share`).
- **Судебная экспертиза:** связка LNK ↔ USBSTOR для установления факта копирования.
- **Анализ утечек:** восстановление пути к похищенному документу.
