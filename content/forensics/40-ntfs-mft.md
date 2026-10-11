---
id: forensics-ntfs-mft
title: "NTFS изнутри: $MFT, $LogFile, $UsnJrnl, ADS"
category: forensics
parent: forensics-fs-internals
difficulty: hard
order: 1
tags: [ntfs, mft, usnjrnl, logfile, ads, sleuthkit, mftecmd, windows]
prerequisites: [forensics-filesystems]
useful_for:
  - "CTF Forensics категория"
  - "Incident Response (Windows)"
  - "Анализ образов Windows"
estimated_minutes: 55
summary: "Глубокий разбор NTFS: записи MFT и их атрибуты, resident/non-resident данные, $LogFile, $UsnJrnl, Alternate Data Streams, восстановление удалённых записей."
---

NTFS — основная файловая система Windows, и почти любая задача по форензике Windows упирается в её метаданные. Поверхностного `fls` недостаточно: чтобы найти удалённый файл, понять, что было переименовано, или вытащить скрытый поток, нужно читать **записи MFT**, **журналы** `$LogFile`/`$UsnJrnl` и **атрибуты** NTFS. Этот урок — про то, как устроен NTFS на уровне байтов и как превратить эти структуры в хронологию событий.

## Архитектура NTFS

NTFS — журналируемая ФС с метаданными, разложенными в служебные файлы (каждый — запись в MFT, имя начинается с `$`):

| Файл | MFT # | Назначение |
|------|------:|-----------|
| `$MFT` | 0 | Master File Table — таблица всех файлов |
| `$MFTMirr` | 1 | зеркало первых 4 записей MFT |
| `$LogFile` | 2 | журнал транзакций метаданных |
| `$Volume` | 3 | метка тома, версия |
| `$AttrDef` | 4 | определения атрибутов |
| `.` (root) | 5 | корневой каталог |
| `$Bitmap` | 6 | занятость кластеров |
| `$Boot` | 7 | загрузочный сектор (копия) |
| `$BadClus` | 8 | список сбойных кластеров |
| `$Secure` | 9 | дескрипторы безопасности (ACL) |
| `$UpCase` | 10 | таблица регистра |
| `$Extend` | 11 | каталог расширений |
| `$Extend\$UsnJrnl` | — | журнал изменений (USN) |
| `$Extend\$Quota`, `$ObjId`, `$Reparse` | — | квоты, object id, reparse |

Ключевая идея: **файл — это набор атрибутов, записанных в запись MFT**. Данные файла — лишь один из атрибутов (`$DATA`). Имя — атрибут `$FILE_NAME`. Именно поэтому можно иметь несколько имён (hard links) и несколько потоков данных (ADS).

Базовые понятия:
- **Кластер** — единица выделения (обычно 4096 байт, задаётся `$Boot`).
- **Запись MFT (FILE record)** — фиксированный размер (обычно 1024 байта), описывает один файл/каталог.
- **Reference number** — 48-битный номер записи + 16-битный sequence number (защита от переиспользования).
- **Runlist** — список экстентов (начальный LCN + длина) для non-resident данных.

## Запись MFT по байтам

Запись MFT начинается с сигнатуры `FILE` (для удалённых — `BAAD`, для пустых — `00 00`). Разбор заголовка:

```bash
# Определяем offset NTFS-раздела
mmls disk.img
# напр. Start Sector = 2048 -> offset = 2048*512 = 104857600

# Загрузочный сектор NTFS: байты 0-2 = EB 52 90, offset 3 = "NTFS    "
xxd -s 104857600 -l 96 disk.img

# Поля $Boot, которые нам нужны:
# offset 0x0D (13): Bytes Per Sector  (обычно 0x0200 = 512)
# offset 0x0E (14): Sectors Per Cluster
# offset 0x30 (48): MFT LCN (кластер начала $MFT)
# offset 0x38 (56): MFTMirr LCN
```

Разбор `$Boot` через `xxd`:

```bash
xxd -s $((104857600 + 0x0E)) -l 2 disk.img   # Sectors/Cluster, напр. 0008 -> 8
xxd -s $((104857600 + 0x30)) -l 8 disk.img   # MFT LCN, little-endian
```

Пример: `Sectors/Cluster = 8`, значит кластер = 8·512 = 4096 байт. Если `MFT LCN = 0x0000000000040000`... читаем как little-endian: реальное значение — младшие байты. Пусть MFT начинается с кластера `N`; тогда offset MFT = `N · 4096` + offset раздела.

Заголовок записи MFT (первые 0x30 байт):

| Смещение | Размер | Поле |
|---------:|-------:|------|
| 0x00 | 4 | сигнатура `FILE` |
| 0x04 | 2 | offset до массива обновления (USA) |
| 0x06 | 2 | размер массива обновления (обычно 3) |
| 0x08 | 8 | `$LogFile` LSN |
| 0x10 | 2 | sequence number |
| 0x12 | 2 | hard-link count |
| 0x14 | 2 | offset первого атрибута (обычно 0x38) |
| 0x16 | 2 | flags (`0x01` in-use, `0x02` directory) |
| 0x18 | 4 | real size (logical) |
| 0x1C | 4 | allocated size |
| 0x20 | 8 | file reference to base record |
| 0x28 | 2 | next attribute id |
| 0x2C | 2 | (XP+) align |
| 0x30 | 4 | MFT record number (self) |

Поле **flags** критично: `0x01` = запись занята, `0x00` = удалена (данные могут ещё лежать), `0x02` = это каталог.

```bash
# Ручной дамп первой записи MFT (после вычисления offset)
xxd -s <mft_offset> -l 512 disk.img
# Ищем "FILE" и разбираем заголовок
```

## Атрибуты и resident/non-resident данные

Каждый атрибут начинается с заголовка:

| Смещение | Размер | Поле |
|---------:|-------:|------|
| 0x00 | 4 | тип атрибута (`0x10`=STANDARD_INFORMATION, `0x30`=FILE_NAME, `0x80`=DATA, `0x90`=INDEX_ROOT, `0xB0`=BITMAP, `0x40`=OBJECT_ID, `0x50`=SECURITY_DESCRIPTOR, `0x100`=LOGGED_UTILITY_STREAM) |
| 0x04 | 4 | длина записи атрибута |
| 0x08 | 1 | non-resident flag (`0` = resident, `1` = non-resident) |
| 0x09 | 1 | длина имени |
| 0x0A | 2 | offset имени |
| 0x0C | 2 | flags |
| 0x0E | 2 | attribute id |
| 0x10 | 4 | resident: длина содержимого; non-resident: старший VCN |
| 0x14 | 2 | resident: offset содержимого |
| 0x18 | 2 | compressed / sparse |

**Resident** — данные лежат прямо внутри записи MFT (мелкие файлы < ~700 байт и все `$FILE_NAME`). **Non-resident** — данные в кластерах, атрибут хранит **runlist** (пары «длина, смещение», где смещение относительно предыдущего LCN, со знаком).

Атрибут `$FILE_NAME` (тип 0x30) хранит четыре **MACB-таймстампа**: Modified, Accessed, MFT-changed (creation of record), Birth (creation). Именно эти времена дают хронологию. Атрибут `$STANDARD_INFORMATION` (тип 0x10) хранит ещё один набор времён (в NTFS — «истинные» времена, которые меняет антифорензика).

```bash
# istat показывает атрибуты, runlist и все четыре времени
istat -o <offset> disk.img <inode>
# fls -m даёт machine-readable вывод для таймлайна
fls -r -m "C:/" -o <offset> disk.img > bodyfile.txt
```

## $LogFile: журнал транзакций

`$LogFile` (MFT #2) — журнал **транзакций метаданных** (redo/undo). Он содержит **предыдущие** значения изменённых структур: переименования, создание/удаление записей MFT, изменения runlist. Это единственный способ увидеть, **что было переименовано** и как выглядело состояние до изменения.

Особенности:
- `$LogFile` — кольцевой буфер; старые записи перезаписываются.
- Логическая нумерация — LSN (Log Sequence Number); LSN хранится в заголовке записи MFT (`$LogFile` LSN).
- Парсить вручную тяжело; используют `LogFileParser` (Zimmerman) или `ntfs-log-tracker`.

```bash
# Извлечь $LogFile (MFT #2) из образа
icat -o <offset> disk.img 2 > LogFile.bin
# Парсинг (Windows-инструмент LogFileParser.exe, .NET)
#   LogFileParser.exe -f LogFile.bin
# Вывод содержит операции: Create/Rename/Delete и old/new имя
```

Типичный результат парсинга — строки вида `Rename: old.txt -> new.txt` и записи `Delete`, что прямо доказывает действия пользователя даже если файл уже удалён.

## $UsnJrnl: журнал изменений

`$UsnJrnl` (в `$Extend`, MFT #11/поток) — журнал **изменений на томе** (Update Sequence Number). В отличие от `$LogFile`, он **не** хранит содержимое, но хранит для каждой операции: USN, имя файла, время, причину (`FILE_CREATE`, `DATA_OVERWRITE`, `RENAME_NEW_NAME`, `FILE_DELETE` и т. д.). Это лучший источник хронологии действий с файлами.

`$UsnJrnl` — файл с двумя потоками: `$Max` (метаданные) и `$J` (сами записи). Извлекать нужно `$J`.

```bash
# Найти inode $UsnJrnl через fls по корню $Extend
fls -o <offset> disk.img 11           # $Extend, увидим $UsnJrnl с номером
# Извлечь поток $J (sleuthkit: имя потока после inode через '-i' + ':' )
icat -o <offset> disk.img <usnjrnl_inode>-128-4 > usnjrnl.bin   # вариант выбора потока
# Надёжнее — MFTECmd на Windows, он сам достаёт $J:
#   MFTECmd.exe -f usnjrnl.bin --csv out
```

Парсинг через Python (библиотека `usnparser`):

```bash
pip install usnparser
usnparser parse usnjrnl.bin > usn.csv
# CSV: Timestamp, USN, Reason, Name, ParentRef
```

Причины (`Reason`) — битовая маска: `0x00000001` FILE_CREATE, `0x00000200` DATA_OVERWRITE, `0x00001000` RENAME_NEW_NAME, `0x00002000` RENAME_OLD_NAME, `0x00000100` FILE_DELETE, `0x80000000` CLOSE. Анализ `RENAME_OLD_NAME` + `RENAME_NEW_NAME` с одинаковым USN даёт пару «было → стало».

## Alternate Data Streams

ADS — дополнительный поток данных того же файла: `secret.txt:hidden.txt`. В `fls` поток виден как отдельная запись; в MFT — как ещё один атрибут `$DATA` с именем.

```bash
# Найти потоки: fls показывает имена с ':' при -r
fls -r -o <offset> disk.img | grep ':'
# Пример:
#  r/r 128-128-3: secret.txt:hidden.txt

# Извлечь конкретный поток
icat -o <offset> disk.img 128-128-3 > hidden.bin
strings hidden.bin

# Смонтировать и увидеть ADS (Linux, ntfs-3g)
sudo mount -t ntfs-3g -o ro,streams_interface=xattr disk.img /mnt/ntfs
getfattr -n user.ADS /mnt/ntfs/secret.txt
# или через ntfs-3g: cat /mnt/ntfs/secret.txt:hidden.txt
```

Частая уловка: полезная нагрузка (флаг, малварь) спрятана в ADS обычного файла — `dir /r` в Windows и `fls | grep :` в Linux это вскрывают.

## Восстановление удалённых записей

Удаление файла в NTFS:
1. Запись MFT помечается как свободная (flag `0x01` снимается → `0x00`), **данные кластеров не затираются**.
2. Номер записи попадает в список свободных и может быть **переиспользован** (тогда sequence number растёт).
3. Имя из `$FILE_NAME` может сохраниться, если запись не переиспользована.

```bash
# Все удалённые записи (fls -d показывает только удалённые)
fls -r -d -o <offset> disk.img
# Читать содержимое по удалённому inode, пока кластеры не перезаписаны
icat -o <offset> disk.img <deleted_inode> > recovered.bin
file recovered.bin

# analyzeMFT / MFTECmd по сырому $MFT
icat -o <offset> disk.img 0 > MFT.bin
analyzeMFT.py -f MFT.bin -o mft.csv -c
# MFTECmd (Windows): MFTECmd.exe -f MFT.bin --csv out --deleted
```

Если запись переиспользована, восстановить имя нельзя, но данные кластеров — можно, если на них ещё нет новых данных (carving по unallocated).

## Разобранный пример: CTF «удалённый секрет»

```bash
file challenge.img                  # NTFS volume
mmls challenge.img                  # Start Sector = 2048
OFF=2048

# 1. Инфо о ФС и её параметрах
fsstat -o $OFF challenge.img | head -40

# 2. Ищем удалённые записи
fls -r -d -o $OFF challenge.img
#  r/r * 42-128-1: secret.txt

# 3. Читаем содержимое (кластеры ещё не перезаписаны)
icat -o $OFF challenge.img 42-128-1 > secret.bin
file secret.bin; strings secret.bin | grep -i flag

# 4. Не нашли? Смотрим ADS и журнал
fls -r -o $OFF challenge.img | grep ':'
icat -o $OFF challenge.img 2 > LogFile.bin
# парсим LogFileParser.exe -> ищем Rename/Delete

# 5. USN: имя + время операции
icat -o $OFF challenge.img <usn_inode> > usn.bin
usnparser parse usn.bin | grep -i secret
```

## Частые ошибки

- **Монтировать образ read-write** — NTFS запишет `$LogFile`/`$UsnJrnl`, и вы потеряете улики. Только `-o ro,loop` или работа через sleuthkit напрямую.
- **Путать `-o` (offset раздела в секторах) с байтами** — `fls`/`icat` ждут **секторы**, `mount offset=` — **байты**.
- **Искать только `fls` без `-r`** — потоки ADS и удалённые записи в подкаталогах не видны.
- **Считать, что `$FILE_NAME`-времена всегда правдивы** — антифорензика (timestomp) меняет `$STANDARD_INFORMATION`; сверяйте оба набора времён.
- **Игнорировать sequence number** — два разных файла могут делить один номер записи.
- **Забывать про кольцевой характер `$UsnJrnl`** — старые записи вытесняются, но остаются как «sparse» в `$J`.

## Квиз

```quiz
- question: "Что означает сигнатура `FILE` в начале записи MFT?"
  options:
    - "запись MFT занята (in-use)"
    - "запись удалена"
    - "это каталог"
    - "это ADS"
  answer: 0
- question: "Какой файл NTFS хранит журнал изменений имён и операций с файлами?"
  options:
    - "`$MFT`"
    - "`$UsnJrnl`"
    - "`$Bitmap`"
    - "`$Boot`"
  answer: 1
- question: "Как в sleuthkit отображается Alternate Data Stream?"
  options:
    - "как отдельный раздел"
    - "как запись с `:` в имени (например `secret.txt:hidden.txt`)"
    - "как `$LogFile`"
    - "как удалённый inode"
  answer: 1
- question: "Что произойдёт с данными файла при удалении в NTFS?"
  options:
    - "кластеры немедленно затираются нулями"
    - "запись MFT помечается свободной, но кластеры не затираются"
    - "файл переезжает в `$Recycle.Bin`"
    - "данные сжимаются"
  answer: 1
- question: "Чем `$UsnJrnl` отличается от `$LogFile`?"
  options:
    - "`$LogFile` хранит историю имён/операций, `$UsnJrnl` — транзакции метаданных"
    - "`$UsnJrnl` хранит хронологию операций с именами, `$LogFile` — транзакции метаданных"
    - "это одно и то же"
    - "`$UsnJrnl` — это раздел диска"
  answer: 1
```

## Где пригодится

- **CTF:** задачи с образами Windows — удалённые файлы, ADS, переименования.
- **Incident Response:** восстановление хронологии действий атакующего на хосте.
- **Threat Hunting:** поиск подозрительных имён и операций в `$UsnJrnl`.
- **Судебная экспертиза:** доказательство удаления/переименования файлов.
- **Разработка детектов:** сигнатуры по причинам USN (FILE_DELETE, RENAME_NEW_NAME).
