---
id: forensics-filesystems
title: "Файловые системы: ext4, FAT, NTFS"
category: forensics
parent: forensics-archives
difficulty: medium
order: 1
tags: [filesystem, ext4, fat, ntfs, sleuthkit, superblock]
prerequisites: [forensics-archives]
useful_for:
  - "CTF Forensics категория"
  - "Data recovery"
  - "Анализ образов дисков"
estimated_minutes: 40
summary: "Устройство основных файловых систем, разбор образов через sleuthkit и testdisk, поиск скрытых и удалённых файлов."
---
Файловая система — это структура, которая превращает сырые блоки диска в файлы и каталоги. В форензике понимание ФС критично: именно на этом уровне находятся удалённые файлы, slack-пространство, журналы и метаданные, которых нет в обычном «дереве». Этот урок разбирает устройство ext4, FAT и NTFS, работу с образами через Sleuth Kit и testdisk, а также поиск скрытых и удалённых данных.

## Три семейства и их философия

**ext4** (Linux) — журналируемая ФС с inode-таблицей: метаданные (права, времена, блоки) хранятся в inode, а имя — в записи каталога. **FAT** (removable, embedded) — простая таблица размещения кластеров, имена в записях каталога (8.3 + LFN), нет прав и журнала. **NTFS** (Windows) — таблица `$MFT`, где каждая запись описывает файл и его атрибуты, плюс журнал `$UsnJrnl` и `$LogFile`.

| Свойство | ext4 | FAT32 | NTFS |
|----------|------|-------|------|
| Метаданные | inode | запись каталога | MFT-запись |
| Журнал | `jbd2` (журнал inode) | нет | `$LogFile`, `$UsnJrnl` |
| Удаление | inode помечается, блоки free | первый байт имени `0xE5` | MFT-флаг + USN |
| Права | POSIX | нет | ACL |
| Таймстемпы | a/m/c + crtime | a/m/c (FAT, локальное время) | 4 набора (SI/FN) |

## Sleuth Kit: разбор образа

Утилиты TSK работают на уровне ФС, не монтируя образ. Все принимают `-o <offset>` в **секторах**.

```bash
# 1. Таблица разделов
$ mmls disk.img
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors
      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:00    0000002048   0000206847   0000204800   Linux (0x83)
```

```bash
OFF=2048
# 2. Параметры ФС
$ fsstat -o $OFF disk.img | head -25
File System Type: Ext4
Block Size: 4096
Inode Size: 256
...
# 3. Файлы (включая удалённые, -d)
$ fls -r -p -o $OFF disk.img
$ fls -r -d -o $OFF disk.img         # только удалённые
# 4. Метаданные inode
$ istat -o $OFF disk.img 12
# 5. Извлечь по inode
$ icat -o $OFF disk.img 12 > file.bin
# 6. Найти inode по имени
$ ifind -o $OFF -n "flag.txt" disk.img
```

## FAT: записи каталога и LFN

В FAT нет inode — файл описан 32-байтовой записью каталога: имя (8.3), атрибуты, кластер, размер, время. Длинные имена (LFN) хранятся в отдельных записях с атрибутом `0x0F`. Удалённый файл — запись с первым байтом имени `0xE5`; цепочка кластеров может остаться в FAT.

```bash
$ fls -o $OFF fat.img            # покажет d/d  (удалённые) записи
$ icat -o $OFF fat.img 5 > rec.bin
```

`fatcat` — удобная альтернатива:

```bash
$ fatcat fat.img -l                    # листинг
$ fatcat fat.img -r /deleted.txt       # восстановить
```

## NTFS: MFT, атрибуты, alternate data streams

NTFS хранит файл в записи `$MFT` (1024 байта) с набором атрибутов: `$STANDARD_INFORMATION` (таймстемпы, флаги), `$FILE_NAME` (имя, ещё таймстемпы), `$DATA` (содержимое), `$ATTRIBUTE_LIST` и т. д. **Alternate Data Streams (ADS)** — дополнительные `$DATA`-потоки, часто используемые для сокрытия (`file.txt:secret:$DATA`).

```bash
# список записей MFT (fls показывает и $MFT-номера)
$ fls -o $OFF -p ntfs.img
# извлечь файл и его ADS
$ icat -o $OFF ntfs.img 42 > file.bin
$ icat -o $OFF ntfs.img 42-128-3 > ads.bin     # ADS по номеру атрибута
# анализ MFT напрямую
$ analyzeMFT.py -f \$MFT -o mft.csv
$ mft2csv \$MFT > mft.csv
```

## Монтирование: только чтение

Монтировать образ можно, но **только read-only**, чтобы не менять улику. Для NTFS используйте `ntfs-3g`/`ntfsundelete`, для ext4 — `debugfs`, для всего — `guestmount`.

```bash
# read-only loop-монтирование
$ sudo mount -o ro,loop,offset=$((OFF*512)) disk.img /mnt/img
# ext4 без монтирования (интерактивная оболочка)
$ sudo debugfs -R "ls -l /" disk.img
$ sudo debugfs -R "cat /home/user/flag.txt" disk.img
# FUSE-монтирование (не требует root, read-only)
$ guestmount -a disk.img -m /dev/sda1 --ro /mnt/img
$ umount /mnt/img
```

## testdisk и photorec

`testdisk` восстанавливает потерянные разделы и загрузочные секторы; `photorec` — carving-восстановление файлов (работает, даже если ФС разрушена).

```bash
$ testdisk disk.img          # интерактивно: Analyse → Quick Search → Write
$ photorec disk.img          # выбор типов файлов, извлечение
```

`photorec` игнорирует ФС и режет по сигнатурам — дополняет `foremost`.

## Скрытые данные: slack и unallocated

- **File slack** — остаток последнего кластера файла (от логического конца до границы кластера).
- **Volume slack** — пространство между концом ФС и концом раздела.
- **Unallocated** — свободные блоки (бывшее содержимое удалённых файлов).

```bash
# дамп нераспределённых блоков
$ blkls -o $OFF disk.img > unalloc.bin
# дамп только allocated
$ blkls -o $OFF -a disk.img > alloc.bin
# дамп slack (по inode)
$ icat -o $OFF -s disk.img 12 > slack.bin
# поиск строк в unallocated
$ strings -n 8 unalloc.bin | grep -iE 'flag|password'
```

## Разобранный пример

Дан `usb.img` (FAT32) с удалённым файлом.

```bash
$ mmls usb.img
002:  000:00  0000000064  0000039999  FAT32 (0x0b)
$ OFF=64
$ fsstat -o $OFF usb.img | head -5
File System Type: FAT32
$ fls -r -d -o $OFF usb.img
r/r * 12: deleted_flag.txt
$ icat -o $OFF usb.img 12
CTF{fat_is_simple}
```

Если `icat` пуст (кластеры переиспользованы), ищем в unallocated:

```bash
$ blkls -o $OFF usb.img | strings -n 6 | grep -i 'CTF{'
CTF{fat_is_simple}
```

## Справочная таблица команд

| Задача | ext4 | FAT | NTFS |
|--------|------|-----|------|
| Разделы | `mmls` | `mmls` | `mmls` |
| Параметры | `fsstat` | `fsstat` | `fsstat` |
| Список | `fls -r` | `fls -r` | `fls -r` |
| Удалённые | `fls -d` | `fls -d` | `fls -d` |
| Извлечь | `icat` | `icat` | `icat` |
| Метаданные | `istat` | `fls -l` | `istat` |
| Восстановление | `extundelete` | `fatcat` | `ntfsundelete` |
| Монтирование | `debugfs` | `mount -t vfat` | `ntfs-3g` |

## Частые ошибки

- **Путать секторы и байты.** `-o` у TSK — секторы; `mount offset=` — байты.
- **Монтировать rw.** Любая запись меняет улику; всегда `ro`.
- **Забывать `-d`.** Удалённые файлы не видны в обычном `fls`.
- **Игнорировать ADS в NTFS** — секрет может быть в потоке, а не в `$DATA`.
- **Не проверять unallocated**, когда `icat` пуст.
- **Считать, что `fls` показывает всё** — без `-r` нет рекурсии, без `-p` нет полных путей.

## Что дальше / решение

Определите ФС (`fsstat`), затем идите по уровням: разделы (`forensics-partition-tables`), удалённые файлы (`forensics-deleted-recovery`), MFT и NTFS-внутренности (`forensics-ntfs-mft`), журналы ext4 (`forensics-ext4-journal`), APFS/HFS+ (`forensics-apfs`). Базовый конвейер: `mmls` → `fsstat` → `fls -r -p` → `icat`/`tsk_recover` → `strings`/`grep` по извлечённому.

## Квиз

```quiz
- question: "Какая утилита показывает таблицу разделов образа?"
  options:
    - "`fls`"
    - "`mmls`"
    - "`icat`"
    - "`exiftool`"
  answer: 1
- question: "Что означает флаг `*` в выводе `fls`?"
  options:
    - "системный файл"
    - "удалённый файл"
    - "каталог"
    - "сжатый"
  answer: 1
- question: "Как извлечь файл по inode в sleuthkit?"
  options:
    - "`dd`"
    - "`icat -o <offset> img <inode>`"
    - "`unzip`"
    - "`foremost`"
  answer: 1
- question: "Где в ext4 находится суперблок?"
  options:
    - "offset 0"
    - "offset 1024, magic `53 EF`"
    - "offset 512"
    - "в конце образа"
  answer: 1
- question: "Что такое ADS в NTFS?"
  options:
    - "дополнительный раздел"
    - "Alternate Data Stream — скрытый поток файла"
    - "алгоритм сжатия"
    - "журнал"
  answer: 1
```

## Где пригодится

- **CTF:** образы дисков, удалённые файлы, slack space.
- **Data recovery:** восстановление после сбоя/удаления.
- **Incident Response:** анализ диска скомпрометированного хоста.
- **Криминалистика:** поиск следов и скрытых данных.
- **Судебная экспертиза:** доказательство наличия/отсутствия файлов.
