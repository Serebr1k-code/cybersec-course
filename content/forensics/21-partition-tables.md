---
id: forensics-partition-tables
title: "Таблицы разделов: MBR и GPT"
category: forensics
parent: forensics-fs-structure
difficulty: medium
order: 1
tags: [mbr, gpt, partition, gdisk, parted, fdisk, sleuthkit]
prerequisites: [forensics-filesystems]
useful_for:
  - "CTF Forensics категория"
  - "Data recovery"
  - "Анализ образов дисков"
estimated_minutes: 35
summary: "Устройство MBR и GPT, разбор таблиц разделов, восстановление потерянных разделов и работа с образами через mmls/parted/gdisk."
---
Таблица разделов описывает, как диск разбит на области. В форензике умение читать MBR и GPT критично: повреждённая таблица скрывает данные, а восстановление потерянных разделов возвращает доступ к уликам. Этот урок — про устройство MBR и GPT, разбор через `mmls`, `parted`, `gdisk`, `fdisk`, и восстановление потерянных разделов.

## MBR: сектор 0

**MBR** (Master Boot Record) занимает первый сектор (512 байт): 446 байт кода загрузчика + 4 записи первичных разделов по 16 байт + сигнатура `55 AA`. Каждая запись:

| Смещение | Размер | Поле |
|----------|--------|------|
| 0x00 | 1 | флаг загрузки (0x80 = active) |
| 0x01 | 3 | CHS начала |
| 0x04 | 1 | тип раздела (0x83 Linux, 0x07 NTFS, 0x0B FAT32, 0x8E LVM) |
| 0x05 | 3 | CHS конца |
| 0x08 | 4 | LBA начала (сектор) |
| 0x0C | 4 | число секторов |

Ограничение MBR — 4 первичных раздела и адресация до 2 ТиБ. Расширение — **расширенный раздел** (тип 0x05/0x0F) с цепочкой логических (EBR).

```bash
$ xxd -l 64 disk.img
00000000: 33c0 8ed0 bc00 7c8e c08e d8be 007c bf00  3.....|......|..
...
000001b0: 0000 0000 0000 0000 0000 0000 0000 80    ...............
000001c0: 0101 0083 fe3f 2000 0000 0800 0000 00    .....? .........
000001f0: 0000 0000 0000 0000 0000 0000 0000 55aa  ..............U.
```

`55 AA` в конце сектора подтверждает MBR; `80` — активный раздел; `83` — Linux.

## GPT: современная таблица

**GPT** (GUID Partition Table) — часть UEFI. Сектор 0 — protective MBR (тип 0xEE), сектор 1 — GPT-заголовок (с CRC32), далее массив записей разделов (обычно 128 × 128 байт). В конце диска — **резервная копия** GPT (backup), что позволяет восстановить таблицу при повреждении начала.

Заголовок GPT (LBA1) содержит: сигнатуру `EFI PART`, размер, CRC заголовка, текущий/резервный LBA, число записей, размер записи, CRC массива записей. Запись раздела: GUID типа, GUID раздела, первый/последний LBA, атрибуты, имя (UTF-16).

```bash
$ gdisk -l disk.img
GPT fdisk (gdisk) version 1.0.9
Disk /dev/loop0: 41943040 sectors, 20.0 GiB
...
Number  Start (sector)    End (sector)  Size       Code  Name
   1            2048         1050623   512.0 MiB   EF00  EFI system
   2         1050624        41940991   19.5 GiB    8300  Linux filesystem
```

## mmls: обзор через Sleuth Kit

```bash
$ mmls disk.img
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors
      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:00    0000002048   0000215039   0000212992   NTFS / exFAT (0x07)
003:  000:01    0000215040   0000419839   0000204800   Linux (0x83)
```

`mmls` показывает и MBR, и GPT, и offset каждого раздела (в секторах) — именно это значение вы передаёте в `fsstat -o`/`fls -o`.

## parted / fdisk / gdisk

```bash
$ parted disk.img unit s print
$ fdisk -l disk.img                 # MBR
$ gdisk -l disk.img                 # GPT (и конвертация)
$ sfdisk -d disk.img > layout.txt   # дамп/восстановление разметки
$ sfdisk disk.img < layout.txt      # восстановить
```

`sfdisk` умеет сохранять и восстанавливать таблицу из текстового дампа — удобно для клонирования и починки.

## Восстановление потерянных разделов

Приёмы восстановления:
1. **Резервная GPT.** `gdisk` предлагает «Recovery/transformation options» и находит backup GPT в конце диска.
2. **Сигнатуры ФС.** `testdisk` сканирует по сигнатурам (NTFS `$MFT`, ext4 superblock, FAT) и предлагает найденные разделы.
3. **Superblock-бэкапы ext4** — `dumpe2fs` показывает резервные superblock, `e2fsck -b` восстанавливает.
4. **Ручной поиск** — `grep -aboP` по сигнатурам (`\x55\xaa` в MBR-секторах, `EFI PART` для GPT, `NTFS    ` для NTFS).

```bash
$ testdisk disk.img          # Analyse → Quick Search → Deeper Search → Write
$ gdisk disk.img             # r (recovery) → b (backup GPT) → w
$ grep -aboP 'EFI PART' disk.img | head
```

## Разобранный пример

Дан `damaged.img`, где GPT в начале разрушен, но данные целы.

```bash
$ mmls damaged.img
Cannot determine partition type
$ xxd -l 16 damaged.img
00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

Начало занулено, но backup GPT в конце может быть цел. Проверим конец диска:

```bash
$ xxd -s -512 damaged.img | tail -2
...
000001b0: ... 4546 4920 5041 5254 ...            EFI PART
```

`gdisk` восстановит из резервной копии:

```bash
$ gdisk damaged.img
Command (? for help): r
Recovery/transformation command (? for help): b
Recovery/transformation command (? for help): w
$ mmls damaged.img
GUID Partition Table (EFI)
002:  000:00    0000002048   0000206847   0000204800   Linux (0x83)
```

Теперь раздел читается: `fsstat -o 2048 damaged.img`.

## Справочная таблица

| Тип MBR | Значение |
|---------|----------|
| 0x07 | NTFS / exFAT |
| 0x0B | FAT32 (CHS) |
| 0x0C | FAT32 (LBA) |
| 0x83 | Linux |
| 0x82 | Linux swap |
| 0x8E | Linux LVM |
| 0x05/0x0F | расширенный (EBR) |
| 0xEE | GPT protective MBR |

| Инструмент | Задача |
|-----------|--------|
| `mmls` | обзор разделов (TSK) |
| `parted`/`fdisk` | MBR-разметка |
| `gdisk` | GPT + восстановление |
| `sfdisk` | дамп/восстановление |
| `testdisk` | поиск потерянных разделов |
| `xxd` | ручной разбор сектора 0 |

## Частые ошибки

- **Путать LBA-секторы и байты.** `fsstat -o` — секторы; `mount offset=` — байты.
- **Игнорировать backup GPT.** При разрушенном начале разделы часто восстанавливаются из конца.
- **Писать на образ.** `testdisk`/`gdisk` могут писать — работайте с копией.
- **Не проверять CRC заголовка GPT** — «валидный» на вид заголовок может быть битым.
- **Забывать про расширенные разделы** — логические тома лежат в EBR-цепочке.
- **Считать, что `fdisk` видит GPT** — используйте `gdisk`/`parted`.

## Что дальше / решение

Прочитайте сектор 0 (`xxd`), определите тип (MBR/GPT), получите offset (`mmls`), разберите ФС (`fsstat`). При повреждении — backup GPT (`gdisk r b`), `testdisk`, поиск сигнатур. Связка: `forensics-filesystems` (структуры ФС), `forensics-disk-images` (монтирование), `forensics-fs-structure` (внутренности).

## Protective MBR и гибридные схемы

GPT-диск содержит **protective MBR** в секторе 0 — одну запись типа `0xEE`, покрывающую весь диск. Это нужно, чтобы старые инструменты, читающие только MBR, не «портили» GPT, приняв его за пустое место. Признак GPT-диска: запись `0xEE` в MBR плюс `EFI PART` в секторе 1.

```bash
$ xxd -l 512 disk.img | grep -A1 '1c0:'
000001c0: 0100 ee3f ...   # тип 0xEE = protective MBR
```

**Гибридный MBR** (hybrid MBR) — нестандартная схема, где protective MBR дополнен реальными записями для legacy-загрузчиков (часто при dual-boot). Это риск: правка одной таблицы не синхронизируется с другой, и разделы могут «пропадать».

```bash
$ gdisk disk.img
Command: p   # покажет, есть ли гибридные записи (hybrid MBR)
```

## Восстановление через superblock и сигнатуры

Если и MBR, и GPT утеряны, разделы находят по сигнатурам файловых систем:

- **ext4**: резервные superblock (`dumpe2fs` перечисляет их), `e2fsck -b 32768`.
- **NTFS**: `$MFT` начинается с сигнатуры `46 49 4C 45` (`FILE`); `ntfsfix`/`testdisk` находят.
- **FAT**: загрузочный сектор с `FAT32`/`FAT16` и `55 AA`.
- **XFS/Btrfs/ZFS**: собственные суперблоки в известных местах.

```bash
$ grep -aboP 'FILE' disk.img | head          # кандидаты NTFS $MFT
$ grep -aboP '\x53\xEF' disk.img | head      # ext superblock magic (0xEF53)
$ testdisk disk.img                          # интерактивный поиск
```

## Резервное копирование таблицы

Перед любыми правками сохраните исходную таблицу — это и улика, и страховка:

```bash
$ dd if=disk.img of=mbr.bak bs=512 count=1 status=none
$ sfdisk -d disk.img > layout.txt
$ gdisk -b gpt.bin disk.img      # backup GPT в файл
```

При восстановлении можно вернуть ровно сохранённое состояние, а не подбирать заново.

## Квиз

```quiz
- question: "Где расположен GPT-заголовок?"
  options:
    - "LBA 0"
    - "LBA 1 (offset 512)"
    - "в конце диска только"
    - "offset 1024"
  answer: 1
- question: "Что означает тип раздела `0x83` в MBR?"
  options:
    - "NTFS"
    - "Linux"
    - "EFI System"
    - "FAT32"
  answer: 1
- question: "Какая утилита показывает карту разделов образа?"
  options:
    - "`fls`"
    - "`mmls`"
    - "`icat`"
    - "`xxd`"
  answer: 1
- question: "На сколько байт внутрь раздела от его начала лежит ext4-суперблок?"
  options:
    - "0"
    - "1024"
    - "512"
    - "2048"
  answer: 1
- question: "Как восстановить GPT при повреждённом основном заголовке?"
  options:
    - "удалить образ"
    - "`gdisk` -> recovery -> rebuild из backup-копии"
    - "`unzip`"
    - "`binwalk -e`"
  answer: 1
```

## Где пригодится

- **CTF:** образы со скрытыми/битыми разделами.
- **Data recovery:** восстановление карты разделов после сбоя.
- **Incident Response:** понимание структуры диска до анализа ФС.
- **Криминалистика:** работа с нестандартными раскладками.
- **Виртуализация:** конвертация и разбор виртуальных дисков.
