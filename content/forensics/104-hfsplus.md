---
id: forensics-hfsplus
title: "HFS+: volume header, catalog B-tree и resource forks"
category: forensics
parent: forensics-fs-family
difficulty: hard
order: 4
tags: [hfs, hfsplus, macos, btree, resource-fork, journal]
prerequisites: [forensics-filesystems]
useful_for:
  - "CTF Forensics категория"
  - "Анализ образов macOS"
  - "Data recovery"
estimated_minutes: 52
summary: "Устройство HFS+: volume header, B-дерево каталога (catalog file), extents overflow, resource forks и journal — разбор macOS-образов и восстановление данных."
---

HFS+ (Hierarchical File System Plus, он же HFS Extended) — файловая система macOS до появления APFS (2017). Она до сих пор встречается на внешних дисках, Time Machine-бэкапах (HFS+ до перехода на APFS) и старых Mac. Для форензика важны две особенности: **почти вся структура — B-деревья**, а метаданные файла разделены на **data fork** и **resource fork** (историческое наследие классического Mac OS).

## Volume header

HFS+ не занимает весь раздел: первые 1024 байта — загрузочный блок, затем **volume header** (offset 1024). Магия — `H+` (0x482B), для HFSX — `HX`.

| Смещение | Размер | Поле |
|---------:|-------:|------|
| 0x00 | 2 | signature `H+` |
| 0x02 | 2 | version (4) |
| 0x04 | 4 | attributes |
| 0x08 | 4 | lastMountedVersion |
| 0x0C | 4 | journalInfoBlock |
| 0x10 | 4 | createDate (Mac epoch, 1904) |
| 0x14 | 4 | modifyDate |
| 0x18 | 4 | backupDate |
| 0x1C | 4 | checkedDate |
| 0x20 | 4 | fileCount |
| 0x24 | 4 | folderCount |
| 0x28 | 4 | blockSize |
| 0x2C | 4 | totalBlocks |
| 0x30 | 4 | freeBlocks |
| 0x34 | 4 | nextAllocation |
| 0x38 | 4 | rsrcClumpSize |
| 0x3C | 4 | dataClumpSize |
| 0x40 | 4 | nextCatalogID |
| 0x44 | 4 | writeCount |
| 0x48 | 8 | encodingsBitmap |
| 0x50 | 8 | finderInfo |
| 0x70 | 80 | allocationFile (fork) |
| 0xC0 | 80 | extentsFile (fork) |
| 0x110 | 80 | catalogFile (fork) |
| 0x160 | 80 | attributesFile (fork) |
| 0x1B0 | 80 | startupFile (fork) |

Каждый **fork descriptor** (80 байт) содержит logicalSize, clumpSize, totalBlocks и массив из 8 **extent descriptors** (startBlock + blockCount). Если файл длиннее 8 extents, остальные — в extents overflow B-дереве.

## B-деревья: catalog, extents, attributes

Четыре системных B-дерева:

| B-дерево | Назначение |
|----------|-----------|
| Catalog | иерархия файлов/каталогов, имена, inode (CNID) |
| Extents Overflow | дополнительные extents для больших/фрагментированных файлов |
| Attributes | расширенные атрибуты и **xattr**, включая «Resource Fork» как атрибут |
| Allocation | битовая карта занятости блоков |

Заголовок B-дерева (BTNode): signature `BT` (0x4254), nodeSize, rootNode, leafRecords, firstLeafNode, lastLeafNode, nodeCount, freeNodes, height. Узлы бывают header, index, leaf, map.

**Каталог (catalog)**: leaf-запись типа `recordType=1` (folder), `2` (file), `3` (folder thread), `4` (file thread). Запись файла содержит **CNID** (Catalog Node ID — аналог inode), timestamps, permissions, а также **data fork** и **resource fork** descriptors.

**Resource fork** — отдельный поток данных (иконки, метаданные приложений, иногда скрытые полезные нагрузки). В HFS+ (в отличие от классики) resource fork хранится как **xattr** в Attributes B-дереве.

## Инструменты и флаги

```bash
# Параметры ФС
fsstat -o <offset> disk.img | head -30

# Листинг/восстановление
fls -o <offset> -r disk.img
fls -o <offset> -r -d disk.img
icat -o <offset> disk.img <CNID> > out.bin
# Чтение конкретного потока (resource fork): icat с суффиксом потока
icat -o <offset> disk.img <CNID>:<attrname> > rsrc.bin

# Монтирование read-only (Linux, hfsplus)
sudo mount -t hfsplus -o ro,loop,offset=<bytes> disk.img /mnt/hfs
# xattr (resource fork) виден как атрибут
getfattr -d /mnt/hfs/file

# Специализированные инструменты
hfsdebug disk.img            # разбор HFS/HFS+
hfsutils (hls, hcopy)        # старый, но полезен
```

## Разобранный пример: resource fork с флагом

```bash
$ fsstat -o 63 disk.img | sed -n '1,12p'
FILE SYSTEM INFORMATION
File System Type: HFS+
Block Size: 4096
$ fls -o 63 -r disk.img | grep -i secret
r/r 23: secret.txt
$ icat -o 63 disk.img 23 > data.bin
$ strings data.bin
nothing to see here
$ fls -o 63 -r -p disk.img | grep '23'
# видим поток "com.apple.ResourceFork"
$ icat -o 63 disk.img '23:com.apple.ResourceFork' > rsrc.bin
$ strings rsrc.bin
flag{hfs_resource_fork}
```

Флаг лежал в resource fork — если смотреть только data fork, он не виден. `fls -p` показывает имена потоков/атрибутов.

## Краевые случаи и подводные камни

- **Mac epoch.** HFS+ считает время от 1904-01-01 (не 1970). При переводе в Unix epoch: вычесть 2082844800 секунд.
- **Volume header на offset 1024.** Не 0 — не спутайте с MBR/загрузочным блоком.
- **Resource fork как xattr.** В HFS+ это атрибут `com.apple.ResourceFork`; в классическом HFS — отдельная структура. `fls -p` обязателен.
- **Extents overflow.** Файл с >8 extents хранит остальные в B-дереве; sleuthkit обычно склеивает автоматически, но при ручном разборе это отдельный шаг.
- **Case sensitivity.** HFS+ по умолчанию **case-insensitive**, HFSX — case-sensitive. Это влияет на поиск по имени.
- **Журнал.** `journalInfoBlock` указывает на журнал; после аварийного отключения он может содержать актуальные (ещё не сброшенные) метаданные — источник удалённых записей.
- **Hard links на macOS.** Каталоги с hard links используют «file threads» и link IDs; обычный `fls` может показать странные имена.
- **Compression (decmpfs).** На macOS файлы могут быть сжаты прозрачно; data fork содержит метаданные сжатия, а не данные. Нужен `decmpfs`/`afscexpand`.
- **Unicode-нормализация.** Имена хранятся в decomposed UTF-16; поиск по «нормальному» имени может не сработать.

## Особенности HFS+ для аналитика

HFS+ — продукт эпохи, когда Mac OS использовала двойную структуру файла: **data fork** (содержимое) и **resource fork** (иконки, метаданные, иногда код). В HFS+ resource fork превратился в расширенный атрибут, но привычка приложений хранить данные в нём осталась. Это создаёт классическую ловушку: вы читаете data fork, видите безобидный текст, а флаг лежит в resource fork.

Второй важный момент — **всё на B-деревьях**. Каталог (catalog file), карта extents (extents overflow), атрибуты (attributes) и занятость блоков (allocation) — каждое отдельное B-дерево с общим форматом узлов (`BTNode`). Понимая этот формат один раз, вы читаете все четыре.

## Формат узла B-дерева

| Смещение | Размер | Поле |
|---------:|-------:|------|
| 0x00 | 4 | fLink (следующий узел) |
| 0x04 | 4 | bLink (предыдущий) |
| 0x08 | 1 | kind (-1 leaf, 0 index, 1 header, 2 map) |
| 0x09 | 1 | height |
| 0x0A | 2 | numRecords |
| 0x0C | 2 | reserved |
| 0x0E | 2 | offsets[numRecords+1] |

Записи лежат с конца узла; таблица смещений — от offset 0x0E. Leaf-записи каталога имеют ключ (parentID + имя) и данные (CNID, timestamps, forks).

Типы записей каталога:
- `1` — folder record (каталог)
- `2` — file record (файл)
- `3` — folder thread (обратная ссылка)
- `4` — file thread

`recordType=2` содержит `fileID` (CNID), `createDate`, `contentModDate`, `attributeModDate`, `accessDate`, `backupDate`, permissions и два fork-дескриптора.

## Работа с потоками и xattr

```bash
# Показать потоки/атрибуты (важно для resource fork)
fls -o <offset> -r -p disk.img | grep -i resource
# Извлечь data fork
icat -o <offset> disk.img <CNID> > data.bin
# Извлечь resource fork как атрибут
icat -o <offset> disk.img '<CNID>:com.apple.ResourceFork' > rsrc.bin
# Другие атрибуты
icat -o <offset> disk.img '<CNID>:com.apple.metadata:kMDItemWhereFroms' > where.bin
```

Атрибут `kMDItemWhereFroms` хранит URL, откуда файл скачан — аналог Zone.Identifier в Windows. Он часто остаётся, даже если файл переместили.

## Сжатие decmpfs

macOS прозрачно сжимает файлы (decmpfs), особенно системные и скачанные. В этом случае data fork содержит не данные, а **заголовок сжатия** (`cmpf`) и сжатый поток. Признаки:

- атрибут `com.apple.decmpfs` присутствует;
- data fork начинается с `cmpf`;
- алгоритмы: zlib (тип 3/4), LZVN (7/8), LZFSE (11/12).

```bash
# Определить сжатие
xxd -l 16 <(icat -o <offset> disk.img <CNID>)   # ищите 'cmpf'
# Распаковать (на macOS) через afscexpand / ditto, на Linux — спец-скриптами
```

## Журнал и восстановление

`journalInfoBlock` в volume header указывает на журнал. После аварийного отключения журнал может содержать не сброшенные метаданные: свежие записи каталога, ещё не отражённые в основном B-дереве. Для recovery удалённых файлов это иногда единственный источник.

```bash
hfsdebug disk.img | head -60        # volume header + journal info
# После пересборки B-дерева из журнала — обычный fls/icat
```

## Типичные ошибки

- **Игнорирование resource fork** — самая частая ошибка в CTF с macOS-образами.
- **Mac epoch** — времена HFS+ отсчитываются от 1904-01-01; не забывайте про сдвиг 2082844800 с.
- **Case-insensitivity** — HFS+ обычно регистронезависима; поиск по имени может «не найти» из-за нормализации Unicode (NFD vs NFC).
- **decmpfs** — считать data fork сжатого файла «данными» бессмысленно.
- **Hard links** — на macOS каталоги с hard links используют file threads; `fls` может показать необычные имена.
- **Монтирование** — только read-only; Linux-драйвер `hfsplus` писал в журнал, поэтому образ снимают до монтирования.

## Что дальше / решение

1. `fsstat` — block size и число блоков.
2. `fls -r -p` — список файлов **вместе с потоками** (важно для resource fork).
3. `icat <CNID>:<attr>` — читать data и resource fork отдельно.
4. `hfsdebug` — если нужно заглянуть в volume header и B-деревья.
5. Учесть decmpfs для сжатых файлов; при необходимости `afscexpand`.

Дальше — `forensics-apfs` (современная macOS-ФС) и `forensics-macos-artifacts` (артефакты самой ОС).

## Квиз

```quiz
- question: "Где в HFS+ лежит volume header?"
  options:
    - "по offset 0"
    - "по offset 1024"
    - "в конце тома"
    - "в MFT"
  answer: 1
  explanation: "Первые 1024 байта — загрузочный блок, затем volume header с магией H+."
- question: "Что такое resource fork в HFS+?"
  options:
    - "дополнительный поток данных (в HFS+ хранится как xattr)"
    - "основное содержимое файла"
    - "таблица разделов"
    - "журнал ФС"
  answer: 0
  explanation: "Resource fork — исторически отдельный поток (иконки, метаданные), в HFS+ реализован как расширенный атрибут."
- question: "От какой даты HFS+ отсчитывает время?"
  options:
    - "1970-01-01"
    - "1904-01-01"
    - "1601-01-01"
    - "2000-01-01"
  answer: 1
  explanation: "Mac epoch — 1904; для перевода в Unix epoch вычитают 2082844800 секунд."
- question: "Какое B-дерево HFS+ хранит иерархию файлов и их CNID?"
  options:
    - "Extents Overflow"
    - "Catalog"
    - "Allocation"
    - "Attributes"
  answer: 1
  explanation: "Catalog B-tree описывает файлы/каталоги, имена и CNID (аналог inode)."
```

## Где пригодится

- **CTF:** образы macOS и внешних HFS+-дисков.
- **DFIR:** разбор Time Machine и старых Mac.
- **Data recovery:** восстановление data/resource fork.
- **Судебная экспертиза:** доказательство сокрытия данных в resource fork.
