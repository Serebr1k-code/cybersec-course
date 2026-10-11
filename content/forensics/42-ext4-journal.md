---
id: forensics-ext4-journal
title: "ext4 изнутри: журнал, inode, extent-дерево"
category: forensics
parent: forensics-fs-internals
difficulty: hard
order: 2
tags: [ext4, journal, jbd2, inode, extent, debugfs, ext4magic]
prerequisites: [forensics-filesystems]
useful_for:
  - "CTF Forensics категория"
  - "Data recovery (Linux)"
  - "Анализ образов Linux"
estimated_minutes: 55
summary: "Глубокий разбор ext4: суперблок и группы блоков, inode и extent-дерево, журнал JBD2 и восстановление удалённых файлов, работа с debugfs и ext4magic."
---

ext4 — файловая система по умолчанию на большинстве Linux-хостов, и в CTF-задачах она встречается чаще всего. Поверхностного `fls`/`icat` из прошлого урока достаточно для простых случаев, но когда нужно **восстановить недавно удалённый файл**, **прочитать журнал** или понять, куда указывает extent-дерево, нужны внутренности: суперблок, группы блоков, inode и журнал JBD2. Этот урок — про них.

## Устройство ext4

ext4 делит том на **группы блоков** (block groups). Каждая группа имеет копию суперблока, таблицу групповых дескрипторов, битмапы блоков и inode, таблицу inode и область данных.

Ключевые структуры:

| Структура | Где | Назначение |
|-----------|-----|-----------|
| Суперблок | offset 1024, magic `0xEF53` | размеры, число групп, фичи |
| Group Descriptor | после суперблока | где битмапы/inode-таблицы группы |
| Inode | таблица inode | метаданные файла, указатели на данные |
| Extent tree | внутри inode | дерево экстентов (замена косвенных блоков) |
| Журнал (JBD2) | inode #8 (журнал) | транзакции метаданных |

Суперблок (ext4_super_block) — важные поля:

| Смещение | Поле |
|---------:|------|
| 0x00 | s_inodes_count |
| 0x04 | s_blocks_count_lo |
| 0x0C | s_free_blocks_count |
| 0x18 | s_log_block_size (размер блока = 1024 << value) |
| 0x20 | s_blocks_per_group |
| 0x28 | s_inodes_per_group |
| 0x38 | s_magic = `0xEF53` |
| 0x58 | s_inode_size (обычно 256) |
| 0x5C | s_block_group_nr |
| 0x60 | s_feature_compat |
| 0x64 | s_feature_incompat (0x40 = EXTENTS) |
| 0x68 | s_feature_ro_compat |
| 0x9C | s_journal_inum (обычно 8) |

```bash
# Суперблок
xxd -s 1024 -l 8 disk.img            # ... 53 ef
dumpe2fs -h disk.img 2>/dev/null | head -50   # все параметры ФС
```

`dumpe2fs` — быстрый способ узнать размер блока, число inode, размер inode, состояние журнала.

## Inode и extent-дерево

Каждый файл описан **inode** фиксированного размера (обычно 256 байт). В ext4 inode хранит **extent-дерево** — иерархию экстентов (непрерывных диапазонов блоков) вместо классических 12 косвенных указателей.

Inode (ext4_inode), ключевые поля:

| Смещение | Поле |
|---------:|------|
| 0x00 | i_mode (тип+права) |
| 0x04 | i_uid |
| 0x1C | i_size_lo (младшие 32 бита размера) |
| 0x28 | i_atime (аксесс) |
| 0x2C | i_ctime (change) |
| 0x30 | i_mtime (modify) |
| 0x34 | i_dtime (delete time!) |
| 0x64 | i_size_high |
| 0x68 | i_block (начало extent-дерева / указателей) |

Поле `i_dtime` — время удаления: если оно ненулевое, файл удалён. Extent-заголовок (`ext4_extent_header`) в `i_block`: `eh_magic = 0xF30A`, `eh_entries`, `eh_max`, `eh_depth`. Если `eh_depth = 0` — это лист с экстентами `ee_block, ee_len, ee_start_hi, ee_start_lo`.

```bash
# Разбор inode и его extent-дерева
debugfs -R "stat <12>" disk.img 2>/dev/null
#  Inode: 12   Type: regular   Mode: 0644 ...
#  Inode size: 256
#  EXTENTS:
#  (0):12345-12400, (4):20000-20010 ...

# Ручной дамп inode (inode table группы 0)
xxd -s <inode_table_offset + (inode-1)*256> -l 128 disk.img
```

Читать данные по экстентам: `dd` по диапазону блоков, зная размер блока.

## Журнал JBD2

ext4 журналируется через **JBD2** (Journaling Block Device 2). Журнал — служебный inode (обычно #8), может быть встроенным или отдельным устройством. Он хранит **дескрипторы транзакций**: какие блоки меняются и их новое содержимое (журнал write-ahead).

Записи журнала:
- **Descriptor block** (`0xC03B3998` magic, type `1`) — какие блоки следуют.
- **Data block** — новое содержимое блока.
- **Commit block** (type `2`) — транзакция завершена.
- **Revoke block** — отмена.

Для форензики журнал ценен тем, что там могут лежать **старые метаданные** (inode, directory entries) — то есть имена и размеры удалённых файлов.

```bash
# Прочитать журнал в текстовом виде
debugfs -R "logdump -a" disk.img 2>/dev/null | head -100
# Или показать «сырой» журнал как файл
debugfs -R "dump <8> journal.bin" disk.img 2>/dev/null
ls -l journal.bin

# jls / jcat из sleuthkit по устройству журнала
jls -o <offset> disk.img          # список транзакций журнала
jcat -o <offset> disk.img 123     # содержимое блока журнала
```

`jls`/`jcat` (sleuthkit) умеют читать ext3/ext4 журнал без монтирования.

## Восстановление удалённых файлов

Удаление в ext4: inode помечается свободным (в битмапе inode), `i_links_count = 0`, `i_dtime` = время удаления. Указатели блоков (extent-дерево) могут быть обнулены, но **данные в блоках ещё лежат**, пока не перезаписаны.

Стратегии:
1. **icat по удалённому inode** — если extent-дерево сохранилось.
2. **journal replay** — вытащить inode из журнала, если он там есть.
3. **carving по unallocated** — `blkls` + `foremost`/`photorec`/`binwalk`.

```bash
OFF=2048
# Список удалённых (флаг *)
fls -r -d -o $OFF disk.img

# Попытка извлечь по inode
icat -o $OFF disk.img <deleted_inode> > recovered.bin
file recovered.bin

# Журнал -> старые inode/dirent
debugfs -R "logdump -a" disk.img | grep -iE 'deleted|inode|name'

# unallocated -> carving
blkls -o $OFF disk.img > unallocated.bin
foremost -i unallocated.bin -o out
```

`extundelete`/`ext4magic` автоматизируют восстановление через журнал:

```bash
# Только чтение образа! Работаем на копии
cp disk.img work.img
extundelete work.img --restore-all --output-dir recovered
# ext4magic: -M восстановить удалённые, -j работать через журнал
ext4magic work.img -M -d recovered/
ext4magic work.img -j recovered/     # восстановление из журнала
```

**Важно:** `extundelete`/`ext4magic` требуют, чтобы ФС была **не смонтирована** (или смонтирована ro). Иначе журнал перезапишет улики.

## Slack space и unallocated

- **Slack space** — байты после конца файла в последнем блоке (остатки предыдущего файла).
- **Unallocated** — свободные блоки: удалённые данные, фрагменты каталогов.

```bash
# Дамп только нераспределённых блоков
blkls -o $OFF disk.img > unalloc.bin
strings -n 6 unalloc.bin | grep -iE 'flag|pass|secret'
binwalk unalloc.bin

# Последние 4 КБ каждого файла (slack) — сложнее, обычно через tsk_recover
tsk_recover -o $OFF -e disk.img out_dir   # извлечение всех файлов
```

## Разобранный пример: CTF «удалённый флаг в ext4»

```bash
file disk.img                       # ext4 filesystem data
mmls disk.img                       # offset раздела, напр. 2048
OFF=2048

# 1. Параметры ФС
dumpe2fs -h disk.img 2>/dev/null | grep -iE 'block size|inode size|filesystem state|journal'

# 2. Удалённые файлы
fls -r -d -o $OFF disk.img
#  r/r * 17: flag.txt

# 3. Прямое извлечение
icat -o $OFF disk.img 17 > out.bin
file out.bin; strings out.bin | grep -i flag

# 4. Если не вышло — журнал
debugfs -R "logdump -a" disk.img 2>/dev/null | grep -iA2 flag

# 5. Если и там нет — carving unallocated
blkls -o $OFF disk.img > unalloc.bin
strings -n 5 unalloc.bin | grep -iE 'flag\{|CTF\{'
```

## Частые ошибки

- **Монтировать образ read-write** — ядро переиграет журнал и перезапишет удалённые inode. Только `-o ro,loop` или offline-инструменты.
- **Запускать extundelete на смонтированной ФС** — результат непредсказуем и разрушителен.
- **Путать `-o` в секторах и байтах** — sleuthkit ждёт секторы.
- **Считать, что обнулённое extent-дерево = потерянные данные** — блоки могут лежать в unallocated, читайте `blkls`.
- **Игнорировать `i_dtime`** — это прямое доказательство удаления.
- **Не проверять `s_feature_incompat` на EXTENTS (0x40)** — ext3 использует косвенные блоки, разбор другой.

## Квиз

```quiz
- question: "Какая сигнатура (magic) у суперблока ext4?"
  options:
    - "`0xEF53`"
    - "`0xF30A`"
    - "`NTFS`"
    - "`0xC03B3998`"
  answer: 0
- question: "Какое поле inode хранит время удаления файла?"
  options:
    - "`i_mtime`"
    - "`i_ctime`"
    - "`i_dtime`"
    - "`i_atime`"
  answer: 2
- question: "Что пришло на смену косвенным блокам в ext4?"
  options:
    - "MFT"
    - "extent-дерево"
    - "FAT-таблица"
    - "B-дерево каталогов"
  answer: 1
- question: "Каким инструментом читают журнал ext4 без монтирования?"
  options:
    - "`mount`"
    - '`debugfs -R "logdump -a"` / `jls`'
    - "`ntfsinfo`"
    - "`exiftool`"
  answer: 1
- question: "Почему extundelete запускают только на несмонтированной ФС?"
  options:
    - "иначе не хватит прав"
    - "ядро переиграет журнал и перезапишет улики/данные"
    - "он работает только с FAT"
    - "так требует лицензия"
  answer: 1
```

## Где пригодится

- **CTF:** образы Linux-дисков, удалённые файлы, журнальные артефакты.
- **Data recovery:** восстановление удалённых файлов из ext4.
- **Incident Response:** анализ Linux-хостов после компрометации.
- **Судебная экспертиза:** доказательство удаления по `i_dtime` и журналу.
- **Разработка ФС-инструментов:** понимание layout ext4.
