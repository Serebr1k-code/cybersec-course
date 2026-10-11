---
id: forensics-usn
title: "Журнал USN ($UsnJrnl): хронология операций с файлами"
category: forensics
parent: forensics-ntfs-mft
difficulty: hard
order: 1
tags: [usn, usnjrnl, ntfs, timeline, rename, delete, mftecmd]
prerequisites: [forensics-ntfs-mft]
useful_for:
  - "CTF Forensics категория"
  - "Incident Response (Windows)"
  - "Timeline analysis"
estimated_minutes: 50
summary: "Практический разбор $UsnJrnl: извлечение потока $J, парсинг причин (Reason), реконструкция пар rename, поиск удалений и построение таймлайна действий."
---

`$UsnJrnl` (Update Sequence Number Journal) — это журнал NTFS, который фиксирует **каждое** изменение на томе: создание, запись, переименование, удаление, смену атрибутов. В отличие от `$LogFile`, он не хранит старое содержимое, зато даёт непрерывную ленту событий с именем файла, временем и причиной. Для восстановления «кто что делал с файлами» это самый ценный артефакт Windows. Урок — практический: как достать `$J`, распарсить и превратить в таймлайн.

## Что внутри $UsnJrnl

`$UsnJrnl` — служебный файл в каталоге `$Extend` (запись MFT #11 — сам `$Extend`, а `$UsnJrnl` — его дочерняя запись). У него два потока данных:

| Поток | Назначение |
|-------|-----------|
| `$Max` | метаданные: максимальный USN, выделение, версия (USN_RECORD_V2/V3/V4) |
| `$J` | сами записи USN (это то, что мы парсим) |

Важно: `$UsnJrnl:$J` — **разреженный (sparse)** файл. Старые записи при переполнении не удаляются, а помечаются как «дырки» (нулевые диапазоны). Парсер должен уметь пропускать нули и синхронизироваться по сигнатуре записи.

Запись USN (USN_RECORD_V2) — заголовок:

| Смещение | Размер | Поле |
|---------:|-------:|------|
| 0x00 | 4 | RecordLength (длина записи) |
| 0x04 | 2 | MajorVersion (2/3/4) |
| 0x06 | 2 | MinorVersion |
| 0x08 | 8 | FileReferenceNumber (inode+seq) |
| 0x10 | 8 | ParentFileReferenceNumber |
| 0x18 | 8 | USN (номер записи) |
| 0x20 | 8 | TimeStamp (FILETIME) |
| 0x28 | 4 | Reason (битовая маска) |
| 0x2C | 4 | SourceInfo |
| 0x30 | 4 | SecurityId |
| 0x34 | 4 | FileAttributes |
| 0x38 | 2 | FileNameLength |
| 0x3A | 2 | FileNameOffset |
| 0x3C | var | FileName (UTF-16LE) |

## Извлечение потока $J

Сначала находим NTFS-раздел и записи, затем вытаскиваем `$J`.

```bash
mmls disk.img
# Start Sector = 2048 -> offset раздела
OFF=2048

# Список каталога $Extend (inode 11) и поиск $UsnJrnl
fls -o $OFF disk.img 11
#  d/d 42-128-1: $UsnJrnl

# Поток $J — отдельная запись потока. Ищем его:
fls -r -o $OFF disk.img | grep -i 'usnjrnl'
#  r/r 42-128-3: $UsnJrnl:$J

# Извлекаем поток $J
icat -o $OFF disk.img 42-128-3 > usnjrnl_J.bin
ls -l usnjrnl_J.bin
```

На Windows тот же поток достаётся через `MFTECmd` (он сам находит `$UsnJrnl:$J` по `$MFT`):

```cmd
MFTECmd.exe -f C:\$Extend\$UsnJrnl --csv C:\out --usnjrnl
```

Если есть только сырой `$MFT`, а `$UsnJrnl` отсутствует, всё равно извлекаем `$MFT` и парсим его — но `$UsnJrnl` уникален именно лентой операций.

## Парсинг и Reason

Причина (`Reason`) — битовая маска. Основные значения:

| Значение | Имя | Что означает |
|---------:|-----|--------------|
| `0x00000001` | DATA_OVERWRITE | перезапись данных |
| `0x00000002` | DATA_EXTEND | дописывание |
| `0x00000004` | DATA_TRUNCATION | усечение |
| `0x00000100` | FILE_CREATE | создание |
| `0x00000200` | FILE_DELETE | удаление |
| `0x00000400` | EA_CHANGE | смена extended attributes |
| `0x00001000` | SECURITY_CHANGE | смена прав |
| `0x00002000` | RENAME_OLD_NAME | старое имя при переименовании |
| `0x00004000` | RENAME_NEW_NAME | новое имя при переименовании |
| `0x00008000` | INDEXABLE_CHANGE | смена индексируемости |
| `0x00010000` | BASIC_INFO_CHANGE | смена времён/атрибутов |
| `0x00020000` | HARD_LINK_CHANGE | hard link |
| `0x00040000` | COMPRESSION_CHANGE | смена сжатия |
| `0x00080000` | ENCRYPTION_CHANGE | смена шифрования |
| `0x00100000` | OBJECT_ID_CHANGE | object id |
| `0x00200000` | REPARSE_POINT_CHANGE | reparse point |
| `0x00400000` | STREAM_CHANGE | смена потока (ADS!) |
| `0x80000000` | CLOSE | закрытие файла (финал операции) |

```bash
# Парсинг через usnparser (Python)
pip install usnparser
usnparser parse usnjrnl_J.bin > usn.csv
head -5 usn.csv
# Timestamp,USN,Reason,ReasonFlags,Name,ParentPath

# Альтернатива: usn.py из dfir-scripts, или MFTECmd --csv
```

`RENAME_OLD_NAME` и `RENAME_NEW_NAME` для одной операции идут двумя записями с **одинаковым USN** — сшиваем их по USN.

## Реконструкция переименований

Скрипт-сшивка пар rename:

```python
import csv, collections
pairs = collections.defaultdict(dict)
with open('usn.csv', newline='', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        usn = row['USN']; r = int(row['Reason'], 0)
        if r & 0x00002000:
            pairs[usn]['old'] = row['Name']
        if r & 0x00004000:
            pairs[usn]['new'] = row['Name']
        pairs[usn]['ts'] = row['Timestamp']
for usn, d in sorted(pairs.items()):
    if 'old' in d and 'new' in d:
        print(f"{d['ts']}  {d['old']}  ->  {d['new']}")
```

Результат прямо показывает, как злоумышленник переименовывал, например, `update.exe` в `svchost.exe`.

## Поиск удалений и подозрительных имён

```bash
# Только удаления (FILE_DELETE = 0x200)
grep -iE 'FILE_DELETE|0x200' usn.csv

# Массовые удаления в короткий интервал (шифровальщик)
cut -d, -f1 usn.csv | sort | uniq -c | sort -rn | head

# Подозрительные расширения
grep -iE '\.(exe|dll|ps1|bat|vbs|js|scr|tmp)$' usn.csv

# Файлы в Temp/Downloads
grep -iE 'temp|downloads|appdata' usn.csv
```

Признаки ransomware: сотни `FILE_DELETE` + `RENAME_NEW_NAME` в расширения с одним суффиксом (`.locked`) за минуты.

## Построение таймлайна

`$UsnJrnl` — один из источников супер-таймлайна. Приводим его к общему формату и объединяем с MFT и EVTX:

```bash
# USN -> строки bodyfile-подобного вида
python3 - <<'EOF' > usn_bodyfile.txt
import csv
for r in csv.DictReader(open('usn.csv', encoding='utf-8')):
    print(f"0|{r['ParentPath']}/{r['Name']}|-|-|{r['Timestamp']}|{r['Reason']}")
EOF

# Сортируем всё вместе (MFT bodyfile + USN + EVTX-экспорт)
cat mft_bodyfile.txt usn_bodyfile.txt | sort -t'|' -k5 | head -50
```

Времена в USN — UTC (FILETIME). Учитывайте часовой пояс хоста, если сопоставляете с локальными логами.

## Разобранный пример: «кто подменил документ»

```bash
OFF=2048
fls -r -o $OFF disk.img | grep -i 'usnjrnl'
icat -o $OFF disk.img 42-128-3 > usn.bin
usnparser parse usn.bin > usn.csv

# 1. Находим интересный файл
grep -i 'report.docx' usn.csv

# 2. Все операции с ним в порядке времени
grep -i 'report.docx' usn.csv | sort -t, -k1

# 3. Смотрим rename-пары
python3 rename_pairs.py usn.csv | grep -i report

# 4. Удалён ли он?
grep -i 'report.docx' usn.csv | grep -i delete

# Вывод: 10:01 создан, 10:05 перезаписан, 10:07 переименован в .bak, 10:08 удалён
```

## Частые ошибки

- **Парсить `$UsnJrnl` как обычный файл** — нужно именно `$J`, а не `$Max`, и учитывать разреженность (нули).
- **Не синхронизироваться по сигнатуре** — при «дырках» парсер рассыпается; V2-записи начинаются с правдоподобного RecordLength, проверяйте `RecordLength` и `MajorVersion`.
- **Сшивать rename по времени, а не по USN** — USN однозначен, время может совпадать.
- **Игнорировать STREAM_CHANGE (`0x400000`)** — это создание/удаление ADS.
- **Забывать, что журнал кольцевой** — старые события вытеснены; отсутствие записи ≠ отсутствие действия.
- **Считать Reason одним флагом** — это битовая маска, комбинируйте через `&`.

## Квиз

```quiz
- question: "Какой поток $UsnJrnl содержит сами записи журнала?"
  options:
    - "`$Max`"
    - "`$J`"
    - "`$MFT`"
    - "`$LogFile`"
  answer: 1
- question: "Какой флаг Reason соответствует удалению файла?"
  options:
    - "`0x00000100` FILE_CREATE"
    - "`0x00000200` FILE_DELETE"
    - "`0x00004000` RENAME_NEW_NAME"
    - "`0x80000000` CLOSE"
  answer: 1
- question: "Как сшиваются старое и новое имя при переименовании?"
  options:
    - "по времени с точностью до секунды"
    - "по одинаковому USN у RENAME_OLD_NAME и RENAME_NEW_NAME"
    - "по имени"
    - "по размеру файла"
  answer: 1
- question: "Чем $UsnJrnl принципиально отличается от $LogFile?"
  options:
    - "ничем"
    - "$UsnJrnl — лента операций с именами/временем, $LogFile — транзакции метаданных с прежними значениями"
    - "$UsnJrnl хранит содержимое файлов"
    - "$LogFile находится в $Extend"
  answer: 1
- question: "Почему $UsnJrnl называют разреженным файлом?"
  options:
    - "он сжат"
    - "старые записи заменяются нулевыми диапазонами (дырками), а не удаляются"
    - "он зашифрован"
    - "он делится на разделы"
  answer: 1
```

## Где пригодится

- **CTF:** задачи, где надо доказать переименование/удаление файла.
- **Incident Response:** восстановление последовательности действий атакующего.
- **Ransomware-анализ:** массовые rename/delete за короткое время.
- **Threat Hunting:** поиск запусков из Temp/Downloads по именам из USN.
- **Судебная экспертиза:** объективная лента операций с файлами.
