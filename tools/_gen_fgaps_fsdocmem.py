#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gB forensics gaps: fs-extra + doc-formats + memory-extra (3 hubs + 12 lessons)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _fgaps_common import emit  # noqa: E402

HUBS = {}
LESSONS = {}

HUBS["forensics-fs-extra"] = r'''---
id: forensics-fs-extra
title: "Модуль: дополнительные файловые системы и хранилища"
category: forensics
parent: forensics-filesystems
difficulty: hard
order: 7
tags: [forensics, apfs, fat, mdadm, raid, tpm, filesystem, roadmap]
prerequisites: [forensics-fs-structure]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ образов дисков"
estimated_minutes: 13
summary: "Этап ветки «файловые системы»: снимки и шифрование APFS, слак FAT, программный RAID и TPM/измеренная загрузка."
---

Основные ФС мы разобрали. Остаются «краевые» случаи: снимки и шифрование APFS, объёмный
слак FAT, сборка программного RAID и аппаратный TPM. Каждый по-своему меняет картину
восстановления.

## Что покрывает этот модуль

- **APFS-снимки** — версии тома во времени.
- **APFS-шифрование** — keybag и ключи.
- **FAT-слак** — данные в хвостах кластеров.
- **mdadm RAID** — сборка массива из дисков.
- **TPM** — измеренная загрузка и ключи.

## Рекомендуемый порядок изучения

1. `fs-apfs-snapshot` — версии тома.
2. `fs-apfs-encryption` — ключи APFS.
3. `fs-fat-slack` — объёмный слак.
4. `fs-mdadm` — сборка RAID.
5. `fs-tpm` — измеренная загрузка.

## Что вы будете уметь

- Монтировать снимки APFS и доставать удалённое.
- Разбирать keybag APFS.
- Извлекать данные из слака FAT.
- Собирать программный RAID.
- Читать TPM-измерения.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| снимок APFS | версия файла | `apfs-fuse`, `mount_apfs` |
| keybag | где ключи | `apfs-fuse` |
| слак FAT | что было до | hex/карвинг |
| диски RAID | целый массив | `mdadm` |
| TPM | что загружалось | `tpm2-tools` |

## Куда дальше

Открывай урок **«APFS-снимки»** — начнём с версий тома.
'''

HUBS["forensics-doc-formats"] = r'''---
id: forensics-doc-formats
title: "Модуль: форматы документов — OOXML, ODF, RTF, XPS"
category: forensics
parent: forensics-file-magic
difficulty: medium
order: 5
tags: [forensics, docx, ooxml, odf, rtf, xps, documents, roadmap]
prerequisites: [forensics-file-magic]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ документов"
estimated_minutes: 13
summary: "Этап ветки «форматы»: как устроены офисные документы — OOXML (docx/xlsx), ODF, RTF и XPS — и где в них следы и малварь."
---

Документы — самый частый вектор атак и источник метаданных. Современные форматы — это
ZIP-архивы (OOXML/ODF) или текстовые/бинарные форматы (RTF/XPS). Разберём их структуру.

## Что покрывает этот модуль

- **OOXML** — docx/xlsx/pptx (ZIP + XML).
- **ODF** — odt/ods (открытый аналог).
- **RTF** — текстовый формат с объектами.
- **XPS** — «PDF от Microsoft».

## Рекомендуемый порядок изучения

1. `doc-ooxml-internals` — структура OOXML.
2. `doc-odf` — ODF.
3. `doc-rtf` — RTF и его объекты.
4. `doc-xps` — XPS.

## Что вы будете уметь

- Разбирать OOXML/ODF как архивы.
- Находить метаданные, макросы, встроенные объекты.
- Читать RTF и находить в нём полезную нагрузку.
- Разбирать XPS.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| docx | кто создал/менял | `unzip`, XML |
| vbaProject.bin | есть ли макрос | `olevba` |
| .rtf | что внутри | текстовый разбор |
| .xps | структура | `unzip` |

## Куда дальше

Открывай урок **«OOXML изнутри»** — начнём с docx/xlsx.
'''

HUBS["forensics-memory-extra"] = r'''---
id: forensics-memory-extra
title: "Модуль: память — macOS, dyld-кэш и кусты реестра"
category: forensics
parent: forensics-memory-artifacts
difficulty: hard
order: 5
tags: [forensics, memory, macos, dyld, registry-hives, roadmap]
prerequisites: [forensics-memory-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ памяти"
estimated_minutes: 12
summary: "Этап ветки «память»: особенности macOS-памяти, разделяемый кэш dyld и восстановление кустов реестра из дампа."
---

Память Windows и Linux мы разбирали. Остались три особые темы: специфика macOS
(унифицированная память, сжатие), кэш **dyld** (разделяемая библиотека macOS) и
извлечение **кустов реестра** прямо из дампа. Разберём.

## Что покрывает этот модуль

- **macOS-память** — особенности сбора и анализа.
- **dyld-кэш** — где живёт код библиотек macOS.
- **Кусты реестра** — восстановление hives из дампа.

## Рекомендуемый порядок изучения

1. `mem-macos` — специфика macOS.
2. `mem-dyld-cache` — разделяемый кэш.
3. `mem-registry-hives` — реестр из памяти.

## Что вы будете уметь

- Собирать и анализировать память macOS.
- Работать с dyld-кэшем.
- Извлекать кусты реестра из дампа.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| macOS-дамп | что было в памяти | Volatility/osxpmem |
| dyld_shared_cache | где код библиотек | `dyld_extractor` |
| hive в дампе | состояние реестра | Volatility `hivelist` |

## Куда дальше

Открывай урок **«Память macOS»** — начнём со специфики.
'''

LESSONS["fs-apfs-snapshot"] = dict(
parent="forensics-fs-extra", order=1, diff="hard", mins=45,
title="APFS-снимки: версии тома во времени",
tags="[forensics, apfs, snapshot, macos, filesystem]",
prereq="[forensics-fs-structure]",
summary="Как устроены снимки APFS, как их монтировать и доставать из них удалённые или изменённые файлы.",
body=r'''
## Вопрос, с которого всё начинается

На Mac файл изменён, а нужна его прежняя версия. APFS — copy-on-write ФС, поэтому старые
версии могут оставаться в **снимках** (snapshots). Разберём, как их найти и смонтировать.

## Наш пример: том APFS

## Шаг 1: что такое снимок APFS

Снимок — это «замороженное» состояние тома: все блоки на момент создания. Благодаря
copy-on-write, снимок занимает мало места, пока данные не меняются.

```
$ diskutil apfs listSnapshots /dev/disk1s1
Snapshots for disk1s1:
com.apple.TimeMachine.2026-01-14-030000.local
```

## Шаг 2: монтируем снимок

На macOS:

```
$ mkdir /tmp/snap
$ mount_apfs -s com.apple.TimeMachine.2026-01-14-030000.local /dev/disk1s1 /tmp/snap
```

На Linux/Windows (по образу) — `apfs-fuse`:

```
$ apfs-fuse -s 1 disk.img /mnt/apfs
```

`-s` указывает номер снимка.

## Шаг 3: достаём старые версии

В смонтированном снимке видны файлы на тот момент:

```
$ ls /tmp/snap/Users/user/Documents/
old_report.pdf
```

Файл, удалённый сейчас, в снимке ещё есть.

## Шаг 4: сравнение

```
$ diff /tmp/snap/Users/user/.bash_history ~/.bash_history
```

Разница показывает изменения — то, что дописал или удалил злоумышленник.

## Шаг 5: что искать

- удалённые файлы;
- прежние версии документов;
- историю правок;
- доказательства времени.

## Что мы теперь знаем

- APFS copy-on-write хранит старые версии в снимках.
- `diskutil`/`mount_apfs`/`apfs-fuse` дают доступ.
- В снимке видны удалённые файлы.
- Сравнение выявляет изменения.
- Снимок — надёжное доказательство.

## Если не сработало

- Снимков нет? Проверь все тома.
- Образ не читается? Укажи номер снимка в apfs-fuse.
- Нужен контент? Монтируй и копируй.

## Квиз

Проверь себя.

```quiz
- question: Что хранит снимок APFS?
  options:
    - 'только метаданные'
    - 'состояние тома на момент создания'
    - 'пароли'
    - 'сеть'
  answer: 1
  explanation: 'Снимок фиксирует все блоки тома благодаря copy-on-write.'
- question: Как смонтировать снимок APFS на Linux?
  options:
    - 'mount'
    - 'apfs-fuse -s <номер>'
    - 'cp'
    - 'tar'
  answer: 1
  explanation: 'apfs-fuse с -s монтирует конкретный снимок.'
- question: Почему снимок полезен для восстановления удалённого?
  options:
    - 'он быстрый'
    - 'в нём файл ещё существует'
    - 'он шифрует'
    - 'он маленький'
  answer: 1
  explanation: 'Снимок хранит состояние до удаления.'
- question: Что даёт сравнение снимка с текущим томом?
  options:
    - 'ничего'
    - 'выявляет изменения (дописки/удаления)'
    - 'шифрует'
    - 'ускоряет'
  answer: 1
  explanation: 'Diff показывает, что изменилось после снимка.'
```
''')

LESSONS["fs-apfs-encryption"] = dict(
parent="forensics-fs-extra", order=2, diff="hard", mins=50,
title="APFS-шифрование: keybag и ключи",
tags="[forensics, apfs, encryption, keybag, macos]",
prereq="[forensics-fs-structure]",
summary="Как устроено шифрование APFS, что такое keybag и как получить ключи для расшифровки тома.",
body=r'''
## Вопрос, с которого всё начинается

Том APFS зашифрован. Чтобы прочитать данные, нужны ключи. Где они и как устроены?
Разберём **keybag** — хранилище ключей APFS.

## Наш пример: зашифрованный том

## Шаг 1: как шифруется APFS

APFS шифрует **каждый файл** своим ключом. Ключи хранятся в **keybag** — структуре с
несколькими «связками» (keybags):

- `Bag1` — том (volume);
- `Bag2` — метаданные;
- `Bag3` — пользователи.

## Шаг 2: где keybag

На macOS ключи привязаны к **Secure Enclave** (аппаратный чип). Извлечь их «в лоб»
нельзя. При анализе образа keybag лежит внутри тома:

```
$ apfs-fuse --help | grep -i keybag
```

## Шаг 3: пароль и ключи

Расшифровка возможна, если есть:

- **пароль пользователя** (для user keybag);
- **recovery key**;
- **институциональный ключ** (MDM/FileVault).

```
$ apfs-fuse -p <password> disk.img /mnt/apfs
```

`-p` передаёт пароль для разблокировки user keybag.

## Шаг 4: что внутри keybag

Keybag содержит зашифрованные ключи (wrapped keys). Чтобы их развернуть, нужен
KEK (key-encryption key), выводимый из пароля:

```
(password) → PBKDF2 → KEK → unwrap → VEK → decrypt volume
```

Без пароля цепочка не запускается.

## Шаг 5: практика

- если пароль известен — `apfs-fuse -p`;
- если есть Secure Enclave — нужен живой разблокированный Mac;
- brute-force пароля FileVault практически невозможен (сильный KDF).

## Что мы теперь знаем

- APFS шифрует файлы; ключи — в keybag.
- Keybags: том, метаданные, пользователи.
- На Apple Silicon ключи в Secure Enclave.
- Пароль разблокирует user keybag (apfs-fuse -p).
- Без пароля расшифровка невозможна.

## Если не сработало

- Нет пароля? Ищи recovery key у владельца.
- Secure Enclave? Нужен живой Mac.
- MDM? Проверь институциональный ключ.

## Квиз

Проверь себя.

```quiz
- question: Что такое keybag в APFS?
  options:
    - 'архив файлов'
    - 'хранилище ключей шифрования'
    - 'сетевой пакет'
    - 'обои'
  answer: 1
  explanation: 'Keybag содержит wrapped-ключи тома/пользователя.'
- question: Чем разблокируется user keybag?
  options:
    - 'ничем'
    - 'паролем пользователя/recovery key'
    - 'сетью'
    - 'обоями'
  answer: 1
  explanation: 'Из пароля выводится KEK, которым разворачиваются ключи.'
- question: Где ключи на Apple Silicon?
  options:
    - 'в файле'
    - 'в Secure Enclave'
    - 'в облаке'
    - 'в реестре'
  answer: 1
  explanation: 'Ключи защищены аппаратным Secure Enclave.'
- question: Что нужно для расшифровки тома на образе?
  options:
    - 'ничего'
    - 'пароль/recovery key'
    - 'сеть'
    - 'браузер'
  answer: 1
  explanation: 'Без пароля цепочка вывода ключей не работает.'
```
''')

LESSONS["fs-fat-slack"] = dict(
parent="forensics-fs-extra", order=3, diff="medium", mins=40,
title="FAT-слак: данные в хвостах кластеров",
tags="[forensics, fat, slack, carving, filesystem]",
prereq="[forensics-fs-structure]",
summary="Что такое слак в FAT, почему в нём остаются данные и как их извлекать.",
body=r'''
## Вопрос, с которого всё начинается

Файл занимает 100 байт, но кластер — 4096. Остальные ~4000 байт — **слак**: там могут
остаться данные предыдущего файла. Это бесплатная улика. Разберём FAT-слак.

## Наш пример: маленький файл

## Шаг 1: что такое слак

Файловая система выделяет место **кластерами**. Если файл меньше кластера, остаток
кластера остаётся занятым, но не перезаписанным:

```
файл A: 100 байт в кластере 4096 → 3996 байт слака
```

В слаке — «хвост» предыдущего содержимого кластера.

## Шаг 2: где искать в FAT

FAT (FAT16/FAT32) хранит цепочки кластеров в таблице. Последний кластер файла содержит
слак:

```
$ fls -r -p disk.img | grep 'file A'
r/r 5: file_A.txt
$ icat disk.img 5 | wc -c
100
```

Но кластер выделен на 4096 — остальное доступно через raw-чтение.

## Шаг 3: извлечение

Читаем кластер целиком:

```
$ dd if=disk.img bs=4096 skip=<cluster> count=1 | xxd | tail
```

Или используем карвинг: `foremost`/`scalpel` проходят по кластерам и находят сигнатуры.

## Шаг 4: что находится в слаке

- фрагменты удалённых файлов;
- старые версии;
- **RAM-slack** (из памяти) — фрагменты процессов;
- строки паролей/ключей.

## Шаг 5: практика

- слак есть в FAT, NTFS, ext;
- `slack space` собирают целиком для анализа;
- это «мусор», но часто золото.

## Что мы теперь знаем

- Слак — неиспользованный остаток кластера.
- В нём остаются данные предыдущих файлов.
- Извлекается raw-чтением кластера/карвингом.
- Может содержать фрагменты удалённого.
- Есть в FAT/NTFS/ext.

## Если не сработало

- ФС зашифрована? Слак тоже зашифрован.
- Кластеры перезаписаны? Данные потеряны.
- Нужен масштаб? Используй bulk-инструменты.

## Квиз

Проверь себя.

```quiz
- question: Что такое слак?
  options:
    - 'сетевой протокол'
    - 'неиспользованный остаток кластера'
    - 'пароль'
    - 'архив'
  answer: 1
  explanation: 'Слак — «хвост» кластера после конца файла.'
- question: Почему в слаке могут быть чужие данные?
  options:
    - 'их туда кладут специально'
    - 'кластер не перезаписан после предыдущего файла'
    - 'это ошибка'
    - 'это шифр'
  answer: 1
  explanation: 'Новые данные не затирают весь кластер, остаётся предыдущее содержимое.'
- question: Как извлечь слак?
  options:
    - 'grep'
    - 'raw-чтение кластера/карвинг'
    - 'ssh'
    - 'ping'
  answer: 1
  explanation: 'Читают кластер целиком или карвят по сигнатурам.'
- question: В каких ФС есть слак?
  options:
    - 'только в облаке'
    - 'FAT, NTFS, ext и др.'
    - 'только в RAM'
    - 'нигде'
  answer: 1
  explanation: 'Слак есть в большинстве блочных ФС.'
```
''')

LESSONS["fs-mdadm"] = dict(
parent="forensics-fs-extra", order=4, diff="hard", mins=45,
title="mdadm: сборка программного RAID для анализа",
tags="[forensics, mdadm, raid, linux, filesystem]",
prereq="[forensics-fs-structure]",
summary="Как собрать программный RAID (mdadm) из отдельных дисков, чтобы получить цельный образ для анализа.",
body=r'''
## Вопрос, с которого всё начинается

Пришли четыре диска — по отдельности непонятные. Вместе они образуют RAID-массив.
Чтобы анализировать, нужно **собрать** их обратно. Разберём `mdadm`.

## Наш пример: RAID из четырёх дисков

## Шаг 1: определяем метаданные

Linux-RAID хранит метаданные в суперблоке. Посмотрим:

```
$ mdadm --examine /dev/sdb1
/dev/sdb1:
   Magic : a92b4efc
   Array UUID : 1a2b3c4d:...
   Raid Level : raid5
   Devices : 4
```

Здесь видно уровень (raid5), UUID массива и число устройств.

## Шаг 2: собираем

Собираем по копиям (чтобы не трогать оригиналы):

```
$ mdadm --assemble --readonly /dev/md0 /dev/sdb1 /dev/sdc1 /dev/sdd1 /dev/sde1
mdadm: /dev/md0 has been started with 4 drives.
```

`--readonly` — критично: массив может запустить восстановление и изменить диски.

## Шаг 3: монтируем

```
$ mount -o ro /dev/md0 /mnt/raid
```

Если ФС распознана — читаем как обычный диск.

## Шаг 4: если сборка не идёт

- **не хватает диска** (degraded) — можно собрать в degraded-режиме;
- **неправильный порядок** — задай вручную (`--force` с порядком);
- **разные размеры** — учитывай.

```
$ mdadm --assemble --readonly --force /dev/md0 ...
```

## Шаг 5: определение уровня

- **RAID0** — страйп (нет избыточности);
- **RAID1** — зеркало;
- **RAID5/6** — чётность (нужны все, кроме одного/двух);
- **RAID10** — зеркало+страйп.

Уровень определяет, сколько дисков обязательно.

## Что мы теперь знаем

- `mdadm --examine` читает суперблок.
- `--assemble --readonly` собирает массив.
- Монтируем как обычный диск.
- Degraded-сборка возможна.
- Уровень определяет требования к дискам.

## Если не сработало

- Не собирается? Проверь уровень и UUID.
- Нужен порядок? Задай вручную.
- Диск мёртв? RAID5/6 переживёт один/два.

## Квиз

Проверь себя.

```quiz
- question: Что показывает mdadm --examine?
  options:
    - 'пароли'
    - 'суперблок: уровень, UUID, число устройств'
    - 'сеть'
    - 'обои'
  answer: 1
  explanation: 'Examine читает метаданные RAID-диска.'
- question: Зачем --readonly при сборке?
  options:
    - 'для скорости'
    - 'чтобы массив не изменил диски (восстановление)'
    - 'для шифрования'
    - 'для сети'
  answer: 1
  explanation: 'Автосборка может запустить ребилд и изменить улики.'
- question: Сколько дисков нужно для RAID5?
  options:
    - '1'
    - 'минимум 3 (переживёт потерю 1)'
    - '2'
    - '10'
  answer: 1
  explanation: 'RAID5 требует ≥3 дисков и выдерживает отказ одного.'
- question: Что такое degraded-сборка?
  options:
    - 'сборка без части дисков'
    - 'шифрование'
    - 'форматирование'
    - 'обновление'
  answer: 0
  explanation: 'Массив можно собрать, потеряв диск (для RAID1/5/6).'
```
''')

LESSONS["fs-tpm"] = dict(
parent="forensics-fs-extra", order=5, diff="hard", mins=50,
title="TPM и измеренная загрузка: что можно доказать",
tags="[forensics, tpm, measured-boot, bitlocker, pcr]",
prereq="[forensics-fs-structure]",
summary="Как TPM хранит измерения загрузки (PCR), как это связано с BitLocker и что можно доказать по журналу измерений.",
body=r'''
## Вопрос, с которого всё начинается

Нужно доказать, что система загружалась штатно (или что загрузчик подменили). У
современных ПК есть **TPM** — чип, который измеряет загрузку. Разберём, как это
использовать в форензике.

## Наш пример: ПК с TPM 2.0

## Шаг 1: что такое TPM и PCR

TPM — защищённый чип. Он хранит **PCR** (Platform Configuration Registers) — хеши
компонентов загрузки. Каждый этап загрузки «измеряется»: хеш записывается в PCR.

```
$ tpm2_pcrread sha256:0,4,7
sha256:
  0 : 0x3d4b...  (firmware)
  4 : 0x9a1c...  (boot loader)
  7 : 0x...      (secure boot policy)
```

## Шаг 2: измеренная загрузка

Цепочка:

1. прошивка измеряет себя → PCR0;
2. загрузчик → PCR4;
3. ОС-компоненты → PCR7+.

Если хотя бы один компонент изменён, PCR меняется. Это **доказательство** состояния
загрузки.

## Шаг 3: связь с BitLocker

BitLocker «запечатывает» ключ на значения PCR. Если PCR не совпали (загрузчик
подменили) — ключ не выдаётся:

```
Sealed to PCRs 0,2,4,11
```

Значит, изменение загрузчика **ломает** расшифровку — защита и улика одновременно.

## Шаг 4: что можно доказать

- загрузка шла штатной цепочкой (PCR совпадают с эталоном);
- **или** была подмена (PCR не совпадают);
- момент изменения (по журналу);
- связь с ключами BitLocker.

## Шаг 5: практика

- снять PCR: `tpm2_pcrread`;
- сверить с эталоном известной конфигурации;
- проверить event log (TCG log);
- учесть, что TPM можно сбросить (с потерей ключей).

## Что мы теперь знаем

- TPM хранит PCR — хеши компонентов загрузки.
- Измеренная загрузка фиксирует каждый этап.
- BitLocker печатает ключ на PCR.
- Расхождение PCR = подмена/изменение.
- PCR снимают `tpm2_pcrread`, сверяют с эталоном.

## Если не сработало

- TPM сброшен? Ключи потеряны, PCR пусты.
- Нет эталона? Сравни с известной конфигурацией.
- Нужен лог? Читай TCG event log.

## Квиз

Проверь себя.

```quiz
- question: Что хранит TPM?
  options:
    - 'файлы'
    - 'PCR — хеши компонентов загрузки'
    - 'сеть'
    - 'обои'
  answer: 1
  explanation: 'PCR фиксируют измерения этапов загрузки.'
- question: Как связаны BitLocker и PCR?
  options:
    - 'никак'
    - 'ключ запечатан на значения PCR'
    - 'через сеть'
    - 'через реестр'
  answer: 1
  explanation: 'Изменение PCR мешает выдать ключ расшифровки.'
- question: Что означает расхождение PCR с эталоном?
  options:
    - 'ничего'
    - 'компонент загрузки был изменён'
    - 'диск пуст'
    - 'сеть упала'
  answer: 1
  explanation: 'PCR чувствительны к любому изменению измеряемого компонента.'
- question: Как снять значения PCR?
  options:
    - 'ls'
    - 'tpm2_pcrread'
    - 'grep'
    - 'ping'
  answer: 1
  explanation: 'tpm2_pcrread выводит текущие значения PCR.'
```
''')

LESSONS["doc-ooxml-internals"] = dict(
parent="forensics-doc-formats", order=1, diff="medium", mins=45,
title="OOXML изнутри: docx, xlsx, pptx как ZIP-архивы",
tags="[forensics, ooxml, docx, xlsx, macros, metadata]",
prereq="[forensics-file-magic]",
summary="Как устроены офисные документы OOXML, где метаданные, макросы и встроенные объекты, и как их извлекать.",
body=r'''
## Вопрос, с которого всё начинается

Пришёл документ `.docx` — он может быть безобидным, а может содержать макрос или
встроенный объект. Формат OOXML — это **ZIP** с XML внутри. Разберём структуру.

## Наш пример: подозрительный .docx

## Шаг 1: это ZIP

```
$ file report.docx
report.docx: Microsoft Word 2007+
$ unzip -l report.docx
  [Content_Types].xml
  word/document.xml
  word/vbaProject.bin
  docProps/core.xml
```

`vbaProject.bin` — уже сигнал: в документе есть **макросы**.

## Шаг 2: метаданные

```
$ unzip -p report.docx docProps/core.xml | head
<dc:creator>Ivan</dc:creator>
<cp:lastModifiedBy>Ivan</cp:lastModifiedBy>
<dcterms:created>2026-01-14T03:20:00Z</dcterms:created>
```

`core.xml` — авторство и времена. Расхождение created/modified — зацепка.

## Шаг 3: макросы

Макросы — это VBA. Извлекаем и анализируем:

```
$ olevba report.docx
VBA MACRO ThisDocument.cls
  AutoOpen → Shell("powershell -enc ...")
```

`AutoOpen` — автозапуск при открытии. Это классический вектор.

## Шаг 4: встроенные объекты

Документ может содержать:

- встроенный `.exe` (в `word/embeddings/`);
- OLE-объекты;
- внешние ссылки (`word/_rels/`) — откуда подгружаются данные (DDE, remote template).

```
$ unzip -l report.docx | grep embeddings
word/embeddings/oleObject1.bin
```

## Шаг 5: что искать

- макросы (`vbaProject.bin`);
- внешние ссылки (remote template injection);
- встроенные файлы;
- метаданные автора/времени.

## Что мы теперь знаем

- OOXML — ZIP с XML.
- `vbaProject.bin` = макросы.
- `core.xml` — авторство и времена.
- `embeddings/` — встроенные объекты.
- Внешние ссылки = потенциальная загрузка.

## Если не сработало

- Файл зашифрован паролем? Нужен пароль.
- Старый формат (.doc)? Используй OLE-парсеры.
- Макрос скомпилирован? Анализируй p-code.

## Квиз

Проверь себя.

```quiz
- question: Что представляет собой .docx?
  options:
    - 'бинарный файл'
    - 'ZIP-архив с XML'
    - 'текстовый файл'
    - 'образ диска'
  answer: 1
  explanation: 'OOXML — это zip-контейнер с XML-компонентами.'
- question: Что означает vbaProject.bin?
  options:
    - 'картинку'
    - 'наличие макросов VBA'
    - 'шрифт'
    - 'пароль'
  answer: 1
  explanation: 'Это хранилище VBA-макросов документа.'
- question: Где искать автора и время?
  options:
    - 'в document.xml'
    - 'в docProps/core.xml'
    - 'в vbaProject.bin'
    - 'в embeddings'
  answer: 1
  explanation: 'core.xml содержит creator и created/modified.'
- question: Чем опасен AutoOpen?
  options:
    - 'ничем'
    - 'запускает макрос при открытии документа'
    - 'удаляет файл'
    - 'шифрует'
  answer: 1
  explanation: 'AutoOpen — автозапуск VBA при открытии.'
```
''')

LESSONS["doc-odf"] = dict(
parent="forensics-doc-formats", order=2, diff="medium", mins=40,
title="ODF: открытый формат документов изнутри",
tags="[forensics, odf, opendocument, metadata, documents]",
prereq="[forensics-file-magic]",
summary="Как устроен ODF (odt/ods/odp), где метаданные и встроенные объекты, чем отличается от OOXML.",
body=r'''
## Вопрос, с которого всё начинается

Встречается документ `.odt` (LibreOffice/OpenOffice). Это тоже ZIP, но со своей
структурой и метаданными. Разберём, как его читать.

## Наш пример: .odt

## Шаг 1: структура

```
$ unzip -l doc.odt
  mimetype
  content.xml
  meta.xml
  styles.xml
  settings.xml
  Thumbnails/thumbnail.png
```

`mimetype` — тип документа, `content.xml` — содержимое, `meta.xml` — метаданные.

## Шаг 2: метаданные

```
$ unzip -p doc.odt meta.xml
<meta:initial-creator>Ivan</meta:initial-creator>
<meta:creation-date>2026-01-14T03:20:00Z</meta:creation-date>
<meta:editing-cycles>4</meta:editing-cycles>
```

ODF хранит **initial-creator** и число циклов редактирования — то, чего нет в OOXML так
явно.

## Шаг 3: отличия от OOXML

- ODF — открытый стандарт (ISO);
- метаданные в `meta.xml` (отдельный файл);
- макросы — в `Basic/` (LibreOffice Basic) или через внешние ссылки;
- нет `vbaProject.bin`.

## Шаг 4: что искать

- автора и время;
- историю правок (editing-cycles);
- встроенные объекты/картинки;
- внешние ссылки;
- макросы (реже, но бывают).

## Шаг 5: практика

```
$ unzip -o doc.odt -d odt_out
$ grep -ri 'macro\|script' odt_out/ | head
```

## Что мы теперь знаем

- ODF — ZIP с `content.xml`/`meta.xml`.
- `meta.xml` хранит автора и циклы правок.
- Отличия от OOXML: открытый стандарт, иные метаданные.
- Макросы реже, но возможны.
- Разбирается распаковкой.

## Если не сработало

- Файл повреждён? Попробуй восстановить ZIP.
- Макросы? Ищи Basic-скрипты.
- Нужен контент? Читай content.xml.

## Квиз

Проверь себя.

```quiz
- question: Что такое ODF?
  options:
    - 'бинарный формат'
    - 'открытый ZIP-формат документов'
    - 'сетевой протокол'
    - 'образ диска'
  answer: 1
  explanation: 'ODF (odt/ods) — открытый стандарт на базе ZIP+XML.'
- question: Где метаданные ODF?
  options:
    - 'в content.xml'
    - 'в meta.xml'
    - 'в mimetype'
    - 'в стилях'
  answer: 1
  explanation: 'meta.xml содержит автора, даты, циклы редактирования.'
- question: Что даёт editing-cycles?
  options:
    - 'размер'
    - 'число циклов редактирования документа'
    - 'пароль'
    - 'сеть'
  answer: 1
  explanation: 'Это косвенная история правок документа.'
- question: Как разобрать ODF?
  options:
    - 'запустить'
    - 'распаковать как ZIP'
    - 'открыть в браузере'
    - 'никак'
  answer: 1
  explanation: 'ODF — zip-контейнер, разбирается распаковкой.'
```
''')

LESSONS["doc-rtf"] = dict(
parent="forensics-doc-formats", order=3, diff="medium", mins=45,
title="RTF в форензике: объекты и скрытая нагрузка",
tags="[forensics, rtf, ole, exploit, documents]",
prereq="[forensics-file-magic]",
summary="Как читать RTF, находить в нём встроенные OLE-объекты и эксплойты, и почему RTF — популярный вектор.",
body=r'''
## Вопрос, с которого всё начинается

RTF — «Rich Text Format», текстовый формат с разметкой. Его легко создать и он
поддерживает **встроенные объекты**, поэтому часто используется для доставки
эксплойтов. Разберём.

## Наш пример: подозрительный .rtf

## Шаг 1: это текст

```
$ file invoice.rtf
invoice.rtf: Rich Text Format data
$ head -c 200 invoice.rtf
{\rtf1\ansi ...
```

RTF читается как текст, но внутри — управляющие последовательности (`\objdata`, `\object`).

## Шаг 2: встроенный OLE-объект

Ключевое — `\object` + `\objdata`, где лежит OLE-объект в hex:

```
{\object\objemb{\*\objclass Package}\objw100\objh100
{\*\objdata 0105000002000000...}}
```

`objclass Package` — встроенный файл (например, `.exe`). `\objdata` — его hex-представление.

## Шаг 3: извлекаем

```
$ python3 -c "import re;d=open('invoice.rtf').read();h=re.search(r'objdata ([0-9a-fA-F]+)',d).group(1);open('obj.bin','wb').write(bytes.fromhex(h))"
$ file obj.bin
obj.bin: OLE 2 Compound Document
```

Дальше разбираем OLE-объект.

## Шаг 4: эксплойты

RTF известен эксплойтами (например, Equation Editor, OLE-уязвимости). Признаки:

- большие `\objdata` блоки;
- ссылки на уязвимые объекты;
- `\objupdate` (авто-обновление).

## Шаг 5: что искать

- встроенные OLE-объекты;
- hex-блоки (`\objdata`);
- внешние ссылки;
- необычно большой RTF.

## Что мы теперь знаем

- RTF — текстовый формат с разметкой.
- `\object`/`\objdata` несут встроенные объекты (hex).
- Объект извлекается декодированием hex.
- RTF — известный вектор эксплойтов.
- Признак — большие objdata-блоки.

## Если не сработало

- Несколько объектов? Извлекай все.
- Сжатый объект? Распакуй после декода.
- Нужен анализ? Открой OLE-парсером.

## Квиз

Проверь себя.

```quiz
- question: Что такое RTF?
  options:
    - 'бинарный формат'
    - 'текстовый формат с разметкой'
    - 'образ диска'
    - 'протокол'
  answer: 1
  explanation: 'RTF — текстовый Rich Text Format.'
- question: Что несёт \objdata?
  options:
    - 'пароль'
    - 'встроенный объект в hex'
    - 'сеть'
    - 'обои'
  answer: 1
  explanation: 'objdata содержит hex-представление встроенного OLE-объекта.'
- question: Почему RTF популярен у атакующих?
  options:
    - 'он красивый'
    - 'поддерживает встроенные объекты и известен эксплойтами'
    - 'он быстрый'
    - 'он новый'
  answer: 1
  explanation: 'Встроенные объекты и уязвимости делают RTF удобным вектором.'
- question: Как извлечь объект из objdata?
  options:
    - 'grep'
    - 'декодировать hex в бинарь'
    - 'открыть в браузере'
    - 'никак'
  answer: 1
  explanation: 'objdata — hex; после декода получаем OLE-объект.'
```
''')

LESSONS["doc-xps"] = dict(
parent="forensics-doc-formats", order=4, diff="medium", mins=40,
title="XPS: «PDF от Microsoft» и его разбор",
tags="[forensics, xps, oxps, documents, metadata]",
prereq="[forensics-file-magic]",
summary="Что такое XPS/OXPS, как устроен формат, где метаданные и как его анализировать.",
body=r'''
## Вопрос, с которого всё начинается

Встречается файл `.xps` — «документ фиксированного вида» от Microsoft. Это ZIP с
страницами в XML. Разберём структуру и что в нём искать.

## Наш пример: .xps

## Шаг 1: это ZIP

```
$ file doc.xps
doc.xps: Microsoft XPS Document
$ unzip -l doc.xps
  FixedDocumentSequence.fdseq
  Documents/1/Pages/1.fpage
  Metadata/...
  [Content_Types].xml
```

`FixedDocumentSequence` — корень, `Pages/*.fpage` — страницы (XML с элементами).

## Шаг 2: метаданные

XPS хранит метаданные в `Metadata/`:

```
$ unzip -p doc.xps 'Metadata/*' | head
<psf:DocumentProperties>
  <psf:Author>Ivan</psf:Author>
```

## Шаг 3: содержимое страниц

Страницы — XML с текстом и графикой:

```
$ unzip -p doc.xps 'Documents/1/Pages/1.fpage' | grep -o 'UnicodeString="[^"]*"' | head
UnicodeString="Confidential"
```

Текст извлекается как XML-атрибуты — легко искать ключевые слова.

## Шаг 4: встроенные ресурсы

XPS может содержать:

- изображения (`Resources/`);
- шрифты (в т.ч. встроенные);
- ссылки на внешние ресурсы (можно отключить).

## Шаг 5: практика

```
$ unzip -o doc.xps -d xps_out
$ grep -ri 'http\|script' xps_out/ | head
```

## Что мы теперь знаем

- XPS/OXPS — ZIP с XML-страницами.
- Метаданные в `Metadata/`.
- Текст извлекается как XML-атрибуты.
- Может содержать изображения и шрифты.
- Разбирается распаковкой.

## Если не сработало

- OXPS? Структура та же (OpenXPS).
- Нужен рендер? Используй XPS Viewer.
- Ссылки на внешние? Проверь rels.

## Квиз

Проверь себя.

```quiz
- question: Что такое XPS?
  options:
    - 'бинарный формат'
    - 'ZIP-формат фиксированного документа (XML)'
    - 'сеть'
    - 'образ'
  answer: 1
  explanation: 'XPS — zip-контейнер со страницами XML.'
- question: Где метаданные XPS?
  options:
    - 'в страницах'
    - 'в Metadata/'
    - 'в fdseq'
    - 'в шрифтах'
  answer: 1
  explanation: 'Каталог Metadata хранит свойства документа.'
- question: Как извлекается текст из страниц?
  options:
    - 'через рендер'
    - 'как XML-атрибуты (UnicodeString)'
    - 'никак'
    - 'через OCR'
  answer: 1
  explanation: 'Текст страниц лежит в XML-атрибутах.'
- question: Как разобрать XPS?
  options:
    - 'запустить'
    - 'распаковать как ZIP'
    - 'открыть в браузере'
    - 'никак'
  answer: 1
  explanation: 'XPS — zip; разбирается распаковкой.'
```
''')

LESSONS["mem-macos"] = dict(
parent="forensics-memory-extra", order=1, diff="hard", mins=50,
title="Память macOS: сбор и анализ",
tags="[forensics, memory, macos, volatility, unified-memory]",
prereq="[forensics-memory-artifacts]",
summary="Особенности памяти macOS: унифицированная память, сжатие, инструменты сбора и что искать в дампе.",
body=r'''
## Вопрос, с которого всё начинается

Нужно проанализировать память Mac. Но macOS отличается: сжатие страниц, унифицированная
память на Apple Silicon, ограниченная поддержка Volatility. Разберём.

## Наш пример: дамп Mac

## Шаг 1: особенности

- **compressed memory** — неактивные страницы сжимаются, а не пишутся в swap;
- **UMA** (Apple Silicon) — общая память CPU/GPU;
- **шифрование swap** — выгруженные страницы зашифрованы.

Это меняет то, что вообще попадает в дамп.

## Шаг 2: сбор

```
$ sudo osxpmem -o mac.raw
```

Или специализированные средства (в т.ч. коммерческие). На Apple Silicon вариантов
меньше.

## Шаг 3: анализ

Volatility для macOS ограничена. Базовый подход:

- `strings` + `grep` по IOC;
- плагины профилей macOS (если есть);
- специализированные парсеры.

```
$ strings mac.raw | grep -iE 'http://|https://' | head
```

## Шаг 4: что искать

- **процессы** и командные строки;
- **открытые файлы/сокеты**;
- **пароли и ключи**;
- **расшифрованные данные**;
- **код в памяти** (fileless).

## Шаг 5: практика

- фиксируй версию ОС (влияет на структуры);
- снимай память до выключения;
- считай хеш;
- комбинируй с unified log.

## Что мы теперь знаем

- macOS сжимает память и шифрует swap.
- Apple Silicon использует унифицированную память.
- Сбор — osxpmem/спец. средства.
- Volatility ограничена — используй strings/парсеры.
- Ищем процессы, ключи, fileless-код.

## Если не сработало

- Apple Silicon? Используй живые средства.
- Нет профиля? Работай строками.
- Нужен порядок? Фиксируй версию ОС.

## Квиз

Проверь себя.

```quiz
- question: Чем macOS-память отличается от Windows?
  options:
    - 'ничем'
    - 'сжатие страниц и шифрование swap'
    - 'она меньше'
    - 'она в облаке'
  answer: 1
  explanation: 'macOS сжимает неактивные страницы и шифрует swap.'
- question: Какой инструмент снимает память macOS?
  options:
    - 'ls'
    - 'osxpmem'
    - 'grep'
    - 'nmap'
  answer: 1
  explanation: 'osxpmem — средство сбора дампа памяти macOS.'
- question: Что делать, если Volatility не поддерживает профиль?
  options:
    - 'сдаться'
    - 'использовать strings и спец. парсеры'
    - 'перезагрузиться'
    - 'удалить дамп'
  answer: 1
  explanation: 'Базовый анализ возможен по строкам и IOC.'
- question: Почему важно фиксировать версию ОС?
  options:
    - 'для отчёта'
    - 'структуры памяти зависят от версии'
    - 'для сети'
    - 'неважно'
  answer: 1
  explanation: 'Профили и структуры ядра привязаны к версии.'
```
''')

LESSONS["mem-dyld-cache"] = dict(
parent="forensics-memory-extra", order=2, diff="hard", mins=45,
title="dyld-кэш: разделяемый код macOS",
tags="[forensics, memory, macos, dyld, cache]",
prereq="[forensics-memory-artifacts]",
summary="Что такое dyld shared cache, где он живёт, как извлекать из него библиотеки и почему это важно для анализа macOS.",
body=r'''
## Вопрос, с которого всё начинается

На macOS системные библиотеки лежат не отдельными файлами, а в одном большом
**dyld shared cache**. Это важно и для анализа памяти, и для реверса. Разберём.

## Наш пример: dyld-кэш

## Шаг 1: что это

`dyld` — динамический загрузчик macOS. Чтобы ускорить запуск, все системные
библиотеки объединены в единый файл — shared cache:

```
/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e
```

Отдельных `.dylib` на диске может не быть — они внутри кэша.

## Шаг 2: извлечение

```
$ dyld-shared-cache-extractor dyld_shared_cache_arm64e ./out
```

Или `dyldex`. После извлечения появляются обычные `.dylib`, пригодные для анализа.

## Шаг 3: зачем это форензике

- **анализ памяти** — адреса библиотек в дампе указывают в кэш;
- **реверс** — нужно получить «чистые» библиотеки;
- **сравнение** — подменённая библиотека в кэше = компромисс;
- **символы** — кэш хранит отладочную информацию.

## Шаг 4: в дампе памяти

В памяти библиотеки замаплены из кэша по определённым адресам. По смещениям можно
понять, какая библиотека и какая функция выполнялась:

```
$ strings mac.raw | grep -i 'libsystem' | head
```

## Шаг 5: практика

- извлекай кэш для целевой версии ОС;
- сопоставляй адреса дампа с кэшем;
- проверяй целостность (подпись).

## Что мы теперь знаем

- dyld shared cache — объединённый файл системных библиотек macOS.
- Отдельных dylib может не быть.
- Извлекается dyld-shared-cache-extractor/dyldex.
- Нужен для анализа памяти и реверса.
- Подмена кэша = компромисс.

## Если не сработало

- Кэш не извлекается? Проверь версию инструмента.
- Нужна другая ОС? Бери кэш этой версии.
- Символы отсутствуют? Используй отдельные symbol-файлы.

## Квиз

Проверь себя.

```quiz
- question: Что такое dyld shared cache?
  options:
    - 'сетевой кэш'
    - 'объединённый файл системных библиотек macOS'
    - 'реестр'
    - 'образ'
  answer: 1
  explanation: 'Все системные dylib объединены в один кэш-файл.'
- question: Почему отдельных .dylib может не быть?
  options:
    - 'они удалены'
    - 'они внутри dyld-кэша'
    - 'они в облаке'
    - 'они в реестре'
  answer: 1
  explanation: 'Библиотеки хранятся внутри shared cache.'
- question: Чем полезен кэш для анализа памяти?
  options:
    - 'ничем'
    - 'адреса библиотек в дампе указывают в кэш'
    - 'шифрует'
    - 'сжимает'
  answer: 1
  explanation: 'Сопоставление адресов дампа и кэша даёт контекст.'
- question: Как извлечь библиотеки из кэша?
  options:
    - 'unzip'
    - 'dyld-shared-cache-extractor/dyldex'
    - 'grep'
    - 'cp'
  answer: 1
  explanation: 'Эти инструменты распаковывают кэш в отдельные dylib.'
```
''')

LESSONS["mem-registry-hives"] = dict(
parent="forensics-memory-extra", order=3, diff="hard", mins=45,
title="Кусты реестра из памяти: восстановление из дампа",
tags="[forensics, memory, registry, hives, volatility]",
prereq="[forensics-memory-artifacts]",
summary="Как извлечь кусты реестра прямо из дампа памяти, когда файлы hives недоступны или повреждены.",
body=r'''
## Вопрос, с которого всё начинается

Файлы реестра на диске повреждены или зашифрованы. Но реестр был загружен в память —
и его можно оттуда достать. Разберём.

## Наш пример: дамп Windows

## Шаг 1: реестр в памяти

Ядро держит загруженные кусты в памяти. Volatility умеет их находить:

```
$ vol.py -f mem.raw windows.registry.hivelist
Offset      FileFullPath
0x...  \SystemRoot\System32\Config\SOFTWARE
0x...  \??\C:\Users\Ivan\NTUSER.DAT
```

`hivelist` перечисляет загруженные кусты и их адреса в памяти.

## Шаг 2: дампим куст

```
$ vol.py -f mem.raw windows.registry.hivedump --hive-offset 0x... -o SOFTWARE.hive
```

Получаем настоящий файл-куст, который можно открыть RegRipper/Registry Explorer.

## Шаг 3: зачем

- файлы на диске зашифрованы (BitLocker без ключа) — память даёт реестр;
- куст повреждён — память даёт целую версию;
- нужно **актуальное** состояние (на момент снятия).

## Шаг 4: что искать

- автозапуск (`Run`);
- недавние изменения;
- подключённые USB;
- пароли/секреты (иногда в открытом виде);
- конфигурацию.

## Шаг 5: практика

- дампи **все** кусты (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER);
- анализируй RegRipper-плагинами;
- сопоставляй с дисковыми копиями (расхождения = активность).

## Что мы теперь знаем

- Загруженные кусты живут в памяти.
- `hivelist` находит их, `hivedump` извлекает.
- Память спасает, когда диск зашифрован/повреждён.
- Из кустов достаём автозапуск, USB, секреты.
- Дампь все кусты и сопоставляй.

## Если не сработало

- Hive не найден? Проверь профиль/версию.
- Куст повреждён в дампе? Пробуй другие адреса.
- Нужен разбор? Используй RegRipper.

## Квиз

Проверь себя.

```quiz
- question: Что делает windows.registry.hivelist?
  options:
    - 'удаляет кусты'
    - 'перечисляет загруженные кусты реестра в памяти'
    - 'шифрует'
    - 'сканирует сеть'
  answer: 1
  explanation: 'Плагин находит адреса загруженных hive в дампе.'
- question: Чем полезна память для реестра?
  options:
    - 'ничем'
    - 'даёт кусты, когда диск зашифрован/повреждён'
    - 'ускоряет'
    - 'шифрует'
  answer: 1
  explanation: 'Загруженные кусты живут в памяти независимо от диска.'
- question: Как извлечь куст целиком?
  options:
    - 'grep'
    - 'windows.registry.hivedump'
    - 'cp'
    - 'ping'
  answer: 1
  explanation: 'hivedump сохраняет куст в файл для разбора.'
- question: Что искать в кустах?
  options:
    - 'обои'
    - 'автозапуск, USB, секреты, конфигурацию'
    - 'сеть'
    - 'музыку'
  answer: 1
  explanation: 'Реестр хранит ключевые следы активности.'
```
''')

emit(HUBS, LESSONS)
