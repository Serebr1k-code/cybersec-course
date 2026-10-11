---
id: stego-disk
title: "Стеганография на диске: slack space, ADS и скрытые разделы"
category: stego
parent: stego-binary-carriers
difficulty: medium
order: 1
tags: [stego, disk, slack, ads, partition, ntfs, forensics]
prerequisites: [stego-appended]
useful_for:
  - "CTF Forensics/Stego — образы дисков"
  - "Понимание файловых систем"
  - "IR: поиск скрытых данных на носителях"
estimated_minutes: 45
summary: "Сокрытие данных на диске: slack space, Alternate Data Streams (ADS), скрытые/пустые разделы, данные в неразмеченных областях и после конца раздела; инструменты и извлечение."
---

Диск — большой носитель с «щелями»: slack space (хвост последнего кластера файла), неразмеченные области между разделами, Alternate Data Streams (NTFS), удалённые файлы, данные после конца раздела. Данные можно спрятать так, что обычный просмотр файлов их не покажет.

## Slack space

Файл занимает целое число кластеров; хвост последнего кластера (slack) не используется для данных файла и может нести скрытое.

```bash
# найти и извлечь slack (blkls/blkcat из sleuthkit)
blkls -s image.dd > slack.bin
strings -a slack.bin | grep -i flag | head
# или через blkcat по inode
```

## NTFS Alternate Data Streams (ADS)

NTFS позволяет файлу иметь несколько потоков. `file.txt:secret` — скрытый поток, не виден в обычном `dir`.

```bash
# перечислить ADS (Windows)
dir /r file.txt
# извлечь поток
more < file.txt:secret
# на Linux (ntfs-3g)
cat file.txt:secret
# поиск потоков в образе
fls -r image.dd | grep ':'    # sleuthkit
```

## Разделы и неразмеченные области

- Скрытый/пустой раздел (не в таблице разделов или с минимальным содержимым).
- Данные после конца раздела/файловой системы.
- Неразмеченное пространство между разделами.

```bash
# таблица разделов
mmls image.dd
# каравер
binwalk image.dd
foremost -i image.dd -o out
# данные после ФС
# определить размер ФС и вырезать хвост
```

## Удалённые файлы и журналы

```bash
# восстановить удалённые файлы
fls -r -d image.dd
tsk_recover image.dd recovered/
# журнал NTFS
log2timeline.py timeline.db image.dd
```

## Разобранный пример

CTF Forensics: образ `disk.dd`. Пентестер:
1. `mmls disk.dd` → находит скрытый раздел.
2. `fls -r disk.dd | grep ':'` → ADS `notes.txt:flag`.
3. `icat disk.dd <inode>` → флаг. Или `blkls -s` → флаг в slack.

## Частые ошибки

- Монтировать образ и смотреть только «видимые» файлы.
- Не проверять ADS (на NTFS).
- Игнорировать неразмеченные области/скрытые разделы.
- Не извлекать slack space.

## Что делать дальше

- **Скрытый раздел** → `mmls`, монтируйте/караверьте.
- **ADS** → `fls | grep ':'`, `icat`.
- **Slack** → `blkls -s`, `strings`.
- **Удалённые файлы** → `tsk_recover`.

## Полная карта носителя: где прячут данные

Прежде чем извлекать, составьте карту образа — тогда вы будете точно знать, какие «щели» проверять.

| Область | Что там | Инструмент |
|---------|---------|-----------|
| Таблица разделов (MBR/GPT) | разделы, скрытые записи | `mmls`, `fdisk -l` |
| Неразмеченное пространство | данные между разделами | `dd`, `blkls` |
| Slack space | хвост последнего кластера файла | `blkls -s` |
| NTFS ADS | `file:stream` потоки | `fls`, `icat` |
| Удалённые файлы | данные в невыделенных кластерах | `fls -d`, `tsk_recover` |
| Журнал/MFT | история операций | `log2timeline`, `MFTECmd` |
| Хвост после ФС | «appended» данные | `binwalk`, `dd` |

```bash
# Общая разведка образа
file image.dd
mmls image.dd                 # таблица разделов
fsstat image.dd               # параметры ФС
binwalk image.dd              # встроенные файлы/сигнатуры
```

## Slack space: извлечение по шагам

Slack — «пустой» остаток последнего кластера. Данные там не видны в файловой системе, но физически лежат в образе.

```bash
# Выгрузить только slack-байты всех файлов
blkls -s image.dd > slack.bin
strings -a slack.bin | grep -iE 'flag|ctf|key' | head
# Посмотреть размер slack
ls -l slack.bin

# Через inode: найти кластеры файла и хвост последнего
istat image.dd <inode>         # блоки файла
blkcat image.dd <last_cluster> # дамп кластера — хвост содержит скрытое
```

```python
# Ручной поиск «хвоста» кластера: файл занимает ceil(size/4096) кластеров;
# последний кластер заполнен лишь частично — байты после size и есть slack.
import subprocess
```

## NTFS ADS: полный разбор

Alternate Data Streams позволяют файлу иметь несколько потоков; основной поток — то, что видит `dir`, остальные — скрыты.

```bash
# sleuthkit: перечислить потоки в образе (у ADS в fls стоит ':')
fls -r image.dd | grep ':'
# извлечь конкретный поток по inode
icat image.dd <inode> <attr_id>
# смонтировать и читать как file:stream
sudo mount -o loop,ro image.dd /mnt
cat "/mnt/file.txt:secret"
ls -la /mnt                # ADS часто не видны в ls
# Windows: dir /r, powershell Get-Item -Stream *
powershell -c "Get-Item file.txt -Stream *"
```

## Скрытые разделы и неразмеченные области

- **Раздел не в таблице:** существует, но `mmls` его не показывает; ищите по сигнатурам ФС (`binwalk`, `testdisk`).
- **Данные после раздела:** сразу за концом последнего раздела — `dd` от его конца.
- **Неразмеченное между разделами:** вырезать и `strings`/`binwalk`.

```bash
mmls image.dd
# вырезать область после конца последнего раздела (пример смещения)
dd if=image.dd bs=512 skip=<end_sector> of=tail.bin
binwalk tail.bin && foremost -i tail.bin -o out
testdisk image.dd          # поиск потерянных разделов
```

## Удалённые файлы, журнал и MFT

```bash
fls -r -d image.dd                     # список удалённых
tsk_recover image.dd recovered/        # восстановить
# журнал NTFS ($LogFile) и MFT
log2timeline.py timeline.db image.dd
# MFTECmd / analyzeMFT — разбор $MFT
```

## Инструменты (полный набор)

| Инструмент | Назначение | Пример |
|------------|-----------|--------|
| `mmls` | таблица разделов | `mmls image.dd` |
| `fsstat` | параметры ФС | `fsstat image.dd` |
| `fls` | листинг (в т.ч. `-d` удалённые) | `fls -r image.dd` |
| `icat` | извлечь по inode/потоку | `icat image.dd 42` |
| `istat` | метаданные inode | `istat image.dd 42` |
| `blkls`/`blkcat` | сырые блоки/slack | `blkls -s image.dd` |
| `tsk_recover` | восстановление файлов | `tsk_recover image.dd out/` |
| `binwalk`/`foremost` | каравер | `binwalk image.dd` |
| `testdisk` | потерянные разделы | `testdisk image.dd` |
| `log2timeline` | таймлайн | `log2timeline.py db image.dd` |

## Разобранные примеры

**1. Скрытый раздел.** `mmls` показывает два раздела, но `fsstat` по второму — пусто; `binwalk` находит в нём ZIP с флагом.

**2. ADS.** `fls -r image.dd | grep ':'` → `notes.txt:flag`; `icat` извлекает поток → флаг.

**3. Slack.** Видимые файлы чистые; `blkls -s image.dd | strings | grep flag` → флаг в slack.

## Частые ошибки и отладка

- **Монтировать и смотреть только видимые файлы** — главная ошибка.
- **Не проверять ADS** на NTFS.
- **Пропустить неразмеченные области/скрытый раздел.**
- **Не извлекать slack** (нужен `blkls -s`, не `fls`).
- **Отладка:** если `mmls` не видит ФС — `binwalk`/`testdisk`; если файл «есть», но пуст — смотрите ADS и slack.

## Что делать дальше / дерево решений

1. `mmls`/`fsstat` → карта. Скрытый/странный раздел? → монтируйте/караверьте.
2. `fls -r | grep ':'` → ADS? → `icat`.
3. `blkls -s` → slack → `strings`.
4. `fls -d`/`tsk_recover` → удалённые.
5. Всё чисто → `binwalk`/`dd` хвост образа.

## Шпаргалка: конвейер по образу

```bash
# 1) карта
mmls image.dd && fsstat image.dd
# 2) ADS
fls -r image.dd | grep ':'
icat image.dd <inode> <attr>
# 3) slack
blkls -s image.dd | strings | grep -iE 'flag|ctf'
# 4) удалённые
fls -r -d image.dd; tsk_recover image.dd out/
# 5) хвост/каравер
binwalk image.dd; foremost -i image.dd -o carved/
```

Рабочий процесс: сначала составьте карту (`mmls`/`fsstat`), затем пройдите по «щелям» сверху вниз: ADS → slack → удалённые → неразмеченные области → хвост. Если `mmls` не видит ФС, а `binwalk` находит сигнатуру — используйте `testdisk` для поиска потерянного раздела. Если видимые файлы «пустые» — проверьте ADS и slack. В отчёте фиксируйте область (раздел/slack/ADS/удалённый), inode и метод извлечения — это критично для воспроизводимости в forensics.

## Квиз

```quiz
- question: "Что такое slack space?"
  options:
    - "Неиспользуемый хвост последнего кластера файла"
    - "Заголовок раздела"
    - "Журнал ФС"
    - "Тип ADS"
  answer: 0
  explanation: "Slack — остаток кластера, куда можно записать данные."
- question: "Что такое NTFS Alternate Data Stream?"
  options:
    - "Дополнительный поток данных файла (file:stream)"
    - "Раздел диска"
    - "Журнал"
    - "Кластер"
  answer: 0
  explanation: "ADS позволяет файлу иметь несколько потоков."
- question: "Каким инструментом посмотреть таблицу разделов образа?"
  options:
    - "mmls"
    - "zsteg"
    - "jadx"
    - "mutool"
  answer: 0
  explanation: "mmls из sleuthkit показывает разделы."
- question: "Как извлечь файл по inode из образа?"
  options:
    - "icat image.dd <inode>"
    - "cat image.dd"
    - "binwalk image.dd"
    - "file image.dd"
  answer: 0
  explanation: "icat извлекает содержимое по inode."
- question: "Чем восстановить удалённые файлы?"
  options:
    - "tsk_recover / fls -d"
    - "strings"
    - "exiftool"
    - "zsteg"
  answer: 0
  explanation: "sleuthkit восстанавливает удалённые файлы."
```

## Где пригодится

- **CTF Forensics/Stego:** образы дисков.
- **IR:** поиск скрытых данных на носителях.
- **Пентест:** физический доступ и forensics.
- **Работа:** цифровая криминалистика.
