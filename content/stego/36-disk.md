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

## Вопрос, с которого всё начинается

Тебе дали `disk.dd` — образ диска. Ты монтируешь его, видишь обычные файлы, все они чистые. Флага нет. Но задача гарантирует, что он там.

Ответ: данные спрятаны не в файлах, а в **«щелях»** файловой системы — между файлами, после конца раздела, в невидимых потоках. Разберём образ по шагам.

## Наш пример: disk.dd

Сначала составим **карту** образа — какие разделы, какая файловая система.

```
$ file disk.dd
disk.dd: DOS/MBR boot sector
$ mmls disk.dd
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors
      Slot      Start        End          Length       Description
00:  Meta            0          2047          2048   Safety Table
01:  ------         2048       204799        202752   EFI System Partition
02:  ------       204800       819199        614400   Linux (0x83)
```

Видим два раздела. `mmls` (из Sleuth Kit) показывает таблицу разделов. Дальше — параметры файловой системы:

```
$ fsstat disk.dd
File System Type: NTFS
```

## Шаг 1: ADS — Alternate Data Streams

NTFS позволяет файлу иметь **несколько потоков**. Обычный `dir`/`ls` показывает только основной поток, а дополнительные (`file:stream`) скрыты. Ищем их по двоеточию в листинге:

```
$ fls -r disk.dd | grep ':'
r/r 42-128-1: notes.txt
r/r 42-128-2: notes.txt:flag
```

Поток `notes.txt:flag` — скрытый. Извлечём его по inode и attribute id:

```
$ icat disk.dd 42-128-2
flag{ads_stream}
```

## Шаг 2: slack space

Файл занимает целое число **кластеров**. Хвост последнего кластера — это **slack space**: там остаётся место, не занятое данными файла. Туда можно записать скрытое, и файловая система этого «не увидит».

```
$ blkls -s disk.dd > slack.bin
$ strings -a slack.bin | grep -iE 'flag|ctf'
flag{in_slack_space}
```

`blkls -s` выгружает только slack-байты. А через inode можно посмотреть блоки конкретного файла: `istat disk.dd <inode>`, затем `blkcat disk.dd <last_cluster>`.

## Шаг 3: скрытые разделы и неразмеченные области

Данные прячут и вне файловой системы:

- **раздел не в таблице** — существует, но `mmls` его не показывает;
- **данные после конца раздела**;
- **неразмеченное пространство** между разделами.

Ищем по сигнатурам и вырезаем:

```
$ binwalk disk.dd
$ dd if=disk.dd bs=512 skip=<end_sector> of=tail.bin
$ binwalk tail.bin && foremost -i tail.bin -o out
$ testdisk disk.dd          # поиск потерянных разделов
```

## Шаг 4: удалённые файлы и журнал

Удалённые файлы часто остаются в невыделенных кластерах:

```
$ fls -r -d disk.dd                     # список удалённых
$ tsk_recover disk.dd recovered/        # восстановить
$ log2timeline.py timeline.db disk.dd   # таймлайн (журнал NTFS)
```

## Карта носителя

| Область | Что там | Инструмент |
|---|---|---|
| Таблица разделов | разделы, скрытые записи | `mmls`, `fdisk -l` |
| Неразмеченное пространство | данные между разделами | `dd`, `blkls` |
| Slack space | хвост последнего кластера | `blkls -s` |
| NTFS ADS | `file:stream` потоки | `fls`, `icat` |
| Удалённые файлы | данные в невыделенных кластерах | `fls -d`, `tsk_recover` |
| Хвост после ФС | «appended» данные | `binwalk`, `dd` |

## Порядок работы

1. `mmls`/`fsstat` — карта образа.
2. `fls -r | grep ':'` → ADS? → `icat`.
3. `blkls -s` → slack → `strings`.
4. `fls -d`/`tsk_recover` → удалённые.
5. Всё чисто → `binwalk`/`dd` хвост образа.

## Если не сработало

- Не монтируй и не смотри только «видимые» файлы — это главная ошибка.
- Проверь ADS на NTFS — они не видны в `ls`.
- Не пропусти неразмеченные области и скрытый раздел.
- Для slack нужен именно `blkls -s`, а не `fls`.
- Отладка: если `mmls` не видит ФС — `binwalk`/`testdisk`; если файл «есть», но пуст — смотри ADS и slack.

## Что мы теперь знаем

1. Данные на диске прячут в «щелях», а не в файлах.
2. Slack space — неиспользуемый хвост последнего кластера.
3. ADS — дополнительные потоки NTFS (`file:stream`).
4. Есть скрытые разделы, неразмеченные области и удалённые файлы.
5. Sleuth Kit (`mmls`, `fls`, `icat`, `blkls`, `tsk_recover`) — основной набор.

## Шаг 5: полный набор инструментов

| Инструмент | Назначение | Пример |
|---|---|---|
| `mmls` | таблица разделов | `mmls image.dd` |
| `fsstat` | параметры ФС | `fsstat image.dd` |
| `fls` | листинг (в т.ч. `-d` удалённые) | `fls -r image.dd` |
| `icat` | извлечь по inode/потоку | `icat image.dd 42-128-2` |
| `istat` | метаданные inode | `istat image.dd 42` |
| `blkls`/`blkcat` | сырые блоки/slack | `blkls -s image.dd` |
| `tsk_recover` | восстановление файлов | `tsk_recover image.dd out/` |
| `binwalk`/`foremost` | каравер | `binwalk image.dd` |
| `testdisk` | потерянные разделы | `testdisk image.dd` |
| `log2timeline` | таймлайн | `log2timeline.py db image.dd` |

## Шаг 6: разобранные сценарии

**1. Скрытый раздел.** `mmls` показывает два раздела, но `fsstat` по второму — пусто; `binwalk` находит в нём ZIP с флагом.

**2. ADS.** `fls -r image.dd | grep ':'` → `notes.txt:flag`; `icat` извлекает поток → флаг.

**3. Slack.** Видимые файлы чистые; `blkls -s image.dd | strings | grep flag` → флаг в slack.

## Шаг 7: отладка

- Если `mmls` не видит ФС — используй `binwalk`/`testdisk`.
- Если файл «есть», но пуст — смотри ADS и slack.
- Не монтируй образ только для просмотра — так теряются невидимые потоки и неразмеченные области.
- Для NTFS помни: ADS не видны в `ls`/`dir` без специальных флагов (`dir /r`, `Get-Item -Stream *`).

## Шаг 8: slack space по шагам

Slack — «пустой» остаток последнего кластера. Данные там не видны в файловой системе, но физически лежат в образе.

```
$ blkls -s disk.dd > slack.bin
$ strings -a slack.bin | grep -iE 'flag|ctf' | head
$ ls -l slack.bin
```

Через inode можно добраться до конкретного файла: `istat disk.dd <inode>` покажет блоки, а `blkcat disk.dd <last_cluster>` выдаст последний кластер — его хвост и есть slack. Помни: файл занимает `ceil(size/4096)` кластеров, последний заполнен лишь частично.

## Квиз

Проверь себя.

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
    - "`mmls`"
    - "`zsteg`"
    - "`jadx`"
    - "`mutool`"
  answer: 0
  explanation: "mmls из sleuthkit показывает разделы."
- question: "Как извлечь файл по inode из образа?"
  options:
    - "`icat image.dd <inode>`"
    - "`cat image.dd`"
    - "`binwalk image.dd`"
    - "`file image.dd`"
  answer: 0
  explanation: "icat извлекает содержимое по inode."
- question: "Чем восстановить удалённые файлы?"
  options:
    - "`tsk_recover` / `fls -d`"
    - "`strings`"
    - "`exiftool`"
    - "`zsteg`"
  answer: 0
  explanation: "sleuthkit восстанавливает удалённые файлы."
```

## Куда дальше

Дальше — **исполняемые файлы**: overlay, ресурсы и секции, где данные прячут внутри PE/ELF. А пока запомни: образ диска разбирай по карте — разделы, ADS, slack, удалённые, хвост.

## Где пригодится

- **CTF (Forensics/Stego):** образы дисков.
- **IR:** поиск скрытых данных на носителях.
- **Пентест:** физический доступ и forensics.
- **Работа:** цифровая криминалистика.
