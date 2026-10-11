---
id: forensics-timeline
title: "Таймстемпы и построение таймлайна"
category: forensics
parent: forensics-win-logs
difficulty: medium
order: 2
tags: [timeline, timestamps, mactime, plaso, chronology]
prerequisites: [forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ хронологии атаки"
estimated_minutes: 50
summary: "Виды временных меток (MACB), их подделка, построение хронологии событий через mactime, plaso и сведение артефактов Windows в единый супертаймлайн."
---
Таймстемп — временная метка файла. Восстановление хронологии событий (timeline analysis) — сердце форензики: именно упорядочивание артефактов по времени превращает разрозненные находки в доказательную картину «что произошло и в каком порядке». Этот урок — про виды временных меток (MACB), их подделку, построение таймлайна через `mactime`, `plaso` и сведение артефактов Windows в единый супертаймлайн.

## Модель MACB

Классическая модель описывает четыре метки файла:

| Метка | Англ. | Что меняет |
|-------|-------|-----------|
| **M** | Modified | изменение содержимого |
| **A** | Accessed | чтение/открытие |
| **C** | Changed (MFT entry) | изменение метаданных (права, имя, размер) |
| **B** | Born/Created | создание (birth time) |

Разные ФС хранят их по-разному. В NTFS их **четыре набора по восемь меток**: `$STANDARD_INFORMATION` (`$SI`) и `$FILE_NAME` (`$FN`) — по M/A/C/B каждая. Расхождение `$SI` и `$FN` — главный признак timestomping (см. `forensics-timestomp`). В ext4 есть `crtime` (birth), `mtime`, `atime`, `ctime`; в FAT — только дата/время без долей секунды и без часового пояса (локальное время).

## Где лежат временные метки

| Источник | Что даёт |
|----------|----------|
| MFT (`$MFT`) | все метки файлов NTFS, включая удалённые |
| `$UsnJrnl:$J` | журнал изменений: create/rename/delete с временем |
| Prefetch | время последнего запуска (до 8 записей) |
| EVTX | время событий (лог, вход, процесс) |
| Реестр | LastWrite-время ключей |
| LNK/JumpLists | время доступа к целевым файлам |
| Файловая система Linux | `stat`, inode-метки, журнал `jbd2` |

## mactime и bodyfile

Sleuth Kit строит таймлайн из **bodyfile** — текстового представления метаданных. Формат строки:

```
MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
```

Собрать bodyfile можно из `fls`, из MFT или из вывода других инструментов:

```bash
# 1. bodyfile из образа NTFS/ext4
$ fls -r -m "C:/" -o 2048 disk.img > bodyfile.txt
# 2. (опционально) добавить строки из USN/других источников
# 3. построить таймлайн
$ mactime -b bodyfile.txt -d > timeline.csv
$ mactime -b bodyfile.txt 2024-03-01..2024-03-02 > window.txt
$ mactime -b bodyfile.txt -z UTC > timeline_utc.csv   # нормализация TZ
```

Флаги `mactime`: `-b bodyfile`, `-d` CSV с заголовком, `-z` часовой пояс, `-y` год (для файлов без года), диапазон `ДАТА..ДАТА` для окна.

## plaso / log2timeline

`plaso` — движок супертаймлайна, который парсит десятки форматов (EVTX, реестр, MFT, Prefetch, LNK, browser, syslog, pcap-метаданные…) и нормализует их в единую модель. Два шага: сбор (`log2timeline.py`) и вывод (`psort.py`).

```bash
# 1. Собрать все события в хранилище .plaso
$ log2timeline.py --parsers 'winreg,evtx,mft,prefetch,lnk,amcache,usnjrnl' \
    --storage-file timeline.plaso /evidence
# 2. Отфильтровать и вывести
$ psort.py -o l2tcsv -w timeline.csv timeline.plaso \
    "date > '2024-03-01' and date < '2024-03-02'"
$ psort.py -o json_line -w timeline.jsonl timeline.plaso
$ psort.py timeline.plaso -o dynamic -w dynamic.csv     # авто-колонки
# 3. Загрузить в Timesketch для визуального анализа
$ psort.py -o timesketch timeline.plaso
```

Полезные флаги: `--parsers list` (список), `--parsers list:winreg` (какие плагины внутри парсера), `--hashers all` (хеши при парсинге), `-o` формат вывода (`l2tcsv`, `json_line`, `dynamic`, `timesketch`, `opensearch`).

## Timesketch

Timesketch — веб-платформа для совместного анализа таймлайнов. После загрузки вы фильтруете события, строите графики частоты и добавляете аннотации. `psort.py -o timesketch` создаёт ZIP, который импортируется в интерфейс. В облачных расследованиях Timesketch часто связан с `plaso`/`sigma`-правилами для автоматической разметки подозрительных событий.

## Сведение артефактов Windows

Практический конвейер для Windows-хоста:

```bash
# 1. Разобрать каждый источник в CSV (инструменты Zimmerman)
$ MFTECmd.exe -f '$MFT' --csv out --csvf mft.csv
$ EvtxECmd.exe -d C:\Windows\System32\winevt\Logs --csv out --csvf evtx.csv
$ PECmd.exe -d C:\Windows\Prefetch --csv out --csvf pf.csv
$ LECmd.exe -d Recent --csv out --csvf lnk.csv
$ AmcacheParser.exe -f Amcache.hve --csv out --csvf amcache.csv
$ AppCompatCacheParser.exe -f SYSTEM --csv out --csvf shim.csv
$ SrumECmd.exe -f SRUDB.dat --csv out --csvf srum.csv
# 2. Свести в Timeline Explorer (или plaso/psort)
$ psort.py -o l2tcsv -w all.csv merged.plaso
```

В `Timeline Explorer` фильтруйте по `Timestamp`, группируйте по `Source`, сортируйте по времени. Ключ — увидеть последовательность: скачивание → запуск → закрепление → эксфильтрация.

## Часовые пояса и точность

Самая частая ошибка — сравнивать метки в разных TZ. EVTX и NTFS хранят **UTC**, FAT — **локальное** время (плюс только 2-секундная точность mtime). В `plaso` нормализуйте всё в UTC (`--timezone UTC`), в `mactime` используйте `-z UTC`. Доли секунды: NTFS хранит 100-нс тики, ext4 — наносекунды, FAT — нет. При атрибуции «первым делом» учитывайте разницу в точности.

## Разобранный пример

Дан образ с подозрением на закрепление. Строим таймлайн вокруг даты инцидента.

```bash
$ fls -r -m "C:/" -o 2048 disk.img > bf.txt
$ mactime -b bf.txt -z UTC 2024-03-01..2024-03-02 | head
Date,Size,Type,Mode,UID,GID,Meta,File Name
2024-03-01 09:12:03,1024,macb,r/rrwxrwxrwx,0,0,1234-128-2,C:/Users/bob/Downloads/update.exe
2024-03-01 09:12:05,0,a..b,r/rrwxrwxrwx,0,0,1234-128-3,C:/Windows/Temp/run.bat
2024-03-01 09:12:09,0,...b,r/rrwxrwxrwx,0,0,1234-128-4,C:/ProgramData/evil/svc.exe
2024-03-01 09:14:44,0,m...,r/rrwxrwxrwx,0,0,5678-144-1,C:/Windows/System32/Tasks/Updater
```

Читаем цепочку: скачали `update.exe` (m/ac/b), создали `run.bat`, создали `svc.exe` в `ProgramData`, через 2 минуты появилась задача `Updater` (m — изменение каталога Tasks). Это типичная цепочка «dropper → payload → persistence».

## Частые ошибки

- **Игнорировать часовой пояс** — события встанут «не в том порядке».
- **Верить одному источнику** — EVTX может не содержать 4688 без аудита; дополняйте Prefetch/MFT.
- **Забывать про $FN** — только `$SI` покажет подделанные метки.
- **Не учитывать точность FAT** — 2 секунды и локальное время.
- **Путать ctime и birth** — `ctime` меняется при правке метаданных, `crtime`/`$FN` birth — нет.
- **Сортировать строки как текст** — используйте `sort -t, -k1` или парсер.

## Что дальше / решение

Конвейер: собрать источники → нормализовать в UTC → построить bodyfile (`fls -m`) или plaso-хранилище → вывести CSV → отфильтровать окно → визуализировать (Timeline Explorer/Timesketch). Связка: `forensics-windows-artifacts` (что собирать), `forensics-plaso` (глубокий super-timeline), `forensics-timestomp` (аномалии меток), `forensics-attack-mapping` (сопоставить последовательность с ATT&CK).

## Аномалии таймлайна и анти-форензика

Таймлайн — главный инструмент обнаружения сокрытия следов. Ищите: события «из будущего» (метка позже текущего времени), «до создания системы» (раньше даты установки ОС), невозможные последовательности (файл изменён раньше, чем создан), а также пробелы — периоды без событий там, где активность была.

```bash
# события позже «сейчас» — подделка
$ awk -F, '$1 > "2026-01-01" {print}' timeline.csv | head
# файлы, изменённые раньше создания
$ awk -F, '$4 != "" && $1 < $4 {print}' timeline.csv | head
# файл появился, но нет предшествующих событий установки
$ grep -i 'evil.exe' timeline.csv
```

Timestomping (см. `forensics-timestomp`) виден именно в таймлайне: `$SI`-время «отредактировано», а `$FN`-время осталось исходным — при сортировке по времени один и тот же файл «появляется» дважды. USN-журнал хранит реальное время создания и переименования, что обличает подделку.

## Сравнение инструментов таймлайна

| Инструмент | Сильные стороны | Слабые |
|-----------|-----------------|--------|
| `mactime` | простой, быстрый, bodyfile | только ФС-метки |
| `plaso`/`psort` | десятки форматов, фильтры | тяжёлый, требует настройки |
| `Timesketch` | совместная работа, графика | нужен сервер |
| `Timeline Explorer` | GUI, CSV, фильтры | Windows-only |
| `MFTECmd`+`EvtxECmd` | точные поля | по одному источнику |

Для быстрых CTF-задач достаточно `fls -m | mactime`. Для реального IR с десятками артефактов — `plaso` + `Timesketch`. Комбинируйте: сначала `mactime` для «скелета» ФС, затем `plaso` для полного супертаймлайна.

## Практические приёмы фильтрации

```bash
# окно вокруг инцидента
$ psort.py -o l2tcsv -w win.csv timeline.plaso \
    "date > '2024-03-01 09:00:00' and date < '2024-03-01 10:00:00'"
# только записи о конкретном пользователе
$ psort.py timeline.plaso "username == 'bob'" -o l2tcsv -w bob.csv
# только определённые типы событий
$ psort.py timeline.plaso "source == 'MFT' and timestamp_desc contains 'Creation'" -o l2tcsv
```

`psort.py` принимает выражения на языке фильтров plaso (`date`, `username`, `source`, `parser`, `message`), что позволяет сузить миллионы событий до нужного окна.

## Квиз

```quiz
- question: "Что означает «B» в MACB?"
  options:
    - "Backup"
    - "Birth/Created — создание файла"
    - "Binary"
    - "Block"
  answer: 1
- question: "Какая утилита строит таймлайн из bodyfile?"
  options:
    - "mactime"
    - "binwalk"
    - "volatility"
    - "tshark"
  answer: 0
- question: "Какой инструмент создаёт «супертаймлайн»?"
  options:
    - "plaso / log2timeline"
    - "exiftool"
    - "nmap"
    - "unzip"
  answer: 0
- question: "Признак timestomping в MFT?"
  options:
    - "совпадение SI и FN"
    - "расхождение SI и FN таймстемпов"
    - "нулевой размер"
    - "NTFS"
  answer: 1
- question: "В какой зоне обычно хранятся форензик-метки?"
  options:
    - "локальной"
    - "UTC"
    - "MSK"
    - "случайной"
  answer: 1
```

## Где пригодится

- **CTF:** задачи «восстанови хронологию».
- **DFIR:** ключевой метод анализа инцидента.
- **Threat Hunting:** выявление аномалий по времени.
- **Криминалистика:** доказуемая последовательность событий.
- **Анти-форензика:** понимание, как детектится подделка меток.
