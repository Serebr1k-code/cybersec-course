---
id: forensics-plaso
title: "Super-timeline: plaso/log2timeline и Timesketch"
category: forensics
parent: forensics-timeline
difficulty: hard
order: 1
tags: [plaso, log2timeline, timesketch, timeline, supertimeline, dfir]
prerequisites: [forensics-timeline, forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 55
summary: "Построение super-timeline из разнородных артефактов через plaso: сбор, нормализация, фильтрация по времени и визуализация в Timesketch."
---
Plaso (ранее log2timeline) — движок построения **супер-таймлайна**: он собирает события из десятков источников (EVTX, реестр, MFT, Prefetch, LNK, browser, syslog, файлы, PCAP-метаданные) и нормализует их в единую модель. Это основной инструмент хронологического анализа в DFIR. Этот урок — про `log2timeline.py`, `psort.py`, хранилище, фильтры и визуализацию в Timesketch.

## Архитектура

Plaso работает в два шага:
1. **Сбор** (`log2timeline.py`) — парсит источники и сохраняет события в хранилище (`.plaso`).
2. **Вывод** (`psort.py`) — фильтрует, сортирует и экспортирует в нужный формат.

Событие в plaso — это кортеж: `timestamp`, `timestamp_desc`, `data_type`, `message`, `source`, `parser`, `display_name`, `user`, `hostname`, `inode` и др.

## Сбор: log2timeline

```bash
# собрать все события из каталога
$ log2timeline.py --parsers 'winreg,evtx,mft,prefetch,lnk,amcache' \
    --storage-file timeline.plaso /evidence
# список парсеров
$ log2timeline.py --parsers list
# что внутри парсера winreg
$ log2timeline.py --parsers list:winreg
# хеширование во время сбора
$ log2timeline.py --hashers all --storage-file timeline.plaso /evidence
# фильтр по дате при сборе
$ log2timeline.py --parsers 'evtx' --storage-file t.plaso --yara-rules rule.yar /evidence
```

Полезные флаги: `--parsers` (какие), `--hashers` (sha256/md5), `--filter-file` (фильтр по расширениям), `--file-filter` (включить только нужные), `--workers` (параллелизм), `--vss-stores` (обработка теневых копий), `--yara-rules`.

```bash
# обработка теневых копий
$ log2timeline.py --vss-stores all --storage-file t.plaso disk.img
# ограничить файлы по пути
$ log2timeline.py --file-filter '/Users/*' --storage-file t.plaso /evidence
```

## Вывод: psort

```bash
# вывести в CSV с фильтром по времени
$ psort.py -o l2tcsv -w timeline.csv timeline.plaso "date > '2024-03-01' and date < '2024-03-02'"
# JSON lines
$ psort.py -o json_line -w timeline.jsonl timeline.plaso
# динамические колонки (авто)
$ psort.py -o dynamic -w dynamic.csv timeline.plaso
# в Timesketch
$ psort.py -o timesketch timeline.plaso
# анализ (топ-значения)
$ psort.py -a timeline.plaso
```

Флаги `psort.py`: `-o` (формат: `l2tcsv`, `json_line`, `dynamic`, `timesketch`, `opensearch`, `elastic`), `-w` (файл), `-a` (анализ), `--slice` (диапазон), `--output-time-zone` (TZ), `-q` (тихий).

## Язык фильтров

Plaso принимает выражения:

```
date > '2024-03-01 09:00:00' and date < '2024-03-01 10:00:00'
username == 'bob'
source == 'MFT' and timestamp_desc contains 'Creation'
parser contains 'evtx'
message contains 'mimikatz'
```

```bash
$ psort.py timeline.plaso "username == 'bob' and source == 'WinEvt'" -o l2tcsv -w bob.csv
$ psort.py timeline.plaso "message contains 'powershell'" -o dynamic -w ps.csv
```

## Timesketch

Timesketch — веб-платформа для совместного анализа: импорт плазо-хранилища, фильтры, графики частоты, аннотации, поиск по всем событиям. В облачных расследованиях часто связана с `sigma`.

```bash
$ psort.py -o timesketch timeline.plaso     # создаёт ZIP
# загрузить ZIP в веб-интерфейс Timesketch
```

## Разобранный пример

Дан образ `disk.img`. Нужно построить таймлайн вокруг инцидента.

```bash
# 1. Собрать
$ log2timeline.py --parsers 'winreg,evtx,mft,prefetch,lnk' --storage-file t.plaso disk.img
# 2. Обзор типов событий
$ psort.py -a t.plaso | head -40
# 3. Окно инцидента
$ psort.py -o l2tcsv -w win.csv t.plaso "date > '2024-03-01 12:00:00' and date < '2024-03-01 12:30:00'"
# 4. Найти подозрительное
$ grep -iE 'evil|mimikatz|powershell' win.csv | head
# 5. По пользователю
$ psort.py -o l2tcsv -w bob.csv t.plaso "username == 'bob' and message contains 'cmd'"
```

## Справочная таблица парсеров

| Парсер | Источник |
|--------|----------|
| `winreg` | кусты реестра |
| `evtx` | журналы событий |
| `mft` | $MFT |
| `usnjrnl` | USN-журнал |
| `prefetch` | Prefetch |
| `lnk` | LNK |
| `amcache` | Amcache |
| `sqlite` | SQLite (browser и др.) |
| `syslog` | syslog |
| `filestat` | метаданные файлов |

## Частые ошибки

- **Собирать «всё»** без фильтров — гигантское хранилище; используйте `--parsers`/`--file-filter`.
- **Не нормализовать TZ** — `--output-time-zone UTC`.
- **Забывать про теневые копии** — `--vss-stores all`.
- **Выводить без фильтра** — миллионы строк; используйте `psort`-выражения.
- **Не сохранять команды** — воспроизводимость важна.
- **Путать `log2timeline` и `psort`** — первый собирает, второй выводит.

## Что дальше / решение

Конвейер: `log2timeline.py --parsers ...` (сбор) → `psort.py -a` (обзор) → `psort.py "фильтр"` (окно) → Timesketch (визуализация). Связка: `forensics-timeline` (основы), `forensics-windows-artifacts` (что собирать), `forensics-evtx-deep` (EVTX), `forensics-attack-mapping` (ATT&CK).

## Кастомные парсеры и расширения

Plaso расширяется парсерами на Python: класс наследует `FileSystemParser`/`WindowsRegistryParser` и регистрируется. Это нужно для нестандартных артефактов.

```python
from plaso.parsers import interface, manager
from plaso.lib import definitions

class MyParser(interface.FileObjectParser):
    NAME = 'myparser'
    DATA_FORMAT = 'My custom artifact'
    def ParseFileObject(self, parser_mediator, file_object):
        # читать file_object, создавать EventObject
        ...
```

Также plaso поддерживает **плагины анализа** (`--analysis_plugins`), которые постобрабатывают события (например, `tagging`, `browser_search`, `windows_eventlog`). Они позволяют автоматически помечать интересные события.

```bash
$ psort.py --analysis_plugins tagging -w tagged.csv timeline.plaso
$ log2timeline.py --parsers 'filestat' --file-filter '/etc/*' --storage-file etc.plaso /
```

## Производительность и масштаб

Plaso на больших образах может работать часами и потреблять много памяти.

```bash
# параллелизм
$ log2timeline.py --workers 4 --storage-file t.plaso /evidence
# ограничить объём: только нужные каталоги
$ log2timeline.py --file-filter '/Users/*,/Windows/System32/config/*' --storage-file t.plaso disk.img
# исключить шум
$ log2timeline.py --filter-file '*.log' --storage-file t.plaso /evidence
# оценка размера
$ psort.py -a t.plaso
```

Советы: собирайте сначала **узкий** набор парсеров (evtx, mft, prefetch, winreg), расширяйте по необходимости; используйте `--file-filter` для ограничения файлов; храните `.plaso` на быстром диске; для огромных наборов применяйте Timesketch/OpenSearch.

## Разобранный пример с анализом

```bash
# 1. Сбор
$ log2timeline.py --parsers 'winreg,evtx,mft,prefetch,lnk,amcache,sqlite' --storage-file case.plaso /evidence
# 2. Топ источников и типов событий
$ psort.py -a case.plaso | sed -n '1,40p'
# 3. Авто-тегирование интересного
$ psort.py --analysis_plugins tagging -o l2tcsv -w tagged.csv case.plaso
# 4. Окно инцидента
$ psort.py -o l2tcsv -w win.csv case.plaso "date > '2024-03-01 12:00:00' and date < '2024-03-01 12:30:00'"
# 5. В Timesketch
$ psort.py -o timesketch case.plaso
```

## Ограничения и подводные камни

- **Неподдерживаемый артефакт** — плазо его пропустит; проверяйте `--parsers list`.
- **Неверная TZ** — все события сместятся; задавайте `--output-time-zone`.
- **Слишком широкий сбор** — гигабайты `.plaso`; используйте фильтры.
- **Версии парсеров** — обновляйте plaso; старые версии могут не разбирать новые форматы.
- **Дубликаты событий** — один артефакт может дать несколько записей (нормально).

## Краткое резюме

Plaso — движок супер-таймлайна: `log2timeline.py` собирает события из десятков источников в хранилище `.plaso`, `psort.py` фильтрует и выводит их в CSV/JSON/Timesketch. Это стандартный инструмент хронологического анализа: он нормализует артефакты в единую модель и позволяет сузить миллионы событий до окна инцидента языком фильтров. Для эффективности собирайте узкий набор парсеров, нормализуйте часовой пояс и визуализируйте результат в Timesketch.

## Квиз

```quiz
- question: "Какой файл создаёт log2timeline.py?"
  options:
    - "CSV"
    - "хранилище .plaso (ZIP + SQLite)"
    - "JSON"
    - "XML"
  answer: 1
- question: "Какая утилита фильтрует и экспортирует super-timeline?"
  options:
    - "pinfo.py"
    - "psort.py"
    - "log2timeline.py"
    - "exiftool"
  answer: 1
- question: "Что описывает поле timestamp_desc?"
  options:
    - "имя пользователя"
    - "какое именно время события (creation/modified/accessed/...)"
    - "тип файловой системы"
    - "хэш файла"
  answer: 1
- question: "Зачем нужен Timesketch?"
  options:
    - "собирать образы дисков"
    - "визуализация и совместный анализ таймлайнов"
    - "расшифровывать TLS"
    - "парсить EVTX"
  answer: 1
- question: "Почему сырой super-timeline нужно фильтровать?"
  options:
    - "он зашифрован"
    - "миллионы событий делают анализ без фильтра бессмысленным"
    - "он не содержит времени"
    - "он всегда пуст"
  answer: 1
```

## Где пригодится

- **CTF:** задачи на восстановление хронологии сложной атаки.
- **DFIR:** построение единой картины инцидента из разнородных артефактов.
- **Threat Hunting:** поиск аномалий во времени и связей событий.
- **Командная работа:** Timesketch для совместного расследования.
- **Отчётность:** готовые таймлайны для отчёта и суда.
