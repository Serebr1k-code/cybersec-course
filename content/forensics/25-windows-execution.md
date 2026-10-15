---
id: forensics-windows-execution
title: "Артефакты выполнения: Prefetch, Amcache, ShimCache, SRUM"
category: forensics
parent: forensics-win-execution
difficulty: hard
order: 2
tags: [prefetch, amcache, shimcache, srum, appcompatcache, execution]
prerequisites: [forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Malware analysis"
estimated_minutes: 65
summary: "Как доказать, что программа ЗАПУСКАЛАСЬ: Prefetch, Amcache, ShimCache/AppCompatCache, SRUM, BAM/DAM, и как их разбирать инструментами Zimmerman."
lab:
  kind: shell
  title: 'Практика: разбор Prefetch'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, CMD.EXE-8D3F2B1A.pf, amcache.txt, pf_parse.py, notes.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Начни с `file CMD.EXE-8D3F2B1A.pf` — это Prefetch (сигнатура `SCCA`).'
    - 'Prefetch хранит строки в UTF-16LE — обычный `strings` их не покажет.'
    - 'Разбери файл скриптом: `python3 pf_parse.py`.'
    - 'Выдели флаг: `python3 pf_parse.py | grep nto > found.txt`.'
---

## Вопрос, с которого всё начинается

Есть подозрение, что на машине запускали `psexec.exe` — утилиту для удалённого
управления, которую часто используют при перемещении по сети. Но самого файла на диске
уже нет: его удалили. Как доказать, что программа **запускалась**?

Windows оставляет несколько независимых следов запуска, и их корреляция даёт
убедительную картину. В этом уроке мы пройдём по следам по очереди и соберём
доказательство.

## Наш пример: что запускали

Смотрим каталог предзагрузки:

```bash
$ PECmd.exe -d C:\Windows\Prefetch --csv out --csvf pf.csv
$ grep -i psexec out/pf.csv
PSEXESVC.EXE-1A2B3C4D.pf, run_count=1, last_run=2024-03-01 10:00:00
```

`PECmd` — парсер **Prefetch**. Prefetch — это файлы предзагрузки, которые Windows
создаёт при запуске программ, чтобы ускорять их повторный старт. Каждый файл хранит имя
программы, счётчик запусков, время последнего запуска и до 8 путей, которые процесс
читал. Уже здесь видно: `PSEXESVC.EXE` запускался один раз.

## Шаг 1: Prefetch подробнее

```bash
$ PECmd.exe -f 'C:\Windows\Prefetch\CMD.EXE-1A2B3C4D.pf'
Source filename: CMD.EXE-1A2B3C4D.pf
Executable name: CMD.EXE
Run count: 12
Last run: 2024-03-01 12:34:56.789
Files referenced:
  \VOLUME{...}\USERS\BOB\SCRIPT.BAT
```

Поле **Files referenced** показывает, что процесс открывал. Там часто видны пути к
вредоносным скриптам — это подсказка, где искать дальше.

## Шаг 2: Amcache — путь и хеш

```bash
$ AmcacheParser.exe -f Amcache.hve --csv out --csvf ac.csv
$ grep -i psexec out/ac.csv
psexec.exe, C:\Windows\, SHA1=abc...
```

`Amcache.hve` — куст реестра с записями о запущенных и установленных программах. Его
ценность в том, что он хранит **путь и SHA1-хеш** даже удалённого файла. Хеш можно
сразу проверить в VirusTotal — это быстрый путь к атрибуции.

## Шаг 3: ShimCache — присутствие файла

```bash
$ AppCompatCacheParser.exe -f SYSTEM --csv out --csvf shim.csv
```

**ShimCache** (AppCompatCache) — кэш совместимости приложений в реестре. Он доказывает,
что файл **присутствовал** на диске; на Windows 10+ добавляется флаг выполнения. На
старых системах осторожно: это ещё не гарантия запуска.

## Шаг 4: SRUM — сетевой след

```bash
$ SrumECmd.exe -f SRUDB.dat --csv out --csvf srum.csv
$ grep -i psexec out/srum.csv
```

`SRUDB.dat` — база с почасовой статистикой по процессам: трафик, CPU, диск. Здесь видно,
сколько данных процесс передал по сети — для `psexec` это означает удалённые действия.

## Шаг 5: BAM и UserAssist

```bash
$ rip.pl -r SYSTEM -p bam
\Device\HarddiskVolume2\Windows\psexesvc.exe 2024-03-01 10:00:00
$ rip.pl -r NTUSER.DAT -p userassist
UEME_RUNPATH: C:\Tools\mimikatz.exe (3)
```

**BAM** хранит последние выполненные программы с временем, а **UserAssist** — программы,
запущенные через графический интерфейс. UserAssist особенно полезен, когда Prefetch
отключён: он живёт в профиле и не зависит от системных настроек.

## Шаг 6: EVTX — командная строка

```bash
$ evtx_dump -o json Security.evtx | jq -r 'select(.Event.System.EventID==4688)|.Event.EventData.NewProcessName' | grep -i psexec
C:\Windows\psexesvc.exe
```

Событие **4688** фиксирует создание процесса, а Sysmon (событие 1) добавляет командную
строку и родительский процесс. Это последнее звено: мы знаем не только «запускалось»,
но и «с какой командой».

## Сводная таблица артефактов

| Артефакт | Что доказывает | Инструмент |
|----------|---------------|-----------|
| Prefetch | запуск, счётчик, файлы | `PECmd` |
| Amcache | запуск/установку + SHA1 | `AmcacheParser` |
| ShimCache | присутствие (+запуск Win10+) | `AppCompatCacheParser` |
| SRUM | сетевую активность | `SrumECmd` |
| BAM/DAM | запуск | `RegRipper` |
| UserAssist | запуск через GUI | `RegRipper` |

## Пользовательские артефакты

Кроме системных, есть артефакты в профиле пользователя:

- **UserAssist** (`NTUSER.DAT\...\Explorer\UserAssist`) — программы, запущенные через
  графический интерфейс; имена закодированы ROT13, есть счётчик запусков.
- **MUICache** — кэш имён приложений.
- **RecentApps** — недавние приложения (Windows 10+).

```bash
$ rip.pl -r NTUSER.DAT -p userassist
UEME_RUNPATH: C:\Tools\mimikatz.exe (3)
```

UserAssist выручает, когда Prefetch отключён: он живёт в профиле пользователя и не
зависит от системных настроек.

## Приоритеты: какой артефакт когда

| Вопрос | Первичный артефакт | Подтверждение |
|--------|-------------------|---------------|
| Файл запускался? | Prefetch | Amcache, ShimCache, UserAssist |
| Откуда взят? | Amcache, LNK | Prefetch (referenced files) |
| Что делал в сети? | SRUM | EVTX (Sysmon 3/22) |
| С какой командной строкой? | EVTX 4688/Sysmon 1 | — |
| Родительский процесс? | EVTX Sysmon 1 | — |

Собранные вместе, эти артефакты дают восстановленную цепочку: Amcache показывает путь и
хеш, Prefetch подтверждает запуск, SRUM — исходящий трафик, EVTX — командную строку и
родителя. Именно согласованность нескольких независимых источников делает вывод
доказуемым.

## Собираем всё в таймлайн

Правильный подход — свести артефакты в одну ленту и искать согласованность:

```bash
$ PECmd.exe -d Prefetch --csv out --csvf pf.csv
$ AmcacheParser.exe -f Amcache.hve --csv out --csvf ac.csv
$ AppCompatCacheParser.exe -f SYSTEM --csv out --csvf shim.csv
$ SrumECmd.exe -f SRUDB.dat --csv out --csvf srum.csv
# открыть CSV в Timeline Explorer, отфильтровать по имени бинаря
```

Восстановленная цепочка для нашего примера: Amcache даёт путь `C:\Windows\psexec.exe` и
SHA1 → Prefetch подтверждает запуск → SRUM показывает исходящий трафик → EVTX (4688)
даёт командную строку и родителя → LNK подсказывает, откуда файл открыт. Каждый шаг
подкреплён отдельным источником, и вместе они образуют доказательство.

## Частые ошибки

- **Считать, что Prefetch всегда есть** — на серверах его нет.
- **Верить ShimCache как факту запуска** — на старых ОС это лишь присутствие.
- **Игнорировать хеш Amcache** — это быстрый путь к атрибуции через VirusTotal.
- **Забывать про часовые пояса** при сведении артефактов.
- **Смотреть один артефакт** — только корреляция даёт доказуемость.

## Что мы теперь знаем

- Prefetch даёт запуск, счётчик и прочитанные файлы.
- Amcache хранит путь и SHA1 даже удалённого файла.
- ShimCache доказывает присутствие, а на Win10+ и запуск.
- SRUM показывает сетевую активность процесса.
- BAM/UserAssist и EVTX 4688 подтверждают запуск и командную строку.

## На что смотреть дальше

- **Prefetch не всегда есть** — на серверах и при `EnablePrefetcher=0` его нет.
- **ShimCache неточен** на старых ОС — не путайте присутствие с запуском.
- **SRUM циклический** — хранит данные 30–60 дней.
- **Нормализуйте время** — метки могут быть в UTC или локальном времени.
- **Сверяйте несколько источников** — если Prefetch и Amcache дают разное время,
  ищите причину: смену часового пояса или подделку меток.
- **Помните про LNK** — ярлык укажет, откуда файл открыли.

## Разбор формата Prefetch: что внутри

Инструмент прячет детали, но чтобы понимать ограничения артефакта, полезно знать его структуру. Файл `.pf` — это сжатый (в Windows 10+ — алгоритмом MAM/Xpress Huffman) блок с сигнатурой `SCCA` на смещении 4. Внутри:

- **заголовок** — версия формата (по ней определяют ОС: 17 — Windows 7, 23 — 8.1, 26 — 10, 30/31 — 10+), размер, имя исполняемого файла;
- **информация о файле** — счётчик запусков, до 8 последних времён запуска (в новых версиях), хеш;
- **списки строк** — имена файлов и полные пути, которые процесс читал при запуске (та самая секция *Files referenced*);
- **тома** — устройства и время создания тома (полезно при работе с копиями диска).

Достать структуру вручную можно так:

```bash
$ strings -a 'CMD.EXE-1A2B3C4D.pf' | head
SCCA
CMD.EXE
\VOLUME{...}\USERS\BOB\SCRIPT.BAT
```

Но `strings` покажет только незашифрованные строки — для полного разбора нужен `PECmd.exe`, который корректно распаковывает блок и разбирает поля по версии формата. Практический вывод: если `PECmd` пишет «wrong version», ты имеешь дело либо с неполным файлом, либо с артефактом, «подчищенным» нестандартным способом — это уже само по себе находка.

## Справочная таблица: где лежат артефакты выполнения

| Артефакт | Путь | Парсер |
|---|---|---|
| Prefetch | `C:\Windows\Prefetch\*.pf` | `PECmd.exe` |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | `AmcacheParser.exe` |
| ShimCache | SYSTEM: `...\Control\Session Manager\AppCompatCache` | `AppCompatCacheParser.exe` |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | `SrumECmd.exe` |
| BAM | SYSTEM: `...\Services\bam\State\UserSettings\<SID>` | `rip.pl -p bam` |
| UserAssist | NTUSER.DAT: `...\Explorer\UserAssist` | `rip.pl -p userassist` |
| MUICache | USRCLASS.DAT: `...\Shell\MuiCache` | `rip.pl -p muicache` |
| Sysmon | `...\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` | `evtx_dump` |
| Security 4688 | `...\winevt\Logs\Security.evtx` | `evtx_dump` |

Зная точные пути, ты собираешь артефакты быстро и не пропускаешь куст вроде `USRCLASS.DAT`, который многие забывают.

## Ограничения и подводные камни корреляции

Главная ошибка — считать любой из этих артефактов «истиной в последней инстанции». У каждого свои условия.

Prefetch **отключён на серверных ОС** и легко вычищается (например, `PECmd`-совместимым `ccleaner` или простым удалением каталога). На Windows 10+ поле счётчика запусков часто равно 1, а актуальность несёт список из 8 времён — не путай эти поля. Amcache хранит SHA1, но записи со временем вытесняются, поэтому отсутствие `psexec.exe` там не означает, что файла не было. ShimCache на старых ОС показывает только присутствие (без флага выполнения и без времени) — на Windows 10+ флаг появляется, но времени по-прежнему может не быть. SRUM хранит статистику ограниченный период (обычно около месяца), поэтому «нет записей о трафике» часто означает «слишком давно», а не «трафика не было».

Отдельные ловушки — **временные зоны** и **timestomping**. Prefetch хранит время в UTC, а EVTX — в UTC с записью локального смещения; при сведении в таймлайн легко сдвинуть событие на часы. Атакующий может подделать `$STANDARD_INFORMATION`-времена файла, но не все артефакты поддаются подделке одинаково: SRUM и EVTX пишутся ядром и службами, а Prefetch можно просто удалить. Поэтому вывод строится на **согласованности независимых источников**: если Amcache даёт путь и хеш, Prefetch подтверждает запуск, а EVTX 4688 — командную строку, подделать всё сразу непропорционально сложно. Одиночный артефакт — гипотеза, три согласованных — доказательство.

## Квиз

Проверь себя.

```quiz
- question: "Какой артефакт хранит SHA-1 запускавшихся программ?"
  options:
    - "Prefetch"
    - "Amcache"
    - "ShimCache"
    - "SRUM"
  answer: 1
- question: "Что показывает SRUM?"
  options:
    - "пароли"
    - "сетевую/ресурсную активность приложений за 30–60 дней"
    - "USB"
    - "автозапуск"
  answer: 1
- question: "Какая утилита разбирает Prefetch?"
  options:
    - "`PECmd`"
    - "`binwalk`"
    - "`tshark`"
    - "`exiftool`"
  answer: 0
- question: "Чем ShimCache отличается от Prefetch?"
  options:
    - "ничем"
    - "ShimCache в основном доказывает присутствие, а не запуск"
    - "Prefetch — это реестр"
    - "ShimCache не существует"
  answer: 1
- question: "Что подозрительно в Prefetch-каталоге?"
  options:
    - "notepad.exe"
    - "mimikatz.exe / psexec.exe"
    - "explorer.exe"
    - "svchost.exe"
  answer: 1
```

## Куда дальше

Мы доказали запуск программы. Но данные можно было **вынести на флешке** — и это тоже
оставляет следы. В следующем уроке мы восстановим историю подключения USB-устройств и
свяжем с носителем конкретные файлы. А пока запомни: **один артефакт — не
доказательство; запуск подтверждают вместе Prefetch, Amcache и EVTX**.

## Где пригодится

- **CTF:** задачи «что запускал злоумышленник».
- **DFIR:** доказательство выполнения вредоносного ПО.
- **Malware analysis:** сопоставление хешей и путей.
- **Threat Hunting:** поиск аномальных запусков.
- **Криминалистика:** установление фактов запуска в суде.
