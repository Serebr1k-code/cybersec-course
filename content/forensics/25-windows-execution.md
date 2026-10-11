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
estimated_minutes: 50
summary: "Как доказать, что программа ЗАПУСКАЛАСЬ: Prefetch, Amcache, ShimCache/AppCompatCache, SRUM, BAM/DAM, и как их разбирать инструментами Zimmerman."
---
Доказать, что программа **запускалась** (execution artifacts) — одна из ключевых задач DFIR. Windows оставляет несколько независимых следов запуска, и их корреляция даёт убедительную картину. Этот урок — про Prefetch, Amcache, ShimCache/AppCompatCache, SRUM, BAM/DAM и инструменты Eric Zimmerman для разбора каждого.

## Prefetch

`C:\Windows\Prefetch\*.pf` — файлы предзагрузки, ускоряющие запуск. Содержат: имя программы, счётчик запусков, время последнего запуска, до 8 последних использованных файлов/путей, объём данных. Есть только на клиентских/серверных SKU (не на всех) и может быть отключён.

```bash
$ PECmd.exe -f 'C:\Windows\Prefetch\CMD.EXE-XXXX.pf'
$ PECmd.exe -d C:\Windows\Prefetch --csv out --csvf pf.csv
```

Пример вывода:

```
Source filename: CMD.EXE-1A2B3C4D.pf
Executable name: CMD.EXE
Run count: 12
Last run: 2024-03-01 12:34:56.789
Volume information: ... Serial Number: ABCD-1234
Directories referenced (8):
  \VOLUME{...}\WINDOWS\SYSTEM32
  \VOLUME{...}\USERS\BOB
Files referenced:
  \VOLUME{...}\USERS\BOB\SCRIPT.BAT
```

Поле «Files referenced» показывает, что читал процесс — часто там видны пути к вредоносным скриптам.

## Amcache

`Amcache.hve` — куст реестра с записями о запущенных и установленных исполняемых файлах: путь, хеш SHA1, время первой/последней активности, версия. Очень ценно: даёт **хеш** и путь, даже если файл удалён.

```bash
$ AmcacheParser.exe -f Amcache.hve --csv out --csvf amcache.csv
$ grep -i evil out/amcache.csv
```

## ShimCache (AppCompatCache)

ShimCache — кэш совместимости приложений в реестре (`SYSTEM\...\AppCompatCache`). Доказывает **присутствие** файла на диске (и, на новых версиях Windows, факт выполнения). Хранит путь, размер и временную метку.

```bash
$ AppCompatCacheParser.exe -f SYSTEM --csv out --csvf shim.csv
```

Осторожно: ShimCache ≠ гарантированный запуск на старых системах; на Windows 10+ появляется флаг выполнения.

## SRUM

`SRUDB.dat` (`C:\Windows\System32\sru\`) — база ESE с почасовой статистикой по процессам: сетевой трафик, CPU, диск, а также интерфейсы и приложения. Позволяет увидеть, какой процесс и сколько передал по сети.

```bash
$ SrumECmd.exe -f SRUDB.dat --csv out --csvf srum.csv
# фильтр по приложению
$ grep -i evil out/srum.csv
```

## BAM/DAM

`BAM` (Background Activity Moderator) в реестре `SYSTEM\...\Services\bam\State\UserSettings\<SID>` хранит последние выполненные программы с временем. `DAM` — то же для устройств. Появляются в Windows 10+.

```bash
$ rip.pl -r SYSTEM -p bam
```

## Сводная таблица

| Артефакт | Доказывает | Держит | Инструмент |
|----------|-----------|--------|-----------|
| Prefetch | запуск (счётчик, файлы) | до 8 файлов | PECmd |
| Amcache | запуск/установку + SHA1 | путь, хеш | AmcacheParser |
| ShimCache | присутствие (+запуск Win10+) | путь | AppCompatCacheParser |
| SRUM | активность/сеть | почасовую | SrumECmd |
| BAM/DAM | запуск | время | RegRipper |
| UserAssist | запуск в GUI | счётчик | RegRipper |

## Совместное использование

Ни один артефакт не даёт полной картины: Prefetch отключаем, Amcache может отсутствовать, ShimCache неточен. Коррелируйте:

- **PECmd** — запуск и файлы.
- **Amcache** — путь + хеш (можно искать в VirusTotal).
- **ShimCache** — подтверждение присутствия.
- **SRUM** — сетевой след.
- **EVTX 4688/Sysmon 1** — командная строка и родитель.

## Разобранный пример

Подозрение на запуск `psexec.exe` для латерального движения.

```bash
# 1. Prefetch
$ PECmd.exe -d Prefetch --csv out --csvf pf.csv
$ grep -i psexec out/pf.csv
PSEXESVC.EXE-...pf, run_count=1, last_run=2024-03-01 10:00:00
# 2. Amcache — хеш и путь
$ AmcacheParser.exe -f Amcache.hve --csv out --csvf ac.csv
$ grep -i psexec out/ac.csv
psexec.exe, C:\Windows\, SHA1=abc...
# 3. SRUM — трафик от процесса
$ SrumECmd.exe -f SRUDB.dat --csv out --csvf srum.csv
$ grep -i psexec out/srum.csv
# 4. EVTX — командная строка
$ evtx_dump -o json Security.evtx | jq -r 'select(.Event.System.EventID==4688)|.Event.EventData.NewProcessName' | grep -i psexec
C:\Windows\psexesvc.exe
```

Итог: Prefetch (запуск), Amcache (путь+хеш), EVTX (командная строка) — согласовано.

## Частые ошибки

- **Считать, что Prefetch всегда есть** — на серверах и при отключении его нет.
- **Верить ShimCache как факту запуска** — на старых ОС это лишь присутствие.
- **Игнорировать Amcache-хеш** — это быстрый путь к атрибуции через VT.
- **Забывать про часовые пояса** при сведении.
- **Не проверять родительский процесс** — psexec/rundll32/mshta как родитель подозрительны.
- **Смотреть один артефакт** — только корреляция даёт доказуемость.

## Что дальше / решение

Конвейер: `PECmd` → `AmcacheParser` → `AppCompatCacheParser` → `SrumECmd` → `rip.pl -p bam` → EVTX 4688/Sysmon. Связка: `forensics-windows-artifacts` (обзор), `forensics-registry-hives` (кусты), `forensics-evtx-deep` (журналы), `forensics-timeline` (сведение).

## Пользовательские артефакты запуска

Кроме системных, есть артефакты в профиле пользователя:

- **UserAssist** (`NTUSER.DAT\...\Explorer\UserAssist`) — программы, запущенные через GUI; имена ROT13-закодированы, есть счётчик запусков и время последнего.
- **MUICache** — кэш имён приложений.
- **RecentApps** — недавние приложения (Windows 10+).
- **BAM** — последние выполненные программы по SID.

```bash
$ rip.pl -r NTUSER.DAT -p userassist
UEME_RUNPATH: C:\Tools\mimikatz.exe (3)
UEME_RUNPIDL: ... (1)
# BAM из SYSTEM
$ rip.pl -r SYSTEM -p bam
\Device\HarddiskVolume2\Windows\System32\cmd.exe 2024-03-01 10:00:00
```

UserAssist особенно полезен, когда Prefetch отключён: он остаётся в профиле и не зависит от системных настроек.

## Сводный сценарий и таймлайн

Правильный подход — свести все артефакты в один таймлайн и искать согласованность:

```bash
# 1. Парсим каждый источник в CSV
$ PECmd.exe -d Prefetch --csv out --csvf pf.csv
$ AmcacheParser.exe -f Amcache.hve --csv out --csvf ac.csv
$ AppCompatCacheParser.exe -f SYSTEM --csv out --csvf shim.csv
$ SrumECmd.exe -f SRUDB.dat --csv out --csvf srum.csv
# 2. Открываем в Timeline Explorer, фильтруем по интересующему бинарю
# 3. Смотрим: путь (Amcache), запуск (Prefetch), сеть (SRUM), командная строка (EVTX)
```

Пример восстановленной цепочки: Amcache даёт путь `C:\Users\bob\AppData\Local\Temp\a.exe` и SHA1 → Prefetch подтверждает запуск с числом обращений → SRUM показывает исходящий трафик → EVTX (Sysmon 1) даёт командную строку и родителя → LNK показывает, откуда файл открыт.

## Ограничения и подводные камни

- **Prefetch может отсутствовать** (SSD-оптимизация, серверный SKU, отключён в реестре `EnablePrefetcher=0`).
- **ShimCache неточен** — на старых ОС доказывает присутствие, а не запуск.
- **Amcache** не всегда содержит хеши (зависит от версии Windows).
- **SRUM** хранит данные ~30–60 дней (циклическая база).
- **UserAssist** обновляется только для GUI-запусков; запуск из консоли может не отразиться.
- **Временные метки** в артефактах могут быть в UTC или локальном времени — нормализуйте.

## Итоговая таблица приоритетов

| Вопрос | Первичный артефакт | Подтверждение |
|--------|-------------------|---------------|
| Файл запускался? | Prefetch | Amcache, ShimCache, UserAssist |
| Откуда взят? | Amcache, LNK | Prefetch (referenced files) |
| Что делал в сети? | SRUM | EVTX (Sysmon 3/22) |
| С какой командной строкой? | EVTX 4688/Sysmon 1 | — |
| Родительский процесс? | EVTX Sysmon 1 | — |
| Присутствует на диске? | ShimCache | MFT |

## Квиз

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

## Где пригодится

- **CTF:** задачи «что запускал злоумышленник».
- **DFIR:** доказательство выполнения вредоносного ПО.
- **Malware analysis:** сопоставление хешей и путей.
- **Threat Hunting:** поиск аномальных запусков.
- **Криминалистика:** установление фактов запуска в суде.
