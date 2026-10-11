---
id: forensics-prefetch-shimcache
title: "Артефакты выполнения: Prefetch, ShimCache, AmCache"
category: forensics
parent: forensics-win-deep
difficulty: hard
order: 2
tags: [windows, prefetch, shimcache, amcache, pecmd, execution, dfir]
prerequisites: [forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "Incident Response (Windows)"
  - "Threat Hunting"
estimated_minutes: 55
summary: "Глубокий разбор артефактов выполнения Windows: Prefetch (что и сколько раз запускалось), ShimCache/AppCompatCache (следы EXE, включая удалённые), AmCache (пути и хеши) — с инструментами PECmd, AppCompatCacheParser, AmcacheParser."
---

Почти любая задача по Windows-форензике начинается с вопроса: **что здесь запускалось?** Windows оставляет следы выполнения в трёх взаимодополняющих артефактах: Prefetch (счётчик запусков), ShimCache/AppCompatCache (следы существования EXE) и AmCache (пути, хеши, время установки/запуска). Каждый имеет свои пределы, и только вместе они дают уверенную картину.

## Prefetch

Prefetch (`C:\Windows\Prefetch\*.pf`) — файлы, которые Windows создаёт для ускорения запуска программ. Они фиксируют **что запускалось, сколько раз и когда последний раз**, а также список загруженных DLL и файлов. Для Windows 7 и новее — `*.pf` в `Prefetch`; для серверов prefetch может быть **выключен** (ключ реестра `EnablePrefetcher=0`).

Структура `.pf` (версии 17/23/26/30/31 в зависимости от ОС):

| Смещение | Поле |
|---------:|------|
| 0x00 | version (4 байта, напр. `30 00 00 00` → 0x1E) |
| 0x04 | signature `SCCA` |
| 0x0C | file size |
| 0x10 | executable name (UTF-16, до 30 символов) |
| 0x30 | prefetch hash |
| 0x44 | last run time (FILETIME, 8 байт) |
| 0x4C | run count |
| 0x50 | — | device/file references, directory strings |

```bash
# Парсинг всех .pf через PECmd (Eric Zimmerman)
PECmd.exe -d C:\Windows\Prefetch --csv out --csvf prefetch.csv
PECmd.exe -f C:\Windows\Prefetch\CMD.EXE-1234ABCD.pf

# Linux: python-prefetch / prefetch-parser
pip install prefetch-parser
prefetch-parser -f CMD.EXE-1234ABCD.pf -o cmd.json
# или pyscca
python3 -c "import pyscca; f=pyscca.open('CMD.EXE-1234ABCD.pf'); print(f.get_last_run_time(0), f.get_run_count())"
```

Типичный вывод PECmd: `ExecutableName`, `RunCount`, `LastRun`, `VolumeInformation`, `DirectoriesLoaded`, `FilesLoaded`. Имя файла содержит имя EXE и prefetch-хеш, который зависит от пути и параметров запуска.

## ShimCache (AppCompatCache)

ShimCache хранится в реестре:
`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache`.

Он содержит записи о **исполняемых файлах, которые «видел» загрузчик** (не обязательно запускал). Ключевая ценность: ShimCache может сохранить путь и время файла, **даже если файл удалён**. Формат зависит от ОС: на Win7 хранит last-modified время; на Win8+ — также признак «выполнялся ли» (`Executed` флаг) для части записей; на Win10 (1903+) — время изменения.

```bash
# Извлечь hive (SYSTEM) и распарсить
reg.py -r SYSTEM --path 'ControlSet001\Control\Session Manager\AppCompatCache'  # если нужно
AppCompatCacheParser.exe -f SYSTEM --csv out --csvf shimcache.csv

# Linux (python-registry / regipy)
regipy-dump SYSTEM --path 'ControlSet001\Control\Session Manager\AppCompatCache' -o shimcache.json
```

Столбцы: `Path`, `LastModifiedTime`, `Executed` (если доступно), `Source`. Отсутствие `Executed` не значит «не запускался» — ShimCache не для всех версий хранит этот флаг.

## AmCache

AmCache (`C:\Windows\AppCompat\Programs\Amcache.hve` или `RecentFileCache.bcf` на старых системах) — отдельный реестровый hive, который хранит **инвентарь программ**: пути, **SHA-1 хеши** исполняемых файлов, время первого запуска/установки. Хеши позволяют пробивать файлы по VirusTotal.

```bash
AmcacheParser.exe -f Amcache.hve --csv out --csvf amcache.csv
# Linux
regipy-dump Amcache.hve -o amcache.json
```

Столбцы: `Path`, `SHA1`, `FileDescription`, `FirstRunTime`/`InstallDate`, `Publisher`, `Version`. AmCache особенно полезен, когда на диске уже нет самих файлов — хеш остался.

## Сравнение и хронология

| Артефакт | Что доказывает | Хранит время | Хранит хеш | Переживает удаление файла |
|----------|----------------|--------------|------------|---------------------------|
| Prefetch | запуск + число запусков | да (last run) | нет | сам .pf может быть удалён |
| ShimCache | «видел» EXE, иногда запуск | да (last modified) | нет | да |
| AmCache | установка/запуск + инвентарь | да | да (SHA-1) | да |

Сводя всё вместе, можно построить таймлайн: Prefetch даёт точное время запуска, ShimCache — существование подозрительного пути, AmCache — хеш для проверки.

## Разобранный пример

```bash
$ PECmd.exe -d ./Prefetch --csv ./out --csvf pf.csv
Processed 47 .pf files.
$ head -3 ./out/pf.csv
SourceFilename,ExecutableName,Hash,LastRun,RunCount,...
CMD.EXE-1234ABCD.pf,CMD.EXE,1234ABCD,2024-03-01 22:11:03,7,...
POWERSHELL.EXE-5678EFGH.pf,POWERSHELL.EXE,5678EFGH,2024-03-01 22:12:40,3,...
$ grep -i powershell ./out/pf.csv
POWERSHELL.EXE-5678EFGH.pf,POWERSHELL.EXE,5678EFGH,2024-03-01 22:12:40,3,...
```

Вывод: PowerShell запускался 3 раза, последний — сразу после CMD. Это гипотеза об атакующей активности; далее сверяем с ShimCache/AmCache и логами PowerShell.

## Краевые случаи и подводные камни

- **Prefetch выключен на серверах.** `EnablePrefetcher=0` — не делайте вывод «ничего не запускалось».
- **Prefetch не для всех файлов.** Windows не создаёт prefetch для некоторых системных/сетевых запусков; отсутствие ≠ не запускался.
- **Очистка prefetch.** Антифорензика часто чистит `Prefetch`; тогда опирайтесь на ShimCache/AmCache и `$UsnJrnl`.
- **Версии формата.** Структура `.pf` различается по ОС (17/23/26/30/31); используйте актуальный парсер.
- **ShimCache-флаг Executed.** На части версий его нет; отсутствие флага не означает «не запускался».
- **AmCache vs RecentFileCache.** На старых системах инвентарь был в `RecentFileCache.bcf`; не путайте.
- **Hive в пути.** `SYSTEM` может содержать ControlSet001/002; активный — по `Select\Current`.
- **Пути в AmCache могут быть устаревшими.** Файл мог быть перемещён/удалён — хеш всё равно ценен.
- **Часовой пояс.** FILETIME — UTC; приводите к местному времени аккуратно.

## Как читать Prefetch вручную

Если PECmd недоступен, `.pf` можно разобрать вручную — структура документирована. Основные поля:

| Смещение | Размер | Поле |
|---------:|-------:|------|
| 0x00 | 4 | version (17=XP, 23=Vista/7, 26=8/8.1, 30=10, 31=10 1909+) |
| 0x04 | 4 | signature `SCCA` |
| 0x08 | 4 | unknown |
| 0x0C | 4 | file size |
| 0x10 | 60 | executable name (UTF-16LE, до 29 симв.) |
| 0x4C | 4 | prefetch hash |
| 0x50 | 4 | unknown |
| 0x54 | 8 | last run time #1 (FILETIME) |
| 0x5C | 8 | last run time #2 |
| 0x64 | 8 | last run time #3 |
| 0x6C | 8 | last run time #4 |
| 0x74 | 8 | last run time #5 |
| 0x7C | 8 | last run time #6 |
| 0x84 | 8 | last run time #7 |
| 0x8C | 8 | last run time #8 |
| 0x94 | 4 | run count |
| 0x98 | 4 | unknown |

С версии 26 (Win8) перед last-run временами добавлен счётчик и другие поля; версии 30/31 имеют переменную длину секций. Для точного разбора лучше использовать библиотеки (`pyscca`, `prefetch-parser`), но заголовок и run count читаются просто:

```bash
# Имя EXE в UTF-16LE
strings -e l CMD.EXE-1234ABCD.pf | head -3
# Последнее время запуска — 8 байт FILETIME в little-endian
xxd -s 0x54 -l 8 CMD.EXE-1234ABCD.pf
# run count
xxd -s 0x94 -l 4 CMD.EXE-1234ABCD.pf
```

Время хранится как FILETIME (100-нс интервалы с 1601-01-01 UTC); в Python: `datetime(1601,1,1)+timedelta(microseconds=filetime//10)`.

## Что даёт prefetch hash

Prefetch-хеш зависит от **полного пути и имени** запускаемого файла (и для некоторых версий — от аргументов). Поэтому:

- Один и тот же EXE, запущенный из разных каталогов, даёт разные `.pf`.
- Хеш можно пересчитать для проверки гипотезы, откуда запускалась программа (существуют инструменты вроде `WinPrefetchView`).
- Злоумышленник может подделывать/удалять `.pf` — тогда хеш-путь в других артефактах поможет восстановить картину.

## ShimCache на уровне реестра

Значение `AppCompatCache` в hive `SYSTEM` — бинарный blob с переменной структурой по версиям Windows. Разбор вручную неудобен, но важно понимать поля:

- `Path` — путь к исполняемому файлу.
- `LastModifiedTime` — время последнего изменения файла (Win7+).
- `Executed` — флаг, что файл запускался (не во всех версиях и не для всех записей).
- `InsertFlags`/`ShimFlags` — служебные.

На Windows 10 (1607+) структура включает дополнительные поля и «сортировку» записей. Ключевой практический вывод: **ShimCache — это не журнал запусков, а журнал «файлов, которые видел загрузчик»**, поэтому он может содержать EXE, которые никогда не запускались, и НЕ содержать некоторые запущенные.

## AmCache: инвентарь программ

`Amcache.hve` — отдельный hive с несколькими разделами:

- `Root\File\<volume>\<fileid>` — записи о файлах с SHA-1, путём, размером.
- `Root\InventoryApplication*` — установленные приложения (Win10).
- `Root\Programs` — на старых системах.

Ключевая ценность — **SHA-1**, по которому можно однозначно идентифицировать удалённый файл и пробить его в VirusTotal или по локальной базе. AmCache обновляется при запуске/установке, поэтому первое время появления записи — оценка времени первого запуска.

## Комбинированный анализ

Три артефакта дают разную точность:

- Prefetch — точное время запуска и счётчик.
- ShimCache — существование файла (иногда факт запуска).
- AmCache — идентичность (хеш) и путь.

Типовой вопрос «запускал ли злоумышленник `psexec.exe`» решается так: ищем `psexec` в Prefetch (время + счётчик), сверяем с ShimCache (был ли файл), проверяем AmCache (какой именно бинарь по хешу). Если Prefetch очищен — остаются ShimCache/AmCache.

## Типичные ошибки

- **Считать отсутствие prefetch доказательством невиновности.** На серверах prefetch выключен.
- **Путать last-modified в ShimCache с временем запуска.** Это время изменения файла.
- **Игнорировать версию формата.** `.pf` версии 30 отличается от 17.
- **Читать AmCache без учёта control set / volume.** Пути привязаны к томам.
- **Забывать про часовой пояс.** FILETIME — UTC.

## Что дальше / решение

1. Собрать `Prefetch`, `SYSTEM` hive, `Amcache.hve`.
2. Прогнать `PECmd`, `AppCompatCacheParser`, `AmcacheParser` (все с `--csv`).
3. Сопоставить записи по имени/пути/хешу; построить таймлайн запусков.
4. Пробить хеши из AmCache по VirusTotal.
5. Дополнить `$UsnJrnl` (см. `forensics-ntfs-mft`) — он покажет даже удалённые `.pf`.

Дальше — `forensics-jumplists-srum` (активность пользователя) и `forensics-ads` (скрытые потоки).

## Квиз

```quiz
- question: "Какой артефакт Windows хранит счётчик запусков программы?"
  options:
    - "ShimCache"
    - "Prefetch"
    - "AmCache"
    - "$UsnJrnl"
  answer: 1
  explanation: "Prefetch фиксирует run count и время последнего запуска."
- question: "Чем AmCache ценен при удалённом файле?"
  options:
    - "Хранит SHA-1 хеш исполняемого файла"
    - "Хранит содержимое файла"
    - "Расшифровывает диск"
    - "Содержит пароли"
  answer: 0
  explanation: "AmCache хранит пути и SHA-1, что позволяет идентифицировать удалённый файл."
- question: "Что доказывает ShimCache?"
  options:
    - "Что программа точно запускалась"
    - "Что загрузчик «видел» исполняемый файл (иногда с флагом запуска)"
    - "Сетевые соединения"
    - "Содержимое реестра целиком"
  answer: 1
  explanation: "ShimCache/AppCompatCache фиксирует существование EXE, которое видел загрузчик."
- question: "Почему отсутствие .pf не означает «ничего не запускалось»?"
  options:
    - "Prefetch всегда пуст"
    - "Prefetch может быть выключен или очищен антифорензикой"
    - "Prefetch хранится в MFT"
    - ".pf создаётся только для браузеров"
  answer: 1
  explanation: "На серверах prefetch выключен, а злоумышленник может его очистить."
```

## Где пригодится

- **CTF:** задачи «что запускалось» на Windows-образах.
- **IR:** доказательство выполнения малвари и инструментов атакующего.
- **Threat Hunting:** поиск аномальных запусков (LOLBins, powershell).
- **Судебная экспертиза:** реконструкция хронологии по трём артефактам.
