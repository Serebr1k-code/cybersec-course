---
id: forensics-windows-artifacts
title: "Артефакты Windows: реестр, EVTX, MFT, Prefetch"
category: forensics
parent: forensics-memory
difficulty: hard
order: 1
tags: [windows, registry, evtx, mft, prefetch, artifacts, dfir]
prerequisites: [forensics-memory]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 50
summary: "Разбор ключевых артефактов Windows: кусты реестра, журналы событий, MFT/USN, Prefetch, Amcache, ShimCache, LNK и Jump Lists."
---
Windows оставляет после себя множество артефактов — от реестра и журналов событий до MFT, Prefetch и LNK. Для DFIR важно не «искать один артефакт», а сводить их в коррелированную картину: кто, что, когда запускал и к каким файлам обращался. Этот урок — обзорная карта ключевых артефактов Windows и инструментов для их разбора, с разобранным примером восстановления цепочки выполнения.

## Классы артефактов

| Артефакт | Что доказывает | Где лежит | Инструмент |
|----------|----------------|-----------|-----------|
| Registry hives | настройки, автозапуск, история | `C:\Windows\System32\config`, `NTUSER.DAT` | RegRipper, hivex |
| EVTX | события безопасности | `C:\Windows\System32\winevt\Logs` | evtx_dump, EvtxECmd |
| $MFT | файлы и таймстемпы | корень тома NTFS | MFTECmd, analyzeMFT |
| $UsnJrnl | изменения файлов | `$Extend\$UsnJrnl:$J` | MFTECmd, UsnJrnl2Csv |
| Prefetch | запуск программ | `C:\Windows\Prefetch\*.pf` | PECmd |
| Amcache | запуск/установка | `C:\Windows\appcompat\Programs\Amcache.hve` | AmcacheParser |
| ShimCache | запуск (AppCompat) | реестр `...\AppCompatCache` | AppCompatCacheParser |
| LNK/JumpLists | доступ к файлам | `Recent`, `AutomaticDestinations` | LECmd, JLECmd |
| SRUM | сеть/CPU по процессам | `C:\Windows\System32\sru\SRUDB.dat` | SrumECmd |
| Shellbags | просмотр папок | `UsrClass.dat` | SBECmd |

## Реестр

Кусты реестра — это файлы, которые можно анализировать офлайн. Основные: `SAM` (пользователи и хеши), `SYSTEM` (службы, USB, время), `SECURITY` (LSA secrets), `SOFTWARE` (установленный софт), `NTUSER.DAT` (история пользователя).

```bash
$ rip.pl -r NTUSER.DAT -f ntuser | head -40
$ regripper -r SYSTEM -p usb
$ hivexregedit --export SYSTEM '\ControlSet001\Services' > services.txt
```

Автозапуск: `Run`/`RunOnce`, `Services`, `Winlogon`, `AppInit_DLLs`, `Image File Execution Options`.

## Журналы событий (EVTX)

Ключевые Event ID:

| ID | Лог | Смысл |
|----|-----|-------|
| 4624 | Security | успешный вход (LogonType 2/3/10) |
| 4625 | Security | неудачный вход |
| 4648 | Security | явные учётные данные |
| 4672 | Security | особые привилегии |
| 4688 | Security | создание процесса (+командная строка) |
| 4720/4726 | Security | создание/удаление пользователя |
| 7045 | System | установка службы |
| 1/3/11/22 | Sysmon | процесс/сеть/файл/DNS |
| 4103/4104 | PS/Operational | запуск и блок скрипта PowerShell |

```bash
$ evtx_dump -o json Security.evtx | jq -c 'select(.Event.System.EventID==4688) | .Event.EventData'
$ evtx_dump -o json Sysmon.evtx | jq 'select(.Event.System.EventID==1)' | head
$ EvtxECmd.exe -f Sysmon.evtx --csv out --csvf sysmon.csv
```

## MFT и USN

`$MFT` — «сердце» NTFS: каждая запись содержит имя, таймстемпы (`$STANDARD_INFORMATION` и `$FILE_NAME`), размер и флаги. `$UsnJrnl` — журнал изменений: создание, переименование, удаление файлов.

```bash
$ MFTECmd.exe -f '$MFT' --csv out --csvf mft.csv
$ MFTECmd.exe -f '$J' --csv out --csvf usn.csv
$ analyzeMFT.py -f '$MFT' -o mft.csv
```

Расхождение `$SI` и `$FN` — признак timestomping (см. `forensics-timestomp`).

## Prefetch, Amcache, ShimCache

Эти артефакты доказывают **запуск** программ (см. подробно `forensics-windows-execution`):

```bash
$ PECmd.exe -d C:\Windows\Prefetch --csv out --csvf prefetch.csv
$ PECmd.exe -f C:\Windows\Prefetch\CMD.EXE-XXXX.pf
$ AmcacheParser.exe -f Amcache.hve --csv out
$ AppCompatCacheParser.exe -f SYSTEM --csv out
```

Prefetch: счётчик запусков и до 8 последних использованных файлов; существует только на серверных/десктопных SKU и может быть отключён.

## LNK и Jump Lists

Ярлыки (`.lnk`) и списки переходов доказывают доступ к файлам на локальных и съёмных носителях, включая путь, серийный номер тома и MAC-времена целевого файла.

```bash
$ LECmd.exe -d "%APPDATA%\Microsoft\Windows\Recent" --csv out
$ JLECmd.exe -d "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations" --csv out
```

## SRUM

`SRUDB.dat` (ESE-база) содержит почасовую статистику по процессам: сеть, CPU, диск, а также записи о сетевых интерфейсах и приложениях.

```bash
$ SrumECmd.exe -f SRUDB.dat --csv out
```

## Разобранный пример

Подозрение: пользователь запускал `mimikatz.exe`.

```bash
# 1. Prefetch — факт запуска и счётчик
$ PECmd.exe -d Prefetch --csv out --csvf pf.csv
$ grep -i mimikatz out/pf.csv
MIMIKATZ.EXE-1A2B3C4D.pf, run_count=2, last_run=2024-03-01 12:34:56

# 2. Amcache — путь и хеш
$ AmcacheParser.exe -f Amcache.hve --csv out --csvf amcache.csv
$ grep -i mimikatz out/amcache.csv
MIMIKATZ.EXE, C:\Users\bob\Downloads\, SHA1=...

# 3. ShimCache подтверждает присутствие
$ AppCompatCacheParser.exe -f SYSTEM --csv out --csvf shim.csv
$ grep -i mimikatz out/shim.csv

# 4. EVTX: создание процесса (4688/Sysmon 1)
$ evtx_dump -o json Security.evtx | jq -r 'select(.Event.System.EventID==4688) | .Event.EventData.NewProcessName' | grep -i mimikatz
C:\Users\bob\Downloads\mimikatz.exe

# 5. LNK — откуда открыт
$ LECmd.exe -d Recent --csv out --csvf lnk.csv
$ grep -i mimikatz out/lnk.csv
```

Итог: Prefetch (запуск), Amcache (путь+хеш), ShimCache (присутствие), EVTX (командная строка и родитель), LNK (доступ к файлу) — вместе дают доказуемую картину.

## Частые ошибки

- **Полагаться на один артефакт.** Prefetch может быть отключён; коррелируйте.
- **Смотреть только EVTX.** Много событий не пишется по умолчанию (4688 без командной строки, если не включён аудит).
- **Забывать про Sysmon.** Без него мало сетевых/файловых событий.
- **Игнорировать таймзону.** EVTX хранит UTC; артефакты ФС могут быть в локальном времени.
- **Не проверять расхождения таймстемпов** — маркер timestomping.
- **Анализировать живую систему** вместо копии кустов.

## Что дальше / решение

Разбирайте по слоям: реестр (`forensics-registry-hives`), выполнение (`forensics-windows-execution`), журналы (`forensics-evtx-deep`), файловая система (`forensics-ntfs-mft`, `forensics-usn`), таймлайн (`forensics-timeline`). Конвейер: собрать кусты и артефакты → прогнать через инструменты Zimmerman → свести в супертаймлайн (`forensics-plaso`) → сопоставить с ATT&CK (`forensics-attack-mapping`).

## Корреляция и построение таймлайна

Отдельные артефакты мало что доказывают — сила в корреляции. Соберите выводы инструментов в единый CSV/JSON и сведите по времени. `Timeline Explorer` (Zimmerman) читает CSV и умеет фильтровать по колонке времени; `log2timeline.py` + `psort.py` (plaso) строят супертаймлайн из разнородных источников.

```bash
$ log2timeline.py --parsers 'winreg,evtx,mft,prefetch,lnk,amcache' timeline.plaso /evidence
$ psort.py -o l2tcsv -w timeline.csv timeline.plaso "date > '2024-03-01' and date < '2024-03-02'"
$ psort.py -o timesketch timeline.plaso      # загрузка в Timesketch
```

Критично нормализовать таймзону: EVTX хранит UTC, артефакты NTFS — UTC, но FAT — локальное время. Без нормализации вы получите «событие до причины». Для каждого события фиксируйте источник (какой артефакт), чтобы отчёт был воспроизводим.

## Сбор артефактов с живой системы

Иногда образ снять нельзя (шифрование, сервер в продакшене) — тогда собирают «живые» артефакты, соблюдая **порядок волатильности**: сначала самое быстротеряемое (память, сетевые соединения, процессы), затем дисковые артефакты.

```bash
# память
$ winpmem_mini_x64.exe mem.raw
# артефакты одним пакетом
$ KAPE.exe --tsource C: --tdest out --tflush --mdest mout --mflush \
    --target !SANS_Triage --module !EZParser
# сырой сбор выборочных файлов
$ robocopy C:\Windows\System32\config out\config /COPY:DAT
$ robocopy C:\Windows\System32\winevt\Logs out\evtx /COPY:DAT
```

`KAPE` (Kroll) с таргетами (`!SANS_Triage`, `!BasicCollection`) и модулями (EZParser = MFTECmd/PECmd/EvtxECmd/… ) за один проход собирает и парсит артефакты. `Velociraptor` подходит для сбора с парка машин через VQL-запросы. Всегда фиксируйте хеши собранного и помните: сбор меняет систему (создаёт файлы), поэтому задокументируйте каждое действие.

## Квиз

```quiz
- question: "Какой Event ID означает очистку журнала?"
  options:
    - "4624"
    - "1102"
    - "4688"
    - "7045"
  answer: 1
- question: "Что хранит Prefetch?"
  options:
    - "пароли"
    - "следы запуска программ с временем"
    - "сеть"
    - "закладки"
  answer: 1
- question: "Где в реестре ключ автозапуска пользователя?"
  options:
    - "`HKLM\...\Run`"
    - "`NTUSER.DAT\...\CurrentVersion\Run`"
    - "`SAM`"
    - "`SECURITY`"
  answer: 1
- question: "Что такое $UsnJrnl?"
  options:
    - "журнал изменений файлов NTFS"
    - "журнал событий"
    - "реестр"
    - "prefetch"
  answer: 0
- question: "Какая утилита разбирает EVTX в CSV?"
  options:
    - "`EvtxECmd`"
    - "`binwalk`"
    - "`foremost`"
    - "`exiftool`"
  answer: 0
```

## Где пригодится

- **CTF:** задачи с реестром/EVTX/MFT.
- **DFIR:** восстановление хронологии вторжения.
- **Threat Hunting:** поиск следов инструментов атакующего.
- **Криминалистика:** доказательство фактов запуска/доступа.
- **SOC:** триаж инцидентов на Windows-хостах.
