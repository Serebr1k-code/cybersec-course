---
id: misc-windows-misc
title: "Windows-артефакты в misc"
category: misc
parent: misc-data-forensics
difficulty: medium
order: 4
tags: [windows, реестр, prefetch, lnk, usn, evtx, форензика]
prerequisites: [misc-encoding, misc-data-forensics]
useful_for:
  - "CTF forensics: образы Windows"
  - "Инциденты: следы выполнения программ"
  - "Анализ активности пользователя"
estimated_minutes: 45
summary: "Windows-артефакты: реестр (hives), Prefetch, Amcache, LNK/Jump Lists, USN Journal, $MFT, Shellbags и EVTX; инструменты (regripper, Zimmerman, Volatility) и разборы."
---

## Что такое Windows-артефакты

Windows оставляет следы практически везде: в реестре, в файлах Prefetch, в журналах, в «недавних документах». Форензика Windows — это умение читать эти артефакты и восстанавливать, что запускалось, кем и когда. В CTF это задачи на образы дисков и памяти Windows.

## Реестр (hives)

Реестр хранится в «улеях» (hives): `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `NTUSER.DAT`.

- **SAM** — локальные учётные записи (хеши NTLM);
- **SYSTEM** — настройки, `Run`-ключи, USB-история;
- **SOFTWARE** — установленное ПО, последние запуски;
- **NTUSER.DAT** — настройки пользователя, RecentDocs, TypedPaths.

```bash
regripper -r NTUSER.DAT -f recentdocs
regripper -r SYSTEM -f usb
```

## Prefetch и Amcache

**Prefetch** (`C:\Windows\Prefetch\*.pf`) показывает, какие программы запускались и когда (до 8 последних запусков). **Amcache** хранит сведения о выполненных бинарниках, включая SHA1.

```bash
# разбор prefetch
pecmd -d prefetch/ -o out.csv
# или через Eric Zimmerman PECmd
```

Отсутствие Prefetch у «системного» файла — подозрительный признак.

## LNK и Jump Lists

Файлы `.lnk` (ярлыки) и Jump Lists хранят пути к недавно открытым файлам, а иногда — MAC-адрес тома и серийник. Это позволяет связать активность с конкретным устройством.

```bash
# разбор LNK через Eric Zimmerman LECmd
LECmd.exe -d lnk/ --csv out.csv
```

## USN Journal и $MFT

**USN Journal** — журнал изменений тома: фиксирует создание/удаление/переименование файлов. **$MFT** — таблица файлов NTFS с метаданными и временами.

```bash
# список записей MFT и таймлайн
fls -r -m / ntfs.img > body.txt
mactime -b body.txt -d > timeline.csv
```

USN помогает увидеть **удалённые** файлы и их имена.

## Shellbags и RecentDocs

**Shellbags** хранят, какие папки открывал пользователь в проводнике (даже если папки удалены). **RecentDocs** — недавние документы. Вместе они восстанавливают «маршрут» пользователя по файловой системе.

## Event Logs (EVTX)

Windows Event Logs (`Security.evtx`, `System.evtx`) содержат входы в систему, запуск служб, подключение устройств. Event ID 4624 (logon), 4688 (process creation) — ключевые для восстановления атаки.

```bash
python3 -m evtx_dump Security.evtx | head
```

## Инструменты

- **regripper** — разбор реестра.
- **Eric Zimmerman tools** (PECmd, LECmd, JLECmd, MFTECmd) — артефакты Windows.
- **Volatility** — дампы памяти.
- **sleuthkit** — ФС и MFT.
- **plaso/log2timeline** — супер-таймлайн.

## Разобранный пример

Дан образ Windows, нужно найти запущенную программу.

```bash
regripper -r NTUSER.DAT -f userassist
pecmd -d Prefetch/ -o prefetch.csv
```

`UserAssist` покажет, что запускал пользователь, а Prefetch — когда. Сопоставив, находим подозрительный бинарник и путь к нему.

## Частые ошибки и подводные камни

- **Путаница ульев.** `SYSTEM` и `SOFTWARE` — разные файлы.
- **Часовые пояса.** Prefetch/USN в UTC.
- **Игнорирование удалённого.** USN и Shellbags помнят удалённые объекты.
- **Вера одному артефакту.** Сопоставляйте несколько источников.
- **Пропуск Amcache.** Там бывают хеши запущенных бинарников.

## Справочная таблица

| Артефакт | Что даёт |
|----------|----------|
| SAM | локальные учётки |
| Prefetch | запуски программ |
| Amcache | хеши бинарников |
| LNK/JumpList | недавние файлы |
| USN | изменения тома |
| Shellbags | открытые папки |
| EVTX | события системы |

## Что дальше / решение

1. Соберите ульи реестра и артефакты (`Prefetch`, `LNK`).
2. Прогоните `regripper` и Zimmerman-инструменты.
3. Постройте таймлайн (`fls`/`mactime` или plaso).
4. Сопоставьте запуски программ с временами.
5. Проверьте USN/Shellbags на удалённые объекты.

## PowerShell, WMI и BITS-артефакты

Windows хранит следы исполнения не только в Prefetch. Полезные источники:

- **PowerShell Operational Log (EVTX)** — полный текст выполненных скриптов (Event ID 4104);
- **WMI** — постоянные подписки (`__EventFilter`, `CommandLineEventConsumer`) как механизм persistence;
- **BITS** — фоновая передача файлов, иногда используется для загрузки полезной нагрузки;
- **SRUM** — статистика использования ресурсов по приложениям (кто сколько сети/диска потратил);
- **Amcache/ShimCache** — следы выполнения, даже если Prefetch отключён.

```bash
# PowerShell-логи
python3 -m evtx_dump Microsoft-Windows-PowerShell%4Operational.evtx | grep -i 'ScriptBlock'
# WMI persistence
regripper -r OBJECTS.DATA -f wmi
```

`ShimCache` (`AppCompatCache` в SYSTEM) особенно ценен: он показывает, какие бинарники **существовали** на диске, даже если были удалены.

## Частые вопросы по Windows-артефактам

- **Программа запускалась, но Prefetch пуст?** Смотрите Amcache и ShimCache.
- **Как найти persistence?** Ключи `Run`/`RunOnce`, службы, задачи планировщика, WMI.
- **Что показывает SRUM?** Использование ресурсов по приложениям и пользователям.
- **Как связать вход и действие?** EVTX (4624/4688) + таймлайн файлов.

## Мини-шпаргалка Windows-артефактов

```bash
regripper -r NTUSER.DAT -f recentdocs   # реестр
pecmd -d Prefetch/ -o prefetch.csv       # запуски
LECmd.exe -d lnk/ --csv lnk.csv          # ярлыки
python3 -m evtx_dump Security.evtx       # события
fls -r -m / ntfs.img > body.txt          # MFT
```

## Итог по Windows

Форензика Windows строится на сопоставлении артефактов: реестр (persistence, учётки), Prefetch/Amcache/ShimCache (запуски), LNK/JumpLists (недавние файлы), USN/MFT (изменения), EVTX (события). Ни один артефакт не даёт полной картины — комбинируйте. Особенно ценен ShimCache: он помнит бинарники, которых уже нет на диске. Сопоставляя времена и источники, вы восстанавливаете последовательность действий атакующего и находите флаг.

## Кейс: разбор NTUSER.DAT

Дано: пользовательский куст реестра. Цель — что открывал пользователь.

```bash
regripper -r NTUSER.DAT -f recentdocs
regripper -r NTUSER.DAT -f userassist
regripper -r NTUSER.DAT -f typedurls
```

`RecentDocs` покажет недавние документы, `UserAssist` — запущенные программы (с счётчиком запусков), `TypedURLs` — набранные адреса. Из этих данных восстанавливают, чем занимался пользователь, и находят путь к интересному файлу.

## Кейс: поиск persistence

Механизмы закрепления в Windows:

- **Run/RunOnce** — автозапуск при входе;
- **Службы** — `HKLM\SYSTEM\...\Services`;
- **Задачи планировщика** — `C:\Windows\System32\Tasks\`;
- **WMI-подписки** — `OBJECTS.DATA`;
- **Startup-папка** — `%APPDATA%\...\Startup`.

```bash
regripper -r SOFTWARE -f run
regripper -r SYSTEM -f services
```

Подозрительная запись обычно указывает на файл в нестандартном месте (`AppData`, `Temp`) — это и есть зацепка.

## Итог по Windows-артефактам

Работайте комбинацией артефактов: реестр (persistence и учётки), Prefetch/Amcache/ShimCache (запуски), LNK/JumpLists (недавние файлы), USN/MFT (изменения), EVTX (события). Ни один источник не полон; сопоставление времён и путей даёт картину. ShimCache особенно ценен — помнит удалённые бинарники. Именно сопоставление, а не один артефакт, приводит к флагу.

## Частые вопросы по Windows (расширенно)

- **Где искать пароли?** SAM (локальные хеши), LSA-секреты (`SECURITY`), браузерные хранилища, файлы конфигураций.
- **Как восстановить удалённый файл?** USN Journal + карвинг; `fls` покажет записи MFT.
- **Что показывает ShimCache?** Бинарники, которые существовали на диске, даже если удалены.
- **Как связать USB с файлом?** Ключи `USBSTOR`/`MountPoints2` в реестре + времена.
- **Где логи входов?** `Security.evtx` (4624/4625), `System.evtx`.

## Практический порядок действий

Для образа Windows рекомендую такой маршрут: сначала соберите артефакты (`Prefetch`, `LNK`, ульи реестра, EVTX), затем постройте таймлайн и только потом углубляйтесь. Начинайте с самых «говорящих» источников — UserAssist и Prefetch покажут запуски, Run-ключи и задачи планировщика — закрепление, USN и MFT — изменения файлов. Сопоставляя время и пути, вы быстро находите подозрительный бинарник и связанный с ним флаг, не разбирая весь образ целиком.

## Квиз

```quiz
- question: "Что показывает Prefetch?"
  options:
    - "Какие программы запускались и когда"
    - "Пароли"
    - "Сетевые соединения"
    - "Открытые порты"
  answer: 0
  explanation: "До 8 последних запусков."
- question: "Где в реестре хранятся NTLM-хеши локальных учёток?"
  options:
    - "SAM"
    - "SOFTWARE"
    - "NTUSER.DAT"
    - "SYSTEM"
  answer: 0
  explanation: "Security Account Manager."
- question: "Что фиксирует USN Journal?"
  options:
    - "Изменения тома (создание/удаление/переименование)"
    - "Запуски программ"
    - "Логины"
    - "USB-устройства"
  answer: 0
  explanation: "Журнал изменений NTFS."
- question: "Какой Event ID соответствует входу в систему?"
  options:
    - "4624"
    - "4688"
    - "1102"
    - "7045"
  answer: 0
  explanation: "4624 — успешный logon."
```

## Где пригодится

- **CTF forensics:** образы и дампы Windows.
- **Инциденты (IR):** следы выполнения и входов.
- **Работа:** аудит активности пользователей.
- **Malware-анализ:** persistence через реестр.
