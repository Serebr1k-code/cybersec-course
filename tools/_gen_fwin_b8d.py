#!/usr/bin/env python3
"""Generate forensics gB Section B batch D: hub + 4 lessons (config/services/boot)."""
import os, json

C = "content/forensics"
L = "content/labs"

def w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text.rstrip() + "\n")

HUB = '''---
id: forensics-win-config
title: "Модуль: конфигурация, службы и автозапуск Windows"
category: forensics
parent: forensics-win-volatile
difficulty: hard
order: 5
tags: [windows, scheduled-tasks, services, wmi, bcd, persistence, roadmap]
prerequisites: [forensics-win-volatile]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Пентест Windows"
estimated_minutes: 14
summary: "Этап ветки «Артефакты Windows»: механизмы автозапуска и конфигурации — планировщик задач, службы, WMI-подписки и загрузочная конфигурация (BCD/UEFI)."
---

Базовый модуль волатильных артефактов назвал точки автозапуска. Этот — разбирает каждую
углублённо: как именно программа закрепляется в системе и какие следы оставляет. Это ответ
на вопрос «как малварь возвращается после перезагрузки» — и один из самых частых вопросов
форензик-задач.

## Что покрывает этот модуль

- **Планировщик задач** — задания с триггерами и действиями: любимый механизм персистентности.
- **Службы** — создание и изменение служб как способ закрепиться и запуститься от SYSTEM.
- **WMI-подписки** — постоянные подписки на события: скрытый и мощный механизм автозапуска.
- **BCD / UEFI** — загрузочная конфигурация: изменение параметров загрузки и следы загрузчиков.

## Рекомендуемый порядок изучения

1. `win-scheduled-tasks-deep` — самый распространённый механизм персистентности.
2. `win-service-artifacts` — службы и их следы в реестре и журналах.
3. `win-wmi-persistence` — скрытые подписки, которые легко пропустить.
4. `win-boot-config` — загрузка и её конфигурация.

## Что вы будете уметь

- Разбирать XML задач планировщика и находить вредоносные задания.
- Прослеживать создание и изменение служб по реестру и журналам.
- Находить WMI-подписки и понимать, как они запускают код.
- Читать BCD и следы загрузочной конфигурации.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| Задачи планировщика | что запускается по триггеру | `schtasks`, XML, `TaskScheduler` журнал |
| Службы | что стартует как служба | реестр `Services`, 7045 |
| WMI-подписки | что запускается по событию | `wmic`, `WMI repository` |
| BCD/UEFI | как настроена загрузка | `bcdedit`, `BCD` hive |

## Куда дальше

Открывай урок **«Планировщик задач: глубокий разбор»** — начнём с самого частого механизма
автозапуска и научимся читать задания целиком.
'''

LESSONS = {}

LESSONS["win-scheduled-tasks-deep"] = dict(
title="Планировщик задач: глубокий разбор заданий и персистентность",
order=1, diff="hard", mins=55,
tags="[windows, scheduled-tasks, schtasks, persistence, xml, forensics]",
prereq="[forensics-win-volatile, forensics-windows-artifacts]",
summary="Как устроены задания планировщика Windows, где они хранятся, как разобрать XML задания и выявить вредоносную персистентность.",
body=r'''
## Вопрос, с которого всё начинается

После перезагрузки на машине снова стартует подозрительный процесс, хотя в автозапуске
`Run`-ключей нет. Где ещё Windows может «договориться» запустить программу? Один из самых
частых ответов — планировщик задач.

## Наш пример: каталог задач

Задания планировщика хранятся в файловой системе и в реестре:

```
C:\Windows\System32\Tasks\
C:\Windows\Tasks\
```

Посмотрим, что лежит в системном каталоге:

```
$ ls C:\Windows\System32\Tasks\
Microsoft\  GoogleUpdateTaskMachineCore  UpdaterTask
```

Каждое задание — **XML-файл** (в новых версиях) с описанием: когда запускать (триггер) и что
запускать (действие).

## Что такое планировщик задач

**Task Scheduler** — служба Windows, которая запускает программы по расписанию или по
событию. Пользователь и администратор используют её легально (обновления, обслуживание), а
злоумышленник — для **персистентности**: задание переживает перезагрузку, может запускаться
от SYSTEM и маскируется под системное.

Ключевая идея: планировщик — это **штатный механизм**, поэтому вредоносное задание часто
выглядит как обычное. Различать помогает разбор XML: имя, автор, триггер, действие и
привилегии.

## Шаг 1: перечислить задачи

Простейший путь — `schtasks`:

```
$ schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run Author"
TaskName:  \UpdaterTask
Task To Run: C:\Users\Public\upd.exe
Author: CORP\jdoe
```

Уже здесь видно аномалию: задание с действием в пользовательском каталоге `Public` и
автором-пользователем, а не системой.

## Шаг 2: разобрать XML задания

Файл задания даёт больше деталей, чем вывод `schtasks`:

```
$ cat C:\Windows\System32\Tasks\UpdaterTask
<Task ...>
  <RegistrationInfo><Author>CORP\jdoe</Author></RegistrationInfo>
  <Triggers><LogonTrigger>...</LogonTrigger></Triggers>
  <Actions><Exec><Command>C:\Users\Public\upd.exe</Command></Exec></Actions>
  <Principals><Principal><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
</Task>
```

Здесь важны четыре элемента: **автор**, **триггер** (например, вход в систему),
**действие** (что запускается) и **уровень прав** (`HighestAvailable` — повышение).

## Шаг 3: сопоставить с журналами

Журнал `Microsoft-Windows-TaskScheduler/Operational` фиксирует регистрацию и запуск заданий:

```
EventID 106  Task registered: \UpdaterTask
EventID 200  Task started: \UpdaterTask
```

Сопоставив время регистрации с действиями пользователя (вход, скачивание файла), ты
восстанавливаешь цепочку «как появилось задание».

## Индикаторы вредоносной задачи

| Признак | Что означает |
|---------|--------------|
| Действие в `Users\Public`/`Temp` | подозрительное расположение |
| Автор — обычный пользователь | обход ожидаемых админов |
| Триггер «при входе/запуске» | автозапуск после перезагрузки |
| `RunLevel: HighestAvailable` | попытка повышения прав |
| Скрытое задание (`/IT`/hidden) | маскировка |

## Шпаргалка команд

```
# Перечислить задачи
schtasks /query /fo LIST /v

# Разобрать XML конкретного задания
type C:\Windows\System32\Tasks\UpdaterTask

# Журнал планировщика
wevtutil qe Microsoft-Windows-TaskScheduler/Operational /c:50 /f:text
```

## Что мы теперь знаем

- Задания планировщика хранятся в `System32\Tasks` как XML и в реестре.
- Каждое задание описывает триггер, действие и уровень прав.
- Вредоносные задания маскируются под системные; различает разбор XML.
- Журнал TaskScheduler фиксирует регистрацию и запуск.
- Планировщик — частый механизм персистентности.

## Квиз

Проверь себя.

```quiz
- question: "Где Windows хранит задания планировщика в виде XML?"
  options:
    - "C:\\Windows\\System32\\Tasks"
    - "C:\\Windows\\Prefetch"
    - "C:\\Windows\\System32\\config\\SAM"
    - "C:\\Users\\Public"
  answer: 0
  explanation: "Задания лежат в System32\\Tasks (и в реестре), каждое — XML."
- question: "Что означает элемент RunLevel со значением HighestAvailable?"
  options:
    - "Задание пытается запуститься с повышенными правами"
    - "Задание работает только в безопасном режиме"
    - "Задание отключено"
    - "Задание запускается в песочнице"
  answer: 0
  explanation: "HighestAvailable — запрос максимальных доступных прав, признак эскалации."
- question: "Какой журнал фиксирует регистрацию и запуск заданий?"
  options:
    - "Microsoft-Windows-TaskScheduler/Operational"
    - "Microsoft-Windows-SMBServer/Security"
    - "Microsoft-Windows-WinRM/Operational"
    - "System"
  answer: 0
  explanation: "TaskScheduler/Operational логирует регистрацию (106) и запуск (200)."
- question: "Почему действие в каталоге Users\\Public подозрительно?"
  options:
    - "Это общедоступный каталог, удобный для размещения вредоносного файла"
    - "Он зарезервирован только для системы"
    - "Он всегда пуст"
    - "Он шифруется BitLocker"
  answer: 0
  explanation: "Public/Temp — типичные места для малвари из-за доступности на запись."
```

## Куда дальше

Мы разобрали самый частый механизм автозапуска. Дальше возьмём **службы** — ещё один способ
закрепиться и запуститься от SYSTEM. А пока главное запомни: **задание планировщика — это
XML с триггером и действием, и его надо читать целиком**.

## Где пригодится

- **CTF Forensics:** задачи про автозапуск и персистентность.
- **DFIR:** поиск механизмов закрепления.
- **Threat Hunting:** аномальные задания.
- **Работа:** форензика конечных точек.
''')

LESSONS["win-service-artifacts"] = dict(
title="Службы Windows: следы создания и изменения как персистентность",
order=2, diff="hard", mins=50,
tags="[windows, services, persistence, sc, registry, forensics]",
prereq="[forensics-win-scheduled-tasks-deep, forensics-registry-hives]",
summary="Как Windows хранит службы, где искать следы их создания и изменения, и как отличить легитимную службу от вредоносной персистентности.",
body=r'''
## Вопрос, с которого всё начинается

Злоумышленник закрепился в системе через службу — она стартует при загрузке и работает от
SYSTEM. Нужно найти эту службу, понять, когда её создали и что она запускает. Где искать?

## Наш пример: ветка Services в реестре

Службы описываются в реестре:

```
HKLM\SYSTEM\CurrentControlSet\Services\<имя_службы>
```

Посмотрим подозрительную службу:

```
$ reg query "HKLM\SYSTEM\CurrentControlSet\Services\WinUpdater" /v ImagePath
ImagePath    REG_EXPAND_SZ    C:\Users\Public\svc.exe
```

`ImagePath` указывает на исполняемый файл — здесь в пользовательском каталоге, что уже
подозрительно.

## Что такое служба и почему это персистентность

**Служба** — программа, которую диспетчер служб (`services.exe`) запускает в фоне, часто от
имени SYSTEM и при загрузке. Это делает службы идеальным механизмом закрепления: код
запускается автоматически и с высокими правами.

Каждая служба описывается набором значений: `ImagePath` (что запускать), `Start` (когда —
загрузка/вручную), `Type`, `ObjectName` (от чьего имени), `ServiceDll` (для служб-библиотек).
Именно эти поля и проверяет аналитик.

## Шаг 1: перечислить и отфильтровать службы

```
$ sc query type= service state= all | findstr /i SERVICE_NAME
$ reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /v ImagePath | findstr /i "Public Temp Users"
```

Фильтр по подозрительным путям (`Public`, `Temp`, `Users`) сразу выделяет кандидатов.

## Шаг 2: определить время создания

Точного «времени создания службы» в реестре нет, но его можно оценить по:

- метаданным самого исполняемого файла (создание/изменение);
- журналу **System**, событие **7045** (установка службы);
- журналу **Security**, событие **4697** (если включён аудит).

```
$ wevtutil qe System /q:"*[System[(EventID=7045)]]" /c:20 /f:text
Service Name: WinUpdater
Image Path:   C:\Users\Public\svc.exe
```

Событие 7045 даёт имя службы, путь и время установки — ключевое доказательство.

## Индикаторы вредоносной службы

| Признак | Что означает |
|---------|--------------|
| `ImagePath` вне `System32` | подозрительное расположение |
| `Start=0/1/2` у незнакомой службы | автозапуск |
| `ObjectName` = SYSTEM | высокие права |
| `ServiceDll` в нестандартном пути | перехват через svchost |
| Совпадение времени с инцидентом | связь с атакой |

## Шпаргалка команд

```
# Список служб
sc query type= service state= all

# Поля конкретной службы
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<имя>" /s

# Установка служб (журнал)
wevtutil qe System /q:"*[System[(EventID=7045)]]" /f:text
```

## Что мы теперь знаем

- Службы описываются в `HKLM\SYSTEM\CurrentControlSet\Services\<имя>`.
- Ключевые поля: `ImagePath`, `Start`, `Type`, `ObjectName`, `ServiceDll`.
- Службы запускаются от SYSTEM и при загрузке — идеальный механизм персистентности.
- Время установки даёт событие 7045 (System) или 4697 (Security).
- Фильтр по путям `Public/Temp/Users` выделяет подозрительные службы.

## Квиз

Проверь себя.

```quiz
- question: "Какое поле службы указывает исполняемый файл для запуска?"
  options:
    - "ImagePath"
    - "Start"
    - "ObjectName"
    - "Type"
  answer: 0
  explanation: "ImagePath задаёт путь к исполняемому файлу службы."
- question: "Какое событие журнала System фиксирует установку службы?"
  options:
    - "7045"
    - "4624"
    - "4104"
    - "5140"
  answer: 0
  explanation: "EventID 7045 — установка новой службы (Service Control Manager)."
- question: "Почему службы удобны для персистентности?"
  options:
    - "Они запускаются при загрузке и часто от имени SYSTEM"
    - "Они не оставляют следов"
    - "Они работают только в безопасном режиме"
    - "Их нельзя создать пользователем"
  answer: 0
  explanation: "Автозапуск при загрузке и высокие права делают службы идеальным закреплением."
- question: "Что подозрительно в ImagePath со значением C:\\Users\\Public\\svc.exe?"
  options:
    - "Служба запускает файл из общедоступного пользовательского каталога"
    - "Путь слишком короткий"
    - "Файл имеет расширение .exe"
    - "Он указывает на System32"
  answer: 0
  explanation: "Легитимные службы обычно живут в System32, а Public/Temp — типичное место малвари."
```

## Куда дальше

Мы разобрали службы. Дальше возьмём **WMI-подписки** — скрытый механизм автозапуска, который
легко пропустить. А пока главное запомни: **служба — это `ImagePath` плюс `Start`, и её
установку фиксирует событие 7045**.

## Где пригодится

- **CTF Forensics:** задачи про персистентность через службы.
- **DFIR:** поиск механизмов закрепления.
- **Threat Hunting:** подозрительные ImagePath.
- **Работа:** форензика конечных точек.
''')

LESSONS["win-wmi-persistence"] = dict(
title="WMI-подписки: скрытая персистентность через события",
order=3, diff="hard", mins=55,
tags="[windows, wmi, persistence, event-subscription, repository, forensics]",
prereq="[forensics-win-service-artifacts, forensics-windows-artifacts]",
summary="Как работает персистентность через WMI-подписки на события, где они хранятся и как их найти в WMI-репозитории.",
body=r'''
## Вопрос, с которого всё начинается

Все обычные механизмы автозапуска чисты, но код всё равно выполняется по событию. Один из
самых скрытных способов закрепления — **подписка WMI на событие**. Как её найти?

## Наш пример: подписки в WMI-репозитории

WMI-подписки хранятся в репозитории:

```
C:\Windows\System32\wbem\Repository\OBJECTS.DATA
```

Посмотрим подписки через запрос:

```
$ wmic /namespace:\\root\subscription path __EventFilter get Name,Query
Name        Query
FilterA     SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'
```

Фильтр определяет событие, на которое «подписываются».

## Что такое WMI-персистентность

**WMI (Windows Management Instrumentation)** — интерфейс управления Windows. Помимо запросов,
он поддерживает **подписки на события**: можно указать «когда произойдёт событие X, выполни
действие Y». Злоумышленник использует это для закрепления: подписка хранится в репозитории и
активируется системой автоматически.

Схема из трёх частей:

- **__EventFilter** — какое событие отслеживать (например, каждые 60 секунд);
- **__EventConsumer** — что делать (запустить командную строку, выполнить скрипт);
- **__FilterToConsumerBinding** — связь между ними.

Именно **связка** и запускает код; без неё фильтр и консьюмер безвредны.

## Шаг 1: найти подписки

```
$ wmic /namespace:\\root\subscription path __EventConsumer get Name,CommandLineTemplate
$ wmic /namespace:\\root\subscription path __FilterToConsumerBinding
```

Ищи **CommandLineConsumer** (запуск команды) и **ActiveScriptEventConsumer** (запуск скрипта)
— это типовые вредоносные консьюмеры.

## Шаг 2: связать и понять триггер

```
$ wmic /namespace:\\root\subscription path __FilterToConsumerBinding get Filter,Consumer
```

В выводе видно, какой фильтр связан с каким консьюмером. Фильтр с интервалом (`WITHIN 60`) и
консьюмер с командной строкой — готовая персистентность: код выполняется регулярно.

## Индикаторы WMI-персистентности

| Компонент | Подозрительный признак |
|-----------|------------------------|
| __EventFilter | фильтр по таймеру без явной причины |
| CommandLineConsumer | команда с путём в `Temp`/`Public` |
| ActiveScriptEventConsumer | скрипт, загружающий нагрузку |
| FilterToConsumerBinding | связка фильтра с консьюмером |

## Шпаргалка команд

```
# Консьюмеры
wmic /namespace:\\root\subscription path __EventConsumer get *
# Фильтры
wmic /namespace:\\root\subscription path __EventFilter get *
# Связки
wmic /namespace:\\root\subscription path __FilterToConsumerBinding get *

# PowerShell
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
```

## Что мы теперь знаем

- WMI поддерживает подписки на события — механизм автозапуска.
- Подписка состоит из фильтра, консьюмера и связки.
- Вредоносные консьюмеры: `CommandLineConsumer`, `ActiveScriptEventConsumer`.
- Связка `FilterToConsumerBinding` запускает код.
- Подписки хранятся в `wbem\Repository`.

## Квиз

Проверь себя.

```quiz
- question: "Из каких частей состоит WMI-подписка?"
  options:
    - "Фильтр, консьюмер и связка между ними"
    - "Пароль, логин и токен"
    - "Заголовок, тело и подпись"
    - "Диск, раздел и файл"
  answer: 0
  explanation: "__EventFilter, __EventConsumer и __FilterToConsumerBinding."
- question: "Какой консьюмер запускает командную строку?"
  options:
    - "CommandLineEventConsumer"
    - "LogFileEventConsumer"
    - "SMTPEventConsumer"
    - "NTEventLogEventConsumer"
  answer: 0
  explanation: "CommandLineEventConsumer выполняет заданную командную строку."
- question: "Где хранятся WMI-подписки?"
  options:
    - "В C:\\Windows\\System32\\wbem\\Repository"
    - "В C:\\Windows\\Prefetch"
    - "В HKLM\\SAM"
    - "В pagefile.sys"
  answer: 0
  explanation: "Репозиторий WMI — OBJECTS.DATA в каталоге wbem\\Repository."
- question: "Что запускает код в WMI-персистентности?"
  options:
    - "Связка FilterToConsumerBinding"
    - "Только фильтр"
    - "Только консьюмер"
    - "Реестровый ключ Run"
  answer: 0
  explanation: "Без связки фильтр и консьюмер не действуют; именно binding активирует выполнение."
```

## Куда дальше

Мы разобрали скрытую WMI-персистентность. Дальше возьмём **BCD и UEFI** — загрузочную
конфигурацию и её следы. А пока главное запомни: **WMI-подписка — это связка фильтра и
консьюмера, и её надо искать в репозитории**.

## Где пригодится

- **CTF Forensics:** задачи про скрытую персистентность.
- **DFIR:** поиск WMI-закрепления.
- **Threat Hunting:** подозрительные подписки.
- **Работа:** форензика конечных точек.
''')

LESSONS["win-boot-config"] = dict(
title="BCD и UEFI: загрузочная конфигурация и её следы",
order=4, diff="hard", mins=50,
tags="[windows, bcd, uefi, boot, bootkit, forensics]",
prereq="[forensics-win-wmi-persistence, forensics-windows-artifacts]",
summary="Как устроена загрузочная конфигурация Windows (BCD), где она хранится, как её прочитать и какие следы оставляют изменения загрузки и буткиты.",
body=r'''
## Вопрос, с которого всё начинается

Система ведёт себя странно на этапе загрузки, или есть подозрение на загрузочный набор
(буткит). Нужно проверить, не менялась ли конфигурация загрузки. Где Windows хранит её и как
прочитать?

## Наш пример: BCD

Конфигурация загрузки (**BCD**, Boot Configuration Data) хранится как реестровый hive:

```
C:\Boot\BCD          (UEFI-системы)
```

Прочитаем её:

```
$ bcdedit /enum
Windows Boot Loader
-------------------
identifier           {current}
device               partition=C:
path                 \Windows\system32\winload.efi
```

`path` указывает загрузчик, `device` — раздел. Нестандартные значения здесь — сигнал.

## Что такое BCD и UEFI

**UEFI** — современная замена BIOS: прошивка, которая инициализирует систему и передаёт
управление загрузчику. **BCD** — база данных конфигурации загрузки: какие системы грузить,
какой загрузчик использовать, какие параметры передать ядру.

Для форензики BCD важен по двум причинам. Первое — изменения загрузки могут указывать на
**буткит** (вредоносный загрузчик) или на попытку загрузить альтернативную систему. Второе —
параметры отладки/теста (`testsigning`, `nointegritychecks`) ослабляют защиту и иногда
включаются перед атакой.

## Шаг 1: прочитать конфигурацию

```
$ bcdedit /enum all
$ bcdedit /enum {current} /v
```

Обрати внимание на `path` (загрузчик), `device` (раздел), `testsigning`, `nointegritychecks`,
`debug` и `hypervisorlaunchtype`. Нестандартные или включённые «тестовые» параметры —
потенциальный сигнал.

## Шаг 2: проверить целостность загрузчика

```
$ ls -la C:\Windows\System32\winload.efi
$ sigcheck C:\Windows\System32\winload.efi
```

Если загрузчик имеет недействительную подпись или нестандартный размер — это признак
подмены. В UEFI-системах подпись проверяется Secure Boot, но буткиты пытаются её обойти.

## Шаг 3: сопоставить с событиями

Загрузка и её изменения фиксируются в журналах (`System`, события загрузки) и в `Setupapi`.
Сопоставив время изменения BCD с событиями, ты поймёшь, когда менялась конфигурация.

## Индикаторы изменённой загрузки

| Признак | Что означает |
|---------|--------------|
| Нестандартный `path` загрузчика | возможная подмена |
| `testsigning on` | ослаблена проверка подписей |
| `nointegritychecks on` | отключена проверка целостности |
| Дополнительный загрузчик | альтернативная/чужая система |
| Изменённый BCD по времени | связь с инцидентом |

## Шпаргалка команд

```
# Читать BCD
bcdedit /enum all
bcdedit /enum {current} /v

# Проверить загрузчик
sigcheck C:\Windows\System32\winload.efi

# Восстановление (справочно)
bootrec /rebuildbcd
```

## Что мы теперь знаем

- BCD — база конфигурации загрузки, hive `C:\Boot\BCD` (UEFI).
- `bcdedit /enum` показывает загрузчики и параметры.
- Опасные параметры: `testsigning`, `nointegritychecks`, `debug`.
- Подмена загрузчика — признак буткита.
- Изменения BCD сопоставляются с журналами загрузки.

## Квиз

Проверь себя.

```quiz
- question: "Что такое BCD?"
  options:
    - "База конфигурации загрузки Windows"
    - "Тип сетевого протокола"
    - "Формат файла печати"
    - "Журнал событий"
  answer: 0
  explanation: "BCD (Boot Configuration Data) хранит конфигурацию загрузки; hive C:\\Boot\\BCD."
- question: "Какой параметр BCD ослабляет проверку подписей драйверов?"
  options:
    - "testsigning"
    - "device"
    - "path"
    - "identifier"
  answer: 0
  explanation: "testsigning on позволяет загружать драйверы с тестовой подписью."
- question: "На что указывает нестандартный path загрузчика в BCD?"
  options:
    - "Возможную подмену загрузчика (буткит)"
    - "Нормальную работу системы"
    - "Отключённый файрвол"
    - "Пустой каталог"
  answer: 0
  explanation: "Подмена winload указывает на потенциальный bootkit."
- question: "Где хранится BCD в UEFI-системе?"
  options:
    - "C:\\Boot\\BCD"
    - "C:\\Windows\\Prefetch"
    - "C:\\Windows\\System32\\config\\SAM"
    - "C:\\Users\\Public"
  answer: 0
  explanation: "В UEFI-системах BCD лежит в C:\\Boot\\BCD как реестровый hive."
```

## Куда дальше

Модуль конфигурации, служб и автозапуска закрыт. Дальше ветка уходит в **целостность журналов
и восстановление артефактов** (подмена EVTX, восстановление реестра, карантин, обновления).
А пока главное запомни: **BCD — это конфигурация загрузки, и её нестандартные параметры —
сигнал**.

## Где пригодится

- **CTF Forensics:** задачи про загрузку и буткиты.
- **DFIR:** проверка целостности загрузки.
- **Threat Hunting:** изменения конфигурации загрузки.
- **Работа:** форензика конечных точек.
''')

def fm(d):
    return (
        "---\n"
        f'id: {d["id"]}\n'
        f'title: "{d["title"]}"\n'
        "category: forensics\n"
        f'parent: {d["parent"]}\n'
        f'difficulty: {d["diff"]}\n'
        f'order: {d["order"]}\n'
        f'tags: {d["tags"]}\n'
        f'prerequisites: {d["prereq"]}\n'
        "useful_for:\n"
        '  - "CTF Forensics категория"\n'
        '  - "DFIR / Incident Response"\n'
        '  - "Пентест Windows"\n'
        f'estimated_minutes: {d["mins"]}\n'
        f'summary: "{d["summary"]}"\n'
        "lab:\n"
        "  kind: shell\n"
        f'  title: "Практика: {d["labtitle"]}"\n'
        "  toolset: [core, grep, strings, base64]\n"
        "  workdir: /home/student/task\n"
        f'  files: [{d["files"]}]\n'
        "  check: \"grep -q 'nto{' found.txt\"\n"
        "  hints:\n"
        + d["hints"] + "\n"
        "---"
    )

LABS = {
"win-scheduled-tasks-deep": dict(
 labtitle="вредоносное задание планировщика",
 files="task.md, UpdaterTask",
 seedfile="UpdaterTask",
 seedtext=(
  "<Task><RegistrationInfo><Author>CORP\\jdoe</Author></RegistrationInfo>\n"
  "<Triggers><LogonTrigger/></Triggers>\n"
  "<Actions><Exec><Command>C:\\Users\\Public\\upd.exe</Command></Exec></Actions>\n"
  "<Principals><Principal><RunLevel>HighestAvailable</RunLevel></Principal></Principals>\n"
  "<!-- nto{sch3d_t4sk_p3rs1st} --></Task>\n"
 ),
 task=("# Задача: планировщик задач\n\n`UpdaterTask` — XML задания. "
       "Найди действие, уровень прав и метку.\n\n1. `file UpdaterTask`.\n"
       "2. `grep -iE 'Command|RunLevel' UpdaterTask`.\n3. `grep nto UpdaterTask > found.txt`.\n"),
 hints=("    - 'Опознай файл: `file UpdaterTask`.'\n"
        "    - 'Ищи действие: `grep -i command UpdaterTask`.'\n"
        "    - 'Проверь уровень прав: `grep -i runlevel UpdaterTask`.'\n"
        "    - 'Метка: `grep nto UpdaterTask > found.txt`.'"),
 flag="nto{sch3d_t4sk_p3rs1st}",
 solution="grep nto UpdaterTask > found.txt"),
"win-service-artifacts": dict(
 labtitle="подозрительная служба",
 files="task.md, services.reg",
 seedfile="services.reg",
 seedtext=(
  "Windows Registry Editor Version 5.00\n"
  "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinUpdater]\n"
  "\"ImagePath\"=\"C:\\\\Users\\\\Public\\\\svc.exe\"\n"
  "\"Start\"=dword:00000002\n"
  "\"ObjectName\"=\"LocalSystem\"\n"
  "; nto{s3rv1c3_1m4g3p4th_p3rs1st}\n"
 ),
 task=("# Задача: службы\n\n`services.reg` — выгрузка ветки Services. "
       "Найди ImagePath подозрительной службы и метку.\n\n1. `cat services.reg`.\n"
       "2. `grep -i imagepath services.reg`.\n3. `grep nto services.reg > found.txt`.\n"),
 hints=("    - 'Посмотри содержимое: `cat services.reg`.'\n"
        "    - 'Ищи путь запуска: `grep -i imagepath services.reg`.'\n"
        "    - 'Обрати внимание на каталог Public.'\n"
        "    - 'Метка: `grep nto services.reg > found.txt`.'"),
 flag="nto{s3rv1c3_1m4g3p4th_p3rs1st}",
 solution="grep nto services.reg > found.txt"),
"win-wmi-persistence": dict(
 labtitle="WMI-подписка на событие",
 files="task.md, wmi.txt",
 seedfile="wmi.txt",
 seedtext=(
  "namespace: root\\subscription\n"
  "__EventFilter Name=FilterA Query=SELECT * FROM __InstanceModificationEvent WITHIN 60\n"
  "__EventConsumer Name=ConsA CommandLineTemplate=C:\\Users\\Public\\svc.exe\n"
  "__FilterToConsumerBinding Filter=FilterA Consumer=ConsA\n"
  "note: nto{wm1_subscr1pt10n_b1nd}\n"
 ),
 task=("# Задача: WMI-персистентность\n\n`wmi.txt` — выгрузка подписок WMI. "
       "Найди связку фильтра с консьюмером и метку.\n\n1. `cat wmi.txt`.\n"
       "2. `grep -i binding wmi.txt`.\n3. `grep nto wmi.txt > found.txt`.\n"),
 hints=("    - 'Прочитай выгрузку: `cat wmi.txt`.'\n"
        "    - 'Ищи связку: `grep -i binding wmi.txt`.'\n"
        "    - 'Обрати внимание на CommandLineTemplate.'\n"
        "    - 'Метка: `grep nto wmi.txt > found.txt`.'"),
 flag="nto{wm1_subscr1pt10n_b1nd}",
 solution="grep nto wmi.txt > found.txt"),
"win-boot-config": dict(
 labtitle="аномалия в BCD",
 files="task.md, bcd.txt",
 seedfile="bcd.txt",
 seedtext=(
  "Windows Boot Loader\n"
  "identifier  {current}\n"
  "device      partition=C:\n"
  "path        \\Windows\\system32\\winload.efi\n"
  "testsigning Yes\n"
  "note: nto{bcd_t3sts1gn1ng_0n}\n"
 ),
 task=("# Задача: BCD\n\n`bcd.txt` — выгрузка конфигурации загрузки. "
       "Найди опасный параметр и метку.\n\n1. `cat bcd.txt`.\n"
       "2. `grep -iE 'path|testsigning' bcd.txt`.\n3. `grep nto bcd.txt > found.txt`.\n"),
 hints=("    - 'Прочитай выгрузку: `cat bcd.txt`.'\n"
        "    - 'Смотри параметры загрузчика: `grep -i path bcd.txt`.'\n"
        "    - 'Проверь проверку подписей: `grep -i testsigning bcd.txt`.'\n"
        "    - 'Метка: `grep nto bcd.txt > found.txt`.'"),
 flag="nto{bcd_t3sts1gn1ng_0n}",
 solution="grep nto bcd.txt > found.txt"),
}

def main():
    w(f"{C}/forensics-win-config.md", HUB)
    for lid, d in LESSONS.items():
        d["id"] = lid
        d["parent"] = "forensics-win-config"
        d.update(LABS[lid])
        w(f"{C}/{lid}.md", fm(d) + "\n" + d["body"].strip() + "\n")
        bundle = {
            "id": lid,
            "workdir": "/home/student/task",
            "hostname": "lab",
            "expect": {"file": "/home/student/task/found.txt", "contains": LABS[lid]["flag"]},
            "fs": [
                {"path": "/home/student/task", "type": "dir"},
                {"path": "/home/student/task/task.md", "text": LABS[lid]["task"]},
                {"path": f"/home/student/task/{LABS[lid]['seedfile']}", "text": LABS[lid]["seedtext"], "mode": "644"},
            ],
        }
        w(f"{L}/{lid}.json", json.dumps(bundle, ensure_ascii=False, indent=2))
        print("wrote", lid)

if __name__ == "__main__":
    main()
