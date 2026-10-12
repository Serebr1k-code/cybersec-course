---
id: forensics-wmi
title: "Артефакты WMI repository"
category: forensics
parent: forensics-win-execution
difficulty: expert
order: 4
tags: [wmi, repository, objects.data, persistence, fileless, windows, dfir]
prerequisites: [forensics-windows-artifacts, forensics-evtx-deep]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 55
summary: "Разбор WMI repository (OBJECTS.DATA, INDEX.BTR, MAPPING): восстановление WMI-подписок и постоянных потребителей — популярной fileless-персистентности."
---

## Вопрос, с которого всё начинается

У тебя есть образ Windows-машины. Проверил `Run`-ключи, службы, задачи — чисто. Но
пользователь говорит, что «машина иногда что-то запускает сама». Следов в обычной
автозагрузке нет.

`WMI` (**Windows Management Instrumentation**) — это встроенный механизм управления
Windows: через него программы и админы запрашивают состояние системы и подписываются
на события. У WMI есть одна особенность, которая делает его любимым инструментом
атакующих: он умеет запускать код **по событию**, храня это правило не в файле, а в
своей внутренней базе. Такой приём — тоже *fileless* (бесфайловый): в автозагрузке
его не видно. Разберём, где эта база лежит и как её прочитать.

## Наш пример: подозрительный образ

Нам выдали папку `wbem\Repository` из `C:\Windows\System32\wbem\`. В ней три файла:

| Файл | Что содержит |
|------|--------------|
| `OBJECTS.DATA` | сами объекты (классы, экземпляры, в т.ч. подписки) |
| `INDEX.BTR` | индексы |
| `MAPPING1.MAP` | карта страниц |

Посмотрим на размер `OBJECTS.DATA`:

```bash
$ ls -la OBJECTS.DATA
-rw-r--r-- 1 root root 71303168 ... OBJECTS.DATA
```

68 МБ — открывать в текстовом редакторе бессмысленно. Но WMI хранит данные как
B-tree (сбалансированное дерево) из страниц, похоже на формат ESE (база данных
Windows), и **все текстовые строки внутри — в кодировке UTF-16LE** (2 байта на
символ). Значит, нужен поиск по UTF-16LE.

## Шаг 1: как устроена WMI-персистентность

Постоянная подписка WMI собирается из трёх объектов:

1. **`__EventFilter`** — условие срабатывания, написанное на языке запросов `WQL`
   (WMI Query Language, похож на SQL). Пример: «каждые 60 секунд».
2. **Consumer** («потребитель») — что выполнить. Два главных типа:
   `CommandLineEventConsumer` (запускает команду) и `ActiveScriptEventConsumer`
   (запускает скрипт VBScript/JScript).
3. **`__FilterToConsumerBinding`** — «привязка», которая связывает фильтр с
   потребителем.

Вот как выглядит создание такой подписки (для понимания, что мы будем искать):

```powershell
$Filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{
  Name='Updater'; EventNamespace='root\cimv2'; QueryLanguage='WQL';
  Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_PerfFormattedData_PerfOS_System"'}
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{
  Name='Updater'; CommandLineTemplate='cmd.exe /c C:\ProgramData\evil.exe'}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{Filter=$Filter; Consumer=$Consumer}
```

Имя `Updater` выбрано не случайно: оно маскируется под легитимный системный
компонент. Именно такие подписки нам и надо найти.

## Шаг 2: ищем подписки на живой системе

Если система работает, подписки видно прямыми запросами (все они живут в
пространстве имён `root\subscription`):

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

Но у нас **образ**, система не запущена. Живой репозиторий ещё и заблокирован, пока
Windows работает, поэтому с боевой машины его копируют отдельно. Мы разбираем копию.

## Шаг 3: ищем в OBJECTS.DATA офлайн

Поиск строк в UTF-16LE — флаг `-el` у `strings` (encode little-endian, 16 бит):

```bash
$ strings -el OBJECTS.DATA | grep -iE 'EventFilter|Consumer|Updater'
Updater
CommandLineEventConsumer
cmd.exe /c C:\ProgramData\evil\run.exe
```

Три строки — три части подписки. Уже отсюда видно команду, которую запускает
потребитель. Для структурированного разбора есть парсер `python-cim`:

```bash
$ python3 -m pip install python-cim
$ python3 -c "from cim import CIM; c=CIM('OBJECTS.DATA'); print([o for o in c.objects if 'EventFilter' in str(o)])"
```

Инструменты того же класса: `WMI_Forensics`, `WMI-Persistence-Finder`, `WmiExplorer`.
Они выдают связку «фильтр + потребитель + привязка» человекочитаемо.

## Шаг 4: подтверждаем через журнал WMI-Activity

WMI пишет свою активность в журнал `Microsoft-Windows-WMI-Activity/Operational`.
Нас интересует событие **5861** — регистрация *постоянной* подписки:

```bash
$ evtx_dump -o json 'Microsoft-Windows-WMI-Activity%4Operational.evtx' | jq -r 'select(.Event.System.EventID==5861) | .Event.EventData' | head
```

Другие полезные ID: **5857** (загрузка провайдера), **5860** (запуск временного
потребителя), **5858** (ошибка запроса). Событие 5861 — прямое доказательство, что
подписку создали; в его `EventData` часто виден и потребитель.

Если WMI-Activity выключен, полагаемся на сам репозиторий — данные там остаются
даже после удаления подписки (ячейка помечается свободной, но содержимое цело).

## Шаг 5: собираем всё вместе

```bash
# 1. первичная разведка по строкам
$ strings -el OBJECTS.DATA | grep -iE 'EventFilter|Consumer|Updater'
# 2. структурированное извлечение
$ python3 wmi_persistence.py OBJECTS.DATA
[Filter]   Updater: SELECT * FROM __InstanceModificationEvent WITHIN 60 ...
[Consumer] Updater: cmd.exe /c C:\ProgramData\evil\run.exe
[Binding]  Updater
# 3. подтверждение активности
$ evtx_dump -o json WMI-Activity.evtx | jq -r 'select(.Event.System.EventID==5861) | .Event.EventData' | head
```

Итог: постоянная подписка `Updater` каждые 60 секунд запускает `run.exe`. Файла
автозапуска нет — есть только запись в базе WMI. Это и есть WMI-персистентность.

## Что ещё лежит в репозитории

Репозиторий хранит и другие классы, полезные для картины системы на момент снятия:

```bash
$ strings -el OBJECTS.DATA | grep -iE 'Win32_StartupCommand|Win32_Process' | head
$ strings -el OBJECTS.DATA | grep -iE '\.exe|\.ps1|\.vbs' | head
```

`Win32_Process` — запущенные процессы, `Win32_Service` — службы,
`Win32_StartupCommand` — элементы автозапуска. Экземпляры этих классов в репозитории
позволяют восстановить состояние, даже если другие артефакты стёрты.

## Что мы теперь знаем

- WMI-персистентность = связка `__EventFilter` + Consumer + `__FilterToConsumerBinding`.
- Живёт она в базе `wbem\Repository`, а не в файлах-скриптах — отсюда «невидимость».
- Строки в `OBJECTS.DATA` — UTF-16LE: ищи `strings -el`, а не обычным `strings`.
- Событие EVTX **5861** фиксирует создание постоянной подписки.
- Даже удалённая подписка остаётся в репозитории — читай офлайн-копию.

## На что смотреть дальше

- **Искать только файлы и службы** — WMI-закрепление бесфайловое.
- **Забывать про `root\subscription`** — подписки живут только там.
- **Читать OBJECTS.DATA как текст** — нужен `strings -el` или парсер.
- **Анализировать живой репозиторий** — можно изменить состояние; копируй.
- **Верить «легитимным» именам** (`Updater`, `SystemCheck`) — это маскировка.
- **Игнорировать размер файла** — десятки МБ читай потоком, не открывай целиком.

## Квиз

Проверь себя.

```quiz
- question: "Какой файл хранит объекты репозитория WMI?"
  options:
    - "INDEX.BTR"
    - "OBJECTS.DATA"
    - "MAPPING1.MAP"
    - "SYSTEM"
  answer: 1
- question: "Какая тройка классов образует WMI-персистентность?"
  options:
    - "Win32_Process, Win32_Service, Win32_StartupCommand"
    - "__EventFilter, Consumer, __FilterToConsumerBinding"
    - "SAM, SYSTEM, SECURITY"
    - "Prefetch, Amcache, SRUM"
  answer: 1
- question: "Какой потребитель выполняет VBScript/JScript напрямую?"
  options:
    - "CommandLineEventConsumer"
    - "ActiveScriptEventConsumer"
    - "LogFileEventConsumer"
    - "SMTPEventConsumer"
  answer: 1
- question: "Какое событие WMI-Activity фиксирует создание постоянной подписки?"
  options:
    - "4624"
    - "5861"
    - "1102"
    - "4104"
  answer: 1
- question: "Почему WMI-персистентность сложна для обнаружения?"
  options:
    - "она удаляет все логи"
    - "она не требует файла на диске и хранится в базе репозитория"
    - "она работает только в безопасном режиме"
    - "она шифрует диск"
  answer: 1
```

## Куда дальше

Мы научились находить бесфайловое закрепление через WMI. В следующем уроке спустимся
на уровень пользователя и разберём **браузерную форензику** — историю, cookies и
загрузки, по которым видно, какие сайты посещали и что скачивали. А пока запомни:
**если в системе нет следов автозапуска, но код исполняется — проверь репозиторий
WMI**.

## Где пригодится

- **CTF** — задачи на обнаружение fileless-персистентности.
- **DFIR** — вскрытие WMI-подписок, оставленных атакующим.
- **Threat Hunting** — охота на `CommandLineEventConsumer` с подозрительными шаблонами.
- **SOC** — правила на WMI-Activity 5860/5861 и Sysmon 19/20/21.
- **Судебная экспертиза** — доказательство механизма закрепления.
