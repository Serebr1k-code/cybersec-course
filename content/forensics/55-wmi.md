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
WMI (Windows Management Instrumentation) — мощный механизм управления Windows, который атакующие активно используют для **fileless-персистентности**: WMI-подписки (event filter + consumer) выполняют код без файла и часто без явных следов в виде служб. Разбор WMI repository позволяет найти такое закрепление. Этот урок — про структуру репозитория, восстановление подписок и постоянных потребителей.

## Что такое WMI repository

WMI хранит классы и экземпляры в `%SystemRoot%\System32\wbem\Repository\`:

| Файл | Содержимое |
|------|-----------|
| `OBJECTS.DATA` | объекты (классы, экземпляры, в т.ч. подписки) |
| `INDEX.BTR` | индексы |
| `MAPPING*.MAP` | карта страниц |

Репозиторий — это ESE-подобная база (не совсем ESE, но с B-tree). Подписки WMI (permanent subscriptions) хранятся как экземпляры классов `__EventFilter`, `CommandLineEventConsumer`, `ActiveScriptEventConsumer`, `__FilterToConsumerBinding`.

## Механизм персистентности WMI

Атакующий создаёт:
1. **__EventFilter** — условие срабатывания (например, при загрузке или каждые N минут).
2. **Consumer** — что выполнить (`CommandLineEventConsumer` — команда, `ActiveScriptEventConsumer` — VBScript/JScript).
3. **__FilterToConsumerBinding** — связывает фильтр и потребителя.

```powershell
# пример (для понимания артефактов)
$Filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{
  Name='Updater'; EventNamespace='root\cimv2';
  QueryLanguage='WQL'; Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_PerfFormattedData_PerfOS_System"'}
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{
  Name='Updater'; CommandLineTemplate='cmd.exe /c C:\ProgramData\evil.exe'}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{Filter=$Filter; Consumer=$Consumer}
```

Это выполняется при каждом срабатывании — без службы и без файла-скрипта в autoruns (хотя потребитель может запускать файл).

## Обнаружение подписок

На живой системе:

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

На образе/офлайн — по `OBJECTS.DATA`:

```bash
# строковый поиск по репозиторию
$ strings -el OBJECTS.DATA | grep -iE 'evil|cmd|powershell|Updater'
$ strings -el OBJECTS.DATA | grep -i 'CommandLineEventConsumer'
# специализированные парсеры
$ python3 -m pip install python-cim
$ python3 -c "from cim import CIM; c=CIM('OBJECTS.DATA'); print([o for o in c.objects if 'EventFilter' in str(o)])"
```

Инструменты: `WMI-Persistence-Finder`, `python-cim`, `WMI_Forensics` (David Pany), `WmiExplorer`. Также полезен анализ `WMI-Activity` в EVTX (Event ID 5857/5860/5861).

```bash
$ evtx_dump -o json 'Microsoft-Windows-WMI-Activity%4Operational.evtx' | jq 'select(.Event.System.EventID==5861)'
```

## Индикаторы и атрибуты

| Артефакт | Значение |
|----------|----------|
| `__EventFilter` | условие срабатывания (WQL) |
| `CommandLineEventConsumer` | выполняемая команда |
| `ActiveScriptEventConsumer` | скрипт (VBS/JS) |
| `__FilterToConsumerBinding` | связь filter↔consumer |
| EVTX 5857/5860/5861 | активность WMI |

Обращайте внимание на имена, похожие на легитимные (`Updater`, `SystemCheck`), и на потребителей с `cmd.exe`/`powershell`/`mshta`.

## Разобранный пример

Дан образ с подозрением на WMI-закрепление.

```bash
# 1. Поиск в репозитории
$ strings -el OBJECTS.DATA | grep -iE 'EventFilter|Consumer|Updater'
Updater
CommandLineEventConsumer
cmd.exe /c C:\ProgramData\evil\run.exe
# 2. Проверка EVTX WMI-Activity
$ evtx_dump -o json WMI-Activity.evtx | jq -r 'select(.Event.System.EventID==5861) | .Event.EventData' | head
# 3. Найти потребителя и фильтр
$ python3 wmi_persistence.py OBJECTS.DATA
[Filter] Updater: SELECT * FROM __InstanceModificationEvent WITHIN 60 ...
[Consumer] Updater: cmd.exe /c C:\ProgramData\evil\run.exe
[Binding] Updater
```

Итог: постоянная подписка `Updater` каждые 60 секунд запускает `run.exe` — классическая WMI-персистентность.

## Справочная таблица

| Задача | Инструмент/команда |
|--------|--------------------|
| Живая система | `Get-WmiObject -Namespace root\subscription` |
| Офлайн | `python-cim`, `strings -el OBJECTS.DATA` |
| Спец-парсер | `WMI_Forensics`, `WMI-Persistence-Finder` |
| Активность | EVTX 5857/5860/5861 |
| Экспорт | `mofcomp`/`WmiExplorer` |

## Частые ошибки

- **Искать только файлы/службы** — WMI-персистентность fileless.
- **Забывать про `root\subscription`** — там живут подписки.
- **Читать OBJECTS.DATA как текст** — нужен `strings -el` (UTF-16LE) или парсер.
- **Игнорировать EVTX WMI-Activity** — там фиксируется активность.
- **Считать потребителя «безвредным»** — он запускает код.
- **Анализировать живой репозиторий без копии** — можно изменить состояние.

## Что дальше / решение

Конвейер: `Get-WmiObject` (живая) или `strings -el OBJECTS.DATA` (офлайн) → найти `__EventFilter`/`Consumer`/`Binding` → проверить EVTX WMI-Activity → извлечь команду/скрипт. Связка: `forensics-fileless` (fileless), `forensics-windows-artifacts` (обзор), `forensics-evtx-deep` (журналы), `forensics-powershell-logs` (скрипты).

## Связанные классы и активность

Кроме подписок, WMI хранит много полезного: `Win32_Process` (запущенные процессы), `Win32_Service`, `Win32_StartupCommand` (автозапуск), `Win32_NetworkAdapterConfiguration`, `Win32_LoggedOnUser`, `Win32_UserAccount`. Экземпляры этих классов в репозитории позволяют восстановить состояние системы на момент снятия.

```bash
$ strings -el OBJECTS.DATA | grep -iE 'Win32_StartupCommand|Win32_Process' | head
$ strings -el OBJECTS.DATA | grep -iE '\.exe|\.ps1|\.vbs' | head
```

Активность WMI (запросы, выполнение) фиксируется в `Microsoft-Windows-WMI-Activity/Operational`:

| Event ID | Смысл |
|----------|-------|
| 5857 | загрузка провайдера |
| 5858 | ошибка запроса |
| 5859 | регистрация |
| 5860 | запуск временного потребителя |
| 5861 | постоянная подписка (регистрация) |

Событие **5861** — прямой индикатор создания постоянной подписки; в его `EventData` виден consumer.

## Удаление и восстановление подписок

Атакующий может удалить подписку после использования — она останется в `OBJECTS.DATA` как «осиротевшая» запись. Поэтому офлайн-разбор репозитория (а не только живые `Get-WmiObject`) обязателен.

```bash
# поиск всех потребителей, включая удалённые
$ strings -el OBJECTS.DATA | grep -iE 'CommandLineEventConsumer|ActiveScriptEventConsumer'
# восстановить детали через python-cim
$ python3 -c "
from cim import CIM
c=CIM('OBJECTS.DATA')
for o in c.objects:
    s=str(o)
    if 'Consumer' in s or 'EventFilter' in s: print(s[:200])
"
```

Также полезно сравнить репозиторий с эталонным/из теневой копии — появившиеся подписки сразу видны.

## Ограничения

- **WMI repository может быть большим** (`OBJECTS.DATA` — десятки-сотни МБ); используйте `strings`+парсер, не пытайтесь открыть целиком в редакторе.
- **Строки в UTF-16LE** — `strings` без `-el` ничего не найдёт.
- **Живой репозиторий заблокирован** — копируйте файлы (`wbem\Repository`) до разбора.
- **WMI-Activity может быть выключен** — тогда полагайтесь на сам репозиторий.

## Итоговый конвейер и приоритеты

Полный разбор WMI-персистентности: (1) скопировать `Repository` из образа; (2) `strings -el OBJECTS.DATA | grep -iE 'EventFilter|Consumer|Binding'` — первичная разведка; (3) `python-cim`/`WMI_Forensics` — структурированное извлечение подписок; (4) проверить `WMI-Activity` (5860/5861) на активность; (5) сопоставить потребителя с файлами/скриптами, которые он запускает. Приоритет — потребители с `cmd.exe`/`powershell`/`mshta` и фильтры с коротким интервалом (частый запуск). Отдельно проверяйте потребителей, запускающих скрипты из реестра или из временных каталогов: они часто маскируются под системные задачи именами вроде `Updater`, `SystemCheck`, `MicrosoftUpdate`.

## Краткое резюме

WMI-персистентность — одна из самых «невидимых»: подписка не отображается в автозагрузке и не требует файла-службы. Обнаружение строится на разборе `OBJECTS.DATA` (офлайн) и проверке `WMI-Activity` (5860/5861). Ключевая связка — «фильтр + потребитель + привязка»; именно потребитель содержит команду или скрипт, который нужно извлечь и проанализировать. Всегда копируйте репозиторий из образа, а не читайте живой, и сопоставляйте найденные подписки с файлами и процессами в системе.

## Квиз

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
    - "__EventFilter, __EventConsumer, __FilterToConsumerBinding"
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
- question: "Какое событие Sysmon фиксирует создание WMI-подписки?"
  options:
    - "EventID 1"
    - "EventID 19/20/21"
    - "EventID 11"
    - "EventID 22"
  answer: 1
- question: "Почему WMI-персистентность сложна для обнаружения?"
  options:
    - "она удаляет все логи"
    - "она не требует файла на диске (fileless) и хранится в репозитории"
    - "она работает только в безопасном режиме"
    - "она шифрует диск"
  answer: 1
```

## Где пригодится

- **CTF:** задачи на обнаружение fileless-персистентности.
- **DFIR:** вскрытие WMI-подписок, оставленных атакующим.
- **Threat Hunting:** охота на `CommandLineEventConsumer` с подозрительными шаблонами.
- **SOC:** правила на Sysmon 19/20/21 и WMI-Activity.
- **Судебная экспертиза:** доказательство механизма закрепления в системе.
