#!/usr/bin/env python3
"""Generate forensics gB Section B batch B: hub + 4 lessons (deep execution artifacts)."""
import os, json

C = "content/forensics"
L = "content/labs"

def w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text.rstrip() + "\n")

HUB = '''---
id: forensics-win-execution-deep
title: "Модуль: глубокий разбор артефактов выполнения Windows"
category: forensics
parent: forensics-win-deep
difficulty: hard
order: 6
tags: [windows, prefetch, shimcache, amcache, srum, execution, roadmap]
prerequisites: [forensics-win-deep]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 14
summary: "Этап ветки «Артефакты Windows»: углублённый разбор четырёх главных артефактов выполнения — Prefetch, ShimCache/AppCompatCache, AmCache и SRUM — с полями, счётчиками и доказательственной ценностью."
---

Базовый модуль дал обзор артефактов выполнения. Этот — углубляет каждый из четырёх
источников до уровня, когда ты можешь **сам** доказать факт запуска программы, время
первого и последнего запуска, а иногда и то, что программа запускалась с внешнего носителя.
Это ядро почти любой задачи про «что выполнялось на хосте».

## Что покрывает этот модуль

- **Prefetch** — кэш загрузки программ: счётчик запусков, время первого/последнего запуска,
  список файлов и томов, к которым обращался процесс.
- **ShimCache / AppCompatCache** — следы, которые загрузчик оставляет о «виденных» EXE, в том
  числе уже удалённых.
- **AmCache** — реестровый артефакт с путями, хешами и временем установки/запуска программ.
- **SRUM** — база ресурсов: сетевая активность и потребление ресурсов по приложениям.

## Рекомендуемый порядок изучения

1. `win-prefetch-deep` — самый информативный источник по запускам и внешним носителям.
2. `win-appcompat-deep` — что «видел» загрузчик, включая удалённые файлы.
3. `win-amcache-deep` — пути и хеши программ, установка и первое появление.
4. `win-srum-deep` — сетевая активность и объёмы передачи по приложениям.

## Что вы будете уметь

- Читать Prefetch, включая серийные номера томов, и доказывать запуск с внешнего диска.
- Разбирать ShimCache и AmCache и различать «видел» и «запускал».
- Открывать ESE-базу SRUM и строить сетевую активность приложения.
- Сопоставлять четыре источника и отделять факт запуска от факта присутствия файла.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| Prefetch | что запускалось, сколько раз, когда | `PECmd`, `pecmd` |
| ShimCache | какие EXE видел загрузчик | `AppCompatCacheParser` |
| AmCache | пути, хеши, установка | `AmcacheParser` |
| SRUM | сеть и ресурсы по приложениям | `SRUMDump`, `esedbexport` |

## Куда дальше

Открывай урок **«Prefetch: глубокий разбор»** — начнём с артефакта, который прямо доказывает
запуск программы и хранит серийные номера томов.
'''

LESSONS = {}

LESSONS["win-prefetch-deep"] = dict(
title="Prefetch: глубокий разбор, счётчики запусков и серийные номера томов",
order=1, diff="hard", mins=60,
tags="[windows, prefetch, pecmd, execution, volume-serial, usb, forensics]",
prereq="[forensics-win-deep, forensics-windows-artifacts]",
summary="Как устроены файлы Prefetch, как читать счётчики запусков и времена, и как по серийным номерам томов доказать запуск программы с внешнего носителя.",
body=r'''
## Вопрос, с которого всё начинается

Подозревается, что на машине запускали утилиту, которой уже нет на диске. Журналы событий
молчат (аудит запуска процессов не включён). Что докажет сам факт запуска и, что важнее,
**откуда** её запускали — с локального диска или с флешки? Ответ даёт Prefetch.

## Наш пример: каталог Prefetch

```
C:\Windows\Prefetch\
```

```
$ ls
CMD.EXE-4A1B2C3D.pf
NOTEPAD.EXE-9F8E7D6C.pf
PSEXEC.EXE-1A2B3C4D.pf
```

Имя файла — `<ИМЯ_ПРОГРАММЫ>-<хеш>.pf`. Хеш зависит от полного пути к программе, поэтому по
нему можно отличить один и тот же EXE, запущенный из разных каталогов.

## Что такое Prefetch и зачем он нужен

**Prefetch** — это кэш, который Windows ведёт для **ускорения запуска** программ. При первом
запуске ОС запоминает, какие файлы и библиотеки читает процесс, и в следующий раз читает их
заранее. Побочный эффект: чтобы вести кэш, система сохраняет **метаданные** о запуске —
имя, время, счётчик, список томов. Именно эти метаданные и расследуют.

Важно понимать назначение: Prefetch существует ради производительности, а не аудита. Поэтому
он включён не всегда и очищается не всегда — обе крайности влияют на расследование.

## Шаг 1: опознать файл

```
$ file CMD.EXE-4A1B2C3D.pf
CMD.EXE-4A1B2C3D.pf: MS Windows Prefetch file, version 30
```

Версия (`version 30` для Windows 10/11) важна: формат менялся, и старый парсер не прочитает
новый файл. Начиная с Windows 10 файлы Prefetch **сжаты** (XPRESS Huffman), поэтому «в
лоб» через `strings` видны далеко не все строки.

## Шаг 2: разобрать файл инструментом

Правильный путь — парсер, знающий формат. На Windows это **PECmd** (Eric Zimmerman), на
Linux — `pecmd` из пакета libyal или `prefetch-parser`:

```
$ pecmd CMD.EXE-4A1B2C3D.pf
...
[CMD.EXE]
Run count: 7
Last run: 2025-05-30 14:02:11
First run: 2025-05-12 08:41:03
Volume: \VOLUME{01d2...}
Files referenced: ...
```

Мы получили счётчик запусков и две временные метки — этого часто достаточно для вывода.

## Поля Prefetch и что они значат

| Поле | Смысл | Как использовать |
|------|-------|------------------|
| `Run count` | сколько раз запускали | частота использования |
| `Last run` | время последнего запуска | вписать в таймлайн |
| `First run` | время первого запуска | «когда впервые появилась» |
| Volume info | том(ы) запуска и серийники | доказать внешний носитель |
| Files referenced | файлы, которые читал процесс | понять назначение/данные |

## Серийные номера томов: доказательство запуска с флешки

Это самое мощное свойство Prefetch для расследований. Файл хранит **серийные номера томов**,
с которых запускалась программа. Серийник локального `C:` ты найдёшь в реестре
(`HKLM\SYSTEM\MountedDevices`); если в Prefetch есть **другой** серийник — программа
запускалась с иного тома, например USB-накопителя.

Порядок доказательства прост. Сначала выписываем серийник из Prefetch. Затем ищем его в
`MountedDevices` и в журнале `USBSTOR` (`HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`), где
хранятся серийные номера подключённых USB-устройств. Совпадение серийника даёт связку
«программа запускалась с этого конкретного носителя» — сильное доказательство.

## Связь с другими артефактами

Prefetch редко используется в одиночку. Его сверяют с:

- **ShimCache/AmCache** — подтвердить присутствие файла и хеш;
- **UserAssist** — запускал ли программу пользователь через Explorer;
- **JumpLists** — открывал ли он связанные документы;
- **SRUM** — была ли у программы сетевая активность.

Сходимость нескольких источников превращает «в Prefetch есть запись» в надёжный вывод.

## Ограничения Prefetch

- **Не на всех системах.** На серверных редакциях Prefetch отключён по умолчанию; на SSD
  настройка может быть иной.
- **Очистка.** Утилиты «оптимизации» и антифорензика удаляют `Prefetch`; тогда факт запуска
  ищи в других артефактах.
- **Только 1024 записи.** Старые записи вытесняются — отсутствие программы в Prefetch не
  значит, что её не запускали.
- **Сжатие.** На Windows 10+ файлы сжаты; `strings` без распаковки малоинформативен.

## Частые ошибки и подводные камни

- **Читать версию не глядя.** Файл версии 30 и версии 17 парсятся по-разному.
- **Путать First run и время создания файла.** Это разные вещи; времена в Prefetch — метки
  запуска, а не создания `.pf`.
- **Игнорировать серийники.** Без них не отличить запуск с диска от запуска с флешки.
- **Считать отсутствие записи доказательством.** Prefetch ограничен по числу файлов и может
  быть очищен.
- **Забыть про SuperFetch/SysMain.** Служба `SysMain` (бывший SuperFetch) ведёт Prefetch;
  если её отключили, записей не будет.

## Шпаргалка команд

```
# Опознать версию
file *.pf

# Разбор (Windows)
PECmd.exe -d C:\Windows\Prefetch --csv out

# Разбор (Linux)
pecmd CMD.EXE-4A1B2C3D.pf

# Серийники томов
# Prefetch -> серийник; реестр -> MountedDevices; USBSTOR -> серийники USB
```

## Что мы теперь знаем

- Prefetch хранится в `C:\Windows\Prefetch` как `<имя>-<хеш>.pf`.
- Он даёт счётчик запусков, первое/последнее время и список томов.
- Серийные номера томов позволяют доказать запуск с внешнего носителя.
- На Windows 10+ файлы сжаты; нужен парсер, а не `strings`.
- Prefetch не вечен: записей ограниченное число, и его можно очистить.

## Квиз

Проверь себя.

```quiz
- question: "Что означает имя файла Prefetch вида APP.EXE-1A2B3C4D.pf?"
  options:
    - "Имя программы и хеш от её полного пути"
    - "Случайное имя"
    - "Версия Windows"
    - "Имя пользователя"
  answer: 0
  explanation: "Хеш в имени зависит от полного пути к EXE, что различает запуски из разных каталогов."
- question: "Что доказывает серийный номер тома в Prefetch?"
  options:
    - "С какого тома (в т.ч. внешнего USB) запускали программу"
    - "Пароль пользователя"
    - "IP-адрес машины"
    - "Размер оперативной памяти"
  answer: 0
  explanation: "Сопоставив серийник с MountedDevices и USBSTOR, доказывают запуск с конкретного носителя."
- question: "Почему обычный strings мало помогает на Windows 10+?"
  options:
    - "Файлы Prefetch сжаты (XPRESS Huffman)"
    - "Файлы зашифрованы BitLocker"
    - "Строк в Prefetch нет вообще"
    - "strings не читает .pf"
  answer: 0
  explanation: "С Windows 10 Prefetch сжат, поэтому нужен парсер, распаковывающий содержимое."
- question: "Что означает отсутствие записи Prefetch для программы?"
  options:
    - "Ничего однозначного: записей ограниченное число и их можно очистить"
    - "Программа точно не запускалась"
    - "Программа удалена навсегда"
    - "Пользователь — администратор"
  answer: 0
  explanation: "Prefetch хранит ограниченное число записей и может быть очищен, поэтому отсутствие не доказывает не-запуск."
```

## Куда дальше

Prefetch доказывает **запуск**. Дальше возьмём **ShimCache/AppCompatCache** — артефакт,
который отвечает на вопрос «какие EXE загрузчик вообще видел», включая уже удалённые файлы.
А пока главное запомни: **Prefetch — это счётчик запусков плюс серийники томов**.

## Где пригодится

- **CTF Forensics:** задачи «докажи запуск и откуда».
- **DFIR:** установление факта выполнения вредоносной утилиты.
- **Threat Hunting:** поиск запусков подозрительных программ.
- **Работа:** форензика конечных точек, USB-расследования.
''')

LESSONS["win-appcompat-deep"] = dict(
title="ShimCache / AppCompatCache: что загрузчик «видел» и когда",
order=2, diff="hard", mins=55,
tags="[windows, shimcache, appcompatcache, registry, execution, forensics]",
prereq="[forensics-win-prefetch-deep, forensics-registry-hives]",
summary="Как разобрать ShimCache/AppCompatCache из реестра, чем он отличается от Prefetch, и как доказать присутствие удалённого файла и время последнего изменения.",
body=r'''
## Вопрос, с которого всё начинается

Программу удалили, Prefetch тоже чист. Остался ли вообще какой-то след того, что этот EXE
существовал? Да — механизм совместимости приложений ведёт список «виденных» исполняемых
файлов. Разберём этот артефакт и, главное, поймём, чего он **не** доказывает.

## Наш пример: ключ AppCompatCache в hive SYSTEM

ShimCache хранится в реестре, в hive **SYSTEM**:

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```

Копия hive лежит на диске как файл `C:\Windows\System32\config\SYSTEM`. Возьмём его:

```
$ file SYSTEM
SYSTEM: MS Windows registry file, NT/2000 or above
```

Это **реестровый hive** — двоичный файл. Значение `AppCompatCache` внутри него содержит
структуру с записями о файлах.

## Что такое ShimCache и зачем он существует

**ShimCache** (он же **AppCompatCache**) — часть механизма совместимости приложений
(Application Compatibility). Когда загрузчик проверяет исполняемый файл на совместимость, он
запоминает запись о нём в кэше, чтобы не проверять повторно. Кэш переживает удаление файла:
строка с путём остаётся в реестре.

Критически важный нюанс: запись означает, что файл **был проверен** (обычно — потому что его
видели в файловой системе или запускали). Формат менялся между версиями Windows, и не во всех
версиях ShimCache хранит флаг «исполнялся». Поэтому по ShimCache нельзя утверждать «файл
запускали» — только «файл существовал и был виден системе».

## Шаг 1: разобрать hive

Парсить реестр вручную тяжело; берём инструмент. На Windows — `AppCompatCacheParser` (Eric
Zimmerman), на Linux — `regripper` или `regipy`:

```
$ regripper -r SYSTEM -p appcompatcache
...
C:\Users\jdoe\Downloads\mimikatz.exe
Last Modified: 2025-05-28 21:10:44
Executed: (unknown)
```

Мы получили путь и время последнего изменения файла — даже если самого файла нет.

## Поля ShimCache и их смысл

| Поле | Смысл | Тонкость |
|------|-------|----------|
| Path | путь к файлу | может быть удалён |
| Last Modified | время изменения файла | из метаданных, не запуск |
| Insertion Flags | как запись попала в кэш | зависит от версии ОС |
| Executed | флаг исполнения | есть не во всех версиях |

## ShimCache против Prefetch: что и когда доказывает

Это ключевое различие, которое любят проверять в задачах и на собеседованиях.

| Вопрос | Prefetch | ShimCache |
|--------|----------|-----------|
| Файл существовал | косвенно | да (путь) |
| Файл запускался | да (счётчик) | не всегда (нет флага) |
| Время запуска | есть | обычно нет |
| Переживает удаление | ограниченно | да (запись остаётся) |

Практический вывод: **ShimCache — про присутствие, Prefetch — про запуск**. В отчёте не
подменяй одно другим.

## Связь с AmCache

ShimCache и AmCache дополняют друг друга: AmCache хранит путь, хеш и время установки/первого
появления, а ShimCache — факт «видимости» файла. Сверив оба, ты получаешь и хеш (для поиска
в VirusTotal), и хронологию. Если файл есть в AmCache с хешем, а в ShimCache — с путём, то
картина «программа была установлена и присутствовала» становится надёжной.

## Ограничения и подводные камни

- **Формат зависит от версии Windows.** На старых системах поля другие; парсер должен
  поддерживать конкретную версию.
- **Не доказывает запуск.** Отсутствие флага `Executed` — норма, а не «не запускали».
- **Кэш ограничен.** Как и любой кэш, ShimCache не бесконечен: старые записи вытесняются.
- **Много путей.** Записи включают системные файлы; фильтруй по интересующему каталогу.
- **Путать с AmCache.** Это разные артефакты в разных hive (SYSTEM vs SOFTWARE).

## Шпаргалка команд

```
# Windows
AppCompatCacheParser.exe -f SYSTEM --csv out

# Linux
regripper -r SYSTEM -p appcompatcache
regipy-dump SYSTEM   # или короткий скрипт на regipy

# Найти конкретный файл
regripper -r SYSTEM -p appcompatcache | grep -i '<имя>'
```

## Что мы теперь знаем

- ShimCache (AppCompatCache) живёт в hive SYSTEM, в ключе `Session Manager`.
- Он хранит пути «виденных» исполняемых файлов, включая удалённые.
- ShimCache — про **присутствие**, а не про факт запуска.
- Формат зависит от версии Windows; нужен поддерживающий парсер.
- В паре с AmCache даёт и хеш, и хронологию.

## Квиз

Проверь себя.

```quiz
- question: "В каком hive хранится ShimCache/AppCompatCache?"
  options:
    - "SYSTEM"
    - "SAM"
    - "NTUSER.DAT"
    - "SOFTWARE"
  answer: 0
  explanation: "AppCompatCache — значение в hive SYSTEM, ключ Session Manager."
- question: "Что доказывает запись ShimCache?"
  options:
    - "Файл существовал и был виден системе"
    - "Файл обязательно запускали много раз"
    - "Файл был зашифрован"
    - "Файл скачали из интернета"
  answer: 0
  explanation: "ShimCache фиксирует присутствие/видимость файла, но не всегда факт запуска."
- question: "Чем ShimCache отличается от Prefetch по главному вопросу?"
  options:
    - "ShimCache — про присутствие, Prefetch — про запуск"
    - "Они полностью идентичны"
    - "Prefetch хранится в реестре, ShimCache на диске"
    - "ShimCache доказывает сетевую активность"
  answer: 0
  explanation: "Prefetch содержит счётчик запусков, ShimCache — список виденных путей."
- question: "Почему отсутствие флага Executed в ShimCache не означает, что файл не запускали?"
  options:
    - "Флаг есть не во всех версиях Windows"
    - "Флаг всегда удаляют антивирусы"
    - "Флаг хранится в другом файле"
    - "Флага не существует"
  answer: 0
  explanation: "На части версий Windows флаг исполнения в ShimCache отсутствует по формату."
```

## Куда дальше

ShimCache дал путь и присутствие. Дальше возьмём **AmCache** — он добавит хеши и время
установки, что позволит искать файл в базах ВПО. А пока главное запомни: **ShimCache — это
«что видел загрузчик», а не «что запускали»**.

## Где пригодится

- **CTF Forensics:** доказать присутствие удалённого файла.
- **DFIR:** связать путь с хешем через AmCache.
- **Threat Hunting:** поиск подозрительных путей (Downloads, Temp).
- **Работа:** форензика конечных точек.
''')

LESSONS["win-amcache-deep"] = dict(
title="AmCache: пути, хеши и время появления программ",
order=3, diff="hard", mins=50,
tags="[windows, amcache, ese, registry, hashes, execution, forensics]",
prereq="[forensics-win-appcompat-deep, forensics-registry-hives]",
summary="Как разобрать Amcache.hve (ESE/реестр), достать пути, SHA-1 и время появления программ, и как использовать хеши для проверки в базах ВПО.",
body=r'''
## Вопрос, с которого всё начинается

Мы знаем путь подозрительной программы из ShimCache, но нам нужен **хеш**, чтобы проверить
файл в базе ВПО, и хотя бы приблизительное **время появления** программы на хосте. Где это
взять, если файла уже нет? В AmCache.

## Наш пример: Amcache.hve

```
C:\Windows\AppCompat\Programs\Amcache.hve
```

```
$ file Amcache.hve
Amcache.hve: MS Windows registry file, NT/2000 or above
```

Это **реестровый hive**, но внутри он устроен как база с таблицами — поэтому разбирать его
надо инструментом, а не «на глаз».

## Что такое AmCache

**AmCache** — артефакт механизма совместимости, который хранит сведения о программах:
путь, **хеш (SHA-1)**, время последнего изменения файла и иногда время установки. Он
появился как замена части данных ShimCache и оказался очень полезен для форензики, потому что
даёт **хеш** — то, что напрямую проверяется в VirusTotal и в локальной базе IOC.

Важно: AmCache описывает «что было установлено/запущено», и по нему часто нельзя точно
сказать, кто и когда запустил файл. Зато можно доказать **наличие** программы и её
идентичность через хеш.

## Шаг 1: разобрать Amcache.hve

На Windows — `AmcacheParser` (Eric Zimmerman), на Linux — `regripper` или `regipy`:

```
$ regripper -r Amcache.hve -p amcache
...
Path: C:\Users\jdoe\AppData\Local\Temp\svchost.exe
SHA1: 9f2c...e1
LastModified: 2025-05-28 21:09:10
```

Получили путь, SHA-1 и время изменения. Теперь файл можно проверить в базе ВПО по хешу.

## Таблицы AmCache и что они значат

| Таблица/ключ | Что содержит | Зачем |
|--------------|--------------|-------|
| `Root\File` | записи о файлах: путь, SHA-1, время | идентификация по хешу |
| `Root\Programs` | установленные программы | список ПО |
| `Root\InventoryApplication` | метаданные приложений | версии, издатели |

## AmCache и другие артефакты

AmCache — не единственный источник хешей. Дополняй его:

- **Prefetch** — подтверждает запуск (AmCache — присутствие);
- **ShimCache** — путь и «видимость»;
- **SRUM** — сетевая активность по приложению;
- **базы антивируса/EDR** — детекты по хешу.

Комбинация «AmCache (хеш + путь) + Prefetch (запуск)» — стандартный приём доказательства
вредоносного запуска.

## Как использовать хеш на практике

Получив SHA-1, ты можешь:

1. проверить файл в публичной базе (VirusTotal) — есть ли детекты;
2. сопоставить с локальным списком IOC из threat-intel;
3. связать с другими хостами, где встречается тот же хеш.

Это превращает AmCache из «списка программ» в инструмент **атрибуции и корреляции**.

## Ограничения и подводные камни

- **Версии формата.** AmCache менялся; ключи и таблицы различаются между версиями Windows.
- **Не доказывает запуск.** Наличие в AmCache — это «присутствовал/устанавливался», не «кто
  запустил».
- **Неполнота.** Не все файлы попадают в AmCache; отсутствие записи не означает отсутствия
  файла.
- **Хеши только SHA-1** в типичном случае; не жди MD5/SHA-256.
- **Путать с ShimCache.** Разные hive и разные данные (AmCache — в `AppCompat\Programs`).

## Шпаргалка команд

```
# Windows
AmcacheParser.exe -f Amcache.hve --csv out

# Linux
regripper -r Amcache.hve -p amcache
# или regipy:
python3 -c "from regipy.registry import RegistryHive; ..."

# Проверить хеш по базе ВПО (внешне)
# сопоставить SHA1 с IOC / VirusTotal
```

## Что мы теперь знаем

- AmCache лежит в `C:\Windows\AppCompat\Programs\Amcache.hve`.
- Он даёт путь, SHA-1 и время изменения программы.
- Хеш позволяет проверить файл в базе ВПО и связать хосты.
- AmCache — про присутствие, не про запуск; для запуска — Prefetch.
- Формат зависит от версии Windows.

## Квиз

Проверь себя.

```quiz
- question: "Где хранится AmCache?"
  options:
    - "C:\\Windows\\AppCompat\\Programs\\Amcache.hve"
    - "C:\\Windows\\Prefetch"
    - "C:\\Windows\\System32\\config\\SAM"
    - "C:\\Users\\Public\\Amcache.db"
  answer: 0
  explanation: "AmCache — hive в каталоге AppCompat\\Programs."
- question: "Какое главное преимущество AmCache для расследования?"
  options:
    - "Он даёт хеш (SHA-1) программы"
    - "Он хранит пароли пользователя"
    - "Он содержит сетевые пакеты"
    - "Он показывает температуру CPU"
  answer: 0
  explanation: "Хеш позволяет проверить файл в базе ВПО и коррелировать хосты."
- question: "Доказывает ли запись в AmCache факт запуска программы?"
  options:
    - "Нет, это присутствие/установка; запуск подтверждает Prefetch"
    - "Да, AmCache — это журнал запусков"
    - "Да, но только для системных файлов"
    - "Да, если файл в Downloads"
  answer: 0
  explanation: "AmCache описывает наличие программы, а факт запуска даёт Prefetch."
- question: "Что делать с SHA-1 из AmCache?"
  options:
    - "Проверить в базе ВПО и сопоставить с IOC"
    - "Использовать как пароль"
    - "Восстановить по нему файл"
    - "Расшифровать диск"
  answer: 0
  explanation: "Хеш служит для проверки в базах детектов и threat-intel корреляции."
```

## Куда дальше

AmCache дал хеши и присутствие. Дальше возьмём **SRUM** — базу, которая показывает **сетевую
активность** приложений: сколько данных и куда передавалось. А пока главное запомни:
**AmCache — это путь плюс хеш, а не доказательство запуска**.

## Где пригодится

- **CTF Forensics:** идентификация файла по хешу.
- **DFIR:** проверка программы в базе ВПО.
- **Threat Hunting:** корреляция одного хеша по многим хостам.
- **Работа:** форензика конечных точек, threat-intel.
''')

LESSONS["win-srum-deep"] = dict(
title="SRUM: сетевая активность и потребление ресурсов по приложениям",
order=4, diff="hard", mins=55,
tags="[windows, srum, srudb, ese, network, exfiltration, forensics]",
prereq="[forensics-win-amcache-deep, forensics-registry-hives]",
summary="Как открыть SRUDB.dat (ESE), разобрать сетевую активность приложений и пользователей, и как по объёмам передачи выявить эксфильтрацию данных.",
body=r'''
## Вопрос, с которого всё начинается

Подозрение на утечку данных: кто-то мог выгружать файлы наружу. Журналы прокси неполные, но
Windows ведёт собственную базу сетевой активности по приложениям. Где она и как из неё
увидеть, **какое приложение и сколько передало**?

## Наш пример: SRUDB.dat

```
C:\Windows\System32\sru\SRUDB.dat
```

```
$ file SRUDB.dat
SRUDB.dat: Extensible Storage Engine (ESE) Database File (edb)
```

Это **ESE-база**, тот же движок, что у `Windows.edb`. Парсить надо инструментом,
понимающим ESE, а не текстовым просмотром.

## Что такое SRUM

**SRUM (System Resource Usage Monitor)** — подсистема Windows, которая собирает статистику
использования ресурсов: сколько данных приложение передало по сети, сколько CPU/диска
потратило, как долго работало. Данные хранятся в `SRUDB.dat` с привязкой к приложению и
пользователю.

Для форензики SRUM ценен тем, что показывает **сетевую активность в разрезе приложений** —
это прямой ответ на вопрос «кто и сколько передал наружу».

## Шаг 1: разобрать ESE-базу

На Windows — **SRUMDump** (Mark Baggett) или `esedbexport` (libyal), на Linux —
`esedbexport` плюс скрипт-обёртка:

```
$ esedbexport -t out SRUDB.dat
$ ls out.1
SruDbIdMapTable.table  NetworkUsages.table  ...
```

Таблица **`NetworkUsages`** — то, что нам нужно: сетевой трафик по приложениям.

## Шаг 2: связать ID приложения с именем

В SRUM приложения хранятся как числовые **AppId**. Чтобы получить имя, используется таблица
**`SruDbIdMapTable`**:

```
$ grep -a -i svchost out.1/SruDbIdMapTable.table
42  \Device\...\svchost.exe
```

Связка «AppId → имя процесса» обязательна: без неё выгрузка трафика бессмысленна.

## Поля NetworkUsages и их смысл

| Поле | Смысл | Как использовать |
|------|-------|------------------|
| AppId | идентификатор приложения | связать с именем процесса |
| UserId | пользователь | отделить сессии |
| BytesSent | байт передано | искать большие выгрузки |
| BytesRecv | байт принято | искать загрузки |
| Timestamp | интервал | вписать в таймлайн |

## Как выявить эксфильтрацию

Метод прост: отсортировать приложения по `BytesSent` за интересующий период и посмотреть на
аномалии. Большая передача у неизвестного приложения, или всплеск у `powershell.exe`,
`curl.exe`, `rclone.exe` — сильный сигнал. Дальше связываем с другими артефактами: Prefetch
(запуск утилиты), AmCache (хеш и путь), сетевые логи (куда именно шла передача). Так SRUM
превращается из «статистики» в **доказательство выгрузки данных**.

## Ограничения и подводные камни

- **Не все приложения.** SRUM собирает данные не для каждого процесса; отсутствие записи не
  означает отсутствия трафика.
- **Интервалы, а не точные времена.** Данные агрегированы по интервалам (обычно час), не по
  отдельным пакетам.
- **Срок хранения.** База ротируется; старые записи исчезают — работай с историческим
  снимком, если он есть.
- **Идентификаторы.** Без `SruDbIdMapTable` AppId бесполезен.
- **Сброс данных.** Пользователь может очистить SRUM; отсутствие — не доказательство.

## Шпаргалка команд

```
# Разобрать ESE
esedbexport -t out SRUDB.dat
# Windows
SRUMDump.exe -f SRUDB.dat --csv out

# Найти имена процессов
grep -a -i '<имя>' out.1/SruDbIdMapTable.table

# Топ по переданным байтам (после выгрузки NetworkUsages)
sort -t, -k4 -nr out.1/NetworkUsages.csv | head
```

## Что мы теперь знаем

- SRUM хранится в `C:\Windows\System32\sru\SRUDB.dat` и это ESE-база.
- Таблица `NetworkUsages` даёт сетевой трафик по приложениям и пользователям.
- Имена приложений берутся из `SruDbIdMapTable` по AppId.
- Сортировка по `BytesSent` выявляет возможную эксфильтрацию.
- Данные агрегированы по интервалам и ротируются.

## Квиз

Проверь себя.

```quiz
- question: "Какой формат у SRUDB.dat?"
  options:
    - "ESE-база (Extensible Storage Engine)"
    - "SQLite"
    - "Текстовый журнал"
    - "XML"
  answer: 0
  explanation: "SRUDB.dat — ESE-база, как Windows.edb; парсится esedbexport/SRUMDump."
- question: "Какая таблица SRUM показывает сетевую активность приложений?"
  options:
    - "NetworkUsages"
    - "SruDbIdMapTable"
    - "Activity"
    - "Notification"
  answer: 0
  explanation: "NetworkUsages содержит байты отправленные/полученные по AppId."
- question: "Зачем нужна таблица SruDbIdMapTable?"
  options:
    - "Связать числовой AppId с именем процесса"
    - "Хранить пароли"
    - "Показывать температуру"
    - "Содержать таблицу разделов"
  answer: 0
  explanation: "Без сопоставления AppId с именем выгрузка трафика не имеет смысла."
- question: "Что указывает на возможную эксфильтрацию данных в SRUM?"
  options:
    - "Аномально большой BytesSent у подозрительного приложения"
    - "Много свободного места на диске"
    - "Отсутствие записи NetworkUsages"
    - "Высокий BytesRecv у системного процесса"
  answer: 0
  explanation: "Большая исходящая передача у неизвестного/скриптового приложения — сигнал выгрузки."
```

## Куда дальше

Модуль глубокого разбора выполнения закрыт: Prefetch (запуск), ShimCache (присутствие),
AmCache (хеш), SRUM (сеть). Дальше ветка уходит в **инфраструктурные артефакты Windows**
(SMB, WinRM, GPO, печать). А пока главное запомни: **SRUM — это сетевой след по приложениям**.

## Где пригодится

- **CTF Forensics:** задачи про утечку/передачу данных.
- **DFIR:** оценка объёма выгрузки при инциденте.
- **Threat Hunting:** аномалии сетевой активности процессов.
- **Работа:** форензика конечных точек, data-exfiltration расследования.
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
        '  - "Threat Hunting (Windows)"\n'
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
"win-prefetch-deep": dict(
 labtitle="разбор Prefetch и серийника тома",
 files="task.md, PSEXEC.EXE-1A2B3C4D.pf",
 seedfile="PSEXEC.EXE-1A2B3C4D.pf",
 seedtext=(
  "MS Windows Prefetch file, version 30\n"
  "Executable: PSEXEC.EXE\n"
  "Run count: 7\n"
  "Volume: \\VOLUME{01d2a4b6-...}  Serial: 0x7a1c9e42\n"
  "Last run: 2025-05-30 14:02:11\n"
  "note: nto{pr3f3tch_v0lum3_s3r14l}\n"
 ),
 task=("# Задача: Prefetch\n\n`PSEXEC.EXE-1A2B3C4D.pf` — файл Prefetch. "
       "Найди счётчик запусков и серийник тома.\n\n1. `file PSEXEC.EXE-1A2B3C4D.pf`.\n"
       "2. `strings PSEXEC.EXE-1A2B3C4D.pf | grep -iE 'run|volume|serial'`.\n"
       "3. `grep nto PSEXEC.EXE-1A2B3C4D.pf > found.txt`.\n"),
 hints=("    - 'Опознай формат: `file PSEXEC.EXE-1A2B3C4D.pf`.'\n"
        "    - 'Смотри метаданные: `strings PSEXEC.EXE-1A2B3C4D.pf`.'\n"
        "    - 'Найди серийник тома: `strings PSEXEC.EXE-1A2B3C4D.pf | grep -i serial`.'\n"
        "    - 'Метка: `grep nto PSEXEC.EXE-1A2B3C4D.pf > found.txt`.'"),
 flag="nto{pr3f3tch_v0lum3_s3r14l}",
 solution="grep nto PSEXEC.EXE-1A2B3C4D.pf > found.txt"),
"win-appcompat-deep": dict(
 labtitle="ShimCache: присутствие удалённого файла",
 files="task.md, SYSTEM",
 seedfile="SYSTEM",
 seedtext=(
  "MS Windows registry file, NT/2000 or above\n"
  "AppCompatCache entries:\n"
  "C:\\Users\\jdoe\\Downloads\\mimikatz.exe  LastModified 2025-05-28 21:10:44\n"
  "C:\\Windows\\System32\\cmd.exe  LastModified 2025-01-01 00:00:00\n"
  "note: nto{sh1mc4ch3_p4th_f0und}\n"
 ),
 task=("# Задача: ShimCache\n\n`SYSTEM` — hive реестра с AppCompatCache. "
       "Найди путь подозрительного файла и метку.\n\n1. `file SYSTEM`.\n"
       "2. `strings SYSTEM | grep -iE 'mimikatz|downloads'`.\n"
       "3. `grep nto SYSTEM > found.txt`.\n"),
 hints=("    - 'Опознай hive: `file SYSTEM`.'\n"
        "    - 'Ищи пути: `strings SYSTEM | grep -i downloads`.'\n"
        "    - 'Смотри подозрительный файл: `strings SYSTEM | grep -i mimikatz`.'\n"
        "    - 'Метка: `grep nto SYSTEM > found.txt`.'"),
 flag="nto{sh1mc4ch3_p4th_f0und}",
 solution="grep nto SYSTEM > found.txt"),
"win-amcache-deep": dict(
 labtitle="AmCache: путь и SHA-1",
 files="task.md, Amcache.hve",
 seedfile="Amcache.hve",
 seedtext=(
  "MS Windows registry file, NT/2000 or above\n"
  "Root\\File entries:\n"
  "Path: C:\\Users\\jdoe\\AppData\\Local\\Temp\\svchost.exe\n"
  "SHA1: 9f2c1a7b4e8d3c5f6a0b1c2d3e4f5a6b7c8d9e0f\n"
  "LastModified: 2025-05-28 21:09:10\n"
  "note: nto{4mc4ch3_sh4_h4sh}\n"
 ),
 task=("# Задача: AmCache\n\n`Amcache.hve` — hive AmCache. "
       "Найди путь и SHA-1 подозрительной программы.\n\n1. `file Amcache.hve`.\n"
       "2. `strings Amcache.hve | grep -iE 'path|sha1'`.\n"
       "3. `grep nto Amcache.hve > found.txt`.\n"),
 hints=("    - 'Опознай hive: `file Amcache.hve`.'\n"
        "    - 'Ищи записи о файлах: `strings Amcache.hve | grep -i path`.'\n"
        "    - 'Найди хеш: `strings Amcache.hve | grep -i sha1`.'\n"
        "    - 'Метка: `grep nto Amcache.hve > found.txt`.'"),
 flag="nto{4mc4ch3_sh4_h4sh}",
 solution="grep nto Amcache.hve > found.txt"),
"win-srum-deep": dict(
 labtitle="SRUM: сетевая активность приложения",
 files="task.md, SRUDB.dat",
 seedfile="SRUDB.dat",
 seedtext=(
  "Extensible Storage Engine (ESE) Database File (edb)\n"
  "NetworkUsages: AppId=42 BytesSent=104857600 BytesRecv=2048\n"
  "SruDbIdMapTable: 42 rclone.exe\n"
  "note: nto{srum_n3tw0rk_3xf1l}\n"
 ),
 task=("# Задача: SRUM\n\n`SRUDB.dat` — база SRUM. "
       "Определи приложение с большой исходящей передачей и найди метку.\n\n"
       "1. `file SRUDB.dat`.\n2. `strings SRUDB.dat | grep -iE 'bytes|rclone'`.\n"
       "3. `grep nto SRUDB.dat > found.txt`.\n"),
 hints=("    - 'Опознай формат: `file SRUDB.dat`.'\n"
        "    - 'Ищи таблицу трафика: `strings SRUDB.dat | grep -i bytes`.'\n"
        "    - 'Свяжи AppId с процессом: `strings SRUDB.dat | grep -i rclone`.'\n"
        "    - 'Метка: `grep nto SRUDB.dat > found.txt`.'"),
 flag="nto{srum_n3tw0rk_3xf1l}",
 solution="grep nto SRUDB.dat > found.txt"),
}

def main():
    w(f"{C}/forensics-win-execution-deep.md", HUB)
    for lid, d in LESSONS.items():
        d["id"] = lid
        d["parent"] = "forensics-win-execution-deep"
        d.update(LABS[lid])
        txt = fm(d) + "\n" + d["body"].strip() + "\n"
        w(f"{C}/{lid}.md", txt)
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
