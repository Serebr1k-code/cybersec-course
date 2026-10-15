---
id: forensics-volatility-deep
title: "Volatility 3: продвинутый разбор памяти"
category: forensics
parent: forensics-memory
difficulty: hard
order: 3
tags: [volatility, memory, plugins, yarascan, timeline, kernel, advanced]
prerequisites: [forensics-memory]
useful_for:
  - "CTF Forensics категория"
  - "Incident Response"
  - "Malware analysis (in-memory)"
estimated_minutes: 55
summary: "Продвинутые приёмы Volatility 3: символы и ISF, кастомные плагины, yarascan, timeline, анализ ядра, VAD, дампы процессов и работа со сложными дампами."
lab:
  kind: shell
  title: "Практика: найти инъекцию в дампе памяти"
  toolset: [core, volatility]
  workdir: /home/student/task
  files: [task.md, notes.txt, mem.raw]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Начни с `vol -f mem.raw windows.pslist` и `windows.netscan`."
    - "Подозрительное соединение держит процесс с внешним IP на 443."
    - "Регионы инъекции ищет `vol -f mem.raw windows.malfind --pid 4120`."
    - "В выводе malfind есть строка с C2-URL и флагом: `... --pid 4120 | grep nto > found.txt`."
---

## Вопрос, с которого всё начинается

У нас есть дамп оперативной памяти `mem.raw` с подозрительной машины. В памяти нет
файлов — есть процессы, соединения и куски кода, которые на диск никогда не попадали.
Как найти в этом «супе» след вредоносной активности?

**Volatility 3** — основной фреймворк разбора дампов памяти. В этом уроке мы найдём
инъекцию в процесс и вытащим из неё полезную нагрузку.

## Наш пример: mem.raw

Начинаем всегда с общей информации о дампе:

```bash
$ vol -f mem.raw windows.info
Volatility 3 Framework 2.5.0
Variable        Value
Kernel Base     0xf8006...
Is64Bit         True
```

`windows.info` показывает версию ОС, разрядность и базовый адрес ядра. Без этого шага
плагины могут не найти нужные структуры.

## Шаг 1: символы (ISF)

Volatility 3 не требует профилей: она определяет ОС по **ISF**-файлам (описания структур
ядра в формате JSON). Их скачивают автоматически, но в офлайн-среде нужно положить
заранее:

```bash
$ vol -f mem.raw --symbol-dirs ./symbols windows.pslist
$ ls ~/.cache/volatility3/symbols/
```

Если символов нет и сети нет — плагины, работающие со структурами ядра, не отработают.
Поэтому при подготовке к изолированному анализу ISF скачивают заранее.

## Шаг 2: процессы и соединения

```bash
$ vol -f mem.raw windows.pslist | head
$ vol -f mem.raw windows.netscan | grep ESTABLISHED
dllhost.exe 4120 10.0.0.5:49152 185.220.101.7:443 ESTABLISHED
```

`pslist` показывает активные процессы, `netscan` — сетевые соединения. Процесс
`dllhost.exe` (системный) держит соединение с внешним IP на порт 443 — подозрительно.

## Шаг 3: скрытые процессы

Руткит может «вырезать» процесс из списка. Сравниваем два взгляда:

```bash
$ vol -f mem.raw windows.pslist > a.txt
$ vol -f mem.raw windows.psscan > b.txt
$ comm -13 <(awk '{print $1}' a.txt | sort) <(awk '{print $1}' b.txt | sort)
```

`pslist` читает связанный список процессов, `psscan` сканирует пул памяти напрямую. PID,
которые есть только в `psscan`, — скрытые.

## Шаг 4: инъекции

Регионы памяти процесса описывают **VAD** (Virtual Address Descriptor). Инъекция видна
как регион с правами «чтение-запись-выполнение»:

```bash
$ vol -f mem.raw windows.malfind --pid 4120
PID    Process   Start       End         Protection
4120   dllhost   0x400000    0x460000    PAGE_EXECUTE_READWRITE
```

`PAGE_EXECUTE_READWRITE` — регион, который можно и читать, и менять, и исполнять. Обычный
код так не размещают: это признак внедрённого кода.

## Шаг 5: дампим payload

```bash
$ vol -f mem.raw windows.malfind --pid 4120 --dump
$ ls -la pid.4120.dmp
$ yara beacon.yar pid.4120.dmp
```

Флаг `--dump` сохраняет регион в файл, и дальше его можно прогнать через YARA или
открыть в дизассемблере. Так из памяти достают то, чего нет на диске.

## Шаг 6: командная строка и родитель

```bash
$ vol -f mem.raw windows.cmdline --pid 4120
$ vol -f mem.raw windows.pstree | grep -A2 dllhost
```

`cmdline` показывает, с какими аргументами запущен процесс, `pstree` — кто его породил.
Подозрительный родитель (например, `winword.exe` вместо `services.exe`) — сильная зацепка.

## Шаг 7: реестр, хеши и таймлайн из памяти

```bash
$ vol -f mem.raw windows.hashdump
$ vol -f mem.raw windows.registry.printkey --key 'Software\Microsoft\Windows\CurrentVersion\Run'
$ vol -f mem.raw windows.timeliner --output-file timeline.csv
```

Из памяти можно достать хеши локальных паролей, ключи автозапуска и даже построить
таймлайн событий — всё это не нужно снимать с диска.

## Ключевые плагины

| Плагин | Назначение |
|--------|-----------|
| `windows.info` | метаданные дампа |
| `windows.pslist` | список процессов |
| `windows.psscan` | скан пула (находит скрытые) |
| `windows.pstree` | дерево процессов |
| `windows.cmdline` | командные строки |
| `windows.netscan` | сетевые соединения |
| `windows.malfind` | инъекции (RWX-регионы) |
| `windows.dlllist` | загруженные DLL |
| `windows.filescan` | файловые объекты |
| `windows.dumpfiles` | дамп файлов из памяти |
| `windows.yarascan` | YARA по памяти |

## Кастомные плагины

Volatility 3 позволяет писать свои плагины на Python — класс наследует `PluginInterface`
и реализует `run()`. Это нужно для задач под конкретное расследование:

```python
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements

class MyPlugin(interfaces.plugins.PluginInterface):
    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name='primary')]
    def run(self):
        yield renderers.TreeGrid([("Addr", int)], [(0x1000,)])
```

## Работа со сложными дампами

- **Неверный профиль** — задайте `--single-location` или укажите слой явно.
- **Большие дампы** — используйте `--pid` и сохраняйте вывод в файл.
- **Повреждённый дамп** — `banners.Banners` подскажет, распознан ли kernel.
- **Linux-дампы** — `linux.pslist`; **macOS** — `mac.pslist`, `mac.netstat`.

```bash
$ vol -f mem.raw banners.Banners
$ vol -f mem.raw linux.pslist --pid 1
```

## Дампы процессов и файлов

```bash
$ vol -f mem.raw windows.pslist --pid 4120 --dump
$ vol -f mem.raw windows.dumpfiles --pid 4120 --dump-dir out/
$ vol -f mem.raw windows.memmap --pid 4120 --dump
```

Дамп процесса можно открыть в `gdb` или дизассемблере и разобрать инжектированный код.
`dumpfiles` извлекает файлы, которые процесс держал в кэше, даже если на диске их уже
нет.

## Оптимизация и воспроизводимость

Сохраняйте вывод плагинов в файлы для отчёта и повторного анализа. Для больших дампов
запускайте плагины последовательно, ограничивая `--pid`. Всегда записывайте версию
Volatility и хеш дампа — воспроизводимость критична для доказательств.

## Типовые ошибки

- **Забыть `windows.info`** — без него плагины ругаются на символы.
- **Работать без сети и без локальных ISF** — символы не подгрузятся.
- **Верить `pslist`** — скрытые процессы только в `psscan`.
- **Не дампить регионы `malfind`** — payload не проанализировать.
- **Забывать про versioned-плагины** (Windows 10/11 против старых).
- **Не сохранять вывод** плагинов в файл — потом нечего приложить к отчёту.

## Что даёт `banners.Banners`

Для дампа неизвестной ОС `banners.Banners` подскажет, что внутри, — от версии Windows до
Linux-ядра. Это первый шаг, когда `windows.info` не срабатывает: фреймворк сам определит
тип и предложит подходящие плагины.

## Что мы теперь знаем

- Volatility 3 определяет ОС по ISF-символам, а не по профилям.
- `windows.info` — обязательный первый шаг.
- `pslist` против `psscan` находит скрытые процессы.
- `malfind` показывает инъекции (регионы RWX), `--dump` сохраняет payload.
- `cmdline`/`pstree` дают командную строку и родителя.
- Из памяти достают хеши, ключи реестра и таймлайн.

## На что смотреть дальше

- **Не верить `pslist`** — скрытые процессы только в `psscan`.
- **Не забывать дампить регионы** `malfind` — иначе payload не проанализировать.
- **Ограничивать `--pid`** на больших дампах — иначе очень медленно.
- **Проверять символы** — без ISF часть плагинов не работает.

## Скрытые драйверы: `modules` против `driverscan`

Тот же приём, что с процессами, работает и для драйверов. Руткит может вырезать свой
драйвер из списка, но объект остаётся в пуле памяти:

```bash
$ vol -f mem.raw windows.modules | awk '{print $1}' | sort -u > m.txt
$ vol -f mem.raw windows.driverscan | awk '{print $1}' | sort -u > d.txt
$ comm -13 m.txt d.txt
```

Драйвер, видимый только в `driverscan`, — кандидат в руткиты. Дальше сверьте его адрес с
`windows.modscan` и проверьте подписи через `windows.verinfo`.

## VAD подробно: `vadinfo` и `vadwalk`

`malfind` лишь фильтрует RWX-регионы. Чтобы увидеть картину целиком, смотрят все VAD
процесса — это покажет и нормальные DLL, и аномально большие приватные регионы:

```bash
$ vol -f mem.raw windows.vadinfo --pid 4120 | grep -i 'protection\|start'
$ vol -f mem.raw windows.vadwalk --pid 4120 | head
```

Приватный регион без файла-«владельца» (`File: N/A`) с правом Execute — типичное место
in-memory нагрузки.

## Таймлайн по соединениям и процессам

Из памяти удобно строить короткий таймлайн активности: время старта процесса плюс его
сетевые соединения:

```bash
$ vol -f mem.raw windows.pslist --output-file procs.json
$ vol -f mem.raw windows.netscan --output-file nets.json
$ jq -r '.[]|select(.Proto=="TCP")|"\(.Created) \(.Owner) \(.ForeignAddr):\(.ForeignPort)"' nets.json | sort | head
```

Сопоставив время создания процесса со временем соединения к внешнему IP, вы получите
момент установления C2-канала — ключевой факт для отчёта.

## Если не сработало

- Плагин падает на символах → задайте `--symbol-dirs` с локальными ISF.
- `windows.info` не распознаёт дамп → `banners.Banners` определит ОС.
- Очень медленно → ограничьте `--pid` и сохраняйте вывод в файл.
- Linux/macOS-дамп → используйте `linux.*`/`mac.*`, а не `windows.*`.

## Дамп памяти живого хоста

Порядок сбора важен: дамп снимают **до** выключения машины. Инструменты — `winpmem`
(Windows), `avml`/`lime` (Linux). Хешируйте дамп сразу:

```bash
$ winpmem_mini_x64_rc2.exe mem.raw
$ sha256sum mem.raw | tee mem.sha256
```

Без хеша дамп не является доказательством.

## Признаки anti-forensics в памяти

Если `pslist` даёт странные или неполные результаты, доверяйте `psscan` и сверяйтесь с
`windows.devicetree`: расхождение указывает на DKOM — прямое искажение структур ядра.

## Хеш и версия — в отчёт

Всегда фиксируйте версию фреймворка и хеш дампа: без этого результат невоспроизводим и
как доказательство не годится.

```bash
$ vol --version
$ sha256sum mem.raw
```

## Символы под конкретную сборку

Версия ISF должна совпадать с ядром дампа. Для кастомных сборок символы генерируют из
отладочной информации через `dwarf2json`:

```bash
$ dwarf2json windows --elf vmlinux > win.json
```

## Квиз

Проверь себя.

```quiz
- question: "Нужны ли профили в Volatility 3?"
  options:
    - "да"
    - "нет, ОС определяется по символам (ISF)"
    - "только для Linux"
    - "только для Windows"
  answer: 1
- question: "Какой плагин ищет YARA-сигнатуры в памяти?"
  options:
    - "`windows.psscan`"
    - "`yarascan`"
    - "`windows.netscan`"
    - "`windows.info`"
  answer: 1
- question: "Как найти скрытый процесс?"
  options:
    - "по имени"
    - "сравнением `pslist` и `psscan`"
    - "по PID"
    - "по порту"
  answer: 1
- question: "Что даёт `windows.malfind --dump`?"
  options:
    - "сеть"
    - "дамп региона с инъекцией (payload)"
    - "реестр"
    - "хеши"
  answer: 1
- question: "Как восстановить хронологию из памяти?"
  options:
    - "`windows.timeliner`"
    - "`windows.pslist`"
    - "`strings`"
    - "`exiftool`"
  answer: 0
```

## Куда дальше

Мы разобрали память. Но вредоносные данные часто прячут не в коде, а в **архивах** —
многослойных, с паролями, битых. В следующем уроке мы распакуем «матрёшку» из вложенных
контейнеров. А пока запомни: **память хранит то, чего нет на диске — сравнивай `pslist` и
`psscan`**.

## Где пригодится

- **CTF:** сложные задачи с дампами памяти.
- **Incident Response:** глубокая экспертиза памяти.
- **Malware analysis:** разбор инъекций и in-memory нагрузок.
- **Threat Hunting:** поиск скрытых процессов и руткитов.
- **Разработка детектов:** кастомные плагины и сигнатуры.
