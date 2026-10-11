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
---
Volatility 3 — основной фреймворк анализа дампов памяти. Он умеет разбирать процессы, сеть, реестр, файлы, кэш, ключи и находить скрытое/инжектированное. Этот урок — про продвинутые приёмы: символы и ISF, кастомные плагины, `yarascan`, таймлайн, анализ ядра, VAD, дампы процессов и работу со сложными дампами.

## Установка и базовый запуск

```bash
$ pip install volatility3
$ vol -f mem.raw windows.info
Volatility 3 Framework 2.5.0
Variable        Value
Kernel Base     0xf8006...
DTB             0x1ab000
Is64Bit         True
```

Символы (ISF — Intermediate Symbol Format) Volatility 3 скачивает автоматически при доступе к сети; для офлайн-окружения кладите их в `volatility3/symbols/windows/` (или используйте `--symbol-dirs`).

```bash
$ vol -f mem.raw --symbol-dirs ./symbols windows.pslist
$ vol -f mem.raw windows.pslist | head
```

## Ключевые плагины

| Плагин | Назначение |
|--------|-----------|
| `windows.info` | метаданные дампа (версия, arch) |
| `windows.pslist` | список процессов |
| `windows.psscan` | скан пула (находит скрытые) |
| `windows.pstree` | дерево процессов |
| `windows.cmdline` | командные строки |
| `windows.netscan` | сетевые соединения |
| `windows.malfind` | инъекции (RWX-регионы) |
| `windows.dlllist` | загруженные DLL |
| `windows.handles` | handles (файлы, ключи) |
| `windows.registry.hivelist` | кусты в памяти |
| `windows.filescan` | файловые объекты |
| `windows.dumpfiles` | дамп файлов из памяти |
| `windows.memmap` | карта памяти процесса |
| `windows.vadinfo` | VAD-регионы процесса |
| `windows.yarascan` | YARA по памяти |

```bash
$ vol -f mem.raw windows.pslist
$ vol -f mem.raw windows.pstree
$ vol -f mem.raw windows.cmdline
$ vol -f mem.raw windows.netscan | grep ESTABLISHED
$ vol -f mem.raw windows.malfind --pid 4120
```

## Обнаружение скрытого

Сравнение `pslist` (активный список) и `psscan` (скан пула) выявляет процессы, скрытые руткитом (unlinked). `psscan` находит также завершённые процессы, оставшиеся в памяти.

```bash
$ vol -f mem.raw windows.pslist > a.txt
$ vol -f mem.raw windows.psscan > b.txt
# PID, которые есть в psscan, но нет в pslist
$ comm -13 <(awk '{print $1}' a.txt | sort) <(awk '{print $1}' b.txt | sort)
$ vol -f mem.raw windows.psscan | grep -i 'evil'
```

## VAD и инъекции

VAD (Virtual Address Descriptor) описывает регионы памяти процесса. Инъекции (process hollowing, reflective DLL) видны как регионы с правами `PAGE_EXECUTE_READWRITE` и содержимым, похожим на PE/shellcode.

```bash
$ vol -f mem.raw windows.vadinfo --pid 4120
$ vol -f mem.raw windows.malfind --pid 4120
PID    Process   Start       End         Tag  Protection
4120   rundll32  0x400000    0x460000    VadS PAGE_EXECUTE_READWRITE
```

Дамп подозрительного региона и анализ:

```bash
$ vol -f mem.raw windows.memmap --pid 4120 --dump
$ ls -la pid.4120.dmp
$ python3 vol.py -f mem.raw windows.malfind --pid 4120 --dump
```

## YARA по памяти

`yarascan` ищет строки/паттерны в физической памяти, `vadyarascan` — в VAD-регионах (по процессам).

```bash
$ vol -f mem.raw windows.yarascan --yara-file=rule.yar
$ vol -f mem.raw windows.vadyarascan --yara-file=rule.yar --pid 4120
$ vol -f mem.raw windows.yarascan --yara-rules 'rule x { strings: $a="evil.tld" condition: $a }'
```

## Дампы процессов и файлов

```bash
# дамп процесса (для дальнейшего анализа)
$ vol -f mem.raw windows.pslist --pid 4120 --dump
$ vol -f mem.raw windows.dumpfiles --pid 4120 --dump-dir out/
# извлечь конкретный файл из кэша
$ vol -f mem.raw windows.dumpfiles --virtaddr 0x...
```

Дамп процесса можно открыть в `gdb`/`IDA` и проанализировать инжектированный код.

## Реестр и ключи из памяти

```bash
$ vol -f mem.raw windows.registry.hivelist
$ vol -f mem.raw windows.registry.printkey --key 'Software\Microsoft\Windows\CurrentVersion\Run'
$ vol -f mem.raw windows.hashdump        # хеши из памяти
$ vol -f mem.raw windows.lsadump         # LSA secrets
```

## Таймлайн из памяти

```bash
$ vol -f mem.raw timeliner.Timeliner --output-file timeline.csv
$ vol -f mem.raw windows.timeliner       # события процессов/файлов
```

## Разобранный пример

Дан `mem.raw`. Подозрение на инъекцию в `dllhost.exe`.

```bash
# 1. Информация
$ vol -f mem.raw windows.info | grep -E 'Kernel Base|Is64Bit'
# 2. Процессы и сеть
$ vol -f mem.raw windows.netscan | grep ESTABLISHED
dllhost.exe 4120 10.0.0.5:49152 185.220.101.7:443 ESTABLISHED
# 3. Инъекция
$ vol -f mem.raw windows.malfind --pid 4120
# 4. Дамп и YARA
$ vol -f mem.raw windows.malfind --pid 4120 --dump
$ yara beacon.yar pid.4120.dmp
# 5. Командная строка/родитель
$ vol -f mem.raw windows.cmdline --pid 4120
$ vol -f mem.raw windows.pstree | grep -A2 dllhost
```

## Частые ошибки

- **Забыть `windows.info`** — без него плагины могут ругаться на символы.
- **Работать без сети и без локальных ISF** — символы не подгрузятся.
- **Верить `pslist`** — скрытые процессы только в `psscan`.
- **Не дампить регионы malfind** — нельзя проанализировать payload.
- **Игнорировать `--pid`** на больших дампах — очень медленно.
- **Забывать про versioned-плагины** (Windows 10/11 vs старые).

## Что дальше / решение

Конвейер: `windows.info` → `pslist`/`psscan` → `netscan`/`cmdline` → `malfind`/`vadinfo` → дамп → YARA/анализ. Связка: `forensics-memory` (основы), `forensics-memory-injection` (инъекции), `forensics-memory-keys` (ключи), `forensics-malware-yara` (сигнатуры).

## Символы, ISF и офлайн-работа

Volatility 3 использует **ISF**-файлы (JSON с определениями структур ОС). Для Windows они именуются по build (например, `windows.10.0.19041.x64.json.zip`) и автоматически скачиваются с symbol-сервера. В изолированной среде их нужно предварительно скачать.

```bash
# указать каталог символов
$ vol -f mem.raw --symbol-dirs ./symbols windows.pslist
# offline: скачать символы заранее (на машине с сетью) и перенести
$ ls symbols/windows/
# кэш символов
$ ls ~/.cache/volatility3/symbols/
```

Если символов нет и сети нет — плагины, требующие структур ядра, не отработают. Поэтому при подготовке к офлайн-анализу скачивайте ISF заранее.

## Кастомные плагины

Volatility 3 позволяет писать плагины на Python: класс наследует `PluginInterface`, объявляет `requirements`, реализует `run()`. Это нужно для задач под конкретное расследование (например, поиск структуры в пуле).

```python
from volatility3.framework import interfaces, renderers, contexts
from volatility3.framework.configuration import requirements

class MyPlugin(interfaces.plugins.PluginInterface):
    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name='primary'),
                requirements.SymbolTableRequirement(name='vmem')]
    def run(self):
        layer = self.context.layers[self.config['primary']]
        yield renderers.TreeGrid([("Addr", int)], [(0x1000,)])
```

```bash
$ vol -f mem.raw myplugin.MyPlugin
```

## Работа со сложными дампами

- **Неверно определён профиль**: задайте `--single-location` или укажите слой явно.
- **Большие дампы**: используйте `--pid` и конкретные плагины, кэшируйте результат в файл.
- **Повреждённый/обрезанный дамп**: `windows.info` покажет, распознан ли kernel; иначе нужен `kdbgscan`.
- **Linux-дампы**: `banners.Banners`, затем `linux.pslist` (символы из `/proc/kallsyms` или BTF).
- **macOS**: `mac.pslist`, `mac.netstat`.

```bash
$ vol -f mem.raw banners.Banners
$ vol -f mem.raw linux.pslist --pid 1
$ vol -f mem.raw windows.psscan --pid 4120
```

## Оптимизация и воспроизводимость

Сохраняйте вывод плагинов в файлы (`> out.txt`) для отчёта и повторного анализа. Для больших дампов запускайте несколько плагинов с `--parallel` (если поддерживается) или последовательно, фиксируя команды. Всегда записывайте версию Volatility и хеш дампа — воспроизводимость критична для доказательств.

## Квиз

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
    - "`yarascan.YaraScan`"
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
- question: "Что даёт `windows.vadinfo --dump`?"
  options:
    - "сеть"
    - "дамп VAD-региона (полезно для инъекций)"
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

## Где пригодится

- **CTF:** сложные задачи с дампами памяти.
- **Incident Response:** глубокая экспертиза памяти.
- **Malware analysis:** разбор инъекций и in-memory полезных нагрузок.
- **Threat Hunting:** поиск скрытых процессов/руткитов.
- **Разработка детектов:** кастомные плагины и сигнатуры.
