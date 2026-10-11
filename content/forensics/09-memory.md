---
id: forensics-memory
title: "Форензика памяти: Volatility"
category: forensics
parent: forensics-img-captures
difficulty: hard
order: 2
tags: [memory, volatility, ram-dump, processes, ctf]
prerequisites: [forensics-disk-images]
useful_for:
  - "CTF Forensics категория"
  - "Incident Response"
  - "Malware analysis"
estimated_minutes: 45
summary: "Анализ дампов оперативной памяти: профили, процессы, сеть, инъекции, пароли и извлечение артефактов через Volatility 3."
---

## Зачем память

Дамп оперативной памяти содержит то, чего нет на диске: запущенные процессы, сетевые соединения, расшифрованные данные, ключи шифрования, пароли, инжектированный код, командные строки. Для расследования malware (особенно fileless) память — **главный** источник. Формат дампа: raw (`.mem`, `.raw`), Windows crash dump, VMware `.vmem`, `lime`, `avml`.

## Volatility 3

Volatility 3 (Python) — стандарт. Отличие от V2: **не требует профилей** — символы (ISF) подгружаются автоматически из интернета или локального кэша.

```bash
pip install volatility3
vol -f memory.dmp windows.info
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.pstree
vol -f memory.dmp windows.netscan
vol -f memory.dmp windows.cmdline
```

## Ключевые плагины

| Плагин | Назначение |
|---|---|
| `windows.info` | версия ОС, время |
| `windows.pslist` | список процессов |
| `windows.psscan` | процессы (включая скрытые/завершённые) |
| `windows.pstree` | дерево процессов |
| `windows.cmdline` | командные строки |
| `windows.netscan` | сетевые соединения |
| `windows.dlllist` | загруженные DLL |
| `windows.malfind` | инъекции/шеллкоды |
| `windows.handles` | открытые handles |
| `windows.filescan` | файлы в кэше |
| `windows.registry.*` | реестр из памяти |
| `windows.hashdump` | хэши из SAM |
| `windows.lsadump` | LSA secrets |
| `windows.yarascan` | YARA-скан |

```bash
# Процессы и командные строки
vol -f mem.dmp windows.pstree
vol -f mem.dmp windows.cmdline | grep -iE 'powershell|cmd|wmic'
# Сеть
vol -f mem.dmp windows.netscan | grep -iE 'ESTABLISHED|LISTEN'
```

## Обнаружение инъекций

```bash
# malfind — ищет RWX-регионы, не привязанные к файлу (инъекции)
vol -f mem.dmp windows.malfind
# Дамп подозрительного процесса
vol -f mem.dmp windows.memmap --pid <pid> --dump
# YARA-скан памяти
vol -f mem.dmp windows.yarascan --yara-file rules.yar
```

`malfind` показывает VAD-регионы с `PAGE_EXECUTE_READWRITE` и подозрительным содержимым (MZ/шеллкод) — признак process injection/hollowing.

## Извлечение credentials

```bash
# Хэши из SAM (в памяти)
vol -f mem.dmp windows.hashdump
# LSA secrets
vol -f mem.dmp windows.lsadump
# Кэш (кэшированные доменные учётки)
vol -f mem.dmp windows.cachedump
# Поиск паролей в памяти (строки)
strings mem.dmp | grep -iE 'password|passwd|pwd=' | head
# pypykatz для LSASS
pypykatz lsa minidump lsass.dmp
```

## Извлечение артефактов

```bash
# Список файлов в кэше
vol -f mem.dmp windows.filescan | grep -i flag
# Дамп файла по offset
vol -f mem.dmp windows.dumpfiles --virtaddr <addr>
# Реестр
vol -f mem.dmp windows.registry.hivelist
vol -f mem.dmp windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
# Скриншоты (V2: screenshots)
vol -f mem.dmp windows.screenshot   # если есть
```

## Практический пример: CTF-разбор

```bash
# 1. Идентификация
vol -f mem.dmp windows.info
# 2. Процессы
vol -f mem.dmp windows.pstree
# 3. Подозрительные (malfind)
vol -f mem.dmp windows.malfind
# 4. Командные строки
vol -f mem.dmp windows.cmdline
# 5. Поиск флага
vol -f mem.dmp windows.filescan | grep -i flag
vol -f mem.dmp windows.dumpfiles --virtaddr <addr>
strings -a mem.dmp | grep -iE 'flag\{|CTF\{'
# 6. Сеть
vol -f mem.dmp windows.netscan
```

## Инструменты и команды

```bash
pip install volatility3
# Символы: автоматически (кэш ~/.cache/volatility3)
# Альтернативы: Rekall, MemProcFS, winpmem (снятие)
# pypykatz — LSASS
```

## Дополнительные плагины и таймлайн

Volatility 3 предоставляет десятки плагинов. Полезные помимо базовых:

| Плагин | Назначение |
|---|---|
| `windows.modules` | загруженные драйверы (rootkit?) |
| `windows.driverscan` | драйверы (включая скрытые) |
| `windows.ssdt` | таблица системных вызовов (хуки) |
| `windows.callbacks` | kernel callbacks (persistence) |
| `windows.mutantscan` | мьютексы (признак malware) |
| `windows.svcscan` | службы |
| `windows.scheduled_tasks` | задачи |
| `windows.registry.userassist` | UserAssist |
| `windows.timeliner` | таймлайн событий |

```bash
vol -f mem.dmp windows.modules | grep -v "\\Windows\\System32"
vol -f mem.dmp windows.callbacks
vol -f mem.dmp windows.svcscan | grep -iE 'temp|tmp|appdata'
vol -f mem.dmp timeliner.Timeliner > timeline.csv
```

## Снятие дампа памяти

- **Windows:** `winpmem`, `DumpIt`, `Magnet RAM Capture` (пишут в файл).
- **Linux:** `lime`, `avml`, `dd if=/dev/mem` (осторожно).
- **VMware/Hyper-V:** снапшот + `.vmem`/`.vmss`.
- **Облако:** через агент/SSM.

Важно: снимать **до** выключения; учитывать, что память меняется (лучше — на замороженной ВМ).

## Инструменты и команды

```bash
pip install volatility3
vol -f memory.dmp windows.info
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.pstree
vol -f memory.dmp windows.psscan
vol -f memory.dmp windows.cmdline
vol -f memory.dmp windows.netscan
vol -f memory.dmp windows.malfind
vol -f memory.dmp windows.hashdump
vol -f memory.dmp windows.lsadump
vol -f memory.dmp windows.filescan | grep -i flag
vol -f memory.dmp windows.dumpfiles --virtaddr <addr>
vol -f memory.dmp windows.yarascan --yara-file rules.yar
vol -f memory.dmp timeliner.Timeliner > timeline.csv
strings -a memory.dmp | grep -iE 'flag\{|CTF\{'
pypykatz lsa minidump lsass.dmp
```

## Практический пример: разбор malware

```bash
# 1. Подозрительный процесс
vol -f mem.dmp windows.pstree | grep -iE 'temp|appdata|svchost'
# 2. Инъекции
vol -f mem.dmp windows.malfind --pid <pid>
# 3. Дамп процесса
vol -f mem.dmp windows.memmap --pid <pid> --dump
# 4. Анализ дампа (strings/YARA/Disassembly)
strings pid.<pid>.dmp | grep -iE 'http|cmd|powershell'
yara rules.yar pid.<pid>.dmp
# 5. Сеть
vol -f mem.dmp windows.netscan | grep <pid>
# 6. Persistence
vol -f mem.dmp windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

## Типы дампов и их особенности

- **Raw (`.raw`, `.mem`)** — прямой дамп физической памяти; самый распространённый.
- **Windows crash dump** (`.dmp`) — может быть полным или малым.
- **Hibernation** (`hiberfil.sys`) — сжатый дамп памяти (Volatility умеет).
- **VMware** (`.vmem`, `.vmss`), **Hyper-V** (`.bin`), **QEMU** (`.el`).
- **LiME** (Linux), **AVML** (Microsoft, Linux).
- **Pagefile/swap** — фрагменты памяти на диске.

Разные форматы требуют разных параметров; `file`/`capinfos` помогают определить. Для hiberfil нужно указать `--profile`/адрес в V2 или просто подать в V3.

## Итог

Дамп памяти — ключ к fileless-малвари, инъекциям и credential. Volatility 3 (без профилей) + `pstree`/`cmdline`/`netscan`/`malfind`/`hashdump`/`filescan` покрывают 90% задач. Снимайте память до выключения; дампьте подозрительные процессы; используйте YARA и strings. Комбинируйте с дисковыми артефактами.

## Резюме

Volatility 3 без профилей: `info` → `pstree` → `malfind` → `cmdline` → `netscan` → `hashdump` → `filescan`/`dumpfiles` → YARA/strings. Память — ключ к fileless и credential.

## Частые ошибки

- **Неверный формат дампа.** Volatility не распознает — проверьте `file`.
- **Пропустить `psscan`.** `pslist` не видит скрытые процессы.
- **Игнорировать `malfind`.** Инъекции — ключ к malware.
- **Не дампить подозрительные процессы.**
- **Искать флаг только `strings`.** Используйте filescan/dumpfiles.
- **Не проверить credentials.** hashdump/lsadump.

## Как не застрять

- **`windows.info`** — версия.
- **`pstree` + `cmdline`** — что запущено.
- **`malfind`** — инъекции.
- **`netscan`** — C2.
- **`filescan`/`dumpfiles`** — файлы.
- **`strings` + YARA** — флаг/malware.

## Квиз

```quiz
- question: "Что делает плагин malfind?"
  options:
    - "ищет инъекции (RWX-регионы, не привязанные к файлу)"
    - "снимает дамп памяти"
    - "строит таймлайн"
    - "декодирует base64"
  answer: 0
- question: "Чем psscan отличается от pslist?"
  options:
    - "ничем"
    - "psscan находит скрытые/завершённые процессы"
    - "psscan медленнее"
    - "pslist — для Linux"
  answer: 1
- question: "Где взять хэши паролей из памяти?"
  options:
    - "hashdump"
    - "netscan"
    - "malfind"
    - "filescan"
  answer: 0
- question: "Как извлечь файл из кэша памяти?"
  options:
    - "filescan + dumpfiles"
    - "pstree"
    - "netscan"
    - "cmdline"
  answer: 0
- question: "Volatility 3 в отличие от V2:"
  options:
    - "требует профиль"
    - "не требует профилей (авто-символы)"
    - "только Linux"
    - "без плагинов"
  answer: 1
```

## Где пригодится

- **CTF Forensics** — задачи с дампами RAM.
- **Incident Response** — анализ malware в памяти.
- **Malware analysis** — fileless, инъекции.
- **Credential access** — хэши/пароли.
- **Threat Hunting** — поиск следов в памяти.
