---
id: forensics-memory-symbols
title: "Символы Volatility3: ISF, профили и kernel debug"
category: forensics
parent: forensics-memory-advanced
difficulty: expert
order: 1
tags: [volatility3, symbols, isf, linux, windows, kernel, debug]
prerequisites: [forensics-memory-advanced]
useful_for:
  - "CTF Forensics категория"
  - "Memory Forensics"
  - "Incident Response"
estimated_minutes: 50
summary: "Работа с символами Volatility3: Intermediate Symbol Format (ISF), автоматическая загрузка, генерация профилей для Linux/Windows, диагностика ошибок и kernel debug."
---

Volatility3 не хранит «зашитые» профили — она читает **symbol tables** в формате ISF (Intermediate Symbol Format). Символы описывают смещения полей структур ядра: без них плагины не знают, где в памяти лежит список процессов или таблица страниц. Понимание символов — разница между «плагин не работает» и успешным анализом.

## Что такое ISF

ISF — JSON-описание типов и символов конкретного ядра: имена, размеры, смещения полей. Для каждой версии ядра — свой файл. Volatility3 подгружает их автоматически из `volatility3/symbols/<os>/<version>.json`.

```bash
# Посмотреть, какие символы есть локально
ls ~/.local/lib/python3.*/site-packages/volatility3/symbols/ 2>/dev/null
vol -f memory.raw banners          # определить ОС и версию ядра
vol -f memory.raw isfinfo          # какая symbol table нужна
```

`banners` показывает, что за ОС/ядро в дампе; `isfinfo` — какой файл символов требуется.

## Автоматическая загрузка

По умолчанию Volatility3 пытается скачать нужные ISF из интернета. В изолированной среде загрузка не работает — символы нужно положить вручную.

```bash
# Задать каталог символов
vol -f memory.raw --symbol-dirs ./symbols banners
# Или через конфиг
# ~/.volatility3rc / volatility3.conf: symbols_paths
# Скачать символы для Windows (пакет от Volatility)
python3 -m volatility3.symbols --help 2>/dev/null
# Для Linux — сгенерировать из vmlinux/System.map
```

## Генерация символов для Linux

Linux-ядра не имеют готовых ISF «из коробки» для всех версий; их генерируют из отладочных символов или DWARF.

```bash
# Если есть vmlinux с DWARF
dwarf2json linux --elf /path/to/vmlinux > linux.json
# Если есть System.map + исходники
dwarf2json linux --system-map System.map --elf vmlinux > linux.json
# Положить в каталог символов с правильным именем
mkdir -p symbols/linux
cp linux.json symbols/linux/$(uname -r).json
```

`dwarf2json` — утилита из репозитория Volatility, собирающая ISF из ELF/DWARF или из `System.map`.

## Windows: PDB → ISF

Для Windows Volatility3 использует PDB-символы Microsoft через встроенный pdbconv. Если доступ в интернет есть, всё автоматически; иначе PDB скачивают заранее и конвертируют.

```bash
# pdbconv (внутри Volatility) конвертирует PDB в ISF
# Обычно достаточно положить PDB в кэш; Volatility найдёт его по GUID
vol -f memory.raw windows.info
```

`windows.info` покажет, найдены ли символы; если нет — плагины выдают ошибку о missing symbols.

## Диагностика ошибок символов

Типичные сообщения и что делать:

| Ошибка | Причина | Решение |
|--------|---------|---------|
| `Unable to validate the plugin requirements` | нет символов | положить ISF в `symbols/` |
| `Unsatisfied requirement: kernel.symbol_table_name` | не тот ISF | сверить версию ядра |
| `Symbol table not found for ...` | нет файла | сгенерировать/скачать |
| `Invalid symbol table` | повреждён ISF | пересоздать |

```bash
# Проверить версию ядра в дампе (Linux)
vol -f memory.raw banners
# Посмотреть, какой файл ищется
vol -vv -f memory.raw linux.pslist 2>&1 | grep -i symbol | head
```

## Kernel debug

Если символы не совпадают, помогает kernel debug: подключение к живому ядру или анализ через `crash`/`gdb`.

```bash
# GDB против ядра (если есть vmlinux и дамп)
gdb vmlinux
(gdb) target remote /dev/ttyS0   # или qemu-gdb
# crash-утилита для kdump
crash vmlinux vmcore
crash> bt        # backtrace
crash> ps        # процессы
```

Это полезно, когда нужно понять структуру ядра или проверить смещения вручную.

## Разобранный пример

```bash
$ vol -f linux.mem banners
Linux version 5.15.0-91-generic (buildd@lcy02) ...
$ vol -f linux.mem linux.pslist
Volatility 3 Framework ...
Unsatisfied requirement: kernel.symbol_table_name
$ # Генерируем символы
$ dwarf2json linux --system-map /boot/System.map-5.15.0-91-generic --elf /usr/lib/debug/boot/vmlinux-5.15.0-91-generic > 5.15.0-91.json
$ mkdir -p symbols/linux && cp 5.15.0-91.json symbols/linux/
$ vol -f linux.mem --symbol-dirs symbols linux.pslist | head
PID  PPID COMM
1    0    systemd
2    0    kthreadd
```

После подстановки символов плагины работают.

## Краевые случаи и подводные камни

- **Изолированная среда.** Автозагрузка символов не работает — готовьте ISF заранее.
- **Версия ядра.** Символы строго привязаны к версии; «похожая» не подойдёт.
- **KASLR.** Рандомизация адресов ядра компенсируется Volatility, но иногда требует указания базы.
- **DWARF отсутствует.** Без отладочных символов генерация ISF сложна; ищите `vmlinux`/`System.map`.
- **Windows PDB.** Нужен доступ к серверу Microsoft или предварительная загрузка.
- **Конфигурация.** `symbols_paths` в конфиге должен указывать на ваш каталог.
- **macOS.** Символы также требуются; используйте соответствующий генератор.

## Как Volatility находит символы

Volatility3 определяет ОС по «banner» в дампе, затем ищет соответствующий ISF. Поиск идёт в нескольких местах:

1. Встроенные символы пакета (если есть).
2. Каталог из конфига (`symbols_paths`).
3. Автозагрузка с сервера символов (если есть сеть).

```bash
# Где Volatility ищет символы
cat ~/.local/lib/python3*/site-packages/volatility3/framework/constants/__init__.py | grep -i symbol
# Конфигурация
cat /etc/volatility3.conf 2>/dev/null || cat ~/.volatility3rc 2>/dev/null
# Явно указать каталог
vol -f mem.raw --symbol-dirs ./symbols windows.info
```

Правильная раскладка: `symbols/<os>/<name>.json`, например `symbols/linux/5.15.0-91-generic.json` или `symbols/windows/ntkrnlmp.pdb/...`.

## Генерация ISF: подробнее

### Linux

```bash
# Вариант 1: из DWARF (vmlinux с отладкой)
dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-5.15.0-91-generic > out.json
# Вариант 2: System.map + vmlinux (без DWARF)
dwarf2json linux --system-map /boot/System.map-5.15.0-91-generic \
  --elf /boot/vmlinuz-5.15.0-91-generic > out.json
# Вариант 3: из BTF (если ядро собрано с CONFIG_DEBUG_INFO_BTF)
bpftool btf dump file /sys/kernel/btf/vmlinux format raw
```

`dwarf2json` — Go-утилита; собирается из репозитория Volatility. Если ядро без отладочных символов, ISF не сгенерировать точно — придётся искать `vmlinux` для этой версии.

### Windows

```bash
# Volatility3 использует pdbconv; PDB обычно скачивается автоматически.
# Для изолированной среды скачайте PDB заранее (symchk) и положите в кэш.
# Проверить, что символы найдены:
vol -f mem.raw windows.info | grep -i symbol
```

### macOS

```bash
# Символы из Kernel Debug Kit (KDK)
dwarf2json mac --elf /Library/Developer/KDKs/.../kernel > mac.json
```

## Проверка корректности символов

```bash
# Плагин, требующий символов, должен отработать
vol -f mem.raw windows.pslist | head
# Если ошибка — узнать требуемое имя таблицы
vol -vv -f mem.raw windows.pslist 2>&1 | grep -iE 'symbol|require' | head
# Проверить версию ядра в дампе
vol -f mem.raw banners
```

Расхождение версии ядра и символов — самая частая причина ошибок.

## Kernel debug как резервный путь

Когда ISF нет, можно анализировать через `crash` (для kdump) или `gdb`:

```bash
# crash с vmlinux и vmcore
crash /usr/lib/debug/boot/vmlinux-5.15.0-91-generic /var/crash/vmcore
crash> ps            # процессы
crash> files         # открытые файлы
crash> net           # сетевые структуры
crash> bt            # backtrace
# gdb с символами
gdb /usr/lib/debug/boot/vmlinux-5.15.0-91-generic
(gdb) info symbols
```

Это позволяет вручную найти нужные смещения и понять структуры.

## Частые проблемы и решения

| Проблема | Решение |
|----------|---------|
| Автозагрузка не работает | положить ISF локально, `--symbol-dirs` |
| Не та версия ядра | сгенерировать ISF из vmlinux/System.map |
| Нет DWARF | использовать System.map или BTF |
| Ошибка «unsatisfied requirement» | проверить `isfinfo`/`banners` |
| Медленная загрузка | локальный каталог символов |
| macOS | использовать KDK |

## Чек-лист настройки символов

1. `vol -f mem banners` — ОС и версия.
2. `vol -f mem isfinfo` — требуемый ISF.
3. Получить/сгенерировать ISF (`dwarf2json`/PDB/KDK).
4. Положить в `symbols/<os>/` или указать `--symbol-dirs`.
5. Проверить `windows.info`/`linux.pslist`.
6. При неудаче — `crash`/`gdb` для ручного анализа.

## Символы для распространённых дистрибутивов

- **Ubuntu/Debian** — пакет `linux-image-<ver>-dbgsym` содержит `vmlinux` с DWARF.
- **RHEL/CentOS** — `kernel-debuginfo` даёт отладочное ядро.
- **Arch** — `linux-debug` или BTF.
- **Windows** — PDB с сервера Microsoft (автозагрузка).
- **macOS** — Kernel Debug Kit (KDK) от Apple.

```bash
# Ubuntu: установить отладочное ядро
apt-get install linux-image-$(uname -r)-dbgsym
# Сгенерировать ISF
dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > $(uname -r).json
mkdir -p symbols/linux && cp $(uname -r).json symbols/linux/
```

## Проверка целостности дампа

Перед анализом полезно убедиться, что дамп не повреждён:

```bash
# Размер и хеш
ls -lh mem.raw; sha256sum mem.raw
# Volatility banners покажет, читается ли ядро
vol -f mem.raw banners
# Если плагины падают — возможно, дамп усечён или неверный формат (LiME/raw/crash)
```

Volatility3 поддерживает форматы: raw, LiME, ELF core, crash, VMware, VirtualBox. Неверное определение формата даёт «мусор».

## Хранение и обмен символами

- Храните ISF в репозитории/артефактах кейса.
- Для команды — общий каталог `symbols/`.
- Фиксируйте версию символов вместе с версией ядра.
- Не полагайтесь на автозагрузку в изолированных сетях.

## Итоговая шпаргалка

| ОС | Источник символов | Генератор |
|----|-------------------|-----------|
| Linux | vmlinux/System.map/BTF | dwarf2json |
| Windows | PDB (Microsoft) | pdbconv (встроен) |
| macOS | KDK | dwarf2json mac |

Без правильных символов ни один продвинутый плагин не заработает — это первый шаг анализа памяти.

## Что дальше / решение

1. `vol -f mem banners` — определить ОС/ядро.
2. `vol -f mem isfinfo` — узнать нужный ISF.
3. Получить/сгенерировать ISF (`dwarf2json` для Linux, PDB для Windows).
4. Положить в `symbols/<os>/` или указать `--symbol-dirs`.
5. Проверить `windows.info`/`linux.pslist`.

Дальше — `forensics-memory-malware` (охота) и `forensics-volatility-deep` (плагины).

## Квиз

```quiz
- question: "Что такое ISF в Volatility3?"
  options:
    - "формат образа памяти"
    - "Intermediate Symbol Format — описание символов ядра"
    - "правило YARA"
    - "тип дампа"
  answer: 1
  explanation: "ISF — JSON с типами/символами конкретного ядра."
- question: "Чем генерируют ISF для Linux?"
  options:
    - "vol -f"
    - "dwarf2json (из vmlinux/System.map)"
    - "strings"
    - "objdump"
  answer: 1
  explanation: "dwarf2json собирает ISF из DWARF/ELF или System.map."
- question: "Почему символы строго привязаны к версии ядра?"
  options:
    - "Они не привязаны"
    - "Смещения полей структур различаются между версиями"
    - "Так требует лицензия"
    - "Из-за размера файла"
  answer: 1
  explanation: "ISF описывает смещения полей; при смене версии они меняются."
- question: "Что делать в изолированной среде без интернета?"
  options:
    - "Volatility не заработает"
    - "Заранее подготовить ISF и указать --symbol-dirs"
    - "Отключить плагины"
    - "Использовать dd"
  answer: 1
  explanation: "Автозагрузка недоступна — символы кладут локально."
```

## Где пригодится

- **CTF:** дампы памяти без готовых символов.
- **Memory Forensics:** корректная настройка Volatility.
- **IR:** анализ нестандартных ядер.
- **Разработка:** генерация ISF и kernel debug.
