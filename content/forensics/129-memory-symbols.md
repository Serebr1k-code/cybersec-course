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

## Вопрос, с которого всё начинается

Вы запускаете `vol` на дампе памяти и получаете вместо списка процессов ошибку: `Unsatisfied requirement: kernel.symbol_table_name`. Инструмент на месте, дамп не пустой — а плагин не работает. В чём дело? Почти всегда — в отсутствии **символов**.

## Наш пример: дамп Linux, который «не читается»

Есть дамп `linux.mem`. Определяем, что за система внутри:

```bash
$ vol -f linux.mem banners
Linux version 5.15.0-91-generic (buildd@lcy02) ...
```

Это Linux 5.15.0-91-generic. Пробуем список процессов:

```bash
$ vol -f linux.mem linux.pslist
Volatility 3 Framework ...
Unsatisfied requirement: kernel.symbol_table_name
```

Ошибка означает: у Volatility3 нет описания структур этого конкретного ядра.

## Шаг 1: что такое ISF

Volatility3 не хранит «зашитые» профили. Вместо этого она читает **symbol tables** в формате **ISF** (Intermediate Symbol Format). ISF — это JSON-описание типов и символов конкретного ядра: имена, размеры, **смещения полей** структур.

Почему это важно: ядро — это структуры в памяти (список процессов, таблица страниц). Чтобы найти в них нужное поле, нужно знать его смещение от начала структуры. А смещения **различаются между версиями ядра** — поэтому для каждой версии нужен свой ISF-файл. «Похожая» версия не подойдёт.

Посмотрим, какой файл требуется:

```bash
$ vol -f linux.mem isfinfo
```

## Шаг 2: генерируем символы для Linux

Для Linux готовых ISF «из коробки» для всех версий нет — их генерируют утилитой `dwarf2json` из отладочной информации. Источники: `vmlinux` с **DWARF** (отладочные символы) или `System.map`:

```bash
$ dwarf2json linux \
    --system-map /boot/System.map-5.15.0-91-generic \
    --elf /usr/lib/debug/boot/vmlinux-5.15.0-91-generic > 5.15.0-91.json
```

Кладём файл в каталог символов с правильным именем и повторяем:

```bash
$ mkdir -p symbols/linux && cp 5.15.0-91.json symbols/linux/
$ vol -f linux.mem --symbol-dirs symbols linux.pslist | head
PID  PPID COMM
1    0    systemd
2    0    kthreadd
```

Плагин заработал. `dwarf2json` — Go-утилита из репозитория Volatility.

## Шаг 3: Windows и macOS

Для Windows Volatility3 использует **PDB**-символы Microsoft (через встроенный конвертер `pdbconv`). Если есть интернет, всё скачивается автоматически; в изолированной среде PDB готовят заранее:

```bash
$ vol -f mem.raw windows.info | grep -i symbol
```

`windows.info` покажет, найдены ли символы. Для macOS источник символов — **Kernel Debug Kit** (KDK) от Apple, конвертируется тем же `dwarf2json`.

## Шаг 4: диагностика ошибок

Типичные сообщения и что делать:

| Ошибка | Причина | Решение |
|--------|---------|---------|
| `Unsatisfied requirement: kernel.symbol_table_name` | нет символов | положить ISF в `symbols/` |
| `Symbol table not found for ...` | нет файла | сгенерировать/скачать |
| `Invalid symbol table` | повреждён ISF | пересоздать |

Volatility3 ищет символы в трёх местах: встроенные, каталог из конфига (`symbols_paths`), автозагрузка из сети. Правильная раскладка — `symbols/<os>/<name>.json`, например `symbols/linux/5.15.0-91-generic.json`.

```bash
$ vol -f linux.mem --symbol-dirs ./symbols banners
$ vol -vv -f linux.mem linux.pslist 2>&1 | grep -iE 'symbol|require' | head
```

## Шаг 5: kernel debug как резервный путь

Если ISF получить не удаётся, помогает прямой анализ ядра утилитой `crash` (для дампов kdump) или `gdb`:

```bash
$ crash /usr/lib/debug/boot/vmlinux-5.15.0-91-generic /var/crash/vmcore
crash> ps        # процессы
crash> files     # открытые файлы
crash> bt        # backtrace
```

Это позволяет вручную найти нужные смещения и понять структуры, когда готового ISF нет.

## Что мы теперь знаем

- **ISF** — JSON-описание символов конкретного ядра; без него плагины не работают.
- Символы строго привязаны к **версии ядра**: смещения полей структур различаются.
- Для Linux ISF генерируют `dwarf2json` из `vmlinux`/`System.map`/BTF.
- Для Windows источник — PDB Microsoft; для macOS — Kernel Debug Kit.
- В изолированной среде автозагрузка недоступна — символы кладут локально и указывают `--symbol-dirs`.
- Резервный путь — kernel debug через `crash`/`gdb`.

## Частые проблемы и решения

| Проблема | Решение |
|----------|---------|
| Автозагрузка не работает | положить ISF локально, `--symbol-dirs` |
| Не та версия ядра | сгенерировать ISF из vmlinux/System.map |
| Нет DWARF | использовать System.map или BTF |
| Ошибка «unsatisfied requirement» | проверить `isfinfo`/`banners` |
| Медленная загрузка | локальный каталог символов |

Откуда брать символы для популярных систем: Ubuntu/Debian — пакет `linux-image-<ver>-dbgsym` (содержит `vmlinux` с DWARF); RHEL/CentOS — `kernel-debuginfo`; Arch — `linux-debug` или BTF. Если ядро собрано с `CONFIG_DEBUG_INFO_BTF`, ISF можно собрать из BTF.

Перед анализом полезно проверить и сам дамп: `vol -f mem.raw banners` покажет, читается ли ядро. Volatility3 поддерживает форматы raw, LiME, ELF core, crash, VMware, VirtualBox — неверное определение формата даёт «мусор». Храните ISF в репозитории/артефактах кейса вместе с версией ядра и не полагайтесь на автозагрузку в изолированных сетях.

## Квиз

Проверь себя.

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
- question: "Какой источник символов используется для Windows?"
  options:
    - "PDB с сервера Microsoft"
    - "Kernel Debug Kit"
    - "System.map"
    - "DWARF из vmlinux"
  answer: 0
  explanation: "Volatility3 конвертирует PDB Microsoft через встроенный pdbconv."
```

## Куда дальше

Теперь плагины работают, и можно перейти к охоте на малварь (`forensics-memory-malware`) — malfind, yarascan и поиск скрытых процессов. А пока главное запомни: **без правильных символов ISF ни один продвинутый плагин Volatility3 не заработает — это первый шаг анализа памяти**.

## Где пригодится

- **CTF:** дампы памяти без готовых символов.
- **Memory Forensics:** корректная настройка Volatility.
- **IR:** анализ нестандартных ядер.
- **Разработка:** генерация ISF и kernel debug.
