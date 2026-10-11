---
id: forensics-memory-injection
title: "Инъекции в память и руткиты: malfind, VAD, детект"
category: forensics
parent: forensics-volatility-deep
difficulty: expert
order: 2
tags: [memory, malfind, injection, rootkit, vad, hollowing, volatility]
prerequisites: [forensics-volatility-deep]
useful_for:
  - "CTF Forensics категория"
  - "Malware analysis (in-memory)"
  - "Incident Response"
estimated_minutes: 60
summary: "Обнаружение инъекций в память: process hollowing, DLL injection, reflective loading, shellcode; анализ VAD, malfind, скрытых потоков, руткитов и kernel-модификаций в Volatility 3."
---
Инъекция в память — продвинутая техника, позволяющая исполнять код без файла на диске. Атакующий «вживляет» payload в чужой процесс (process hollowing, DLL injection, reflective loading), и обнаружить это можно только анализом памяти. Этот урок — про механизмы инъекций, их артефакты в VAD и `malfind`, скрытые потоки и модификации ядра.

## Механизмы инъекций

| Техника | Суть | Артефакт |
|---------|------|----------|
| Process hollowing | запуск легитимного процесса, замена его образа на payload | пустой/подменённый образ, RWX-регион |
| DLL injection | `CreateRemoteThread` + `LoadLibrary` | необычная DLL, поток в чужом процессе |
| Reflective loading | ручной маппинг PE без загрузчика | регион с PE-заголовком, нет записи в списке модулей |
| Process doppelgänging | транзакция NTFS + создание процесса | нет файла, аномальные handles |
| AtomBombing | инъекция через таблицу атомов | аномальные атомы |
| Thread hijacking | перехват существующего потока | изменённый контекст потока |

Общий признак — **исполняемый регион с содержимым, не привязанным к файлу на диске**.

## Обнаружение: VAD и malfind

VAD описывает регионы памяти. Инъекции видны как регионы `PAGE_EXECUTE_READWRITE` (RWX) с «бесхозным» содержимым.

```bash
$ vol -f mem.raw windows.malfind
PID    Process   Start       End         Tag  Protection           Type
4120   rundll32  0x400000    0x460000    VadS PAGE_EXECUTE_READWRITE Mapped
$ vol -f mem.raw windows.malfind --pid 4120
$ vol -f mem.raw windows.vadinfo --pid 4120
$ vol -f mem.raw windows.vadwalk
```

`malfind` ищет комбинацию RWX-защиты и признаков PE/shellcode. Ложные срабатывания бывают (JIT-движки), поэтому проверяйте содержимое.

```bash
# дамп подозрительного региона
$ vol -f mem.raw windows.malfind --pid 4120 --dump
$ file pid.4120.dmp
$ xxd -l 64 pid.4120.dmp        # проверка MZ-заголовка
```

## Reflective loading

Reflective DLL загружается вручную: в памяти есть PE-структура, но модуля нет в списке (`windows.dlllist` не покажет). Признаки: PE-заголовок (`MZ`/`PE\0\0`) в heap/anon-регионе, отсутствие записи в PEB.

```bash
$ vol -f mem.raw windows.dlllist --pid 4120 | head
$ vol -f mem.raw windows.malfind --pid 4120 | grep -i 'MZ'
# найти PE-заголовки в анонимных регионах
$ vol -f mem.raw windows.yarascan --yara-rules 'rule mz { strings: $a={4D 5A} condition: uint16(0)==0x5A4D }'
```

## Process hollowing

При hollowing легитимный процесс запущен в suspended-состоянии, его образ выгружен (`NtUnmapViewOfSection`), а вместо него записан payload и возобновлён поток. Артефакты: базовый образ процесса не соответствует файлу на диске, несовпадение размера, RWX-регион по ImageBase.

```bash
# сравнить образ процесса с файлом на диске
$ vol -f mem.raw windows.pslist --pid 4120
$ vol -f mem.raw windows.dumpfiles --pid 4120
$ vol -f mem.raw windows.memmap --pid 4120 --dump
# несоответствие: путь exe, но содержимое другое
```

## Скрытые потоки и руткиты

```bash
$ vol -f mem.raw windows.threads --pid 4120
$ vol -f mem.raw windows.threads --pid 4120 | grep -i 'start'
# сравнить потоки через cross-view
$ vol -f mem.raw windows.threads > a.txt
$ vol -f mem.raw windows.threads --pid 4120 > b.txt
```

Kernel-модификации: `windows.ssdt` (таблица системных вызовов), `windows.callbacks` (уведомления ядра), `windows.driverirp`, `windows.modules` vs `windows.modscan` (скрытые драйверы).

```bash
$ vol -f mem.raw windows.ssdt
$ vol -f mem.raw windows.callbacks
$ vol -f mem.raw windows.modules > m1.txt
$ vol -f mem.raw windows.modscan > m2.txt
$ comm -13 <(sort m1.txt) <(sort m2.txt)      # скрытые драйверы
```

## Shellcode и YARA

```bash
# YARA по памяти (искать сигнатуры C2/shellcode)
$ vol -f mem.raw windows.yarascan --yara-file=shellcode.yar
# эвристика shellcode: последовательности с call/pop
$ vol -f mem.raw windows.malfind | grep -iE 'PAGE_EXECUTE'
```

## Разобранный пример

Дан `mem.raw`. Подозрение на hollowing `explorer.exe`.

```bash
# 1. Инъекция
$ vol -f mem.raw windows.malfind --pid 2048
PID  Process   Start      End        Protection
2048 explorer  0x400000   0x4a0000   PAGE_EXECUTE_READWRITE
# 2. Скрытый поток?
$ vol -f mem.raw windows.threads --pid 2048 | tail
# 3. Дамп и тип
$ vol -f mem.raw windows.malfind --pid 2048 --dump
$ file pid.2048.dmp
pid.2048.dmp: PE32+ executable (DLL)
# 4. YARA
$ yara beacon.yar pid.2048.dmp
beacon pid.2048.dmp
# 5. Сеть
$ vol -f mem.raw windows.netscan | grep 2048
```

Итог: `explorer.exe` содержит RWX-регион с PE, совпадающий с сигнатурой beacon — reflective loading.

## Справочная таблица

| Задача | Плагин |
|--------|--------|
| Инъекции | `windows.malfind` |
| Регионы памяти | `windows.vadinfo`, `windows.vadwalk` |
| Дамп региона | `windows.memmap --dump` |
| Потоки | `windows.threads` |
| Скрытые драйверы | `windows.modscan` vs `windows.modules` |
| SSDT | `windows.ssdt` |
| Колбэки | `windows.callbacks` |
| YARA | `windows.yarascan` |

## Частые ошибки

- **Верить RWX = инъекция** — JIT/легитимные регионы дают ложные срабатывания.
- **Не дампить регион** — нельзя проверить содержимое.
- **Игнорировать `modscan`** — скрытые драйверы не в `modules`.
- **Смотреть только `malfind`** — hollowing виден и по несоответствию образа.
- **Забывать про cross-view** (список vs скан).
- **Анализировать без символов** — часть плагинов не отработает.

## Что дальше / решение

Конвейер: `malfind`/`vadinfo` (инъекции) → дамп региона → `file`/YARA (payload) → `threads`/`ssdt`/`modscan` (руткиты) → `netscan` (C2). Связка: `forensics-volatility-deep` (плагины), `forensics-memory` (основы), `forensics-malware-yara` (сигнатуры), `forensics-fileless` (in-memory).

## Инструменты атакующего (для понимания артефактов)

Знание инструментов помогает предсказывать следы:

| Инструмент | Техника | Артефакт |
|-----------|---------|----------|
| Cobalt Strike | Beacon reflective DLL | RWX-регион, named pipes |
| Metasploit | `migrate` (injection) | поток в чужом процессе |
| `Invoke-ReflectivePEInjection` | reflective load | PE в anon-регионе |
| `ProcessHacker` | hollowing | несоответствие образа |
| `psexec` | service + injection | служба `PSEXESVC` |
| `dllinject`/`injector` | `CreateRemoteThread` | необычная DLL |

Cobalt Strike оставляет характерные **named pipes** (`msagent_*`, `mojo_*`, `postex_*`) и watermark; Metasploit — mutex `Msf`/`meterpreter`. Проверяйте `windows.handles`/`windows.mutantscan`.

```bash
$ vol -f mem.raw windows.mutantscan | grep -iE 'Msf|meterpreter|cobalt|mojo'
$ vol -f mem.raw windows.handles --pid 4120 | grep -i 'pipe'
```

## Автоматизация детекта

Для повторяющегося анализа инъекций автоматизируйте проверки:

```bash
# сводка по всем подозрительным регионам
$ vol -f mem.raw windows.malfind > malfind.txt
$ awk '/PAGE_EXECUTE_READWRITE/{print $1,$2}' malfind.txt | sort -u
# процессы с RWX и сетью
$ vol -f mem.raw windows.netscan | awk '$6=="ESTABLISHED"{print $2}' | sort -u > net_pids.txt
$ awk '{print $1}' malfind.txt | sort -u > rwx_pids.txt
$ comm -12 net_pids.txt rwx_pids.txt        # пересечение = приоритет
```

Сочетание «RWX-регион + исходящее соединение + подозрительный родитель» — сильный индикатор компрометации. Сохраняйте вывод для отчёта и повторного анализа.

## Сравнение источников (cross-view)

Единый принцип: любая техника сокрытия ломается при сравнении двух представлений.

- `pslist` vs `psscan` — скрытые процессы.
- `modules` vs `modscan` — скрытые драйверы.
- `threads` vs скан — скрытые потоки.
- Список DLL vs PE-регионы — reflective loading.
- `ssdt`/`callbacks` — перехваты в ядре.

## Ограничения

Не всякий RWX-регион — инъекция (JIT, .NET, упакованные приложения). Проверяйте содержимое (PE-заголовок, shellcode-паттерны), коррелируйте с сетью и поведением. На 64-битных системах и Windows 10/11 структуры отличаются — используйте правильные символы.

## Квиз

```quiz
- question: "Что ищет `windows.malfind`?"
  options:
    - "загруженные DLL"
    - "PE-заголовки в исполняемых регионах, которых нет в списке модулей"
    - "открытые сокеты"
    - "записи реестра"
  answer: 1
- question: "Какой набор флагов `ldrmodules` указывает на рефлективную загрузку DLL?"
  options:
    - "True True True"
    - "False False True (или все False)"
    - "True False True"
    - "False True True"
  answer: 1
- question: "Какая защита VAD-региона наиболее подозрительна?"
  options:
    - "PAGE_READONLY"
    - "PAGE_EXECUTE_READWRITE"
    - "PAGE_NOACCESS"
    - "PAGE_READWRITE"
  answer: 1
- question: "Зачем сравнивать `pslist` и `psscan`?"
  options:
    - "для поиска скрытых руткитом процессов"
    - "для подсчёта потоков"
    - "для поиска DLL"
    - "для дампа памяти"
  answer: 0
- question: "Что показывает `windows.ssdt`?"
  options:
    - "открытые файлы"
    - "таблицу системных вызовов (патчи руткитов)"
    - "сетевые соединения"
    - "реестр"
  answer: 1
```

## Где пригодится

- **CTF:** дампы памяти с инъекциями и руткитами.
- **Malware analysis:** разбор in-memory полезных нагрузок.
- **Incident Response:** обнаружение бесфайлового malware.
- **Threat Hunting:** охота за скрытыми процессами и kernel-хуками.
- **Разработка детектов:** правила на RWX-приватную память и reflective load.
