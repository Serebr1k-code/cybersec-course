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
lab:
  kind: shell
  title: 'Практика: malfind и извлечение shellcode'
  toolset: [core, hex, python3, volatility]
  workdir: /home/student/task
  files: [task.md, mem.raw, malfind_carve.py]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Найди подозрительный процесс: `vol -f mem.raw windows.malfind`.'
    - 'Ищи в дампе заголовок PE: `python3 malfind_carve.py`.'
    - 'Скрипт карит инъецированный регион в `shellcode.bin`.'
    - 'Флаг — строка `nto{…}` внутри вырезанного региона; запиши её в `found.txt`.'
---

## Вопрос, с которого всё начинается

Вредоносного файла на диске нет. Антивирус чист. Но машина явно что-то делает:
идёт трафик на незнакомый адрес. Как такое возможно?

Возможно, если код вообще **не лежит на диске**, а живёт только в оперативной памяти.
Атакующий «вживляет» свою полезную нагрузку в чужой легитимный процесс — например,
в `explorer.exe` — и оттуда исполняет. Такой подход называется **инъекцией в память**.

В этом уроке мы разберём дамп памяти `mem.raw`, найдём в нём инъекцию и поймём, как
она выглядит.

## Шаг 1: как код попадает в чужой процесс

Есть несколько техник. Все они сводятся к одному: в адресном пространстве
легитимного процесса появляется **исполняемая область с кодом, которого нет на
диске**.

| Техника | Суть |
|---------|------|
| Process hollowing | запускают легитимный процесс, выгружают его код и подменяют payload-ом |
| DLL injection | заставляют процесс загрузить чужую DLL через удалённый поток |
| Reflective loading | вручную «маппят» PE-файл в память без загрузчика Windows |
| Process doppelgänging | создают процесс из NTFS-транзакции, минуя файл |

## Шаг 2: VAD — карта памяти процесса

Windows описывает регионы памяти процесса структурой **VAD** (Virtual Address
Descriptor). Каждый регион имеет **protection** — права доступа. Нормальный код
обычно лежит в `PAGE_EXECUTE_READ` (читать и исполнять). Подозрительно, когда регион
имеет `PAGE_EXECUTE_READWRITE` (RWX) — то есть и читать, и писать, и исполнять. Такой
набор нужен, чтобы код мог себя модифицировать, и в легитимных программах он редок.

Смотрим карту памяти подозрительного процесса через Volatility:

```bash
$ vol -f mem.raw windows.vadinfo --pid 4120
PID    Process   Start       End         Protection           Tag
4120   rundll32  0x400000    0x460000    PAGE_EXECUTE_READWRITE VadS
```

`rundll32.exe` — легитимная системная утилита, но RWX-регион размером 384 КиБ у неё
подозрителен. Проверим содержимое.

## Шаг 3: malfind — ищем инъекции

Плагин `malfind` автоматически ищет комбинацию RWX-защиты и признаков PE-файла или
shellcode:

```bash
$ vol -f mem.raw windows.malfind
PID    Process   Start       End         Protection            Type
4120   rundll32  0x400000    0x460000    PAGE_EXECUTE_READWRITE Mapped
```

`malfind` — это первый фильтр, а не приговор: JIT-движки (например, .NET или
JavaScript) тоже создают RWX-регионы. Поэтому подозрительный регион **дампят** и
смотрят на содержимое:

```bash
$ vol -f mem.raw windows.malfind --pid 4120 --dump
$ file pid.4120.dmp
pid.4120.dmp: PE32+ executable (DLL)
$ xxd -l 64 pid.4120.dmp
00000000: 4d5a 9000 ...              MZ......
```

`MZ` в начале — заголовок PE-файла. То есть в памяти `rundll32.exe` лежит
исполняемый PE, которого нет среди загруженных модулей.

## Шаг 4: reflective loading — модуль, которого «нет»

При **reflective loading** DLL загружается вручную, и Windows не знает о ней: её нет
в списке модулей процесса. Сравниваем список загруженных DLL с тем, что реально лежит
в памяти:

```bash
$ vol -f mem.raw windows.dlllist --pid 4120 | head
# в списке нет подозрительной DLL
$ vol -f mem.raw windows.ldrmodules --pid 4120
# у аномальной DLL все три флага (InLoad/InInit/InMem) = False/True вразнобой
```

Если PE есть в памяти, но отсутствует в списке загрузчика, — это reflective load.

## Шаг 5: process hollowing

При **hollowing** процесс запускают приостановленным, выгружают его настоящий код и
записывают вместо него payload. Признак: базовый образ процесса не совпадает с
файлом на диске. Сравниваем:

```bash
$ vol -f mem.raw windows.pslist --pid 2048
$ vol -f mem.raw windows.memmap --pid 2048 --dump
$ file pid.2048.dmp
pid.2048.dmp: PE32+ executable (GUI)
```

Если процесс называется `explorer.exe`, а по адресу его образа лежит совсем другой
PE — это hollowing.

## Шаг 6: руткиты — скрытые потоки и драйверы

Руткит прячет не файлы, а **объекты**: процессы, потоки, драйверы. Против него
работает приём **cross-view** — сравнение двух способов перечисления одного и того же:

```bash
# скрытые процессы: список (pslist) vs сканирование памяти (psscan)
$ vol -f mem.raw windows.pslist > a.txt
$ vol -f mem.raw windows.psscan > b.txt
$ comm -13 <(sort a.txt) <(sort b.txt)      # есть в памяти, но не в списке

# скрытые драйверы: modules vs modscan
$ vol -f mem.raw windows.modules > m1.txt
$ vol -f mem.raw windows.modscan > m2.txt
$ comm -13 <(sort m1.txt) <(sort m2.txt)
```

Ещё руткит может править **SSDT** (таблицу системных вызовов) и уведомления ядра:

```bash
$ vol -f mem.raw windows.ssdt
$ vol -f mem.raw windows.callbacks
```

## Шаг 7: кто в памяти — сигнатуры инструментов

Зная инструменты атакующего, легче узнавать следы. Cobalt Strike оставляет
характерные именованные каналы (named pipes) `msagent_*`, `mojo_*`; Metasploit —
мьютексы `Msf`/`meterpreter`:

```bash
$ vol -f mem.raw windows.mutantscan | grep -iE 'Msf|meterpreter|cobalt|mojo'
$ vol -f mem.raw windows.handles --pid 4120 | grep -i pipe
```

Найденный мьютекс сразу выдаёт семейство.

## Шаг 8: автоматизируем детект

При повторяющемся анализе удобно автоматизировать проверки. Соберём список процессов
с RWX-регионами и пересечём его с процессами, у которых есть сетевые соединения, —
такое сочетание самый сильный признак компрометации:

```bash
$ vol -f mem.raw windows.malfind > malfind.txt
$ awk '/PAGE_EXECUTE_READWRITE/{print $1}' malfind.txt | sort -u > rwx_pids.txt
$ vol -f mem.raw windows.netscan | awk '$6=="ESTABLISHED"{print $2}' | sort -u > net_pids.txt
$ comm -12 rwx_pids.txt net_pids.txt      # пересечение = приоритет
```

Процесс, который и держит исполняемый код «ниоткуда», и стучится наружу, — почти
наверняка инъекция. Сохраняйте вывод: он пригодится в отчёте и при повторном разборе.

## Шаг 9: ограничения

Не всякий RWX-регион — инъекция. JIT-компиляторы, .NET и упакованные приложения тоже
создают исполняемую память. Поэтому всегда проверяйте содержимое (PE-заголовок,
shellcode-паттерны) и коррелируйте с сетью и поведением. На 64-битных системах и
Windows 10/11 структуры памяти отличаются — используйте правильные **символы**
(symbol tables), иначе часть плагинов не отработает.

## Что мы теперь знаем

- Инъекция — исполняемый код в чужом процессе, которого нет на диске.
- VAD-регион с защитой `PAGE_EXECUTE_READWRITE` — первый признак инъекции.
- `malfind` ищет RWX + PE/shellcode; ложные срабатывания проверяют дампом.
- Reflective DLL есть в памяти, но нет в списке модулей.
- Руткиты ловят cross-view: `pslist` vs `psscan`, `modules` vs `modscan`.

## На что смотреть дальше

- **Верить, что RWX = инъекция** — JIT и .NET тоже создают RWX-регионы.
- **Не дампить регион** — нельзя проверить содержимое.
- **Игнорировать `modscan`** — скрытые драйверы не видны в `modules`.
- **Смотреть только `malfind`** — hollowing виден и по несоответствию образа.
- **Забывать про cross-view** — именно сравнение ломает сокрытие.
- **Анализировать без символов** — часть плагинов не отработает.

## Квиз

Проверь себя.

```quiz
- question: "Что ищет `windows.malfind`?"
  options:
    - "загруженные DLL"
    - "PE-заголовки в исполняемых регионах, которых нет в списке модулей"
    - "открытые сокеты"
    - "записи реестра"
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
- question: "Почему `malfind` — не приговор, а фильтр?"
  options:
    - "он не работает на Windows"
    - "легитимные JIT-движки тоже создают RWX-регионы"
    - "он видит только процессы SYSTEM"
    - "он требует пароль"
  answer: 1
```

## Куда дальше

Мы научились находить в памяти спрятанный код. Дальше посмотрим на самую ценную
добычу — учётные данные: хеши, пароли и ключи, которые остаются в дампе
разблокированной системы. А пока запомни: **чего нет на диске — то ищи в памяти,
и лови это сравнением двух представлений**.

## Где пригодится

- **CTF:** дампы памяти с инъекциями и руткитами.
- **Malware analysis:** разбор in-memory полезных нагрузок.
- **Incident Response:** обнаружение бесфайлового malware.
- **Threat Hunting:** охота за скрытыми процессами и kernel-хуками.
- **Разработка детектов:** правила на RWX-приватную память и reflective load.
