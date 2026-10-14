#!/usr/bin/env python3
"""Generate forensics gB batch B10-C: network (2) + tooling (2)."""
import os, json

C = "content/forensics"
L = "content/labs"


def w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text.rstrip() + "\n")


def lesson(lid, title, parent, order, diff, mins, tags, prereq, useful, summary, lab, body):
    files = lab["files"]
    hints = "\n".join(f"    - '{h}'" for h in lab["hints"])
    toolset = ", ".join(lab["toolset"])
    fm = f"""---
id: {lid}
title: "{title}"
category: forensics
parent: {parent}
difficulty: {diff}
order: {order}
tags: [{tags}]
prerequisites: {prereq}
useful_for:
  - "CTF Forensics категория"
{chr(10).join('  - ' + json.dumps(u, ensure_ascii=False) for u in useful)}
estimated_minutes: {mins}
summary: "{summary}"
lab:
  kind: shell
  title: "{lab['title']}"
  toolset: [{toolset}]
  workdir: /home/student/task
  files: [{', '.join(files)}]
  check: "grep -q 'nto{{' found.txt"
  hints:
{hints}
---
{body}
"""
    w(f"{C}/{lid}.md", fm)
    fs = [{"path": "/home/student/task", "type": "dir"},
          {"path": "/home/student/task/task.md", "text": lab["task"]}]
    for name, text in lab["seeds"].items():
        fs.append({"path": f"/home/student/task/{name}", "text": text, "mode": "644"})
    bundle = {
        "id": lid, "workdir": "/home/student/task", "hostname": "lab",
        "expect": {"file": "/home/student/task/found.txt", "contains": lab["flag"]},
        "fs": fs,
    }
    w(f"{L}/{lid}.json", json.dumps(bundle, ensure_ascii=False, indent=2))


lesson(
    "net-http2-3",
    "Форензика HTTP/2 и HTTP/3: кадры, HPACK и QUIC",
    "forensics-network-advanced", 5, "hard", 55,
    "network, http2, http3, quic, hpack, pcap, forensics",
    "[forensics-network-advanced, forensics-tcp-reassembly]",
    ["Network forensics", "DFIR / Incident Response", "CTF Forensics"],
    "Как устроены HTTP/2 (бинарные кадры, HPACK) и HTTP/3 (QUIC), как их анализировать в pcap и чем отличается разбор от HTTP/1.1.",
    dict(
        title="Практика: разбор h2-потока",
        toolset=["core", "grep", "strings"],
        files=["task.md", "h2_stream.txt"],
        hints=[
            "Посмотри кадры: `cat h2_stream.txt`.",
            "Найди заголовки запроса: `grep -i ':method\\|:path' h2_stream.txt`.",
            "Ищи метку: `grep nto h2_stream.txt`.",
            "Собери ответ: `grep nto h2_stream.txt > found.txt`.",
        ],
        flag="nto{http2_hpack_fr4m3s}",
        task=("# Задача: разбор HTTP/2\n\n"
              "`h2_stream.txt` — декодированные кадры HTTP/2.\n"
              "Найди запрос, который сделал клиент, и метку.\n\n"
              "1. `cat h2_stream.txt`.\n"
              "2. `grep -i ':method\\|:path' h2_stream.txt`.\n"
              "3. `grep nto h2_stream.txt > found.txt`.\n"),
        seeds={
            "h2_stream.txt": (
                "HTTP/2 connection (decoded frames)\n"
                "stream 1: HEADERS  :method=GET :scheme=https :authority=api.local :path=/v1/users\n"
                "stream 1: HEADERS  authorization: Bearer eyJ...  user-agent: curl/8.0\n"
                "stream 1: DATA     {\"id\":42}\n"
                "stream 3: HEADERS  :method=POST :path=/v1/upload\n"
                "stream 3: DATA     (binary payload 4096 bytes)\n"
                "stream 3: DATA     (binary payload 8192 bytes)\n"
                "note: h2 marker nto{http2_hpack_fr4m3s}\n"),
        },
    ),
    body=r'''
## Вопрос, с которого всё начинается

Ты открываешь pcap, ждёшь привычный `GET /index.html`, но вместо текстовых строк видишь
бинарные кадры и закодированные заголовки. Это HTTP/2. Как его читать и где в нём искать
следы?

## Наш пример: сессия HTTP/2

В дампе — соединение клиента с `api.local`. Разберём его кадры и поймём, что произошло.

## Шаг 1: чем HTTP/2 отличается от HTTP/1.1

HTTP/1.1 — текст: запросы и ответы это строки, которые видно в pcap. HTTP/2 —
**бинарный** протокол. Он состоит из **кадров** (frames), у каждого есть тип и длина. В
одном TCP-соединении параллельно идёт несколько **потоков** (streams), каждый со своим
номером. Заголовки передаются сжато через **HPACK** — специальный словарь, поэтому в
сыром виде их не прочитать.

## Шаг 2: заголовки через HPACK

HPACK заменяет повторяющиеся заголовки индексами из таблицы. Псевдозаголовки `:method`,
`:path`, `:authority`, `:scheme` описывают запрос. Чтобы увидеть их, нужен декодер (Wireshark
делает это автоматически, если знает, что это HTTP/2). После декодирования ты получаешь
привычную картину:

```
stream 1: HEADERS :method=GET :path=/v1/users authorization: Bearer eyJ...
stream 3: HEADERS :method=POST :path=/v1/upload
```

## Шаг 3: потоки и мультиплексирование

Каждый запрос — свой поток с номером. Потоки чередуются, поэтому в pcap кадры разных
запросов перемешаны. Анализ начинается с группировки по `stream`: сначала все кадры потока 1,
затем потока 3. Так восстанавливается логическая последовательность запрос-ответ.

## Шаг 4: HTTP/3 и QUIC

HTTP/3 работает поверх **QUIC** — протокола на UDP. QUIC шифрует почти всё, включая
служебные кадры, поэтому в pcap видно лишь зашифрованные дейтаграммы. Расшифровать можно
только при наличии ключей (например, `SSLKEYLOGFILE`). HTTP/3 быстрее (меньше задержек), но
для следователя сложнее: без ключей ты видишь факт соединения и объём, но не содержимое.

## Шаг 5: что искать

Интерес для расследования: псевдозаголовок `:authority` (куда ходили), `:path` (что
запрашивали), `authorization` (токены — утечка учётных данных), большие потоки `DATA`
(выгрузка данных), `user-agent` (инструмент клиента). Аномалии — редкие пути, нетипичные
заголовки, многочисленные мелкие потоки (возможный C2 через h2).

## Что мы теперь знаем

- HTTP/2 — бинарный протокол из кадров и потоков, заголовки сжаты HPACK.
- Анализ группируют по `stream`; декодер восстанавливает заголовки.
- HTTP/3 идёт по QUIC/UDP и почти полностью зашифрован.
- Ключевые поля: `:method`, `:path`, `:authority`, `authorization`, `DATA`.
- Без ключей HTTP/3 даёт только метаданные соединения.

## Квиз

Проверь себя.

```quiz
- question: Чем HTTP/2 принципиально отличается от HTTP/1.1?
  options: ['Работает по UDP', 'Бинарный, с кадрами и потоками', 'Не использует заголовки', 'Всегда шифрован']
  answer: 1
  explanation: HTTP/2 передаёт бинарные кадры и мультиплексирует потоки в одном соединении.
- question: Как называется сжатие заголовков в HTTP/2?
  options: ['gzip', 'HPACK', 'QPACK', 'Brotli']
  answer: 1
  explanation: HPACK — схема сжатия заголовков HTTP/2 (в HTTP/3 — QPACK).
- question: Что нужно, чтобы прочитать содержимое HTTP/3 в pcap?
  options: ['Только номер порта', 'Ключи расшифровки (SSLKEYLOGFILE)', 'Декодер HPACK', 'Ничего, оно открыто']
  answer: 1
  explanation: HTTP/3 поверх QUIC почти полностью шифрован; без ключей видно лишь метаданные.
- question: Какое поле показывает, куда обращался клиент?
  options: [':method', ':path', ':authority', 'user-agent']
  answer: 2
  explanation: :authority — хост назначения; :path — путь запроса.
```

## Куда дальше

Дальше — анализ сетевых потоков (flow) и детектирование beaconing. Главное запомни:
**HTTP/2 анализируют по потокам, а HTTP/3 без ключей почти непрозрачен**.

## Где пригодится

- Network forensics: разбор современных веб-соединений.
- CTF-категория Forensics с pcap HTTP/2/3.
- Threat hunting: поиск C2 через h2-мультиплексирование.
''',
)

lesson(
    "net-flow-beaconing",
    "Анализ потоков и детектирование beaconing",
    "forensics-network-deep", 5, "hard", 55,
    "network, netflow, ipfix, beaconing, rita, c2, forensics",
    "[forensics-network-deep, forensics-suricata]",
    ["Network forensics", "Threat Hunting", "DFIR / Incident Response"],
    "Как анализировать сетевые потоки (NetFlow/IPFIX) и выявлять beaconing — периодические обращения заражённых хостов к C2.",
    dict(
        title="Практика: найти beacon в потоках",
        toolset=["core", "grep", "sort", "uniq"],
        files=["task.md", "flows.txt"],
        hints=[
            "Посмотри потоки: `cat flows.txt`.",
            "Найди повторяющиеся соединения к одному IP: `grep 198.51.100.9 flows.txt`.",
            "Ищи метку: `grep nto flows.txt`.",
            "Собери ответ: `grep nto flows.txt > found.txt`.",
        ],
        flag="nto{b34c0n1ng_p3r10d1c}",
        task=("# Задача: детект beaconing\n\n"
              "`flows.txt` — записи NetFlow (время, src, dst, порт, байты).\n"
              "Найди периодические обращения к подозрительному IP и метку.\n\n"
              "1. `cat flows.txt`.\n"
              "2. `grep 198.51.100.9 flows.txt`.\n"
              "3. `grep nto flows.txt > found.txt`.\n"),
        seeds={
            "flows.txt": (
                "start,src,dst,sport,dport,bytes\n"
                "1746086400,10.0.0.12,198.51.100.9,51001,443,540\n"
                "1746086700,10.0.0.12,198.51.100.9,51002,443,548\n"
                "1746087000,10.0.0.12,198.51.100.9,51003,443,552\n"
                "1746087300,10.0.0.12,198.51.100.9,51004,443,544\n"
                "1746087600,10.0.0.12,198.51.100.9,51005,443,550\n"
                "1746086455,10.0.0.12,93.184.216.34,52000,443,120000\n"
                "note: flow marker nto{b34c0n1ng_p3r10d1c}\n"),
        },
    ),
    body=r'''
## Вопрос, с которого всё начинается

В сети заражённый хост каждые пять минут стучится к серверу управления. В обычном pcap это
легко потерять среди миллионов пакетов. Как найти такой «маяк» (beaconing), не разбирая
каждый пакет?

## Наш пример: записи потоков

У нас есть **NetFlow** — метаданные соединений: кто, с кем, когда, сколько байт. Записи:

```
1746086400,10.0.0.12,198.51.100.9,51001,443,540
1746086700,10.0.0.12,198.51.100.9,51002,443,548
1746087000,10.0.0.12,198.51.100.9,51003,443,552
```

Заметь: каждые 300 секунд — новое соединение к одному IP, примерно одинакового размера.
Это подпись beaconing.

## Шаг 1: что такое flow

**Flow** (поток) — агрегированная запись о соединении: пятерка (src IP, dst IP, src port,
dst port, протокол) плюс время начала/конца, число пакетов и байт. NetFlow и IPFIX —
форматы таких записей; маршрутизаторы и хосты их экспортируют. Flow не содержит содержимого
(это не pcap), но по **метаданным** видно очень много: периодичность, объёмы, направления.

## Шаг 2: признаки beaconing

Beacon — регулярный «пульс» заражённого хоста к C2. Признаки:

- **Регулярные интервалы** (каждые N секунд) с малым разбросом;
- **Одинаковый размер** запросов (короткий ответ «нет задач»);
- **Один dst IP/домен**, много соединений;
- **Постоянные сессии** в нерабочее время;
- Маленький объём данных на соединение.

Наши записи: интервал ровно 300 с, размеры 540–552 байта — почти идеальный маяк.

## Шаг 3: как искать в большом объёме

Ручной анализ flow-логов не масштабируется, поэтому считают статистику. Инструменты вроде
**RITA** (Real Intelligence Threat Analytics) импортируют flow и оценивают периодичность:
считают распределение интервалов, дисперсию, «оценку beaconing». Хосты с высокой
регулярностью попадают в отчёт первыми.

Вручную можно сгруппировать по (src, dst) и посмотреть интервалы между соединениями:

```
$ grep 198.51.100.9 flows.txt | awk -F, '{print $1}' | sort -n
```

Разница между соседними значениями — и есть период. Если он стабилен — это маяк.

## Шаг 4: jitter и его обход

Продвинутые C2 добавляют **jitter** — случайный разброс интервала, чтобы не выглядеть
слишком регулярно. Тогда строгий детект по «ровному» периоду не срабатывает, и смотрят на
**длительность** сессий, объём, повторяемость на длинном окне. Даже с jitter средний период
и общий профиль остаются аномальными на фоне легитимного трафика.

## Шаг 5: что делать с находкой

Найденный beacon — это зацепка: зафиксируй dst IP/домен как IOC, найди все хосты,
обращавшиеся к нему, и сопоставь с другими источниками (DNS, proxy). Часто beacon — лишь
один из многих хостов в кампании; по одному маяку можно раскрыть всю инфраструктуру.

## Что мы теперь знаем

- Flow (NetFlow/IPFIX) — метаданные соединений без содержимого.
- Beaconing выдаёт регулярность, одинаковый размер и один dst.
- Статистику считают инструментами (RITA) или вручную по интервалам.
- Jitter усложняет детект, но профиль остаётся аномальным.
- Найденный beacon даёт IOC и путь к другим заражённым хостам.

## Квиз

Проверь себя.

```quiz
- question: Что содержит запись NetFlow?
  options: ['Содержимое пакетов', 'Метаданные соединения (пятерка, время, объём)', 'Только DNS', 'Файлы из трафика']
  answer: 1
  explanation: NetFlow — агрегированные метаданные соединений без payload.
- question: Какой признак типичен для beaconing?
  options: ['Случайные редкие соединения', 'Регулярные интервалы и одинаковый размер к одному dst', 'Огромные выгрузки', 'Один пакет за сутки']
  answer: 1
  explanation: Beacon шлёт короткие запросы с постоянным периодом к C2.
- question: Зачем C2 добавляют jitter?
  options: ['Ускорить связь', 'Сделать интервалы менее регулярными, чтобы обойти детект', 'Сжать трафик', 'Шифровать DNS']
  answer: 1
  explanation: Jitter — случайный разброс периода, затрудняющий обнаружение по строгой периодичности.
- question: Что даёт найденный beacon?
  options: ['Только имя файла', 'IOC (dst) и путь к другим заражённым хостам', 'Пароль администратора', 'Полный дамп памяти']
  answer: 1
  explanation: По dst из beacon ищут другие хосты с тем же обращением — масштаб кампании.
```

## Куда дальше

Дальше — инструменты DFIR: набор Эрика Циммермана. Главное запомни: **beacon виден в
метаданных, даже когда содержимое зашифровано**.

## Где пригодится

- Network forensics: поиск C2 по метаданным.
- Threat hunting: регулярные проверки flow на периодичность.
- CTF-категория Forensics с логами NetFlow.
''',
)

lesson(
    "tool-eric-zimmerman",
    "Инструменты Эрика Циммермана (EZ Tools)",
    "forensics-tooling", 4, "medium", 50,
    "tools, ez-tools, mftecmd, pecmd, amcache, evtxecmd, forensics",
    "[forensics-tooling, forensics-windows-artifacts]",
    ["DFIR / Incident Response", "Windows forensics", "CTF Forensics"],
    "Обзор набора EZ Tools: MFTECmd, PECmd, AmcacheParser, AppCompatCacheParser, EvtxECmd, JLECmd, LECmd, SBECmd — что каждый парсит и как читать вывод.",
    dict(
        title="Практика: разбор вывода PECmd",
        toolset=["core", "grep", "cut", "sort"],
        files=["task.md", "PECmd_out.csv"],
        hints=[
            "Посмотри CSV: `cat PECmd_out.csv`.",
            "Найди запуски программ: `grep -i run PECmd_out.csv`.",
            "Ищи метку: `grep nto PECmd_out.csv`.",
            "Собери ответ: `grep nto PECmd_out.csv > found.txt`.",
        ],
        flag="nto{ez_t00ls_pecmd}",
        task=("# Задача: EZ Tools\n\n"
              "`PECmd_out.csv` — вывод PECmd по Prefetch.\n"
              "Определи, какая программа запускалась, и найди метку.\n\n"
              "1. `cat PECmd_out.csv`.\n"
              "2. `grep -i run PECmd_out.csv`.\n"
              "3. `grep nto PECmd_out.csv > found.txt`.\n"),
        seeds={
            "PECmd_out.csv": (
                "SourceFile,ExecutableName,RunCount,LastRun,Volume\n"
                "POWERSHELL.EXE-1.pf,powershell.exe,7,2025-05-01 09:03:20,C:\n"
                "CMD.EXE-2.pf,cmd.exe,3,2025-05-01 09:03:18,C:\n"
                "NOTEPAD.EXE-3.pf,notepad.exe,12,2025-04-30 18:00:00,C:\n"
                "UPDATER.EXE-4.pf,updater.exe,1,2025-05-01 09:03:25,C:\n"
                "note: ez marker nto{ez_t00ls_pecmd}\n"),
        },
    ),
    body=r'''
## Вопрос, с которого всё начинается

Windows хранит десятки бинарных артефактов: MFT, Prefetch, Amcache, журналы. Разбирать их
руками больно. Есть набор бесплатных инструментов, который делает это быстро и единообразно
— **EZ Tools** Эрика Циммермана. Что в него входит и что даёт каждый инструмент?

## Наш пример: вывод PECmd

Перед нами CSV-файл `PECmd_out.csv` — результат работы **PECmd** по файлам Prefetch. Prefetch
— механизм Windows, ускоряющий запуск программ; попутно он фиксирует, **что и сколько раз
запускалось**. Разберём вывод.

## Шаг 1: что такое EZ Tools

EZ Tools — набор утилит командной строки (и GUI) для парсинга Windows-артефактов в
читаемый вид (CSV/JSON). Главные:

| Инструмент | Что парсит |
|------------|-----------|
| `MFTECmd` | `$MFT` (файловая система NTFS) |
| `PECmd` | Prefetch (запуски программ) |
| `AmcacheParser` | Amcache.hve (история исполняемых файлов) |
| `AppCompatCacheParser` | ShimCache (совместимость приложений) |
| `EvtxECmd` | журналы событий EVTX |
| `JLECmd` | Jump Lists (недавние файлы) |
| `LECmd` | LNK-файлы (ярлыки) |
| `SBECmd` | Shellbags (папки в проводнике) |
| `RECmd` | реестр по batch-файлам |
| `SrumECmd` | SRUM (использование ресурсов) |

## Шаг 2: читаем Prefetch

```
$ PECmd.exe -f POWERSHELL.EXE-1.pf --csv out
```

В CSV мы видим колонки: `ExecutableName`, `RunCount`, `LastRun`, `Volume`. Из них:

- `powershell.exe` запускался 7 раз, последний — 2025-05-01 09:03:20;
- `cmd.exe` — 3 раза, в 09:03:18;
- `updater.exe` — 1 раз, в 09:03:25.

Связка `cmd` → `powershell` → `updater` в течение семи секунд — классическая цепочка
заражения. Prefetch даёт **время запуска** и **число запусков**, чего нет во многих других
артефактах.

## Шаг 3: как инструменты дополняют друг друга

Один артефакт редко даёт полную картину. `PECmd` скажет «запускалось», `AmcacheParser` —
«откуда файл пришёл» (путь и хеш), `MFTECmd` — «когда файл создан на диске», `EvtxECmd` —
«какое событие при этом записано». Объединяя их в таймлайн, ты получаешь связную историю.
Именно поэтому EZ Tools используют вместе, а не по одному.

## Шаг 4: почему это удобно

Все инструменты выдают **единообразный** вывод (CSV/JSON) с одинаковым стилем колонок. Это
позволяет строить автоматические конвейеры: распарсить всё, слить в одну таблицу, отсортировать
по времени. GUI-версии (например, Timeline Explorer) открывают эти CSV и дают фильтрацию и
поиск. Для аналитика это экономит часы ручной работы.

## Шаг 5: что искать

Приоритеты: нетипичные `ExecutableName` (инструменты атакующего), редкие `RunCount`, запуски
в нерабочее время, цепочки процессов, пути в `Temp`/`AppData`, совпадение времени запуска с
сетевыми событиями. В нашем примере `updater.exe` с одним запуском сразу после PowerShell —
главный подозреваемый.

## Что мы теперь знаем

- EZ Tools — набор парсеров Windows-артефактов в CSV/JSON.
- `PECmd` даёт имя программы, число запусков и время последнего запуска.
- Инструменты дополняют друг друга и складываются в таймлайн.
- Единый формат вывода позволяет автоматизировать конвейеры.
- Ищи нетипичные программы, редкие запуски и цепочки процессов.

## Квиз

Проверь себя.

```quiz
- question: Что парсит PECmd?
  options: ['Журналы событий', 'Prefetch — запуски программ', '$MFT', 'Реестр целиком']
  answer: 1
  explanation: PECmd разбирает Prefetch и показывает запуски программ с временем и счётчиком.
- question: Какой инструмент разбирает журналы EVTX?
  options: ['MFTECmd', 'JLECmd', 'EvtxECmd', 'SBECmd']
  answer: 2
  explanation: EvtxECmd парсит журналы событий Windows.
- question: Что показывает AmcacheParser?
  options: ['Папки в проводнике', 'Историю исполняемых файлов (пути, хеши)', 'Сетевые соединения', 'Задачи планировщика']
  answer: 1
  explanation: Amcache хранит сведения об исполняемых файлах, включая пути и хеши.
- question: Почему EZ Tools используют вместе?
  options: ['Они одинаковые', 'Разные артефакты дополняют друг друга в общем таймлайне', 'Так быстрее качается', 'Иначе не запустятся']
  answer: 1
  explanation: Комбинация артефактов (запуск, происхождение, время, события) даёт полную картину.
```

## Куда дальше

Дальше — KAPE: как собрать нужные артефакты с хоста быстро и прицельно. Главное запомни:
**EZ Tools превращают бинарные артефакты Windows в таблицы, которые можно объединять в
таймлайн**.

## Где пригодится

- DFIR на Windows: быстрый разбор артефактов.
- CTF-категория Forensics с образом Windows.
- Построение таймлайнов из разнородных артефактов.
''',
)

lesson(
    "tool-kape",
    "KAPE: прицельный сбор артефактов (triage)",
    "forensics-tooling", 5, "medium", 50,
    "tools, kape, triage, collection, targets, modules, forensics",
    "[forensics-tooling, forensics-windows-artifacts]",
    ["DFIR / Incident Response", "Windows forensics", "CTF Forensics"],
    "Как работает KAPE: targets (что собирать), modules (чем парсить), режимы сбора и построение прицельной triage-коллекции.",
    dict(
        title="Практика: разбор triage-коллекции",
        toolset=["core", "grep", "cat"],
        files=["task.md", "kape_collection.txt"],
        hints=[
            "Посмотри список собранного: `cat kape_collection.txt`.",
            "Найди цель по журналам: `grep -i evtx kape_collection.txt`.",
            "Ищи метку: `grep nto kape_collection.txt`.",
            "Собери ответ: `grep nto kape_collection.txt > found.txt`.",
        ],
        flag="nto{k4p3_tr14g3_c0ll3ct10n}",
        task=("# Задача: KAPE-коллекция\n\n"
              "`kape_collection.txt` — список артефактов, собранных KAPE.\n"
              "Определи, что попало в коллекцию, и найди метку.\n\n"
              "1. `cat kape_collection.txt`.\n"
              "2. `grep -i evtx kape_collection.txt`.\n"
              "3. `grep nto kape_collection.txt > found.txt`.\n"),
        seeds={
            "kape_collection.txt": (
                "KAPE triage collection (targets applied)\n"
                "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx\n"
                "C:\\Windows\\System32\\winevt\\Logs\\System.evtx\n"
                "C:\\Windows\\System32\\winevt\\Logs\\PowerShell-Operational.evtx\n"
                "C:\\Windows\\Prefetch\\POWERSHELL.EXE-1.pf\n"
                "C:\\Windows\\appcompat\\Programs\\Amcache.hve\n"
                "C:\\Users\\jdoe\\NTUSER.DAT\n"
                "C:\\$MFT\n"
                "C:\\Windows\\System32\\config\\SYSTEM\n"
                "note: kape marker nto{k4p3_tr14g3_c0ll3ct10n}\n"),
        },
    ),
    body=r'''
## Вопрос, с которого всё начинается

Нужно быстро собрать артефакты с сотни машин, не выкачивая весь диск. Как указать, **что
именно** брать, и как сразу распарсить собранное? Для этого есть **KAPE**.

## Наш пример: triage-коллекция

Перед нами список того, что KAPE собрал с хоста. Разберём, как формируется такая коллекция.

## Шаг 1: что такое KAPE

**KAPE** (Kroll Artifact Parser and Extractor) — инструмент для **triage**-сбора: он быстро
забирает только нужные артефакты и при необходимости сразу их парсит. Работает по двум
концепциям: **targets** (что копировать) и **modules** (чем обрабатывать).

## Шаг 2: targets — что собирать

**Target** — это правило, которое описывает файлы/каталоги для копирования. Например, цель
`EventLogs` забирает все `.evtx` из `C:\Windows\System32\winevt\Logs\`. Цель `Prefetch` —
содержимое `C:\Windows\Prefetch\`. Цель `RegistryHives` — `SYSTEM`, `SOFTWARE`, `SAM` и
`NTUSER.DAT`.

Targets описываются в файлах `.tkape` (YAML-подобный формат) и могут быть составными: одна
цель ссылается на другие. Собрав набор целей, ты описываешь «профиль сбора» под задачу.

## Шаг 3: modules — чем парсить

**Module** — это программа, которая обрабатывает уже собранные артефакты. Модули часто
используют EZ Tools: например, модуль `PECmd` парсит Prefetch, `EvtxECmd` — журналы,
`AmcacheParser` — Amcache. В результате на выходе ты получаешь не сырые бинарники, а готовые
CSV/JSON.

## Шаг 4: режимы работы

KAPE может работать в двух режимах:

- **collect** — только копирование артефактов (быстро, минимально нагружает систему);
- **collect + process** — копирование и сразу парсинг (удобно для одной машины).

Для массового сбора с парка машин обычно собирают коллекции, а парсят централизованно —
чтобы не нагружать хосты. Такой подход хорошо ложится на IR: сначала быстрый срез со всех
машин, потом глубокий анализ.

## Шаг 5: почему это важно

Полный образ диска с каждой машины — долго и дорого. Triage-сбор по целям забирает доли
процента данных, но при этом содержит 90% ценных артефактов: журналы, реестр, Prefetch,
MFT. Именно поэтому KAPE стал стандартом в DFIR. Важно правильно выбрать **набор целей** под
гипотезу: для подозрения на PowerShell-атаку берут журнал PowerShell, Prefetch и Amcache.

## Что мы теперь знаем

- KAPE — инструмент прицельного сбора артефактов (triage).
- Targets определяют, **что** копировать; modules — **чем** парсить.
- Targets описываются в `.tkape`, modules часто вызывают EZ Tools.
- Режимы: только сбор или сбор + обработка.
- Правильный набор целей под гипотезу — ключ к эффективному сбору.

## Квиз

Проверь себя.

```quiz
- question: Что описывают targets в KAPE?
  options: ['Чем парсить', 'Какие артефакты копировать', 'Куда писать лог', 'Пароль пользователя']
  answer: 1
  explanation: Targets определяют набор файлов/каталогов для сбора.
- question: Что делают modules?
  options: ['Копируют файлы', 'Обрабатывают собранные артефакты (парсят)', 'Сжимают архив', 'Шифруют коллекцию']
  answer: 1
  explanation: Modules запускают парсеры (часто EZ Tools) по собранным данным.
- question: В чём смысл triage-сбора вместо полного образа?
  options: ['Он полнее', 'Он забирает малую долю данных, но содержит большинство ценных артефактов', 'Он быстрее шифруется', 'Он не требует прав']
  answer: 1
  explanation: Triage быстро собирает ключевые артефакты, экономя время и место.
- question: Почему набор целей выбирают под гипотезу?
  options: ['Так требует лицензия', 'Чтобы собрать релевантные артефакты и не тратить время на лишнее', 'Иначе KAPE не запустится', 'Чтобы уменьшить размер диска']
  answer: 1
  explanation: Цели подбирают под конкретную задачу расследования, чтобы получить нужные данные.
```

## Куда дальше

Мы закрыли блок инструментов DFIR. Дальше — специализированные области: IoT, automotive и
другие нишевые устройства. Главное запомни: **KAPE собирает прицельно — сначала определи
гипотезу, потом набор целей**.

## Где пригодится

- DFIR: массовый сбор артефактов с парка машин.
- CTF-категория Forensics: понимание структуры Windows-артефактов.
- Построение воспроизводимых пайплайнов сбора и разбора.
''',
)
print("B10-C done")
