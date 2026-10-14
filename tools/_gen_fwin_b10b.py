#!/usr/bin/env python3
"""Generate forensics gB batch B10-B: mobile backups (2) + malware deep (2)."""
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


# --------------------------------------------------------------------------
# Mobile backups — parent forensics-mobile-deep (4 -> 6)
# --------------------------------------------------------------------------

lesson(
    "mobile-ios-backup",
    "Резервная копия iOS: структура и разбор",
    "forensics-mobile-deep", 5, "hard", 55,
    "mobile, ios, backup, itunes, manifest, keybag, forensics",
    "[forensics-mobile-deep, forensics-mobile-extraction]",
    ["DFIR / Incident Response", "Mobile forensics", "CTF Forensics"],
    "Как устроена резервная копия iOS (iTunes/Finder): каталоги, Manifest.db, хешированные имена файлов и разбор через libimobiledevice.",
    dict(
        title="Практика: карта файлов из Manifest",
        toolset=["core", "grep", "strings"],
        files=["task.md", "Manifest_dump.txt"],
        hints=[
            "Посмотри записи манифеста: `cat Manifest_dump.txt`.",
            "Найди домен WhatsApp: `grep -i whatsapp Manifest_dump.txt`.",
            "Ищи метку: `grep nto Manifest_dump.txt`.",
            "Собери ответ: `grep nto Manifest_dump.txt > found.txt`.",
        ],
        flag="nto{1os_b4ckup_m4n1f3st}",
        task=("# Задача: резервная копия iOS\n\n"
              "`Manifest_dump.txt` — выгрузка Manifest.db из бэкапа iPhone.\n"
              "Определи, какие файлы мессенджера есть в копии, и найди метку.\n\n"
              "1. `cat Manifest_dump.txt`.\n"
              "2. `grep -i whatsapp Manifest_dump.txt`.\n"
              "3. `grep nto Manifest_dump.txt > found.txt`.\n"),
        seeds={
            "Manifest_dump.txt": (
                "Manifest.db rows (fileID, domain, relativePath)\n"
                "a1b2  HomeDomain            Library/SMS/sms.db\n"
                "c3d4  AppDomain-com.apple.mobilesafari  Library/Safari/History.db\n"
                "e5f6  AppDomain-net.whatsapp.WhatsApp   Documents/msgstore.db\n"
                "g7h8  CameraRollDomain      Media/DCIM/100APPLE/IMG_0001.JPG\n"
                "i9j0  RootDomain            Library/Preferences/com.apple.MobileSMS.plist\n"
                "note: backup marker nto{1os_b4ckup_m4n1f3st}\n"),
        },
    ),
    body=r'''
## Вопрос, с которого всё начинается

Тебе передали папку с резервной копией iPhone. Внутри — тысячи файлов с непонятными именами
вроде `3f/3fa1b2c3...`. Где искать сообщения, историю Safari, фото? Без карты копии ты
будешь блуждать. Карта — это `Manifest.db`.

## Наш пример: бэкап iPhone

Копия iOS (сделанная через iTunes или Finder) лежит в каталоге вида:

```
~/Library/Application Support/MobileSync/Backup/<UDID>/
```

Внутри — `Manifest.plist` (метаданные и настройки шифрования), `Status.plist` (состояние
последнего бэкапа), `Manifest.db` (карта файлов) и подкаталоги с самими файлами.

## Шаг 1: почему имена файлов хешированы

В бэкапе файл хранится под именем = SHA-1 от строки `<domain>-<relativePath>`. Это значит,
что по имени файла **нельзя** понять, что внутри. Реальная карта — в базе `Manifest.db`:

| Колонка | Что означает |
|---------|--------------|
| `fileID` | хеш-имя файла на диске |
| `domain` | логическая область (`AppDomain-…`, `HomeDomain`, `CameraRollDomain`) |
| `relativePath` | путь внутри области (как в телефоне) |
| `flags` | тип записи (файл/каталог/симлинк) |

Связка `fileID ↔ (domain, relativePath)` — ключ ко всей копии.

## Шаг 2: находим нужное

Запрос к манифесту показывает, где лежат интересные базы:

```
$ sqlite3 Manifest.db "SELECT fileID, domain, relativePath FROM Files"
a1b2  HomeDomain                        Library/SMS/sms.db
c3d4  AppDomain-com.apple.mobilesafari  Library/Safari/History.db
e5f6  AppDomain-net.whatsapp.WhatsApp   Documents/msgstore.db
```

Теперь ясно: `sms.db` — сообщения, `History.db` — браузер, `msgstore.db` — WhatsApp. Зная
`fileID`, находим сам файл в подкаталоге и копируем для анализа.

## Шаг 3: шифрование копии

Копия может быть **зашифрована** (в `Manifest.plist` поле `IsEncrypted=true`). Тогда файлы
и метаданные защищены ключом, выведённым из пароля копии. Без пароля разобрать её нельзя —
это принципиальное ограничение. Расшифровка выполняется инструментами, которые просят
пароль и выводят открытую копию. Если пароль неизвестен, зацепки ищут в незашифрованных
артефактах (например, в `Status.plist` и части метаданных).

## Шаг 4: инструменты

Разбор делают библиотекой `libimobiledevice` и её утилитами:

```
$ idevicebackup2 backup --full /tmp/backup        # сделать копию
$ idevicebackup2 unback /tmp/backup               # распаковать
```

Для анализа манифеста и извлечения файлов есть специализированные парсеры
(например, `iphone-dataprotection`, скрипты на Python с `sqlite3`). В CTF-задаче часто
достаточно `sqlite3 Manifest.db` плюс чтения нужного файла по `fileID`.

## Шаг 5: что искать

Приоритетные артефакты в бэкапе: `sms.db` (переписка), `CallHistory.storedata` (звонки),
`History.db` (браузер), `AddressBook.sqlitedb` (контакты), базы мессенджеров, `Cache.db`
(сетевые ответы), геоданные. Каждый файл — отдельная область расследования. Начинай с
манифеста: он отвечает на вопрос «что вообще есть в копии», а дальше ты копируешь и
анализируешь конкретные базы.

## Что мы теперь знаем

- Бэкап iOS хранит файлы под SHA-1 именами; карта — в `Manifest.db`.
- Записи связывают `fileID`, `domain` и `relativePath`.
- Копия может быть зашифрована; без пароля её не разобрать.
- `libimobiledevice`/`idevicebackup2` делают и распаковывают копии.
- Ключевые цели: SMS, звонки, браузер, контакты, мессенджеры, кэш.

## Квиз

Проверь себя.

```quiz
- question: Где хранится карта файлов резервной копии iOS?
  options: ['Manifest.plist', 'Manifest.db', 'Status.plist', 'Info.plist']
  answer: 1
  explanation: Manifest.db — SQLite-база, связывающая fileID, domain и relativePath.
- question: Чем является имя файла в каталоге бэкапа?
  options: ['Исходным путём', 'SHA-1 хешем от domain-relativePath', 'Случайным UUID', 'Именем приложения']
  answer: 1
  explanation: Файлы хранятся под SHA-1 хешем строки domain-relativePath.
- question: Что означает IsEncrypted=true в Manifest.plist?
  options: ['Копия сжата', 'Копия зашифрована и требует пароль', 'Копия повреждена', 'Копия сделана через iCloud']
  answer: 1
  explanation: Зашифрованную копию нельзя разобрать без пароля.
- question: Какая утилита из libimobiledevice делает/распаковывает бэкап?
  options: ['idevicebackup2', 'idevicesyslog', 'plutil', 'otool']
  answer: 0
  explanation: idevicebackup2 управляет созданием и распаковкой резервных копий.
```

## Куда дальше

Дальше — резервные копии Android (формат `.ab`), где всё иначе: один поток данных, а не
каталог файлов. Главное запомни: **в бэкапе iOS ищи не файлы, а `Manifest.db` — карту,
которая скажет, что где лежит**.

## Где пригодится

- DFIR по мобильным устройствам: разбор изъятой копии.
- CTF-категория Forensics с образом iPhone.
- Корпоративные расследования: переписка и активность сотрудника.
''',
)

lesson(
    "mobile-android-backup",
    "Резервная копия Android: формат .ab и его разбор",
    "forensics-mobile-deep", 6, "hard", 50,
    "mobile, android, adb, backup, ab-format, forensics",
    "[forensics-mobile-deep, forensics-mobile-extraction]",
    ["DFIR / Incident Response", "Mobile forensics", "CTF Forensics"],
    "Как устроен формат Android Backup (.ab): заголовок ANDROID BACKUP, сжатие, шифрование и распаковка через abe/abx.",
    dict(
        title="Практика: разбор .ab-заголовка",
        toolset=["core", "grep", "strings", "base64"],
        files=["task.md", "backup.ab"],
        hints=[
            "Посмотри содержимое: `cat backup.ab`.",
            "Найди версию и флаги: `grep -i ANDROID BACKUP backup.ab`.",
            "Ищи метку: `grep nto backup.ab`.",
            "Собери ответ: `grep nto backup.ab > found.txt`.",
        ],
        flag="nto{4ndr01d_4b_b4ckup}",
        task=("# Задача: резервная копия Android\n\n"
              "`backup.ab` — файл резервной копии adb.\n"
              "Определи параметры копии (сжатие, шифрование) и найди метку.\n\n"
              "1. `cat backup.ab`.\n"
              "2. `grep -i ANDROID BACKUP backup.ab`.\n"
              "3. `grep nto backup.ab > found.txt`.\n"),
        seeds={
            "backup.ab": (
                "ANDROID BACKUP\n"
                "5\n"
                "1\n"
                "none\n"
                "\n"
                "packages:\n"
                "com.example.notes\n"
                "com.android.providers.telephony\n"
                "com.whatsapp\n"
                "payload: (zlib-compressed tar, base64 shown for readability)\n"
                "H4sIAAAAAAAA... (tar entries: apps/com.whatsapp/db/msgstore.db, ...)\n"
                "note: android backup marker nto{4ndr01d_4b_b4ckup}\n"),
        },
    ),
    body=r'''
## Вопрос, с которого всё начинается

Android-приложение может сохранить данные командой `adb backup`. На выходе получается
единственный файл `backup.ab` — не каталог, как в iOS, а один поток. Как его открыть и что
внутри?

## Наш пример: файл backup.ab

```
$ adb backup -apk -shared -all -f backup.ab
```

Полученный `backup.ab` — это контейнер с заголовком и полезной нагрузкой. Разберём его
послойно.

## Шаг 1: заголовок ANDROID BACKUP

Файл начинается с текстового заголовка. Смотрим первые строки:

```
$ cat backup.ab
ANDROID BACKUP
5
1
none
```

Здесь четыре поля: магия `ANDROID BACKUP`, **версия формата** (5), **флаг сжатия**
(1 = сжато zlib, 0 = без сжатия) и **алгоритм шифрования** (`none`, `AES-256`). Уже из
заголовка понятно, как обрабатывать payload.

## Шаг 2: структура payload

После заголовка идёт полезная нагрузка — это **tar**-архив (при сжатии — сжатый zlib).
Внутри tar лежат записи приложений:

```
apps/com.example.notes/db/notes.db
apps/com.whatsapp/db/msgstore.db
shared/DCIM/Camera/IMG_0001.jpg
```

То есть `.ab` — это «tar в обёртке», где tar, в свою очередь, может быть сжат и/или
зашифрован. Понимание этой вложенности — ключ к разбору.

## Шаг 3: шифрование

Если в заголовке стоит `AES-256`, payload зашифрован. Ключ выводится из пароля, который
пользователь задал при создании копии. Первые байты зашифрованной области — соль и
проверочное значение. Без пароля расшифровать нельзя. Инструменты (`abe`, `abx`,
`android-backup-extractor`) просят пароль и выводят открытый tar.

## Шаг 4: распаковка

Для незашифрованной и несжатой копии достаточно убрать заголовок и распаковать tar. Для
сжатой — распаковать zlib. Инструмент `abe` делает всё автоматически:

```
$ abe unpack backup.ab backup.tar
```

В CTF-задаче часто нужно вручную отрезать текстовый заголовок (до пустой строки), затем
распаковать оставшееся. Это проверяет понимание формата: где кончается заголовок и
начинается tar.

## Шаг 5: что искать

Внутри tar — те же ценные базы, что и на устройстве: сообщения мессенджеров, заметки,
контакты, история звонков. Особенность: `adb backup` берёт только то, что приложение
разрешило (некоторые приложения запрещают бэкап, `android:allowBackup=false`). Поэтому
отсутствие данных приложения в копии — тоже информация: оно защищено от бэкапа. Полноценное
извлечение Android чаще делают через **физический образ** или root, но `.ab` — быстрый и
легальный способ на незалоченном устройстве с отладкой.

## Что мы теперь знаем

- `.ab` — контейнер: текстовый заголовок + tar-payload (сжатый/зашифрованный).
- Заголовок задаёт версию, сжатие и алгоритм шифрования.
- AES-256 требует пароль; без него payload не разобрать.
- Распаковка: `abe unpack` или ручное отрезание заголовка + tar.
- `adb backup` берёт только данные приложений с разрешённым бэкапом.

## Квиз

Проверь себя.

```quiz
- question: С чего начинается файл Android Backup?
  options: ['с ZIP-заголовка PK', 'с текстовой магии ANDROID BACKUP', 'с tar-заголовка', 'с SHA-1 хеша']
  answer: 1
  explanation: Первые строки — текстовая магия ANDROID BACKUP и параметры.
- question: Что означает третье поле заголовка (1 или 0)?
  options: ['Версию Android', 'Флаг сжатия payload', 'Число приложений', 'Длину ключа']
  answer: 1
  explanation: 1 = payload сжат zlib, 0 = без сжатия.
- question: Что представляет собой payload после заголовка?
  options: ['ZIP-архив', 'tar-архив (возможно сжатый/зашифрованный)', 'SQLite-базу', 'JSON-файл']
  answer: 1
  explanation: Полезная нагрузка — tar-архив, при необходимости сжатый и/или зашифрованный.
- question: Что значит отсутствие данных приложения в копии?
  options: ['Копия повреждена', 'Приложение запрещает бэкап (allowBackup=false)', 'Не хватило места', 'Ошибка adb']
  answer: 1
  explanation: Приложения с android:allowBackup=false не попадают в adb backup.
```

## Куда дальше

Мы закрыли ветку мобильных резервных копий. Дальше перейдём к анализу вредоносного ПО:
динамический анализ в песочнице и разбор shellcode. Главное запомни: **`.ab` — это tar в
обёртке; сначала читай заголовок, потом распаковывай payload**.

## Где пригодится

- DFIR по Android: быстрый разбор логической копии.
- CTF-категория Forensics с файлом `.ab`.
- Мобильные расследования при недоступности физического образа.
''',
)

# --------------------------------------------------------------------------
# Malware deep — parent forensics-malware-advanced (4 -> 6)
# --------------------------------------------------------------------------

lesson(
    "mal-dynamic-sandbox",
    "Динамический анализ в песочнице: Cuckoo/CAPE",
    "forensics-malware-advanced", 5, "hard", 60,
    "malware, sandbox, cuckoo, cape, dynamic, behavior, forensics",
    "[forensics-malware-advanced, mal-static]",
    ["Malware analysis", "DFIR / Incident Response", "Threat Hunting"],
    "Как работает динамический анализ в песочнице (Cuckoo/CAPE), что даёт отчёт о поведении и как читать его ключевые разделы.",
    dict(
        title="Практика: разбор отчёта песочницы",
        toolset=["core", "grep", "strings"],
        files=["task.md", "report.txt"],
        hints=[
            "Посмотри отчёт: `cat report.txt`.",
            "Найди сетевую активность: `grep -i http report.txt`.",
            "Ищи метку: `grep nto report.txt`.",
            "Собери ответ: `grep nto report.txt > found.txt`.",
        ],
        flag="nto{s4ndb0x_b3h4v10r}",
        task=("# Задача: отчёт песочницы\n\n"
              "`report.txt` — фрагмент отчёта динамического анализа.\n"
              "Найди, что образец делает в сети, и метку.\n\n"
              "1. `cat report.txt`.\n"
              "2. `grep -i http report.txt`.\n"
              "3. `grep nto report.txt > found.txt`.\n"),
        seeds={
            "report.txt": (
                "CAPE sandbox report\n"
                "sample: invoice.doc.exe  sha256: 9f2c...c1\n"
                "processes:\n"
                "  invoice.doc.exe (pid 1044) -> cmd.exe (pid 1108) -> powershell.exe (pid 1112)\n"
                "http requests:\n"
                "  GET http://198.51.100.9/p.sh\n"
                "  POST http://198.51.100.9/gate.php\n"
                "dns:\n"
                "  cdn.example.net -> 198.51.100.9\n"
                "dropped files:\n"
                "  C:/Users/jdoe/AppData/Local/Temp/p.sh\n"
                "registry keys written:\n"
                "  HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater\n"
                "note: sandbox marker nto{s4ndb0x_b3h4v10r}\n"),
        },
    ),
    body=r'''
## Вопрос, с которого всё начинается

У тебя есть подозрительный файл, но запускать его на рабочей машине нельзя. Как узнать, что
он делает, безопасно? Ответ — **песочница**: изолированная виртуальная машина, куда образец
запускают и записывают всё, что он делает.

## Наш пример: отчёт по образцу

Перед нами отчёт песочницы **CAPE** (развитие Cuckoo) по файлу `invoice.doc.exe`. Отчёт
состоит из разделов: процессы, сетевые запросы, DNS, созданные файлы, изменения реестра.
Разберём их по порядку.

## Шаг 1: что такое динамический анализ

**Статический** анализ смотрит на файл, не запуская его (строки, импорты, дизассемблер).
**Динамический** — запускает в контролируемой среде и наблюдает поведение. Песочница
записывает: созданные процессы, обращения к файлам и реестру, сетевые соединения, вызовы
API. Плюс динамики — ты видишь **реальное** поведение, включая расшифрованный payload.
Минус — образец может определить, что он в песочнице, и ничего не сделать.

## Шаг 2: цепочка процессов

```
invoice.doc.exe (pid 1044) -> cmd.exe (pid 1108) -> powershell.exe (pid 1112)
```

Дерево процессов — первое, на что смотрят. Здесь документ запускает `cmd.exe`, а тот —
`powershell.exe`. Это классика: офисный документ запускает shell, а через PowerShell
скачивает и выполняет код. Такая цепочка сама по себе — сильный индикатор вредоноса
(нормальный документ не должен порождать PowerShell).

## Шаг 3: сетевые запросы и DNS

```
GET  http://198.51.100.9/p.sh
POST http://198.51.100.9/gate.php
cdn.example.net -> 198.51.100.9
```

Сетевой раздел даёт **инфраструктуру**: домены, IP, URL. Здесь образец скачивает скрипт
`p.sh` и стучится на `gate.php` — вероятно, панель управления (C2). Эти IOC (индикаторы
компромисса) можно сразу занести в блок-листы и использовать для поиска других заражённых
машин по сетевым логам.

## Шаг 4: файлы и реестр

```
dropped: C:/Users/jdoe/AppData/Local/Temp/p.sh
registry: HKCU\...\Run\Updater
```

Созданный файл `p.sh` — это скачанный payload. Запись в ключе `Run` — **закрепление**: при
следующем входе образец запустится снова. Динамический отчёт показывает и то, и другое, что
позволяет восстановить полную цепочку: доставка → скачивание → выполнение → закрепление.

## Шаг 5: как читать отчёт правильно

Песочница — не истина в последней инстанции. Образец может «спать» (проверять окружение),
обнаруживать VM и вести себя иначе, чем на реальной машине. Поэтому:

- сравнивай поведение при разных конфигурациях песочницы;
- дополняй динамику статикой (строки, конфиг, деobfuscation);
- проверяй, не «замолчал» ли образец из-за anti-VM;
- используй сетевые IOC для hunting по инфраструктуре.

CAPE дополнительно умеет распаковывать payload из памяти и строить сигнатуры — это сильно
экономит время при разборе упакованных образцов.

## Что мы теперь знаем

- Песочница запускает образец изолированно и записывает поведение.
- Ключевые разделы отчёта: процессы, сеть, DNS, файлы, реестр.
- Дерево процессов с shell/PowerShell — признак вредоноса.
- Сетевой раздел даёт IOC для hunting.
- Динамику всегда дополняют статикой и учитывают anti-VM.

## Квиз

Проверь себя.

```quiz
- question: Чем динамический анализ отличается от статического?
  options: ['Смотрит строки файла', 'Запускает образец в изолированной среде и наблюдает поведение', 'Только считает хеш', 'Работает без виртуальной машины']
  answer: 1
  explanation: Динамический анализ наблюдает реальное поведение образца в песочнице.
- question: Что означает цепочка doc.exe -> cmd.exe -> powershell.exe?
  options: ['Нормальное поведение документа', 'Документ запускает shell и PowerShell — признак вредоноса', 'Ошибка песочницы', 'Обновление системы']
  answer: 1
  explanation: Офисный документ не должен порождать shell/PowerShell — это типичный признак атаки.
- question: Что даёт сетевой раздел отчёта?
  options: ['Хеш файла', 'IOC: домены, IP, URL инфраструктуры', 'Версию Windows', 'Имя пользователя']
  answer: 1
  explanation: Сетевые запросы раскрывают инфраструктуру (C2, серверы доставки) — готовые IOC.
- question: Почему песочнице нельзя доверять слепо?
  options: ['Она всегда медленная', 'Образец может обнаружить VM и изменить поведение', 'Она не пишет сеть', 'Она не поддерживает Windows']
  answer: 1
  explanation: Anti-VM/anti-sandbox заставляет образец вести себя иначе, поэтому динамику дополняют статикой.
```

## Куда дальше

Дальше — разбор shellcode: как анализировать позиционно-независимый код, извлечённый из
памяти. Главное запомни: **песочница показывает поведение, а не гарантию — её отчёт это
гипотеза, которую подтверждают статикой**.

## Где пригодится

- Malware analysis: первичный разбор неизвестного образца.
- DFIR: восстановление цепочки «доставка → выполнение → закрепление».
- Threat hunting: извлечение IOC и поиск по инфраструктуре.
''',
)

lesson(
    "mal-shellcode",
    "Анализ shellcode: извлечение и эмуляция",
    "forensics-malware-advanced", 6, "expert", 60,
    "malware, shellcode, emulation, scdbg, position-independent, forensics",
    "[forensics-malware-advanced, mal-unpacking]",
    ["Malware analysis", "Exploit development", "DFIR / Incident Response"],
    "Что такое shellcode, как его извлекают из памяти и файлов, как анализируют через эмуляцию и что искать в строках.",
    dict(
        title="Практика: строки из shellcode",
        toolset=["core", "grep", "strings", "xxd"],
        files=["task.md", "sc_strings.txt"],
        hints=[
            "Посмотри извлечённые строки: `cat sc_strings.txt`.",
            "Найди API-вызовы: `grep -i 'LoadLibrary\\|WinExec' sc_strings.txt`.",
            "Ищи метку: `grep nto sc_strings.txt`.",
            "Собери ответ: `grep nto sc_strings.txt > found.txt`.",
        ],
        flag="nto{sh3llc0d3_3mul4t10n}",
        task=("# Задача: анализ shellcode\n\n"
              "`sc_strings.txt` — печатаемые строки, извлечённые из shellcode.\n"
              "Определи, что shellcode делает, и найди метку.\n\n"
              "1. `cat sc_strings.txt`.\n"
              "2. `grep -i 'LoadLibrary\\|WinExec' sc_strings.txt`.\n"
              "3. `grep nto sc_strings.txt > found.txt`.\n"),
        seeds={
            "sc_strings.txt": (
                "strings extracted from shellcode (offset: string)\n"
                "0x0000  kernel32.dll\n"
                "0x0010  LoadLibraryA\n"
                "0x0020  WinExec\n"
                "0x0030  urlmon.dll\n"
                "0x0040  URLDownloadToFileA\n"
                "0x0050  http://198.51.100.9/p.sh\n"
                "0x0060  cmd.exe /c start /b\n"
                "note: shellcode marker nto{sh3llc0d3_3mul4t10n}\n"),
        },
    ),
    body=r'''
## Вопрос, с которого всё начинается

В памяти процесса ты нашёл область байтов, которая не похожа на данные и начинает
выполняться. Это **shellcode** — небольшой позиционно-независимый код, который выполняет
полезную нагрузку. Как его извлечь и понять, что он делает, не запуская?

## Наш пример: блок shellcode

Shellcode — это машинный код (обычно x86/x64), который должен работать по любому адресу,
поэтому он **позиционно-независимый** (PIC): не использует абсолютные адреса, а находит
функции динамически. Начнём с извлечения и посмотрим на строки.

## Шаг 1: откуда берётся shellcode

Shellcode появляется в нескольких местах:

- внутри эксплойта (переполнение буфера, use-after-free);
- как payload после **распаковки** упакованного файла;
- в памяти процесса, куда его впрыснули (injection);
- в сетевом трафике (загрузка второй стадии).

Найти его можно в дампе памяти (Volatility, `malfind`), в образе файла (после unpacking) или
в перехваченном трафике.

## Шаг 2: почему нельзя просто запустить

Shellcode рассчитан на конкретную среду: он ищет `kernel32.dll` в памяти, вызывает функции
по хешу или имени. Запустить его «как есть» на другой системе опасно и ненадёжно. Поэтому
используют **эмуляцию** — пошаговое исполнение в контролируемом интерпретаторе, который
записывает вызовы, но не выполняет реальные действия.

## Шаг 3: извлечение строк

Первый шаг — вытащить печатаемые строки:

```
$ strings -n 6 shellcode.bin
kernel32.dll
LoadLibraryA
WinExec
urlmon.dll
URLDownloadToFileA
http://198.51.100.9/p.sh
cmd.exe /c start /b
```

Уже из этого видно сценарий: shellcode загружает `urlmon.dll`, вызывает
`URLDownloadToFileA` (скачать файл), затем `WinExec` для запуска. То есть поведение —
«скачай и запусти» (downloader). Строки часто раскрывают намерение без дизассемблирования.

## Шаг 4: эмуляция

Для точного анализа используют эмуляторы (`scdbg`, `Speakeasy`, `Qiling`). Они выполняют
инструкции и логируют вызовы API:

```
$ scdbg -f shellcode.bin
...
CreateFileA("C:\\Users\\...\\p.sh")
URLDownloadToFileA(...)
WinExec("cmd.exe /c start /b p.sh")
```

Эмулятор показывает последовательность вызовов и аргументы. Это безопасно: реальные файлы
не создаются, сеть не используется (можно подменить функции заглушками). Так получают
поведенческий отчёт по shellcode.

## Шаг 5: как быть с обфускацией

Продвинутый shellcode шифрует строки и вычисляет адреса функций по хешам, чтобы избежать
подозрительных строк. Тогда приёмы такие: искать таблицы хешей, точки вызова API по
регистру, расшифровывать строки эмуляцией (эмулятор сам подставит результат), использовать
`Speakeasy`/`Qiling` для распаковки. Часто после эмуляции строки и API «проявляются» сами.

## Что мы теперь знаем

- Shellcode — позиционно-независимый машинный код полезной нагрузки.
- Он появляется в эксплойтах, после unpacking, при injection, в трафике.
- `strings` даёт быстрый ответ о намерении (скачать/запустить).
- Эмуляторы (`scdbg`, `Speakeasy`, `Qiling`) безопасно логируют вызовы API.
- Обфускация обходится эмуляцией и расшифровкой строк.

## Квиз

Проверь себя.

```quiz
- question: Почему shellcode называют позиционно-независимым?
  options: ['Он работает только по одному адресу', 'Он может выполняться по любому адресу и находит функции динамически', 'Он всегда зашифрован', 'Он не использует память']
  answer: 1
  explanation: PIC-shellcode не опирается на абсолютные адреса, поэтому работает где угодно.
- question: Что показывает команда strings для shellcode?
  options: ['Хеш файла', 'Печатаемые строки (имена API, URL, команды)', 'Размер памяти', 'Список процессов']
  answer: 1
  explanation: Строки раскрывают намерение: имена функций, URL, команды.
- question: Зачем нужна эмуляция shellcode?
  options: ['Чтобы ускорить загрузку', 'Чтобы безопасно исполнять код пошагово и логировать вызовы', 'Чтобы зашифровать код', 'Чтобы сжать файл']
  answer: 1
  explanation: Эмулятор исполняет инструкции в контролируемой среде и логирует API без реальных действий.
- question: Как обходят обфускацию строк в shellcode?
  options: ['Удаляют строки', 'Эмуляцией и расшифровкой: эмулятор подставляет результат', 'Перезагрузкой', 'Сжатием']
  answer: 1
  explanation: Эмуляция естественным образом расшифровывает строки и проявляет вызовы API.
```

## Куда дальше

Мы разобрали динамику и shellcode. Дальше — скриптовый вредонос (JavaScript/PowerShell) и
анти-анализ. Главное запомни: **shellcode анализируют эмуляцией, а `strings` часто сразу
говорят, что он делает**.

## Где пригодится

- Malware analysis: разбор payload эксплойтов и упакованных образцов.
- Exploit development: понимание чужой полезной нагрузки.
- DFIR: восстановление действий после injection.
''',
)
print("B10-B done")
