---
id: forensics-macos-artifacts
title: "Артефакты macOS: FSEvents, quarantine, unified logs"
category: forensics
parent: forensics-apfs
difficulty: hard
order: 1
tags: [macos, fsevents, quarantine, unified-log, keychain, apfs, dfir]
prerequisites: [forensics-apfs, forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ macOS"
estimated_minutes: 45
summary: "Ключевые артефакты macOS: FSEvents, Unified Log, quarantine (com.apple.quarantine), LaunchAgents/Daemons, Keychain, Time Machine — и как их извлекать."
---

## Вопрос, с которого всё начинается

На рабочем маке пользователь пожаловался: «что-то само открывает окна и просит пароль». Сняли образ диска. Вопрос: какой файл это делает, откуда он взялся и как закрепился в системе, чтобы запускаться после перезагрузки?

macOS оставляет свои, непохожие на Windows, следы. Мы знаем файловую систему APFS (`forensics-apfs`) и артефакты Windows (`forensics-windows-artifacts`) — теперь разберём один образ macOS по её собственным артефактам.

## Наш пример: образ с подозрительным `update.app`

Начнём с самого файла, который подозреваем — `~/Downloads/update.app`. Расширение `.app` в macOS означает **бандл** — это каталог, который система показывает как одну программу.

Первым делом смотрим **расширенный атрибут** (xattr) `com.apple.quarantine`. Это метка, которую macOS вешает на любой скачанный файл: она говорит, откуда он пришёл.

```bash
$ xattr -p com.apple.quarantine /evidence/Users/bob/Downloads/update.app
0083;5f8a1b2c;Safari;F0E5A1B2-...
```

Строка кодирует четыре поля: флаги (`0083`), время скачивания в hex (`5f8a1b2c`), приложение-загрузчик (`Safari`) и UUID. Время легко перевести в Unix-формат:

```bash
$ python3 -c "import datetime;print(datetime.datetime.utcfromtimestamp(int('5f8a1b2c',16)))"
2020-10-17 12:34:20
```

Это **атрибуция загрузки**: файл пришёл через Safari. Рядом лежит xattr `com.apple.metadata:kMDItemWhereFroms` — в нём бывает полный URL источника.

## Шаг 1: как файл закрепился в системе

Запуск программ «при входе» в macOS управляет служба `launchd`. Она читает конфиги-`plist` (XML-файлы свойств) из специальных каталогов. `LaunchAgent` работает в сессии пользователя, `LaunchDaemon` — на уровне системы (от root, без входа пользователя).

Проверяем пользовательские агенты:

```bash
$ find /evidence/Users/bob/Library/LaunchAgents -name '*.plist'
/evidence/Users/bob/Library/LaunchAgents/com.evil.updater.plist

$ plutil -p /evidence/Users/bob/Library/LaunchAgents/com.evil.updater.plist
{
  "ProgramArguments" => [ "/Users/bob/Library/evil/run.sh" ]
  "RunAtLoad" => 1
  "Label" => "com.evil.updater"
}
```

`plutil -p` печатает plist в читаемом виде. Видим `RunAtLoad = 1` — программа запускается сразу при загрузке агента, то есть при входе пользователя. Это **персистентность**: вредоносный скрипт `run.sh` из `~/Library/evil/` будет стартовать каждый раз.

## Шаг 2: когда файл появился (FSEvents)

macOS ведёт журнал изменений файловой системы — **FSEvents**, в каталоге `/.fseventsd/`. Он записывает создание, удаление и переименование файлов с временем и флагами. Даже если файл удалили, запись о нём останется.

Записи хранятся в бинарных файлах, поэтому нужен парсер:

```bash
$ fseventsparse /evidence/.fseventsd/ > fsevents.csv
$ grep -i evil fsevents.csv | head -3
1770890000, /Users/bob/Library/evil/run.sh, Created
1770890000, /Users/bob/Library/evil, Created
```

Теперь мы знаем **точное время** появления вредоносного каталога — это событие можно сопоставить с другими артефактами.

## Шаг 3: что записал Unified Log

Современный macOS пишет почти все события в **Unified Log** — бинарный, сжатый, структурированный журнал в `/var/db/diagnostics/*.tracev3`. Это аналог Windows EVTX. На живой системе его читают командой `log`, а на образе — парсером.

```bash
$ unifiedlog_parser /evidence/var/db/diagnostics/*.tracev3 > unified.csv
$ grep -i evil unified.csv | head -3
2025-10-06 14:20:11  runningboardd  ... /Users/bob/Library/evil/run.sh
2025-10-06 14:20:11  kernel         ... exec /Users/bob/Library/evil/run.sh
```

Здесь виден **факт запуска** скрипта и подсистема, которая это сделала (`runningboardd` — служба управления процессами). Unified Log — основной источник событий: входы, запуски, сетевые соединения.

## Шаг 4: пароли и данные приложений

Если задача — понять, что злоумышленник успел прочитать, смотрим **Keychain** — хранилище паролей, сертификатов и ключей macOS (`~/Library/Keychains/login.keychain-db`). Оно защищено паролем входа, но с ним разбирается инструментом `chainbreaker`.

Приложения macOS хранят данные в своих SQLite-базах. Например, история Safari лежит в `~/Library/Safari/History.db`, а iMessage — в `~/Library/Messages/chat.db`:

```bash
$ sqlite3 /evidence/Users/bob/Library/Safari/History.db \
  "SELECT url FROM history_visits JOIN history_items ON history_visits.history_item=history_items.id LIMIT 3;"
http://evil.tld/download
http://evil.tld/payload
```

Важная деталь: время в базах macOS часто хранится в секундах с 2001 года, а не с Unix-эпохи 1970-го. Разница — константа `978307200`; чтобы получить Unix-время, её прибавляют.

## Шаг 5: индекс Spotlight и активность приложений

Ещё два источника, о которых легко забыть. **Spotlight** — поисковый индекс macOS, лежит в `.Spotlight-V100`. Он хранит метаданные файлов (путь, тип, даты), причём запись может остаться даже после удаления самого файла:

```bash
$ python3 spotlight_parser.py /evidence/.Spotlight-V100/ > spotlight.csv
$ grep -i evil spotlight.csv | head -3
```

Второй — **knowledgeC.db** (`~/Library/Application Support/Knowledge/`). Это база активности: какие приложения использовались, когда и с какими файлами или URL. Отличный источник таймлайна:

```bash
$ sqlite3 /evidence/Users/bob/Library/Application\ Support/Knowledge/knowledgeC.db ".tables"
```

Обе базы читаются тем же `sqlite3`, что и любая другая SQLite-база.

## Если задача — восстановить состояние до атаки

На macOS есть то, чего часто нет на Windows: **Time Machine** — локальные APFS-снапшоты с версиями файлов. Если файл удалили или изменили, старую версию можно достать из снапшота (механизм снапшотов разбирали в `forensics-apfs`). Это позволяет увидеть систему до заражения и точно установить, что появилось после.

Ещё стоит помнить об **ограничениях**: System Integrity Protection (SIP) закрывает системные файлы, Unified Log быстро ротируется и сжат, а если диск защищён FileVault — нужен ключ расшифровки. Поэтому образ всегда снимают **до** анализа, а не работают на живом маке (живая система меняет свои же артефакты).

## Полный разбор: от quarantine к закреплению

Соберём разбор `update.app` в один сценарий.

| Артефакт | Где | Что даёт |
|----------|-----|----------|
| `com.apple.quarantine` | xattr файла | откуда скачан |
| FSEvents | `.fseventsd/` | когда появился |
| Unified Log | `.tracev3` | что записала система |
| LaunchAgents/Daemons | `~/Library`, `/Library` | автозапуск |
| Keychain | `login.keychain-db` | пароли |
| Time Machine | бэкапы | состояние «до» |

1. **Происхождение.** `xattr -p com.apple.quarantine update.app` — источник загрузки.
2. **Появление.** FSEvents — журнал изменений ФС; восстанавливает порядок событий.
3. **Что делал.** Unified Log (`log show`) — запуск, сетевые события.
4. **Закрепление.** LaunchAgent/Daemon — ключевой признак персистентности.
5. **Секреты.** Keychain — пароли/сертификаты (может быть защищён паролем входа).

## Частые вопросы

**FSEvents — это журнал запусков?** Нет, это изменения файловой системы; запуск подтверждают Unified Log/Spotlight.

**Почему Unified Log «пустой»?** Он ротируется и ограничен по размеру — старые записи исчезают.

**Как прочитать Keychain?** С ключом из памяти/логином пользователя; иначе зашифрован.

**Time Machine полезен?** Да: даёт «до»-состояние для сравнения с «после».

## Что мы теперь знаем

- `com.apple.quarantine` (xattr) даёт **источник** файла: браузер, время, URL.
- Автозапуск в macOS — `LaunchAgents`/`LaunchDaemons`; `RunAtLoad=1` = запуск при входе.
- FSEvents хранит историю изменений файлов, включая удалённые, и время появления.
- Unified Log (`*.tracev3`) — основной журнал событий, аналог EVTX.
- Keychain хранит пароли, а приложения — SQLite-базы (Safari, Messages).
- Время в базах macOS — секунды с 2001 (`+978307200` = Unix).

## Квиз

Проверь себя.

```quiz
- question: "Что означает атрибут com.apple.quarantine у файла?"
  options:
    - "шифрование файла"
    - "метка скачанного файла с источником (агент, время, URL)"
    - "права доступа"
    - "сжатие"
  answer: 1
  explanation: "Quarantine фиксирует, откуда и когда файл скачан — это атрибуция загрузки."
- question: "Где в macOS настраивается автозапуск программ?"
  options:
    - "реестр"
    - "LaunchAgents / LaunchDaemons"
    - "SAM"
    - "MFT"
  answer: 1
  explanation: "launchd читает plist-конфиги из LaunchAgents (пользователь) и LaunchDaemons (система)."
- question: "Что хранит FSEvents?"
  options:
    - "пароли"
    - "журнал изменений файловой системы с временем и флагами"
    - "сетевой трафик"
    - "ключи Keychain"
  answer: 1
  explanation: "FSEvents фиксирует создание/удаление/переименование файлов, в том числе уже удалённых."
- question: "Где хранится Unified Log macOS?"
  options:
    - "/var/log/syslog"
    - "/var/db/diagnostics/*.tracev3"
    - "/etc/logs"
    - "~/log"
  answer: 1
  explanation: "Unified Log — бинарные сжатые файлы .tracev3 в /var/db/diagnostics."
- question: "Какой xattr хранит полный URL источника загрузки?"
  options:
    - "com.apple.metadata:kMDItemWhereFroms"
    - "com.apple.quarantine"
    - "com.apple.ResourceFork"
    - "com.apple.FinderInfo"
  answer: 0
  explanation: "kMDItemWhereFroms содержит URL/приложение, откуда скачан файл."
```

## Куда дальше

Мы разобрали образ macOS по её артефактам. В следующем уроке (`forensics-mobile-android`) мы перейдём к мобильным устройствам и разберём, как извлечь данные из Android через ADB и бэкапы. А пока главное запомни: **на macOS источник файла виден в `com.apple.quarantine`, персистентность живёт в `LaunchAgents`, а события — в Unified Log**.

## Где пригодится

- **CTF Forensics:** задачи с образами macOS.
- **DFIR:** расследование инцидентов на маках.
- **Анализ macOS:** корпоративные ноутбуки Apple.
- **SOC:** детекты на персистентность через LaunchAgents.
- **Пентест:** понимание следов, которые оставляет атакующий.
