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
macOS оставляет специфичный набор артефактов, отличающийся от Windows. Ключевые источники — FSEvents (журнал изменений файлов), Unified Log (системные события), quarantine-атрибуты (источник загрузки), LaunchAgents/Daemons (автозапуск), Keychain (пароли) и Time Machine (версии). Этот урок — про их извлечение и анализ.

## FSEvents

`/.fseventsd/` хранит журнал изменений файловой системы: создание, удаление, переименование файлов и папок, с флагами и временем. Даже если файл удалён, FSEvents покажет, что он существовал.

```bash
# инструменты: fseventsparse, FSEventsParser, mac_apt
$ fseventsparse /path/to/.fseventsd/ > fsevents.csv
$ python3 FSEventsParser.py -s /evidence -o out/
```

FSEvents хранит записи в бинарных файлах (`0000000000000001` и т. д.); парсеры декодируют путь и флаги (Created/Removed/Renamed/Modified). Это мощный источник таймлайна.

## Unified Log

Современный macOS логирует всё в **Unified Log** (`/var/db/diagnostics/*.tracev3`). Это бинарный, сжатый, структурированный лог с тысячами подсистем (процессы, сеть, авторизация, приложения).

```bash
# инструменты: macos-unifiedlogs (Mandiant), UnifiedLogReader, log (на macOS)
$ unifiedlog_parser /path/to/diagnostics/*.tracev3 > unified.csv
$ python3 -m macos_unifiedlogs.cli /evidence
# на живой macOS
$ log show --last 1h --predicate 'process == "sshd"'
$ log collect --output system.logarchive
```

Фильтруйте по процессу/подсистеме/сообщению: входы, запуски, сетевые соединения.

## Quarantine и атрибуция загрузки

Расширенный атрибут `com.apple.quarantine` показывает, откуда скачан файл (браузер, приложение, URL), — бесценно для атрибуции.

```bash
$ xattr -p com.apple.quarantine /path/file
0083;5f8a1b2c;Safari;F0E5...
# структура: flags;timestamp(hex);agent;UUID
# расшифровать время (hex -> unix)
$ python3 -c "print(int('5f8a1b2c',16))"
# инструменты: mac_apt, mac_apt quarantine
```

Также полезны `com.apple.metadata:kMDItemWhereFroms` (URL загрузки) и `com.apple.metadata:kMDItemDownloadedDate`.

```bash
$ xattr -p com.apple.metadata:kMDItemWhereFroms /path/file | xxd
```

## LaunchAgents / LaunchDaemons

Автозапуск в macOS — через `launchd` (plist-файлы):

| Путь | Тип |
|------|-----|
| `/Library/LaunchAgents` | агент (все пользователи) |
| `/Library/LaunchDaemons` | демон (система) |
| `~/Library/LaunchAgents` | агент пользователя |
| `/System/Library/...` | системные (SIP) |

```bash
$ find /evidence -path '*Launch*' -name '*.plist'
$ plutil -p /path/com.evil.agent.plist
{ "ProgramArguments" => [ "/Users/bob/Library/evil/run.sh" ], "RunAtLoad" => 1 }
```

Также `login items`, `cron`, `periodic`, `emond`, `StartupItems` (устарело).

## Keychain и Time Machine

**Keychain** (`~/Library/Keychains/login.keychain-db`) хранит пароли, сертификаты, ключи. Разбор — `chainbreaker`, `security` (на macOS).

```bash
$ python3 chainbreaker.py login.keychain-db -p password
```

**Time Machine** — локальные снапшоты APFS с версиями файлов (см. `forensics-apfs`): удалённое можно восстановить из снапшота.

## Прочие артефакты

| Артефакт | Путь | Что даёт |
|----------|------|----------|
| Unified Log | `/var/db/diagnostics` | события |
| FSEvents | `/.fseventsd` | изменения файлов |
| Quarantine | xattr | источник загрузки |
| Spotlight | `.Spotlight-V100` | метаданные, история |
| plist | `~/Library/Preferences` | настройки/история |
| Safari | `~/Library/Safari/History.db` | история |
| Messages | `~/Library/Messages/chat.db` | iMessage |
| KnowledgeC | `~/Library/Application Support/Knowledge/knowledgeC.db` | активность приложений |

```bash
$ sqlite3 ~/Library/Messages/chat.db "SELECT text FROM message LIMIT 5;"
$ sqlite3 ~/Library/Application\ Support/Knowledge/knowledgeC.db ".tables"
```

## Разобранный пример

Дан образ macOS. Нужно найти загруженный и закреплённый файл.

```bash
# 1. Quarantine: откуда скачан
$ xattr -p com.apple.quarantine /evidence/Users/bob/Downloads/update.app
0083;5f8a1b2c;Safari;...
# 2. LaunchAgent: закрепление
$ plutil -p /evidence/Users/bob/Library/LaunchAgents/com.evil.updater.plist
{ ProgramArguments => [ "/Users/bob/Library/evil/run.sh" ] }
# 3. FSEvents: когда появился
$ fseventsparse /evidence/.fseventsd | grep -i evil | head
# 4. Unified Log: запуск
$ unifiedlog_parser /evidence/var/db/diagnostics/*.tracev3 | grep -i evil | head
```

## Справочная таблица

| Задача | Инструмент |
|--------|-----------|
| FSEvents | `fseventsparse`, `mac_apt` |
| Unified Log | `macos-unifiedlogs`, `log` |
| Quarantine | `xattr`, `mac_apt` |
| LaunchAgents | `plutil`, `find` |
| Keychain | `chainbreaker` |
| Spotlight | `mdfind`/парсеры |

## Частые ошибки

- **Игнорировать FSEvents** — там история удалённых файлов.
- **Не читать Unified Log** — основной источник событий.
- **Забывать про xattr** — quarantine даёт атрибуцию.
- **Не проверять LaunchAgents** — там персистентность.
- **Путать агент и демон** — область действия разная.
- **Анализировать живой macOS без образа** — меняет состояние.

## Что дальше / решение

Конвейер: `xattr` (quarantine) → `plutil`/`find` (LaunchAgents) → `fseventsparse` (изменения) → `unifiedlog_parser` (события) → SQLite (приложения). Связка: `forensics-apfs` (ФС), `forensics-macos-artifacts` (глубоко), `forensics-plaso` (таймлайн), `forensics-sqlite`.

## Spotlight и knowledgeC

**Spotlight** (`.Spotlight-V100`) индексирует метаданные файлов: путь, тип, даты, авторы. Даже после удаления файла индекс может хранить запись.

```bash
# извлечь индекс (mac_apt, spotlight_parser)
$ python3 spotlight_parser.py /evidence/.Spotlight-V100/ > spotlight.csv
$ grep -i evil spotlight.csv | head
# на живой macOS
$ mdfind -onlyin /Users 'kMDItemFSName == "*evil*"'
```

**knowledgeC.db** (`~/Library/Application Support/Knowledge/knowledgeC.db`) — база активности: какие приложения использовались, когда, с какими файлами/URL. Отличный источник таймлайна.

```bash
$ sqlite3 knowledgeC.db "SELECT ZOBJECT.ZVALUESTRING, datetime(ZOBJECT.ZCREATIONDATE+978307200,'unixepoch') FROM ZOBJECT JOIN ZSTRUCTUREDMETADATA ON ZOBJECT.ZSTRUCTUREDMETADATA=ZSTRUCTUREDMETADATA.Z_PK WHERE ZSTRUCTUREDMETADATA.Z_DKAPPINTENTMETADATAKEY__SERIALIZEDINTERACTION IS NOT NULL LIMIT 5;"
```

## Safari и браузеры macOS

```bash
$ sqlite3 ~/Library/Safari/History.db "SELECT url, datetime(visit_time+978307200,'unixepoch') FROM history_visits JOIN history_items ON history_visits.history_item=history_items.id ORDER BY visit_time DESC LIMIT 5;"
$ sqlite3 ~/Library/Safari/Downloads.plist 2>/dev/null
$ ls ~/Library/Caches/com.apple.Safari/
```

Время Safari — секунды с 2001 (`978307200` смещение к Unix).

## Сводный чек-лист

1. `xattr` — quarantine/WhereFroms (источник файлов).
2. `plutil`/`find` — LaunchAgents/Daemons (персистентность).
3. `fseventsparse` — история изменений файлов.
4. `unifiedlog_parser` — системные события.
5. Spotlight — индекс метаданных.
6. knowledgeC.db — активность приложений.
7. Safari/браузеры — история.
8. SQLite-приложения (Messages и др.).

## Ограничения

- **SIP** защищает системные файлы — часть артефактов недоступна.
- **Unified Log** быстро ротируется и сжат.
- **FSEvents** может быть отключён или обрезан.
- **Зашифрованный диск** (FileVault) — нужен ключ.
- **APFS COW** — старые версии в checkpoint, но разбор сложнее.

## Сравнение с Windows

| Артефакт | Windows | macOS |
|----------|---------|-------|
| Журнал событий | EVTX | Unified Log |
| Изменения файлов | USN | FSEvents |
| Автозапуск | Run/Services/Task | LaunchAgents/Daemons |
| Ярлыки/недавние | LNK/Jump Lists | `.recently-used`, Recent Items |
| Реестр | hives | plist |
| Пароли | DPAPI/SAM | Keychain |
| Браузер | History/Cookies | Safari History.db |

Понимание соответствий помогает переносить методики: как USN↔FSEvents, так Run↔LaunchAgents.

## Инструменты: сводка

| Инструмент | Задача |
|-----------|--------|
| `mac_apt` | комплексный разбор |
| `unifiedlog_parser` | Unified Log |
| `fseventsparse` | FSEvents |
| `plutil` | plist |
| `xattr` | quarantine |
| `chainbreaker` | Keychain |
| `sqlite3` | app-базы |
| `apfs-fuse` | монтирование APFS |

## Практические приёмы

- **Unified Log** — сначала `log show`/`unifiedlog_parser` по процессу.
- **FSEvents** — восстанавливает историю удалённых файлов.
- **Quarantine** — быстрая атрибуция загрузки.
- **LaunchAgents** — обязательная проверка на персистентность.
- **Safari History.db** — время в секундах с 2001.
- **Time Machine** — удалённое из снапшотов.
- **Фиксируйте хеши** артефактов; работайте с копией.

## Квиз

```quiz
- question: "Где хранится Unified Log в macOS?"
  options:
    - "/var/log/syslog"
    - "/var/db/diagnostics/ (.tracev3)"
    - "/etc/logs"
    - "~/log"
  answer: 1
- question: "Что хранит FSEvents?"
  options:
    - "пароли"
    - "журнал изменений файловой системы (каталоги/время)"
    - "сетевой трафик"
    - "реестр"
  answer: 1
- question: "Что означает атрибут com.apple.quarantine?"
  options:
    - "шифрование"
    - "метка загруженного файла с источником (URL, агент, время)"
    - "права доступа"
    - "сжатие"
  answer: 1
- question: "Где persistence через автозапуск в macOS?"
  options:
    - "реестр"
    - "LaunchAgents / LaunchDaemons"
    - "SAM"
    - "MFT"
  answer: 1
- question: "Как восстановить состояние до атаки?"
  options:
    - "удалить логи"
    - "Time Machine / APFS-снапшоты"
    - "перезагрузить"
    - "ничего"
  answer: 1
```

## Где пригодится

- **CTF Forensics** — задачи с образами macOS.
- **DFIR** — расследование на маках.
- **Анализ macOS** — корпоративные маки.
- **SOC** — детекты на persistence.
- **Пентест** — понимание следов.
