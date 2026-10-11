---
id: forensics-sqlite
title: "Форензика SQLite"
category: forensics
parent: forensics-web-forensics
difficulty: hard
order: 1
tags: [sqlite, database, wal, freelist, browser, forensics, recovery]
prerequisites: [forensics-web-forensics]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Веб-форензика"
estimated_minutes: 45
summary: "Как читать SQLite-базы в форензике: WAL/journal, свободные страницы и восстановление удалённых записей, структура b-tree, типичные источники (браузеры, приложения)."
---
SQLite — самая распространённая встраиваемая база: её используют браузеры, мобильные приложения, мессенджеры, macOS/Windows-артефакты. Для форензика важно не только прочитать текущие данные, но и восстановить **удалённые записи** из свободных страниц и WAL-журнала. Этот урок — про структуру SQLite, WAL/journal, freelist и восстановление.

## Структура базы

SQLite-файл состоит из страниц (обычно 4 КБ). Первая страница — заголовок (`SQLite format 3\0`), затем страницы B-tree (таблицы/индексы), страницы **freelist** (свободные) и overflow-страницы (для больших записей).

```bash
$ xxd -l 16 app.db
00000000: 5351 4c69 7465 2066 6f72 6d61 7420 33  SQLite format 3
$ sqlite3 app.db "PRAGMA page_size; PRAGMA page_count; PRAGMA freelist_count;"
```

Заголовок содержит `page_size`, `page_count`, `freelist_head`, `schema_cookie` — всё это полезно для ручного анализа.

## Чтение данных

```bash
$ sqlite3 app.db ".tables"
$ sqlite3 app.db ".schema messages"
$ sqlite3 app.db "SELECT * FROM messages LIMIT 5;"
$ sqlite3 app.db ".dump" > dump.sql          # весь дамп
$ sqlite3 -header -csv app.db "SELECT * FROM users;" > users.csv
# GUI: DB Browser for SQLite
```

## WAL и journal

SQLite использует журналы для атомарности:
- **rollback journal** (`-journal`): старые страницы перед изменением.
- **WAL** (`-wal`, режим Write-Ahead Logging): новые страницы сначала в WAL, затем checkpoint в основную базу.
- **`-shm`**: разделяемая память для WAL.

Свежие данные часто лежат **только в WAL** и не перенесены в основную базу. Для полного анализа копируйте все три файла.

```bash
$ cp app.db app.db-wal app.db-shm /evidence/
$ sqlite3 app.db "PRAGMA journal_mode;"       # wal / delete
# WAL можно применить к базе (или читать в SQLite автоматически)
$ sqlite3 app.db "PRAGMA wal_checkpoint(FULL);"   # осторожно: меняет файл!
```

Не выполняйте checkpoint на оригинале — это изменит улику. Работайте с копией.

## Восстановление удалённых записей

Удаление строки освобождает страницу/ячейку, но данные остаются в **freelist** и в «неиспользуемом» пространстве страниц. Инструменты:

```bash
# sqlite3 .recover (встроено в SQLite 3.29+)
$ sqlite3 app.db ".recover" | grep -i 'secret' | head
# восстановить в новую базу
$ sqlite3 app.db ".recover" | sqlite3 recovered.db
# undark (специализированный)
$ undark -i app.db -o out/
# строковый поиск по файлу
$ strings app.db | grep -iE 'CTF\{|password|secret' | head
```

`undark` сканирует freelist и неиспользуемые области, извлекая «осиротевшие» записи, которые SQLite уже не показывает.

## Ручной анализ: B-tree и страницы

```bash
# дамп страниц
$ xxd app.db | grep -i 'CTF{'
# определить тип страницы (0x0D leaf table, 0x05 interior)
$ python3 -c "d=open('app.db','rb').read();print(d[100])"
# извлечь freelist
$ sqlite3 app.db "PRAGMA freelist_count;"
```

Инструменты вроде `sqlite-forensics`/`undark` автоматизируют обход B-tree и freelist.

## Типичные источники SQLite

| Источник | База |
|----------|------|
| Chrome/Edge | `History`, `Cookies`, `Login Data` |
| Firefox | `places.sqlite`, `cookies.sqlite` |
| WhatsApp | `msgstore.db` |
| Signal/Telegram | `signal.db`, `cache4.db` |
| iOS | `Manifest.db`, app-базы |
| macOS | `knowledgeC.db`, `Biome` |
| Windows | `ActivitiesCache.db`, `SRUDB.dat` (ESE, не SQLite) |

## Разобранный пример

Дан `msgstore.db` с удалённым сообщением.

```bash
# 1. Структура
$ sqlite3 msgstore.db ".tables"
# 2. Текущие сообщения
$ sqlite3 msgstore.db "SELECT key_remote_jid, substr(data,1,40) FROM messages LIMIT 3;"
# 3. Удалённые — через .recover
$ sqlite3 msgstore.db ".recover" | grep -i 'CTF{' | head
CTF{deleted_msg_recovered}
# 4. WAL: возможно, свежие записи там
$ cp msgstore.db* /evidence/ && sqlite3 /evidence/msgstore.db "SELECT count(*) FROM messages;"
# 5. undark
$ undark -i msgstore.db -o undark_out/
$ grep -ri 'CTF{' undark_out/ | head
```

## Справочная таблица

| Задача | Команда |
|--------|---------|
| Список таблиц | `.tables` |
| Схема | `.schema` |
| Дамп | `.dump` |
| Восстановить | `.recover` |
| Freelist | `PRAGMA freelist_count` |
| WAL | `-wal`/`-shm` |
| Спец-инструмент | `undark` |

## Частые ошибки

- **Не копировать `-wal`/`-shm`** — потеряете свежие данные.
- **Делать checkpoint на оригинале** — измените улику.
- **Игнорировать freelist** — удалённые записи остаются там.
- **Не использовать `.recover`** — обычный `SELECT` не покажет удалённое.
- **Забывать про overflow-страницы** — большие записи лежат отдельно.
- **Считать базу «пустой»** — проверьте WAL и freelist.

## Что дальше / решение

Конвейер: `.tables`/`.schema` (структура) → `SELECT` (данные) → `.recover`/`undark` (удалённое) → `-wal` (свежее) → строковый поиск. Связка: `forensics-browser` (браузеры), `forensics-mobile` (мобильные), `forensics-database` (СУБД), `forensics-deleted-recovery` (восстановление).

## Сравнение инструментов

| Инструмент | Что делает | Плюсы |
|-----------|-----------|-------|
| `sqlite3` | чтение, `.recover`, `.dump` | встроен, универсален |
| `undark` | восстановление из freelist/свободных | глубокое восстановление |
| `DB Browser for SQLite` | GUI | удобно для ручного разбора |
| `sqlite-forensics` | анализ структуры | специализирован |
| `Hindsight` | Chrome/Edge | готовые артефакты |
| `aleapp`/`ileapp` | mobile | готовые артефакты |

```bash
# сравнить текущий SELECT и восстановленные записи
$ sqlite3 app.db "SELECT count(*) FROM messages;"
$ sqlite3 app.db ".recover" | sqlite3 recovered.db
$ sqlite3 recovered.db "SELECT count(*) FROM messages;"
```

## Практические приёмы

- **Копируйте `-wal`/`-shm`** вместе с базой — иначе свежие данные потеряются.
- **Не делайте checkpoint** на оригинале.
- **Строковый поиск** (`strings app.db | grep`) часто быстрее показывает флаг/секрет, чем SQL.
- **`.recover`** восстанавливает структуру и «осиротевшие» записи.
- **`undark`** копает глубже в freelist и неиспользуемое пространство.
- **Время**: у каждого приложения своя эпоха — конвертируйте.
- **Несколько баз** (например, `History` + `History-journal`) — проверяйте все.

```bash
# поиск секрета без знания схемы
$ strings -n 8 app.db | grep -iE 'CTF\{|flag|password|token'
# дамп всех страниц в hex для ручного анализа
$ xxd app.db > app.hex
```

## Ограничения

- **VACUUM** перестраивает базу и уничтожает следы удалённых данных.
- **Шифрование** (SQLCipher) — без ключа не прочитать.
- **Перезапись freelist** — чем активнее приложение, тем меньше восстановится.
- **WAL-чекпоинт** переносит данные в основную базу, «стирая» разделение.
- **Сжатые BLOB** — данные могут быть сжаты приложением; распакуйте. Помните также, что приложения вроде WhatsApp/Telegram хранят медиа отдельными файлами, а в базе — лишь ссылки, поэтому для полной картины извлекайте и вложения.

## Краткое резюме

SQLite-базы — повсеместный источник в форензике: браузеры, мессенджеры, мобильные и macOS/Windows-артефакты. Для полного анализа критично копировать базу вместе с `-wal`/`-shm` (свежие данные часто только там) и восстанавливать удалённые записи через `.recover`/`undark` (freelist и неиспользуемые страницы). Помните про разные эпохи времени у приложений и про `VACUUM`, который уничтожает следы. Связка «текущий SELECT + восстановленное + WAL» даёт максимально полную картину.

## Квиз

```quiz
- question: "Где могут лежать незакоммиченные данные SQLite?"
  options:
    - "в -wal"
    - "в .schema"
    - "в PRAGMA page_size"
    - "в индексе"
  answer: 0
- question: "Что показывает PRAGMA freelist_count > 0?"
  options:
    - "база зашифрована"
    - "есть свободные страницы, потенциально с удалёнными данными"
    - "база пуста"
    - "это WAL"
  answer: 1
- question: "Какая встроенная команда восстанавливает максимум записей, включая удалённые?"
  options:
    - "SELECT *"
    - ".recover"
    - "VACUUM"
    - "PRAGMA integrity_check"
  answer: 1
- question: "Почему нельзя открывать базу на запись при форензике?"
  options:
    - "она станет больше"
    - "SQLite применит/перезапишет WAL и изменит улики"
    - "она удалится"
    - "ничего не произойдёт"
  answer: 1
- question: "В каком формате Chrome хранит историю?"
  options:
    - "SQLite (urls, downloads)"
    - "XML"
    - "JSON"
    - "CSV"
  answer: 0
```

## Где пригодится

- **CTF:** восстановление удалённых записей в базах браузеров/приложений.
- **DFIR:** анализ активности пользователя и приложений.
- **Веб-форензика:** данные CMS/приложений на SQLite.
- **Мобильная форензика:** app-базы Android/iOS.
- **Судебная экспертиза:** доказательство фактов переписки/посещений.
