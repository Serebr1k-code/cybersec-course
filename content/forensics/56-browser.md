---
id: forensics-browser
title: "Браузерная форензика: Chrome, Firefox, Edge"
category: forensics
parent: forensics-win-registry
difficulty: medium
order: 1
tags: [browser, chrome, firefox, edge, history, cookies, cache, sqlite, windows]
prerequisites: [forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 50
summary: "История, cookies, загрузки, кэш и сессии Chrome/Firefox/Edge: где лежат SQLite-базы, как их читать и что доказывать."
---
Браузеры хранят огромный объём данных о пользователе: историю посещений, cookies, пароли, загрузки, кэш, сессии. Для расследования это золотая жила — от доказательства посещения сайта до извлечения украденных сессий. Этот урок — про структуру данных Chrome/Firefox/Edge, SQLite-базы и инструменты их разбора.

## Где лежат данные

| Браузер | Профиль |
|---------|---------|
| Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\` |
| Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\` |
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\` |

Ключевые файлы Chrome/Edge:

| Файл | Содержимое |
|------|-----------|
| `History` | URL, заголовки, переходы, загрузки |
| `Cookies` | cookies (зашифрованы) |
| `Login Data` | пароли (DPAPI/AES) |
| `Web Data` | автозаполнение, карты |
| `Top Sites`, `Favicons` | топ-сайты, иконки |
| `Cache/`, `Code Cache/` | кэш ресурсов |
| `Sessions/`, `Current Session` | сессии/вкладки |
| `Preferences` | настройки (JSON) |

Firefox: `places.sqlite` (история+закладки), `cookies.sqlite`, `formhistory.sqlite`, `logins.json` (пароли), `downloads.sqlite`, `sessionstore-backups/`.

## История и переходы (Chrome)

`History` — SQLite. Ключевые таблицы: `urls` (id, url, title, visit_count, last_visit_time), `visits` (переходы с временем), `downloads`, `downloads_url_chains`, `keyword_search_terms`.

```bash
$ sqlite3 History "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 10;"
$ sqlite3 History "SELECT urls.url, visits.visit_time FROM visits JOIN urls ON visits.url=urls.id ORDER BY visits.visit_time DESC LIMIT 10;"
# время Chrome — microseconds since 1601 (WebKit/Windows epoch)
```

Время Chrome/WebKit — микросекунды с 1601-01-01. Конвертация:

```bash
$ python3 -c "print(__import__('datetime').datetime(1601,1,1)+__import__('datetime').timedelta(microseconds=13355000000000000))"
```

## Cookies и пароли

Cookies и пароли зашифрованы. Chrome (Windows) использует AES-GCM с ключом, защищённым DPAPI; ключ лежит в `Local State` (base64). На macOS/Linux — Keychain/`kwallet`/`gnome-keyring`.

```bash
# Linux: ключ в gnome-keyring или 'peanuts' по умолчанию
$ sqlite3 Cookies "SELECT host_key, name, encrypted_value FROM cookies LIMIT 5;"
# извлечение ключа из Local State
$ python3 -c "import json,base64;d=json.load(open('Local State'));print(base64.b64decode(d['os_crypt']['encrypted_key'])[5:])"
# инструменты: chrome_decrypt, browser_cookie3, pypykatz dpapi
```

Для офлайн-разбора паролей нужен master key (DPAPI) — он может быть в памяти (см. `forensics-memory-keys`) или в keychain.

## Кэш и сессии

Кэш хранит ресурсы (картинки, страницы); сессии — открытые вкладки. Полезно для восстановления содержимого посещённых страниц.

```bash
# кэш Chrome (в старых версиях — простой, в новых — сжатый)
$ strings -n 8 Cache/* | grep -i 'password\|token' | head
# Firefox sessionstore
$ python3 -c "import json;d=json.load(open('sessionstore.jsonlz4'));..."   # или mozlz4
# закладки Firefox
$ sqlite3 places.sqlite "SELECT url,title FROM moz_bookmarks b JOIN moz_places p ON b.fk=p.id WHERE title IS NOT NULL;"
```

## Инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `Hindsight` | разбор Chrome/Edge (GUI/CLI) |
| `BrowsingHistoryView` | история (Windows) |
| `DB Browser for SQLite` | GUI для SQLite |
| `browser_cookie3` | извлечение cookies |
| `chrome_decrypt` | пароли Chrome |
| `firefox_decrypt` | пароли Firefox |
| `mozilla_history`/`hindsight` | Firefox |

```bash
$ hindsight.py -i "User Data" -o out/
$ python3 firefox_decrypt.py <profile>
```

## Разобранный пример

Дан профиль Chrome. Нужно доказать посещение фишингового сайта и кражу сессии.

```bash
# 1. История
$ sqlite3 History "SELECT url, title, datetime(last_visit_time/1000000-11644473600,'unixepoch') FROM urls WHERE url LIKE '%login%' ORDER BY last_visit_time DESC LIMIT 5;"
https://secure-login.evil.tld/|Sign in|2024-03-01 12:10:00
# 2. Загрузки
$ sqlite3 History "SELECT target_path, tab_url, datetime(start_time/1000000-11644473600,'unixepoch') FROM downloads ORDER BY start_time DESC LIMIT 5;"
C:\Users\bob\Downloads\invoice.pdf|https://evil.tld/invoice.pdf|2024-03-01 12:11:00
# 3. Cookies для сессии
$ sqlite3 Cookies "SELECT host_key, name FROM cookies WHERE host_key LIKE '%evil%';"
# 4. Автозаполнение (введённые данные)
$ sqlite3 'Web Data' "SELECT name, value FROM autofill LIMIT 5;"
```

## Справочная таблица времени

| Браузер | Формат времени |
|---------|----------------|
| Chrome/WebKit | микросекунды с 1601 |
| Firefox (places) | микросекунды с 1970 (Unix) |
| Safari (macOS) | секунды с 2001 |
| Windows FILETIME | 100-нс тики с 1601 |

## Частые ошибки

- **Читать базы на живой системе** — файлы заблокированы; работайте с копией (+ `-wal`/`-shm`).
- **Путать эпохи времени** (Chrome 1601 vs Firefox 1970).
- **Игнорировать `Web Data`** — там введённые пользователем данные (пароли в формах).
- **Забывать про кэш** — восстановление содержимого страниц.
- **Не извлекать ключ DPAPI** — пароли останутся зашифрованными.
- **Смотреть один профиль** — их может быть несколько.

## Что дальше / решение

Конвейер: `Hindsight`/`sqlite3` (история/загрузки) → `Cookies`/`Login Data` (ключ DPAPI) → кэш/сессии → свести с таймлайном. Связка: `forensics-sqlite` (базы), `forensics-memory-keys` (DPAPI), `forensics-windows-artifacts` (обзор), `forensics-web-forensics` (веб).

## Firefox: places.sqlite

Firefox хранит историю и закладки в `places.sqlite`, cookies — в `cookies.sqlite`, формы — в `formhistory.sqlite`, пароли — в `logins.json` (зашифрованы через key4.db).

```bash
# история Firefox (время в микросекундах Unix)
$ sqlite3 places.sqlite "SELECT url, title, datetime(last_visit_date/1000000,'unixepoch') FROM moz_places ORDER BY last_visit_date DESC LIMIT 10;"
# переходы
$ sqlite3 places.sqlite "SELECT p.url, datetime(v.visit_date/1000000,'unixepoch') FROM moz_historyvisits v JOIN moz_places p ON v.place_id=p.id ORDER BY v.visit_date DESC LIMIT 10;"
# cookies
$ sqlite3 cookies.sqlite "SELECT host, name, value FROM moz_cookies LIMIT 5;"
# закладки
$ sqlite3 places.sqlite "SELECT p.url, b.title FROM moz_bookmarks b JOIN moz_places p ON b.fk=p.id WHERE b.title IS NOT NULL;"
# сессии (сжатый lz4)
$ python3 -c "import mozlz4; print(mozlz4.open('sessionstore.jsonlz4'))" 2>/dev/null | head
```

Firefox-время (`last_visit_date`) — микросекунды с 1970 (Unix), в отличие от Chrome (с 1601).

## Восстановление и целостность

SQLite-базы браузеров активно перезаписываются; свежие данные лежат в `-wal`/`-shm`. Для корректного чтения копируйте все три файла.

```bash
# копировать базу вместе с WAL
$ cp History History-wal History-shm /evidence/
# восстановить удалённые записи (freelist)
$ sqlite3 History ".recover" | grep -i 'evil' | head
# удалённые cookies/история могут быть в freelist-страницах
```

```bash
$ sqlite3 History "PRAGMA integrity_check;"
$ strings History | grep -iE 'http|password' | head
```

Для офлайн-анализа сессий и восстановления удалённых записей используйте `undark`/`.recover` (см. `forensics-sqlite`). Удалённая история и cookies часто восстанавливаются из свободных страниц.

## Профили и шифрование

- **Несколько профилей**: `Default`, `Profile 1`, и т. д. — проверяйте все.
- **Incognito/Private**: история не пишется, но кэш/сеть могут остаться.
- **Ключ DPAPI** привязан к пользователю; без него пароли не читаются.
- **Синхронизация**: данные могут быть в облачном профиле (Google/Mozilla account).

## Справочная таблица

| Браузер | История | Cookies | Пароли |
|---------|---------|---------|--------|
| Chrome | `History` | `Cookies` | `Login Data` |
| Edge | `History` | `Cookies` | `Login Data` |
| Firefox | `places.sqlite` | `cookies.sqlite` | `logins.json` |

## Частые ошибки (расширенно)

- **Игнорировать `-wal`/`-shm`** — потеряете свежие записи.
- **Путать эпохи** (Chrome 1601 vs Firefox 1970).
- **Забывать про `.recover`** — удалённая история восстанавливается.
- **Смотреть один профиль** — их может быть несколько.
- **Не извлекать DPAPI-ключ** — пароли останутся нечитаемыми.
- **Копировать на живую** без учёта блокировок — получите консистентную, но неполную базу.

## Квиз

```quiz
- question: "В каком формате хранится история Chrome/Firefox?"
  options:
    - "JSON"
    - "SQLite"
    - "XML"
    - "ESE"
  answer: 1
- question: "Какую эпоху времени использует Chrome для last_visit_time?"
  options:
    - "Unix (1970)"
    - "1601 (WebKit/Chrome, микросекунды)"
    - "2000"
    - "Windows FILETIME без деления"
  answer: 1
- question: "Что даёт файл places.sqlite в Firefox?"
  options:
    - "cookies"
    - "историю и закладки"
    - "кэш"
    - "пароли"
  answer: 1
- question: "Почему важно учитывать файл History-wal?"
  options:
    - "он содержит пароли"
    - "свежие записи могут быть ещё не перенесены в основную БД"
    - "он шифрует базу"
    - "он не нужен"
  answer: 1
- question: "Чем ценен браузерный кэш для форензики?"
  options:
    - "хранит тела ответов, включая контент уже изменённых/удалённых страниц"
    - "хранит пароли"
    - "хранит USB-историю"
    - "хранит EVTX"
  answer: 0
```

## Где пригодится

- **CTF:** задачи на историю браузера, поисковые запросы, скачанные файлы.
- **DFIR:** реконструкция активности пользователя и загрузок.
- **Threat Hunting:** поиск обращений к подозрительным доменам/URL.
- **Судебная экспертиза:** доказательство посещения ресурсов и загрузок.
- **Анализ инцидентов:** получение контента из кэша при отсутствии исходника.
