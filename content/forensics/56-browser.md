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

## Вопрос, с которого всё начинается

Тебе дали профиль пользователя с рабочей машины. Подозрение: сотрудник перешёл по
фишинговой ссылке и ввёл пароль. Нужно доказать **факт посещения сайта** и показать,
что именно скачивалось.

Браузеры хранят огромный объём данных о своём пользователе: историю посещений,
cookies, загрузки, кэш страниц. Для расследования это золотая жила — от
доказательства визита до извлечения украденной сессии.

## Наш пример: профиль Chrome

Профиль Chrome по умолчанию лежит здесь:

```
%LOCALAPPDATA%\Google\Chrome\User Data\Default\
```

`%LOCALAPPDATA%` — это переменная окружения, путь вида
`C:\Users\<имя>\AppData\Local`. Посмотрим, что внутри:

```bash
$ ls "User Data/Default/"
History  Cookies  'Login Data'  'Web Data'  'Top Sites'  Cache/  Preferences
```

Каждый файл — отдельное хранилище. Все ключевые (кроме `Preferences`) — это **SQLite**,
встроенная база данных в одном файле. SQLite-базу читают утилитой `sqlite3`, выполняя
SQL-запросы (язык запросов к базе). Начнём с истории.

## Шаг 1: читаем историю

`History` — это SQLite-база. Ключевые таблицы: `urls` (адрес, заголовок, число
посещений), `visits` (каждый переход с временем), `downloads` (загрузки). Выведем
последние посещения:

```bash
$ sqlite3 History "SELECT url, title, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 5;"
https://secure-login.evil.tld/|Sign in|3
https://mail.example.com/|Inbox|12
```

Первая строка — то, что нам нужно: пользователь трижды открывал
`secure-login.evil.tld`. Но время тут не показано. Проблема в том, что Chrome
хранит время в **своём** формате: это **микросекунды с 1601-01-01** (эпоха
Windows/WebKit), а не привычные секунды с 1970-го. Переведём его прямо в SQL:

```bash
$ sqlite3 History "SELECT url, datetime(last_visit_time/1000000-11644473600,'unixepoch') FROM urls WHERE url LIKE '%login%';"
https://secure-login.evil.tld/|2024-03-01 12:10:00
```

Теперь время читаемо: визит был 1 марта 2024 в 12:10. (Число `11644473600` —
разница в секундах между 1601 и 1970 годами.)

## Шаг 2: что скачивали

Загрузки лежат в той же базе, в таблице `downloads`:

```bash
$ sqlite3 History "SELECT target_path, tab_url, datetime(start_time/1000000-11644473600,'unixepoch') FROM downloads ORDER BY start_time DESC LIMIT 5;"
C:\Users\bob\Downloads\invoice.pdf|https://evil.tld/invoice.pdf|2024-03-01 12:11:00
```

Через минуту после входа пользователь скачал `invoice.pdf` с того же домена
`evil.tld`. Связка «фишинг-логин → загрузка файла» уже вырисовывается.

## Шаг 3: cookies и сессии

`Cookies` — ещё одна SQLite-база. В таблице `cookies` есть `host_key` (для какого
сайта), `name` и `encrypted_value`. Значения зашифрованы:

```bash
$ sqlite3 Cookies "SELECT host_key, name FROM cookies WHERE host_key LIKE '%evil%';"
.evil.tld|sessionid
```

Cookie `sessionid` для `.evil.tld` — это то, что позволяет «оставаться в системе».
Показать значение просто так нельзя: Chrome шифрует его **AES-GCM** (современный
алгоритм шифрования), а ключ защищён **DPAPI** — механизмом Windows, который
привязывает секрет к учётной записи пользователя. Ключ лежит в файле `Local State`
в виде base64:

```bash
$ python3 -c "import json,base64; d=json.load(open('Local State')); print(base64.b64decode(d['os_crypt']['encrypted_key'])[5:])"
b'...ключ...'
```

Чтобы расшифровать cookies/пароли офлайн, нужен этот ключ, а его, в свою очередь,
защищает DPAPI-мастер-ключ — он может быть в памяти системы (см. урок про ключи в
памяти) или в хранилище учётных данных. Инструменты `chrome_decrypt`,
`browser_cookie3` делают расшифровку, если ключ доступен.

## Шаг 4: `Web Data` — введённые данные

Файл `Web Data` хранит то, что пользователь **сам вводил** в формы (автозаполнение):

```bash
$ sqlite3 'Web Data' "SELECT name, value FROM autofill LIMIT 5;"
email|bob@example.com
```

Если сотрудник вводил на фишинг-странице логин и пароль, эти данные часто остаются
здесь — прямое доказательство ввода.

## Шаг 5: Firefox устроен похоже, но по-другому

Firefox хранит историю и закладки в `places.sqlite`, cookies — в `cookies.sqlite`:

```bash
$ sqlite3 places.sqlite "SELECT url, title, datetime(last_visit_date/1000000,'unixepoch') FROM moz_places ORDER BY last_visit_date DESC LIMIT 3;"
https://secure-login.evil.tld/|Sign in|2024-03-01 12:10:00
```

Обрати внимание: у Firefox время — **микросекунды с 1970** (Unix-эпоха), а у Chrome —
с 1601. Перепутать эпохи — самая частая ошибка: дата уедет на 369 лет.

## Шаг 6: не забыть свежие данные (WAL)

SQLite активно перезаписывается, и самые свежие записи могут лежать не в основном
файле, а в спутниковых `-wal` и `-shm`. Копируй их **вместе** с базой:

```bash
$ cp History History-wal History-shm /evidence/
```

Иначе получишь старую картину. А ещё удалённые записи часто восстанавливаются из
свободных страниц базы:

```bash
$ sqlite3 History ".recover" | grep -i evil | head
```

## Что мы теперь знаем

- История, cookies, загрузки браузеров лежат в **SQLite-базах** (Chrome — `History`,
  `Cookies`; Firefox — `places.sqlite`).
- Chrome хранит время как микросекунды с **1601**, Firefox — с **1970**.
- Cookies и пароли зашифрованы AES, ключ защищён **DPAPI**; без ключа не прочитать.
- `Web Data` хранит введённые в формы данные — прямое доказательство ввода.
- Копируй базу вместе с `-wal`/`-shm`, иначе потеряешь свежие записи.

## На что смотреть дальше

- **Читать базы на живой системе** — файлы заблокированы; работай с копией.
- **Путать эпохи времени** (Chrome 1601 vs Firefox 1970).
- **Игнорировать `-wal`/`-shm`** — потеряешь последние записи.
- **Смотреть один профиль** — их может быть несколько (`Default`, `Profile 1`).
- **Забывать про `Web Data`** — там введённые пользователем данные.
- **Не искать `.recover`** — удалённая история восстанавливается.

## Квиз

Проверь себя.

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
- question: "Почему важно копировать файл History-wal?"
  options:
    - "он содержит пароли"
    - "свежие записи могут быть ещё не перенесены в основную БД"
    - "он шифрует базу"
    - "он не нужен"
  answer: 1
- question: "Что защищает ключ расшифровки cookies Chrome на Windows?"
  options:
    - "DPAPI (привязка к учётной записи)"
    - "SMB"
    - "Kerberos"
    - "LDAP"
  answer: 0
```

## Куда дальше

Мы прочитали браузерные базы и восстановили активность пользователя. В следующем
уроке заглянем **внутрь кустов реестра** — как устроены hbin/cell, зачем нужны
транзакционные журналы `.LOG` и как достать ключи, которые атакующий удалил. А пока
запомни: **браузер — это набор SQLite-баз; читай их в копии и следи за эпохой
времени**.

## Где пригодится

- **CTF** — задачи на историю браузера, поисковые запросы, скачанные файлы.
- **DFIR** — реконструкция активности пользователя и загрузок.
- **Threat Hunting** — поиск обращений к подозрительным доменам/URL.
- **Судебная экспертиза** — доказательство посещения ресурсов и загрузок.
- **Анализ инцидентов** — получение контента из кэша при отсутствии исходника.
