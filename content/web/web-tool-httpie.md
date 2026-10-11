---
id: web-tool-httpie
title: "HTTPie: полный практический справочник"
category: web
parent: web-tools-cli
difficulty: easy
order: 2
tags: [httpie, http, cli, tooling, api, json, debugging]
prerequisites: [web-http-basics, web-tooling]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
  - "Работа с API"
estimated_minutes: 35
summary: "Полный справочник по HTTPie: синтаксис, JSON и формы, сессии, аутентификация, вывод и отладка, offline-режим — плюс сравнение с curl на каждой задаче."
---

**HTTPie** (`http`) — это HTTP-клиент для людей. Там, где curl требует `-H`, `-d`, `-X` и кавычек, HTTPie обходится «говорящим» синтаксисом: `http POST example.com name=bob`. По умолчанию он формирует JSON, подсвечивает вывод, красиво печатает заголовки и умеет **сессии** и **offline-режим** (построить запрос, не отправляя его).

В веб-тестировании HTTPie не заменяет curl (PoC в отчёте — почти всегда curl), но резко ускоряет ручную работу: перебор ручек, проверку JSON-API, чтение заголовков, повторяемые сессии. Этот урок — **рабочий справочник**: весь синтаксис, таблицы флагов, рецепты и сравнение с curl бок-о-бок.

## Шпаргалка: синтаксис, который нужен в 90% задач

| Флаг/синтаксис | Что делает | Пример |
|------|-----------|--------|
| `field=value` | JSON-поле (строка) | `http POST t/api name=bob` |
| `field:=json` | JSON-поле сырым JSON (число/булево/массив) | `http POST t/api age:=30 active:=true` |
| `field==value` | query-параметр | `http GET t/api page==2` |
| `Name:value` | заголовок запроса | `http GET t/ X-Trace:abc` |
| `--form` | urlencoded-форма | `http --form POST t/login user=a pass=b` |
| `-a user:pass` | Basic-аутентификация | `http -a admin:secret GET t/admin` |
| `--session NAME` | сохраняемая сессия (cookie+заголовки) | `http --session=app GET t/api/me` |
| `-v` | показать и запрос, и ответ | `http -v POST t/api a=1` |
| `-h` / `-b` | только заголовки / только тело | `http -h GET t/` |
| `--offline` | построить запрос, не отправляя | `http --offline POST t/api a=1` |
| `--follow` | следовать редиректам | `http --follow GET t/login` |
| `--verify=no` | не проверять TLS | `http --verify=no GET https://t/` |
| `--proxy=http:URL` | через прокси | `http --proxy=http:http://127.0.0.1:8080 GET t/` |

## Когда HTTPie лучше curl

| Ситуация | Почему HTTPie |
|----------|---------------|
| Ручной JSON-запрос | `http POST url a=1` вместо кавычек и `-H` |
| Чтение ответа глазами | цветной pretty-print JSON из коробки |
| Повторяющиеся запросы с логином | встроенные **sessions** |
| Нужно посмотреть, что уйдёт, без отправки | `--offline` |
| Загрузка/скачивание файлов | `--download`, `@file` |
| Быстрая отладка заголовков | `-v` показывает и запрос, и ответ |

| Ситуация | Почему curl |
|----------|-------------|
| PoC в отчёте/bug bounty | стандарт де-факто, принимают везде |
| Скрипты и CI | есть на любом хосте, стабильный вывод |
| Экзотика (HTTP/3, `--path-as-is`, `--connect-to`) | шире покрытие протоколов |
| Тонкий контроль над байтами тела | `--data-binary`, `--data-raw` |

Практический вывод: **исследуйте в HTTPie, доказывайте в curl**.

## Синтаксис и базовые вызовы

Общая форма:

```bash
http [флаги] [МЕТОД] URL [поле ...]
```

- `http` — HTTP, `https` — HTTPS (обе — команды из одного бинарника).
- Метод можно опустить: `http example.com` → GET.
- Поля после URL описывают тело/заголовки/параметры (см. следующий раздел).

```bash
http example.com                       # GET
http GET example.com                   # то же явно
http HEAD example.com                  # HEAD
http POST example.com a=1              # POST с JSON
http :3000/api/items                   # localhost:3000
http example.com/api Accept:application/xml
```

Сокращение `:3000` означает `localhost:3000` — удобно в разработке.

## Headers, query, JSON и формы

Это сердце HTTPie. Тип оператора определяет, куда попадут данные.

| Синтаксис | Куда попадает | Пример |
|-----------|---------------|--------|
| `Name:value` | **заголовок** запроса | `Content-Type:application/xml` |
| `Name:value` (пусто) | заголовок без значения | `X-Debug:` |
| `name=value` | **JSON-поле** (строка) | `name=bob` |
| `name:=value` | **JSON-поле** как сырой JSON | `age:=30`, `admin:=true` |
| `name@file` | JSON-поле из файла (текст) | `bio@bio.txt` |
| `name=@file` | JSON-поле из файла (JSON) | `cfg=@cfg.json` |
| `name==value` | **query-параметр** | `page==2` |
| `name:=@file` | JSON-поле как сырой JSON из файла | `data:=@d.json` |
| `name=value` + `--form` | **form-поле** | `--form user=bob` |
| `name@file` + `--form` | **файл в multipart** | `--form file@a.png` |

```bash
# JSON по умолчанию (Content-Type: application/json)
http POST t.local/api/users name=bob role=admin active:=true age:=30

# Заголовок и query-параметры
http GET t.local/api/items page==2 limit==50 X-Trace:abc

# Форма urlencoded (Content-Type: application/x-www-form-urlencoded)
http --form POST t.local/login user=admin pass=admin

# multipart с файлом
http --form POST t.local/upload title=demo file@/etc/hosts

# Тело из файла
http POST t.local/api/items @item.json
```

**Ключевая разница `=` и `:=`:** `active=true` отправит **строку** `"true"`, а `active:=true` — **булево** `true`. Для чисел и вложенных объектов используйте `:=`.

Вложенные поля и массивы можно задавать «точечно»:

```bash
http POST t.local/api/users name=bob address.city=Moscow tags:='["a","b"]'
```

## Аутентификация и сессии

| Флаг | Что делает |
|------|-----------|
| `-a user:pass` / `--auth` | Basic-аутентификация |
| `-A TYPE` / `--auth-type` | `basic`, `digest`, `bearer` |
| `--bearer TOKEN` | Bearer-токен (эквивалент `Authorization: Bearer ...`) |
| `--session NAME` | читаемая/записываемая сессия (cookie + заголовки) |
| `--session-read-only NAME` | только чтение сессии, без записи |
| `--session-dir DIR` | каталог для файлов сессий |

```bash
# Basic
http -a admin:s3cret GET t.local/admin

# Digest
http -A digest -a admin:s3cret GET t.local/admin

# Bearer
http --auth-type bearer --auth TOKEN GET t.local/api/me
# или просто заголовком
http GET t.local/api/me Authorization:"Bearer $TOKEN"

# Сессия: логин, дальше cookie живёт сам
http --session=app POST t.local/login user=alice pass=hunter2
http --session=app GET t.local/api/me
http --session=app GET t.local/api/orders/1001
```

Сессия хранит cookie и (при желании) постоянные заголовки между вызовами. Это прямой аналог `curl -c jar -b jar`, только имя сессии — строка.

## Вывод и отладка

HTTPie по умолчанию печатает заголовки ответа + тело. Управлять этим можно точно.

| Флаг | Что делает |
|------|-----------|
| `-v` / `--verbose` | показать **и запрос, и ответ** целиком |
| `-h` / `--headers` | только заголовки ответа |
| `-b` / `--body` | только тело ответа |
| `-p LIST` / `--print LIST` | что печатать: `H` (загр. запроса), `B` (тело запроса), `h` (загр. ответа), `b` (тело ответа) |
| `-P FORMAT` / `--pretty` | `all`, `colors`, `format`, `none` |
| `--stream` / `-S` | потоковый вывод (SSE, длинные ответы) |
| `--offline` | не отправлять, только построить запрос |
| `--all` | показать промежуточные ответы (с `--follow`) |
| `--check-status` | ненулевой код выхода при HTTP-ошибке (4xx/5xx) |
| `-o FILE` / `--output` | записать вывод в файл |
| `--style THEME` | тема подсветки |

```bash
# Увидеть, что реально ушло (запрос) и что вернулось
http -v POST t.local/api/items name=bob

# Только заголовки ответа
http -h GET t.local/

# Заголовки запроса + тело ответа (полезно для отладки)
http -p HBb GET t.local/api

# Без подсветки (для скриптов/логов)
http --pretty=none GET t.local/api | jq .

# Потоковый ответ
http --stream GET t.local/events
```

`-p HBb` — один из самых полезных режимов: видно, какие именно заголовки ушли, и что вернулось, без «шума» тела запроса.

## Загрузка, редиректы, прокси, TLS, таймауты

| Флаг | Что делает |
|------|-----------|
| `--download` / `-d` | скачать ответ в файл (по имени из URL) |
| `-o FILE` / `--output` | сохранить в конкретный файл |
| `-c` / `--continue` | докачать с места обрыва |
| `-F` / `--follow` | следовать редиректам |
| `--max-redirects N` | лимит редиректов |
| `--proxy PROTO:URL` | прокси, напр. `--proxy=http:http://127.0.0.1:8080` |
| `--verify=no` | не проверять TLS (аналог `curl -k`) |
| `--verify FILE` | доверять указанному CA |
| `--cert FILE` / `--cert-key FILE` | клиентский сертификат (mTLS) |
| `--timeout SEC` | таймаут запроса |
| `--max-headers N` | лимит размера заголовков |
| `--ignore-stdin` | не читать stdin (для скриптов) |

```bash
# Скачать файл
http --download GET t.local/backup.zip

# Через Burp
http --proxy=http:http://127.0.0.1:8080 --verify=no GET https://t.local/

# Следовать редиректам, показать всю цепочку
http --follow --all GET t.local/login

# Клиентский сертификат
http --cert=client.pem --cert-key=client.key GET t.local/mtls

# Таймаут 10 секунд и ненулевой код на 4xx/5xx
http --timeout=10 --check-status GET t.local/api/items
```

## Дополнительные флаги (полный охват)

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `--raw DATA` | отправить тело как есть, без интерпретации полей | `http --raw '{"a":1}' POST t/api` |
| `-j` / `--json` | форсировать JSON (по умолчанию) | `http -j POST t/api a=1` |
| `-f` / `--form` | форсировать urlencoded-форму | `http -f POST t/login a=1` |
| `--multipart` | форсировать multipart/form-data | `http --multipart POST t/up f@a.png` |
| `--boundary STR` | свой multipart-boundary | `http --multipart --boundary=X POST t/up f@a.png` |
| `--path-as-is` | не нормализовать `../` в пути (traversal) | `http --path-as-is GET 't/static/../../etc/passwd'` |
| `--chunked` | chunked-тело (Transfer-Encoding) | `http --chunked POST t/api @big.json` |
| `--compress` | сжать тело запроса | `http --compress POST t/api @big.json` |
| `--ciphers LIST` | набор шифров TLS | `http --ciphers 'DEFAULT@SECLEVEL=1' https://t/` |
| `--cert-key-pass PASS` | пароль к ключу клиентского серта | `http --cert=c.pem --cert-key=k.pem --cert-key-pass=x https://t/` |
| `--default-scheme S` | схема по умолчанию для «голого» хоста | `http --default-scheme=https t/` |
| `--ignore-netrc` | не использовать `~/.netrc` | `http --ignore-netrc GET t/` |
| `--format-options JSON` | опции форматирования вывода | `http --format-options '{"json":{"sort_keys":true}}' GET t/` |
| `--unsorted` / `--sorted` | не сортировать / сортировать ключи JSON | `http --sorted GET t/api` |
| `--response-charset ENC` | кодировка ответа | `http --response-charset=utf-8 GET t/` |
| `--response-mime MIME` | принудительный MIME ответа для раскраски | `http --response-mime=application/json GET t/` |
| `--history-print LIST` | что печатать для промежуточных ответов | `http --follow --history-print=Hh GET t/login` |
| `--block-size N` | размер блока при `--download` | `http --download --block-size=100k GET t/big.iso` |
| `--debug` | отладочный вывод | `http --debug GET t/` |
| `--traceback` | показать traceback при ошибке | `http --traceback GET t/` |
| `--print LIST` | что печатать (`H`/`B`/`h`/`b`) | `http -p HBb GET t/api` |

> Опущены чисто оформительские/диагностические флаги (`--style`, `--pretty`, `--colors`, `--meta`, `--session-dir` — описаны выше) и редкие опции отдельных плагинов.

## Плагины и offline-режим

**Offline-режим** — уникальная фича: HTTPie строит запрос и показывает его, **не отправляя**. Идеально, чтобы понять, что именно уйдёт на сервер, и собрать заготовку.

```bash
http --offline --pretty=all POST t.local/api/items name=bob role=admin active:=true
```

Вывод покажет точные строку запроса, заголовки и тело — можно скопировать в curl.

**Плагины** расширяют HTTPie (форматы аутентификации, вывод). Установка и список:

```bash
pip install httpie-oauth httpie-jwt-auth
httpie --plugins
http --auth-type oauth2 --auth TOKEN GET t.local/api/me
```

Популярные: `httpie-oauth` (OAuth2), `httpie-jwt-auth` (JWT), `httpie-aws-auth` (подпись AWS SigV4), `httpie-edgegrid`.

## Side-by-side: curl против HTTPie

| Задача | curl | httpie |
|--------|------|--------|
| GET | `curl t.local/api` | `http t.local/api` |
| POST JSON | `curl -X POST t.local/api -H 'Content-Type: application/json' -d '{"name":"bob"}'` | `http POST t.local/api name=bob` |
| Query-параметр | `curl 't.local/api?page=2'` | `http t.local/api page==2` |
| Заголовок | `curl -H 'X-Trace: abc' t.local` | `http t.local X-Trace:abc` |
| Bearer | `curl -H 'Authorization: Bearer T' t.local` | `http t.local Authorization:"Bearer T"` |
| Basic | `curl -u u:p t.local` | `http -a u:p t.local` |
| Форма | `curl -d 'a=1&b=2' t.local` | `http --form POST t.local a=1 b=2` |
| Файл в форме | `curl -F 'f=@a.png' t.local` | `http --form POST t.local f@a.png` |
| Только заголовки | `curl -I t.local` | `http -h t.local` |
| Показать запрос+ответ | `curl -v t.local` | `http -v t.local` |
| Не проверять TLS | `curl -k t.local` | `http --verify=no t.local` |
| Прокси | `curl -x http://127.0.0.1:8080 t.local` | `http --proxy=http:http://127.0.0.1:8080 t.local` |
| Редиректы | `curl -L t.local` | `http --follow t.local` |
| Скачать файл | `curl -O t.local/f.zip` | `http --download t.local/f.zip` |
| Сохранить cookie | `curl -c jar -b jar t.local` | `http --session=s t.local` |
| Без отправки | (нет прямого аналога) | `http --offline t.local` |

## Типичные сценарии: что делать в любой ситуации

**«Нужно быстро дёрнуть JSON-API».** `http POST url key=val` — и всё. HTTPie сам ставит `Content-Type: application/json`.

**«Логин и много запросов под сессией».** `http --session=app POST .../login`, затем все запросы с `--session=app`. Cookie подставится автоматически.

**«Не понимаю, что уходит на сервер».** `http --offline ...` — покажет запрос без отправки. Либо `http -v ...` — покажет и запрос, и ответ.

**«Ответ 302, а тело пустое».** Добавьте `--follow`; чтобы увидеть промежуточные ответы — `--follow --all`.

**«Сервер за self-signed TLS».** `--verify=no`. Для внутреннего CA — `--verify=ca.pem`.

**«Нужен Burp».** `--proxy=http:http://127.0.0.1:8080 --verify=no`.

**«Проверяю IDOR».** Сохраните сессию, меняйте id в пути: `http --session=app GET t.local/api/orders/1002`.

**«Нужно передать булево/число/массив, а не строку».** `:=`: `admin:=true`, `age:=30`, `tags:='["a"]'`.

**«Скрипт должен упасть на 4xx/5xx».** `--check-status` даёт ненулевой код выхода.

**«Нужен PoC для отчёта».** Постройте запрос в HTTPie, затем переведите в curl (таблица выше) — bug bounty принимает curl.

## Частые ошибки

- **Путать `=` и `:=`** — числа/булевы уходят строками. Используйте `:=` для «сырого» JSON.
- **Забыть `--form`** — HTTPie отправит JSON, а сервер ждёт urlencoded-форму; получите 400/415.
- **`name@file` без `--form`** — это JSON-поле из файла, а не загрузка файла; для загрузки нужен `--form`.
- **Путать `==` и `=`** — `page==2` это query-параметр, `page=2` это поле тела.
- **Думать, что `-h` это «help»** — в HTTPie `-h` печатает заголовки; help — `http --help`.
- **Игнорировать `--check-status`** — в скриптах ошибка HTTP не даст ненулевого кода, и пайплайн «проглотит» сбой.
- **Не задать сессию** — все запросы анонимные, авторизация «не работает».
- **Ждать от HTTPie `--path-as-is`/`--connect-to`** — их там нет; для тонкого контроля берите curl.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Как в HTTPie отправить числовое или булево JSON-значение, а не строку?"
  options:
    - "name=value"
    - "name==value"
    - "name:=value"
    - "name:value"
  answer: 2
  explanation: "Оператор `:=` вставляет значение как сырой JSON; `=` отправляет строку."
- question: "Какой синтаксис задаёт query-параметр в URL?"
  options:
    - "name=value"
    - "name:value"
    - "name@value"
    - "name==value"
  answer: 3
  explanation: "Двойное равно `==` кладёт пару в query-строку, а не в тело."
- question: "Что делает флаг --offline?"
  options:
    - "Отключает проверку TLS"
    - "Сохраняет cookie в файл"
    - "Строит и показывает запрос, не отправляя его на сервер"
    - "Следует по редиректам"
  answer: 2
  explanation: "Offline-режим печатает готовый запрос без сетевого вызова."
- question: "Как организовать повторяющиеся запросы под одним логином?"
  options:
    - "--form при каждом вызове"
    - "--download на каждом шаге"
    - "--offline всегда"
    - "--session=NAME при логине и последующих вызовах"
  answer: 3
  explanation: "Сессия хранит cookie и заголовки между вызовами."
- question: "Как отправить файл в multipart-форме?"
  options:
    - "POST url file=/path/a.png"
    - "--form POST url file@/path/a.png"
    - "POST url file:=/path/a.png"
    - "POST url file==/path/a.png"
  answer: 1
  explanation: "Оператор `@` вместе с `--form` прикладывает файл к multipart-телу."
```

## Где пригодится

- **CTF (Web):** быстрая ручная проверка API, JSON-полей и IDOR без громоздких curl-команд.
- **Bug bounty:** исследование эндпоинтов и построение запросов; финальный PoC всё равно переводится в curl.
- **Пентест:** разбор JSON-API, работа с сессиями и токенами, отладка заголовков через `-p HBb`.
- **Работа (разработка/AppSec):** ручное тестирование API, сборка запросов offline-режимом, чтение ответов глазами.
