---
id: web-http-basics
title: "Основы HTTP и анатомия веб-запроса"
category: web
parent:
difficulty: beginner
order: 1
tags: [http, requests, headers, cookies, curl]
prerequisites: []
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Как устроен HTTP-запрос и ответ: методы, заголовки, cookies, коды состояния — фундамент для всех дальнейших атак."
---
HTTP (HyperText Transfer Protocol) — текстовый протокол «запрос-ответ», на котором стоит почти весь веб. Клиент (браузер, curl, скрипт) отправляет **запрос**, сервер отвечает **ответом**. Понимание анатомии HTTP — фундамент всего дальнейшего: без него невозможно ни заметить аномалию (request smuggling, host header), ни правильно повторить запрос в curl, ни понять, где искать уязвимость. Этот урок — про то, как устроен запрос/ответ, какие бывают методы и коды, и как смотреть на реальный трафик инструментами.

## Что такое HTTP и зачем он нужен

HTTP — протокол прикладного уровня, работающий поверх TCP (или TLS в случае HTTPS). Он **stateless**: каждый запрос независим, а «состояние» (сессия, логин) держится за счёт cookie и серверных сессий. Именно stateless-природа объясняет, зачем нужны cookie и заголовки: сервер не помнит, что вы делали раньше, если вы не передадите это явно.

Формат — человекочитаемый текст: и запрос, и ответ можно набрать руками в `nc`. Это ключевое свойство для пентеста: мы можем вручную формировать любые запросы, в том числе невалидные, и наблюдать, как сервер реагирует.

## Структура запроса: строка, заголовки, тело

Запрос состоит из трёх частей:

```http
GET /index.html?q=1 HTTP/1.1
Host: example.com
User-Agent: curl/8.5.0
Accept: */*
Cookie: sess=abc123

```

1. **Стартовая строка** — `МЕТОД путь HTTP/версия`. Путь включает query-string (`?key=value`).
2. **Заголовки** — пары `Имя: значение`, каждый на своей строке. Заканчиваются пустой строкой.
3. **Тело** — необязательно (у GET обычно нет, у POST/PUT есть). Его наличие и тип описывают `Content-Type` и `Content-Length`.

Корректная стартовая строка для получения ресурса: `GET / HTTP/1.1` — метод, путь, версия, разделённые пробелами. `GET /` без версии или `GET HTTP/1.1 /` — некорректны.

## Структура ответа и коды состояния

Ответ тоже из трёх частей:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1256
Set-Cookie: sess=abc123; HttpOnly; Secure

<html>...</html>
```

**Коды состояния** — первая цифра задаёт класс:

| Код | Класс | Значение |
|-----|-------|----------|
| 1xx | информационные | 101 Switching Protocols (WebSocket) |
| 2xx | успех | 200 OK, 201 Created, 204 No Content |
| 3xx | перенаправление | 301/302, 304 Not Modified, 307/308 |
| 4xx | ошибка клиента | 400, 401, 403 Forbidden, 404, 405, 429 |
| 5xx | ошибка сервера | 500, 502, 503, 504 |

`403 Forbidden` означает, что сервер **понял** запрос, но **отказал** в доступе (в отличие от `401 Unauthorized`, где требуется аутентификация). `405 Method Not Allowed` — путь есть, но метод не поддержан.

## Методы HTTP и их назначение

| Метод | Назначение | Тело |
|-------|-----------|------|
| `GET` | получить ресурс | нет |
| `POST` | создать/отправить данные | да |
| `PUT` | заменить ресурс целиком | да |
| `PATCH` | частично изменить | да |
| `DELETE` | удалить | нет |
| `HEAD` | как GET, но только заголовки | нет |
| `OPTIONS` | узнать поддерживаемые методы | нет |

Пара «метод — назначение»: `GET` — чтение, `POST` — создание/отправка. Подмена метода (`GET` вместо `POST`, `PUT` для обхода) — база для многих уязвимостей (`web-http-verb-tampering`).

## Важные заголовки

- **`Host`** — какой сайт запрошен (на одном IP может быть много сайтов). Управляемость `Host` → `web-host-header`.
- **`Content-Type`** — тип тела: `application/x-www-form-urlencoded`, `application/json`, `multipart/form-data`, `text/xml`.
- **`Content-Length` / `Transfer-Encoding`** — длина тела / потоковая передача. Расхождение → request smuggling.
- **`Cookie`** — передаёт сессию. **`Set-Cookie`** — устанавливает её (атрибуты `HttpOnly`, `Secure`, `SameSite`).
- **`Authorization`** — учётные данные (Basic/Bearer).
- **`User-Agent`, `Referer`, `X-Forwarded-For`** — часто используются для логики/фильтров и легко подделываются.

Тело `{"user":"admin"}` передаётся с заголовком `Content-Type: application/json` — это самый частый формат API.

## Инструменты: curl, devtools, httpie

**curl** — базовый инструмент для ручных запросов:

| Флаг | Значение |
|------|----------|
| `-i` | показать заголовки ответа |
| `-I` | сделать `HEAD`-запрос (только заголовки) |
| `-v` | подробно: и запрос, и ответ |
| `-X POST` | задать метод |
| `-H 'Name: v'` | добавить заголовок |
| `-d 'a=1&b=2'` | тело (form), подразумевает POST |
| `--data-binary @f` | тело из файла без изменений |
| `-b 'k=v'` / `-c jar` | отправить/сохранить cookie |
| `-L` | следовать редиректам |
| `-k` | не проверять TLS |
| `--http1.1` / `--http2` | версия протокола |

```bash
# HEAD-запрос: только заголовки
curl -I https://example.com
# POST JSON
curl -s -X POST https://example.com/api -H 'Content-Type: application/json' -d '{"user":"admin"}'
# verbose: видеть точный запрос
curl -v https://example.com/
```

**Браузерные DevTools** (F12 → Network) показывают реальный трафик, включая заголовки и тело; правый клик → «Copy as cURL» переносит запрос в консоль. **httpie** (`http GET example.com`) — более читаемый синтаксис для ручных запросов.

## Разобранный пример: ручной логин через curl

Задача — залогиниться в форме и получить сессию.

```bash
# 1. смотрим форму в DevTools: метод POST, action /login, поля user/pass
# 2. повторяем запрос curl, сохраняя cookie
curl -s -i -c jar.txt -X POST https://app.example/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'user=admin&pass=admin'
# HTTP/1.1 302 Found
# Set-Cookie: session=eyJ...; HttpOnly
# 3. используем полученную cookie
curl -s -b jar.txt https://app.example/profile | grep -i 'welcome\|admin'
```

Так мы видим и код ответа, и `Set-Cookie`, и тело — то есть полностью контролируем сессию.

## Разобранный пример: разбор запроса в DevTools

1. Откройте Network, обновите страницу.
2. Найдите запрос XHR/`fetch` — смотрите Headers → Request Headers, Payload.
3. Определите Content-Type и структуру тела.
4. Правый клик → Copy → Copy as cURL — получаете точный запрос для повторения/фаззинга.

Так находится реальный API-эндпоинт, который не виден в исходном HTML.

## Типичные ошибки новичков

- **Путать 401 и 403.** 401 — «не залогинен», 403 — «залогинен, но нельзя».
- **Забыть `Content-Type`.** JSON уйдёт как form-urlencoded и сервер вернёт 400.
- **Игнорировать редиректы.** `302` без `-L` выглядит как «пусто» — смотрите `Location`.
- **Не сохранять cookie.** Без `-c/-b` второй запрос неаутентифицирован.
- **Считать GET безопасным.** GET меняет состояние в плохо спроектированных приложениях (CSRF-поверхность).
- **Верить `X-Forwarded-For`/`User-Agent` как «защите».** Их легко подделать.

## Что делать дальше / решение

1. Поймите запрос/ответ — метод, путь, заголовки, тело.
2. Переведите реальный запрос в curl (`Copy as cURL`).
3. Определите, где сервер доверяет клиенту: `Host`, `X-Forwarded-For`, cookie, метод.
4. Проверьте смежные темы: `web-http-parameter-pollution`, `web-host-header`, `web-http-verb-tampering`, `web-request-smuggling`.
5. Зафиксируйте аномалию и переходите к конкретному классу уязвимости.

## Справочная таблица

| Элемент | Пример | Зачем смотреть |
|---------|--------|----------------|
| стартовая строка | `GET /x HTTP/1.1` | метод, путь, версия |
| `Host` | `example.com` | vhost-логика, SSRF |
| `Content-Type` | `application/json` | как парсится тело |
| `Content-Length` | `27` | smuggling |
| `Cookie` | `sess=...` | сессия, фиксация |
| код 302 | `Location: /x` | редиректы, open redirect |
| код 403 | доступ запрещён | IDOR/обход |
## Разобранный пример: фаззинг параметра через ffuf

Когда эндпоинт найден, следующий шаг — понять, как он реагирует на разные значения. Для этого есть `ffuf`:

```bash
# перебор значений параметра id
ffuf -u 'https://app.example/item?id=FUZZ' -w ids.txt -mc all -fc 404 -o out.json
# перебор имён параметров (param discovery)
ffuf -u 'https://app.example/api?FUZZ=1' -w params.txt -mc all -fs 0
```

Флаг `-mc all` показывает все коды (включая 500), `-fc 404` скрывает «не найдено». Так обнаруживаются параметры, влияющие на логику, — кандидаты на IDOR/инъекции.

## Разобранный пример: разница HTTP/1.1 и HTTP/2

Версия протокола влияет на парсинг и на уязвимости:

```bash
# HTTP/1.1
curl --http1.1 -sI https://app.example/
# HTTP/2 (если поддерживается)
curl --http2 -sI https://app.example/
# HTTP/2 cleartext (h2c) — часто не проверяется WAF
curl --http2-prior-knowledge -s http://app.example/
```

Расхождения между фронтенд- и бэкенд-парсерами (HTTP/1 vs HTTP/2, разная трактовка `Content-Length`/`Transfer-Encoding`) — основа request smuggling (`web-request-smuggling`, `web-http2-attacks`). Даже если «основной» путь защищён, h2c-порт часто нет.

## Пошаговый чек-лист

1. **Снять реальный запрос** через DevTools → Copy as cURL.
2. **Повторить в curl** и убедиться, что ответ совпадает.
3. **Определить доверие к клиенту:** `Host`, `X-Forwarded-For`, `Cookie`, метод, `Content-Type`.
4. **Проверить коды/редиректы:** `-i -L`, посмотреть `Location` и `Set-Cookie`.
5. **Пофаззить** параметры (`ffuf`) и методы (`OPTIONS`).
6. **Сравнить версии протокола** (1.1 / 2 / h2c).
7. **Зафиксировать аномалию** и перейти к конкретному классу (`web-http-parameter-pollution`, `web-host-header`, `web-request-smuggling`).

## Полезные однострочники

```bash
# сохранить cookie и переиспользовать
curl -s -c j -X POST https://t/login -d 'u=a&p=b' && curl -s -b j https://t/profile
# отправить ровно то тело, что в файле (без перекодирования)
curl -s --data-binary @req.body -H 'Content-Type: application/json' https://t/api
# посмотреть только заголовки ответа и статус
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' https://t/
# проверить поддержку методов
curl -s -X OPTIONS -i https://t/api | grep -i allow
```

## Справочная таблица заголовков и их рисков

| Заголовок | Риск при доверии клиенту |
|-----------|--------------------------|
| `Host` | password reset poisoning, SSRF, cache poisoning |
| `X-Forwarded-For` | обход rate-limit/whitelist, spoof IP |
| `X-Forwarded-Host` | подмена ссылок, cache poisoning |
| `Content-Length` | request smuggling |
| `Transfer-Encoding` | request smuggling |
| `Cookie` | session fixation, deser |
| `Origin`/`Referer` | CSRF-проверки, обход |
| `User-Agent` | фильтры, логи (log injection) |

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Какая строка HTTP-запроса корректна для получения ресурса?"
  options:
    - "`GET /index.html HTTP/1.1`"
    - "`POST /index.html HTTP/1.1`"
    - "`HTTP/1.1 GET /index.html`"
    - "`GET index.html HTTP/1.1`"
  answer: 0
  explanation: "сначала метод, затем путь, затем версия протокола."
- question: "Что означает код `403 Forbidden`?"
  options:
    - "Пользователь не аутентифицирован"
    - "Пользователь аутентифицирован, но у него нет прав на ресурс"
    - "Ресурс не найден"
    - "Внутренняя ошибка сервера"
  answer: 1
  explanation: "`401` — про аутентификацию, `403` — про авторизацию."
- question: "Каким заголовком передаётся тело `{"a":1}` в JSON-запросе?"
  options:
    - "`Accept: application/json`"
    - "`Content-Type: application/json`"
    - "`Content-Encoding: json`"
    - "`X-Requested-With: JSON`"
  answer: 1
  explanation: "`Content-Type` описывает формат тела запроса; `Accept` — что клиент готов принять в ответе."
- question: "Что делает флаг `curl -I`?"
  options:
    - "Идёт по редиректам"
    - "Отправляет HEAD-запрос и показывает только заголовки"
    - "Включает cookie-jar"
    - "Игнорирует TLS-ошибки"
  answer: 1
  explanation: "`-I` = HEAD-запрос, только заголовки ответа."
- question: "Какая пара «метод — назначение» верна?"
  options:
    - "`HEAD` — удалить ресурс"
    - "`OPTIONS` — получить тело ресурса"
    - "`PUT` — заменить ресурс целиком"
    - "`PATCH` — идемпотентно заменить ресурс"
  answer: 2
  explanation: "`PUT` идемпотентно заменяет ресурс; `PATCH` — частичное неидемпотентное изменение."
```

## Где пригодится

- **CTF (Web):** любой challenge начинается с того, что вы «читаете» запросы к приложению через DevTools/curl; без этого не найти ни один параметр для инъекции.
- **Bug bounty:** воспроизведение найденного бага в отчёте делается именно через `curl`-команду — её требует большинство платформ (HackerOne, Bugcrowd).
- **Пентест:** ручное воспроизведение запросов в Burp/curl — основа доказательства эксплуатируемости; автосканер без ручной проверки даёт false positives.
- **Работа (AppSec/Dev):** понимание заголовков и кодов состояния нужно для чтения логов, отладки API и ревью конфигураций прокси/WAF.
