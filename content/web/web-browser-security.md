---
id: web-browser-security
title: "Модель безопасности браузера: site isolation, CORB/ORB, COOP/COEP"
category: web
parent: web-browser-core
difficulty: medium
order: 1
tags: [browser-security, site-isolation, corb, orb, coop, coep, same-origin]
prerequisites: [web-same-origin-cors]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 40
summary: "Как устроена изоляция сайтов в браузере и какие механизмы защищают данные между origin, сайтами и процессами."
---

## Вопрос, с которого всё начинается

Ты нашёл на сайте JavaScript-файл с API-ключом: `window.__CONFIG__ = {"apiKey":"..."}`. Логично подключить его со своей страницы как `<script src>` и прочитать переменную. Но почему-то данные не утекают — браузер их не отдаёт.

Почему? Потому что браузер — не «прозрачное окно», а среда с собственной **моделью безопасности**. Понимание этой модели отличает того, кто «знает payload'ы», от того, кто понимает, **почему** атака работает или не работает. Сегодня разберём её на одном сайте.

## Наш пример: shop.local и его поддомен

Возьмём магазин `shop.local` с API на отдельном поддомене `api.shop.local`. Первый вопрос, который задаёт модель браузера: это **один origin** или два?

**Origin** определяется тройкой: **схема + хост + порт**. Сравним:

- `https://shop.local` и `https://api.shop.local` — **разные** origin (разный хост);
- `https://shop.local` и `https://shop.local:443` — один origin (порт по умолчанию);
- `http://shop.local` и `https://shop.local` — разные (разная схема).

Схема и порт так же важны, как имя хоста. Это первая граница, которую нужно держать в голове.

## Шаг 1: SOP — запрещает читать, но разрешает действовать

**Same-Origin Policy (SOP)** — базовое правило: скрипт с одного origin не может **читать** данные другого. Именно поэтому `fetch('https://api.shop.local/me')` со страницы `shop.local` завершится ошибкой CORS, а не вернёт данные.

Но SOP запрещает именно **чтение**. Отправлять запросы, подключать скрипты, картинки и стили — можно. В этой «щели» и живут целые классы атак: **CSRF** (действие без чтения ответа), **JSONP/XSSI** (данные приходят как скрипт) и **XS-Leaks** (утечка состояния через различимое поведение).

## Шаг 2: Site Isolation

Раньше страницы разных сайтов жили в одном процессе, что открывало атаки через побочные каналы (например, Spectre). **Site Isolation** (в Chrome с 2018) помещает каждый сайт в отдельный процесс, изолируя память.

Здесь важно различать **origin** и **site**. Origin — это схема+хост+порт, а **site** — схема + регистрируемый домен (`eTLD+1`). То есть `shop.local` и `api.shop.local` — разные origin, но **один site** (общий `shop.local`). Site Isolation группирует именно по site, поэтому поддомены одного домена могут разделять процесс.

## Шаг 3: CORB/ORB — почему JSON не читается как скрипт

Вернёмся к нашему примеру. Почему не удаётся подключить `config.js` чужого origin и прочитать данные? За это отвечают **CORB** (Cross-Origin Read Blocking) и его преемник **ORB** (Opaque Response Blocking).

Идея: если cross-origin ответ имеет тип, который не должен исполняться как скрипт (JSON, HTML), браузер не отдаёт его содержимое в скрипт-контекст. Проверим заголовки ответа:

```bash
$ curl -sI https://api.shop.local/user | grep -iE 'content-type|x-content-type'
content-type: application/json
x-content-type-options: nosniff
```

`application/json` + `nosniff` — такой ответ ORB **не даст** исполнить как скрипт. А вот если тот же эндпоинт отдаёт `text/javascript` (например, в режиме JSONP), он исполнится — и данные утекут:

```bash
$ curl -sI 'https://api.shop.local/user?callback=x' | grep -i content-type
content-type: text/javascript
```

Вот тут модель безопасности и «ломается» — не из-за ошибки в браузере, а потому что сервер сам отдал данные как скрипт.

## Шаг 4: COOP, COEP и CORP — изоляция контекстов

Три заголовка управляют тем, как страницы и ресурсы видят друг друга:

| Заголовок | Значение | Эффект |
|-----------|----------|--------|
| `COOP: same-origin` | изоляция opener | `window.opener` недоступен из чужого origin |
| `COEP: require-corp` | требуются CORP | включает `crossOriginIsolated` |
| `CORP: same-origin` | ресурс только своего origin | защита от встраивания |
| `CORP: cross-origin` | ресурс можно встраивать | нужен для COEP |

**COOP** (`Cross-Origin-Opener-Policy`) ломает связь между окнами: с `same-origin` страница не может получить ссылку на `window.opener` чужого origin — это защита от reverse tabnabbing. **COEP** (`Cross-Origin-Embedder-Policy`) требует, чтобы все встраиваемые ресурсы явно разрешали встраивание через CORP; вместе с COOP он включает мощные API (`SharedArrayBuffer`). Проверим на нашем сайте:

```bash
$ curl -sI https://shop.local/ | grep -iE 'cross-origin-opener-policy|cross-origin-embedder-policy'
cross-origin-opener-policy: same-origin
```

## Шаг 5: document.domain и PNA

Два механизма, которые меняют ландшафт. Первый — **`document.domain`**: он позволяет ослабить SOP между поддоменами одного родителя. Это устаревшая практика, она ломает изоляцию, поэтому современные браузеры её ограничивают. Если видишь `document.domain` в коде — это признак старой модели:

```bash
$ curl -s https://shop.local/ | grep -o 'document.domain'
```

Второй — **Private Network Access (PNA)**: публичный сайт не должен без разрешения обращаться к локальной сети (`127.0.0.1`, приватные диапазоны, `.local`). Браузер шлёт preflight с `Access-Control-Request-Private-Network: true`, и сервер должен ответить `Access-Control-Allow-Private-Network: true`. Это защита от браузерного SSRF и DNS rebinding — часть старых векторов теперь блокируется.

## Как применять модель в тестировании

Модель браузера — это карта того, что возможно и что нет. Начни с определения origin-границ: какие поддомены, порты и схемы есть у цели, где проходят границы cookie и CORS. Затем проверь заголовки изоляции — их наличие и, что важнее, отсутствие:

```bash
$ for h in https://shop.local https://api.shop.local https://static.shop.local; do
>   echo "== $h"; curl -sI "$h" | grep -iE 'access-control|content-type|x-content-type|cross-origin'; done
== https://shop.local
cross-origin-opener-policy: same-origin
== https://api.shop.local
access-control-allow-origin: https://shop.local
```

Такой проход сразу показывает, где модель ослаблена. Дальше ищи **ослабления SOP**: CORS с отражением `Origin`, `postMessage` без проверки, `document.domain`, JSONP с `text/javascript`. Каждое ослабление — это канал чтения чужого origin. И не забывай про «щели»: CSRF (действия), XS-Leaks (утечка состояния), кликджекинг (действия через UI) — они работают даже при строгом SOP.

## Что мы теперь знаем

- Origin — это тройка **схема + хост + порт**; site — схема + регистрируемый домен.
- SOP запрещает **чтение** чужого origin, но разрешает **действия** — отсюда CSRF и XS-Leaks.
- Site Isolation разносит сайты по процессам, усложняя Spectre и побочные каналы.
- CORB/ORB блокируют чтение JSON/HTML как скрипта, но не мешают JSONP с `text/javascript`.
- COOP изолирует `window.opener`, COEP+CORP включают cross-origin isolation.
- `document.domain` ослабляет SOP (устарело); PNA ограничивает доступ к локальной сети.

## На что смотреть дальше

- Не считай поддомены «одним origin»: `a.com`, `api.a.com`, `static.a.com` — разные origin.
- Не игнорируй порт и схему: `https://a.com` и `http://a.com:8080` — разные origin.
- Помни, что CORS не «ослабляет SOP для всех», а разрешает конкретное чтение при согласии сервера.
- Ищи «щели» SOP: CSRF и XS-Leaks работают даже при строгом SOP.
- Проверяй заголовки изоляции: их отсутствие открывает tabnabbing и утечки.
- Учитывай новые механизмы (PNA, partitioned storage), которые меняют ландшафт.

## Квиз

Проверь себя.

```quiz
- question: "Чем Origin отличается от Site?"
  options:
    - "Origin = схема+хост+порт; Site = схема+eTLD+1"
    - "Это одно и то же"
    - "Site = IP-адрес"
    - "Origin = cookie"
  answer: 0
  explanation: "Site группирует поддомены одного регистрируемого домена."
- question: "Что делает `Cross-Origin-Opener-Policy: same-origin`?"
  options:
    - "Изолирует `window.opener` от чужих документов"
    - "Шифрует cookies"
    - "Отключает TLS"
    - "Включает CORS"
  answer: 0
  explanation: "COOP ломает reverse tabnabbing и часть XS-Leaks."
- question: "Зачем нужны CORB/ORB?"
  options:
    - "Блокируют чтение кросс-ориджин «чувствительных» ресурсов через теги"
    - "Ускоряют сайт"
    - "Меняют DNS"
    - "Ставят cookie"
  answer: 0
  explanation: "Они мешают утечке HTML/JSON через `<img>`/`<script>`."
- question: "Что включает cross-origin isolation?"
  options:
    - "COOP + COEP"
    - "CORS + CORP"
    - "TLS + HSTS"
    - "DNS + CDN"
  answer: 0
  explanation: "Только их комбинация даёт `crossOriginIsolated === true`."
- question: "Что делает `Cross-Origin-Resource-Policy: same-origin`?"
  options:
    - "Запрещает встраивание ресурса с других origin"
    - "Разрешает всем"
    - "Шифрует ресурс"
    - "Отключает кэш"
  answer: 0
  explanation: "CORP ограничивает, кто может встраивать ответ."
```

## Куда дальше

В следующем уроке мы возьмём конкретный обход SOP — **JSONP и XSSI**: как через тег `<script>` читать данные, которые SOP вроде бы защищает. А пока главное запомни: SOP запрещает читать, но разрешает действовать, и почти все клиентские атаки живут именно в этой щели.

## Где пригодится

- **CTF (Web):** задачи на browser-side изоляцию и «почему не читается».
- **Bug bounty:** отсутствующие security-заголовки как цепочка к утечкам.
- **Пентест:** понимание границ доверия при клиентских атаках.
- **Работа (AppSec/Dev):** внедрение COOP/COEP/CORP и корректной cookie-политики.
