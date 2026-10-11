---
id: reversing-wasm
title: "Реверс WebAssembly"
category: reversing
parent: reversing-architectures
difficulty: hard
order: 2
tags: [reversing, wasm, webassembly, wabt, wasm2c, wasmtime]
prerequisites: [reversing-architectures]
useful_for:
  - "CTF Reversing / Web"
  - "Анализ web-клиентов и WASM-крипто"
  - "Reverse-engineering игр/DRM в браузере"
estimated_minutes: 60
summary: "Как читать .wasm: текстовый WAT, wabt, wasm2c, декомпиляция и динамический анализ в Node/браузере."
---
**WebAssembly (WASM)** — компактный бинарный формат со стековой машиной, исполняемый в браузере и вне его (wasmtime/wasmer, Node.js). Он используется для производительных web-клиентов, крипто (в т.ч. DRM), игр и даже малвари. Реверс `.wasm` требует своих инструментов: конвертации в читаемый текст (WAT), декомпиляции в псевдо-C, запуска в рантайме и динамического анализа. Этот урок — практический разбор WASM от формата до crackme end-to-end.

## Формат WASM

Бинарный модуль состоит из секций:

| Секция | Содержимое |
|--------|------------|
| Type | сигнатуры функций (params/results) |
| Import | импортируемые функции/память/таблицы (из JS/OS) |
| Function | типы локальных функций |
| Table | таблица косвенных вызовов (`call_indirect`) |
| Memory | линейная память (единый массив байт) |
| Global | глобальные переменные |
| Export | экспортируемые функции/память |
| Element | инициализация таблицы (адреса функций) |
| Code | тела функций (байткод стековой машины) |
| Data | инициализация линейной памяти (строки, константы) |

Ключевое отличие от обычного бинаря: **стековая машина** (инструкции оперируют стеком, а не регистрами) и **линейная память** (единый массив; «указатели» — просто смещения). **WAT** (WebAssembly Text) — читаемый текстовый эквивалент.

## Инструменты

| Инструмент | Назначение |
|------------|------------|
| `wabt` (`wasm2wat`, `wasm-decompile`, `wat2wasm`, `wasm-objdump`) | конвертация/обзор |
| `wasm2c` (wabt) | конвертация в C (компилируемый) |
| `wasmtime`/`wasmer` | рантайм вне браузера |
| Node.js `WebAssembly` | запуск/динамика |
| Ghidra/IDA + WASM-плагины | нативный дизасм |
| Chrome DevTools | отладка в браузере |

```bash
# Бинарный -> текстовый
wasm2wat module.wasm -o module.wat
# Обзор секций/импортов/экспортов
wasm-objdump -x module.wasm
# Декомпиляция в псевдо-C
wasm-decompile module.wasm -o module.dcmp
# Конвертация в C
wasm2c module.wasm -o module.c
```

## Чтение WAT

```wat
(func $add (param $a i32) (param $b i32) (result i32)
  local.get $a
  local.get $b
  i32.add)
```

WAT читаем как стековую программу: `local.get` кладёт значение на стек, `i32.add` снимает два и кладёт сумму. Частые инструкции: `i32.const` (константа), `local.get`/`local.set` (локальные), `i32.load`/`i32.store` (память), `call`/`call_indirect` (вызовы), `br`/`br_if`/`loop` (управление), `i32.eq`/`i32.lt` (сравнения), `i32.and`/`xor`/`shl` (битовые).

## Реверс логики

- **Точка входа** — экспортируемые функции (`wasm-objdump -x | grep -A20 Export`).
- **Строки** — в data-секции; `strings` их видит, если не обфусцированы.
- **Крипто** — ищите константы (S-box, раундовые константы), циклы, битовые операции.
- **Индексы памяти** — `i32.load offset=...` обращается к линейной памяти; строки/таблицы лежат там.
- **Косвенные вызовы** — `call_indirect` использует таблицу; сопоставьте индексы с адресами функций.

```bash
# Строки в data-секции
strings -a module.wasm | head
# Экспорты
wasm-objdump -x module.wasm | grep -A20 Export
```

## Динамика

```bash
# Запуск в wasmtime
wasmtime module.wasm
# В Node.js
node -e "const fs=require('fs'); WebAssembly.instantiate(fs.readFileSync('m.wasm')).then(r=>console.log(r.instance.exports))"
```

```js
// Вызов экспортированной функции
const fs = require('fs');
const buf = fs.readFileSync('module.wasm');
WebAssembly.instantiate(buf, imports).then(({ instance }) => {
    console.log(instance.exports.check(123));
});
```

Динамика позволяет быстро перебирать входы и наблюдать результат — часто быстрее статического разбора.

## Разобранный пример: WASM-crackme end-to-end

```text
1) wasm-objdump -x: найти экспорт check.
2) wasm-decompile: получить псевдо-C.
3) Понять проверку (например, сравнение входа с константой).
4) Динамика в Node: вызвать check с разными входами.
5) Решить (или подобрать) правильный ввод.
```

**Шаг 1. Обзор модуля.**

```bash
wasm-objdump -x module.wasm | head -50
# exports / imports / sections
```

**Шаг 2. Текст и декомпиляция.**

```bash
wasm2wat module.wasm -o module.wat
wasm-decompile module.wasm -o module.dcmp
wasm2c module.wasm -o module.c
```

**Шаг 3. Найти логику.** Экспорт `check` → разобрать в WAT/dcmp:

```wat
(func $check (param i32) (result i32)
  local.get 0
  i32.const 1234
  i32.eq)
```

**Шаг 4. Динамика в Node.**

```js
const fs = require('fs');
WebAssembly.instantiate(fs.readFileSync('module.wasm')).then(r => {
    console.log(r.instance.exports.check(1234));   // 1 (true)
});
```

**Шаг 5. Строки.** Data-секция хранит строки:

```bash
strings -a module.wasm | head
```

## Сценарии в CTF и реальном реверсе

| Сценарий | Что делать |
|----------|------------|
| WASM-crackme | найти экспорт `check`, декомпилировать, подобрать/решить вход |
| WASM-крипто (DRM/лицензии) | искать S-box, раундовые константы, проверку ключа |
| Обфусцированный WASM | разбирать `br_table`-диспетчеры, декодировать строки |
| WASM в Electron/Node | запустить модуль в Node, вызвать экспорты, логировать |
| Малварь (криптомайнер) | найти worker-функцию и параметры пула (строки/константы) |

Практический приём: если модуль небольшой, быстрее всего сконвертировать его в C (`wasm2c`), скомпилировать и отлаживать как обычную программу — вы получаете полноценный gdb с точками останова. Для больших модулей (Unity/игры) удобнее `wasm-decompile` и навигация по функциям.

## Сравнение с нативным реверсом

- **Нет регистров** — стековая машина; привычные «mov/cmp» заменяются на `local.get`/`i32.eq`.
- **Нет прямых указателей** — линейная память и смещения; «адреса» — это индексы в `memory`.
- **Импорты/экспорты** — граница с host (JS/OS); без них модуль не работает.
- **Верифицируемость** — WASM всегда «валиден» (нет произвольных прыжков в середину инструкции), что упрощает дизасм, но обфускация остаётся.
- **Переносимость** — один и тот же модуль идёт в браузере и в wasmtime; динамика легко автоматизируется.

## Практика: WASM в Node/Electron и автоматизация

WASM вне браузера (Node.js, Electron, Deno) реверсить проще: есть доступ к файловой системе и отладчику. Подход:

```text
1) Найти .wasm-файл (в Electron — внутри asar; распаковать: npx asar extract).
2) Загрузить модуль в Node, перечислить exports/imports.
3) Подменить imports (заглушки) и логировать вызовы host-функций.
4) Вызвать экспорты с разными входами; сравнить с ожидаемым.
5) Если логика зашифрована в WASM — декомпилировать (wasm-decompile) и разобрать.
```

```js
// Перечисление экспортов и вызов с логированием
const fs = require('fs');
const buf = fs.readFileSync('module.wasm');
const imports = { env: { log: (x) => console.log('host log:', x) } };
WebAssembly.instantiate(buf, imports).then(({ instance }) => {
  console.log(Object.keys(instance.exports));
  console.log(instance.exports.check(123));
});
```

Автоматизация подбора: оберните вызов в цикл по диапазону/словарю и ищите вход, при котором экспорт возвращает «успех». Для больших модулей — `wasm2c` и компиляция в нативный код, чтобы отлаживать gdb с точками останова.

## Обфускация WASM

- **Искажённые имена** — секция `name` может отсутствовать; функции безымянны (`func[0]`).
- **Контроль потока** — `br_table`-диспетчеры (аналог switch), усложняющие чтение.
- **Строковое шифрование** — строки расшифровываются в рантайме; ищите декодер в WAT.
- **WASM-пакеры** — добавляют собственный загрузчик/расшифровку модуля в JS.
- **Инструменты:** `wasm-decompile` даёт читаемый псевдо-C; для сложных случаев — Ghidra WASM-плагин и динамика.

## Частые ошибки

- **Читать .wasm как бинарь.** Нужны WASM-инструменты (wabt); hex-редактор бесполезен.
- **Путать WAT и бинарь.** WAT — текстовое представление, `.wasm` — байткод.
- **Игнорировать память.** Строки/данные в data-секции линейной памяти, а не в коде.
- **Забыть про imports.** Модуль зависит от host-функций (JS/OS); без них не запустится.
- **Неверный рантайм.** wasmtime и браузер имеют разные API импортов.
- **Обфускация.** Некоторые сборки обфусцированы (искажённые имена/структуры) — нужен ручной разбор.
- **Пропуск call_indirect.** Косвенные вызовы скрывают реальные цели — сопоставляйте с таблицей.

## Что делать дальше / решение

1. Сделайте обзор: `wasm-objdump -x` (секции, экспорты, импорты).
2. Получите текст/псевдо-C: `wasm2wat`, `wasm-decompile`, `wasm2c`.
3. Найдите точку входа (экспорт) и локализуйте логику по строкам/константам.
4. Запустите в wasmtime/Node, вызовите экспорт с разными входами.
5. При обфускации — разбирайте `br_table`-диспетчеры и декодер строк.
6. Для DRM/игр — восстановите крипто-константы и проверки лицензии.

## Квиз

```quiz
- question: "Что такое WAT?"
  options:
    - "Текстовое представление WebAssembly"
    - "Формат изображения"
    - "Тип шифрования"
    - "Пакер"
  answer: 0
  explanation: "WAT (WebAssembly Text) — читаемый эквивалент .wasm."
- question: "Как конвертировать .wasm в текст?"
  options:
    - "wasm2wat"
    - "nm"
    - "ldd"
    - "objdump -d"
  answer: 0
  explanation: "wabt-утилита wasm2wat делает WAT."
- question: "Где хранятся строки WASM-модуля?"
  options:
    - "В data-секции линейной памяти"
    - "В GOT"
    - "В ASLR"
    - "В canary"
  answer: 0
  explanation: "Строки/данные лежат в data-секции и памяти."
- question: "Как запустить .wasm вне браузера?"
  options:
    - "wasmtime/wasmer"
    - "gdb"
    - "ldd"
    - "objdump"
  answer: 0
  explanation: "wasmtime/wasmer — рантаймы для WASM."
- question: "Что нужно учитывать при анализе WASM?"
  options:
    - "Imports от host (JS/OS)"
    - "GOT"
    - "BTF"
    - "SVD"
  answer: 0
  explanation: "Модуль вызывает host-функции через imports."
```

## Где пригодится

- **CTF:** Reversing/Web — WASM-задачи.
- **Анализ web-клиентов:** WASM-крипто/логика.
- **RE игр/DRM:** браузерные приложения.
- **Работа:** web security, analysis.
