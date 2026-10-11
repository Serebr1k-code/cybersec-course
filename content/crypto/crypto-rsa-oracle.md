---
id: crypto-rsa-oracle
title: "RSA parity/LSB oracle и Manger (OAEP)"
category: crypto
parent: crypto-rsa-padding
difficulty: hard
order: 1
tags: [crypto, rsa, parity-oracle, lsb-oracle, manger, oaep, chosen-ciphertext, bleichenbacher]
prerequisites: [crypto-rsa-padding]
useful_for:
  - "Восстанавливать сообщение по одному биту на запрос"
  - "Понимать Manger-атаку на OAEP"
  - "Различать типы RSA-оракулов"
estimated_minutes: 45
summary: "RSA parity/LSB oracle: восстановление сообщения за ~n бит запросов через бинарный поиск по интервалу. Manger attack на OAEP. Сравнение с Блейхенбахером, распознавание оракула по условию задачи, полный рабочий скрипт и защита (constant-time, единый ответ)."
---

## Идея оракулов в RSA

RSA-оракул — это сервис, который по запросу расшифровывает `c'` и сообщает **один бит** информации о результате. Виды:

- **Parity/LSB oracle:** возвращает чётность (младший бит) `m' = c'^d mod n`.
- **Padding oracle (PKCS#1 v1.5):** сообщает, валиден ли padding (Блейхенбахер, `crypto-rsa-padding`).
- **Manger oracle (OAEP):** сообщает, равен ли старший байт нулю.

Любой такой бит позволяет **восстановить всё сообщение** за `O(n_bits)` запросов через бинарный поиск по интервалу. Это классика выбранно-шифротекстных атак.

## Parity oracle: механика

Ключевое свойство: **умножение шифротекста на `2^e mod n`** соответствует умножению открытого текста на 2 (по модулю n):

```
(c · 2^e) mod n  расшифровывается в  (2m mod n)
```

Схема атаки (интервал `[lo, hi]`, изначально `[0, n]`):

1. Запрос: `oracle(c · 2^e)`. Если `2m mod n` чётно → `2m < n` (то есть `m < n/2`), иначе `2m ≥ n`.
2. Сужаем интервал: если чётно — `hi = (lo+hi)/2`, иначе `lo = (lo+hi)/2`.
3. Повторяем, каждый раз умножая на `2^e` (то есть исследуя `2^k·m mod n`).
4. После ~`log2(n)` итераций `lo == hi == m`.

Точнее: поддерживаем `m_k = (m · 2^k) mod n` и используем чётность, чтобы определить, «переполнился» ли модуль. Это **бинарный поиск** по значению `m`.

## Полный рабочий скрипт

```python
from Crypto.Util.number import long_to_bytes

def parity_oracle(c_modified):
    # сервер: m = pow(c_modified, d, n); return m & 1
    ...

n = ...
e = ...
c = ...
lo, hi = 0, n
factor = pow(2, e, n)          # множитель для m -> 2m
for _ in range(n.bit_length()):
    c = (c * factor) % n       # теперь расшифровывается в 2m mod n
    if parity_oracle(c) == 0:  # чётно -> 2m < n
        hi = (lo + hi) // 2
    else:
        lo = (lo + hi) // 2
m = (lo + hi) // 2
print(long_to_bytes(m))
```

Обратите внимание: каждый запрос даёт один бит; всего нужно ~`bit_length(n)` запросов (1024/2048). Это дёшево.

## Manger attack на OAEP

Manger (2001) эксплуатирует другой oracle: OAEP-расшифровка проверяет, что **первый байт == 0x00**. Если сервер различает «первый байт 0» и «первый байт ≠ 0», применима атака:

1. Атакующий умножает `c` на `f^e` (f подбирается), чтобы «сдвинуть» `m` в нужный диапазон.
2. Каждый ответ (старший байт == 0?) сужает интервал `[n/256, 2n/256]`-типа.
3. За ~`8·log256(n)` запросов `m` восстанавливается.

Это **аналог** Блейхенбахера, но для OAEP. Требует oracle, различающий «первый байт нулевой». Реальные реализации могут утекать это через код ошибки или тайминг.

## Сравнение оракулов

| Оракул | Что утекает | Схема | Число запросов |
|---|---|---|---|
| Parity/LSB | младший бит | любой | ~n_bits |
| PKCS#1 v1.5 | валидность padding | PKCS#1 v1.5 | ~2^20 |
| Manger | старший байт == 0 | OAEP | ~8·log256(n) |
| Timing | время | разные | зависит |

## Распознавание

- «oracle возвращает чётность/младший бит» → parity oracle.
- «padding valid/invalid» → Блейхенбахер.
- «OAEP», «первый байт», «leading zero» → Manger.
- Дан `(n, e, c)` и интерактивный сервис.

## Практический пример (упрощённо, с отладкой)

```python
# Локальный oracle с известным ключом для проверки атаки
from Crypto.PublicKey import RSA
key = RSA.generate(512)
n, e, d = key.n, key.e, key.d
m_secret = 0xdeadbeefcafe
c_secret = pow(m_secret, e, n)

def parity_oracle(c):
    return pow(c, d, n) & 1

# атака
lo, hi, c = 0, n, c_secret
for _ in range(n.bit_length()):
    c = (c * pow(2, e, n)) % n
    if parity_oracle(c) == 0:
        hi = (lo + hi) // 2
    else:
        lo = (lo + hi) // 2
print(hex((lo + hi)//2), hex(m_secret))
```

## Инструменты и команды

```bash
pip install pycryptodome
# готовые PoC: RSA parity oracle, Manger attack (GitHub)
python3 -c "from Crypto.Util.number import long_to_bytes; print('ok')"
```

## Частые ошибки

- **Неверный множитель.** Нужно `2^e mod n`, а не `2`.
- **Перепутать чётность.** `0` → `2m < n`; `1` → `2m ≥ n`.
- **Мало итераций.** Нужно ~`bit_length(n)`.
- **Шумный oracle.** Тайминги требуют повторов/статистики.
- **Считать OAEP безопасным от oracle.** Manger существует.
- **Забыть про padding в Manger.** Manger работает на OAEP-структуре.

## Почему атака работает: интуиция

Представьте, что `m` — точка на числовой прямой `[0, n)`. Запрос `c·2^e` расшифровывается в `2m mod n`. Если `2m < n`, результат — чётное число (младший бит 0); если `2m ≥ n`, результат — `2m − n` (нечётное, младший бит 1). Один бит сообщает, в какой половине лежит `m`. Умножая дальше (на `4, 8, ...`), мы последовательно делим интервал пополам — это **двоичный поиск** по значению секрета. `log2(n)` шагов — и `m` известен точно.

Это иллюстрирует общий принцип: **любая утечка одного бита о результате расшифрования ломает RSA целиком.** Поэтому криптографические реализации обязаны быть «герметичными»: ни ошибки, ни тайминги не должны зависеть от секрета.

## Варианты оракулов и их распознавание

| Формулировка в задаче | Оракул | Атака |
|---|---|---|
| «возвращает чётность», «LSB» | parity | бинарный поиск |
| «padding valid/invalid» | PKCS#1 v1.5 | Bleichenbacher |
| «OAEP», «leading zero» | Manger | Manger |
| «время ответа зависит от…» | timing | статистика/Marvin |
| «возвращает старший бит» | MSB | бинарный поиск |

## Полный рабочий скрипт (с защитой от шума)

```python
from Crypto.Util.number import long_to_bytes

def parity_oracle(c, retries=3):
    # усреднение/повтор для борьбы с шумом
    votes = [oracle(c) for _ in range(retries)]
    return 1 if sum(votes) > retries/2 else 0

def rsa_parity_attack(n, e, c, oracle):
    lo, hi = 0, n
    factor = pow(2, e, n)
    for _ in range(n.bit_length()):
        c = (c * factor) % n
        if parity_oracle(c) == 0:
            hi = (lo + hi) // 2
        else:
            lo = (lo + hi) // 2
    return (lo + hi) // 2

m = rsa_parity_attack(n, e, c, oracle)
print(long_to_bytes(m))
```

## Защита: как не создать оракул

- **Constant-time** расшифрование и проверки.
- **Единый ответ об ошибке** (одинаковый текст, код, длина).
- **Не логировать** причину ошибки расшифрования.
- **Blinding** на стороне сервера (RSA blinding) для защиты от timing.
- **OAEP** вместо v1.5 и корректная проверка (без раннего выхода).
- **Отказ от RSA-шифрования** в пользу ECDH/Hybrid (RSA-KEM).

## Как не застрять

- **Определите тип оракула** (чётность/паддинг/старший байт).
- **Parity** → бинарный поиск с `2^e`.
- **Padding v1.5** → Блейхенбахер.
- **OAEP** → Manger.
- **Возьмите готовый PoC** и адаптируйте.
- **Проверяйте сходимость** на локальном ключе.

## Квиз

```quiz
- question: "Parity/LSB oracle восстанавливает сообщение за:"
  options:
    - "O(n^2) запросов"
    - "~n_bits запросов (бинарный поиск по интервалу)"
    - "1 запрос"
    - "2^256 запросов"
  answer: 1
- question: "Умножение шифротекста на 2^e mod n соответствует:"
  options:
    - "m -> 2m mod n"
    - "m -> m^2"
    - "m -> m + 1"
    - "m -> 0"
  answer: 0
- question: "Manger attack нацелена на:"
  options:
    - "RSA-OAEP (oracle: старший байт равен 0?)"
    - "ECC"
    - "AES"
    - "хэши"
  answer: 0
- question: "Что общего у Bleichenbacher и Manger?"
  options:
    - "обе эксплуатируют утечку padding-валидности"
    - "обе факторизуют n"
    - "обе про ECC"
    - "обе не требуют oracle"
  answer: 0
- question: "Лучшая защита от padding-oracle атак:"
  options:
    - "constant-time обработка и единый ответ об ошибке"
    - "увеличить n"
    - "использовать XOR"
    - "малый e"
  answer: 0
```

## Где пригодится

- **CTF (expert)** — «oracle возвращает чётность», «padding valid?».
- **Реальные стеки** — ROBOT-атака на TLS, аналоги в API-подписях.
- **Аудит** — поиск oracle-поведения в реализациях RSA.
- **Работа (IR)** — разбор утечек через timing/ошибки.
- **Крипто-разработка** — constant-time и унификация ошибок.
