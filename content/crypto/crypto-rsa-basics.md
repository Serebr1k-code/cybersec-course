---
id: crypto-rsa-basics
title: "RSA с нуля: устройство, параметры и первые атаки (small-e)"
category: crypto
parent: crypto-number-theory
difficulty: easy
order: 1
tags: [crypto, rsa, textbook-rsa, small-e, cube-root, factorization, padding]
prerequisites: [crypto-number-theory]
useful_for:
  - "Понимать математику RSA и генерацию ключей"
  - "Решать базовые RSA-задачи: малый e, факторизация"
  - "Распознавать слабые параметры по условию"
estimated_minutes: 40
summary: "RSA с нуля: генерация ключей, шифрование/подпись, textbook RSA и почему он небезопасен. Атаки начального уровня: малый e и целочисленный корень, факторизация малого/слабого n, малый размер ключа. Инструменты (RsaCtfTool, sympy, Sage) и распознавание по условию задачи."
---

## Математика RSA

RSA основан на сложности **факторизации** большого числа.

**Генерация ключей:**

1. Выбрать два больших простых `p`, `q`.
2. `n = p·q` (модуль), `φ(n) = (p−1)(q−1)`.
3. Выбрать `e` (публичная экспонента), обычно `65537`, с `gcd(e, φ) = 1`.
4. Вычислить `d = e⁻¹ mod φ(n)` (приватная экспонента).

**Публичный ключ:** `(n, e)`. **Приватный:** `(n, d)`.

**Шифрование:** `c = m^e mod n`. **Расшифрование:** `m = c^d mod n`. **Подпись:** `s = H(m)^d mod n`, проверка `s^e = H(m) mod n`.

## Почему textbook RSA небезопасен

«Голый» RSA (`c = m^e mod n` без padding) **детерминирован** и **мультипликативен**:

- Детерминизм: одинаковый `m` → одинаковый `c` (нет семантической стойкости).
- Мультипликативность: `(m1·m2)^e = m1^e · m2^e`, поэтому `c(m1·m2) = c1·c2 mod n` — атакующий может «склеивать» шифротексты.

Именно поэтому стандарты требуют **padding** (PKCS#1 v1.5, OAEP — см. `crypto-rsa-padding`). В CTF textbook RSA встречается постоянно.

## Атака: малый e и целочисленный корень

Если `e` мал (3, 5, 17) и сообщение `m` короткое (так что `m^e < n`), то модуль **не срабатывает**: `c = m^e` в точности. Тогда `m = c^(1/e)` (целочисленный корень).

```python
from gmpy2 import iroot
m, exact = iroot(c, e)     # exact == True если корень точный
if exact:
    print(m.to_bytes((m.bit_length()+7)//8, "big"))
```

Признак: маленький `c`, `e=3`, `n` большой. Если `m^e ≥ n`, но лишь немного — применяют Coppersmith (см. `crypto-rsa-coppersmith-deep`).

## Атака: факторизация слабого n

Если `n` мал (несколько сотен бит) или его множители «слабые», его факторизуют:

```python
from sympy import factorint
print(factorint(n))            # для n до ~100 бит быстро
# factordb.com — онлайн-база известных факторизаций
```

Признаки слабого `n`:

- Маленький размер (256/512 бит).
- `p` и `q` близки → атака Ферма (см. `crypto-rsa-multi`).
- `n` — произведение многих простых (multi-prime).
- Общий множитель с другим `n` → shared primes.

## Практический пример: полный разбор

```python
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes

n = 0x...   # большой
e = 3
c = 0x...   # маленький

# 1. Пробуем целочисленный корень
m, exact = iroot(c, e)
if exact:
    print(long_to_bytes(int(m)))
else:
    # 2. Если не сошлось — факторизуем n (если он слабый)
    from sympy import factorint
    print(factorint(n))
```

## Инструменты и команды

```bash
pip install pycryptodome gmpy2 sympy
# RsaCtfTool — автоматический перебор известных атак
python3 RsaCtfTool.py --publickey key.pub --uncipher cipher.bin
python3 RsaCtfTool.py --publickey key.pub --attack all
# sage для продвинутых
sage -c "print(factor(2**128-1))"
```

## Частые ошибки

- **Перебирать `d`.** RSA-задачи так не решаются.
- **Забывать про малый `e`.** Первая проверка — `iroot`.
- **Не проверять `n` на слабость.** Факторизация/Ферма/gcd.
- **Путать шифрование и подпись.** Разные экспоненты.
- **Игнорировать padding.** Если он есть — нужна другая атака.
- **Не конвертировать `long_to_bytes`.** Флаг — это байты.

## Подпись RSA и атаки на неё

Подпись `s = H(m)^d mod n`, проверка `s^e ≡ H(m) mod n`. Ошибки применения порождают атаки:

- **Отсутствие padding в подписи** (textbook signature) позволяет подделывать подписи мультипликативно: `s(m1·m2) = s(m1)·s(m2) mod n`. Если подпись запрашивается у оракула для «безобидных» сообщений, произведение даёт подпись для «опасного».
- **Малый e + короткий хэш** — если `H(m)^e < n`, подпись находится без ключа (целочисленный корень).
- **Bleichenbacher на PKCS#1 v1.5** (см. `crypto-rsa-padding`) — oracle по padding подписи/шифрования.
- **Fault attack** — сбой при вычислении подписи (одно ошибочное `s`) позволяет факторизовать `n` через `gcd(s^e − m, n)`.

```python
# Подпись и проверка
from Crypto.PublicKey import RSA
key = RSA.generate(2048)
s = pow(m, key.d, key.n)
assert pow(s, key.e, key.n) == m % key.n
```

## Параметры и их влияние на стойкость

| Параметр | Безопасно | Опасно |
|---|---|---|
| `n` | ≥ 2048 бит | < 1024 бит |
| `e` | 65537 | 3 (без OAEP) |
| `d` | большой (≈ n) | малый (Винер/Boneh-Durfee) |
| `p, q` | далеки, случайны | близки, общий множитель |
| padding | OAEP | отсутствует / v1.5 без constant-time |

## RSA в реальных протоколах

- **TLS:** RSA key exchange (устаревшее) и RSA-подписи в сертификатах; переход на ECDHE.
- **SSH:** RSA-ключи хоста/пользователя; слабые 1024-битные ключи всё ещё встречаются.
- **PGP/GPG:** RSA-шифрование и подпись.
- **JWT (RS256):** подпись RSA; алгоритм-конфузия RS256→HS256 — известная атака.
- **Код-подпись:** Android APK, Windows Authenticode — на RSA.

Знание этих протоколов помогает при аудите: ищите слабые параметры, отсутствие padding, оракулы ошибок.

## Разбор задачи с факторизацией

```python
from sympy import factorint
from Crypto.Util.number import long_to_bytes, inverse

n = 0x...      # например 512 бит
e = 65537
c = 0x...

fac = factorint(n)                 # {p:1, q:1}
p, q = list(fac.keys())
phi = (p-1)*(q-1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

Если `factorint` не справляется — `n` слишком большой; переходите к структурным атакам (Ферма, gcd, Coppersmith).

## Разбор: три классические задачи

**1. Малый e, короткое m.**

```python
from gmpy2 import iroot
m, ok = iroot(c, e)
if ok: print(long_to_bytes(int(m)))
```

**2. Слабый n (маленький/с близкими p,q).**

```python
from sympy import factorint
fac = factorint(n)          # быстро для n < ~100 бит
from Crypto.Util.number import inverse
p, q = list(fac)
d = inverse(e, (p-1)*(q-1))
print(long_to_bytes(pow(c, d, n)))
```

**3. Несколько ключей → gcd.**

```python
from math import gcd
if gcd(n1, n2) != 1:
    p = gcd(n1, n2)         # shared prime!
```

## Что делать по порядку

1. Соберите `n, e, c` (и все дополнительные параметры).
2. `e` мал (3,5,17)? → `iroot`.
3. `e` велик? → Wiener (`crypto-rsa-wiener-bonedurfee`).
4. `n` мал? → факторизация.
5. Несколько `n`? → gcd/shared primes.
6. Несколько `c` с одним `n`? → common modulus.
7. Ничего не помогло? → Coppersmith/partial key.

## Разбор: RSA-подпись и верификация

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

key = RSA.generate(2048)
h = SHA256.new(b"message")
sig = pkcs1_15.new(key).sign(h)
# проверка
pkcs1_15.new(key.publickey()).verify(SHA256.new(b"message"), sig)
```

Атака на слабую подпись: если верификатор не проверяет строго структуру `DigestInfo`, подпись подделывается.

## Разбор: почему RSA работает (маленькая теорема Ферма)

Расшифрование корректно благодаря теореме Эйлера: `m^(ed) ≡ m mod n` при `ed ≡ 1 mod φ(n)`. Для `p, q` простых `φ(n) = (p−1)(q−1)`. Если `m` не взаимно просто с `n` (крайне редко), формула всё равно даёт верный результат по CRT.

## Как не застрять

- **Соберите `(n, e, c)`.** Ищите структуру.
- **`e` мал + `c` мал** → целочисленный корень.
- **`n` слабый** → факторизация/Ферма/gcd.
- **`e` большой** → Wiener.
- **Несколько пар** → common modulus/Håstad.
- **RsaCtfTool `--attack all`** как быстрый прогон.

## Квиз

```quiz
- question: "На чём основана стойкость RSA?"
  options:
    - "на сложности XOR"
    - "на сложности факторизации больших чисел"
    - "на длине ключа XOR"
    - "на хэшировании"
  answer: 1
- question: "Что такое textbook RSA?"
  options:
    - "RSA с OAEP"
    - "`c = m^e mod n` без padding"
    - "RSA с двумя ключами"
    - "RSA на эллиптических кривых"
  answer: 1
- question: "При e=3 и коротком сообщении c равно:"
  options:
    - "`m^3 mod n` всегда"
    - "`m^3` (если `m^3 < n`), и `m` берётся кубическим корнем"
    - "`m + 3`"
    - "`3^m`"
  answer: 1
- question: "Первый шаг при слабом/маленьком n:"
  options:
    - "сразу сдаться"
    - "попробовать факторизацию (sympy/factordb)"
    - "XOR с ключом"
    - "перебрать d"
  answer: 1
- question: "Что автоматизирует RsaCtfTool?"
  options:
    - "хэширование"
    - "перебор известных RSA-атак по заданным параметрам"
    - "генерацию ключей"
    - "AES"
  answer: 1
```

## Где пригодится

- **CTF** — RSA-задачи всех уровней.
- **Анализ TLS/PGP/SSH** — понимание параметров и слабостей ключей.
- **Пентест** — поиск слабых ключей (маленький n, общие простые множители) в инфраструктуре.
- **Крипто-разработка** — понимание, почему нужен padding и большие ключи.
- **Forensics** — восстановление ключей из артефактов.
