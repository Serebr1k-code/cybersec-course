---
id: crypto-prng
title: "PRNG: предсказание MT19937 и Python random"
category: crypto
parent: crypto-stream-ciphers
difficulty: medium
order: 1
tags: [crypto, prng, mt19937, python-random, lcg, seed, predictability, mersenne-twister]
prerequisites: [crypto-stream-ciphers]
useful_for:
  - "Предсказывать выход MT19937 по 624 значениям"
  - "Ломать слабые генераторы токенов и ключей"
  - "Восстанавливать seed и состояние PRNG"
estimated_minutes: 40
summary: "Генераторы псевдослучайных чисел: почему Python random (MT19937) предсказуем по 624 выходам, как восстанавливается состояние и seed, атаки на LCG (линейный конгруэнтный генератор), поиск слабого seed, безопасная альтернатива (secrets/os.urandom). Практические скрипты."
---

## PRNG и CSPRNG

**PRNG** (pseudo-random number generator) детерминирован: по внутреннему состоянию (seed) он детерминированно порождает последовательность. Если состояние восстановлено — вся последовательность (и прошлая, и будущая) известна.

**CSPRNG** (cryptographically secure PRNG) спроектирован так, чтобы по выходу нельзя было восстановить состояние. Примеры: `os.urandom`, `/dev/urandom`, `secrets`, `getrandom()`. **Используйте только их для ключей, токенов, nonce.**

Ошибка №1 в реальном коде: использование `random` (Python), `Math.random()` (JS), `rand()` (C) для генерации секретов. Все они **не** криптостойкие и предсказуемы.

## MT19937 и Python random

Python `random` использует **Mersenne Twister (MT19937)**: состояние — 624 32-битных слова (19937 бит). Генерация — линейная операция над GF(2).

Ключевой факт: **624 последовательных 32-битных выхода полностью определяют состояние.** После этого можно предсказать все будущие (и прошлые) значения. Если приложение использует `random` для токенов сброса пароля/сессий/OTP — оно ломается.

```python
import random
random.seed(12345)
outputs = [random.getrandbits(32) for _ in range(624)]
# по этим 624 значениям восстанавливаем состояние и предсказываем
```

## Атака: восстановление состояния MT19937

Состояние MT19937 — 624 слова. Зная 624 выхода `getrandbits(32)`, можно **отменить tempering** (выход проходит через обратимое преобразование `_temper`) и восстановить состояние.

```python
def untemper(y):
    y ^= y >> 18
    y ^= (y << 15) & 0xefc60000
    y ^= ((y << 7) & 0x9d2c5680)
    # для y ^= y>>11 нужно итеративно (старшие биты уже исправлены)
    for _ in range(3):
        y ^= y >> 11
    return y & 0xffffffff

# клонируем состояние
state = [untemper(x) for x in outputs]
# подставляем в новый генератор
clone = random.Random()
clone.setstate((3, tuple(state + [624]), None))
print(clone.getrandbits(32))   # = следующее значение оригинала
```

Если приложение выдаёт **меньше 32 бит** за раз (например, `random.randint(0, 255)`), нужно собирать биты по кусочкам или применять другие методы (например, решать систему над GF(2) через Z3).

## Восстановление seed

Если состояние недоступно, но известен **диапазон seed** (например, `random.seed(int(time.time()))`), можно перебрать seed:

```python
import random, time
target = 1234567890   # известный первый выход
for t in range(int(time.time())-3600, int(time.time())+1):
    random.seed(t)
    if random.getrandbits(32) == target:
        print("seed =", t); break
```

Признак: seed из timestamp, PID, user ID — перебираемо.

## LCG: линейный конгруэнтный генератор

LCG: `x_{i+1} = (a·x_i + c) mod m`. По нескольким последовательным выходам `a`, `c`, `m` восстанавливаются:

- `m` — через `gcd` разностей: `m = gcd(x2-x1, x3-x2, ...)` (при неизвестном m).
- `a`, `c` — из системы линейных уравнений.

```python
from math import gcd
# зная x1,x2,x3,x4:
m = gcd(x2-x1, x3-x2)          # если m неизвестно (может быть кратно)
# затем a = (x2-x1)*inv(x1-x0) mod m, c = x1 - a*x0 mod m
```

LCG используется в Java `Random` (48-бит состояние, предсказуем по 2 выходам), в glibc `rand()`, в старых языках.

## Практический пример: предсказание OTP

```python
import random, requests
# Приложение генерирует OTP через random.randint(0, 999999)
# Собираем 624 выходов getrandbits(32) через какой-то канал (или OTP-и)
# ... восстанавливаем состояние ...
clone = random.Random(); clone.setstate(state)
next_otp = clone.randint(0, 999999)
print("predicted OTP:", next_otp)
```

## Инструменты и команды

```bash
pip install randcrack z3-solver
# randcrack: удобное восстановление MT19937
python3 - <<'EOF'
from randcrack import RandCrack
rc = RandCrack()
for _ in range(624):
    rc.submit(random.getrandbits(32))
print(rc.predict_getrandbits(32))
EOF
```

## Частые ошибки

- **Использовать `random` для секретов.** Предсказуемо.
- **Мало выходов.** Нужно 624 (или меньше при частичной информации + Z3).
- **Путать getrandbits(32) и randint.** Разное число бит.
- **Забыть про tempering.** Без `untemper` состояние не восстановить.
- **Игнорировать seed.** Если он слабый — перебор быстрее.
- **Считать CSPRNG предсказуемым.** `os.urandom` не ломается так.

## Другие PRNG и их слабости

- **Java `Random`:** 48-битный LCG. По **двум** последовательным выходам `nextInt` состояние восстанавливается полностью. `java.util.Random` **не** криптостойкий; используйте `SecureRandom`.
- **glibc `rand()`:** аддитивный генератор, предсказуем по нескольким десяткам выходов.
- **PHP `rand()`/`mt_rand()`:** `mt_rand` — MT19937, предсказуем.
- **C `rand()`:** зависит от libc, часто LCG или линейный.
- **JS `Math.random()`:** движко-зависимый, но не CSPRNG (V8 — xorshift128+; ломается по нескольким выходам).

## Подход через Z3

Если выход усечён (например, `random.randint(0, 255)` даёт только 8 бит за раз), можно построить систему битовых уравнений MT19937 и решить через Z3:

```python
from z3 import BitVec, BitVecVal, Solver, LShR

# Построить переменные состояния MT (624 x 32 бит), уравнения tempering,
# ограничения на известные усечённые выходы, и решить.
s = Solver()
# ... (построение модели — код на несколько десятков строк) ...
if s.check() == ...:
    m = s.model()
```

Это мощный подход для «частичных» утечек.

## Разбор: предсказание токена

```python
from randcrack import RandCrack
import requests

rc = RandCrack()
# Приложение выдаёт "случайные" ID через random.getrandbits(32)
for i in range(624):
    r = requests.get(f"http://target/item/{i}")
    rc.submit(int(r.json()["id"]))
# Предсказываем следующий
print(rc.predict_getrandbits(32))
```

## Разбор: seed-атака на токены

```python
import random, time
# Приложение: token = random.randint(0, 10**6) сразу после старта
# и seed = int(time.time())
known_token = 873421
now = int(time.time())
for t in range(now - 7200, now + 1):    # окно ±2 часа
    random.seed(t)
    if random.randint(0, 10**6) == known_token:
        print("seed =", t)
        print("next =", random.randint(0, 10**6))
        break
```

## Разбор: LCG в Java

```python
# java.util.Random: state = (state * 0x5DEECE66D + 0xB) & ((1<<48)-1)
# nextInt(n) использует старшие биты. По двум nextInt(2^32) состояние восстанавливается.
```

## Пара слов о криптостойких PRNG

`os.urandom` (Linux) — это `getrandom()`/`/dev/urandom`, основанный на ChaCha20 после сбора энтропии. Он **не** ломается предсказанием. Если задача использует `os.urandom`/`secrets`, атакуйте не генератор, а **потребление** (например, reuse ключа/IV, утечка состояния через форк).

## Разбор: полный клон MT19937

```python
import random
from randcrack import RandCrack

# 1. Собираем 624 выхода
outputs = [get_next_output() for _ in range(624)]   # ваша функция добычи
rc = RandCrack()
for o in outputs:
    rc.submit(o)
# 2. Предсказываем
predicted = rc.predict_getrandbits(32)
```

Если выходы усечены (например, 16 бит), используйте Z3-модель MT19937.

## Разбор: LCG

```python
from math import gcd
def crack_lcg(xs):
    diffs = [xs[i+1]-xs[i] for i in range(len(xs)-1)]
    m = 0
    for d in diffs:
        m = gcd(m, abs(d))
    # уточнить m (может быть кратно), затем a, c по первым трём
    a = (xs[2]-xs[1]) * pow(xs[1]-xs[0], -1, m) % m
    c = (xs[1] - a*xs[0]) % m
    return a, c, m
```

## Как не застрять

- **Определите генератор** (Python random, LCG, кастомный).
- **Соберите достаточно выходов** (624 для MT19937).
- **Примените untemper + клонирование.**
- **Проверьте seed-перебор** при малом пространстве.
- **Для LCG** решайте систему.
- **Если CSPRNG** — ищите другой вектор (утечка состояния/seed).

## Квиз

```quiz
- question: "Почему Python `random` небезопасен для криптографии?"
  options:
    - "он медленный"
    - "MT19937 линейный и предсказуемый по 624 выходам"
    - "он не генерирует числа"
    - "он использует AES"
  answer: 1
- question: "Сколько 32-битных выходов MT19937 нужно для восстановления состояния?"
  options:
    - "32"
    - "128"
    - "624"
    - "65536"
  answer: 2
- question: "Какая безопасная альтернатива `random` в Python?"
  options:
    - "`time`"
    - "`secrets` / `os.urandom`"
    - "`math.random`"
    - "`hashlib`"
  answer: 1
- question: "LCG ломается, потому что:"
  options:
    - "он нелинейный"
    - "рекуррентность линейна — по выходам восстанавливаются a, c, m"
    - "он слишком быстрый"
    - "он использует ключ"
  answer: 1
- question: "Если генератор криптостойкий (CSPRNG), атака:"
  options:
    - "работает так же"
    - "не работает — ищите другой вектор"
    - "требует 2^256 запросов"
    - "ломает ключ"
  answer: 1
```

## Где пригодится

- **CTF** — «угадай следующее число», предсказание токенов.
- **Web-пентест** — слабые токены сброса пароля, сессии, OTP.
- **Аудит** — проверка использования CSPRNG в критичных местах.
- **Реверс** — определение генератора в бинарниках.
- **Крипто-разработка** — почему нельзя `random` для ключей.
