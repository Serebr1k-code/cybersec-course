---
id: crypto-rsa-multi
title: "Мультипростой, общий модуль и общие простые множители RSA"
category: crypto
parent: crypto-rsa-factorization
difficulty: hard
order: 3
tags: [crypto, rsa, common-modulus, shared-primes, gcd, fermat, multi-prime, crt, egcd]
prerequisites: [crypto-rsa-attacks]
useful_for:
  - "Ломать RSA по нескольким ключам"
  - "Находить общие простые множители через gcd"
  - "Применять common-modulus и Fermat"
estimated_minutes: 40
summary: "Атаки на RSA по нескольким ключам и модулям: common modulus (один n, разные e, egcd), shared primes (общий простой множитель через gcd), атака Ферма (близкие p и q), мультипростой RSA и его слабости. Практические скрипты и распознавание."
---

## Идея: несколько ключей — больше информации

Если в задаче несколько публичных ключей или модулей, это сигнал к «связным» атакам. Один `gcd` или одно разложение может сломать сразу несколько ключей. Всегда собирайте **все** модули и проверяйте их попарно.

## Common modulus attack

Одно сообщение `m` зашифровано **с одним `n`**, но разными `e1, e2`, причём `gcd(e1, e2) = 1`:

```
c1 = m^e1 mod n
c2 = m^e2 mod n
```

По тождеству Безу найдутся `a, b`: `a·e1 + b·e2 = 1`. Тогда:

```
m = c1^a · c2^b mod n
```

```python
def egcd(a, b):
    if b == 0: return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y

def common_modulus(n, e1, c1, e2, c2):
    g, a, b = egcd(e1, e2)
    assert g == 1
    if a < 0:
        c1 = pow(c1, -1, n); a = -a
    if b < 0:
        c2 = pow(c2, -1, n); b = -b
    return (pow(c1, a, n) * pow(c2, b, n)) % n
```

Если `gcd(e1,e2) = g > 1` — получаем `m^g`, дальше корень g-й степени или Coppersmith.

## Shared primes (общий простой множитель)

Если даны **два модуля** `n1 = p·q1` и `n2 = p·q2` с **общим простым множителем** `p`, то `p = gcd(n1, n2)`. Один `gcd` — и оба ключа сломаны.

```python
from math import gcd
import itertools
for n1, n2 in itertools.combinations(all_n, 2):
    g = gcd(n1, n2)
    if 1 < g < n1:
        print("shared prime!", g)
```

**Всегда проверяйте попарные gcd всех `n`** — это бесплатно и часто срабатывает. Реальные инциденты: плохой RNG генерировал ключи с общими множителями (например, у встроенных устройств).

## Атака Ферма (близкие p и q)

Если `p` и `q` близки, `n = p·q` раскладывается быстро: `n = a² − b² = (a−b)(a+b)`, где `a = (p+q)/2`, `b = (p−q)/2`. Перебираем `a` от `⌈√n⌉` вверх, пока `a² − n` не станет полным квадратом.

```python
from gmpy2 import isqrt

def fermat(n):
    a = isqrt(n) + 1
    for _ in range(10_000_000):
        b2 = a*a - n
        b = isqrt(b2)
        if b*b == b2:
            return int(a-b), int(a+b)
        a += 1
    return None
```

**Признак:** `p` и `q` различаются незначительно (автор сгенерировал их подряд). Работает за секунды даже для больших `n`.

## Мультипростой RSA

`n = p1·p2·...·pk` с `k > 2` простыми. Используется для ускорения (меньшие `p_i`), но **слаб** при малом размере каждого простого: если `k` велик, а `n` фиксирован, каждый `p_i` меньше, и факторизация (ECM, Pollard p−1) становится легче. Также при утечке одного `p_i` (общий с другим ключом) — shared primes.

## Практический пример: выбор атаки

```python
from math import gcd
import itertools

# Шаг 1: shared primes (всегда первым — дёшево)
for n1, n2 in itertools.combinations(all_moduli, 2):
    g = gcd(n1, n2)
    if 1 < g < n1:
        print("shared prime between moduli:", g)

# Шаг 2: common modulus
if len(set(all_e)) > 1 and len(set(all_n)) == 1:
    m = common_modulus(n, e1, c1, e2, c2)

# Шаг 3: n не факторизуется и не помогло -> Fermat
if not factors:
    p, q = fermat(n)
```

## Инструменты и команды

```bash
pip install gmpy2 sympy
# RsaCtfTool
python3 RsaCtfTool.py --publickey key.pub --attack all
# sage
sage -c "print(gcd(n1, n2))"
```

## Частые ошибки

- **Не проверять gcd всех `n`.** Самая частая недоработка.
- **Считать Ферма бесполезным для больших `n`.** Работает при близких p,q.
- **Путать common modulus и shared primes.** Разные условия.
- **Забыть про случай `gcd(e1,e2) > 1`.** Тогда нужен корень.
- **Не собирать все параметры** из условия.
- **Игнорировать multi-prime** при `n` с маленькими множителями.

## Multi-prime RSA детальнее

`n = p1·p2·...·pk`. При фиксированном размере `n` увеличение `k` уменьшает каждый `p_i`, что ускоряет расшифрование (CRT), но **снижает стойкость**: факторизация методом ECM зависит от размера наименьшего множителя, а Pollard `p−1` срабатывает, если `p_i − 1` гладко. Если `k` велик (например, 10 простых по 100 бит), ECM находит множители за реальное время.

**Признак multi-prime:** `n` «круглый» размер (1024/2048), но факторизация «ломается» на много частей; либо задача прямо говорит «multi-prime».

```python
from sympy import factorint
# для multi-prime factorint может справиться при малых множителях
print(factorint(n))
```

## Разбор: shared primes на практике

Реальный инцидент: устройства с плохим RNG генерировали RSA-ключи, у которых `gcd` попарно не равен 1. Собрав публичные ключи (SSH, TLS) и посчитав все `gcd`, исследователи ломали тысячи ключей. Скрипт:

```python
from math import gcd
import itertools, glob
moduli = [int(open(f).read().strip()) for f in glob.glob("keys/*.n")]
for a, b in itertools.combinations(moduli, 2):
    g = gcd(a, b)
    if 1 < g < a:
        print("pwned:", g)
```

## Разбор: Fermat на практике

```python
# p и q сгенерированы как next_prime(random) + небольшое смещение
from gmpy2 import isqrt
def fermat(n, limit=10**7):
    a = isqrt(n)
    if a*a < n: a += 1
    for _ in range(limit):
        b2 = a*a - n
        b = isqrt(b2)
        if b*b == b2:
            return int(a-b), int(a+b)
        a += 1
    return None
print(fermat(n))
```

Если `p` и `q` отличаются на несколько тысяч — разложится мгновенно.

## Разбор: common modulus с числами

```python
n = 0x...; e1 = 3; e2 = 5
c1 = pow(m, e1, n); c2 = pow(m, e2, n)
# gcd(3,5)=1, ищем a*3 + b*5 = 1 -> a=2, b=-1
a, b = 2, -1
m = (pow(c1, a, n) * pow(pow(c2, -1, n), -b, n)) % n
print(long_to_bytes(m))
```

Если `gcd(e1,e2)=g>1`, получаем `m^g` — далее корень или Coppersmith.

## Разбор: shared primes на большом парке

```python
import itertools
from math import gcd
# собрали публичные модули (например, из TLS-сертификатов)
moduli = [...]
vuln = 0
for a, b in itertools.combinations(moduli, 2):
    g = gcd(a, b)
    if 1 < g < a:
        vuln += 1
        print("vuln key:", g)
print("total vulnerable:", vuln)
```

На реальном парке ключей с плохим RNG это ломает тысячи ключей.

## Разбор: асимметрия Ферма

Если `p` и `q` близки, но не очень (`|p−q|` велик), Fermat медленный. Тогда используют **обобщённый Fermat** (поиск `a` с `a²−n = b²·k` для малых `k`) или **Hart's method** (быстрая сходимость). Для `|p−q|` в пределах нескольких миллионов — обычный Fermat работает за секунды.

## Как не застрять

- **Соберите ВСЕ `n`, `e`, `c`.**
- **gcd всех `n`** — первым делом.
- **Один `n`, разные `e`** → common modulus.
- **`p ≈ q`** → Fermat.
- **Много простых** → ECM/Pollard.
- **RsaCtfTool `--attack all`** как быстрый прогон.

## Квиз

```quiz
- question: "Common modulus attack требует:"
  options:
    - "факторизации n"
    - "двух шифротекстов одного сообщения с разными e при одном n и gcd(e1,e2)=1"
    - "малого d"
    - "padding oracle"
  answer: 1
- question: "Как обнаружить общий простой множитель двух модулей?"
  options:
    - "через gcd(n1, n2)"
    - "через XOR"
    - "через хэш"
    - "через перебор d"
  answer: 0
- question: "Fermat-факторизация эффективна, когда:"
  options:
    - "p и q далеки друг от друга"
    - "p и q близки (|p-q| мал)"
    - "e = 3"
    - "d мал"
  answer: 1
- question: "Мультипростой RSA использует:"
  options:
    - "один простой множитель"
    - "n = p1*p2*...*pk, k > 2"
    - "только ECC"
    - "два ключа"
  answer: 1
- question: "Если gcd(n1, n2) == n1, это скорее всего:"
  options:
    - "shared-prime атака"
    - "common-modulus (одинаковый n, разные e)"
    - "Fermat"
    - "ошибка ввода"
  answer: 1
```

## Где пригодится

- **CTF (hard)** — задачи с несколькими ключами; самая частая «RSA-связка».
- **Bug bounty** — аудит генерации ключей, слабый RNG у нескольких сертификатов.
- **Пентест инфраструктуры** — сбор публичных ключей (SSH/TLS) и поиск общих множителей.
- **Работа** — расследование инцидентов с утечкой ключей, оценка энтропии генерации.
- **Крипто-разработка** — почему нельзя повторно использовать `p` между ключами.
