---
id: crypto-rsa-attacks
title: "RSA-атаки: common modulus, Wiener, Håstad, Fermat, shared primes"
category: crypto
parent: crypto-rsa-basics
difficulty: hard
order: 1
tags: [crypto, rsa, wiener, hastad, fermat, common-modulus, shared-primes, continued-fractions, broadcast]
prerequisites: [crypto-rsa-basics]
useful_for:
  - "Атаковать RSA по нескольким ключам/шифротекстам"
  - "Применять цепные дроби (Wiener) и CRT (Håstad)"
  - "Распознавать атаку по структуре параметров задачи"
estimated_minutes: 25
summary: "Каталог классических RSA-атак: common modulus (общий n), Wiener (малый d через цепные дроби), Håstad broadcast (малое e, несколько получателей, CRT), атака Ферма (близкие p и q), shared primes (общий простой множитель), малый d и их распознавание по условию задачи. Готовые скрипты."
---

## Как читать условие RSA-задачи

Ключ к успеху — распознать атаку по тому, **какие параметры даны**:

| Что дано | Вероятная атака |
|---|---|
| один `(n, e, c)`, `e` мал | small-e / cube-root (`crypto-rsa-basics`) |
| один `(n, e, c)`, `e` огромен | малый `d` → Wiener |
| `(n, e1, c1)` и `(n, e2, c2)` | common modulus |
| `(n1, c1), (n2, c2), ..., (nk, ck)`, `e` мал, `k ≥ e` | Håstad broadcast |
| `n` не факторизуется, `p ≈ q` | атака Ферма |
| несколько `n`, у них общий делитель | shared primes |
| `n`, часть битов `p`/`d` известна | Coppersmith (`crypto-rsa-advanced`) |

Соберите все параметры в кучу и сопоставьте с таблицей.

## Common modulus attack (общий модуль)

Если **одно сообщение** `m` зашифровано дважды **с одним `n`**, но разными `e1, e2`, причём `gcd(e1, e2) = 1`:

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
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m

m = common_modulus(n, e1, c1, e2, c2)
print(m.to_bytes((m.bit_length()+7)//8, "big"))
```

**Если `gcd(e1,e2) = g > 1`** — атака даёт `m^g`, дальше корень g-й степени (если получится) или Coppersmith.

## Атака Винера (Wiener) — малый `d`

Если приватная экспонента `d` мала (`d < n^0.25 / 3`), её можно восстановить через **непрерывные (цепные) дроби** из `e/n`.

Идея: `e·d ≡ 1 (mod φ)`, значит `e/φ ≈ k/d` для некоторого `k`. Разложение `e/n` в цепную дробь даёт среди подходящих дробей `k/d`.

```python
from sympy import Rational
from sympy.ntheory.continued_fraction import continued_fraction_periodic, continued_fraction_convergents
from sympy import Integer

def wiener(n, e):
    cf = continued_fraction_convergents(
        __import__('sympy').continued_fraction(e, n))
    for conv in cf:
        k, d = conv.p, conv.q
        if k == 0: continue
        # phi = (e*d - 1) / k
        if (e*d - 1) % k != 0: continue
        phi = (e*d - 1) // k
        # n = p*q, phi = (p-1)(q-1) => p+q = n - phi + 1
        s = n - phi + 1
        disc = s*s - 4*n
        if disc < 0: continue
        t = int(disc**0.5)
        if t*t == disc and (s+t) % 2 == 0:
            return int(d)
    return None

d = wiener(n, e)
if d:
    m = pow(c, d, n)
```

**Признак:** `e` подозрительно большой (почти как `n`). Это прямой намёк на малый `d`.

## Håstad broadcast attack

Одно сообщение `m` зашифровано **разными** модулями `n1..nk` с **малым** `e`, причём `k ≥ e`:

```
c1 = m^e mod n1
...
ck = m^e mod nk
```

По **CRT** находим `M = m^e mod (n1·n2·...·nk)`. Если `N = Π ni > m^e`, то `M` — это точное `m^e` (без модуля), и `m = корень_e(M)`.

```python
from sympy.ntheory.modular import crt
from gmpy2 import iroot

def hastad(e, pairs):   # pairs = [(n1,c1),(n2,c2),...]
    ns = [p[0] for p in pairs]
    cs = [p[1] for p in pairs]
    M, N = crt(ns, cs)
    m, exact = iroot(M, e)
    if exact:
        return m.to_bytes((m.bit_length()+7)//8, "big")
    return None
```

**Признак:** несколько пар `(n, c)` с одинаковым малым `e`, и число пар `≥ e`. Классика: `e=3` и три получателя.

## Атака Ферма (близкие p и q)

Если `p` и `q` близки, то `n = p·q` можно разложить быстро. Идея: `n = a^2 - b^2 = (a-b)(a+b)`, где `a = (p+q)/2`, `b = (p-q)/2`. Перебираем `a` от `⌈√n⌉` вверх, пока `a^2 - n` не станет полным квадратом.

```python
from gmpy2 import isqrt

def fermat(n):
    a = isqrt(n) + 1
    for _ in range(1000000):
        b2 = a*a - n
        b = isqrt(b2)
        if b*b == b2:
            return int(a-b), int(a+b)
        a += 1
    return None

p, q = fermat(n)
```

**Признак:** `p` и `q` различаются незначительно (автор сгенерировал их подряд). `n` может быть большим, но разложится за секунды.

## Shared primes (общий простой множитель)

Если даны **два модуля** `n1 = p·q1` и `n2 = p·q2` с **общим простым множителем** `p`, то:

```
p = gcd(n1, n2)
```

Один `gcd` — и оба ключа сломаны.

```python
from math import gcd
p = gcd(n1, n2)
q1 = n1 // p
q2 = n2 // p
```

**Признак:** в задаче несколько публичных ключей/модулей. **Всегда** проверяйте попарные `gcd` всех `n` — это бесплатно и часто срабатывает.

```python
import itertools
for (n1, n2) in itertools.combinations(all_n, 2):
    g = gcd(n1, n2)
    if 1 < g < n1:
        print("shared prime!", g)
```

## Практический пример: выбор атаки

```python
from math import gcd
import itertools

# Шаг 1: shared primes (всегда первым — дёшево)
for n1, n2 in itertools.combinations(all_moduli, 2):
    g = gcd(n1, n2)
    if 1 < g < n1:
        print("shared prime between moduli:", g)

# Шаг 2: e большой? -> Wiener
if e > n // 2:
    d = wiener(n, e)

# Шаг 3: несколько пар, малый e -> Hastad
if len(pairs) >= e and e < 20:
    print(hastad(e, pairs))

# Шаг 4: n не факторизуется и не помогло -> Fermat
if not factors:
    fermat(n)
```

## Как не застрять

- **Соберите ВСЕ параметры.** Атаку диктует структура условия, а не догадка.
- **`gcd` всех `n` — первым делом.** Это одна строка и иногда весь ответ.
- **Wiener если e большой; Fermat если p≈q; Håstad если много пар с малым e.**
- **RsaCtfTool `--attack all`** прогоняет большинство этих атак автоматически.
- **Не факторизуйте «в лоб» большой n.** Используйте структурные атаки.
- **Проверяйте, что атака применима.** Håstad требует `k ≥ e`; Wiener — `d < n^0.25/3`.

## Квиз

```quiz
- question: "В common modulus attack два шифротекста получены:"
  options:
    - "с разными n и разными e"
    - "с одним n и разными e"
    - "с разными n и одним e"
    - "без ключей"
  answer: 1
- question: "Атака Винера применима, когда:"
  options:
    - "e мал"
    - "приватная экспонента d мала"
    - "p и q близки"
    - "n простое"
  answer: 1
- question: "Håstad broadcast требует:"
  options:
    - "один модуль"
    - "число шифротекстов ≥ e при малом e"
    - "малый d"
    - "общий простой множитель"
  answer: 1
- question: "Атака Ферма эффективна, когда:"
  options:
    - "p и q близки"
    - "e = 65537"
    - "d мал"
    - "n простое"
  answer: 0
- question: "Если два модуля имеют общий простой множитель, его находят через:"
  options:
    - "XOR"
    - "gcd(n1, n2)"
    - "корень кубический"
    - "цепные дроби"
  answer: 1
```

## Где пригодится

- **CTF** — основной арсенал RSA-задач среднего и высокого уровня.
- **Аудит TLS/PGP** — поиск общих простых множителей в парке ключей (реальные инциденты с shared primes).
- **Пентест** — анализ слабых ключей на инфраструктуре.
- **Исследования** — понимание границ стойкости RSA.
- **Крипто-разработка** — как НЕ надо генерировать ключи (близкие p,q; малый d).
