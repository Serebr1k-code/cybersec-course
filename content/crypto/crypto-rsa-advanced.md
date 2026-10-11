---
id: crypto-rsa-advanced
title: "Продвинутый RSA: частичный ключ, Coppersmith, Franklin-Reiter"
category: crypto
parent: crypto-rsa-advanced-attacks
difficulty: expert
order: 2
tags: [crypto, rsa, coppersmith, franklin-reiter, partial-key, lll, small-roots, stereotyped]
prerequisites: [crypto-rsa-attacks, crypto-rsa-small-e-hastad]
useful_for:
  - "Атаковать RSA при частичной утечке ключа"
  - "Применять Coppersmith и Franklin-Reiter"
  - "Понимать решёточные атаки на RSA"
estimated_minutes: 45
summary: "Продвинутые атаки на RSA: Franklin-Reiter (линейно связанные сообщения), Coppersmith (малые корни полинома), восстановление ключа при известных старших битах p или d, stereotyped messages. Разбор с кодом на Sage, распознавание и связь с решётками."
---

## Обзор продвинутых атак

Когда базовые атаки (малый e, common modulus, Ферма, Винер) не работают, остаются **решёточные** атаки — самые мощные и самые «злые» в CTF. Их объединяет идея: если атакующий знает **часть** ключевого материала или сообщение имеет **структуру**, задача сводится к поиску **малого корня полинома** (Coppersmith) или к **gcd полиномов** (Franklin-Reiter).

## Franklin-Reiter

Если два сообщения **линейно связаны** (`m2 = a·m1 + b mod n`), зашифрованы одним ключом с малым `e`, то `m1` находится через `gcd` двух полиномов над `Z_n[x]`:

```python
# Sage
R.<x> = PolynomialRing(Zmod(n))
f1 = x^e - c1
f2 = (a*x + b)^e - c2
g = f1.gcd(f2)
# g линейный -> корень = m1
m1 = -g[0] / g[1]   # из ax + b
```

Условие: `e` мал (обычно 3), связь линейная. Обобщение — несколько связанных сообщений (Coppersmith).

## Coppersmith: малые корни

Теорема Coppersmith: если `f(x)` — монический полином степени `d` по модулю `N`, и `f(x0) ≡ 0 mod N` имеет корень `|x0| < N^(1/d)`, то `x0` находится за полиномиальное время (решётка + LLL).

В Sage: `small_roots(X, beta)`:

```python
# Sage
N = ...
R.<x> = PolynomialRing(Zmod(N))
f = x^2 + a*x + b
roots = f.small_roots(X=2^40, beta=0.5)
print(roots)
```

`X` — верхняя граница корня, `beta` — доля `N`, которую делит неизвестный множитель (для полного `N` beta=1; для факторизации beta<0.5).

## Атака: известны старшие биты p

Если известны старшие биты `p` (`p = p_high + x`, `x < N^0.25`), то `p_high + x` делит `n`. Строим полином `f(x) = p_high + x mod n` и ищем малый корень:

```python
# Sage
N = ...
p_high = ...      # известные старшие биты
R.<x> = PolynomialRing(Zmod(N))
f = p_high + x
roots = f.small_roots(X=2^unknown_bits, beta=0.4)
p = p_high + roots[0]
q = N // p
```

Аналогично для `d` (известны старшие биты `d`) — комбинируется с Boneh-Durfee.

## Атака: stereotyped message

Сообщение имеет известную структуру: `m = m0 + x`, где `m0` известен (например, ASCII-префикс), `x` мал (несколько байт). Тогда `(m0 + x)^e ≡ c mod n` — полином от `x`, и Coppersmith находит `x`.

```python
# Sage
m0 = bytes_to_long(b"flag{") << (8*20)   # известный префикс + место под x
R.<x> = PolynomialRing(Zmod(N))
f = (m0 + x)^e - c
x0 = f.small_roots(X=2^(8*20))[0]
m = m0 + x0
```

## Восстановление ключа при частичном d

Если известны младшие/старшие биты `d`, применяют решётку (HNP-подобную) или Boneh-Durfee-модификации. Это уже «экспертный» уровень, но на CTF встречается в задачах «дано d mod 2^k» или «известно, что d начинается с ...».

## Практический пример: Franklin-Reiter

```python
# Sage
n, e = ...
c1, c2 = ...
a, b = ...   # m2 = a*m1 + b
R.<x> = PolynomialRing(Zmod(n))
f1 = x^e - c1
f2 = (a*x + b)^e - c2
g = f1.gcd(f2)
print(g)     # линейный -> m1
m1 = int(-g[0] / g[1])
print(bytes.fromhex(hex(m1)[2:]))
```

## Инструменты и команды

```bash
sudo apt install sagemath
pip install pycryptodome gmpy2
# Coppersmith: https://github.com/defund/coppersmith (sage-скрипт)
sage -c "load('coppersmith.sage'); print('ok')"
```

## Частые ошибки

- **Неверная граница `X`.** Coppersmith требует `X < N^(1/d)`; слишком большой `X` → не найдёт.
- **Полином не монический.** Приведите к моническому (умножьте на обратный ведущий коэффициент).
- **Не тот `beta`.** Для факторизации `beta < 0.5`, для полного модуля `beta=1`.
- **Путать Franklin-Reiter и Coppersmith.** Разные условия.
- **Игнорировать `e`.** При большом `e` эти атаки не работают.
- **Нет Sage.** Coppersmith практически невозможно реализовать вручную.

## Обзор решёточных атак на RSA

Все продвинутые атаки на RSA сводятся к одной из двух идей:

1. **Поиск малого корня** (Coppersmith): если существует `x0` с `f(x0) ≡ 0 mod N` и `|x0|` мал, решётка его находит.
2. **gcd полиномов** (Franklin-Reiter): если есть несколько полиномиальных уравнений от одного секрета, их общий корень находится через `gcd`.

Применения:

| Утечка | Полином | Метод |
|---|---|---|
| известный префикс `m0` | `(m0+x)^e − c` | Coppersmith |
| старшие биты `p` | `p_high + x` | Coppersmith (beta<0.5) |
| линейная связь сообщений | `x^e−c1`, `(ax+b)^e−c2` | Franklin-Reiter |
| разные paddings | система `(a_i x+b_i)^e−c_i` | CRT + Coppersmith |
| младшие биты `d` | HNP-полином | решётка/Boneh-Durfee |

## Полный пример: факторизация по старшим битам p

```python
# Sage
n = 0x...
p_high = 0x...        # известные старшие биты p (например, 768 из 1024)
unknown_bits = n.nbits() - p_high.nbits()
R.<x> = PolynomialRing(Zmod(n))
f = p_high + x
roots = f.small_roots(X=2^unknown_bits, beta=0.4)
if roots:
    p = p_high + roots[0]
    q = n // p
    assert p*q == n
    print("factored:", p, q)
```

Граница: `unknown_bits < n.nbits()/4` (при `beta=0.5`). Если неизвестных бит больше — атака не сработает.

## Полный пример: stereotyped message

```python
# Sage
n, e, c = ...
m0 = bytes_to_long(b"The flag is: ")     # известный префикс
R.<x> = PolynomialRing(Zmod(n))
f = (m0 * 2^(8*30) + x)^e - c            # 30 неизвестных байт
x0 = f.small_roots(X=2^(8*30), beta=1.0)
if x0:
    m = m0 * 2^(8*30) + x0[0]
    print(bytes.fromhex(hex(int(m))[2:]))
```

## Разбор: Franklin-Reiter с числами

```python
# Sage
n = 0x...; e = 3
c1 = 0x...
c2 = 0x...
a = 1; b = 0x...    # m2 = a*m1 + b (например, m2 = m1 + delta)
R.<x> = PolynomialRing(Zmod(n))
f1 = x^e - c1
f2 = (a*x + b)^e - c2
g = f1.gcd(f2)              # степень 1
print(g)                    # например, x + c
m1 = int(-g[0] / g[1])
from Crypto.Util.number import long_to_bytes
print(long_to_bytes(m1))
```

Если `gcd` даёт степень 1 — успех. Если степень больше — `e` больше 3 или связь не линейна.

## Разбор: Coppersmith для маленького корня

```python
# Sage
n = 0x...; e = 3; c = 0x...
m0 = 0x1234567890abcdef << (8*10)   # известный префикс, 10 неизвестных байт
R.<x> = PolynomialRing(Zmod(n))
f = (m0 + x)^e - c
roots = f.small_roots(X=2^(8*10), beta=1.0)
if roots:
    m = m0 + roots[0]
    print(long_to_bytes(int(m)))
```

## Другие приёмы

- **CRT-утечка:** если известен `p mod k` для маленького `k`, комбинируйте с Coppersmith по модулю `p`.
- **Common modulus с gcd(e1,e2)>1:** получите `m^g` и извлеките корень (если `m^g < n`) или Coppersmith.
- **Partial key exposure:** известны младшие биты `d` — HNP-решётка.
- **Fault attacks:** одна ошибочная подпись → `gcd(s^e − m, n)` факторизует `n`.

## Как не застрять

- **Линейная связь сообщений** → Franklin-Reiter.
- **Известна структура/префикс** → Coppersmith (stereotyped).
- **Известны старшие биты `p`** → Coppersmith по модулю `p`.
- **Известны биты `d`** → Boneh-Durfee/решётки.
- **Используйте готовый `coppersmith.sage`.**
- **Проверяйте границы** (`X`, `beta`).

## Квиз

```quiz
- question: "Franklin-Reiter атакует:"
  options:
    - "один шифротекст"
    - "два линейно связанных сообщения с малым e под одним ключом"
    - "общий модуль с разными e"
    - "хэши"
  answer: 1
- question: "Coppersmith находит:"
  options:
    - "большой корень полинома"
    - "малые корни полинома по модулю n (|x| < n^(1/d))"
    - "обратный элемент"
    - "коллизии"
  answer: 1
- question: "Если известны старшие биты p, ключ восстанавливают через:"
  options:
    - "XOR"
    - "Coppersmith (полином `p_high + x`, малый корень делит n)"
    - "частотный анализ"
    - "перебор d"
  answer: 1
- question: "Какой алгоритм лежит в основе Coppersmith?"
  options:
    - "Dijkstra"
    - "LLL (решётки)"
    - "CRC"
    - "AES"
  answer: 1
- question: "Атака Boneh-Durfee применима при:"
  options:
    - "e = 3"
    - "малом d (d < n^0.292)"
    - "p ≈ q"
    - "общем модуле"
  answer: 1
```

## Где пригодится

- **CTF (hard/expert)** — большинство «невзламываемых» RSA-задач решаются Coppersmith/LLL.
- **Криптоанализ** — понимание реальных атак на реализации (утечки побочных каналов).
- **Академические исследования** — решётки центральны в современной криптографии.
- **Аудит** — оценка риска при частичных утечках ключевого материала.
- **Пост-квантовая криптография** — решётки (LWE) лежат в её основе.
