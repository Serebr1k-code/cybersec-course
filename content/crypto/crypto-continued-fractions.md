---
id: crypto-continued-fractions
title: "Цепные дроби и атаки семейства Винера: convergents, rational reconstruction"
category: crypto
parent: crypto-rsa-factorization
difficulty: hard
order: 2
tags: [crypto, continued-fractions, wiener, convergents, rational-reconstruction, boneh-durfee, rsa, small-d]
prerequisites: [crypto-rsa-attacks, crypto-number-theory]
useful_for:
  - "Ломать RSA с малым приватным показателем d"
  - "Восстанавливать рациональные соотношения из приближений"
  - "Понимать математику за атаками на малый d и частично известный ключ"
estimated_minutes: 28
summary: "Цепные дроби как инструмент криптоанализа: разложение, подходящие дроби (convergents), rational reconstruction и точная атака Винера на малый d. Разбор, почему d < n^0.25/3 гарантирует успех, и переход к атаке Боне–Дюрфе."
---

В `crypto-rsa-attacks` атака Винера показана как «готовый скрипт». Здесь мы разберём **механику**: что такое цепные дроби, откуда берутся подходящие дроби (convergents), почему они появляются в RSA и как применять **rational reconstruction** — восстановление рационального числа из приближённого значения. Это фундамент для атаки Боне–Дюрфе и для многих задач, где «известно приближение» к секретному отношению.

## Цепные дроби: определение

Любое рациональное число `a/b` можно разложить в **цепную (непрерывную) дробь**:

```
a/b = q0 + 1/(q1 + 1/(q2 + 1/(... + 1/qn)))
     = [q0; q1, q2, ..., qn]
```

Коэффициенты `qi` получаются алгоритмом Евклида:

```python
def continued_fraction(a, b):
    cf = []
    while b:
        q = a // b
        cf.append(q)
        a, b = b, a - q * b
    return cf

print(continued_fraction(415, 93))   # [4, 2, 6, 7]
```

**Подходящие дроби (convergents)** `p_k/q_k` — это усечения цепной дроби. Они дают **наилучшие рациональные приближения** числа `a/b` со знаменателем, не превышающим `q_k`. Рекуррентно:

```
p_{-1}=1, p_0=q0
q_{-1}=0, q_0=1
p_k = q_k·p_{k-1} + p_{k-2}
q_k = q_k·q_{k-1} + q_{k-2}
```

```python
def convergents(cf):
    p_prev, p_cur = 1, cf[0]
    q_prev, q_cur = 0, 1
    yield p_cur, q_cur
    for a in cf[1:]:
        p_next = a * p_cur + p_prev
        q_next = a * q_cur + q_prev
        p_prev, p_cur = p_cur, p_next
        q_prev, q_cur = q_cur, q_next
        yield p_cur, q_cur

for num, den in convergents(continued_fraction(415, 93)):
    print(f"{num}/{den} = {num/den:.6f}")
```

**Теорема Лежандра:** если `|x - p/q| < 1/(2q²)`, то `p/q` — одна из подходящих дробей `x`. Именно этой теоремой пользуются атаки: показывают, что искомое отношение `k/d` достаточно близко к известному `e/n`, а значит лежит среди convergents.

## Почему это появляется в RSA

Из соотношения `e·d ≡ 1 (mod φ)` следует существование целого `k`:

```
e·d = 1 + k·φ,   то есть   e/φ = k/d + 1/(d·φ)
```

Значит `k/d ≈ e/φ`. Но `φ = (p-1)(q-1) = n - (p+q) + 1 ≈ n`, поскольку `p+q` мало по сравнению с `n`. Поэтому `e/φ ≈ e/n`. Следовательно `k/d` — приближение к `e/n`, и по теореме Лежандра при достаточной близости оно окажется среди convergents.

## Точная атака Винера

Условие успеха: `d < n^{0.25} / 3` (для классической формулировки с `e < φ`). Тогда для каждого convergent `k/d` проверяем:

1. `(e·d - 1) mod k == 0` → `φ = (e·d - 1) / k`;
2. `p + q = n - φ + 1`;
3. дискриминант `(p+q)² - 4n` — полный квадрат;
4. если да — `d` найден.

```python
from math import isqrt

def wiener_attack(n, e):
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        t = isqrt(disc)
        if t * t == disc and (s + t) % 2 == 0:
            return d, (s + t) // 2, (s - t) // 2
    return None

d, p, q = wiener_attack(n, e)
m = pow(c, d, n)
```

**Признак:** `e` «огромно» — почти такое же, как `n` (сотни-тысячи бит). Это означает, что `d` мал, иначе `e` был бы обычным (65537).

## Rational reconstruction

Иногда известен не `e/n`, а **приближённое значение** отношения. **Rational reconstruction** (восстановление рационального числа) по паре `(a, m)` ищет `num/den` с малыми `|num|, den` такие, что `num ≡ a·den (mod m)`. Это делается через цепные дроби: останавливаемся, когда знаменатель convergent превышает границу.

```python
def rational_reconstruction(a, m, bound):
    # ищем p/q: p ≡ a*q (mod m), |p|, q <= bound
    old_r, r = a, m
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0 and abs(r) > bound:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    # |old_r| <= bound: p = old_s? -> используем классическую формулу
    if abs(old_s) <= bound:
        return old_s, old_t
    return None
```

**Применение в крипто:** восстановление `d` из «шумного» набора данных; атаки на частично известный `φ`; задачи, где дано `k·φ mod e` или подобное. Также это ядро атаки Боне–Дюрфе (малый `d`, но `d < n^{0.292}`), где уже применяется двумерный вариант цепных дробей и решёточный базис.

## Boneh–Durfee (обзорно)

Винер требует `d < n^{0.25}/3`. Боне–Дюрфе расширяет границу до `d < n^{0.292}`, используя тот факт, что `k` и `d` связаны полиномиальным уравнением, которое решается методом Копперсмита на решётках (LLL). Идея: из `e·d - k·φ = 1` и `φ ≈ n - 2√n` строится полином `f(x, y) = 1 + x·(n - y)` с малыми корнями `(k, p+q)`. Цепные дроби — «одномерный» предшественник; LLL — «многомерное» обобщение.

```python
# Sage: атака Boneh-Durfee реализуется через small_roots / LLL
# Готовые скрипты ищите как "boneh_durfee.sage"
```

```bash
# RsaCtfTool содержит атаку Винера из коробки
python3 RsaCtfTool.py -n N -e E --attack wiener
```

## Инструменты и команды

```bash
# sympy: цепные дроби и convergents
python3 - <<'PY'
from sympy import continued_fraction, continued_fraction_convergents, Rational
from sympy.ntheory.continued_fraction import continued_fraction_periodic
cf = continued_fraction(Rational(415, 93))
print(list(cf))                       # [4, 2, 6, 7]
print([str(c) for c in continued_fraction_convergents(cf)])
PY
```

```bash
# sage: convergents, rational_reconstruction, LLL
sage -c "print(continued_fraction(415/93))"
sage -c "print(rational_reconstruction(Mod(5,101), 100))"
```

```bash
# RsaCtfTool: все атаки, включая wiener и boneh-durfee (если есть реализация)
python3 RsaCtfTool.py --publickey key.pub --private
```

## Разобранный пример: малый d

```python
from math import isqrt

n = 90581
e = 17993          # заметьте: e близко к n/5, d мал
c = 12345

def cf(a, b):
    out = []
    while b:
        out.append(a // b); a, b = b, a % b
    return out

def convs(cf):
    pp, pc = 1, cf[0]; qp, qc = 0, 1
    yield pc, qc
    for a in cf[1:]:
        pp, pc = pc, a*pc + pp
        qp, qc = qc, a*qc + qp
        yield pc, qc

for k, d in convs(cf(e, n)):
    if k and (e*d - 1) % k == 0:
        phi = (e*d - 1)//k
        s = n - phi + 1
        disc = s*s - 4*n
        t = isqrt(disc) if disc >= 0 else -1
        if t > 0 and t*t == disc:
            print("d =", d, "p =", (s+t)//2, "q =", (s-t)//2)
            print("m =", pow(c, d, n))
            break
```

Скрипт выведет `d` и расшифрует `c`. Обратите внимание: `e` близко к `n` — это сигнал Винера.

## Частые ошибки

- **Разлагать `e/n`, а не `e/φ`.** Винер работает именно потому, что `φ ≈ n`; если бы `p+q` было сопоставимо с `n`, метод бы не сработал.
- **Забыть `k == 0`.** Первый convergent `[q0]` даёт `k=0`, его нужно пропустить.
- **Проверять только один convergent.** Нужно перебрать все и для каждого проверить дискриминант.
- **Путать границы.** `d < n^{0.25}/3` для Винера; `n^{0.292}` — для Боне–Дюрфе (LLL).
- **Игнорировать rational reconstruction.** Во многих задачах он сам по себе даёт секрет из «шумных» данных.

## Квиз

```quiz
- question: "Что дают подходящие дроби (convergents) цепной дроби числа x?"
  options:
    - "случайные рациональные приближения"
    - "наилучшие рациональные приближения со ограниченным знаменателем"
    - "точное значение x"
    - "десятичную запись x"
  answer: 1
- question: "Атака Винера применима, когда приватный показатель d удовлетворяет:"
  options:
    - "d < n^(1/4)/3"
    - "d > n/2"
    - "d = 65537"
    - "d произвольное"
  answer: 0
- question: "Почему `k/d ≈ e/n` работает в атаке Винера?"
  options:
    - "Потому что e мало"
    - "Потому что phi = (p-1)(q-1) близко к n"
    - "Потому что p = q"
    - "Потому что n простое"
  answer: 1
- question: "Какая теорема гарантирует, что близкое приближение — среди convergents?"
  options:
    - "Теорема Ферма"
    - "Теорема Лежандра"
    - "Теорема Эйлера"
    - "Теорема Вильсона"
  answer: 1
- question: "Насколько Боне–Дюрфе расширяет границу малого d относительно Винера?"
  options:
    - "с n^(1/4)/3 до n^(0.292)"
    - "с n^(0.292) до n^(1/4)"
    - "до n^(0.5)"
    - "не расширяет"
  answer: 0
```

## Где пригодится

- **CTF crypto:** RSA с малым `d`, «шумными» соотношениями, частично известным ключом.
- **Аудит крипто:** выявление небезопасной генерации `d` (малый приватный показатель).
- **Bug bounty / пентест:** анализ самописных реализаций RSA.
- **Работа:** понимание требований к размеру `d` в стандартах.
- **Исследования:** мост от цепных дробей к решёточным атакам (LLL, Coppersmith).
