---
id: crypto-rsa-small-e-hastad
title: "RSA с малым e: Håstad broadcast и целочисленный корень"
category: crypto
parent: crypto-rsa-advanced-attacks
difficulty: hard
order: 1
tags: [crypto, rsa, small-e, hastad, broadcast, crt, cube-root, coppersmith, franklin-reiter]
prerequisites: [crypto-rsa-basics, crypto-rsa-attacks]
useful_for:
  - "Решать broadcast-задачи с малым e"
  - "Применять CRT и целочисленный корень"
  - "Распознавать варианты small-e атак"
estimated_minutes: 40
summary: "Атаки на RSA с малым e: целочисленный корень (m^e < n), Håstad broadcast (одно сообщение под k >= e модулями, CRT), обобщения с padding (Coppersmith), Franklin-Reiter (линейно связанные сообщения). Практические скрипты и распознавание."
---

## Почему малый e опасен

Малый `e` (3, 5, 17) ускоряет шифрование и подпись, но открывает атаки. Основная идея: если `m^e < n`, модуль **не срабатывает**, и `c = m^e` в точности — тогда `m = c^(1/e)`. Даже когда `m^e ≥ n`, при малом `e` и нескольких шифротекстах работает CRT (Håstad).

## Атака 1: целочисленный корень

```python
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes

m, exact = iroot(c, e)      # e = 3 обычно
if exact:
    print(long_to_bytes(int(m)))
```

Признак: маленький `c`, `e=3`, `n` большой. `m^e < n` значит `m < n^(1/e)`.

## Атака 2: Håstad broadcast

Одно сообщение `m` зашифровано **разными** модулями `n1..nk` с **малым** `e`, причём `k ≥ e`:

```
c1 = m^e mod n1
c2 = m^e mod n2
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

## Атака 3: Håstad с padding (Coppersmith)

Если у получателей **разный линейный padding** (`m_i = a_i·m + b_i`), простой корень не сработает. Тогда применяется **Coppersmith** (см. `crypto-rsa-coppersmith-deep`): строится система полиномов `(a_i·x + b_i)^e − c_i ≡ 0 mod n_i`, комбинируется по CRT в один полином mod `N`, и находится малый корень `x = m`. Это «обобщённый Håstad».

## Атака 4: Franklin-Reiter (линейно связанные сообщения)

Если два сообщения линейно связаны: `m2 = a·m1 + b`, зашифрованы одним ключом с малым `e`, то `gcd` двух полиномов `x^e − c1` и `(ax+b)^e − c2` над `Z_n[x]` даёт линейный множитель, из которого находится `m1`.

```python
# Sage
R.<x> = PolynomialRing(Zmod(n))
f1 = x^e - c1
f2 = (a*x + b)^e - c2
g = f1.gcd(f2)
print(g)   # линейный -> m1
```

## Практический пример: Håstad с e=3

```python
pairs = [(n1, c1), (n2, c2), (n3, c3)]
m = hastad(3, pairs)
print(m)
```

Если `m` выглядит как флаг — готово. Если нет — возможно, есть padding, переходите к Coppersmith.

## Инструменты и команды

```bash
pip install gmpy2 sympy pycryptodome
python3 RsaCtfTool.py --attack hastad --publickey key.pub --uncipherfile cipher
sage -c "R.<x>=PolynomialRing(Zmod(n)); print((x^3-c1).gcd((a*x+b)^3-c2))"
```

## Частые ошибки

- **Считать, что малый e всегда ломается.** Только при `m^e < n` или `k ≥ e`.
- **Забыть про padding.** С padding нужен Coppersmith, а не простой корень.
- **Неверный CRT.** Модули должны быть взаимно просты (обычно да).
- **Мало шифротекстов.** Нужно `k ≥ e`.
- **Путать Håstad и Franklin-Reiter.** Разные условия.
- **Игнорировать конвертацию в байты.**

## Разбор с конкретными числами

Пусть `e = 3`, три модуля `n1, n2, n3` (~1024 бита), одно `m` (~200 бит). Тогда `m^3` (~600 бит) **меньше** каждого `n_i`, и `c_i = m^3` без модуля для всех трёх. CRT от `(c1,c2,c3)` даёт `M = m^3` (точное), корень 3-й степени — `m`. Если бы `m` было длиннее (например, 400 бит → `m^3` ~1200 бит > `n`), то модуль сработал бы, и простой корень не помог бы — нужен `k > e` или Coppersmith.

Ключевая проверка: `m^e < n`. Для `e=3` и `n` 1024 бита это `m < 2^341` (≈42 байта).

## Обобщения Håstad

- **Разные `e`:** если сообщение отправлено с разными экспонентами, common modulus / CRT-комбинация (см. `crypto-rsa-multi`).
- **Padding:** если получатели применяют `m_i = a_i·m + b_i`, применяется Coppersmith (обобщённый Håstad).
- **`k > e` шифротекстов:** избыток помогает при наличии шума.
- **Известная часть сообщения:** `m = m0 + x` → Coppersmith.

## Связь с Franklin-Reiter

Håstad и Franklin-Reiter — «родственники»: оба комбинируют несколько шифротекстов малого `e`. Разница: Håstad — **разные модули** (CRT), Franklin-Reiter — **один модуль** и линейная связь сообщений (gcd полиномов). Если в задаче один `n` и два связанных сообщения — это Franklin-Reiter; если несколько `n` — Håstad.

## Разбор: полный Håstad

```python
from sympy.ntheory.modular import crt
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes

e = 3
pairs = [(n1, c1), (n2, c2), (n3, c3)]
ns = [p[0] for p in pairs]
cs = [p[1] for p in pairs]
M, N = crt(ns, cs)          # M = m^e mod (n1*n2*n3)
m, exact = iroot(M, e)
if exact:
    print(long_to_bytes(int(m)))
else:
    print("Нужен Coppersmith (padding/больше данных)")
```

## Разбор: целочисленный корень

```python
# один шифротекст, m^e < n
m, ok = iroot(c, e)
if ok:
    print(long_to_bytes(int(m)))
```

## Обобщённый Håstad с линейным padding (Sage)

```python
# m_i = a_i*m + b_i, e=3, три модуля
# Строим полиномы (a_i*x+b_i)^e - c_i mod n_i
# CRT-комбинируем в один полином mod N
# small_roots -> x = m
```

## Разбор: Franklin-Reiter (один модуль)

Если один `n`, два сообщения `m2 = a·m1 + b`, `e` мал:

```python
# Sage
R.<x> = PolynomialRing(Zmod(n))
f1 = x^e - c1
f2 = (a*x + b)^e - c2
g = f1.gcd(f2)
m1 = int(-g[0] / g[1])
```

## Разбор: почему CRT даёт точное m^e

Если `N = n1·n2·n3 > m^e`, то `M = m^e mod N` **равно** `m^e` (без модуля), потому что `m^e < N`. Значит, извлечение корня `e`-й степени из `M` даёт точное `m`. Если `N < m^e`, модуль срабатывает и корень неточный — тогда нужно больше шифротекстов (`k > e`) или Coppersmith.

## Разбор: когда `m^e` «почти» меньше n

Если `m^e = n + x` с малым `x` (то есть `m^e` лишь немного больше `n`), то `c = m^e − n`, и `m = (c + n)^(1/e)` — то есть просто ищем корень от `c + n`. Обобщение: если `c = m^e mod n` и известно, что `m^e = k·n + c` для малого `k`, перебираем `k` и проверяем точность корня.

```python
from gmpy2 import iroot
for k in range(1000):
    m, ok = iroot(c + k*n, e)
    if ok:
        print(long_to_bytes(int(m))); break
```

## Разбор: защита от Håstad

Правильная реализация RSA **обязана** использовать padding (OAEP). Даже при `e=3` OAEP рандомизирует сообщение, поэтому `m^e` не имеет структуры и Håstad/целочисленный корень не работают. Это одна из причин, по которой малый `e` допустим только с OAEP.

## Разбор: как выбрать e

- `e=3` — быстрый, но требует OAEP и осторожности.
- `e=65537` — стандарт (достаточно большой, чтобы избежать small-e атак, и быстрый).
- Случайный большой `e` — риск малого `d` (Wiener).

## Как не застрять

- **Проверьте `e`.** Малый → думайте small-e.
- **Один шифротекст** → целочисленный корень.
- **Несколько, `k ≥ e`** → Håstad/CRT.
- **С padding** → Coppersmith.
- **Линейная связь сообщений** → Franklin-Reiter.
- **RsaCtfTool** автоматизирует большинство.

## Квиз

```quiz
- question: "Когда работает прямое извлечение корня при малом e?"
  options:
    - "всегда"
    - "когда m^e < n (сообщение короткое, модуль не сработал)"
    - "когда d мал"
    - "когда p = q"
  answer: 1
- question: "Håstad broadcast attack требует:"
  options:
    - "один шифротекст"
    - "одно сообщение под k >= e модулями с одним малым e"
    - "общий модуль"
    - "padding oracle"
  answer: 1
- question: "Какой инструмент комбинирует шифротексты в Håstad?"
  options:
    - "XOR"
    - "CRT (китайская теорема об остатках)"
    - "хэш"
    - "перебор"
  answer: 1
- question: "Если у получателей разный padding, нужен:"
  options:
    - "простой корень"
    - "Coppersmith с учётом линейного padding"
    - "Fermat"
    - "ничего"
  answer: 1
- question: "Правильная защита от этих атак:"
  options:
    - "малый d"
    - "padding (OAEP)"
    - "короткий ключ"
    - "повтор e"
  answer: 1
```

## Где пригодится

- **CTF (hard)** — «флаг отправлен трём людям», `e=3`, broadcast.
- **Bug bounty** — аудит реализаций RSA с малым `e` и самодельным padding.
- **Пентест** — TLS/почтовые реализации с `e=3` (устаревшие сертификаты).
- **Работа** — разбор инцидентов с перехватом нескольких сообщений.
- **Крипто-разработка** — почему OAEP обязателен при малом `e`.
