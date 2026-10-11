---
id: crypto-pairing
title: "Спаривания и BLS-подписи"
category: crypto
parent: crypto-ecc-advanced-curves
difficulty: expert
order: 2
tags: [crypto, pairing, bls, bilinear, tate, weil, aggregate-signature, mov]
prerequisites: [crypto-ecc, crypto-ecdsa-advanced]
useful_for:
  - "Понимать билинейные спаривания (Tate/Weil)"
  - "Работать с BLS-подписями и агрегацией"
estimated_minutes: 36
summary: "Билинейные спаривания: Weil/Tate, pairing-friendly кривые (embedding degree), BLS-подписи и агрегация, threshold/KZG, атаки MOV и rogue-key, практические скрипты на py_ecc и Sage."
---

Спаривание (pairing) — это билинейная функция `e: G1 × G2 → GT`, которая «перемножает» скаляры: `e(aP, bQ) = e(P, Q)^{ab}`. Из этого одного свойства вырастает целая ветвь криптографии: BLS-подписи с агрегацией, пороговые схемы, KZG-коммитменты (zk-SNARK), identity-based encryption. В CTF спаривания встречаются в задачах на BLS, на «сверни подписи» и на MOV-атаку, которая переносит ECDLP в слабую конечную группу.

## Что такое билинейное спаривание

Спаривание `e` на группах `G1`, `G2` (подгруппы точек эллиптической кривой) и `GT` (мультипликативная подгруппа расширения поля):

- **билинейность:** `e(aP, bQ) = e(P, Q)^{ab}` для скаляров `a, b`;
- **невырожденность:** `e(P, Q) ≠ 1` для ненулевых `P, Q`;
- **вычислимость:** `e` эффективно считается.

Интуиция: спаривание превращает «умножение на скаляр» в «возведение в степень» — аддитивную структуру ECC в мультипликативную структуру `GT`. Именно это позволяет проверять криптографические равенства без раскрытия скаляров.

## Pairing-friendly кривые и embedding degree

Не любая кривая годится: нужно, чтобы подгруппа порядка `r` из `E(F_q)` содержалась в `E(F_{q^k})`, и `k` (embedding degree) был **мал**, иначе спаривание невычислимо. Стандартные семейства:

- **BN-кривые** (Barreto-Naehrig) — `k=12`, используются в Ethereum (alt_bn128).
- **BLS-кривые** — `k=12`, например BLS12-381 (Zcash, Ethereum 2).
- **MNT, KSS** — `k=4..6`.

Для CTF важны: **secp256k1 не pairing-friendly** (k огромно), а alt_bn128 и BLS12-381 — да.

## Weil и Tate: как вычисляют

- **Weil pairing** — спаривание над дивизорами, требует работы с функциями на кривой.
- **Tate pairing** — проще в реализации (Miller's algorithm), чаще используется; `e_T(P, Q)` вычисляется через итеративный подсчёт `f_{r,P}(Q)` и финальное возведение в `(q^k-1)/r`.

```python
# py_ecc (alt_bn128) — идеоматическая проверка билинейности
from py_ecc.bn128 import G1, G2, pairing, multiply, curve_order

a, b = 7, 11
lhs = pairing(multiply(G2, b), multiply(G1, a))   # e(aG1, bG2)
rhs = pairing(G2, multiply(G1, (a*b) % curve_order))  # e((ab)G1, G2)
print(lhs == rhs)   # True
```

## BLS-подписи

BLS (Boneh-Lynn-Shacham) — подпись, которая «сжимается»:

- **KeyGen:** приватный `x`, публичный `X = xG1`.
- **Sign:** `σ = x·H(m)` (хэш в точку `G2`).
- **Verify:** `e(G1, σ) == e(X, H(m))`.

Главное свойство — **агрегация**: `σ_agg = σ_1 + σ_2 + ...`; проверка `e(G1, σ_agg) == e(X_1, H(m_1))·...`. Тысячи подписей сжимаются в одну точку. Именно поэтому BLS любят блокчейны (Ethereum consensus, Filecoin).

```python
# BLS-подпись на py_ecc (упрощённо)
from py_ecc.bn128 import G1, G2, multiply, pairing, curve_order, add
from hashlib import sha256

def H_to_G1(m):
    # в реальности — hash-to-curve; здесь учебная заглушка
    return multiply(G1, int(sha256(m).hexdigest(), 16) % curve_order)

x = 0xdeadbeef
X = multiply(G1, x)
m = b"hello"
sig = multiply(H_to_G1(m), x)
ok = pairing(G2, sig) == pairing(multiply(G2, x), H_to_G1(m))  # упрощённая проверка
```

## Атаки

- **MOV-атака.** Если embedding degree `k` мал, ECDLP переносится в `GT` (мультипликативную группу `F_{q^k}`), где работает субэкспоненциальный индексный метод (index calculus). Для «нормальных» кривых `k` огромно, и MOV неприменима; для слабых/самодельных — ломает.
- **Rogue-key attack (BLS).** Злоумышленник регистрирует публичный ключ `X' = X_target - X_own`, и агрегат подписей подделывается. Защита: **proof of possession** (подпись на своём ключе) или коэффициенты `H(X_i)`.
- **Invalid-curve / small-subgroup** при проверке без валидации точки (см. `crypto-invalid-curve`).
- **Подделка агрегата** при отсутствии привязки сообщений: разные сообщения должны хэшироваться с ключом/сообщением, иначе «перестановка» подписей.
- **Fault attacks** на Miller's algorithm (сложные, редкие).

## Инструменты и код

| Инструмент | Язык | Для чего |
|-----------|------|----------|
| py_ecc | Python | alt_bn128, BLS, обучение |
| SageMath | Python | Tate/Weil, кривые, MOV |
| blspy / milagro | Python/C | BLS12-381 |
| gnark / arkworks | Go/Rust | zk-SNARK, pairing |

```bash
pip install py-ecc
sage -c "E = EllipticCurve(GF(p), [a,b]); # ... Weil pairing"
```

## Разобранный пример: проверка агрегированной подписи

Дано: три публичных ключа `X1..X3`, три сообщения и одна агрегированная подпись `σ`. Проверяем:

```python
from py_ecc.bn128 import G1, G2, pairing, multiply, add, curve_order
# σ = σ1 + σ2 + σ3
lhs = pairing(G2, sigma)
rhs = pairing(multiply(G2, x1), H1)   # + ... произведение
# в py_ecc pairing возвращает элемент GT; перемножение через умножение
assert lhs == (pairing(multiply(G2, x1), H1) * pairing(multiply(G2, x2), H2) * pairing(multiply(G2, x3), H3))
```

Если проверка проходит — агрегат валиден. В CTF «сломай BLS» обычно означает rogue-key: подобрать `X'` так, чтобы агрегат сошёлся.

## Варианты: threshold, KZG, IBE

- **Threshold BLS.** Подпись собирается из `t` из `n` долей (комбинация со `crypto-shamir`).
- **KZG commitments.** `C = [f(s)]G1`, проверка через `e(C - [f(z)]G1, G2) == e([q(s)]G1, [s]G2 - [z]G2)` — основа zk-SNARK (Groth16, PLONK).
- **IBE (Boneh-Franklin).** Публичный ключ = идентификатор (`email`), приватный выдаёт доверенный центр через спаривание.
- **Краткие подписи.** BLS-подпись — одна точка (48/96 байт), короче RSA/ECDSA.

## Частые ошибки и тупики

- **Пытаться применить спаривание к secp256k1.** Она не pairing-friendly.
- **Игнорировать порядок аргументов.** `e(aP, Q) ≠ e(P, aQ)` в разных реализациях по типу групп.
- **Забыть про hash-to-curve.** BLS требует хэширования в точку с правильным распределением; наивный `hash * G` уязвим.
- **Нет proof of possession.** Rogue-key ломает агрегацию.
- **Считать MOV всегда применимой.** Только при малом `k`.
- **Путать `GT` и `G1`/`G2`.** Это разные группы; операции не смешиваются.

## Что дальше (decision)

1. BLS-задача с агрегацией → проверьте proof-of-possession и rogue-key.
2. Дана кривая с малым `k` → MOV-атака: перенос ECDLP в `GT`.
3. Задача про zk-SNARK/KZG → спаривания для проверки полиномиальных коммитментов.
4. Пороговая подпись → `crypto-shamir` + BLS.
5. Слабая валидация точки → `crypto-invalid-curve`.
6. Нужно «свернуть» подписи в блокчейне → BLS aggregate.

## Справочная таблица

| Понятие | Значение |
|---------|----------|
| `e: G1×G2→GT` | билинейное спаривание |
| embedding degree `k` | степень расширения для спаривания |
| Weil/Tate | конкретные спаривания |
| BLS | короткая агрегируемая подпись |
| MOV | перенос ECDLP в `GT` при малом `k` |
| KZG | полиномиальный коммитмент на спариваниях |

## Полный разбор: KZG-проверка

KZG (Kate-Zaverucha-Goldberg) — полиномиальный коммитмент на спариваниях, основа zk-SNARK. Доверенная установка даёт `[s]G1`, `[s]G2` для секретного `s`.

- **Commit:** для полинома `f` публикуется `C = [f(s)]G1`.
- **Open:** для точки `z` вычисляется `q(x) = (f(x) - f(z))/(x - z)`; proof `π = [q(s)]G1`.
- **Verify:** проверяем

```
e(C - [f(z)]G1, G2) == e(π, [s]G2 - [z]G2)
```

Билинейность делает проверку возможной, не раскрывая `s`: обе стороны «умножаются» на один и тот же `(s - z)`. Именно так доказывают корректность вычислений в Groth16/PLONK.

```python
# py_ecc: идея проверки
lhs = pairing(G2, add(C, neg(multiply(G1, f_z))))
rhs = pairing(add(multiply(G2, s), neg(multiply(G2, z))), pi)
assert lhs == rhs
```

В CTF «сломать KZG» обычно означает найти способ обойти проверку при известном `s` (если установка скомпрометирована) или эксплуатировать отсутствие проверки точки.

## Квиз

```quiz
- question: "Главное свойство билинейного спаривания:"
  options:
    - "e(aP, bQ) = e(P, Q)^{ab}"
    - "e(P, Q) = P + Q"
    - "e(P, Q) = P XOR Q"
    - "e(P, Q) = hash(P)"
  answer: 0
- question: "Что даёт BLS-подписям агрегацию?"
  options:
    - "билинейность спаривания позволяет сложить подписи и проверить одной парой"
    - "короткие ключи"
    - "симметричность"
    - "хеширование"
  answer: 0
- question: "Когда применима MOV-атака?"
  options:
    - "при малом embedding degree k"
    - "всегда"
    - "только для RSA"
    - "только для AES"
  answer: 0
- question: "Чем опасна rogue-key атака на BLS?"
  options:
    - "можно подделать агрегат без proof of possession"
    - "ломает AES"
    - "факторизует N"
    - "восстанавливает IV"
  answer: 0
- question: "Какая кривая НЕ подходит для спариваний?"
  options:
    - "secp256k1"
    - "BN254"
    - "BLS12-381"
    - "MNT"
  answer: 0
```

## Где пригодится

- **CTF (expert):** BLS, агрегация, MOV, zk-SNARK-примитивы.
- **Bug bounty/аудит:** подделка агрегированных подписей, слабые pairing-friendly параметры.
- **Blockchain:** консенсус (Ethereum), zk-rollups, KZG.
- **Работа:** аудит крипто-протоколов на спариваниях.
- **Разработка:** BLS/IBE/zk-SNARK в реальных системах.
