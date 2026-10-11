---
id: crypto-classical-deep
title: "Классические шифры вглубь: Playfair, Hill, Affine, Bacon и автоматизация частотного анализа"
category: crypto
parent: crypto-classical
difficulty: medium
order: 1
tags: [crypto, classical, playfair, hill, affine, bacon, frequency-analysis, substitution, vigenere]
prerequisites: [crypto-classical]
useful_for:
  - "Ломать классические шифры на CTF автоматизацией, а не глазами"
  - "Реализовывать и атаковать матричные (Hill) и полиграммные (Playfair) шифры"
  - "Писать свой частотный анализатор и индекс совпадений"
estimated_minutes: 35
summary: "Глубокое погружение в классику: Affine и Hill (линейная алгебра по модулю), Playfair (полиграммная замена), Bacon (бинарное кодирование в тексте), а также автоматизированный частотный анализ — индекс совпадений, χ², n-граммы — с готовыми скриптами на Python."
---

`crypto-classical` даёт обзор: Caesar, Vigenère, простая замена. Этот урок — про **остальные** классические системы, которые регулярно встречаются в CTF, и про то, как ломать их **автоматически**, а не «на глаз». Здесь математика: Affine — линейные функции, Hill — матрицы над `Z_26`, Playfair — полиграммы, Bacon — бинарное представление. В конце — рабочий частотный анализатор.

## Affine (аффинный шифр)

Шифрование: `c = (a·m + b) mod 26`, где `gcd(a, 26) = 1`. Ключ — пара `(a, b)`.

```python
def affine_encrypt(m, a, b):
    return (a * m + b) % 26

def affine_decrypt(c, a, b):
    a_inv = pow(a, -1, 26)
    return (a_inv * (c - b)) % 26

# "HELLO" -> числа
text = "HELLO"
nums = [ord(ch) - 65 for ch in text]
enc = [affine_encrypt(n, 5, 8) for n in nums]
print("".join(chr(e + 65) for e in enc))
```

**Пространство ключей** — всего `12 × 26 = 312` (для `a` подходят 1,3,5,7,9,11,15,17,19,21,23,25). Значит, brute force тривиален:

```python
from math import gcd
for a in range(26):
    if gcd(a, 26) != 1:
        continue
    for b in range(26):
        pt = "".join(chr(affine_decrypt(n, a, b) + 65) for n in enc)
        if "HELLO" in pt or "THE" in pt:
            print(a, b, pt)
```

**Атака по известному открытому тексту:** две пары `(m1,c1), (m2,c2)` дают систему `c1 - c2 ≡ a(m1 - m2)`, откуда `a = (c1-c2)·(m1-m2)^{-1} mod 26`, затем `b = c1 - a·m1`.

## Hill (матричный шифр)

Шифрование блока из `n` букв: `C = K · M mod 26`, где `K` — матрица `n×n` обратимая по модулю 26. Дешифрование: `M = K^{-1} · C mod 26`.

```python
import numpy as np

def hill_encrypt(block, K):
    v = np.array(block) % 26
    return (K @ v) % 26

K = np.array([[3, 3], [2, 5]])       # классический пример 2x2
# определитель должен быть взаимно прост с 26

def mod_inv_matrix(K, mod=26):
    det = int(round(np.linalg.det(K))) % mod
    det_inv = pow(det, -1, mod)
    adj = np.round(np.linalg.inv(K) * np.linalg.det(K)).astype(int) % mod
    return (det_inv * adj) % mod

print(mod_inv_matrix(K))
```

**Атака known-plaintext:** если известен блок открытого текста `M` и соответствующий `C`, то `K = C · M^{-1} mod 26` (при обратимой `M`). Нужно `n` независимых блоков для матрицы `n×n`. **Ciphertext-only** ломается частотным анализом с биграммами (для `n=2`) — Hill скрывает частоты отдельных букв, но не биграмм.

## Playfair (полиграммная замена)

Ключевая квадратная таблица 5×5 (I/J объединены). Шифруются **пары** букв:
- обе в одной строке → сдвиг вправо;
- оба в одном столбце → сдвиг вниз;
- иначе → прямоугольник (меняем столбцы).

```python
def build_square(key):
    key = "".join(dict.fromkeys(key.upper().replace("J", "I") + "ABCDEFGHIKLMNOPQRSTUVWXYZ"))
    return [key[i*5:(i+1)*5] for i in range(5)]

def playfair_encrypt(pt, key):
    sq = build_square(key)
    pos = {sq[r][c]: (r, c) for r in range(5) for c in range(5)}
    pt = pt.upper().replace("J", "I")
    pairs = []
    i = 0
    while i < len(pt):
        a = pt[i]
        b = pt[i+1] if i+1 < len(pt) and pt[i+1] != a else "X"
        pairs.append((a, b))
        i += 2 if b != "X" or (i+1 < len(pt) and pt[i+1] == a) else 1
    out = []
    for a, b in pairs:
        ra, ca = pos[a]; rb, cb = pos[b]
        if ra == rb:
            out += [sq[ra][(ca+1) % 5], sq[rb][(cb+1) % 5]]
        elif ca == cb:
            out += [sq[(ra+1) % 5][ca], sq[(rb+1) % 5][cb]]
        else:
            out += [sq[ra][cb], sq[rb][ca]]
    return "".join(out)

print(playfair_encrypt("HELLO WORLD", "MONARCHY"))
```

**Атака:** Playfair скрывает частоты отдельных букв, но не пар. Используйте частотный анализ **диграмм** + известные пары. Автоматизировать сложнее, чем подстановку; часто ключ находится в условии (тогда просто реализуйте дешифрование).

## Bacon (бинарное кодирование в тексте)

Каждая буква кодируется 5-битным числом (A=0..Z=25), замаскированным под **два шрифта** (A — обычный, B — курсив/жирный). Скрытое сообщение прячется в выборе шрифта, а не в самих буквах.

```python
BACON = "ABCDEFGHIKLMNOPQRSTUVWXYZ"   # 24 или 26 букв

def bacon_decode(bits):
    out = []
    for i in range(0, len(bits) - 4, 5):
        chunk = bits[i:i+5]
        idx = int(chunk.replace("A", "0").replace("B", "1"), 2)
        if idx < len(BACON):
            out.append(BACON[idx])
    return "".join(out)

# "AAAAA" -> A, "AAAAB" -> B, ...
print(bacon_decode("AAAAABBBBBAAAAB"))   # AB...
```

**CTF-вариант:** два регистра, два шрифта, пробелы/табы, скрытые символы. Соберите битовую строку и разбейте на 5.

## Автоматизация частотного анализа

### Индекс совпадений (IC)

`IC = Σ n_i(n_i-1) / (N(N-1))`, где `n_i` — частота буквы. Для английского текста `IC ≈ 0.066`, для случайного — `≈ 0.038`. Высокий IC → моноалфавитная подстановка; низкий при длинном тексте → полиалфавитная.

```python
from collections import Counter

def index_of_coincidence(text):
    text = "".join(ch for ch in text.upper() if ch.isalpha())
    N = len(text)
    freqs = Counter(text)
    return sum(v*(v-1) for v in freqs.values()) / (N*(N-1)) if N > 1 else 0
```

### χ² (хи-квадрат)

Сравнивает наблюдаемые частоты с ожидаемыми для английского:

```python
ENG = [8.167,1.492,2.782,4.253,12.702,2.228,2.015,6.094,6.966,0.153,0.772,4.025,
       2.406,6.749,7.507,1.929,0.095,5.987,6.327,9.056,2.758,0.978,2.360,0.150,
       1.974,0.074]

def chi_squared(text):
    text = "".join(ch for ch in text.upper() if ch.isalpha())
    N = len(text)
    counts = Counter(text)
    s = 0.0
    for i, exp in enumerate(ENG):
        observed = counts.get(chr(65+i), 0)
        expected = N * exp / 100
        s += (observed - expected)**2 / expected
    return s
```

Меньший χ² = текст ближе к английскому. Для Caesar/Vigenère (после разбиения) χ² — основной критерий.

### Автоматический Caesar/Vigenère

```python
def caesar_bruteforce(ct):
    best = None
    for shift in range(26):
        pt = "".join(chr((ord(c)-65-shift) % 26 + 65) if c.isalpha() else c for c in ct.upper())
        score = chi_squared(pt)
        if best is None or score < best[0]:
            best = (score, shift, pt)
    return best

def vigenere_keylength(ct):
    ct = "".join(c for c in ct.upper() if c.isalpha())
    best, best_ic = None, 0
    for kl in range(1, 21):
        cols = [ct[i::kl] for i in range(kl)]
        ic = sum(index_of_coincidence(col) for col in cols) / kl
        if ic > best_ic:
            best_ic, best = ic, kl
    return best
```

Дальше каждый столбец (при известной длине ключа) решается как Caesar через χ². Это классическая атака на Vigenère без ключа.

## Инструменты и команды

```bash
# Cryptanalysis tooling
pip install pycipher
python3 -c "from pycipher import Playfair; print(Playfair('MONARCHY').encipher('HELLO'))"

# Частотный анализ и «умный» brute force
python3 -c "import subprocess"  # dcode.fr, quipqiup.com — онлайн
```

```bash
# quipqiup (онлайн) — лучший автомат для простой замены
# dcode.fr — Playfair, Hill, Bacon, Affine с автоопределением
# Установите wordfreq/nltk для n-граммного скоринга
pip install nltk
python3 -c "import nltk; nltk.download('brown')"
```

## Разобранный пример: ломаем Affine без ключа

```python
from math import gcd
from collections import Counter

ct = "SIZLXYFVO"     # некий шифротекст, зашифрованный Affine
enc = [ord(c) - 65 for c in ct]

best = None
for a in range(26):
    if gcd(a, 26) != 1:
        continue
    a_inv = pow(a, -1, 26)
    for b in range(26):
        pt = "".join(chr((a_inv*(n-b)) % 26 + 65) for n in enc)
        # простой скоринг по частым буквам
        score = sum(pt.count(c) for c in "ETAOIN")
        if best is None or score > best[0]:
            best = (score, a, b, pt)
print(best)
```

Запустите — увидите осмысленный текст. В реальных задачах замените скоринг на χ²/триграммы.

## Частые ошибки

- **Забыть, что `a` в Affine должно быть взаимно просто с 26.** Иначе дешифрования не существует.
- **Считать `K^{-1}` обычной инверсией в Hill.** Нужна **модулярная** инверсия матрицы по модулю 26.
- **Ломать Playfair частотным анализом букв.** Он не сохраняет частоты букв — работайте с биграммами.
- **Путать Bacon 24-буквенный и 26-буквенный алфавиты.** I/J и U/V иногда объединяют.
- **Останавливаться на IC при полиалфавитном шифре.** Сначала найдите длину ключа, потом ломайте столбцы.
- **Забыть про padding в Playfair.** Пары-дубликаты и нечётная длина требуют вставки `X`.

## Квиз

```quiz
- question: "Сколько всего ключей у аффинного шифра над 26 буквами?"
  options:
    - "26"
    - "312"
    - "676"
    - "3120"
  answer: 1
- question: "Что требуется от матрицы K в шифре Hill?"
  options:
    - "симметричность"
    - "обратимость по модулю 26 (det взаимно прост с 26)"
    - "все элементы равны"
    - "размер 1x1"
  answer: 1
- question: "Шифр Playfair шифрует:"
  options:
    - "отдельные буквы"
    - "пары букв (диграммы)"
    - "тройки букв"
    - "целые слова"
  answer: 1
- question: "Что кодирует шифр Bacon?"
  options:
    - "частоты букв"
    - "5-битные значения, замаскированные под смену шрифта"
    - "матрицу 3x3"
    - "числа Фибоначчи"
  answer: 1
- question: "Индекс совпадений (IC) около 0.066 для длинного текста указывает на:"
  options:
    - "моноалфавитную подстановку"
    - "полиалфавитный шифр"
    - "одноразовый блокнот"
    - "стеганографию"
  answer: 0
```

## Где пригодится

- **CTF crypto:** классические задачи начального уровня — самый частый источник «лёгких» очков.
- **Освоение инструментов:** тренировка частотного анализа и авто-скоринга пригодится для всех подстановочных систем.
- **Образование:** наглядная демонстрация, почему моноалфавитные шифры нестойки.
- **Работа (SOC/IR):** распознавание «самодельной» обфускации в малвари (часто это Caesar/Affine/XOR).
- **Bug bounty:** обфускация конфигов и токенов простыми шифрами.
