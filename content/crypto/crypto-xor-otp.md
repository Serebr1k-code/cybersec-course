---
id: crypto-xor-otp
title: "XOR, crib-dragging и одноразовый блокнот"
category: crypto
parent: crypto-foundations
difficulty: easy
order: 3
tags: [crypto, xor, otp, one-time-pad, crib-drag, many-time-pad, keystream]
prerequisites: [crypto-intro, crypto-encodings]
useful_for:
  - "Взламывать XOR с повторяющимся ключом"
  - "Применять crib-dragging к many-time pad"
  - "Понимать, почему одноразовый блокнот ломается при переиспользовании"
estimated_minutes: 35
summary: "XOR как основа потоковых шифров: свойства, атаки на однобайтовый и повторяющийся ключ, crib-dragging против many-time pad, почему одноразовый блокнот катастрофически рушится при переиспользовании ключа. Пошаговые скрипты и разбор реальных CTF-сценариев."
---

## XOR: основа всего

**XOR** (исключающее ИЛИ) — побитовая операция: `1 ⊕ 1 = 0`, `0 ⊕ 0 = 0`, `1 ⊕ 0 = 1`. Свойства, которые надо знать:

- **Обратимость:** `(P ⊕ K) ⊕ K = P`. Поэтому XOR — идеальная операция для шифрования.
- **Коммутативность/ассоциативность:** порядок не важен.
- **Сам XOR с собой:** `X ⊕ X = 0`.
- **XOR двух шифротекстов с одним ключом:** `C1 ⊕ C2 = P1 ⊕ P2` — ключ «выпадает».

XOR лежит в основе **всех** потоковых шифров (RC4, ChaCha20, AES-CTR) — там «ключ» это keystream.

## Одноразовый блокнот (OTP)

OTP — теоретически невзламываемый шифр, если:

1. Ключ **случаен** (истинно случайный, не PRNG).
2. Ключ **не короче** сообщения.
3. Ключ **используется ровно один раз**.

Нарушение любого условия ломает OTP. Особенно катастрофично **переиспользование ключа** — оно превращает OTP в many-time pad.

## Атака на однобайтовый XOR

Если ключ — один байт, перебираем все 256 значений и выбираем то, где результат — печатный текст:

```python
def single_byte_xor(ct):
    best = None
    for k in range(256):
        pt = bytes(b ^ k for b in ct)
        score = sum(chr(c).isprintable() or c == 0 for c in pt)
        if best is None or score > best[0]:
            best = (score, k, pt)
    return best

ct = bytes.fromhex("...")
print(single_byte_xor(ct))
```

Классика Cryptopals set 1.

## Атака на повторяющийся ключ

Если ключ длиной `k` повторяется, то `C_i = P_i ⊕ K_{i mod k}`. Определяем длину ключа через **нормализованное расстояние Хэмминга**: для правильной длины `k` блоки на расстоянии `k` «похожи» (маленькое расстояние Хэмминга после нормализации на длину).

```python
def hamming(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

def guess_keylen(ct, maxlen=40):
    best = []
    for k in range(1, maxlen+1):
        blocks = [ct[i:i+k] for i in range(0, len(ct)-k, k)][:4]
        dists = [hamming(blocks[i], blocks[i+1])/k for i in range(len(blocks)-1)]
        best.append((sum(dists)/len(dists), k))
    return sorted(best)[:3]
```

Затем для каждой позиции ключа `j` решаем однобайтовый XOR по байтам `ct[j::k]`. Инструмент `xortool` автоматизирует всё.

```bash
xortool cipher.bin              # подбор длины и расшифровка
xortool -l 5 cipher.bin         # если знаете длину
xortool -c 20 cipher.bin        # если текст hex-подобный
```

## Crib-dragging против many-time pad

Если два (или более) сообщения зашифрованы одним ключом:

```
C1 ⊕ C2 = P1 ⊕ P2
```

Мы не знаем `P1` и `P2`, но знаем, что это осмысленный текст. **Crib-dragging**: предполагаем слово в одной позиции одного текста, XOR-им и смотрим, получается ли осмысленное слово в другой позиции. Если да — подтверждаем и расширяем.

```python
def crib_drag(xor, crib):
    results = []
    for i in range(len(xor) - len(crib)):
        candidate = bytes(a ^ b for a, b in zip(xor[i:], crib))
        if all(32 <= c < 127 for c in candidate[:len(crib)]):
            results.append((i, candidate[:len(crib)]))
    return results

# xor = C1 ^ C2
for pos, guess in crib_drag(xor, b" the "):
    print(pos, guess)
```

Чем длиннее известный/угаданный фрагмент, тем надёжнее атака. Часто один из текстов — стандартный (HTTP-заголовок, приветствие), что даёт «якорь».

## Практический пример: two-time pad

```python
c1 = bytes.fromhex(open("c1.hex").read().strip())
c2 = bytes.fromhex(open("c2.hex").read().strip())
xor = bytes(a ^ b for a, b in zip(c1, c2))

# Шаг 1: угадываем, что P1 начинается с "Dear "
crib = b"Dear "
partial = bytes(a ^ b for a, b in zip(xor, crib))
print("P2 начинается с:", partial[:len(crib)])
# Шаг 2: расширяем, используя полученный P2 как crib для P1
```

## Инструменты и команды

```bash
pip install xortool
xortool -b cipher.bin               # с учётом бинарного текста
python3 -c "print(bytes(a^b for a,b in zip(open('c1','rb').read(), open('c2','rb').read())))"
# CyberChef: операции XOR, XOR Brute Force
```

## Частые ошибки

- **Считать XOR «шифрованием».** Без уникального ключа — не шифрование.
- **Повтор ключа.** Ломается мгновенно.
- **Неверная длина ключа.** Проверяйте расстояние Хэмминга на нескольких кандидатах.
- **Мало crib-слов.** Нужен якорь.
- **Игнорировать непечатные байты.** В текстах их почти нет — используйте как фильтр.
- **Путать XOR и сложение.** Разные операции.

## Много текстов: голосование по байтам

Если зашифровано **три и более** сообщения одним ключом, атака становится надёжнее. Для каждой позиции `i` байт keystream `K_i` удовлетворяет `K_i = C_i^{(j)} ⊕ P_i^{(j)}`. Перебирая кандидатов `K_i` (256 значений) и предполагая, что тексты «печатные» (ASCII), выбираем `K_i`, дающее печатные байты во **всех** текстах одновременно. Это фильтрует почти все неверные варианты.

```python
def recover_keystream(ciphertexts):
    n = min(len(c) for c in ciphertexts)
    ks = bytearray()
    for i in range(n):
        for k in range(256):
            if all(32 <= (c[i] ^ k) < 127 or (c[i] ^ k) in (10, 13) for c in ciphertexts):
                ks.append(k)
                break
    return bytes(ks)

pts = [bytes(a ^ b for a, b in zip(c, ks)) for c in ciphertexts]
```

## Автоматизация crib-dragging

Для больших текстов ручной перебор утомителен — используйте словарь вероятных слов и автоматический поиск:

```python
CRIBS = [b" the ", b"flag{", b"http", b"login", b"password", b"admin", b"user="]
def auto_crib(xor, cribs):
    found = {}
    for crib in cribs:
        for off in range(len(xor) - len(crib)):
            cand = bytes(a ^ b for a, b in zip(xor[off:], crib))
            if all(32 <= x < 127 for x in cand[:len(crib)]):
                found.setdefault(off, []).append((crib, cand[:len(crib)]))
    return found
```

## Разбор: полная атака на many-time pad

```python
c1 = bytes.fromhex(open("c1.hex").read().strip())
c2 = bytes.fromhex(open("c2.hex").read().strip())
xor = bytes(a ^ b for a, b in zip(c1, c2))

# 1. Угадываем, что P1 — стандартное приветствие
for guess in [b"Dear Bob,", b"Hello,", b"To whom"]:
    for off in range(0, 40):
        if off + len(guess) > len(xor): continue
        cand = bytes(a ^ b for a, b in zip(xor[off:], guess))
        if all(32 <= x < 127 for x in cand[:len(guess)]):
            print(f"P1[{off}:] ~ {guess} -> P2 ~ {cand[:len(guess)]}")
```

## Разбор: XOR в малвари

Малварь часто XOR-ит строки (URL, ключи) одним байтом или строкой. Извлечение:

```python
# ключ — один байт; перебираем и ищем осмысленное
for k in range(256):
    out = bytes(b ^ k for b in blob)
    if b"http" in out or b"\\\\" in out:
        print(k, out)
```

Инструменты: `xorsearch`, `xortool`, `CyberChef`.

## Как не застрять

- **Один байт** → перебор 256.
- **Повторяющийся ключ** → расстояние Хэмминга + xortool.
- **Два+ текста** → `C1⊕C2`, затем crib-dragging.
- **Ищите якорь** — известный формат (флаг, HTTP, приветствие).
- **Фильтруйте по печатности** — отсекает ложные.
- **Чем больше текстов** — тем легче (можно голосовать по байтам).

## Квиз

```quiz
- question: "Чему равно `(P ^ K) ^ K`?"
  options:
    - "0"
    - "P"
    - "K"
    - "2K"
  answer: 1
- question: "При каких условиях одноразовый блокнот невзламываем?"
  options:
    - "ключ короткий"
    - "ключ случаен, не короче сообщения и используется один раз"
    - "ключ повторяется"
    - "ключ равен паролю"
  answer: 1
- question: "Два сообщения зашифрованы одним ключом. Что даёт `C1 ^ C2`?"
  options:
    - "ключ"
    - "`P1 ^ P2`"
    - "ноль"
    - "`P1`"
  answer: 1
- question: "Что такое crib-dragging?"
  options:
    - "перебор ключей"
    - "перетаскивание угаданного слова по XOR-тексту для восстановления обоих сообщений"
    - "атака на хэши"
    - "метод факторизации"
  answer: 1
- question: "Какая метрика помогает найти длину ключа в repeating-key XOR?"
  options:
    - "энтропия"
    - "нормализованное расстояние Хэмминга между блоками"
    - "индекс совпадений букв"
    - "CRC32"
  answer: 1
```

## Где пригодится

- **CTF** — одна из самых частых crypto-задач (Cryptopals set 1).
- **Реверс малвари** — строки и конфиги обфусцированы XOR; ключ часто находится перебором.
- **Пентест** — самодельные «шифры» в приложениях и прошивках почти всегда ломаются XOR-атаками.
- **Форензика** — восстановление XOR-обфусцированных скриптов (PowerShell, VBS).
- **Понимание потоковых шифров** — ChaCha20/AES-CTR концептуально это «XOR с хорошим keystream».
