---
id: crypto-stream-ciphers
title: "Потоковые шифры: RC4 и LFSR"
category: crypto
parent: crypto-symmetric-core
difficulty: medium
order: 4
tags: [crypto, stream-cipher, rc4, lfsr, keystream, berlekamp-massey, wots]
prerequisites: [crypto-intro, crypto-xor-otp]
useful_for:
  - "Атаковать RC4 (WEP, слабые ключи, biased keystream)"
  - "Восстанавливать LFSR по выходной последовательности"
  - "Понимать устройство потоковых шифров"
estimated_minutes: 40
summary: "Потоковые шифры: принцип keystream, RC4 и его слабости (KSA/PRGA, biases, WEP-атака), регистры сдвига с обратной связью (LFSR) и атака Берлекампа-Месси. Практические скрипты на Python. Мост к PRNG-предсказанию."
---

## Принцип потокового шифра

**Потоковый шифр** генерирует **keystream** (поток байт/бит, зависящий от ключа и nonce/IV) и XORит его с открытым текстом:

```
C_i = P_i ⊕ KS_i
P_i = C_i ⊕ KS_i
```

Это, по сути, «одноразовый блокнот с псевдослучайным ключом». Всё держится на том, что keystream **неотличим от случайного** и **никогда не повторяется**. Как только keystream повторяется (reused IV/nonce) или предсказуем (слабый генератор) — шифр ломается.

Потоковые шифры быстры, не требуют padding, работают с потоками — но требуют строгой уникальности nonce.

## RC4: устройство и слабости

RC4 (см. подробно `crypto-rc4-deep`) — самый известный потоковый шифр. Две фазы: **KSA** (перемешивание S-бокса ключом) и **PRGA** (генерация keystream). Слабости:

- **Статистические смещения:** второй байт keystream равен 0 вдвое чаще случайного; многие байты смещены.
- **Связанные ключи:** в WEP ключ = `IV || K`, и смена IV даёт связанные ключи → FMS-атака.
- **Повтор keystream:** при повторе ключа/IV — many-time pad.
- **Запрещён** в TLS (RFC 7465).

```python
def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    out = bytearray(); i = j = 0
    for b in data:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)
```

## Атака на RC4 с известным открытым текстом

Если известна часть открытого текста, keystream восстанавливается: `KS = C ⊕ P`. Затем расшифровывается остальное. Если keystream переиспользован (одинаковый ключ для нескольких сообщений) — `C1 ⊕ C2 = P1 ⊕ P2`, и crib-dragging восстанавливает тексты (см. `crypto-xor-otp`).

## LFSR: линейный генератор

**LFSR** (см. `crypto-lfsr`) — регистр, где новый бит = XOR от некоторых бит. Аппаратно дёшев, но **линеен**: по 2L битам выхода восстанавливается (Berlekamp–Massey). Поэтому в чистом виде непригоден; комбинируют нелинейно.

## Сравнение подходов

| Шифр | Тип | Слабость | Атака |
|---|---|---|---|
| XOR-OTP | игрушечный | повтор ключа | crib-dragging |
| RC4 | потоковый | смещения, связанные ключи | FMS, статистика |
| LFSR | потоковый | линейность | Berlekamp–Massey |
| ChaCha20 | потоковый (ARX) | nonce reuse | XOR текстов |
| AES-CTR | блочный в потоковом | nonce reuse | XOR текстов |

## Практический пример: восстановление LFSR

```python
# дано: 2L бит выхода LFSR
bits = [1,0,1,1,0,0,1,0,1,0,1,0,1,1,0,0]
L, poly = berlekamp_massey(bits)
print("LFSR length:", L, "poly:", poly)
# предсказываем следующие биты
```

## Практический пример: RC4 many-time pad

```python
c1 = bytes.fromhex(open("c1.hex").read().strip())
c2 = bytes.fromhex(open("c2.hex").read().strip())
xor = bytes(a ^ b for a, b in zip(c1, c2))    # = P1 ^ P2
# crib-dragging: угадываем слово в одном из текстов
for crib in [b"flag{", b"HTTP/", b"login"]:
    for off in range(len(xor) - len(crib)):
        guess = bytes(x ^ y for x, y in zip(xor[off:], crib))
        if all(32 <= g < 127 or g == 0 for g in guess[:len(crib)]):
            print(off, crib, guess[:len(crib)])
```

## Инструменты и команды

```bash
pip install pycryptodome
python3 -c "from Crypto.Cipher import ARC4; print(ARC4.new(b'k').encrypt(b'hi').hex())"
xortool cipher.bin        # для repeating-key XOR
aircrack-ng capture.cap   # WEP (RC4)
```

## Частые ошибки

- **Повтор nonce/IV.** Самая частая ошибка потоковых шифров.
- **Считать RC4 безопасным.** Запрещён.
- **Использовать LFSR напрямую.** Линеен.
- **Мало данных для статистики.** RC4-смещения требуют объёма.
- **Забывать про дроп первых байт** в RC4.
- **Путать keystream и ключ.** Восстановили keystream ≠ узнали ключ.

## Современные потоковые шифры

Современные потоковые шифры спроектированы так, чтобы их keystream был неотличим от случайного и не имел статистических смещений:

- **ChaCha20/Salsa20 (ARX):** add-rotate-xor; TLS 1.3, WireGuard, SSH.
- **AES-CTR/GCM:** блочный шифр в потоковом режиме; аппаратное ускорение.
- **Trivium, Grain, Rabbit:** eSTREAM-финалисты для аппаратуры.

Общая черта: keystream зависит от `(key, nonce, counter)`, и **уникальность nonce критична**. Если nonce повторяется, любой из них ломается одинаково: `C1 ⊕ C2 = P1 ⊕ P2`.

## Разбор: определение типа шифра по данным

1. **Длина == длине текста, не кратна 16** → потоковый.
2. **Два шифротекста, XOR осмыслен** → reused keystream.
3. **Есть смещения (RC4)** → статистика.
4. **Есть тег аутентификации** → AEAD (GCM/ChaCha20-Poly1305).
5. **Линейная рекуррентность** → LFSR.

## Сравнение: что использовать

| Задача | Выбор |
|---|---|
| Шифрование потока | ChaCha20 или AES-CTR |
| С аутентификацией | ChaCha20-Poly1305, AES-GCM |
| Аппаратура | Trivium/Grain |
| Legacy | избегать RC4 |

## Разбор: восстановление keystream и расшифровка

```python
# 1. Известен открытый текст P (например, HTTP-заголовок) и C
ks = bytes(a ^ b for a, b in zip(c, p))
# 2. Если keystream переиспользован для другого сообщения C2:
p2 = bytes(a ^ b for a, b in zip(c2, ks))
print(p2)
```

Это базовая атака на любой потоковый шифр с reused key/nonce.

## Разбор: статистика RC4

```python
from collections import Counter
# собрали много keystream-образцов (известные тексты, разные ключи)
c0 = Counter(ks[1] for ks in samples)
print(c0[0] / sum(c0.values()))   # ~0.0078 для RC4
```

## Разбор: LFSR через Berlekamp-Massey

```python
def berlekamp_massey(bits):
    C=[1]; B=[1]; L=0; m=-1
    for n in range(len(bits)):
        d=bits[n]
        for i in range(1,L+1): d ^= C[i] & bits[n-i]
        if d:
            T=C[:]; sh=n-m
            if len(C)<len(B)+sh: C+=[0]*(len(B)+sh-len(C))
            for j in range(len(B)): C[j+sh]^=B[j]
            if 2*L<=n: L=n+1-L; B=T; m=n
    return L,C

bits = [1,0,1,1,0,0,1,0,1,0,1,0,1,1,0,0]
print(berlekamp_massey(bits))   # (L, полином)
```

## Разбор: RC4 end-to-end

```python
def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in data:
        i = (i+1) & 0xff; j = (j+S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i]+S[j]) & 0xff])
    return bytes(out)

ct = rc4(b"secretkey", b"attack at dawn")
print(ct.hex())
```

## Разбор: ChaCha20 keystream вручную

```python
import struct
def rotl(x, n): return ((x << n) | (x >> (32-n))) & 0xffffffff
def qr(s,a,b,c,d):
    s[a]=(s[a]+s[b])&0xffffffff; s[d]^=s[a]; s[d]=rotl(s[d],16)
    s[c]=(s[c]+s[d])&0xffffffff; s[b]^=s[c]; s[b]=rotl(s[b],12)
    s[a]=(s[a]+s[b])&0xffffffff; s[d]^=s[a]; s[d]=rotl(s[d],8)
    s[c]=(s[c]+s[d])&0xffffffff; s[b]^=s[c]; s[b]=rotl(s[b],7)
def block(key, nonce, ctr):
    st = list(struct.unpack("<4I", b"expand 32-byte k")) + list(struct.unpack("<8I", key)) \
         + [ctr] + list(struct.unpack("<3I", nonce))
    w = st[:]
    for _ in range(10):
        qr(w,0,4,8,12); qr(w,1,5,9,13); qr(w,2,6,10,14); qr(w,3,7,11,15)
        qr(w,0,5,10,15); qr(w,1,6,11,12); qr(w,2,7,8,13); qr(w,3,4,9,14)
    return struct.pack("<16I", *[(w[i]+st[i])&0xffffffff for i in range(16)])
print(block(b"\x00"*32, b"\x00"*12, 0).hex())
```

## Разбор: сравнение потоковых шифров по скорости

- **RC4:** быстрый в софте, но сломан (смещения).
- **ChaCha20:** быстрый в софте (ARX), безопасен.
- **AES-CTR:** очень быстрый с AES-NI, безопасен.
- **LFSR:** дёшев в железе, но линеен.

## Как не застрять

- **Определите шифр** (RC4, LFSR, ChaCha, AES-CTR).
- **Ищите повтор keystream** — сравните два шифротекста.
- **Известный текст** → восстановите keystream.
- **RC4** → статистика/FMS.
- **LFSR** → Berlekamp–Massey.
- **Помните про мост к PRNG** (`crypto-prng`).

## Квиз

```quiz
- question: "Как потоковый шифр превращает текст в шифротекст?"
  options:
    - "подстановкой"
    - "XOR с keystream"
    - "факторизацией"
    - "перестановкой блоков"
  answer: 1
- question: "Какая слабость RC4 позволяет атаковать WEP?"
  options:
    - "коллизии"
    - "смещения keystream и связанные ключи с IV"
    - "padding"
    - "малый e"
  answer: 1
- question: "Сколько бит последовательности нужно для однозначного восстановления LFSR длины n?"
  options:
    - "n"
    - "2n"
    - "n^2"
    - "256"
  answer: 1
- question: "Что делает алгоритм Берлекампа–Месси?"
  options:
    - "факторизует n"
    - "находит минимальный LFSR по последовательности"
    - "ломает AES"
    - "считает gcd"
  answer: 1
- question: "Если известна часть открытого текста RC4, что можно получить?"
  options:
    - "ключ AES"
    - "соответствующий keystream и расшифровать остальное"
    - "d"
    - "хэш"
  answer: 1
```

## Где пригодится

- **CTF** — RC4-задачи, LFSR-предсказание, «известный plaintext».
- **Wi-Fi** — WEP/WPA-TKIP атаки (aircrack-ng).
- **Протоколы** — исторические TLS/SSL с RC4.
- **Hardware/IoT** — LFSR в прошивках и генераторах.
- **Мост к PRNG** — предсказание генераторов (см. `crypto-prng`).
