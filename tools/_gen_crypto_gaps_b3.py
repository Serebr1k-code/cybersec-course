#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Batch CR-GAP-2: symmetric ciphers & modes (2 hubs + 7 lessons + 7 labs).
import os
import sys
import base64

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson, _dir, _f, pyver, py_tool  # noqa: E402
from Crypto.Cipher import AES, DES  # noqa: E402

WD = '/home/student/task'
CHECK = "grep -q 'nto{' found.txt"


def b64(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('ascii')


def _lab(files, hints, flag, fs, tools, title, toolset=None):
    return {'title': title, 'toolset': toolset or ['core', 'python'],
            'workdir': WD, 'files': files, 'check': CHECK, 'hints': hints,
            'expect': {'file': WD + '/found.txt', 'contains': flag},
            'fs': fs, 'tools': tools}


# --- AES S-box --------------------------------------------------------------
def gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def gf_inv(a):
    if a == 0:
        return 0
    r = 1
    for _ in range(254):
        r = gf_mul(r, a)
    return r


def aes_sbox(a):
    b = gf_inv(a)
    s = b
    for i in range(1, 5):
        s ^= ((b << i) | (b >> (8 - i))) & 0xff
    return s ^ 0x63


# --- PRESENT ---------------------------------------------------------------
PSB = [0xC, 5, 6, 0xB, 9, 0, 0xA, 0xD, 3, 0xE, 0xF, 8, 4, 7, 1, 2]
PPB = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51, 4, 20, 36,
       52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55, 8, 24, 40, 56, 9, 25,
       41, 57, 10, 26, 42, 58, 11, 27, 43, 59, 12, 28, 44, 60, 13, 29, 45, 61,
       14, 30, 46, 62, 15, 31, 47, 63]


def present_keys(key80):
    k = key80 & ((1 << 80) - 1)
    ks = []
    for r in range(1, 32):
        ks.append((k >> 16) & 0xffffffffffffffff)
        k = ((k << 61) | (k >> 19)) & ((1 << 80) - 1)
        top = PSB[(k >> 76) & 0xf]
        k = (k & ((1 << 76) - 1)) | (top << 76)
        k ^= (r << 15)
    ks.append((k >> 16) & 0xffffffffffffffff)
    return ks


def present_enc(block, key80):
    state = block
    ks = present_keys(key80)
    for i, rk in enumerate(ks):
        state ^= rk
        if i == 31:
            break
        state = int(''.join('%x' % PSB[(state >> (4 * (15 - j))) & 0xf]
                            for j in range(16)), 16)
        out = 0
        for b in range(64):
            if (state >> b) & 1:
                out |= 1 << PPB[b]
        state = out
    return state


def present_dec(block, key80):
    state = block
    ks = present_keys(key80)
    for i in range(31, -1, -1):
        state ^= ks[i]
        if i == 0:
            break
        inv = [0] * 64
        for b in range(64):
            inv[PPB[b]] = b
        out = 0
        for b in range(64):
            if (state >> b) & 1:
                out |= 1 << inv[b]
        state = out
        state = int(''.join('%x' % PSB.index((state >> (4 * (15 - j))) & 0xf)
                            for j in range(16)), 16)
    return state


# --- SM4 -------------------------------------------------------------------
MSBOX = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2,
    0x28, 0xfb, 0x2c, 0x05, 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
    0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4,
    0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa,
    0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
    0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2,
    0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b,
    0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a, 0xd2,
    0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30,
    0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
    0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45,
    0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41,
    0x1f, 0x10, 0x5a, 0xd8, 0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
    0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0, 0x89, 0x69, 0x97, 0x4a,
    0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e,
    0xd7, 0xcb, 0x39, 0x48]
MFK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
MCK = [0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1,
       0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
       0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1,
       0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
       0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41,
       0x484f565d, 0x646b7279]


def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def sm4_tau(a):
    return ((MSBOX[(a >> 24) & 0xff] << 24) | (MSBOX[(a >> 16) & 0xff] << 16) |
            (MSBOX[(a >> 8) & 0xff] << 8) | MSBOX[a & 0xff])


def sm4_L(b):
    return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)


def sm4_Lp(b):
    return b ^ rotl(b, 13) ^ rotl(b, 23)


def sm4_keys(key):
    mk = [int.from_bytes(key[i * 4:i * 4 + 4], 'big') for i in range(4)]
    k = [mk[i] ^ MFK[i] for i in range(4)]
    rk = []
    for i in range(32):
        t = k[1] ^ k[2] ^ k[3] ^ MCK[i]
        rk.append(k[0] ^ sm4_Lp(sm4_tau(t)))
        k = [k[1], k[2], k[3], rk[-1]]
    return rk


def sm4_crypt(block, rk):
    x = [int.from_bytes(block[i * 4:i * 4 + 4], 'big') for i in range(4)]
    for i in range(32):
        t = x[1] ^ x[2] ^ x[3] ^ rk[i]
        x = [x[1], x[2], x[3], x[0] ^ sm4_L(sm4_tau(t))]
    return b''.join(x[3 - i].to_bytes(4, 'big') for i in range(4))


def sm4_enc(block, key):
    return sm4_crypt(block, sm4_keys(key))


def sm4_dec(block, key):
    return sm4_crypt(block, sm4_keys(key)[::-1])


# --- XTS (manual, AES-ECB core) --------------------------------------------
def xts_mul_alpha(t):
    t = bytearray(t)
    carry = t[15] >> 7
    for i in range(15, 0, -1):
        t[i] = ((t[i] << 1) & 0xff) | (t[i - 1] >> 7)
    t[0] = (t[0] << 1) & 0xff
    if carry:
        t[15] ^= 0x87
    return bytes(t)


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def xts_encrypt(pt, key1, key2, sector):
    tweak = AES.new(key2, AES.MODE_ECB).encrypt(sector.to_bytes(16, 'little'))
    out = b''
    for i in range(0, len(pt), 16):
        blk = pt[i:i + 16]
        c = xor(AES.new(key1, AES.MODE_ECB).encrypt(xor(blk, tweak)), tweak)
        out += c
        tweak = xts_mul_alpha(tweak)
    return out


def xts_decrypt(ct, key1, key2, sector):
    tweak = AES.new(key2, AES.MODE_ECB).encrypt(sector.to_bytes(16, 'little'))
    out = b''
    for i in range(0, len(ct), 16):
        blk = ct[i:i + 16]
        p = xor(AES.new(key1, AES.MODE_ECB).decrypt(xor(blk, tweak)), tweak)
        out += p
        tweak = xts_mul_alpha(tweak)
    return out


# --- toy Feistel -----------------------------------------------------------
FSBOX = [0x6, 0x4, 0xC, 0x5, 0x0, 0x7, 0x2, 0xE, 0x1, 0xF, 0x3, 0xD, 0x8,
         0xA, 0x9, 0xB]


def feistel_F(r, k):
    return FSBOX[(r ^ k) & 0xf]


def feistel_enc(block, key, rounds=6):
    L = (block >> 8) & 0xff
    R = block & 0xff
    for i in range(rounds):
        L, R = R, L ^ feistel_F(R, key[i % len(key)])
    return (L << 8) | R


def feistel_dec(block, key, rounds=6):
    L = (block >> 8) & 0xff
    R = block & 0xff
    for i in reversed(range(rounds)):
        L, R = R ^ feistel_F(L, key[i % len(key)]), L
    return (L << 8) | R


# ===========================================================================
# HUBS
# ===========================================================================
def hub_design():
    m = {
        'id': 'crypto-symmetric-design', 'category': 'crypto',
        'title': 'Устройство блочных шифров: DES, AES, лёгкие и национальные',
        'parent': 'crypto-symmetric-core', 'difficulty': 'medium', 'order': 5,
        'tags': ['crypto', 'aes', 'des', 'present', 'speck', 'sm4', 'gost', 'block-cipher'],
        'prerequisites': ['crypto-aes-modes'],
        'useful_for': [
            'Понимать внутреннее устройство блочных шифров',
            'CTF Crypto: нестандартные и лёгкие шифры',
        ],
        'estimated_minutes': 12,
        'summary': 'Модуль о внутреннем устройстве блочных шифров: DES/3DES, AES (S-box, key schedule, MixColumns), лёгкие шифры (PRESENT, Speck/Simon, GIFT, ASCON) и национальные (SM4, GOST, ARIA, Camellia, SEED).',
        'lab': None,
    }
    body = r'''Этот модуль открывает блочные шифры изнутри. В `crypto-aes-modes` ты узнал, **что** делают режимы (ECB, CBC, GCM). Здесь мы разберём, **как устроен сам блочный шифр** — что происходит внутри AES и DES, почему раунды повторяются, откуда берётся стойкость и почему появились лёгкие и национальные шифры.

## Что покрывает модуль

- **crypto-des-3des-deep** — DES и 3DES: сеть Фейстеля, S-боксы, key schedule, дифференциальный криптоанализ DES и почему 3DES всё ещё живёт в банкоматах.
- **crypto-aes-structure** — AES изнутри: поле GF(2^8), S-box как обращение + аффинное преобразование, MixColumns, key schedule и почему AES не сеть Фейстеля.
- **crypto-lightweight-ciphers** — лёгкие шифры: PRESENT, Speck/Simon, GIFT, ASCON. Для IoT и RFID нужна дешёвая аппаратная реализация.
- **crypto-regional-ciphers** — национальные стандарты: SM4 (Китай), GOST/Магма (Россия), ARIA (Корея), Camellia (Япония), SEED.

## Почему такой порядок

Начинаем с DES: он проще AES и наглядно показывает сеть Фейстеля. Затем AES — современный стандарт, но устроенный иначе (SP-сеть). После — лёгкие шифры, где ограничения по площади и энергии диктуют дизайн. И в конце — национальные стандарты, показывающие, как разные страны строят свои «AES».

## Что вы сможете после модуля

- Реализовать AES S-box и раунд DES на Python.
- Понимать разницу между сетью Фейстеля и SP-сетью.
- Оценивать параметры лёгких шифров для встраиваемых систем.
- Различать национальные шифры и знать их блок/ключ.

## Квиз

```quiz
- question: "Чем AES отличается от DES по структуре?"
  options:
    - "Ничем"
    - "DES — сеть Фейстеля, AES — SP-сеть (подстановка-перестановка)"
    - "AES использует ключ 56 бит"
    - "DES не имеет раундов"
  answer: 1
- question: "Почему появились лёгкие шифры?"
  options:
    - "AES слишком слабый"
    - "Для IoT/RFID нужна дешёвая аппаратная реализация с малым числом гейтов"
    - "DES устарел"
    - "Они быстрее на серверах"
  answer: 1
- question: "Что такое SM4?"
  options:
    - "Режим AES"
    - "Национальный блочный шифр Китая (128-битный блок и ключ)"
    - "Хэш-функция"
    - "Потоковый шифр"
  answer: 1
```

## Где пригодится

- **CTF Crypto:** нестандартные шифры требуют понимания устройства.
- **Аудит:** проверка корректности крипто-реализаций.
- **IoT:** выбор шифра под ограничения железа.
- **Работа:** понимание, почему нельзя «изобретать свой шифр».
'''
    write_lesson(m, body)


def hub_modes_advanced():
    m = {
        'id': 'crypto-modes-advanced', 'category': 'crypto',
        'title': 'Продвинутые режимы: SIV, tweakable и Feistel',
        'parent': 'crypto-modern-modes', 'difficulty': 'hard', 'order': 5,
        'tags': ['crypto', 'modes', 'siv', 'gcm-siv', 'ocb', 'xts', 'adiantum', 'feistel'],
        'prerequisites': ['crypto-modern-modes'],
        'useful_for': [
            'CTF Crypto: нестандартные режимы',
            'Понимать nonce-misuse-resistant шифрование',
        ],
        'estimated_minutes': 12,
        'summary': 'Продвинутые режимы: nonce-misuse-resistant (SIV, GCM-SIV), OCB/EAX, tweakable-шифры (XTS, Adiantum, Threefish) и обобщённые сети Фейстеля (unbalanced, Luby-Rackoff, тип-1/2/3).',
        'lab': None,
    }
    body = r'''Этот модуль продолжает тему режимов. В `crypto-modern-modes` были CBC, CTR, GCM. Здесь — режимы, которые решают конкретные проблемы: устойчивость к повтору nonce (SIV), шифрование дисков (XTS, Adiantum) и теоретические конструкции (Feistel, Luby-Rackoff).

## Что покрывает модуль

- **crypto-block-cipher-modes-siv** — SIV и GCM-SIV: что делать, если nonce повторился. SIV делает шифрование **детерминированным по содержимому**, поэтому повтор nonce не катастрофа.
- **crypto-tweakable-deep** — tweakable-шифры: XEX, XTS (диски), Adiantum (ChaCha+NH), Threefish (Skein). Tweak — это «ключ для позиции», не требующий повторного расписания.
- **crypto-feistel-advanced** — сети Фейстеля вглубь: unbalanced, тип-1/2/3, конструкция Luby-Rackoff (3-4 раунда дают псевдослучайную перестановку).

## Почему такой порядок

SIV идёт первым: он показывает, как «защититься от ошибки использования». Затем tweakable-шифры — практический инструмент для дисков, где важно шифровать блок по номеру сектора. И в конце — теория сетей Фейстеля, объясняющая, почему 3-4 раунда достаточно и как строить шифр из хэш-функции (Luby-Rackoff).

## Что вы сможете после модуля

- Реализовать AES-XTS и понимать, зачем два ключа.
- Объяснить, почему SIV устойчив к повтору nonce.
- Строить псевдослучайную перестановку из round-функции (Feistel).
- Понимать ограничения режимов и выбирать подходящий.

## Квиз

```quiz
- question: "В чём главное преимущество SIV-режима?"
  options:
    - "Он быстрее GCM"
    - "Он устойчив к повтору nonce (nonce-misuse-resistant)"
    - "Он не требует ключа"
    - "Он использует XOR"
  answer: 1
- question: "Зачем в XTS два ключа?"
  options:
    - "Для удвоения стойкости ключа"
    - "Один для данных, второй для генерации tweak по номеру сектора"
    - "Для резервного копирования"
    - "Для хэширования"
  answer: 1
- question: "Сколько раундов Luby-Rackoff достаточно для псевдослучайной перестановки?"
  options:
    - "1"
    - "3 (4 для сильной)"
    - "16"
    - "32"
  answer: 1
```

## Где пригодится

- **CTF Crypto:** режимы и их слабости.
- **Дисковое шифрование:** LUKS/BitLocker используют XTS.
- **Протоколы:** выбор режима под угрозы.
- **Обучение:** теория конструкций из примитивов.
'''
    write_lesson(m, body)


# ===========================================================================
# LESSONS
# ===========================================================================
def lesson_des():
    flag = 'nto{m33t_1n_th3_m1ddl3_0n_2d3s}'
    P = b'MITM2DES-pair16!'

    def mkkey(a, b):
        # vary two 4-bit nibbles; LSB of every byte is the DES parity bit -> 0
        return b'\x00' * 6 + bytes([a << 1, b << 1])

    K1 = mkkey(2, 10)
    K2 = mkkey(9, 12)

    def e(k, p):
        return DES.new(k, DES.MODE_ECB).encrypt(p)

    def dd(k, c):
        return DES.new(k, DES.MODE_ECB).decrypt(c)

    C = e(K2, e(K1, P))
    fs = [
        _dir(WD),
        _f(WD + '/task.md',
           '# Задача: meet-in-the-middle на 2DES\n\n'
           '`pair.txt` содержит открытый текст `P`, шифртекст `C = E_K2(E_K1(P))`\n'
           'и подсказку: ключи имеют вид `000000000000` + 2 байта, где каждый\n'
           'байт — это ниббл, сдвинутый влево на 1 (младший бит — бит чётности DES).\n'
           'Значит, ключевое пространство — 16*16 = 256 вариантов.\n\n'
           'Атака MITM: перебрать все `K1`, зашифровать `P`, сложить в словарь;\n'
           'затем перебрать все `K2`, расшифровать `C` и найти совпадение.\n\n'
           'Шаги:\n1. `cat pair.txt`.\n'
           '2. `python3 mitm.py` — находит K1, K2 и печатает флаг.\n'
           '3. `python3 mitm.py | grep nto > found.txt`.\n'),
        _f(WD + '/notes.txt',
           'Заметки:\n- 2DES: C = E_K2(E_K1(P)); brute-force = 2^56 * 2.\n'
           '- MITM: 2^56 памяти + 2^56 времени — вот почему 2DES не используют.\n'
           '- У DES младший бит каждого байта ключа — бит чётности, он игнорируется.\n'),
        _f(WD + '/pair.txt',
           'P_hex = %s\nC_hex = %s\nkey_space = 000000000000XXYY (XX,YY = nibble<<1)\n'
           % (P.hex(), C.hex())),
        _f(WD + '/mitm.py',
           "from Crypto.Cipher import DES\n"
           "P=bytes.fromhex('" + P.hex() + "')\n"
           "C=bytes.fromhex('" + C.hex() + "')\n"
           "def mk(a,b): return b'\\x00'*6+bytes([a<<1,b<<1])\n"
           "def e(k,p): return DES.new(k,DES.MODE_ECB).encrypt(p)\n"
           "def d(k,c): return DES.new(k,DES.MODE_ECB).decrypt(c)\n"
           "table={}\n"
           "for a in range(16):\n"
           "    for b in range(16):\n"
           "        table[e(mk(a,b),P)]=(a,b)\n"
           "for c in range(16):\n"
           "    for dd2 in range(16):\n"
           "        v=d(mk(c,dd2),C)\n"
           "        if v in table:\n"
           "            print('K1 =',table[v],' K2 =',(c,dd2))\n"
           "            print('flag: %s' % '" + flag + "')\n"
           "            raise SystemExit\n"),
    ]
    out = ('K1 = (2, 10)  K2 = (9, 12)\n'
           'flag: ' + flag + '\n')
    lab = _lab(['task.md', 'notes.txt', 'pair.txt', 'mitm.py'],
               ['`cat pair.txt` — P, C и вид ключа (7 нулей + 1 байт).',
                'MITM: словарь `E_K1(P)` для всех 256 K1, затем ищи `D_K2(C)`.',
                'Готовый скрипт: `python3 mitm.py`.',
                'Запиши флаг: `python3 mitm.py | grep nto > found.txt`.'],
               flag, fs, py_tool([pyver(),
                                  {'match': r'mitm\.py', 'example': 'python3 mitm.py', 'output': out}]),
               'Практика: meet-in-the-middle на 2DES')
    m = {
        'id': 'crypto-des-3des-deep', 'category': 'crypto',
        'title': 'DES и 3DES вглубь: сеть Фейстеля, S-боксы, key schedule',
        'parent': 'crypto-symmetric-design', 'difficulty': 'medium', 'order': 1,
        'tags': ['crypto', 'des', '3des', 'feistel', 'sbox', 'meet-in-the-middle', '2des'],
        'prerequisites': ['crypto-aes-modes'],
        'useful_for': [
            'CTF Crypto: DES/3DES и MITM',
            'Понимать сеть Фейстеля',
        ],
        'estimated_minutes': 35,
        'summary': 'DES изнутри: сеть Фейстеля, 16 раундов, S-боксы, key schedule и ослабление ключа. 2DES и атака meet-in-the-middle, 3DES и его режимы, дифференциальный криптоанализ DES и почему 3DES всё ещё в банкоматах.',
        'lab': None,
    }
    body = r'''## Вопрос, с которого всё начинается

AES — стандарт, но до него был **DES** (Data Encryption Standard), принятый в 1977 году. Он до сих пор встречается в банкоматах, смарт-картах и устаревших протоколах. Как он устроен и почему его «удвоение» (2DES) небезопасно, хотя «утроение» (3DES) — приемлемо? Разберём на конкретном примере с атакой meet-in-the-middle.

## Наш пример: 2DES и подозрительно быстрый взлом

У нас `pair.txt` с открытым текстом `P`, шифртекстом `C = E_K2(E_K1(P))` и подсказкой: ключи имеют вид `00000000000000XX`, то есть всего 256 вариантов каждый.

```
$ cat pair.txt
P_hex = 4d49544d32444553
C_hex = 7a1c...
```

## Шаг 1: сеть Фейстеля

DES — это **сеть Фейстеля**: блок 64 бита делится на две половины `L`, `R`, и каждый раунд делает:

```
L' = R
R' = L XOR F(R, K_i)
```

где `F` — раундовая функция, а `K_i` — подключ раунда. Такая структура обратима **без обратной функции F**: для расшифровки достаточно применять раунды в обратном порядке. DES делает 16 раундов, ключ 56 бит (8 байт, из которых 8 бит — контрольные).

## Шаг 2: раундовая функция F и S-боксы

Функция `F(R, K)` расширяет 32-битный `R` до 48 бит, складывает с подключом, разбивает на 8 групп по 6 бит и пропускает через **S-боксы** — таблицы 4×16, каждая заменяет 6 бит на 4. S-боксы — **нелинейный** элемент; без них DES был бы линейным и ломался бы мгновенно. Затем результат переставляется (P-бокс) и возвращает 32 бита.

## Шаг 3: key schedule

Из 56-битного ключа генерируются 16 подключей. Ключ сначала переставляется (PC-1), затем сдвигается и переставляется (PC-2) для каждого раунда. Слабость: некоторые ключи (**weak/semi-weak**) дают повторяющиеся подключи.

## Шаг 4: атака meet-in-the-middle на 2DES

Наивный перебор 2DES требует `2^56 * 2^56 = 2^112` операций. Но **meet-in-the-middle** уменьшает до `2^56` времени и памяти:

1. Для всех `K1` вычисляем `E_K1(P)` и складываем в словарь.
2. Для всех `K2` вычисляем `D_K2(C)` и ищем совпадение в словаре.

Совпадение даёт `K1, K2`. Это делает 2DES небезопасным (сложность `2^56`, а не `2^112`). В нашем примере ключи крошечные, поэтому MITM работает за миллисекунды.

```
$ python3 mitm.py
K1 byte = 42  K2 byte = 156
flag: nto{m33t_1n_th3_m1ddl3_0n_2d3s}
```

## Шаг 5: 3DES

3DES применяет DES трижды: `C = E_K3(D_K2(E_K1(P)))`. При трёх независимых ключах сложность `2^112` (MITM даёт только `2^112`, что приемлемо). Вариант **EDE** (encrypt-decrypt-encrypt) позволяет использовать 3DES как DES, положив `K1=K2=K3`. 3DES медленный, но живучий — он встречается в EMV, банкоматах и старых VPN.

## Полный прогон от начала до конца

1. `cat pair.txt` — P, C и вид ключа.
2. Строим словарь `E_K1(P)` для всех 256 `K1`.
3. Перебираем `K2`, ищем `D_K2(C)` в словаре.
4. Находим `K1, K2`, печатаем флаг.
5. `python3 mitm.py | grep nto > found.txt`.

## Если не сработало

Если совпадений много (ложные) — проверь кандидата на **втором** известном блоке. Если ключевое пространство не сводится к 256, MITM на полном DES нереален — нужен другой подход (дифференциальный криптоанализ). Помни: MITM требует памяти порядка числа кандидатов; для реального DES это `2^56` записей, что делает атаку теоретической.

## Дифференциальный и линейный криптоанализ DES

DES проектировался так, чтобы противостоять **дифференциальному криптоанализу** — методу, который смотрит на пары открытых текстов с известной разницей и ищет разницу шифртекстов с повышенной вероятностью. Для DES лучшая дифференциальная характеристика имеет вероятность порядка `2^-47`, поэтому для взлома нужно около `2^47` выбранных пар — больше, чем перебор `2^56`? Нет, меньше, но всё ещё нереально в 1970-х. **Линейный криптоанализ** ищет линейные аппроксимации S-боксов; для DES лучшая аппроксимация даёт смещение `2^-21`, и требуется `~2^43` известных пар.

Именно эти оценки объясняют, почему DES выбрал **8 S-боксов** с тщательно подобранными таблицами: они минимизируют максимальное дифференциальное и линейное смещение. S-боксы DES не случайны — они оптимизированы. Изучая их, криптографы создали целую науку о проектировании нелинейных слоёв.

## 3DES на практике: режимы и ключи

3DES бывает в вариантах **2-ключевой** (K1, K2, K1) и **3-ключевой** (K1, K2, K3). Двухключевой даёт `2^80` (из-за MITM на двух ключах), трёхключевой — `2^112`. В реальных системах (EMV, банкоматы, старые VPN) 3DES часто используется в режиме CBC или в **retail MAC** (для аутентификации сообщений). Поскольку DES-блок всего 64 бита, в CBC-режиме на больших объёмах появляется **Sweet32** — коллизии блоков при `2^32` блоках, что позволяет восстановить данные. Поэтому 3DES сейчас выводят из эксплуатации (NIST запретил его для новых систем с 2024 года), но в унаследованных системах он ещё живёт.

## Как отличить DES от AES по тест-вектору

На CTF часто дают «неизвестный блочный шифр» и надо понять, что это. Быстрый способ — прогнать известный тест-вектор. Для DES с ключом `133457799BBCDFF1` и открытым текстом `0123456789ABCDEF` шифртекст равен `85E813540F0AB405`. Для AES-128 с нулевым ключом и нулевым блоком шифртекст `66E94BD4EF8A2C3B884CFA59CA342B2E`. Если сервис или библиотека дают один из этих результатов — шифр опознан.

Дополнительный признак — **размер блока**: DES — 64 бита (8 байт), AES — 128 бит (16 байт). Если шифртекст при шифровании 8 байт даёт 8 байт — это, скорее, DES/Blowfish/3DES. Если 16 байт и меньше — AES/SM4/Кузнечик. А если шифртекст длиннее открытого на 16 байт — это AEAD с тегом (GCM/CCM).

## 3DES в режиме CBC и атака Sweet32

Когда 3DES применяют в CBC-режиме на больших объёмах данных, проявляется атака **Sweet32**. Она основана на **парадоксе дней рождения**: при шифровании `2^32` блоков (для 64-битного блока) с высокой вероятностью два блока совпадут, и атакующий, наблюдая повторы в шифртексте, восстановит часть открытого текста. Для 64-битного блока порог всего `2^32` блоков = 32 ГБ данных на одном ключе — вполне достижимо в долгоживущем TLS-соединении.

Из-за Sweet32 (и низкой скорости) 3DES выводят из эксплуатации. NIST официально запретил 3DES для новых применений, а браузеры и TLS-библиотеки удаляют соответствующие шифрсьюты. Для 128-битного блока (AES) порог составляет `2^64` блоков — практически недостижимо. Это ещё один аргумент в пользу перехода на AES/ChaCha20.

## Что мы теперь знаем

- DES — сеть Фейстеля с 16 раундами и нелинейными S-боксами.
- Сеть Фейстеля обратима без обратной F.
- 2DES ломается MITM за `2^56`, а не `2^112`.
- 3DES с тремя ключами даёт `~2^112` и всё ещё используется.
- S-боксы — источник нелинейности, без них шифр линеен.

## Квиз

Проверь себя.

```quiz
- question: "Как устроена сеть Фейстеля?"
  options:
    - "SP-сеть"
    - "Блок делится на L,R; раунд: L'=R, R'=L XOR F(R,K)"
    - "Только перестановки"
    - "Только XOR"
  answer: 1
- question: "Почему 2DES ломается легче, чем кажется?"
  options:
    - "Ключ короткий"
    - "Атака meet-in-the-middle даёт ~2^56 вместо 2^112"
    - "S-боксы слабые"
    - "Он не использует ключ"
  answer: 1
- question: "Что даёт нелинейность в DES?"
  options:
    - "Перестановки"
    - "S-боксы"
    - "XOR"
    - "Расширение"
  answer: 1
- question: "Сколько ключей в 3DES-EDE?"
  options:
    - "1"
    - "До трёх (24 байта)"
    - "16"
    - "56"
  answer: 1
```

## Куда дальше

Дальше — `crypto-aes-structure`: AES устроен иначе (SP-сеть) и не имеет S-боксов, вычисляемых таблицей DES. А пока главное: **сеть Фейстеля обратима без обратной функции, а 2DES не спасает от meet-in-the-middle.**

## Где пригодится

- **CTF Crypto** — DES/3DES, MITM-задачи.
- **Банкоматы/EMV** — 3DES всё ещё в эксплуатации.
- **Аудит** — оценка устаревших крипто-систем.
- **Обучение** — сеть Фейстеля как базовый строительный блок.
'''
    write_lesson(m, body, lab)


def lesson_aes_structure():
    flag = 'nto{a3s_sb0x_1s_1nv3rs3_plus_4ff1n3}'
    s0 = aes_sbox(0)
    s53 = aes_sbox(0x53)
    fs = [
        _dir(WD),
        _f(WD + '/task.md',
           '# Задача: AES S-box из первых принципов\n\n'
           'S-box AES не задаётся таблицей «на глаз» — он вычисляется:\n'
           '`S(a) = affine(inverse(a))`, где inverse берётся в GF(2^8)\n'
           '(не 0 -> 0), а affine — побитовое преобразование с константой 0x63.\n\n'
           'Шаги:\n1. `cat notes.txt`.\n'
           '2. Реализуй умножение в GF(2^8) с полиномом 0x11b.\n'
           '3. Обратный элемент = a^254; затем affine-преобразование.\n'
           '4. `python3 sbox.py` — печатает S(0x00), S(0x53) и флаг.\n'
           '5. `python3 sbox.py | grep nto > found.txt`.\n'),
        _f(WD + '/notes.txt',
           'Заметки:\n- GF(2^8): умножение с редукцией по 0x11b (x^8+x^4+x^3+x+1).\n'
           '- inverse(a)=a^254 (a!=0).\n- affine: s = b ^ rol(b,1) ^ rol(b,2) ^ rol(b,3) ^ rol(b,4) ^ 0x63.\n'),
        _f(WD + '/sbox.py',
           "def mul(a,b):\n"
           "    p=0\n"
           "    for _ in range(8):\n"
           "        if b&1: p^=a\n"
           "        hi=a&0x80; a=(a<<1)&0xff\n"
           "        if hi: a^=0x1b\n"
           "        b>>=1\n"
           "    return p\n"
           "def inv(a):\n"
           "    if a==0: return 0\n"
           "    r=1\n"
           "    for _ in range(254): r=mul(r,a)\n"
           "    return r\n"
           "def sbox(a):\n"
           "    b=inv(a); s=b\n"
           "    for i in range(1,5): s ^= ((b<<i)|(b>>(8-i)))&0xff\n"
           "    return s^0x63\n"
           "print('S(0x00) = 0x%02x' % sbox(0))\n"
           "print('S(0x53) = 0x%02x' % sbox(0x53))\n"
           "print('flag: %s' % '" + flag + "')\n"),
    ]
    out = ('S(0x00) = 0x63\nS(0x53) = 0xed\nflag: ' + flag + '\n')
    lab = _lab(['task.md', 'notes.txt', 'sbox.py'],
               ['`cat notes.txt` — формула S-box.',
                'Инверсия в GF(2^8): `a^254`; умножение с редукцией по `0x11b`.',
                'Affine: XOR сдвигов b и константа `0x63`.',
                'Запиши флаг: `python3 sbox.py | grep nto > found.txt`.'],
               flag, fs, py_tool([pyver(),
                                  {'match': r'sbox\.py', 'example': 'python3 sbox.py', 'output': out}]),
               'Практика: AES S-box')
    m = {
        'id': 'crypto-aes-structure', 'category': 'crypto',
        'title': 'AES изнутри: S-box, GF(2^8), MixColumns, key schedule',
        'parent': 'crypto-symmetric-design', 'difficulty': 'hard', 'order': 2,
        'tags': ['crypto', 'aes', 'sbox', 'gf256', 'mixcolumns', 'key-schedule', 'sp-network'],
        'prerequisites': ['crypto-aes-modes'],
        'useful_for': [
            'CTF Crypto: AES-структура и её атаки',
            'Понимать алгебру AES',
        ],
        'estimated_minutes': 40,
        'summary': 'AES изнутри: состояние 4x4, SubBytes через GF(2^8)-инверсию и аффинное преобразование, ShiftRows, MixColumns как умножение на полином, AddRoundKey и key schedule. Почему AES — SP-сеть, а не Фейстель, и как это влияет на атаки.',
        'lab': None,
    }
    body = r'''## Вопрос, с которого всё начинается

AES — самый используемый блочный шифр в мире. Но его S-box выглядит как «магическая таблица» из 256 чисел. Откуда она берётся? Оказывается, S-box AES **вычислим** из алгебры: это обращение в конечном поле плюс простое аффинное преобразование. Разберём это на конкретных значениях и напишем S-box с нуля.

## Наш пример: вычислим S(0x00) и S(0x53)

У нас есть только формула, и мы хотим получить два значения S-box: `S(0x00)` и `S(0x53)`.

```
$ cat notes.txt
- GF(2^8): умножение с редукцией по 0x11b (x^8+x^4+x^3+x+1).
- inverse(a)=a^254 (a!=0).
- affine: s = b ^ rol(b,1) ^ rol(b,2) ^ rol(b,3) ^ rol(b,4) ^ 0x63.
```

## Шаг 1: конечное поле GF(2^8)

Байт — это полином степени ≤7 над GF(2). Сложение — XOR, умножение — как умножение полиномов по модулю неприводимого `0x11b`. Реализация:

```python
def mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80; a = (a << 1) & 0xff
        if hi: a ^= 0x1b
        b >>= 1
    return p
```

Здесь `0x1b` — «остаток» от `0x11b` без старшего бита.

## Шаг 2: инверсия и аффинное преобразование

Обратный элемент `a^{-1}` в поле равен `a^254` (так как порядок мультипликативной группы 255). Для `a=0` инверсия считается 0 (по соглашению AES). Затем применяется аффинное преобразование — линейная комбинация битов плюс константа:

```python
def inv(a):
    if a == 0: return 0
    r = 1
    for _ in range(254): r = mul(r, a)
    return r

def sbox(a):
    b = inv(a); s = b
    for i in range(1, 5): s ^= ((b << i) | (b >> (8 - i))) & 0xff
    return s ^ 0x63
```

```
$ python3 sbox.py
S(0x00) = 0x63
S(0x53) = 0xed
flag: nto{a3s_sb0x_1s_1nv3rs3_plus_4ff1n3}
```

## Шаг 3: раунд AES

AES работает с состоянием 4×4 байт и делает 10/12/14 раундов (для ключей 128/192/256 бит). Раунд:

1. **SubBytes** — S-box к каждому байту (нелинейность).
2. **ShiftRows** — сдвиг строк на 0/1/2/3 (диффузия по строкам).
3. **MixColumns** — умножение каждого столбца на фиксированный полином в GF(2^8) (диффузия по столбцам).
4. **AddRoundKey** — XOR с раундовым ключом.

Последний раунд не содержит MixColumns. Ключевое отличие от DES: AES — **SP-сеть** (substitution-permutation), а не сеть Фейстеля. Шифрование и расшифровка различаются, но структура симметрична.

## Шаг 4: MixColumns и key schedule

**MixColumns** умножает столбец на матрицу, соответствующую умножению на полином `03·x^3 + 01·x^2 + 01·x + 02` по модулю `x^4+1`. Это обеспечивает быструю диффузию: изменение одного байта затрагивает весь столбец за один раунд. **Key schedule** расширяет ключ в 11/13/15 раундовых ключей через `RotWord`, `SubWord` и XOR с константами `Rcon`; для AES-256 дополнительно применяется S-box к промежуточным словам.

## Полный прогон от начала до конца

1. `cat notes.txt` — формула S-box.
2. Реализуем умножение в GF(2^8) с редукцией по `0x11b`.
3. Инверсия = `a^254`, затем affine с `0x63`.
4. `python3 sbox.py` — получаем S(0)=0x63, S(0x53)=0xed.
5. `python3 sbox.py | grep nto > found.txt`.

## Если не сработало

Частые ошибки: (1) редукция не по `0x11b`, а по другому полиному; (2) аффинное преобразование применяется к инверсии, а не к исходному байту; (3) константа не `0x63`; (4) инверсия считается как `pow(a, 254)` без учёта `a=0`. Проверь на известных значениях: `S(0)=0x63`, `S(1)=0x7c`, `S(0x53)=0xed`.

## ShiftRows и диффузия

**ShiftRows** циклически сдвигает строки состояния: строка 0 — на 0, строка 1 — на 1, строка 2 — на 2, строка 3 — на 3 байта влево. Зачем? Вместе с **MixColumns** (диффузия по столбцам) ShiftRows обеспечивает «перемешивание»: байт, попавший в столбец, после сдвига оказывается в другом столбце, и за два раунда изменение одного байта затрагивает весь блок. Это называется **полной диффузией** за 2 раунда — ключевое свойство AES.

Без ShiftRows AES был бы «по столбцам» и ломался бы по-блочно: каждый столбец шифровался бы независимо. Именно комбинация «диффузия по столбцам + сдвиг строк» даёт лавинный эффект: изменение одного бита меняет около половины битов выхода после нескольких раундов.

## Почему AES устойчив и где ломается

AES прошёл беспрецедентный публичный анализ: 25 лет и миллионы атак — и ни одна не сломала полный AES быстрее перебора. Известные атаки (например, **biclique**) снижают сложность до `2^254` для AES-256 — теоретически, но не практически. Реальные взломы AES — это взломы **реализаций**: 

- **Кэш-тайминг атаки** на табличные S-box (Bernstein, Osvik-Shamir-Tromer) — по времени доступа к таблицам восстанавливают ключ.
- **AES-NI** (аппаратная инструкция) устраняет таблицы и, значит, эти утечки.
- **Неправильные режимы** (ECB, повтор IV/nonce) ломают конфиденциальность, хотя сам AES цел.
- **Атаки по сторонним каналам** (питание, ЭМИ) на встраиваемых устройствах.

Вывод: **сам AES надёжен; ломается обвязка — режим, реализация, управление ключами.**

## Инструменты и проверка AES

На практике AES удобно проверять готовыми средствами. OpenSSL шифрует в режиме ECB/CBC/GCM:

```bash
$ echo -n '00112233445566778899aabbccddeeff' | xxd -r -p > pt.bin
$ openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -nopad -in pt.bin | xxd -p
```

В Python `pycryptodome` даёт прямой доступ к AES. Для проверки самодельной реализации сравни байт-в-байт с библиотекой на нескольких векторах. Если расходится — ищи ошибку в S-box, порядке байтов или в key schedule.

Отдельно стоит упомянуть **AES-NI**: современные CPU умеют AES аппаратно, и это одновременно быстрее и безопаснее (нет табличных кэш-утечек). При аудите реализации смотри, используется ли аппаратное ускорение и не строится ли S-box в памяти (что создаёт timing-канал).

## Лавинный эффект и число раундов

Проверить качество шифра можно «лавинным тестом»: меняем один бит входа и считаем, сколько битов выхода изменилось. У хорошего шифра после нескольких раундов меняется около половины битов (для AES — ~64 из 128). Если после одного раунда меняется мало битов, диффузия слабая. AES достигает полной диффузии за 2 раунда, но делает 10-14 для запаса.

Число раундов — это **страховка**. Криптоанализ всегда находит атаки на «урезанные» версии (AES с 4-5 раундами ломается), но не на полные. Поэтому дизайнеры берут с запасом: AES — 10/12/14, PRESENT — 31, SM4 — 32. Урезание раундов «ради скорости» — классическая ошибка, которая превращает стойкий шифр в сломанный.

## Что мы теперь знаем

- AES работает в GF(2^8) с полиномом `0x11b`.
- S-box = инверсия + аффинное преобразование + `0x63`.
- AES — SP-сеть (SubBytes/ShiftRows/MixColumns/AddRoundKey).
- MixColumns даёт диффузию по столбцам; ShiftRows — по строкам.
- Key schedule расширяет ключ в раундовые ключи через Rcon.

## Квиз

Проверь себя.

```quiz
- question: "Чему равен S(0x00) в AES?"
  options:
    - "0x00"
    - "0x63"
    - "0x1b"
    - "0xff"
  answer: 1
- question: "Как получается S-box AES?"
  options:
    - "Случайной таблицей"
    - "Инверсией в GF(2^8) и аффинным преобразованием"
    - "Умножением на ключ"
    - "XOR с Rcon"
  answer: 1
- question: "Что делает MixColumns?"
  options:
    - "Переставляет строки"
    - "Умножает столбцы на полином в GF(2^8), обеспечивая диффузию"
    - "XOR с ключом"
    - "Применяет S-box"
  answer: 1
- question: "AES — это..."
  options:
    - "сеть Фейстеля"
    - "SP-сеть (подстановка-перестановка)"
    - "потоковый шифр"
    - "хэш-функция"
  answer: 1
```

## Куда дальше

Дальше — `crypto-lightweight-ciphers`: PRESENT, Speck/Simon, GIFT и ASCON, где та же идея подстановки-перестановки оптимизирована под железо. А пока главное: **S-box AES не магия, а алгебра: инверсия в GF(2^8) плюс аффинное преобразование.**

## Где пригодится

- **CTF Crypto** — задачи на структуру AES и алгебру.
- **Аудит** — понимание реализаций AES (кэш-тайминги S-box).
- **Обучение** — конечные поля и SP-сети.
- **Работа** — оценка аппаратных реализаций.
'''
    write_lesson(m, body, lab)


def lesson_lightweight():
    flag = 'nto{pr3s3nt_31_r0unds_4nd_l1ghtw31ght}'
    key80 = int.from_bytes(bytes.fromhex('00000000000000000000'), 'big')
    pt = 0x0123456789abcdef
    ct = present_enc(pt, key80)
    back = present_dec(ct, key80)
    assert back == pt
    fs = [
        _dir(WD),
        _f(WD + '/task.md',
           '# Задача: лёгкий шифр PRESENT\n\n'
           '`present.txt` содержит 80-битный ключ (hex) и 64-битный шифртекст.\n'
           'Нужно расшифровать его шифром **PRESENT** (64-битный блок, 80-битный\n'
           'ключ, 31 раунд: addRoundKey, S-box по нибблам, битовая перестановка).\n\n'
           'Шаги:\n1. `cat present.txt`.\n'
           '2. Реализуй key schedule (rotate 61, S-box top nibble, XOR counter<<15).\n'
           '3. `python3 present.py` — расшифровка.\n'
           '4. `python3 present.py | grep nto > found.txt`.\n'),
        _f(WD + '/notes.txt',
           'Заметки:\n- PRESENT S-box: C,5,6,B,9,0,A,D,3,E,F,8,4,7,1,2.\n'
           '- Перестановка P(i): 0,16,32,48,1,17,...\n'
           '- Key schedule: rotate left 61, S-box на старший ниббл, XOR (r<<15).\n'),
        _f(WD + '/present.txt',
           'key_hex = %s\ncipher_hex = %016x\n' % ('00' * 10, ct)),
        _f(WD + '/present.py',
           "SB=[0xC,5,6,0xB,9,0,0xA,0xD,3,0xE,0xF,8,4,7,1,2]\n"
           "PB=[0,16,32,48,1,17,33,49,2,18,34,50,3,19,35,51,4,20,36,52,5,21,37,53,6,22,38,54,7,23,39,55,8,24,40,56,9,25,41,57,10,26,42,58,11,27,43,59,12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63]\n"
           "key=int('00'*10,16); ct=0x%016x\n" % ct +
           "def keys(k):\n"
           "    ks=[]\n"
           "    for r in range(1,32):\n"
           "        ks.append((k>>16)&0xffffffffffffffff)\n"
           "        k=((k<<61)|(k>>19))&((1<<80)-1)\n"
           "        top=SB[(k>>76)&0xf]; k=(k&((1<<76)-1))|(top<<76); k^=(r<<15)\n"
           "    ks.append((k>>16)&0xffffffffffffffff); return ks\n"
           "def dec(b,k):\n"
           "    st=b; ks=keys(k)\n"
           "    for i in range(31,-1,-1):\n"
           "        st^=ks[i]\n"
           "        if i==0: break\n"
           "        inv=[0]*64\n"
           "        for x in range(64): inv[PB[x]]=x\n"
           "        o=0\n"
           "        for x in range(64):\n"
           "            if (st>>x)&1: o|=1<<inv[x]\n"
           "        st=o\n"
           "        st=int(''.join('%x'%SB.index((st>>(4*(15-j)))&0xf) for j in range(16)),16)\n"
           "    return st\n"
           "print('plaintext_hex = %016x' % dec(ct,key))\n"
           "print('flag: %s' % '" + flag + "')\n"),
    ]
    out = ('plaintext_hex = %016x\nflag: %s\n' % (pt, flag))
    lab = _lab(['task.md', 'notes.txt', 'present.txt', 'present.py'],
               ['`cat present.txt` — 80-битный ключ и 64-битный шифртекст.',
                'PRESENT: 31 раунд S-box по нибблам + битовая перестановка.',
                'Key schedule: rotate 61, S-box старшего ниббла, XOR (r<<15).',
                'Запиши флаг: `python3 present.py | grep nto > found.txt`.'],
               flag, fs, py_tool([pyver(),
                                  {'match': r'present\.py', 'example': 'python3 present.py', 'output': out}]),
               'Практика: лёгкий шифр PRESENT')
    m = {
        'id': 'crypto-lightweight-ciphers', 'category': 'crypto',
        'title': 'Лёгкие шифры: PRESENT, Speck/Simon, GIFT, ASCON',
        'parent': 'crypto-symmetric-design', 'difficulty': 'medium', 'order': 3,
        'tags': ['crypto', 'lightweight', 'present', 'speck', 'simon', 'gift', 'ascon', 'iot'],
        'prerequisites': ['crypto-aes-modes'],
        'useful_for': [
            'CTF Crypto: нестандартные блочные шифры',
            'Выбор шифра для IoT/RFID',
        ],
        'estimated_minutes': 35,
        'summary': 'Лёгкие блочные шифры: PRESENT (SP-сеть, 31 раунд), Speck/Simon (ARX), GIFT и ASCON (AEAD-победитель NIST LWC). Почему для IoT/RFID важны площадь и энергия, и как это меняет дизайн.',
        'lab': None,
    }
    body = r'''## Вопрос, с которого всё начинается

AES отлично работает на серверах, но у него тяжёлый S-box и MixColumns — на дешёвом микроконтроллере или RFID-метке это дорого. Для таких устройств придумали **лёгкие шифры**: минимум гейтов, минимум энергии. Разберём **PRESENT** — один из первых стандартов ISO для лёгкой криптографии.

## Наш пример: расшифруем PRESENT

У нас `present.txt` с 80-битным ключом и 64-битным шифртекстом. Расшифруем.

```
$ cat present.txt
key_hex = 00000000000000000000
cipher_hex = 5579c1387b228445
```

## Шаг 1: структура PRESENT

PRESENT — **SP-сеть** с 31 раундом. Блок 64 бита, ключ 80 бит. Каждый раунд:

1. **addRoundKey** — XOR с 64-битным раундовым ключом.
2. **sBoxLayer** — S-box применяется к каждому из 16 нибблов.
3. **pLayer** — битовая перестановка `P(i)`.

Последний (32-й) раунд — только XOR с ключом. S-box PRESENT — 4-битный (`C,5,6,B,9,0,A,D,3,E,F,8,4,7,1,2`), что делает его дешёвым в железе.

## Шаг 2: key schedule

Ключ 80 бит обновляется между раундами:

1. **Ротация** влево на 61 бит.
2. **S-box** применяется к старшему нибблу (4 бита).
3. **XOR** 5-битного счётчика раунда в позицию 15.

```python
k = ((k << 61) | (k >> 19)) & ((1 << 80) - 1)
top = SB[(k >> 76) & 0xf]
k = (k & ((1 << 76) - 1)) | (top << 76)
k ^= (r << 15)
```

## Шаг 3: расшифровка

Расшифровка идёт раундами в обратном порядке: XOR с ключом, обратная перестановка, обратный S-box. Так как S-box и перестановка обратимы, всё просто.

```
$ python3 present.py
plaintext_hex = 0123456789abcdef
flag: nto{pr3s3nt_31_r0unds_4nd_l1ghtw31ght}
```

## Шаг 4: Speck, Simon, GIFT, ASCON

- **Speck** — ARX-шифр (сложение, ротация, XOR), очень компактный в софте.
- **Simon** — оптимизирован под железо, использует только AND/rotate/XOR.
- **GIFT** — улучшенный PRESENT, победитель конкурса для лёгких AEAD.
- **ASCON** — победитель NIST Lightweight Cryptography (2023), обеспечивает и шифрование, и аутентификацию (AEAD) при малых затратах.

Общая идея: **заменить дорогой S-box на дешёвый и сделать диффузию битовой перестановкой**. Это снижает площадь, но требует больше раундов для той же стойкости.

## Полный прогон от начала до конца

1. `cat present.txt` — ключ и шифртекст.
2. Реализуем key schedule (ротация, S-box, XOR счётчика).
3. Расшифровываем: XOR, обратная P, обратный S-box.
4. `python3 present.py | grep nto > found.txt`.

## Если не сработало

Частые ошибки: (1) счётчик XORed не в бит 15, а в младшие биты; (2) порядок «S-box, затем перестановка» перепутан; (3) обратный S-box построен неверно (`SB.index`); (4) в последнем раунде применён S-box. Проверь на векторе: ключ 0, текст 0 → шифртекст `5579C1387B228445`.

## ARX: Speck и Simon детальнее

**Speck** и **Simon** — семейства от АНБ, опубликованные в 2013 году для лёгких устройств. Speck оптимизирован под **софт**: использует только сложение по модулю `2^n`, циклические сдвиги и XOR (отсюда **ARX** — Add-Rotate-Xor). Это делает его быстрым на обычных CPU без таблиц. Simon оптимизирован под **железо**: только AND, rotate и XOR, что даёт минимальную площадь.

Оба имеют варианты блоков от 32 до 128 бит. Например, **Speck32/64** — 32-битный блок, 64-битный ключ, 22 раунда; **Speck128/256** — 128/256 и 34 раунда. Раунд Speck:

```
x = (ROTR(x, 7) + y) XOR k
y = ROTL(y, 2) XOR x
```

Ключевая идея: **заменить S-box арифметикой**. Стойкость держится на смешивании сложения (нелинейного по модулю) и сдвигов (линейных).

## ASCON и лёгкий AEAD

**ASCON** — победитель конкурса NIST Lightweight Cryptography (выбран в 2023, стандарт в 2024). Он обеспечивает **AEAD** (шифрование + аутентификация) при очень малых затратах, используя **sponge-конструкцию** (см. `crypto-sponge`): состояние 320 бит, перестановка из 12/8/6 раундов. ASCON применяется в IoT, автомобилях и смарт-картах.

Важное отличие от PRESENT: PRESENT — это только блочный шифр (нужен режим), а ASCON — **готовый AEAD**, что упрощает безопасное использование (нет ошибок в выборе режима). Это современный тренд: делать «батарейки в комплекте», чтобы разработчик не собрал небезопасную схему.

## Сравнение лёгких шифров

| Шифр | Блок | Ключ | Раунды | Стиль | AEAD |
|---|---|---|---|---|---|
| PRESENT | 64 | 80/128 | 31 | SP-сеть | нет |
| Speck | 32–128 | 64–256 | 22–34 | ARX | нет |
| Simon | 32–128 | 64–256 | 32–72 | ARX (железо) | нет |
| GIFT | 64/128 | 80/128 | 28–40 | SP-сеть | нет |
| ASCON | 320 (sponge) | 128 | 12/8/6 | sponge | да |

Таблица помогает выбирать: для RFID с минимумом гейтов — PRESENT/Simon; для софта без AES — Speck; для готового AEAD — ASCON. Ключевое, что нужно помнить: **лёгкость достигается ценой числа раундов и меньшего запаса стойкости**, поэтому такие шифры нельзя урезать ещё сильнее.

## Атаки на лёгкие шифры

Лёгкие шифры — не «игрушки», но у них меньше запаса. Основные классы атак:

- **Дифференциальный/линейный криптоанализ** — работает, но требует много пар. Для PRESENT лучшие характеристики покрывают 25 из 31 раунда, поэтому полный шифр не ломается.
- **Integral (square) атаки** — эффективны против схем с байтовой структурой (как AES-подобные). Для PRESENT применимы к урезанным версиям.
- **Related-key атаки** — если key schedule слаб, можно связать ключи и получить уравнения.
- **Атаки на режим** — самая частая проблема: сам PRESENT цел, а неправильный режим (ECB) ломает конфиденциальность.

Практический вывод: **лёгкие шифры требуют не меньше аккуратности в режимах**, чем AES. ASCON выигрывает тем, что даёт готовый AEAD — меньше шансов ошибиться.

## Что мы теперь знаем

- PRESENT — 64-битный блок, 80-битный ключ, 31 раунд SP-сети.
- S-box 4-битный; диффузия — битовая перестановка.
- Key schedule: ротация 61, S-box, XOR счётчика.
- Speck/Simon — ARX; GIFT/ASCON — современные лёгкие схемы.
- Цена лёгкости — больше раундов и меньшая скорость в софте.

## Запомни главное

Лёгкие шифры решают одну задачу — уложиться в минимум гейтов и энергии. Плата — число раундов и меньший запас стойкости. Если железо не ограничено, AES всегда предпочтительнее. Если ограничено — бери стандарт (PRESENT, ASCON) и готовую реализацию, а не самодельную схему. Помни, что ASCON даёт готовый AEAD и потому безопаснее в использовании, чем «PRESENT + самодельный режим».

## Квиз

Проверь себя.

```quiz
- question: "Сколько раундов в PRESENT?"
  options:
    - "10"
    - "31"
    - "16"
    - "64"
  answer: 1
- question: "Чем лёгкие шифры отличаются от AES?"
  options:
    - "Они слабее по определению"
    - "Дешёвый S-box и битовая перестановка вместо тяжёлых операций"
    - "Они не используют ключ"
    - "Они потоковые"
  answer: 1
- question: "Какой тип конструкции у Speck?"
  options:
    - "SP-сеть"
    - "ARX (сложение, ротация, XOR)"
    - "Сеть Фейстеля"
    - "Хэш"
  answer: 1
- question: "Что такое ASCON?"
  options:
    - "Режим AES"
    - "Победитель NIST LWC — лёгкий AEAD"
    - "Национальный шифр"
    - "Потоковый шифр 1990-х"
  answer: 1
```

## Куда дальше

Дальше — `crypto-regional-ciphers`: SM4, GOST, ARIA, Camellia — национальные стандарты, каждый со своим дизайном. А пока главное: **лёгкие шифры меняют дорогой S-box на дешёвый и компенсируют это числом раундов.**

## Где пригодится

- **IoT/RFID** — выбор шифра под ограничения железа.
- **CTF Crypto** — нестандартные шифры.
- **Аудит** — оценка реализаций лёгкой криптографии.
- **Обучение** — компромисс «площадь ↔ раунды».
'''
    write_lesson(m, body, lab)


def lesson_regional():
    flag = 'nto{sm4_1s_ch1n4s_n4t10n4l_4es}'
    key = bytes.fromhex('0123456789abcdeffedcba9876543210')
    pt = bytes.fromhex('0123456789abcdeffedcba9876543210')
    ct = sm4_enc(pt, key)
    assert ct.hex() == '681edf34d206965e86b3e94f536e4246'
    fs = [
        _dir(WD),
        _f(WD + '/task.md',
           '# Задача: национальный шифр SM4\n\n'
           '`sm4.txt` содержит 128-битный ключ и 128-битный шифртекст.\n'
           'Расшифруй их шифром **SM4** (Китай, GB/T 32907-2016):\n'
           '32 раунда, 128-битный блок и ключ, 8-битный S-box.\n\n'
           'Шаги:\n1. `cat sm4.txt`.\n'
           '2. Реализуй key schedule (FK, CK) и 32 раунда.\n'
           '3. `python3 sm4.py` — расшифровка.\n'
           '4. `python3 sm4.py | grep nto > found.txt`.\n'),
        _f(WD + '/notes.txt',
           'Заметки:\n- SM4: X_{i+4}=X_i ^ L(tau(X_{i+1}^X_{i+2}^X_{i+3}^rk_i)).\n'
           '- tau — S-box по байтам; L — XOR ротаций (2,10,18,24).\n'
           '- Расшифровка — те же раунды с обратным порядком ключей.\n'),
        _f(WD + '/sm4.txt',
           'key_hex = %s\ncipher_hex = %s\n' % (key.hex(), ct.hex())),
        _f(WD + '/sm4.py',
           "SBOX=[0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48]\n"
           "FK=[0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc]\n"
           "CK=[0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279]\n"
           "key=bytes.fromhex('%s'); ct=bytes.fromhex('%s')\n" % (key.hex(), ct.hex()) +
           "def rotl(x,n): return ((x<<n)|(x>>(32-n)))&0xffffffff\n"
           "def tau(a): return ((SBOX[(a>>24)&0xff]<<24)|(SBOX[(a>>16)&0xff]<<16)|(SBOX[(a>>8)&0xff]<<8)|SBOX[a&0xff])\n"
           "def L(b): return b^rotl(b,2)^rotl(b,10)^rotl(b,18)^rotl(b,24)\n"
           "def Lp(b): return b^rotl(b,13)^rotl(b,23)\n"
           "mk=[int.from_bytes(key[i*4:i*4+4],'big') for i in range(4)]\n"
           "k=[mk[i]^FK[i] for i in range(4)]; rk=[]\n"
           "for i in range(32):\n"
           "    t=k[1]^k[2]^k[3]^CK[i]; rk.append(k[0]^Lp(tau(t))); k=[k[1],k[2],k[3],rk[-1]]\n"
           "x=[int.from_bytes(ct[i*4:i*4+4],'big') for i in range(4)]\n"
           "for i in range(32):\n"
           "    t=x[1]^x[2]^x[3]^rk[31-i]; x=[x[1],x[2],x[3],x[0]^L(tau(t))]\n"
           "pt=b''.join(x[3-i].to_bytes(4,'big') for i in range(4))\n"
           "print('plaintext_hex =', pt.hex())\n"
           "print('flag: %s' % '" + flag + "')\n"),
    ]
    out = ('plaintext_hex = %s\nflag: %s\n' % (pt.hex(), flag))
    lab = _lab(['task.md', 'notes.txt', 'sm4.txt', 'sm4.py'],
               ['`cat sm4.txt` — 128-битный ключ и шифртекст.',
                'SM4: 32 раунда, tau (S-box по байтам) и L (XOR ротаций 2,10,18,24).',
                'Расшифровка — раунды с обратным порядком ключей.',
                'Запиши флаг: `python3 sm4.py | grep nto > found.txt`.'],
               flag, fs, py_tool([pyver(),
                                  {'match': r'sm4\.py', 'example': 'python3 sm4.py', 'output': out}]),
               'Практика: национальный шифр SM4')
    m = {
        'id': 'crypto-regional-ciphers', 'category': 'crypto',
        'title': 'Национальные шифры: SM4, GOST/Магма, ARIA, Camellia, SEED',
        'parent': 'crypto-symmetric-design', 'difficulty': 'hard', 'order': 4,
        'tags': ['crypto', 'sm4', 'gost', 'magma', 'aria', 'camellia', 'seed', 'national'],
        'prerequisites': ['crypto-aes-modes'],
        'useful_for': [
            'CTF Crypto: национальные стандарты',
            'Понимать разнообразие блочных шифров',
        ],
        'estimated_minutes': 35,
        'summary': 'Национальные блочные шифры: SM4 (Китай, GB/T 32907), ГОСТ Р 34.12-2015 «Магма» и «Кузнечик» (Россия), ARIA (Корея), Camellia (Япония), SEED. Структуры, параметры, S-боксы и практика расшифровки SM4.',
        'lab': None,
    }
    body = r'''## Вопрос, с которого всё начинается

AES — международный стандарт, но не единственный. Многие страны приняли **свои** блочные шифры: Китай — SM4, Россия — «Магма» и «Кузнечик», Корея — ARIA, Япония — Camellia. Они обязательны в госсекторе этих стран и встречаются на CTF. Разберём SM4 и сравним с родственниками.

## Наш пример: расшифруем SM4

У нас `sm4.txt` с 128-битным ключом и 128-битным шифртекстом. Расшифруем.

```
$ cat sm4.txt
key_hex = 0123456789abcdeffedcba9876543210
cipher_hex = 681edf34d206965e86b3e94f536e4246
```

## Шаг 1: структура SM4

SM4 — 32-раундовый шифр с 128-битным блоком и ключом. Раунд очень похож на AES-подобную конструкцию, но без MixColumns-матрицы: вместо неё — функция `L`, комбинирующая ротации. Формула раунда:

```
X_{i+4} = X_i XOR L(tau(X_{i+1} XOR X_{i+2} XOR X_{i+3} XOR rk_i))
```

где `tau` — S-box, применённый к каждому из четырёх байтов слова, а `L` — XOR циклических сдвигов на 2, 10, 18 и 24.

## Шаг 2: key schedule

Ключ расширяется через константы `FK` и `CK`:

```python
k = [mk[i] ^ FK[i] for i in range(4)]
for i in range(32):
    t = k[1] ^ k[2] ^ k[3] ^ CK[i]
    rk.append(k[0] ^ Lp(tau(t)))   # Lp — ротации 13, 23
    k = [k[1], k[2], k[3], rk[-1]]
```

Обрати внимание: в key schedule используется другая линейная функция `Lp` (ротации 13 и 23), а не `L`.

## Шаг 3: расшифровка

SM4 расшифровывается **теми же раундами** с раундовыми ключами в обратном порядке — как и положено «AES-подобной» схеме. Никаких обратных S-box не нужно.

```
$ python3 sm4.py
plaintext_hex = 0123456789abcdeffedcba9876543210
flag: nto{sm4_1s_ch1n4s_n4t10n4l_4es}
```

## Шаг 4: ГОСТ, ARIA, Camellia, SEED

- **ГОСТ Р 34.12-2015** определяет два шифра: **«Магма»** (бывший ГОСТ 28147-89, 64-битный блок, сеть Фейстеля) и **«Кузнечик»** (128-битный блок, SP-сеть).
- **ARIA** (Корея) — 128-битный блок, SP-сеть с двумя S-боксами (как AES, но с инволютивными слоями).
- **Camellia** (Япония) — 128-битный блок, сеть Фейстеля с «белыми» операциями XOR/rotate; близка по скорости к AES.
- **SEED** (Корея) — 128-битный блок, сеть Фейстеля с 16 раундами.

Общая черта: все они **AES-совместимы по параметрам** (128-битный блок), но различаются нелинейным слоем и диффузией.

## Полный прогон от начала до конца

1. `cat sm4.txt` — ключ и шифртекст.
2. Реализуем `tau` (S-box), `L` и `Lp`, key schedule с `FK`/`CK`.
3. Расшифровываем раундами с обратным порядком ключей.
4. `python3 sm4.py | grep nto > found.txt`.

## Если не сработало

Частые ошибки: (1) в key schedule использована `L` вместо `Lp` (ротации 13/23); (2) порядок байтов в слове (big-endian); (3) S-box не тот (у SM4 он свой, не AES); (4) неверный порядок раундовых ключей при расшифровке. Сверься с тест-вектором: ключ = текст = `0123...3210` → шифртекст `681edf34d206965e86b3e94f536e4246`.

## ГОСТ: Магма и Кузнечик

Российский стандарт ГОСТ Р 34.12-2015 определяет два шифра. **«Магма»** — преемник ГОСТ 28147-89: 64-битный блок, 256-битный ключ, 32-раундовая сеть Фейстеля с 4-битными S-боксами (нестандартное решение, S-боксы «настраиваемые»). **«Кузнечик»** (Kuznyechik) — 128-битный блок, 256-битный ключ, 9 раундов SP-сети с 8-битным S-боксом, порождённым специальной конструкцией (некоторые исследователи находили в нём «скрытую структуру», что вызвало дискуссии).

Оба шифра используются в российских крипто-библиотеках и обязательны в ряде систем. На CTF они встречаются в задачах «определи шифр по тест-вектору»: характерные параметры (64/256 у Магмы, 128/256 у Кузнечика) выдают страну происхождения.

## Как выбирают национальный шифр

Почему страны не используют просто AES? Причины разные: независимость от внешних стандартов, требования регуляторов, желание контролировать крипто-цепочку. Технически же все эти шифры близки: 128-битный блок, SP-сеть или Фейстель, 8-битный S-box. Различия — в деталях диффузии и key schedule, которые влияют на аппаратную эффективность и стойкость к конкретным атакам.

Для практика важно: **никогда не «улучшай» стандартный шифр** и **используй проверенную реализацию**. Национальные шифры проходят собственный криптоанализ, и не все они столь же изучены, как AES. Если задача требует SM4/Кузнечик — бери официальную библиотеку, а не самодельную.

## Практические заметки по национальным шифрам

При работе с национальными шифрами помни: их реализации должны быть **сертифицированы** в соответствующей юрисдикции. Самодельная реализация SM4 или Кузнечика легко содержит ошибку, а проверочных векторов меньше, чем для AES. Для CTF это неважно (там нужен лишь результат), но для продакшена — критично.

Второй момент — **режимы**. SM4/Кузнечик часто используются с режимами из своих стандартов: SM4-GCM, SM4-CBC; Кузнечик — с GOST-режимами (gost-mac, gost-ctr). При парсинге трафика или файлов важно понимать, какой режим и как передаётся IV. Ошибки «свой шифр + неверный режим» — частая причина уязвимостей в национальных крипто-системах.

Третий момент — **векторы атак**. Национальные шифры изучаются меньше, чем AES, поэтому новые атаки на них появляются реже, но и «запаса» доверия меньше. Не полагайся на «секретность дизайна» — это плохая практика (принцип Керкгоффса).

## Векторы атак на национальные шифры

Национальные шифры атакуют так же, как AES: через **реализации** и **режимы**, а не через сам алгоритм. Типичные проблемы:

- **Табличные S-box и кэш-тайминг** — как у AES, если нет аппаратного ускорения.
- **Слабый key schedule** — если раундовые ключи коррелируют, возможны related-key атаки.
- **Неправильный режим** — SM4-ECB на структурированных данных раскрывает паттерны.
- **Ошибки в тест-векторах** — самодельные реализации часто неверны; сравнение с официальными векторами обязательно.

Кузнечик и «Магма» изучены меньше AES, поэтому им доверяют меньше. Если задача не требует именно национальный стандарт — используй AES или ChaCha20. Если требует — бери сертифицированную библиотеку и не изобретай.

## Что мы теперь знаем

- SM4 — 128-битный блок и ключ, 32 раунда, S-box + линейная функция L.
- Key schedule использует FK, CK и функцию Lp.
- Расшифровка — обратный порядок раундовых ключей.
- ГОСТ-«Магма» — сеть Фейстеля; «Кузнечик» — SP-сеть.
- ARIA/Camellia/SEED — национальные шифры с 128-битным блоком.

## Запомни главное

Национальные шифры — это не «альтернатива AES», а её параметрические родственники: тот же 128-битный блок, та же идея SP-сети или Фейстеля. Разница в нелинейном слое и key schedule. Выбирая шифр, смотри не на «страну», а на стойкость, скорость и наличие проверенной реализации. Для учебных и CTF-задач важно уметь реализовать SM4 с нуля и сверить с официальным тест-вектором.

## Квиз

Проверь себя.

```quiz
- question: "Какой размер блока и ключа у SM4?"
  options:
    - "64/128"
    - "128/128"
    - "128/256"
    - "56/64"
  answer: 1
- question: "Чем SM4 отличается от AES?"
  options:
    - "Ничем"
    - "Вместо MixColumns-матрицы — линейная функция L на ротациях; key schedule со своими константами"
    - "Он потоковый"
    - "У него 56-битный ключ"
  answer: 1
- question: "Как расшифровывается SM4?"
  options:
    - "Обратным S-box"
    - "Теми же раундами с ключами в обратном порядке"
    - "Перебором"
    - "Через хэш"
  answer: 1
- question: "Какой российский шифр — сеть Фейстеля с 64-битным блоком?"
  options:
    - "Кузнечик"
    - "Магма (ГОСТ 28147-89)"
    - "SM4"
    - "ARIA"
  answer: 1
```

## Куда дальше

Мы закончили «устройство». Дальше — `crypto-block-cipher-modes-siv`: продвинутые режимы (SIV, XTS), где эти блочные шифры применяются к дискам и сообщениям с устойчивостью к повтору nonce. А пока главное: **национальные шифры параметрически совместимы с AES, но у каждого свой нелинейный слой.**

## Где пригодится

- **Госсектор/регуляция** — обязательные национальные стандарты.
- **CTF Crypto** — нестандартные шифры.
- **Аудит** — проверка «своего» шифра в продукте.
- **Обучение** — разнообразие дизайнов блочных шифров.
'''
    write_lesson(m, body, lab)


def lesson_siv():
    flag = 'nto{s1v_surv1v3s_n0nc3_r3us3}'
    key = bytes(range(32))
    data = b'nonce-misuse-resistant payload'
    c = AES.new(key, AES.MODE_SIV)
    ct, tag = c.encrypt_and_digest(data)
    d = AES.new(key, AES.MODE_SIV)
    assert d.decrypt_and_verify(ct, tag) == data
    fs = [
        _dir(WD),
        _f(WD + '/task.md',
           '# Задача: режим AES-SIV\n\n'
           '`siv.txt` содержит 32-байтный ключ, шифртекст и тег SIV-режима.\n'
           'Особенность SIV: nonce **выводится из самого сообщения** (через CMAC),\n'
           'поэтому даже при повторе внешнего nonce сообщения не раскрываются.\n\n'
           'Шаги:\n1. `cat siv.txt`.\n'
           '2. Расшифруй: `AES.new(key, MODE_SIV)` + `decrypt_and_verify(ct, tag)`.\n'
           '3. `python3 siv.py` — печатает открытый текст и флаг.\n'
           '4. `python3 siv.py | grep nto > found.txt`.\n'),
        _f(WD + '/notes.txt',
           'Заметки:\n- SIV = CMAC (для nonce) + CTR (для шифрования).\n'
           '- Шифрование: ct,tag = AES.new(key,MODE_SIV).encrypt_and_digest(data).\n'
           '- Расшифровка: AES.new(key,MODE_SIV).decrypt_and_verify(ct,tag).\n'),
        _f(WD + '/siv.txt',
           'key_hex = %s\ncipher_hex = %s\ntag_hex = %s\n'
           % (key.hex(), ct.hex(), tag.hex())),
        _f(WD + '/siv.py',
           "from Crypto.Cipher import AES\n"
           "key=bytes.fromhex('%s')\n" % key.hex() +
           "ct=bytes.fromhex('%s')\n" % ct.hex() +
           "tag=bytes.fromhex('%s')\n" % tag.hex() +
           "pt=AES.new(key,AES.MODE_SIV).decrypt_and_verify(ct,tag)\n"
           "print('plaintext:', pt.decode())\n"
           "print('flag: %s' % '" + flag + "')\n"),
    ]
    out = ('plaintext: nonce-misuse-resistant payload\nflag: ' + flag + '\n')
    lab = _lab(['task.md', 'notes.txt', 'siv.txt', 'siv.py'],
               ['`cat siv.txt` — ключ, шифртекст и тег.',
                'SIV: nonce = CMAC(сообщение); расшифровка идёт по тегу.',
                'Готовый скрипт: `python3 siv.py`.',
                'Запиши флаг: `python3 siv.py | grep nto > found.txt`.'],
               flag, fs, py_tool([pyver(),
                                  {'match': r'siv\.py', 'example': 'python3 siv.py', 'output': out}]),
               'Практика: режим AES-SIV')
    m = {
        'id': 'crypto-block-cipher-modes-siv', 'category': 'crypto',
        'title': 'Nonce-misuse-resistant режимы: SIV, GCM-SIV, OCB, EAX',
        'parent': 'crypto-modes-advanced', 'difficulty': 'hard', 'order': 1,
        'tags': ['crypto', 'modes', 'siv', 'gcm-siv', 'ocb', 'eax', 'nonce-misuse', 'aead'],
        'prerequisites': ['crypto-modern-modes'],
        'useful_for': [
            'CTF Crypto: режимы AEAD',
            'Проектировать устойчивое к ошибкам шифрование',
        ],
        'estimated_minutes': 35,
        'summary': 'Режимы, устойчивые к повтору nonce: SIV (CMAC+CTR, детерминированный nonce из сообщения), GCM-SIV, OCB и EAX. Почему повтор nonce в GCM катастрофичен, как SIV это чинит и в чём цена (нет потоковой обработки, нужен второй проход).',
        'lab': None,
    }
    body = r'''## Вопрос, с которого всё начинается

GCM — популярный AEAD-режим, но у него есть ахиллесова пята: **повтор nonce**. Если зашифровать два сообщения одним и тем же nonce, атакующий восстанавливает XOR открытых текстов и даже подделывает теги (атака «forbidden»). На практике nonce часто генерируют случайно или счётчиком, и ошибки случаются. Есть ли режим, устойчивый к такой ошибке? Да — **SIV**.

## Наш пример: расшифруем AES-SIV

У нас `siv.txt` с 32-байтным ключом, шифртекстом и тегом.

```
$ cat siv.txt
key_hex = 000102...1f
cipher_hex = 4a1c...
tag_hex = 9f3b...
```

## Шаг 1: почему повтор nonce в GCM катастрофичен

GCM шифрует, добавляя к открытому тексту поток, выведенный из `(key, nonce)`. Если nonce повторился, **поток тот же**: `C1 XOR C2 = P1 XOR P2`. XOR двух открытых текстов ломается статистикой (crib-dragging). Хуже: повтор nonce позволяет восстановить аутентификационный ключ GHASH и **подделывать теги** для произвольных сообщений. Поэтому в GCM nonce должен быть уникальным **на каждый ключ**.

## Шаг 2: идея SIV

SIV (Synthetic IV) выворачивает схему: nonce **не задаётся снаружи**, а вычисляется из сообщения. Схема:

1. `V = CMAC(K1, message)` — синтетический вектор (он же nonce).
2. `C = CTR(K2, V, message)` — шифрование.
3. Тег = `V` (или его часть).

Если одно и то же сообщение зашифровать дважды — получится одинаковый шифртекст (детерминированно), что приемлемо. Если **разные** сообщения — nonce почти наверняка разный (CMAC от разного входа). Значит, повтор внешнего nonce невозможен: его просто нет.

```python
c = AES.new(key, AES.MODE_SIV)
ct, tag = c.encrypt_and_digest(data)
d = AES.new(key, AES.MODE_SIV, nonce=tag)
assert d.decrypt_and_verify(ct, tag) == data
```

```
$ python3 siv.py
plaintext: nonce-misuse-resistant payload
flag: nto{s1v_surv1v3s_n0nc3_r3us3}
```

## Шаг 3: GCM-SIV, OCB, EAX

- **GCM-SIV** — «GCM с синтетическим IV»: использует POLYVAL вместо GHASH, но с той же идеей детерминированного nonce. Это RFC 8452.
- **OCB** — очень быстрый AEAD, но **не** устойчив к повтору nonce (как GCM).
- **EAX** — AEAD на базе CTR + CMAC; проще SIV, но тоже требует уникального nonce.

Ключевое различие: **SIV/GCM-SIV** устойчивы к misuse, **GCM/OCB/EAX** — нет. Цена SIV — два прохода по данным (сначала CMAC, потом CTR), поэтому он не потоковый и медленнее.

## Полный прогон от начала до конца

1. `cat siv.txt` — ключ, шифртекст, тег.
2. Создаём SIV-шифр с ключом и nonce=tag.
3. `decrypt_and_verify` возвращает открытый текст.
4. `python3 siv.py | grep nto > found.txt`.

## Если не сработало

Частые ошибки: (1) для расшифровки передают не тот `nonce` (нужен **тег**); (2) ключ не 32 байта (SIV требует двух ключей — CMAC и CTR — по 16 байт каждый); (3) `decrypt_and_verify` бросает исключение, если тег не совпал — это защита от подделки, а не баг. Помни: SIV **детерминирован**, поэтому одинаковые сообщения дают одинаковый шифртекст — это by design.

## Атака forbidden на GCM

Разберём подробнее, почему повтор nonce в GCM — катастрофа. GCM строит аутентификацию через **GHASH** — полиномиальный хэш над GF(2^128) с ключом `H = AES_K(0^128)`. Тег вычисляется как функция от шифртекста и длины. Если два сообщения зашифрованы одним nonce:

1. Их потоки `CTR(nonce)` совпадают, поэтому `C1 XOR C2 = P1 XOR P2` — конфиденциальность теряется.
2. Атакующий получает два тега на один и тот же `H`. Это позволяет **восстановить `H`** и затем подделывать теги для произвольных сообщений (атака **forbidden attack**).

Отсюда правило: **никогда не повторяй nonce в GCM**. Обычно nonce — 96-битный счётчик, и его переполнение (после `2^32` сообщений на ключ) уже опасно. Именно из-за сложности корректного использования nonce появились SIV и GCM-SIV.

## Детерминированное шифрование

SIV **детерминирован**: одно и то же сообщение с одним и тем же ключом даёт одинаковый шифртекст. Это и защита (повтор nonce невозможен), и ограничение: детерминированное шифрование **раскрывает равенство сообщений**. Если нужно скрыть и это, добавляют случайный «associated data» или используют ключ заново. В базах данных детерминированное шифрование иногда даже удобно (поиск по зашифрованному полю), но оно утекает паттерны. Выбор зависит от угроз: SIV оптимален там, где важно пережить ошибку nonce, а утечка равенства допустима.

## Сравнение AEAD-режимов

| Режим | Устойчив к повтору nonce | Потоковый | Скорость | Стандарт |
|---|---|---|---|---|
| GCM | нет | да | высокая (AES-NI) | NIST SP 800-38D |
| CCM | нет | нет | средняя | NIST SP 800-38C |
| OCB | нет | да | очень высокая | RFC 7253 |
| EAX | нет | да | средняя | ISO |
| SIV | да | нет | ниже | RFC 5297 |
| GCM-SIV | да | нет | ниже | RFC 8452 |

Выбор прост: если можешь гарантировать уникальность nonce — бери GCM/OCB (быстрее). Если нет — SIV/GCM-SIV. Если данных мало и важна простота — CCM/EAX. Главное правило: **не изобретай AEAD сам** — комбинирование шифра и MAC вручную почти всегда даёт уязвимость (как MAC-then-Encrypt).

## Практика: когда выбирать SIV

Алгоритм выбора AEAD на практике:

1. Можешь гарантировать уникальный nonce на каждый ключ? — да: бери **GCM** (быстро, аппаратно). Нет: бери **SIV/GCM-SIV**.
2. Нужна потоковая обработка гигабайтов? — GCM (SIV требует два прохода).
3. Устройство слабое, AES медленный? — **ChaCha20-Poly1305** или ASCON.
4. Нужна детерминированность (одинаковый вход → одинаковый выход)? — **SIV**.

Типичная ошибка — использовать GCM с **случайным** 96-битным nonce и большим числом сообщений: при `2^32` сообщениях вероятность коллизии nonce становится значимой (парадокс дней рождения), а коллизия в GCM катастрофична. SIV снимает эту головную боль.

## Что мы теперь знаем

- Повтор nonce в GCM раскрывает XOR открытых текстов и ломает теги.
- SIV выводит nonce из сообщения через CMAC — misuse-resistant.
- GCM-SIV — стандартизованный вариант (RFC 8452).
- OCB/EAX быстрее, но не устойчивы к повтору nonce.
- Цена SIV — два прохода, нет потоковости.

## Запомни главное

Выбор AEAD — это выбор угрозы, от которой ты защищаешься. GCM быстр, но требует дисциплины с nonce. SIV медленнее, но прощает ошибку. На практике безопаснее взять SIV там, где nonce генерируется в нескольких местах или может повториться, и GCM/ChaCha20-Poly1305 там, где nonce строго контролируется.

## Квиз

Проверь себя.

```quiz
- question: "Что происходит при повторе nonce в GCM?"
  options:
    - "Ничего"
    - "Один и тот же поток: XOR открытых текстов раскрывается, теги подделываются"
    - "Ключ меняется"
    - "Шифртекст короче"
  answer: 1
- question: "Откуда SIV берёт nonce?"
  options:
    - "Из счётчика"
    - "Из CMAC от сообщения (синтетический вектор)"
    - "Из ключа"
    - "Случайно"
  answer: 1
- question: "Какой режим НЕ устойчив к повтору nonce?"
  options:
    - "SIV"
    - "GCM"
    - "GCM-SIV"
    - "Все устойчивы"
  answer: 1
- question: "Почему SIV не потоковый?"
  options:
    - "Он использует хэш"
    - "Нужно два прохода: сначала CMAC, потом CTR"
    - "Он медленный"
    - "Он детерминированный"
  answer: 1
```

## Куда дальше

Дальше — `crypto-tweakable-deep`: XTS и Adiantum, где «tweak» привязывает шифрование к позиции (номеру сектора). А пока главное: **SIV делает nonce частью сообщения и потому переживает повтор внешнего nonce.**

## Где пригодится

- **Протоколы** — выбор AEAD под угрозы misuse.
- **CTF Crypto** — режимы и их слабости.
- **Аудит** — проверка обработки nonce.
- **Обучение** — компромиссы AEAD-дизайна.
'''
    write_lesson(m, body, lab)


def lesson_tweakable():
    flag = 'nto{xts_tw34k_1s_th3_s3ct0r_numb3r}'
    key1 = bytes(range(16))
    key2 = bytes(range(16, 32))
    sector = 7
    pt = b'sector data block padding-123456'
    ct = xts_encrypt(pt, key1, key2, sector)
    assert xts_decrypt(ct, key1, key2, sector) == pt
    fs = [
        _dir(WD),
        _f(WD + '/task.md',
           '# Задача: AES-XTS (tweakable)\n\n'
           '`xts.txt` содержит два 16-байтных ключа, номер сектора, открытый\n'
           'текст-заглушку и шифртекст. Нужно расшифровать XTS и найти флаг.\n\n'
           'Идея XTS: tweak = AES_K2(sector); каждый блок шифруется как\n'
           '`C = AES_K1(P XOR tweak) XOR tweak`, а tweak умножается на x в GF(2^128)\n'
           'после каждого блока.\n\n'
           'Шаги:\n1. `cat xts.txt`.\n'
           '2. `python3 xts.py` — расшифровка и вывод.\n'
           '3. `python3 xts.py | grep nto > found.txt`.\n'),
        _f(WD + '/notes.txt',
           'Заметки:\n- XTS: два ключа; tweak зависит от номера сектора.\n'
           '- Умножение на x: сдвиг влево, при переносе XOR 0x87 в старший байт.\n'),
        _f(WD + '/xts.txt',
           'key1_hex = %s\nkey2_hex = %s\nsector = %d\ncipher_hex = %s\n'
           % (key1.hex(), key2.hex(), sector, ct.hex())),
        _f(WD + '/xts.py',
           "from Crypto.Cipher import AES\n"
           "k1=bytes.fromhex('%s'); k2=bytes.fromhex('%s')\n" % (key1.hex(), key2.hex()) +
           "sector=%d; ct=bytes.fromhex('%s')\n" % (sector, ct.hex()) +
           "def mulx(t):\n"
           "    t=bytearray(t); c=t[15]>>7\n"
           "    for i in range(15,0,-1): t[i]=((t[i]<<1)&0xff)|(t[i-1]>>7)\n"
           "    t[0]=(t[0]<<1)&0xff\n"
           "    if c: t[15]^=0x87\n"
           "    return bytes(t)\n"
           "tw=AES.new(k2,AES.MODE_ECB).encrypt(sector.to_bytes(16,'little'))\n"
           "out=b''\n"
           "for i in range(0,len(ct),16):\n"
           "    b=ct[i:i+16]\n"
           "    x=bytes(a^b for a,b in zip(b,tw))\n"
           "    p=AES.new(k1,AES.MODE_ECB).decrypt(x)\n"
           "    out+=bytes(a^b for a,b in zip(p,tw))\n"
           "    tw=mulx(tw)\n"
           "print('plaintext:', out)\n"
           "print('flag: %s' % '" + flag + "')\n"),
    ]
    out = ("plaintext: b'sector data block padding-123456'\nflag: " + flag + '\n')
    lab = _lab(['task.md', 'notes.txt', 'xts.txt', 'xts.py'],
               ['`cat xts.txt` — два ключа, номер сектора и шифртекст.',
                'tweak = AES_K2(sector); далее C = AES_K1(P XOR tweak) XOR tweak.',
                'После каждого блока tweak умножается на x в GF(2^128).',
                'Запиши флаг: `python3 xts.py | grep nto > found.txt`.'],
               flag, fs, py_tool([pyver(),
                                  {'match': r'xts\.py', 'example': 'python3 xts.py', 'output': out}]),
               'Практика: AES-XTS')
    m = {
        'id': 'crypto-tweakable-deep', 'category': 'crypto',
        'title': 'Tweakable-шифры: XTS, Adiantum, Threefish',
        'parent': 'crypto-modes-advanced', 'difficulty': 'hard', 'order': 2,
        'tags': ['crypto', 'xts', 'tweakable', 'adiantum', 'threefish', 'xex', 'disk-encryption'],
        'prerequisites': ['crypto-modern-modes'],
        'useful_for': [
            'CTF Crypto: XTS и дисковое шифрование',
            'Понимать tweakable-конструкции',
        ],
        'estimated_minutes': 35,
        'summary': 'Tweakable-шифры: XEX, AES-XTS (дисковое шифрование с номером сектора как tweak), Adiantum (ChaCha+NH для дешёвых устройств), Threefish (Skein). Зачем нужен tweak и как он отличается от nonce и IV.',
        'lab': None,
    }
    body = r'''## Вопрос, с которого всё начинается

При шифровании дисков каждая **позиция** должна шифроваться по-разному, иначе одинаковые блоки дают одинаковый шифртекст и утекает структура файла. Но менять ключ на каждый сектор нельзя. Решение — **tweak**: дополнительный вход, привязывающий шифрование к позиции, но не требующий пересчёта расписания ключа. Разберём XTS — стандарт дискового шифрования.

## Наш пример: расшифруем AES-XTS

У нас `xts.txt` с двумя ключами, номером сектора и шифртекстом.

```
$ cat xts.txt
key1_hex = 000102...0f
key2_hex = 101112...1f
sector = 7
cipher_hex = 9a2c...
```

## Шаг 1: что такое tweak

**Tweak** — это как nonce, но он **детерминированно привязан к позиции**. Для дисков tweak = номер сектора. Он не секретен: атакующий может его знать. Задача tweak — сделать так, чтобы один и тот же блок данных на разных позициях шифровался по-разному. Это свойство называется **tweakable block cipher**.

## Шаг 2: конструкция XEX

XEX (XOR-Encrypt-XOR) строит tweakable-шифр из обычного:

```
C = E_K(P XOR T) XOR T
```

где `T = AES_K2(sector)`, а между блоками `T` умножается на `x` в GF(2^128) (сдвиг влево с редукцией по `0x87`). Такой «счётчик tweak» гарантирует, что каждый 16-байтный блок сектора шифруется своим значением.

```python
tw = AES.new(k2, AES.MODE_ECB).encrypt(sector.to_bytes(16, 'little'))
for each block:
    C = AES_K1(P XOR tw) XOR tw
    tw = mulx(tw)      # умножение на x в GF(2^128)
```

```
$ python3 xts.py
plaintext: b'sector data block padding-1234567'
flag: nto{xts_tw34k_1s_th3_s3ct0r_numb3r}
```

## Шаг 3: Adiantum и Threefish

**Adiantum** — tweakable-шифр для дешёвых устройств (Android Go). Вместо AES он использует ChaCha12 + NH + Poly1305, что быстрее AES на слабых процессорах без AES-ускорения. Структура: сначала NH-хэш, затем ChaCha для «широкого» блока, затем снова NH — всё с tweak.

**Threefish** — блочный шифр из хэш-функции Skein. Он «tweakable» по дизайну: tweak — обязательный вход, что делает его удобным для построения режимов. Триfish-512/1024 использовался в конкурсе SHA-3.

## Шаг 4: XTS vs CBC vs GCM

- **XTS** — для дисков: tweak = сектор, нет аутентификации (её добавляют отдельно, например, в BitLocker через отдельный HMAC).
- **CBC** — для сообщений, IV — на сообщение; нет привязки к позиции.
- **GCM** — AEAD с nonce; повтор nonce катастрофичен, тогда как XTS-«tweak» повторять можно (он привязан к позиции).

Ключевое: **tweak можно повторять для одного сектора, nonce — нельзя**. Это разные роли.

## Полный прогон от начала до конца

1. `cat xts.txt` — ключи, сектор, шифртекст.
2. Вычисляем `tweak = AES_K2(sector)`.
3. Для каждого блока: `P = AES_K1(C XOR tweak) XOR tweak`, умножаем tweak на x.
4. `python3 xts.py | grep nto > found.txt`.

## Если не сработало

Частые ошибки: (1) tweak не умножается на x после каждого блока; (2) умножение реализовано с неверным полиномом (нужен `0x87` при переносе); (3) номер сектора не little-endian; (4) ключи перепутаны местами (K1 для данных, K2 для tweak). Проверь roundtrip: зашифруй и расшифруй свои данные.

## XEX и почему XTS не аутентифицирует

XTS защищает **конфиденциальность**, но **не целостность**: атакующий может менять биты шифртекста, и расшифровка даст искажённый (но не «проверяемый») открытый текст. Для дисков это осознанный компромисс: аутентификация всего диска была бы слишком дорогой (нужно хранить теги на каждый сектор). Поэтому XTS применяют вместе с отдельным механизмом целостности: например, в **BitLocker** есть отдельные «validation» структуры, а в LUKS2 можно включить **dm-integrity** (HMAC на сектор).

Важно: если применить XTS к короткому сообщению и **повторно использовать tweak** (номер сектора) для разных данных, получится та же проблема, что с повторным IV в CTR: XOR двух шифртекстов раскроет XOR открытых текстов. Поэтому в дисковом шифровании tweak = номер сектора, а каждый сектор уникален.

## Adiantum детальнее

Adiantum — «XTS для слабых CPU». Он строит tweakable-шифр из:
1. **NH** — быстрый полиномиальный хэш (расширяет данные до 256 бит).
2. **ChaCha12** — потоковый шифр для основного блока.
3. **NH снова** — сжатие обратно.

Это даёт шифрование, устойчивое к «потоковой» структуре, с производительностью лучше AES на процессорах без AES-NI (например, бюджетные ARM). Adiantum используется в Android Go для шифрования пользовательских данных. Его стойкость сведена к стойкости ChaCha и NH.

## Сравнение tweakable-конструкций

| Конструкция | Примитив | Tweak | Применение |
|---|---|---|---|
| XEX | любой блочный | 1 блок | теоретическая база |
| XTS | AES (2 ключа) | номер сектора | диски (LUKS, BitLocker) |
| Adiantum | ChaCha+NH | номер сектора | Android Go |
| Threefish | собственный | 128 бит | Skein, режимы |

Общий принцип: tweakable-шифр позволяет **менять tweak без пересчёта ключа**, что критично для дисков с миллионами секторов. XEX/XTS — самый распространённый вариант; Adiantum — когда AES недоступен или медленный; Threefish — когда нужен tweakable-примитив «из коробки».

На CTF tweakable-задачи обычно дают XTS-шифртекст и просят расшифровать, зная ключи и номер сектора. Понимание XEX-формулы (`C = E(P XOR T) XOR T`) решает их за минуты.

## Ошибки при использовании XTS

XTS кажется простым, но ошибки встречаются. Главные:

- **Повтор tweak.** Если два разных фрагмента шифруются с одним номером сектора, XOR их шифртекстов раскроет XOR открытых текстов. Поэтому номер сектора должен быть уникален.
- **Нет аутентификации.** XTS не защищает от модификации: атакующий может «переставить» сектора (copy-paste) или изменить биты. Нужен отдельный MAC (dm-integrity, BitLocker validation).
- **Короткие последние блоки.** Если данные не кратны 16 байтам, применяется ciphertext stealing; самодельные реализации часто ошибаются здесь.
- **Переиспользование ключей.** Два ключа должны быть независимы; вывод второго из первого (K2 = K1) ломает XEX.

Понимание этих ошибок важно при аудите дискового шифрования: именно они дают реальные уязвимости.

## Что мы теперь знаем

- Tweak привязывает шифрование к позиции (номеру сектора).
- XTS = XEX с двумя ключами и умножением tweak на x.
- Adiantum — дешёвая альтернатива AES на слабых CPU.
- Threefish — tweakable-шифр из Skein.
- Tweak можно повторять; nonce — нельзя.

## Запомни главное

Tweakable-шифры — это инструмент для позиционно-зависимого шифрования. XTS — стандарт дисков; Adiantum — дешёвая альтернатива; Threefish — tweakable-примитив общего назначения. Не путай tweak (позиция, публичный) с nonce (уникальность, может быть публичным) и с ключом (секрет).

## Квиз

Проверь себя.

```quiz
- question: "Что такое tweak?"
  options:
    - "Второй ключ"
    - "Дополнительный вход, привязывающий шифрование к позиции"
    - "Хэш сообщения"
    - "IV"
  answer: 1
- question: "Чем XTS отличается от CBC?"
  options:
    - "Ничем"
    - "В XTS tweak привязан к номеру сектора, что скрывает структуру диска"
    - "XTS не использует ключ"
    - "CBC быстрее"
  answer: 1
- question: "Почему в XTS два ключа?"
  options:
    - "Для резерва"
    - "Один для данных, второй для генерации tweak"
    - "Для хэша"
    - "Для аутентификации"
  answer: 1
- question: "Что использует Adiantum вместо AES?"
  options:
    - "DES"
    - "ChaCha12 + NH + Poly1305"
    - "SM4"
    - "RSA"
  answer: 1
```

## Куда дальше

Дальше — `crypto-feistel-advanced`: обобщённые сети Фейстеля и конструкция Luby-Rackoff. А пока главное: **tweak — это «nonce для позиции», и его можно повторять, потому что он не секрет и не несёт случайности.**

## Где пригодится

- **Дисковое шифрование** — LUKS, BitLocker, FileVault.
- **Android Go** — Adiantum на слабых устройствах.
- **CTF Crypto** — tweakable-режимы.
- **Обучение** — роли IV, nonce и tweak.
'''
    write_lesson(m, body, lab)


def lesson_feistel():
    flag = 'nto{luby_r4ck0ff_3_r0unds_prp}'
    key = [0x3, 0x7, 0xB, 0x1]
    pt = 0x1A2B
    ct = feistel_enc(pt, key)
    assert feistel_dec(ct, key) == pt
    fs = [
        _dir(WD),
        _f(WD + '/task.md',
           '# Задача: сеть Фейстеля и её обратимость\n\n'
           '`feistel.txt` содержит ключ (список раундовых байтов) и шифртекст\n'
           'учебной 16-битной сети Фейстеля с 6 раундами. Расшифруй его.\n\n'
           'Раунд: `L,R -> R, L XOR F(R,K)`. Расшифровка: раунды в обратном порядке.\n'
           'Функция F(R,K) = SBOX[(R XOR K) & 0xf].\n\n'
           'Шаги:\n1. `cat feistel.txt`.\n'
           '2. `python3 feistel.py` — расшифровка.\n'
           '3. `python3 feistel.py | grep nto > found.txt`.\n'),
        _f(WD + '/notes.txt',
           'Заметки:\n- F не обязана быть обратимой — обратима сама структура.\n'
           '- Luby-Rackoff: 3 раунда дают PRP, 4 — сильную PRP.\n'),
        _f(WD + '/feistel.txt',
           'key = %s\ncipher_hex = %04x\n' % (key, ct)),
        _f(WD + '/feistel.py',
           "SBOX=[0x6,0x4,0xC,0x5,0x0,0x7,0x2,0xE,0x1,0xF,0x3,0xD,0x8,0xA,0x9,0xB]\n"
           "key=%s; ct=0x%04x\n" % (key, ct) +
           "def F(r,k): return SBOX[(r^k)&0xf]\n"
           "L=(ct>>8)&0xff; R=ct&0xff\n"
           "for i in reversed(range(6)):\n"
           "    L,R = R^F(L,key[i%len(key)]), L\n"
           "pt=(L<<8)|R\n"
           "print('plaintext_hex = %04x' % pt)\n"
           "print('flag: %s' % '" + flag + "')\n"),
    ]
    out = ('plaintext_hex = %04x\nflag: %s\n' % (pt, flag))
    lab = _lab(['task.md', 'notes.txt', 'feistel.txt', 'feistel.py'],
               ['`cat feistel.txt` — ключ и шифртекст.',
                'Расшифровка: раунды в обратном порядке; F не нужно обращать.',
                'Готовый скрипт: `python3 feistel.py`.',
                'Запиши флаг: `python3 feistel.py | grep nto > found.txt`.'],
               flag, fs, py_tool([pyver(),
                                  {'match': r'feistel\.py', 'example': 'python3 feistel.py', 'output': out}]),
               'Практика: сеть Фейстеля')
    m = {
        'id': 'crypto-feistel-advanced', 'category': 'crypto',
        'title': 'Сети Фейстеля вглубь: unbalanced, Luby-Rackoff, тип-1/2/3',
        'parent': 'crypto-modes-advanced', 'difficulty': 'expert', 'order': 3,
        'tags': ['crypto', 'feistel', 'luby-rackoff', 'unbalanced', 'prp', 'des', 'construction'],
        'prerequisites': ['crypto-modern-modes'],
        'useful_for': [
            'CTF Crypto: конструкции и обратимость',
            'Понимать теорию построения шифров',
        ],
        'estimated_minutes': 35,
        'summary': 'Сети Фейстеля вглубь: почему раундовая функция не обязана быть обратимой, типы 1/2/3, unbalanced-варианты, конструкция Luby-Rackoff (3 раунда — PRP, 4 — сильная PRP) и связь с DES и хэш-функциями.',
        'lab': None,
    }
    body = r'''## Вопрос, с которого всё начинается

Что если раундовая функция шифра **необратима** — например, это хэш? Оказывается, шифр всё равно можно построить: сеть Фейстеля делает обратимую перестановку из любой функции. Это фундаментальная конструкция, лежащая в основе DES и многих других шифров. Разберём её и расшифруем конкретный пример.

## Наш пример: 6-раундовая сеть Фейстеля

У нас `feistel.txt` с ключом и 16-битным шифртекстом.

```
$ cat feistel.txt
key = [3, 7, 11, 1]
cipher_hex = 8a5f
```

## Шаг 1: конструкция

Блок делится на две половины `L`, `R`. Раунд:

```
L' = R
R' = L XOR F(R, K_i)
```

где `F` — **любая** функция (не обязана быть обратимой). После раунда половины меняются местами. Расшифровка — те же раунды в обратном порядке:

```
L, R = R' XOR F(L', K_i), L'
```

Обратимость обеспечивается **структурой**, а не функцией `F`. Это ключевая идея.

## Шаг 2: unbalanced и типы

- **Balanced Feistel** — половины равны (DES: 32/32).
- **Unbalanced Feistel** — половины разного размера (например, 16/48 в MacGuffin). Позволяет строить шифры из хэшей с меньшим блоком.
- **Тип-1** — `F` зависит от `(L, R, K)`; **тип-2** — от `(R, K)`; **тип-3** — от `(R, K)` с разными подключом. DES — тип-2.

## Шаг 3: Luby-Rackoff

Теорема Luby-Rackoff: если `F` — псевдослучайная функция, то **3 раунда** Фейстеля дают псевдослучайную перестановку (PRP), а **4 раунда** — «сильную» PRP (устойчивую к атакам с доступом к обратной перестановке). Это объясняет, почему DES делает целых 16 раундов: запас стойкости.

Именно из этой теоремы выросли конструкции шифрования на хэш-функциях: **Luby-Rackoff** и **balanced Feistel** позволяют построить блочный шифр из хэша (например, из SHA-2), что использовалось в некоторых дизайнах.

```
$ python3 feistel.py
plaintext_hex = 1a2b
flag: nto{luby_r4ck0ff_3_r0unds_prp}
```

## Шаг 4: связь с DES и практикой

DES — 16-раундовая сеть Фейстеля типа-2. Blowfish, CAST, TEA/XTEA — тоже Фейстель. Даже AES-подобные SP-сети иногда комбинируют с Фейстелем для обратной совместимости. Понимание Фейстеля объясняет, почему «необратимую» функцию можно использовать в шифре и почему число раундов важно.

## Полный прогон от начала до конца

1. `cat feistel.txt` — ключ и шифртекст.
2. Берём `L`, `R` из шифртекста.
3. Применяем раунды в обратном порядке: `L, R = R XOR F(L, K_i), L`.
4. `python3 feistel.py | grep nto > found.txt`.

## Если не сработало

Частые ошибки: (1) раунды идут в прямом порядке вместо обратного; (2) подключи не развёрнуты; (3) `F` применена к неверной половине; (4) путаница с порядком `L`/`R` при извлечении из блока. Проверь на roundtrip: зашифруй свой открытый текст и расшифруй.

## Три раунда Luby-Rackoff: почему

Почему именно 3 раунда дают псевдослучайную перестановку? Интуиция: один раунд слишком «прозрачен» — `L' = R` видно снаружи. Два раунда тоже уязвимы к простой атаке. Три раунда «разрывают» связь между входом и выходом так, что без знания `F` предсказать выход невозможно. Четыре раунда добавляют устойчивость к атакам, где атакующий имеет доступ и к обратной перестановке. Формальное доказательство опирается на предположение, что `F` — псевдослучайная функция (PRF).

Это фундаментальный результат: он говорит, что **из слабого примитива (PRF) можно построить сильный (PRP)**. Именно поэтому сети Фейстеля так популярны в дизайне шифров — они «бесплатно» дают обратимость.

## Фейстель из хэш-функции

Если `F` — хэш-функция, то сеть Фейстеля даёт блочный шифр из хэша. Это основа конструкций типа **Luby-Rackoff** и некоторых «хэш-шифров». Проблема: хэш обычно обрабатывает блоки фиксированного размера, и приходится подгонять размеры половин. Практически это применялось в редких протоколах и в «retrofit»-шифровании, когда AES недоступен, а SHA-256 есть.

Обратная сторона: такая конструкция медленнее и менее изучена, чем AES. Использовать её стоит только при явной необходимости. На CTF такие задачи встречаются как «шифр на хэше» — и решаются пониманием того, что **обратимость обеспечивает структура, а не функция**.

## Практические заметки по Фейстелю

На CTF сети Фейстеля встречаются в задачах на «шифр из хэша» и на слабые round-функции. Типичная атака: если `F` линейна или зависит только от части входа, можно решить систему уравнений и восстановить ключ без перебора. Другая атака — **slide-атака**: если раунды одинаковы и ключи повторяются, шифр «сдвигается» относительно себя, и это даёт соотношения для анализа.

При реализации важно следить за **размером половин** и **числом раундов**. Слишком мало раундов (2-3 для unbalanced) — атакуемо; слишком много — медленно. DES выбрал 16, Blowfish — 16, TEA — 64 (простые раунды). Запас раундов — это осознанный компромисс между скоростью и стойкостью.

И главное: **сеть Фейстеля — не панацея**. Она даёт обратимость, но не гарантирует стойкость сама по себе. Всё решает качество round-функции и число раундов.

## Slide-атаки и слабые раундовые функции

Если все раунды сети Фейстеля **идентичны** (одинаковая `F`, одинаковые подключи), возникает **slide-атака**: шифр «сдвигается» относительно себя. Формально, если `E = R∘R∘...∘R`, то связь между `E(P)` и `E(R(P))` даёт уравнения, позволяющие восстановить ключ без полного перебора. Защита — делать раунды разными (разные подключи, константы), что и делают DES/AES.

Второй класс — атаки на **слабые round-функции**. Если `F(R,K) = R XOR K` (линейна), сеть Фейстеля становится линейной и решается гауссовым исключением. Если `F` зависит только от младших битов `R`, старшие биты не перемешиваются. Поэтому `F` обязана быть нелинейной и зависеть от всего входа.

Для CTF: если видишь «Фейстель с XOR-функцией» или «раунды без подключей», почти наверняка задача решается линейной алгеброй или slide-атакой.

## Что мы теперь знаем

- Сеть Фейстеля делает обратимую перестановку из любой (даже необратимой) функции.
- Расшифровка — раунды в обратном порядке, `F` не обращается.
- Типы 1/2/3 различаются входами `F`.
- Luby-Rackoff: 3 раунда — PRP, 4 — сильная PRP.
- DES/Blowfish/TEA — сети Фейстеля.

## Запомни главное

Сеть Фейстеля — универсальный конструктор: она превращает любую функцию в обратимую перестановку. Это объясняет и DES, и теорему Luby-Rackoff, и «шифры из хэшей». Но обратимость не равна стойкости: всё решает нелинейность и число раундов. На CTF «Фейстель» почти всегда означает либо восстановление ключа из слабой F, либо slide-атаку. Запомни формулу раунда: L'=R, R'=L XOR F(R,K) — и то, что расшифровка просто идёт в обратном порядке без обращения F.

## Квиз

Проверь себя.

```quiz
- question: "Обязана ли раундовая функция F быть обратимой?"
  options:
    - "Да"
    - "Нет: обратимость обеспечивает структура сети"
    - "Только для DES"
    - "Да, всегда"
  answer: 1
- question: "Как расшифровать сеть Фейстеля?"
  options:
    - "Обратить F"
    - "Пройти раунды в обратном порядке, не обращая F"
    - "Перебором"
    - "XOR с ключом"
  answer: 1
- question: "Сколько раундов Luby-Rackoff дают сильную PRP?"
  options:
    - "1"
    - "4"
    - "16"
    - "2"
  answer: 1
- question: "Какой шифр НЕ является сетью Фейстеля?"
  options:
    - "DES"
    - "AES"
    - "Blowfish"
    - "TEA"
  answer: 1
```

## Куда дальше

Мы закончили тему устройства шифров и режимов. Дальше — криптоанализ блочных шифров (`crypto-impossible-boomerang` и родственные): как атакуют раунды и почему число раундов важно. А пока главное: **сеть Фейстеля превращает любую функцию в обратимую перестановку — это фундамент DES и теории Luby-Rackoff.**

## Где пригодится

- **CTF Crypto** — конструкции и обратимость.
- **Проектирование** — построение шифров из примитивов.
- **Обучение** — теоретические основы блочных шифров.
- **Аудит** — понимание, почему нельзя урезать раунды.
'''
    write_lesson(m, body, lab)


if __name__ == '__main__':
    hub_design()
    hub_modes_advanced()
    lesson_des()
    lesson_aes_structure()
    lesson_lightweight()
    lesson_regional()
    lesson_siv()
    lesson_tweakable()
    lesson_feistel()
    print('batch 2 written')
