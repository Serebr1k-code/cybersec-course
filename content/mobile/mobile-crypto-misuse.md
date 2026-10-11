---
id: mobile-crypto-misuse
title: "Ошибки криптографии в мобильных приложениях"
category: mobile
parent: mobile-storage-deep
difficulty: hard
order: 4
tags: [crypto, aes, ecb, iv, hardcoded-key, hashing, android, misuse]
prerequisites: [mobile-insecure-storage, mobile-static-analysis]
useful_for:
  - "CTF Mobile (расшифровка данных/флага)"
  - "Bug bounty (слабая криптография)"
  - "Пентест мобильных приложений"
estimated_minutes: 35
summary: "Типовые ошибки криптографии в клиентах: hardcoded-ключи, ECB, фиксированный IV, слабое хэширование, самодельные схемы — и как их находить и эксплуатировать."
---
## Модель угроз клиентской криптографии

Ключевая аксиома мобильного пентеста: **всё, что исполняется на устройстве, доступно атакующему**. Значит, любой ключ, зашитый в APK, любой алгоритм, реализованный в клиенте, и любой «секретный» параметр шифрования попадают в руки исследователя. Клиентская криптография может защищать данные только от пассивного наблюдателя (например, от другого приложения на том же устройстве) — но не от того, кто декомпилировал APK.

Отсюда три класса ошибок, которые вы будете искать: **плохой примитив** (AES-ECB, MD5 для паролей, самодельный XOR), **плохое управление ключом** (hardcoded-ключ, фиксированный IV, предсказуемый `SecureRandom`) и **плохое применение** (шифрование вместо аутентификации, отсутствие проверки целостности, ключ, выводимый из публичных данных). В CTF эти ошибки дают прямой путь к расшифровке флага; в реальном пентесте — к раскрытию токенов и PII.

## Где искать криптокод в APK

Начинайте со статики: декомпилируйте APK и ищите вызовы криптопримитивов.

```bash
apktool d app.apk -o out
jadx -d out_jadx app.apk

# криптопримитивы
grep -rn "Cipher.getInstance\|SecretKeySpec\|IvParameterSpec\|MessageDigest" out_jadx | head -40
grep -rn "AES\|DES\|Blowfish\|RC4\|XOR" out_jadx | head -40
# режимы и паддинги
grep -rn "ECB\|CBC\|GCM\|CFB\|NoPadding\|PKCS5Padding\|PKCS7" out_jadx | head -40
# источники случайности и ключи
grep -rn "SecureRandom\|Random()\|new byte\[\]\|getBytes()" out_jadx | head -40
```

Красные флаги, которые надо отмечать сразу:

- `Cipher.getInstance("AES/ECB/PKCS5Padding")` — ECB виден по паттернам блоков.
- `new SecretKeySpec("mysecretkey12345".getBytes(), "AES")` — ключ-константа.
- `new IvParameterSpec("1234567890abcdef".getBytes())` — фиксированный IV.
- `new SecureRandom(new byte[]{1,2,3})` — засеянный PRNG (предсказуем).
- `MessageDigest.getInstance("MD5")` для паролей без соли.
- Свой цикл `for (...) out[i] = in[i] ^ key[i % key.length]` — XOR-«шифр».

## ECB: практическая эксплуатация

ECB шифрует одинаковые 16-байтные блоки открытого текста **одинаково**. Это даёт два вектора: визуальный анализ паттернов и перестановку блоков (cut-and-paste). Для визуализации классика — зашифровать картинку с однотонными областями: в ECB контуры сохраняются.

```python
from Crypto.Cipher import AES
from PIL import Image

key = b'0123456789abcdef'
img = Image.open('tux.bmp').convert('RGB')
raw = img.tobytes()
# добить до кратного 16
raw += b'\x00' * (-len(raw) % 16)
enc = AES.new(key, AES.MODE_ECB).encrypt(raw)
Image.frombytes('RGB', img.size, enc[:img.size[0]*img.size[1]*3]).save('ecb.png')
```

Для расшифровки используйте шифрование как **оракул** (chosen-plaintext) или переставляйте блоки. Если приложение шифрует ваши данные с известным префиксом, можно подобрать блок байт за байтом.

```python
# cut-and-paste: заменить блок шифротекста на блок с известным значением
ct = bytearray(open('token.bin','rb').read())
known = AES.new(key, AES.MODE_ECB).encrypt(b'admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b')
ct[16:32] = known            # подмена второго блока
open('tampered.bin','wb').write(ct)
```

## Фиксированный IV и повторное использование nonce

В CBC фиксированный IV означает, что одинаковые открытые тексты дают одинаковый шифротекст — утечка «равенства». В GCM/CTR **повторное использование nonce катастрофично**: два шифротекста с одним nonce позволяют восстановить XOR открытых текстов, а в GCM — ещё и подделать аутентификационный тег.

```python
# XOR двух шифротекстов CTR с одинаковым nonce = XOR открытых текстов
c1 = open('msg1.bin','rb').read()
c2 = open('msg2.bin','rb').read()
x = bytes(a ^ b for a, b in zip(c1, c2))     # = p1 ^ p2
print(x)
# если известен p1 (например, известный префикс), получаем p2:
p1 = b'Known prefix text!!'
p2 = bytes(a ^ b for a, b in zip(x, p1))
print(p2)
```

В CBC с фиксированным IV работает «byte-at-a-time»: если приложение шифрует `attacker_input || secret` и отдаёт шифротекст, вы восстанавливаете секрет побайтово, сравнивая блоки.

## Слабое хэширование и самодельные схемы

MD5/SHA1 без соли для паролей ломаются радужными таблицами и брутом. Ищите проверки вида:

```java
String h = md5(password);              // без соли
if (h.equals(storedHash)) { ... }      // уязвимо к rainbow tables
```

Самодельные «шифры» часто сводятся к XOR с константой или к ROT. В CTF их ломают частотным анализом или прямым восстановлением ключа из известного фрагмента:

```python
# known-plaintext для XOR
ct = bytes.fromhex('1d0f1c...')
known = b'FLAG{'
key = bytes(c ^ p for c, p in zip(ct[:len(known)], known))
# достроить ключ по длине и расшифровать
pt = bytes(c ^ key[i % len(key)] for i, c in enumerate(ct))
print(pt)
```

## Ключ из публичных данных (KDF-ошибки)

Частая ошибка — выводить ключ шифрования из чего-то, что атакующий знает или контролирует: IMEI, ANDROID_ID, имя пакета, UUID устройства, константу. Такая «защита» ломается декомпиляцией.

```java
// плохо: ключ = SHA-256(packageName + "salt")
SecretKey key = new SecretKeySpec(sha256(pkg + "salt"), "AES");
```

Если видите такое — просто воспроизведите вывод ключа локально с известными значениями и расшифруйте данные. Аналогично ломаются «обфусцированные» ключи, собранные из строковых констант (`"par"+"t1"+"t2"`) — декомпилятор склеивает их.

## Разобранный пример: расшифровка локальной БД

Задача: приложение хранит данные в зашифрованной SQLite, ключ зашит в коде.

```bash
# 1. находим криптокод
grep -rn "SecretKeySpec\|IvParameterSpec" out_jadx | head
# → SecretKeySpec("SuperSecretKey01".getBytes(),"AES"), IvParameterSpec("0000000000000000")

# 2. забираем файл БД с устройства
adb shell run-as com.target.app ls -la /data/data/com.target.app/databases/
adb shell run-as com.target.app cat /data/data/com.target.app/databases/app.db > app.db.enc

# 3. расшифровываем (CBC, PKCS5)
python3 - <<'PY'
from Crypto.Cipher import AES
key = b'SuperSecretKey01'
iv  = b'0000000000000000'
data = open('app.db.enc','rb').read()
pt = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
open('app.db','wb').write(pt)
PY
file app.db && sqlite3 app.db '.tables'
```

Дальше — обычный SQLite: ищем таблицу с токенами/флагом.

## Справочная таблица ошибок и последствий

| Ошибка | Признак в коде | Последствие | Как эксплуатировать |
|--------|----------------|-------------|---------------------|
| ECB | `AES/ECB/...` | видны паттерны блоков | cut-and-paste, byte-at-a-time |
| Фиксированный IV (CBC) | `IvParameterSpec("00...")` | равенство блоков | known-plaintext |
| Повтор nonce (GCM/CTR) | один nonce | XOR открытых текстов | XOR двух CT |
| Hardcoded key | `SecretKeySpec("...")` | полный обход | декомпиляция |
| Засеянный PRNG | `new SecureRandom(seed)` | предсказуемость | воспроизведение seed |
| MD5/SHA1 без соли | `MessageDigest("MD5")` | брут/таблицы | hashcat |
| Самодельный XOR | цикл `^` | тривиальный криптоанализ | known-plaintext |
| KDF из публичных данных | `sha(pkg+salt)` | воспроизводим | локальный расчёт |

## Типовые ошибки новичка

- **Искать только в Java.** Современные приложения выносят крипту в native (`.so`): ищите `grep` по строкам библиотек и реверсьте JNI-функции (`mobile-android-native`).
- **Забыть про runtime-ключи.** Часть ключей вычисляется в рантайме (из ответа сервера). Тогда поможет Frida-хук на `Cipher.doFinal` или на `SecretKeySpec` — дамп ключа и IV.
- **Путать шифрование и хэширование.** Хэш нельзя «расшифровать», только подобрать; проверяйте, что именно применяется.
- **Не проверять целостность.** Если MAC нет, возможна подмена блоков; не считайте схему безопасной только из-за AES.
- **Игнорировать Keystore.** Ключи в Android Keystore извлечь сложнее; если приложение их использует — смотрите `mobile-keystore`.

## Что дальше / решение

Нашли криптокод — сначала определите примитив, режим и источник ключа. Если ключ статичен — расшифровывайте локально. Если ключ рантаймовый — ставьте Frida-хук (`mobile-dynamic-frida`) и дампьте `doFinal`/`SecretKeySpec`. Если крипта в native — идите в `mobile-android-native`. Для понимания аппаратной защиты ключей — `mobile-keystore`. Решение задачи считается достигнутым, когда вы либо расшифровали целевые данные (флаг/токен), либо доказали, что ключ извлекается (для отчёта).

## Разобранный пример: byte-at-a-time против ECB-оракула

Классическая CTF-задача: сервис шифрует `ваш_ввод || secret` в ECB и отдаёт шифротекст. Секрет восстанавливается побайтово.

```python
from Crypto.Cipher import AES
BLOCK = 16

def oracle(data: bytes) -> bytes:
    # на сервере: AES-ECB(prefix + data + secret, key)
    return AES.new(KEY, AES.MODE_ECB).encrypt(pad(data + SECRET))

def recover(secret_len=32):
    known = b''
    for i in range(secret_len):
        # выравниваем так, чтобы последний байт секрета попал в конец блока
        filler = b'A' * (BLOCK - 1 - (len(known) % BLOCK))
        target_block_idx = (len(filler) + len(known)) // BLOCK
        # словарь всех возможных последних байтов
        table = {}
        for b in range(256):
            probe = filler + known + bytes([b])
            table[oracle(probe)[BLOCK*(target_block_idx):BLOCK*(target_block_idx+1)]] = b
        # сравниваем с реальным блоком (без последнего байта ввода)
        real = oracle(filler)[BLOCK*target_block_idx:BLOCK*(target_block_idx+1)]
        known += bytes([table[real]])
    return known

print(recover())   # b'FLAG{ecb_is_not_encryption}'
```

Идея: одинаковые префиксы блоков дают одинаковый шифротекст, поэтому мы «подставляем» байт за байтом и узнаём секрет по совпадению блоков. Такой же приём ломает ECB-«cookie»-схемы в вебе.

## Справочная таблица: инструменты криптоанализа

| Задача | Инструмент | Команда |
|--------|-----------|---------|
| Расшифровка AES | Python pycryptodome | `AES.new(key, AES.MODE_CBC, iv)` |
| Брут пароля/хэша | hashcat | `hashcat -m 0 hashes.txt rockyou.txt` |
| Определение типа хэша | hashid / hash-identifier | `hashid '$2a$10$...'` |
| XOR-криптоанализ | xortool | `xortool -l 16 cipher.bin` |
| Частотный анализ | CyberChef / dcode | операция «Frequency» |
| RSA-слабости | RsaCtfTool | `RsaCtfTool.py --publickey pub.pem --uncipher c.bin` |
| Поиск ключей в APK | apkleaks / jadx+grep | `apkleaks -f app.apk` |
| Дамп рантайм-ключа | Frida | хук на `SecretKeySpec.$init` |

Держите эту таблицу под рукой: по признаку (режим, длина ключа, источник) вы быстро выбираете инструмент и не тратите время на «написать с нуля».

## Квиз

```quiz
- question: "Какой режим AES даёт видимые повторы блоков и небезопасен?"
  options:
    - "ECB"
    - "GCM"
    - "CBC"
    - "CTR"
  answer: 0
  explanation: "ECB шифрует одинаковые блоки одинаково, раскрывая паттерны."
- question: "Что не хватает для расшифровки, если найден только ключ?"
  options:
    - "Режим и IV"
    - "Подпись APK"
    - "Версия Android"
    - "Язык приложения"
  answer: 0
  explanation: "Cipher.getInstance задаёт режим; IV нужен для CBC/CTR."
- question: "Чем опасен фиксированный IV?"
  options:
    - "Одинаковые начала сообщений дают одинаковый шифротекст"
    - "Он замедляет шифрование"
    - "Он требует root"
    - "Он блокирует сеть"
  answer: 0
  explanation: "Константный IV ломает семантическую стойкость."
- question: "Почему MD5 без соли для паролей — плохо?"
  options:
    - "Уязвим к радужным таблицам/перебору"
    - "Он слишком медленный"
    - "Он требует TLS"
    - "Он не поддерживается"
  answer: 0
  explanation: "Без соли одинаковые пароли дают одинаковые хэши."
- question: "Что такое base64 относительно шифрования?"
  options:
    - "Кодирование, не шифрование"
    - "Надёжный шифр"
    - "Хэш-функция"
    - "KDF"
  answer: 0
  explanation: "base64 лишь кодирует данные, не защищая их."
```

## Где пригодится

- **CTF Mobile:** расшифровка конфигов/флагов.
- **Bug bounty:** слабая криптография — валидная находка.
- **Пентест:** криптоаудит клиента.
- **Работа:** ревью использования крипто-API.
