---
id: stego-encryption
title: "Комбинация шифрования и стеганографии: двойная защита"
category: stego
parent: stego-advanced
difficulty: easy
order: 1
tags: [stego, encryption, aes, password, layered, crypto]
prerequisites: [stego-advanced, stego-stegseek]
useful_for:
  - "CTF Stego — многослойные задачи"
  - "Понимание защиты конфиденциальности"
  - "Forensics: извлечение зашифрованных контейнеров"
estimated_minutes: 35
summary: "Зачем и как комбинируют шифрование со стеганографией: шифротекст в стего-контейнере, порядок извлечения, типичные цепочки (стего → архив → крипто) и инструменты."
---

Стеганография скрывает факт наличия сообщения, шифрование скрывает его содержимое. Вместе они дают и незаметность, и конфиденциальность: сначала шифруют данные, затем прячут шифротекст в контейнер (или наоборот). В CTF это порождает многослойные задачи: нужно правильно определить порядок распаковки и не перепутать, где какой слой.

## Зачем комбинировать

- **Стего без шифра:** нашедший контейнер прочитает данные.
- **Шифр без стего:** видно, что есть зашифрованный файл (повод копать).
- **Вместе:** данные выглядят как случайные байты внутри обычного файла; нужен и пароль, и знание канала.

## Порядок извлечения

Обычно: **сначала стего, потом крипто**. То есть вы находите данные в контейнере, и только затем расшифровываете. Обратный порядок тоже встречается (зашифрованный контейнер, внутри которого стего). Признаки порядка: заголовок `Salted__` (OpenSSL) → это шифр; `PK` → архив; base64 → кодирование.

```bash
# признаки слоёв
xxd extracted.bin | head
file extracted.bin
binwalk extracted.bin
```

## Типичные цепочки

1. **стего → base64 → шифр:** извлекли строку, декодировали base64, получили `Salted__` → `openssl enc -d -aes-256-cbc -in c.bin -k pass`.
2. **стего → архив → крипто:** извлекли ZIP (`zip2john` → john/hashcat), внутри зашифрованный файл.
3. **крипто-контейнер → стего:** зашифрованный образ, внутри — стего-канал.
4. **двойное стего:** данные в LSB, а ключ — в EXIF/метаданных.

## Инструменты

```bash
# OpenSSL-шифротекст
openssl enc -d -aes-256-cbc -pbkdf2 -in secret.enc -k "password"
# gpg
gpg -d secret.gpg
# архивы
zip2john secret.zip > h; john h --wordlist=rockyou.txt
7z2john secret.7z > h; john h --wordlist=rockyou.txt
# hashcat
hashcat -m 17200 secret.zip.hash rockyou.txt   # PKZIP
# стего-пароли
stegseek container.jpg rockyou.txt
```

## Разобранный пример

CTF: PNG, zsteg выдаёт base64. Декодируем → `Salted__...` → `openssl enc -d -aes-256-cbc -k` с паролем из метаданных (`exiftool`) → флаг. Мораль: собирайте подсказки из всех слоёв (метаданные = часто пароль).

## Частые ошибки

- Пытаться расшифровать до извлечения из контейнера.
- Не распознавать формат шифротекста (`Salted__`, `-----BEGIN PGP`).
- Игнорировать метаданные как источник пароля.
- Путать base64 (кодирование) и шифрование.

## Что делать дальше

- **`Salted__`** → OpenSSL с паролем из подсказки.
- **`PK`/`7z`** → архив, брут пароля (`zip2john`/hashcat).
- **PGP** → `gpg -d`.
- **Нет подсказки** → ищите пароль в метаданных/других слоях.

## Модель угроз: стего + крипто

Два независимых механизма решают разные задачи и усиливают друг друга:

- **Стеганография** скрывает **факт** передачи сообщения (данные выглядят как обычный файл).
- **Шифрование** скрывает **содержимое** (даже найдя данные, их не прочитать).

Комбинация даёт «незаметно и непонятно». В CTF это многослойная задача: контейнер → извлечение → расшифровка → флаг.

## Распознавание слоёв (детект-таблица)

| Признак в hex/строке | Что это | Действие |
|----------------------|---------|----------|
| `Salted__` | OpenSSL enc (AES/DES + соль) | `openssl enc -d` |
| `-----BEGIN PGP` | PGP/GPG | `gpg -d` |
| `PK\x03\x04` | ZIP | `unzip`, `zip2john` |
| `7z\xbc\xaf` | 7-Zip | `7z x`, `7z2john` |
| `Rar!\x1a` | RAR | `unrar`, `rar2john` |
| `base64`-алфавит | кодирование (не шифр!) | `base64 -d` |
| высокий индекс энтропии | шифр/сжатие | сначала распознать контейнер |
| `U2FsdGVkX1` | base64 от `Salted__` | base64 → openssl |

```bash
xxd extracted.bin | head
file extracted.bin
binwalk extracted.bin
# энтропия (высокая = шифр/сжатие)
python3 -c "import math;d=open('extracted.bin','rb').read();from collections import Counter;c=Counter(d);n=len(d);print(-sum(v/n*math.log2(v/n) for v in c.values()))"
```

## OpenSSL/GPG: полные команды

```bash
# OpenSSL: расшифровка (пароль)
openssl enc -d -aes-256-cbc -pbkdf2 -in secret.enc -out plain.txt -k "password"
# с солью в файле (Salted__) — -k достаточно, соль читается из файла
openssl enc -d -aes-256-cbc -in secret.enc -k "password"
# если известен IV/соль отдельно
openssl enc -d -aes-256-cbc -K <hexkey> -iv <hexiv> -in secret.enc
# GPG
gpg -d secret.gpg                 # расшифровать (спросит пароль)
gpg --decrypt --passphrase "p" --batch secret.gpg
# определить, что это openssl
file secret.enc && head -c 8 secret.enc | xxd
```

## Архивы: zip2john/7z2john/hashcat

```bash
# ZIP
zip2john secret.zip > zip.hash
john zip.hash --wordlist=/usr/share/wordlists/rockyou.txt
hashcat -m 17200 zip.hash rockyou.txt           # PKZIP (или -m 13600 WinZip)
# 7-Zip
7z2john secret.7z > 7z.hash
hashcat -m 11600 7z.hash rockyou.txt
# RAR
rar2john secret.rar > rar.hash
hashcat -m 13000 rar.hash rockyou.txt
# извлечь после взлома
unzip -P pass secret.zip
7z x -pPASS secret.7z
```

## Пароль из метаданных/подсказок

В CTF пароль часто лежит **рядом**: в EXIF, комментарии, имени файла, другом слое.

```bash
exiftool cover.jpg | grep -iE 'comment|description|user|software'
strings -a cover.jpg | grep -iE 'pass|key|hint' | head
# пароль может быть в другом стего-слое (например, LSB другого файла)
zsteg cover.png | grep -i pass
```

## Полные цепочки (4 сценария)

**1. стего → base64 → шифр.** `zsteg` даёт base64 → `base64 -d` → `Salted__` → `openssl enc -d -aes-256-cbc -k <пароль из EXIF>` → флаг.

**2. стего → архив → крипто.** Извлекли ZIP → `zip2john` + john → распаковали → внутри ещё один зашифрованный файл → повторяем.

**3. крипто-контейнер → стего.** Зашифрованный образ; пароль найден → внутри стего-канал (LSB) → второй слой.

**4. двойное стего.** Данные в LSB, а ключ — в EXIF/метаданных или в другом канале (альфа/аудио).

## Инструменты (таблица)

| Инструмент | Назначение | Пример |
|------------|-----------|--------|
| `openssl` | симметричное шифрование | `openssl enc -d -aes-256-cbc -k p` |
| `gpg` | PGP | `gpg -d file.gpg` |
| `zip2john`/`7z2john`/`rar2john` | хэш пароля архива | `zip2john a.zip > h` |
| `john`/`hashcat` | подбор пароля | `hashcat -m 17200 h rockyou.txt` |
| `stegseek` | пароль steghide | `stegseek c.jpg rockyou.txt` |
| `exiftool` | источник пароля | `exiftool c.jpg` |
| `zsteg`/`binwalk` | извлечение слоя | `zsteg c.png` |

## Разобранные примеры

**1. Salted__.** PNG → zsteg → base64 → `U2FsdGVkX1...` → decode → `Salted__` → openssl с паролем из `exiftool` → флаг.

**2. Архив.** WAV → LSB → ZIP → `zip2john`+rockyou → `unzip -P` → внутри `flag.txt`.

**3. Метаданные-пароль.** Извлекли `.enc`, пароля нет; `strings` контейнера даёт «hint: password is the model name» → используем.

## Частые ошибки и отладка

- **Расшифровывать до извлечения** — сначала стего, потом крипто.
- **Не распознать формат** — `Salted__`/`PK`/PGP определяют инструмент.
- **Путать base64 и шифр** — base64 не защищает.
- **Игнорировать метаданные** как источник пароля.
- **Отладка:** если openssl даёт «bad decrypt» — неверный пароль/алгоритм; переберите `-aes-128-cbc`/`-aes-256-cbc`/`-des3`; проверьте, нет ли соли в файле.

## Что делать дальше / дерево решений

1. `xxd`/`file` → распознайте формат шифротекста.
2. `Salted__` → openssl с паролем из подсказки/метаданных.
3. `PK`/`7z`/`Rar` → архив → `*2john` + hashcat.
4. PGP → `gpg -d`.
5. Нет пароля → ищите в метаданных, других слоях, условии задачи.

## Квиз

```quiz
- question: "Что скрывает стеганография, а что — шифрование?"
  options:
    - "Стего — факт сообщения; шифр — содержимое"
    - "Наоборот"
    - "Оба — только содержимое"
    - "Оба — только факт"
  answer: 0
  explanation: "Стего прячет наличие, шифрование — смысл."
- question: "Какой признак указывает на OpenSSL-шифротекст?"
  options:
    - "Заголовок Salted__"
    - "Сигнатура PK"
    - "%%EOF"
    - "ACGT"
  answer: 0
  explanation: "Salted__ — маркер формата openssl enc."
- question: "В каком порядке обычно решают многослойную задачу?"
  options:
    - "Сначала стего (извлечь), потом крипто (расшифровать)"
    - "Сначала расшифровать, потом искать"
    - "Порядок не важен"
    - "Сначала сжать"
  answer: 0
  explanation: "Данные сначала извлекают из контейнера, затем расшифровывают."
- question: "Каким инструментом вскрыть пароль ZIP?"
  options:
    - "zip2john + john/hashcat"
    - "zsteg"
    - "mutool"
    - "exiftool"
  answer: 0
  explanation: "zip2john извлекает хэш, john/hashcat подбирает пароль."
- question: "Где часто прячут пароль к контейнеру?"
  options:
    - "В метаданных или другом слое"
    - "В размере файла"
    - "В имени пользователя ОС"
    - "В версии ядра"
  answer: 0
  explanation: "Пароль-подсказка нередко лежит в EXIF/другом канале."
```

## Где пригодится

- **CTF Stego:** многослойные задачи.
- **Forensics:** извлечение зашифрованных контейнеров.
- **Bug bounty:** понимание защиты конфиденциальности.
- **Работа:** оценка каналов утечки данных.
