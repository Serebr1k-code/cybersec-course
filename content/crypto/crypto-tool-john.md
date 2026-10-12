---
id: crypto-tool-john
title: "John the Ripper: полный практический справочник"
category: crypto
parent: crypto-tools
difficulty: easy
order: 2
tags: [crypto, john, jtr, cracking, wordlist, rules, incremental, mask, 2john]
prerequisites: [crypto-hashing, crypto-hashcracking]
useful_for:
  - "CTF Crypto/Forensics: взлом хэшей и контейнеров"
  - "Пентест: автодетект формата и извлечение хэшей"
  - "Форензика: пароли из архивов и документов"
estimated_minutes: 28
summary: "John the Ripper (jumbo) от А до Я: форматы, режимы перебора (--wordlist, --rules, --incremental, --mask, --single), сессии и pot-файлы, конвертеры *2john, сравнение с hashcat и рабочие рецепты."
---

## Вопрос, с которого всё начинается

У нас есть файл `/etc/shadow` с хэшами паролей Linux. hashcat их тоже умеет, но у **John the Ripper** есть два козыря: он **сам определяет формат** хэша и поставляется с конвертерами `*2john` для архивов, PDF, документов Office, KeePass и SSH-ключей. Разберём его на конкретной строке из shadow.

## Наш пример

Достанем строку пароля пользователя `jsmith` и попробуем её восстановить. Возьмём реальный sha512crypt-хэш (его же генерирует `openssl passwd -6`):

```python
import subprocess
def sha512crypt(pw, salt="s3cr3t"):
    return subprocess.run(["openssl","passwd","-6","-salt",salt,pw],
                          capture_output=True, text=True).stdout.strip()
target = sha512crypt("Summer2025!")
print(target[:60] + "...")
```

Реальный вывод и восстановление:

```
строка из /etc/shadow: $6$s3cr3t$6N5eJ3beB5b/P1.8ReRHAOKgPq2ad1TjoqzglcZ3sa3e8hypC9...
( john определит её как sha512crypt / --format=sha512crypt )
взломано кандидатом: Summer2025!
```

Префикс `$6$` — это sha512crypt. John распознаёт формат по префиксу **без** подсказки `--format`.

## Шаг 1: core vs jumbo

- **Core** (`john`) — базовые форматы, минимум конвертеров.
- **Jumbo** — сотни форматов, все `*2john`, `--list=formats`, OpenCL.

```bash
john --list=build-info      # покажет версию и 'Jumbo'
john --list=formats | tr ',' '\n' | head -20
```

Если `--list=formats` работает — у вас jumbo (на Kali/Parrot он по умолчанию). Для нестандартных контейнеров нужна именно jumbo-сборка.

## Шаг 2: базовый синтаксис и форматы

```bash
john [режим] [--format=<fmt>] <файл-хэшей>
john hashes.txt                                  # автоопределение формата
john --wordlist=rockyou.txt hashes.txt
john --format=raw-md5 --wordlist=rockyou.txt hashes.txt
john --show hashes.txt                           # показать взломанное
```

Частые форматы (у jumbo их сотни):

| Формат | Что это | Формат | Что это |
|---|---|---|---|
| `raw-md5` / `raw-sha1` | MD5 / SHA-1 | `sha512crypt` | Linux `$6$` |
| `raw-sha256` / `raw-sha512` | SHA-256 / SHA-512 | `bcrypt` | `$2a$/$2b$/$2y$` |
| `nt` / `lm` | NTLM / LM | `phpass` | WordPress/Joomla/phpBB3 |
| `netntlmv2` | NetNTLMv2 | `krb5tgs` | Kerberoast TGS-REP |
| `mscash2` | DCC2 / MS Cache 2 | `krb5asrep` | AS-REP roast |
| `md5crypt` | Linux `$1$` | `wpapsk` | WPA-PSK |

Полный список именно вашей сборки: `john --list=formats | tr ',' '\n'`. Ошибка `No password hashes loaded` почти всегда означает неверный формат или неразобранный контейнер.

## Шаг 3: режимы перебора

| Режим | Флаг | Что делает |
|---|---|---|
| Wordlist | `--wordlist=FILE` / `-w` | перебор словаря |
| Rules | `--rules[=SECTION]` | мутации слов словаря |
| Single | `--single` | кандидаты из логина/полей записи, **без словаря** |
| Incremental | `--incremental[=MODE]` | brute-force по статистике (markov) |
| Mask | `--mask=...` | brute-force по шаблону |
| Loopback | `--loopback` | использовать уже взломанные как словарь |

```bash
john --wordlist=rockyou.txt --rules=Jumbo hashes.txt
john --single hashes.txt
john --incremental=Digits hashes.txt        # только цифры, быстрее
john --mask='?u?l?l?l?l?d?d' hashes.txt
```

**`--single`** — то, чего нет у hashcat: он строит кандидатов из самого логина и полей записи (`jsmith` → `Jsmith`, `jsmith1`, `jsmith2025`). В нашем примере именно `--single`-подобные кандидаты и сработали.

## Шаг 4: сессии, pot-файл, --show

John пишет результат в `~/.john/john.pot` — аналог pot-файла hashcat.

```bash
john --session=myjob --wordlist=rockyou.txt hashes.txt   # именованная сессия
john --status                                            # прогресс
john --restore=myjob                                     # восстановить после Ctrl-C
john --show hashes.txt                                   # hash:password
john --pot=my.pot --show hashes.txt                      # свой pot
```

`--show` — основной способ забрать результат: пароли лежат в pot-файле, а не только в выводе на экран.

## Шаг 5: конвертеры *2john

John не ломает контейнеры напрямую — сначала извлекают хэш конвертером:

| Конвертер | Источник |
|---|---|
| `unshadow` | `/etc/passwd` + `/etc/shadow` |
| `zip2john` / `rar2john` / `7z2john` | архивы |
| `pdf2john` / `office2john` | PDF, docx/xlsx/pptx |
| `ssh2john` / `gpg2john` / `putty2john` | ключи |
| `keepass2john` / `bitlocker2john` | .kdbx, BitLocker |

```bash
unshadow /etc/passwd /etc/shadow > u.txt && john --wordlist=rockyou.txt u.txt
zip2john secret.zip > zip.hash && john --wordlist=rockyou.txt zip.hash
ssh2john id_rsa > k.hash && john --wordlist=rockyou.txt k.hash
```

Для контейнеров `--show` показывает **внутренний пароль**, а не содержимое.

## john vs hashcat

| Критерий | john | hashcat |
|---|---|---|
| Скорость на GPU | хорошая (jumbo+OpenCL) | **лучшая** |
| Автодетект формата | **да** | нет (нужен `-m`) |
| Конвертеры `*2john` | **полный набор** | частично |
| Режим `--single` | **есть** | нет прямого аналога |
| Когда выбирать | нестандартный контейнер, автодетект | массовый взлом стандартных хэшей |

Практика: контейнеры и неясные форматы — сначала john (`*2john` + автодетект), затем при необходимости конвертировать в hashcat для скорости.

## Частые ошибки

- **`No password hashes loaded`** — неверный формат или контейнер не разобран (`*2john`).
- **Сломанный хэш** — лишние пробелы, `user:` без `--format`, обрезанные строки.
- **Core вместо jumbo** — нет нужного формата/конвертера.
- **Забыли `--show`** — результат в `john.pot`, а не на экране.
- **Полный brute-force на bcrypt/argon2** — нереально; только словарь и правила.

## Что мы теперь знаем

- John **сам определяет формат** хэша; нужна jumbo-сборка.
- `--single` строит кандидатов из логина без словаря.
- Результат — в `~/.john/john.pot`, забирать `--show`.
- Контейнеры сначала разбирают `*2john`, потом ломают.
- john удобнее для нестандартных форматов, hashcat — для массового GPU-взлома.

## Квиз

Проверь себя.

```quiz
- question: "Чем john-jumbo отличается от core-сборки?"
  options:
    - "Он медленнее"
    - "В нём сотни форматов и конвертеры *2john, OpenCL"
    - "Он не умеет словари"
    - "Он работает только на Windows"
  answer: 1
  explanation: "Jumbo добавляет сотни форматов, все *2john и OpenCL."
- question: "Как извлечь хэш из ZIP-архива для john?"
  options:
    - "unzip -p archive.zip"
    - "zip2john archive.zip > hash"
    - "john --format=zip archive.zip"
    - "hashid archive.zip"
  answer: 1
  explanation: "zip2john конвертирует архив в формат хэша для john."
- question: "Что делает режим --single?"
  options:
    - "Перебирает один пароль"
    - "Строит кандидатов из логина и полей записи, без словаря"
    - "Использует один поток CPU"
    - "Останавливается после первой находки"
  answer: 1
  explanation: "--single генерирует кандидатов из самого логина и полей записи."
- question: "Где john хранит найденные пароли?"
  options:
    - "в stdout"
    - "в ~/.john/john.pot"
    - "в /etc/shadow"
    - "в памяти до перезапуска"
  answer: 1
  explanation: "john.pot — аналог pot-файла hashcat."
- question: "Когда john удобнее hashcat?"
  options:
    - "Для массового взлома NTLM на GPU"
    - "Для нестандартных контейнеров и автоопределения формата"
    - "Когда нужен только benchmark"
    - "Для подбора Wi-Fi на GPU"
  answer: 1
  explanation: "Автодетект формата и полный набор *2john — сильная сторона john."
```

## Куда дальше

Мы разобрали офлайн-взлом хэшей и контейнеров. Дальше — урок **crypto-tool-hydra-medusa-patator**: онлайн-перебор по сети (формы логина, SSH, БД), где нет дампа и где важно не заблокировать аккаунт. А пока главное: **john сам определяет формат и разбирает контейнеры через `*2john` — это делает его первым инструментом для «странных» хэшей.**

## Где пригодится

- **CTF** — контейнеры (zip/rar/pdf/office/ssh) и «странные» хэши, которые hashcat не распознаёт по `-m`.
- **Пентест** — автодетект формата дампа и быстрый первый прогон `--single` + словарь.
- **Форензика** — извлечение паролей из конфигов, GPG/PuTTY-ключей и архивов.
- **Red team** — Kerberoast/AS-REP, shadow, приватные SSH-ключи с парольной фразой.
