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

John the Ripper (JtR) — второй по популярности офлайн-взломщик хэшей. Его сильные стороны: **автоопределение формата**, огромная библиотека конвертеров `*2john` (zip, rar, pdf, ssh-ключи, документы Office, KeePass) и встроенные режимы вроде `--single`, которые не требуют словаря. Здесь — справочник по jumbo-сборке (именно она нужна для нестандартных форматов).

## Версии: core vs jumbo

- **Core** (обычный `john`) — базовые форматы, минимум конвертеров.
- **Jumbo** (`john-the-ripper` / сборка с openwall) — сотни форматов, все `*2john`, `--list=formats`, OpenCL. Для работы нужна именно jumbo.

```bash
john --list=build-info     # покажет версию и 'Jumbo'
john --list=formats | tr ',' '\n' | head -50
```

Если `--list=formats` работает — у вас jumbo. На Kali/Parrot он идёт по умолчанию.

## Базовый синтаксис

```bash
john [режим] [--format=<fmt>] <файл-хэшей>
```

```bash
john hashes.txt                                  # автоопределение формата
john --wordlist=rockyou.txt hashes.txt
john --format=raw-md5 --wordlist=rockyou.txt hashes.txt
john --show hashes.txt                           # показать взломанное
```

John пишет результат в `~/.john/john.pot` — это его аналог pot-файла hashcat.

## Форматы (--format)

```bash
john --list=formats | tr ',' '\n' | grep -i ntlm
john --list=formats | tr ',' '\n' | grep -i -E 'zip|rar|pdf|office|ssh|keepass'
```

Частые форматы (полная таблица — у jumbo их сотни, здесь всё, что реально встречается):

| Формат | Что это | Пример |
|---|---|---|
| `raw-md5` | MD5 | `--format=raw-md5` |
| `raw-md4` | MD4 | `--format=raw-md4` |
| `raw-sha1` | SHA-1 | `--format=raw-sha1` |
| `raw-sha1-linkedin` | SHA-1(LinkedIn) | `--format=raw-sha1-linkedin` |
| `raw-sha224` | SHA-224 | `--format=raw-sha224` |
| `raw-sha256` | SHA-256 | `--format=raw-sha256` |
| `raw-sha384` | SHA-384 | `--format=raw-sha384` |
| `raw-sha512` | SHA-512 | `--format=raw-sha512` |
| `raw-blake2b` | BLAKE2b | `--format=raw-blake2b` |
| `raw-keccak` | Keccak | `--format=raw-keccak` |
| `raw-sha3` | SHA-3 | `--format=raw-sha3` |
| `raw-skein` | Skein | `--format=raw-skein` |
| `raw-whirlpool` | Whirlpool | `--format=raw-whirlpool` |
| `raw-gost` | ГОСТ (GOST R 34.11) | `--format=raw-gost` |
| `nt` | NTLM | `--format=nt` |
| `lm` | LM | `--format=lm` |
| `mscash` | DCC (Domain Cached Credentials) | `--format=mscash` |
| `mscash2` | DCC2 / MS Cache 2 | `--format=mscash2` |
| `netntlm` | NetNTLMv1 | `--format=netntlm` |
| `netntlmv2` | NetNTLMv2 | `--format=netntlmv2` |
| `md5crypt` | Linux `$1$` | `--format=md5crypt` |
| `sha256crypt` | Linux `$5$` | `--format=sha256crypt` |
| `sha512crypt` | Linux `$6$` | `--format=sha512crypt` |
| `bcrypt` | `$2a$/$2b$/$2y$` | `--format=bcrypt` |
| `descrypt` | DES(Unix) | `--format=descrypt` |
| `bsdicrypt` | BSDI DES | `--format=bsdicrypt` |
| `sunmd5` | Solaris MD5 | `--format=sunmd5` |
| `phpass` | phpass (WordPress/Joomla/phpBB3) | `--format=phpass` |
| `drupal7` | Drupal 7 | `--format=drupal7` |
| `joomla` | Joomla | `--format=joomla` |
| `mediawiki` | MediaWiki | `--format=mediawiki` |
| `moodle` | Moodle | `--format=moodle` |
| `vbulletin` | vBulletin | `--format=vbulletin` |
| `mysql` | MySQL 3.x | `--format=mysql` |
| `mysql-sha1` | MySQL 4.1+ | `--format=mysql-sha1` |
| `mssql` | MSSQL 2000 | `--format=mssql` |
| `mssql05` | MSSQL 2005 | `--format=mssql05` |
| `mssql12` | MSSQL 2012+ | `--format=mssql12` |
| `oracle` | Oracle (DES) | `--format=oracle` |
| `oracle11` | Oracle 11+ | `--format=oracle11` |
| `postgres` | PostgreSQL (MD5) | `--format=postgres` |
| `krb5tgs` | Kerberoast TGS-REP | `--format=krb5tgs` |
| `krb5asrep` | AS-REP roast | `--format=krb5asrep` |
| `krb5pa-md5` | Kerberos pre-auth (RC4) | `--format=krb5pa-md5` |
| `krb5pa-sha1` | Kerberos pre-auth (AES) | `--format=krb5pa-sha1` |
| `wpapsk` | WPA-PSK | `--format=wpapsk` |
| `wpapsk-pmk` | WPA PMKID | `--format=wpapsk-pmk` |
| `zip` | ZIP (в т.ч. AES) | `--format=zip` |
| `rar` | RAR3 | `--format=rar` |
| `rar5` | RAR5 | `--format=rar5` |
| `7z` | 7-Zip | `--format=7z` |
| `pdf` | PDF | `--format=pdf` |
| `office` | MS Office (2007–2013) | `--format=office` |
| `oldoffice` | MS Office ≤ 2003 | `--format=oldoffice` |
| `ssh` | Приватный SSH-ключ | `--format=ssh` |
| `gpg` | GPG-ключ | `--format=gpg` |
| `putty` | PuTTY `.ppk` | `--format=putty` |
| `keepass` | KeePass `.kdbx` | `--format=keepass` |
| `bitlocker` | BitLocker | `--format=bitlocker` |
| `keychain` | macOS Keychain | `--format=keychain` |
| `dmg` | Apple DMG | `--format=dmg` |
| `luks` | LUKS | `--format=luks` |
| `truecrypt` | TrueCrypt | `--format=truecrypt` |
| `encfs` | EncFS | `--format=encfs` |
| `sip` | SIP digest (MD5) | `--format=sip` |
| `snmp` | SNMP | `--format=snmp` |
| `cram-md5` | CRAM-MD5 | `--format=cram-md5` |
| `nethash` | Netware NDS | `--format=nethash` |
| `sap` | SAP | `--format=sap` |
| `ldap` | LDAP (SHA-1) | `--format=ldap` |
| `bitcoin` | Bitcoin wallet | `--format=bitcoin` |
| `blockchain` | Blockchain.com wallet | `--format=blockchain` |
| `electrum` | Electrum wallet | `--format=electrum` |
| `ethereum` | Ethereum wallet | `--format=ethereum` |
| `1password` | 1Password | `--format=1password` |
| `lastpass` | LastPass | `--format=lastpass` |
| `androidbackup` | Android Backup | `--format=androidbackup` |
| `ansible` | Ansible Vault | `--format=ansible` |
| `axcrypt` | AxCrypt | `--format=axcrypt` |
| `dynamic_N` | «Dynamic» (авто под формат) | `--format=dynamic_1` |

Полный список именно вашей сборки: `john --list=formats | tr ',' '\n'` (сотни строк) и `john --list=formats --format=descrypt` для деталей по одному формату. Если формат не определяется — задайте явно `--format=`. Ошибка `No password hashes loaded` почти всегда означает неверный формат или формат контейнера.

## Режимы перебора — таблица

| Режим | Флаг | Что делает | Пример |
|---|---|---|---|
| Wordlist | `--wordlist=FILE` / `-w` | перебор словаря | `-w rockyou.txt` |
| Rules | `--rules[=SECTION]` | мутации слов словаря | `--rules=Jumbo` |
| Single | `--single[=SECTION]` | «single crack»: из логина/полей делает кандидатов | `--single` |
| Incremental | `--incremental[=MODE]` | brute-force по статистике (markov) | `--incremental=Digits` |
| Mask | `--mask=...` | brute-force по шаблону | `--mask='?u?l?l?l?d?d'` |
| External | `--external=MODE` | пользовательский C-режим | `--external=Filter_Test` |
| Loopback | `--loopback` | использовать уже взломанные как словарь | `--loopback` |
| Markov | `--markov[=LEVEL]` | статистический генератор | `--markov=200` |
| Wordlist + rules | `-w F --rules` | самый частый стартовый прогон | `-w rockyou.txt --rules` |
| Dupe suppression | `--dupe-suppression` | не повторять кандидатов | `--dupe-suppression` |
| Stdin | `--stdin` | читать кандидатов из stdin | `cat w.txt \| john --stdin h.txt` |
| Pipe | `--pipe` | загрузка кандидатов через пайп (быстро) | `--pipe` |

```bash
# классический старт
john --wordlist=rockyou.txt --rules=Jumbo hashes.txt

# single (без словаря, из логинов)
john --single hashes.txt

# incremental brute-force
john --incremental hashes.txt
john --incremental=Digits hashes.txt        # только цифры, быстрее

# маска
john --mask='?u?l?l?l?l?d?d' hashes.txt
john --mask='?d?d?d?d' --format=raw-md5 hashes.txt

# loopback: словарь из уже найденных паролей
john --loopback hashes.txt
```

## Полная таблица флагов john

| Флаг | Что делает | Пример |
|---|---|---|
| `--format=NAME` | Задать формат хэша вручную | `--format=nt` |
| `--list=WHAT` | Список: `formats`, `rules`, `incremental`, `external`, `build-info`, `hidden-options` | `john --list=formats` |
| `--wordlist=FILE` / `-w` | Файл-словарь | `-w rockyou.txt` |
| `--stdin` | Читать кандидатов из stdin | `cat w.txt \| john --stdin h.txt` |
| `--rules[=SECTION]` | Правила (секция или все) | `--rules=All` |
| `--single[=SECTION]` | Режим single | `--single` |
| `--incremental[=MODE]` | Инкрементальный перебор | `--incremental=Alnum` |
| `--mask=MASK` | Маска | `--mask='?d?d?d?d'` |
| `--external=MODE` | Внешний C-режим | `--external=Filter_Test` |
| `--loopback` | Взломанные → словарь | `--loopback` |
| `--markov[=LEVEL]` | Уровень markov | `--markov=100` |
| `--dupe-suppression` | Подавлять дубликаты | `--dupe-suppression` |
| `--min-length=N` / `--max-length=N` | Границы длины | `--min-length=4 --max-length=8` |
| `--min-candidates=N` | Мин. число кандидатов на соль | `--min-candidates=100` |
| `--session=NAME` | Именованная сессия | `--session=job1` |
| `--restore[=NAME]` | Восстановить сессию | `--restore=job1` |
| `--status[=NAME]` | Прогресс сессии | `--status=job1` |
| `--pot=FILE` | Свой pot-файл | `--pot=my.pot` |
| `--show` | Показать взломанное | `--show` |
| `--config=FILE` | Доп. конфиг | `--config=john.conf.local` |
| `--fork=N` | N параллельных процессов | `--fork=4` |
| `--node=M/N` | Часть работы для распределения | `--node=1/4` |
| `--skip` / `--limit` | Пропустить / ограничить кандидатов | `--skip=1000` |
| `--encoding=NAME` | Кодировка ввода | `--encoding=utf-8` |
| `--input-encoding` / `--target-encoding` | Кодировки вход/цель | `--input-encoding=cp1251` |
| `--field-separator-char=C` | Разделитель полей | `--field-separator-char=:` |
| `--user=NAME` | Обрабатывать только этого пользователя | `--user=root` |
| `--shells=LIST` / `--groups=LIST` | Фильтр по shell/группе | `--shells=/bin/bash` |
| `--salt=STR` | Задать соль | `--salt=abcd` |
| `--save-memory=N` | Экономия памяти (1-3) | `--save-memory=2` |
| `--nolog` / `--no-log` | Не писать лог | `--nolog` |
| `-v` / `--verbosity=N` | Подробность | `--verbosity=5` |
| `-q` / `--quiet` | Тихий режим | `--quiet` |
| `--progress-every=N` | Прогресс каждые N сек | `--progress-every=10` |
| `--max-run-time=N` | Лимит времени (сек) | `--max-run-time=600` |
| `--test[=N]` | Self-test | `--test=0` |
| `--test-full[=N]` | Полный self-test | `--test-full=1` |
| `--make-charset=FILE` | Сгенерировать charset из словаря | `--make-charset=my.chr` |
| `--regex=REGEX` | Фильтр кандидатов регуляркой | `--regex='^[a-z]{6}$'` |
| `--rules-stack=SECTION` | Наложить правила поверх режима | `--rules-stack=Jumbo` |
| `--regen-lost-salts=N` | Восстанавливать неизвестные соли | `--regen-lost-salts=10` |
| `--list=hidden-options` | Показать скрытые опции сборки | `john --list=hidden-options` |

Проверить доступные опции своей сборки: `john --list=hidden-options | head -80`. Часть флагов (например `--regen-lost-salts`, `--regex`) есть только в jumbo.

## Сессии, статус и восстановление

```bash
john --session=myjob --wordlist=rockyou.txt hashes.txt   # именованная сессия
john --status                                             # прогресс текущей
john --restore=myjob                                      # восстановить
```

Сессии позволяют прервать длинный прогон (`Ctrl-C`) и продолжить позже. `--status` показывает скорость, остаток, время до конца.

## Pot-файл, --show и --pot

```bash
john --show hashes.txt                  # взломанное в формате hash:password
john --show --format=nt hashes.txt
john --pot=my.pot --show hashes.txt     # свой pot-файл
john --wordlist=rockyou.txt --pot=my.pot hashes.txt
```

`--show` — основной способ забрать результат: пароли лежат в `john.pot`, а не только в выводе.

## Конвертеры *2john

John не ломает контейнеры напрямую — сначала извлекают хэш конвертером:

| Конвертер | Источник |
|---|---|
| `unshadow` | `/etc/passwd` + `/etc/shadow` |
| `zip2john` | ZIP-архив |
| `rar2john` | RAR-архив |
| `7z2john` | 7-Zip |
| `pdf2john` | PDF |
| `office2john` | docx/xlsx/pptx |
| `ssh2john` | приватный SSH-ключ |
| `keepass2john` | .kdbx |
| `bitlocker2john` | BitLocker-том |
| `gpg2john` | GPG-ключ |
| `putty2john` | PuTTY `.ppk` |
| `pcap2john` | сетевые дампы с хэшами |

```bash
# Linux
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john --wordlist=rockyou.txt unshadowed.txt

# ZIP
zip2john secret.zip > zip.hash
john --wordlist=rockyou.txt zip.hash

# SSH-ключ с парольной фразой
ssh2john id_rsa > id_rsa.hash
john --wordlist=rockyou.txt id_rsa.hash

# Office
office2john report.docx > office.hash
john --wordlist=rockyou.txt office.hash

# KeePass
keepass2john db.kdbx > kp.hash
john --wordlist=rockyou.txt kp.hash
```

Результат `--show` для контейнеров часто нужно трактовать: он показывает внутренний пароль, а не содержимое.

## Правила john (--rules)

John использует свою библиотеку правил (совместимую с hashcat лишь частично):

```bash
john --list=rules | head                 # список секций правил
john -w words.txt --rules hashes.txt                 # секция по умолчанию
john -w words.txt --rules=Jumbo hashes.txt
john -w words.txt --rules=All hashes.txt             # все секции
john -w words.txt --rules=Single-Extra hashes.txt
```

Синтаксис правил john: `l` (lower), `u` (upper), `c` (capitalize), `$X` (append), `^X` (prepend), `sXY` (substitute), `d` (duplicate), `r` (reverse), `f` (reflect). Своё правило задаётся через `--rules=: ` или файл:

```bash
printf '[List.Rules:MyRule]\nc$1$2$3\n' > john.conf.local
john -w words.txt --rules=MyRule --config=john.conf.local hashes.txt
```

## Маски и свои charsets

```bash
john --mask='?u?l?l?l?d?d' hashes.txt
john --1='?l?d' --mask='?1?1?1?1?1?1?1?1' hashes.txt   # свой charset
john --min-length=4 --max-length=8 --mask='?a' hashes.txt
```

Символы масок совпадают с hashcat: `?l ?u ?d ?s ?a`, плюс `?w` (вся клавиатура). Отличие: john требует задать формат или корректно его определить, иначе `--mask` не поймёт, что считать.

## john vs hashcat — что выбрать

| Критерий | john | hashcat |
|---|---|---|
| Скорость на GPU | хорошая (jumbo+OpenCL) | лучшая |
| Автодетект формата | **да** | нет (нужен `-m`) |
| Конвертеры `*2john` | **да, полный набор** | частично (через hashcat-utils/john) |
| Режим `--single` | **есть** | нет прямого аналога |
| Правила | свои секции | свои `.rule`-файлы |
| Когда выбирать | нестандартный контейнер, автодетект, `--single` | массовый взлом стандартных хэшей |

Практика: контейнеры и неясные форматы — сначала john (`*2john` + автодетект), затем при необходимости конвертировать в hashcat для скорости.

## Практические рецепты

```bash
# 1. shadow с логинами
unshadow passwd shadow > u.txt && john --wordlist=rockyou.txt u.txt

# 2. NTLM-дамп (user:rid:lm:nt)
john --format=nt --wordlist=rockyou.txt ntlm.txt
john --format=nt --show ntlm.txt

# 3. Kerberoast
john --format=krb5tgs --wordlist=rockyou.txt tgs.txt

# 4. AS-REP
john --format=krb5asrep --wordlist=rockyou.txt asrep.txt

# 5. ZIP AES
zip2john a.zip > a.hash && john --wordlist=rockyou.txt a.hash

# 6. PDF
pdf2john a.pdf > a.hash && john --wordlist=rockyou.txt a.hash

# 7. SSH-ключ
ssh2john id_rsa > k.hash && john --wordlist=rockyou.txt k.hash

# 8. Только цифры (PIN), быстро
john --incremental=Digits --format=raw-md5 h.txt

# 9. Маска Name+2 цифры
john --mask='?u?l?l?l?l?d?d' --format=raw-md5 h.txt

# 10. Все секции правил по словарю
john -w rockyou.txt --rules=All h.txt
```

## Частые ошибки

- **`No password hashes loaded`.** Неверный формат или контейнер не разобран — проверьте `--format` и что запустили `*2john`.
- **Сломанный хэш.** Лишние пробелы, `user:` без `--format`, обрезанные строки.
- **Core вместо jumbo.** Нет нужного формата/конвертера — ставьте jumbo-сборку.
- **Забыли `--show`.** John хранит результат в `john.pot`, экран не всё показывает.
- **Полный brute-force на медленном формате.** bcrypt/argon2 — только словарь и правила.
- **Один прогон `--incremental` по всему алфавиту.** Долго; комбинируйте `--single`, словарь+правила, затем `--incremental` с ограничением `--min-length/--max-length`.

## Квиз

```quiz
- question: "Чем john-jumbo отличается от core-сборки?"
  options:
    - "Он медленнее"
    - "В нём сотни форматов и конвертеры *2john, OpenCL"
    - "Он не умеет словари"
    - "Он работает только на Windows"
  answer: 1
- question: "Как извлечь хэш из ZIP-архива для john?"
  options:
    - "unzip -p archive.zip"
    - "zip2john archive.zip > hash"
    - "john --format=zip archive.zip"
    - "hashid archive.zip"
  answer: 1
- question: "Что делает режим --single?"
  options:
    - "Перебирает один пароль"
    - "Строит кандидатов из логина и полей записи, без словаря"
    - "Использует один поток CPU"
    - "Останавливается после первой находки"
  answer: 1
- question: "Где john хранит найденные пароли?"
  options:
    - "в stdout"
    - "в ~/.john/john.pot"
    - "в /etc/shadow"
    - "в памяти, до перезапуска"
  answer: 1
- question: "Когда john удобнее hashcat?"
  options:
    - "Для массового взлома NTLM на GPU"
    - "Для нестандартных контейнеров и автоопределения формата"
    - "Когда нужен только benchmark"
    - "Для подбора Wi-Fi на GPU"
  answer: 1
```

## Где пригодится

- **CTF** — контейнеры (zip/rar/pdf/office/ssh) и «странные» хэши, которые hashcat не распознаёт по `-m`.
- **Пентест** — автодетект формата дампа и быстрый первый прогон `--single` + словарь.
- **Форензика** — извлечение паролей из конфигов, GPG/PuTTY-ключей и архивов.
- **Red team** — Kerberoast/AS-REP, shadow, приватные SSH-ключи с парольной фразой.
- **Работа/SOC** — оценка того, насколько быстро ломается пароль сотрудника по словарю и правилам.
