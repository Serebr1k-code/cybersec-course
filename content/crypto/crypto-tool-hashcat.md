---
id: crypto-tool-hashcat
title: "hashcat: полный практический справочник"
category: crypto
parent: crypto-tools
difficulty: easy
order: 1
tags: [crypto, hashcat, cracking, gpu, rules, mask, wordlist, mode, attack]
prerequisites: [crypto-hashing, crypto-hashcracking]
useful_for:
  - "CTF Crypto/Forensics: взлом хэшей и архивов"
  - "Пентест: офлайн-взлом дампов хэшей"
  - "Red team: Kerberoast, AS-REP, NetNTLM"
estimated_minutes: 30
summary: "hashcat от А до Я: все режимы хэшей (-m), режимы атак (-a), словари, правила, маски, hashcat-utils, свои правила, GPU/CPU и распределённый перебор. Таблицы флагов и рабочие рецепты."
---

hashcat — самый быстрый в мире офлайн-взломщик хэшей. Он берёт файл с хэшами и список кандидатов (словарь, маску или их комбинацию), считает хэш каждого кандидата на GPU и сравнивает с целью. Этот урок — справочник: не теория, а таблицы флагов, режимов и готовые команды под конкретные типы хэшей.

## Установка и проверка железа

```bash
# Debian/Ubuntu
sudo apt install hashcat
# или собрать/скачать свежую сборку с hashcat.net (важно для новых режимов)

hashcat --version
hashcat -I                # показать CPU/GPU-устройства и драйверы
hashcat -b                # benchmark всех устройств (посмотреть скорость)
hashcat -b -m 1000        # benchmark только NTLM
```

`-I` (`--backend-info`) показывает OpenCL/CUDA-устройства и их ID — это нужно для `-d`. `-b` без `-m` прогоняет бенчмарк по всем популярным режимам: полезно понять, потянет ли ваша карта bcrypt.

## Как устроена командная строка

Общий вид:

```bash
hashcat -m <режим-хэша> -a <режим-атаки> <файл-хэшей> [словарь|маска] [флаги]
```

Порядок аргументов важен: сначала `-m`, потом `-a`, затем хэш-файл, затем источник кандидатов. Результат пишется в pot-файл, а не только на экран.

```bash
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt          # NTLM словарём
hashcat -m 0 -a 3 hashes.txt ?d?d?d?d?d?d?d?d      # MD5 по маске (8 цифр)
hashcat -m 0 hashes.txt --show                     # показать уже взломанное
```

## Режимы хэшей (-m) — таблица

| `-m` | Хэш / формат | Типичный источник |
|---|---|---|
| 0 | MD5 | веб-БД, старые CMS |
| 10 | md5($pass.$salt) | кастомные приложения |
| 20 | md5($salt.$pass) | кастомные приложения |
| 30 | md5(unicode($pass).$salt) | кастомные (UTF-16LE) |
| 40 | md5($salt.unicode($pass)) | кастомные (UTF-16LE) |
| 50 | HMAC-MD5 (key = $pass) | токены/API |
| 60 | HMAC-MD5 (key = $salt) | токены/API |
| 100 | SHA-1 | git-хэши, старые БД |
| 110 | sha1($pass.$salt) | кастомные |
| 120 | sha1($salt.$pass) | кастомные |
| 130 | sha1(unicode($pass).$salt) | кастомные (UTF-16LE) |
| 140 | sha1($salt.unicode($pass)) | кастомные (UTF-16LE) |
| 150 | HMAC-SHA1 (key = $pass) | токены/API |
| 160 | HMAC-SHA1 (key = $salt) | токены/API |
| 200 | MySQL323 | старые MySQL |
| 300 | MySQL4.1/MySQL5 | MySQL |
| 400 | phpass (MD5(WordPress)/Joomla/phpBB3) | WordPress, PHP |
| 500 | md5crypt (`$1$`) | Linux shadow |
| 501 | md5crypt, MD5(Unix), Cisco-IOS `$1$` | Cisco/Unix |
| 600 | BLAKE2b-512 | современные KDF |
| 900 | MD4 | NTLM-производные |
| 1000 | NTLM | SAM, secretsdump |
| 1100 | Domain Cached Credentials (DCC), MS Cache | старый AD-кэш |
| 1300 | SHA-1 (DCC2, MS Cache 2) | AD-кэш домена |
| 1400 | SHA-256 | современные БД |
| 1410 | sha256($pass.$salt) | кастомные |
| 1420 | sha256($salt.$pass) | кастомные |
| 1430 | sha256(unicode($pass).$salt) | кастомные (UTF-16LE) |
| 1440 | sha256($salt.unicode($pass)) | кастомные (UTF-16LE) |
| 1450 | HMAC-SHA256 (key = $pass) | JWT/токены |
| 1460 | HMAC-SHA256 (key = $salt) | JWT/токены |
| 1500 | DES(Unix) | очень старые shadow |
| 1600 | Apache `$apr1$` MD5 | Apache `.htpasswd` |
| 1700 | SHA-512 | современные БД |
| 1710 | sha512($pass.$salt) | кастомные |
| 1720 | sha512($salt.$pass) | кастомные |
| 1730 | SHA-512(unicode($pass).$salt) | кастомные (UTF-16LE) |
| 1740 | SHA-512(unicode($salt.$pass)) | кастомные (UTF-16LE) |
| 1750 | HMAC-SHA512 (key = $pass) | токены |
| 1760 | HMAC-SHA512 (key = $salt) | токены |
| 1800 | sha512crypt (`$6$`) | Linux shadow |
| 2100 | Domain Cached Credentials 2 (DCC2), MS Cache 2 | AD-кэш |
| 2400 | Cisco-PIX MD5 | Cisco |
| 2410 | Cisco-ASA MD5 | Cisco |
| 2500 | WPA-EAPOL-PBKDF2 | Wi-Fi handshake (старый) |
| 2600 | md5(md5($pass)) | кастомные |
| 3000 | LM | старые Windows-дампы |
| 3100 | Oracle H: Type (Oracle 7+) | Oracle |
| 3200 | bcrypt (`$2a$/$2b$/$2y$`) | веб-фреймворки, PHP |
| 3300 | MD5(Sun) | Solaris |
| 3500 | md5(md5(md5($pass))) | кастомные |
| 3700 | md5(md5($salt).$pass) | кастомные |
| 4000 | phpBB3 | phpBB |
| 5000 | SHA-3(Keccak) | современные KDF |
| 5500 | NetNTLMv1 | перехват по сети |
| 5600 | NetNTLMv2 | Responder/ntlmrelayx |
| 5700 | NTLMv1 (ESS) | AD |
| 6300 | AIX `{smd5}` | AIX |
| 6400 | AIX `{ssha256}` | AIX |
| 6500 | AIX `{ssha512}` | AIX |
| 6700 | AIX `{ssha1}` | AIX |
| 6800 | LastPass + LastPass sniffed | LastPass |
| 7300 | IPMI2 RAKP HMAC-SHA1 | серверы/IPMI |
| 7400 | sha256crypt (`$5$`) | Linux shadow |
| 7500 | Kerberos 5 AS-REQ Pre-Auth etype 23 | AD |
| 7900 | Drupal7 | Drupal |
| 8900 | scrypt | современные KDF |
| 9000 | Password Safe v3 | Password Safe |
| 9100 | DPAPI masterkey file v1 | Windows |
| 9200 | DPAPI masterkey file v2 | Windows |
| 9400 | MS Office 2007 | docx/xlsx |
| 9500 | MS Office 2010 | docx/xlsx |
| 9600 | MS Office 2013 | docx/xlsx |
| 9700 | MS Office <= 2003 (MD5+RC4) | .doc/.xls |
| 9800 | MS Office <= 2003 (SHA1+RC4) | .doc/.xls |
| 9900 | Radmin2 | Radmin |
| 10400 | PDF 1.1–1.3 (Acrobat 2–4) | PDF |
| 10500 | PDF 1.4–1.6 (Acrobat 5–8) | PDF |
| 10600 | PDF 1.7 Level 3 (Acrobat 9) | PDF |
| 10700 | PDF 1.7 Level 8 (Acrobat 10–11) | PDF |
| 10900 | PBKDF2-HMAC-SHA256 | современные KDF |
| 11000 | PBKDF2-HMAC-SHA1 | современные KDF |
| 11100 | PostgreSQL CRAM (MD5) | PostgreSQL |
| 11200 | MySQL CRAM (SHA1) | MySQL |
| 11300 | Bitcoin/Litecoin wallet.dat | крипто-кошельки |
| 11400 | SIP digest authentication (MD5) | VoIP/SIP |
| 11600 | 7-Zip | архивы |
| 11700 | GOST R 34.11-2012 (Streebog) 256 | ГОСТ |
| 11800 | GOST R 34.11-2012 (Streebog) 512 | ГОСТ |
| 11900 | PBKDF2-HMAC-MD5 | современные KDF |
| 12000 | PBKDF2-HMAC-SHA512 | современные KDF |
| 12100 | PBKDF2-HMAC-SHA512 (generic) | современные KDF |
| 12500 | RAR3-hp | старые RAR |
| 12600 | ColdFusion 10+ (PBKDF2-HMAC-SHA256) | ColdFusion |
| 12700 | Blockchain, My Wallet | кошельки |
| 12800 | MS-AzureSync PBKDF2-HMAC-SHA256 | Azure AD Connect |
| 12900 | Android FDE (Samsung DEK) | Android |
| 13000 | RAR5 | архивы |
| 13100 | Kerberos 5 TGS-REP etype 23 (Kerberoast) | AD |
| 13200 | AxCrypt 1 | AxCrypt |
| 13400 | KeePass 1 (AES/Twofish) / KeePass 2 (AES) | .kdbx |
| 13500 | KeePass 1 (AES/Twofish) / KeePass 2 (AES) | .kdbx |
| 13600 | WinZip | zip AES |
| 13711 | VeraCrypt RIPEMD160 + XTS | VeraCrypt |
| 13721 | VeraCrypt SHA512 + XTS | VeraCrypt |
| 13731 | VeraCrypt Whirlpool + XTS | VeraCrypt |
| 13741 | VeraCrypt RIPEMD160 + XTS + boot | VeraCrypt |
| 13800 | Windows Phone 8+ PIN/password | Windows Phone |
| 13900 | OpenCart | OpenCart |
| 14000 | DES (PT = $salt, key = $pass) | кастомные |
| 14100 | 3DES (PT = $salt, key = $pass) | кастомные |
| 14400 | sha1(CX) | кастомные |
| 14600 | LUKS | LUKS |
| 14700 | iTunes Backup < 10.0 | iTunes |
| 14800 | iTunes Backup >= 10.0 | iTunes |
| 15000 | descrypt, DES(Unix), Traditional DES | Unix |
| 15100 | Skein-256 | современные KDF |
| 15200 | Skein-512 | современные KDF |
| 15300 | Skein-256(128) | современные KDF |
| 15400 | Skein-512(128) | современные KDF |
| 15600 | Ethereum Wallet, PBKDF2-HMAC-SHA256 | Ethereum |
| 15700 | Ethereum Wallet, SCRYPT | Ethereum |
| 16300 | Ethereum Wallet, MultiETH | Ethereum |
| 16400 | CRAM-MD5 | IMAP/SMTP |
| 16500 | JWT (HS256/HS384/HS512) | токены |
| 16600 | Electrum Wallet (Salt-Type 1-3) | Electrum |
| 16700 | FileVault 2 | macOS |
| 16800 | WPA-PMKID-PBKDF2 | Wi-Fi PMKID |
| 16900 | Ansible Vault | Ansible |
| 17010 | sha512(Unix) | Unix |
| 17020 | sha256(Unix) | Unix |
| 17030 | sha1(Unix) | Unix |
| 17200 | PKZIP (Compressed) | zip |
| 17210 | PKZIP (Uncompressed) | zip |
| 17220 | PKZIP (Compressed Multi-File) | zip |
| 17225 | PKZIP (Mixed Multi-File) | zip |
| 17230 | PKZIP (Compressed Multi-File Checksum-Only) | zip |
| 17300 | SHA3-224 | современные KDF |
| 17400 | SHA3-256 | современные KDF |
| 17500 | SHA3-384 | современные KDF |
| 17600 | SHA3-512 | современные KDF |
| 17700 | Keccak-224 | современные KDF |
| 17800 | Keccak-256 | современные KDF |
| 17900 | Keccak-384 | современные KDF |
| 18000 | Keccak-512 | современные KDF |
| 18200 | Kerberos 5 AS-REP etype 23 (AS-REP roast) | AD |
| 18300 | Apple FileVault 2 | macOS |
| 18400 | OpenSSL AES 256-bit (gzip) | OpenSSL |
| 19600 | Kerberos 5 TGS-REP etype 17 (AES128) | AD |
| 19700 | Kerberos 5 TGS-REP etype 18 (AES256) | AD |
| 19800 | Kerberos 5 Pre-Auth etype 17 (AES128) | AD |
| 19900 | Kerberos 5 Pre-Auth etype 18 (AES256) | AD |
| 20000 | BitLocker | BitLocker |
| 20200 | Python passlib pbkdf2-sha512 | Python |
| 20300 | Python passlib pbkdf2-sha256 | Python |
| 20400 | Python passlib pbkdf2-sha1 | Python |
| 20500 | PKZIP Master Key | zip |
| 20710 | sha256(sha256($pass).$salt) | кастомные |
| 20711 | AuthME sha256 | Minecraft AuthME |
| 22000 | WPA-PBKDF2-PMKID+EAPOL | Wi-Fi handshake |
| 22100 | BitLocker | BitLocker |
| 22400 | AES Crypt (SHA256) | AES Crypt |
| 22500 | MultiBit Classic .key (MD5) | Bitcoin |
| 22600 | Telegram Desktop App Passcode (SHA256) | Telegram |
| 22700 | MultiBit HD (scrypt) | Bitcoin |
| 23000 | SecureZIP AES-128 | SecureZIP |
| 23100 | SecureZIP AES-192 | SecureZIP |
| 23200 | SecureZIP AES-256 | SecureZIP |
| 23700 | RAR3-p (Uncompressed) | RAR |
| 23800 | RAR3-p (Compressed) | RAR |
| 24100 | Infinispan (MD5) | Java/Infinispan |
| 24200 | Infinispan (SHA1) | Java/Infinispan |
| 24300 | Infinispan (SHA256) | Java/Infinispan |
| 24410 | PKCS#8 Private Keys (PBKDF2-HMAC-SHA1) | PEM-ключи |
| 24420 | PKCS#8 Private Keys (PBKDF2-HMAC-SHA256) | PEM-ключи |
| 24500 | Telegram Desktop App Passcode (PBKDF2-HMAC-SHA1) | Telegram |
| 24600 | SQLCipher | SQLCipher |
| 24900 | Django (PBKDF2-SHA256) | Django |
| 25100 | SNMPv3 HMAC-MD5-96/HMAC-SHA1-96 | SNMP |
| 25300 | MS Office 2016 - SheetProtection | Office |
| 25600 | bcrypt(md5($pass)) | кастомные |
| 25700 | bcrypt(sha256($pass)) | кастомные |
| 25800 | bcrypt(sha512($pass)) | кастомные |
| 26000 | Mozilla key3.db | Firefox |
| 26100 | Mozilla key4.db | Firefox |
| 26300 | FortiGate256 | FortiGate |
| 26600 | MetaMask Wallet | MetaMask |
| 26700 | SNMPv3 HMAC-SHA256-128 | SNMP |
| 26800 | SNMPv3 HMAC-SHA384-192 | SNMP |
| 26900 | SNMPv3 HMAC-SHA512-256 | SNMP |
| 27000 | NetNTLMv1 / NetNTLMv2 | AD (совмещённый) |
| 27100 | Microsoft Azure AD Connect (PBKDF2-HMAC-SHA256) | Azure AD Connect |
| 27200 | Python Django (scrypt) | Django |
| 27400 | VMX (PBKDF2-HMAC-SHA1) | VMware |
| 27500 | VirtualBox (PBKDF2-HMAC-SHA256) | VirtualBox |
| 27600 | VirtualBox (PBKDF2-HMAC-SHA512) | VirtualBox |
| 27700 | MultiBit Classic .wallet (scrypt) | Bitcoin |
| 27800 | Telegram Desktop App Passcode (PBKDF2-HMAC-SHA512) | Telegram |
| 27900 | RAR5 (XZ) | RAR |
| 28000 | CRC32 | CRC |
| 28100 | Windows Hello PIN/Password | Windows |
| 28300 | Ethereum Pre-Sale Wallet | Ethereum |
| 28400 | bcrypt-SHA256 | кастомные |
| 28500 | Bitcoin Core (PBKDF2-HMAC-SHA512) | Bitcoin |
| 28600 | PostgreSQL SCRAM-SHA-256 | PostgreSQL |
| 28900 | OutLook PST | Outlook |
| 29100 | Flask Session Cookie Signer | Flask |
| 29200 | Radmin3 | Radmin |
| 29300 | macOS Keychain | macOS |
| 29400 | WPA-PMKID-PBKDF2 (with PMKID) | Wi-Fi |
| 29600 | Terra Station Wallet (AES256-CBC) | Terra |
| 29700 | KeePass 1 (AES/Twofish) and KeePass 2 (AES) | KeePass |
| 29800 | Bisq | Bisq |
| 29900 | 7-Zip (uncompressed) | архивы |
| 30000 | Python Werkzeug | Python |
| 30100 | Bitcoin Raw Private Key | Bitcoin |
| 30200 | Python hashlib (Generic) | Python |

Полный список: `hashcat --example-hashes` (показывает и режим, и пример хэша) и `hashcat -h | grep -i <слово>`.

```bash
hashcat --example-hashes | grep -i -A2 'kerberos'
hashcat -h | grep -i bcrypt        # найти режим по названию
```

## Режимы атак (-a) — таблица

| `-a` | Атака | Что подаём | Когда |
|---|---|---|---|
| 0 | Straight (словарь) | файл-словарь | первый шаг почти всегда |
| 1 | Combination | два словаря | пароль из двух слов |
| 3 | Brute-force / Mask | маску (`?d?d...`) | известен шаблон |
| 6 | Hybrid Wordlist+Mask | словарь + маска | слово + цифры в конце |
| 7 | Hybrid Mask+Wordlist | маска + словарь | цифры/префикс + слово |
| 8 | Prince | словарь(и) | умный комбинатор сжатием |
| 9 | Association | ассоциативный словарь | пары кандидатов |

> **Устаревшие режимы.** В старых версиях были `-a 2` (Toggle-Case), `-a 4` (Permutation) и `-a 5` (Table-Lookup) — они **удалены** и в современных hashcat отсутствуют. Не рассчитывайте на них: toggle-case делается правилами (`t`), permutation — правилами/`--stdout`, table-lookup — через `combinator.bin` и `-a 1`.

```bash
hashcat -m 0 -a 0 h.txt rockyou.txt
hashcat -m 0 -a 1 h.txt words1.txt words2.txt
hashcat -m 0 -a 3 h.txt ?u?l?l?l?l?d?d
hashcat -m 0 -a 6 h.txt rockyou.txt ?d?d?d?d
hashcat -m 0 -a 7 h.txt ?d?d?d?d rockyou.txt
hashcat -m 0 -a 8 h.txt rockyou.txt
```

## Словари, правила и маски

### Словари

```bash
/usr/share/wordlists/rockyou.txt                 # 14M паролей, стандарт
ls /usr/share/seclists/Passwords/                # SecLists: Leaked-Databases, Common-Credentials
```

Несколько словарей в одной атаке `-a 0` можно подавать через запятую:

```bash
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt,seclists.txt
```

### Правила (`-r`)

Правила мутируют каждое слово словаря: меняют регистр, добавляют цифры/символы, делают leet. Один прогон с правилами заменяет десятки прогонов вручную.

```bash
ls /usr/share/hashcat/rules/                     # best64, dive, rockyou-30000, combinator, d3ad0ne...
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r best64.rule
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r dive.rule
hashcat -m 0 -a 0 h.txt words.txt -r /usr/share/hashcat/rules/rockyou-30000.rule
hashcat -m 0 -a 0 h.txt words.txt -j '$-'        # одна inline-функция на слово (здесь: добавить '-')
hashcat -m 0 -a 0 h.txt words.txt -k '$1'        # добавить '1' в конец (то же, что -j с другим правилом)
```

`-j` — одно правило слева (по слову), `-k` — одно правило справа. Для целых файлов правил — `-r`.

### Маски и charsets

| Символ | Значит |
|---|---|
| `?l` | строчные латинские `a-z` |
| `?u` | заглавные `A-Z` |
| `?d` | цифры `0-9` |
| `?h` | hex-цифры нижнего регистра `0-9a-f` |
| `?H` | hex-цифры верхнего регистра `0-9A-F` |
| `?s` | спецсимволы `!@#$%^&*...` |
| `?a` | всё вместе (`?l?u?d?s`) |
| `?b` | любые байты `0x00-0xff` |
| `?1..?4` | свой charset, заданный флагом `-1..-4` |

```bash
hashcat -m 0 -a 3 h.txt ?d?d?d?d                  # 4 цифры (PIN)
hashcat -m 0 -a 3 h.txt ?u?l?l?l?l?d?d            # Name + 2 цифры
hashcat -m 0 -a 3 h.txt -1 ?l?d ?1?1?1?1?1?1?1?1  # свой charset
hashcat -m 0 -a 3 h.txt --increment --increment-min 4 ?a?a?a?a?a?a?a?a   # от 4 до 8 символов
```

## Полезные флаги — таблица

### Шпаргалка: 12 самых нужных флагов

| Флаг | Что делает | Пример |
|---|---|---|
| `-m` | Тип (режим) хэша | `hashcat -m 1000 ntlm.txt rockyou.txt` |
| `-a` | Режим атаки | `hashcat -m 0 -a 3 h.txt ?d?d?d?d` |
| `-O` | Оптимизированное ядро (быстрее) | `hashcat -m 1000 -a 0 h.txt w.txt -O` |
| `-w 3` | Workload profile | `hashcat ... -w 3` |
| `-r` | Файл правил | `hashcat ... -r best64.rule` |
| `--show` | Показать взломанное из pot-файла | `hashcat -m 1000 h.txt --show` |
| `--username` | В файле `user:hash` | `hashcat -m 1000 --username h.txt w.txt` |
| `-o` | Писать результат в файл | `hashcat ... -o found.txt` |
| `--session` | Именованная сессия | `hashcat ... --session job1` |
| `--restore` | Восстановить сессию | `hashcat --restore --session job1` |
| `--force` | Игнорировать предупреждения | `hashcat ... --force` |
| `-b` | Benchmark | `hashcat -b -m 3200` |

### Полная таблица флагов

| Флаг | Что делает | Пример |
|---|---|---|
| `-m` / `--hash-type` | Режим хэша | `-m 1800` |
| `-a` / `--attack-mode` | Режим атаки | `-a 3` |
| `-O` / `--optimize-kernel` | Оптимизированное ядро (быстрее; длина пароля ≤ 31) | `-O` |
| `-w 1..4` / `--workload-profile` | Профиль нагрузки (1=низкий … 4=высокий) | `-w 3` |
| `-r` / `--rules-file` | Файл правил | `-r best64.rule` |
| `-j` / `--rule-left` | Одно правило слева (по слову) | `-j '$-'` |
| `-k` / `--rule-right` | Одно правило справа | `-k '$1'` |
| `-g N` / `--generate-rules` | Сгенерировать N случайных правил | `-g 100` |
| `--generate-rules-func-min/-max` | Границы числа функций в правиле | `--generate-rules-func-min 1` |
| `-1..-4` / `--custom-charset1..4` | Свои charsets | `-1 ?l?d` |
| `--increment` | Инкремент длины маски | `--increment` |
| `--increment-min N` | Начать с длины N | `--increment --increment-min 4` |
| `--increment-max N` | Ограничить максимальную длину | `--increment-max 10` |
| `-o FILE` / `--outfile` | Писать результаты в файл | `-o found.txt` |
| `--outfile-format N` | Какие поля писать в `-o` (1=hash, 2=plain …) | `--outfile-format 2` |
| `--outfile-check-timer N` | Как часто проверять outfile | `--outfile-check-timer 10` |
| `--show` | Показать взломанное из pot-файла | `--show` |
| `--left` | Показать невзломанные | `--left` |
| `--potfile-path FILE` | Свой pot-файл | `--potfile-path my.pot` |
| `--potfile-disable` | Не использовать pot-файл | `--potfile-disable` |
| `--session NAME` | Именованная сессия | `--session job1` |
| `--restore` | Восстановить сессию | `--restore --session job1` |
| `--restore-disable` | Отключить файлы восстановления | `--restore-disable` |
| `--restore-file-path FILE` | Своё имя restore-файла | `--restore-file-path j.restore` |
| `--runtime N` | Остановиться через N секунд | `--runtime 600` |
| `--force` | Игнорировать предупреждения | `--force` |
| `-b` / `--benchmark` | Benchmark всех устройств | `-b` |
| `-I` / `--backend-info` | Показать CPU/GPU и драйверы | `-I` |
| `-D 1,2,3` / `--opencl-device-types` | Тип backend (1=CPU, 2=CUDA, 3=HIP) | `-D 2` |
| `-d 1,2` / `--backend-devices` | Выбрать устройства по ID | `-d 1,2` |
| `--backend-ignore-cuda` | Отключить CUDA | `--backend-ignore-cuda` |
| `--backend-ignore-opencl` | Отключить OpenCL | `--backend-ignore-opencl` |
| `-n N` / `--kernel-loops` | Число циклов ядра | `-n 128` |
| `-T N` / `--kernel-accel` | Ускорение ядра (threads) | `-T 64` |
| `--backend-vector-width N` | Ширина вектора backend | `--backend-vector-width 4` |
| `--hwmon-disable` | Отключить мониторинг температур | `--hwmon-disable` |
| `--hwmon-temp-abort N` | Прервать при температуре N °C | `--hwmon-temp-abort 90` |
| `--status` | Периодический статус | `--status` |
| `--status-timer N` | Статус каждые N секунд | `--status-timer 30` |
| `--status-json` | Статус в JSON | `--status-json` |
| `--machine-readable` | Машиночитаемый вывод статуса | `--machine-readable` |
| `--username` | В файле есть `user:hash` | `--username` |
| `--separator X` / `-p X` | Разделитель полей (в т.ч. при `-a 1`) | `--separator ':'` |
| `--remove` | Удалять взломанные из исходного файла | `--remove` |
| `--remove-timer N` | Как часто переписывать файл при `--remove` | `--remove-timer 60` |
| `--stdout` | Печатать кандидатов без подсчёта хэшей | `--stdout -r my.rule` |
| `--hex-salt` | Соль задана в hex | `--hex-salt` |
| `--hex-wordlist` | Словарь в hex | `--hex-wordlist` |
| `--hex-charset` | Charsets заданы в hex | `--hex-charset` |
| `--encoding-from X` | Кодировка словаря | `--encoding-from cp1251` |
| `--encoding-to X` | Целевая кодировка | `--encoding-to utf8` |
| `--keyspace` | Показать размер пространства | `--keyspace -a 3 ?a?a?a?a` |
| `-s N` / `--skip` | Пропустить первые N кандидатов | `-s 1000000` |
| `-l N` / `--limit` | Взять только N кандидатов | `-l 1000000` |
| `--loopback` | Добавить взломанные в словарь | `--loopback` |
| `--markov-disable` | Отключить markov-цепь | `--markov-disable` |
| `--markov-classic` | Классический markov | `--markov-classic` |
| `--markov-threshold N` | Порог markov | `--markov-threshold 100` |
| `--example-hashes` | Примеры хэшей и их режимы | `--example-hashes` |
| `--speed-only` | Только скорость, без взлома | `--speed-only` |
| `--quiet` | Не выводить статус | `--quiet` |
| `--logfile-disable` | Не писать лог-файл | `--logfile-disable` |
| `--debug-mode N` | Режим отладки | `--debug-mode 1` |
| `--debug-file FILE` | Файл отладки | `--debug-file dbg.txt` |
| `--version` | Версия hashcat | `--version` |

## hashcat-utils и смежные утилиты

hashcat-utils — набор маленьких программ, которые готовят словари:

| Утилита | Назначение |
|---|---|
| `combinator.bin` | склеивает два словаря в один (word1+word2) |
| `rli.bin` | правило «слева» по словарю |
| `cap2hccapx.bin` | .cap → .hccapx (Wi-Fi, старый формат) |
| `hcxtools` (`hcxpcapngtool`) | pcapng → `.hc22000` (Wi-Fi, новый) |
| `gate.bin` | генерирует словарь по шаблону |
| `splitlen.bin` | разбивает словарь по длине |

```bash
combinator.bin words1.txt words2.txt > combined.txt
hashcat -m 0 -a 0 h.txt combined.txt
```

## Как писать свои правила

Правило — строка из функций, применяемых к слову слева направо. Мини-шпаргалка:

| Функция | Действие |
|---|---|
| `l` / `u` | всё в нижний / верхний регистр |
| `c` / `C` | первая заглавная / первая строчная |
| `t` | toggle регистр всего слова |
| `$X` / `^X` | добавить символ X в конец / начало |
| `d` / `f` | дублировать слово / отразить его |
| `sXY` | заменить X на Y |
| `@X` | удалить все X |
| `z1` / `z2` | дублировать первый / последний символ |

```bash
echo 'c $1 $2 $3' > my.rule          # Capitalize + добавить '123'
hashcat -m 0 -a 0 h.txt words.txt -r my.rule
hashcat --stdout words.txt -r my.rule | head   # проверить вывод правил без взлома
```

`--stdout` — лучший способ отладки правил и масок: он печатает кандидатов, не считая хэши.

## Практические рецепты по типам хэшей

```bash
# 1. Linux shadow (sha512crypt), с логинами
hashcat -m 1800 -a 0 shadow.txt rockyou.txt -r best64.rule --username

# 2. Windows NTLM из secretsdump (user:rid:lm:ntlm)
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -O --username

# 3. bcrypt (cost 12) — только словарь, перебор нереален
hashcat -m 3200 -a 0 bcrypt.txt rockyou.txt

# 4. Kerberoast TGS
hashcat -m 13100 -a 0 tgs.txt rockyou.txt -r best64.rule

# 5. AS-REP roast
hashcat -m 18200 -a 0 asrep.txt rockyou.txt

# 6. NetNTLMv2 (из Responder)
hashcat -m 5600 -a 0 ntlmv2.txt rockyou.txt

# 7. ZIP AES
zip2john secret.zip > zip.hash
hashcat -m 13600 -a 0 zip.hash rockyou.txt

# 8. RAR5
rar2john secret.rar > rar.hash
hashcat -m 13000 -a 0 rar.hash rockyou.txt

# 9. JWT HS256
hashcat -m 16500 -a 0 jwt.txt rockyou.txt

# 10. KeePass
keepass2john db.kdbx > kp.hash
hashcat -m 13400 -a 0 kp.hash rockyou.txt

# 11. Wi-Fi handshake
hcxpcapngtool -o hs.hc22000 capture.pcapng
hashcat -m 22000 -a 0 hs.hc22000 rockyou.txt

# 12. Гибрид: слово + 2 цифры (очень часто)
hashcat -m 0 -a 6 h.txt rockyou.txt ?d?d
```

## GPU vs CPU и распределённый перебор

- Проверьте скорость: `hashcat -b -m 1000`. GPU даёт миллиарды/с на MD5/NTLM и тысячи/с на bcrypt.
- На CPU (CTF-контейнер, VM) используйте словари + правила, а не полный brute-force.
- Разделите работу между машинами: `--skip N --limit M` или `--keyspace` + `--skip`/`--limit`.
- Ограничьте время: `--runtime=600` (10 минут) на стратегию, потом меняйте подход.
- Следите за температурой/дросселем: `--hwmon-disable` отключает мониторинг, `--status-timer 30` — статус.

## Частые ошибки

- **Неверный `-m`.** Самая частая причина нуля результатов. Проверяйте `hashid -m` и `--example-hashes`.
- **Лишние символы в хэш-файле.** Уберите `user:` через `--username`, лишние пробелы/переводы строк.
- **`Token length exception`.** Хэш не той длины для режима — перепроверьте тип.
- **`Exhausted`.** Пространство кандидатов кончилось — нужен другой словарь/маска/правила.
- **bcrypt/argon2 полным перебором.** Это нереально; ищите слабый пароль словарём или другой вектор.
- **Правильный пароль не в словаре.** Правила (`best64`, `dive`, `rockyou-30000`) и гибрид `-a 6` закрывают большинство таких случаев.
- **Забыли `--show`.** hashcat пишет в pot-файл; результат смотрите им, а не глазами по экрану.

## Квиз

```quiz
- question: "Каким флагом задаётся тип хэша в hashcat?"
  options:
    - "-a"
    - "-m"
    - "-r"
    - "-w"
  answer: 1
  explanation: "`-m` — режим хэша (тип), `-a` — режим атаки, `-r` — файл правил, `-w` — workload."
- question: "Какой режим атаки используют для шаблона «слово + 4 цифры»?"
  options:
    - "-a 0"
    - "-a 1"
    - "-a 6"
    - "-a 3"
  answer: 2
  explanation: "Гибрид wordlist+mask (-a 6) берёт слово из словаря и добавляет маску цифр."
- question: "Что означает маска ?u?l?l?l?d?"
  options:
    - "четыре цифры"
    - "заглавная, три строчные и цифра"
    - "любые байты"
    - "спецсимвол и три цифры"
  answer: 1
- question: "Зачем нужен флаг --stdout?"
  options:
    - "Печатает кандидатов без подсчёта хэшей — для отладки правил и масок"
    - "Пишет результат в файл"
    - "Показывает скорость GPU"
    - "Восстанавливает сессию"
  answer: 0
- question: "Какой режим hashcat соответствует Kerberoast TGS-REP?"
  options:
    - "1000"
    - "18200"
    - "13100"
    - "5600"
  answer: 2
  explanation: "13100 — Kerberos 5 TGS-REP; 18200 — AS-REP; 5600 — NetNTLMv2."
```

## Где пригодится

- **CTF** — любая задача с хэшем, архивом, PDF, JWT или Wi-Fi handshake закрывается hashcat.
- **Пентест** — взлом дампов SAM/`/etc/shadow`/БД для последующего lateral movement.
- **Red team** — Kerberoast, AS-REP roast, NetNTLMv2 — обязательный этап после сбора хэшей.
- **Форензика** — восстановление паролей из архивов, документов и хранилищ KeePass.
- **Работа/SOC** — оценка стойкости парольной политики: сколько времени реально держится хэш сотрудника.
