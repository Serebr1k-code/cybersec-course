---
id: crypto-hashcracking
title: "Взлом хэшей: hashcat и john в бою"
category: crypto
parent: crypto-hashing
difficulty: easy
order: 1
tags: [crypto, hashcat, john, cracking, wordlist, rules, mask, brute-force, gpu]
prerequisites: [crypto-hashing]
useful_for:
  - "Определять режим hashcat по типу хэша"
  - "Подбирать пароли словарём, правилами и масками"
  - "Взламывать NTLM, bcrypt, SHA-крипт и архивы"
estimated_minutes: 40
summary: "Практический взлом хэшей: как определять режим hashcat (-m) и формат john, стратегии перебора (словарь, правила, маски, гибрид), работа с GPU и словарями, извлечение хэшей из zip/rar/pdf/keepass. Реальные команды и разбор типичных ошибок."
---

## Идентификация хэша: первый шаг

Прежде чем что-то ломать, нужно понять, **что именно** вы ломаете. Признаки:

| Признак | Тип |
|---|---|
| 32 hex-символа | MD5 / NTLM / MD4 |
| 40 hex | SHA-1 |
| 64 hex | SHA-256 |
| 96 hex | SHA-384 |
| 128 hex | SHA-512 |
| `$2a$`, `$2b$`, `$2y$` | bcrypt |
| `$1$`, `$5$`, `$6$` | md5crypt / sha256crypt / sha512crypt |
| `$argon2id$` | Argon2 |
| `$pbkdf2-sha256$` | PBKDF2 |
| `aad3b435b51404eeaad3b435b51404ee:...` | NTLM (LM:NTLM) |
| `$P$` / `$H$` | phpass (WordPress) |

```bash
hashid -m '<hash>'        # подсказывает режимы hashcat
hash-identifier '<hash>'  # альтернатива
john --list=formats | tr ',' '\n' | grep -i <type>
```

Важно: MD5 и NTLM — оба 32 hex; различить помогает контекст (NTLM — из Windows SAM, MD5 — из веба/файлов).

## Режимы hashcat (-m)

Ключевые режимы, которые надо знать наизусть:

| Режим | Тип |
|---|---|
| `0` | MD5 |
| `100` | SHA-1 |
| `1400` | SHA-256 |
| `1700` | SHA-512 |
| `1000` | NTLM |
| `3000` | LM |
| `5500` | NetNTLMv1 |
| `5600` | NetNTLMv2 |
| `13100` | Kerberoast (TGS-REP) |
| `18200` | AS-REP |
| `3200` | bcrypt |
| `1800` | sha512crypt (`$6$`) |
| `500` | md5crypt (`$1$`) |
| `22000` | WPA-PBKDF2-PMKID |
| `11600` | 7-Zip |
| `13600` | WinZip |
| `12500` | RAR3-hp |
| `23700` | RAR5 |
| `10500` | PDF 1.4–1.6 |
| `13400` | KeePass |

## Атаки: словарь, правила, маска, гибрид

1. **Словарь (straight):**
   ```bash
   hashcat -m 1000 hashes.txt rockyou.txt
   ```
2. **Правила (rules):** мутируют каждое слово словаря (регистр, замена `a→@`, добавление цифр):
   ```bash
   hashcat -m 1000 hashes.txt rockyou.txt -r rules/best64.rule
   ```
3. **Маска (mask):** задаём шаблон. `?l` — строчная, `?u` — заглавная, `?d` — цифра, `?s` — спецсимвол, `?a` — всё.
   ```bash
   hashcat -m 1000 hashes.txt -a 3 '?u?l?l?l?d?d'          # Abcd12
   hashcat -m 1000 hashes.txt -a 3 '?d?d?d?d'              # PIN
   ```
4. **Гибрид:** словарь + маска (`-a 6`) или маска + словарь (`-a 7`):
   ```bash
   hashcat -m 1000 hashes.txt -a 6 rockyou.txt '?d?d?d?d'  # слово + 4 цифры
   ```
5. **Комбинация (`-a 1`):** два словаря, склейка слов.

## John the Ripper

John удобнее для некоторых форматов и умеет автоматически определять тип:

```bash
john --wordlist=rockyou.txt hashes.txt
john --format=bcrypt hashes.txt
john --show hashes.txt
# извлечение хэшей
zip2john secret.zip > zip.hash
rar2john secret.rar > rar.hash
pdf2john secret.pdf > pdf.hash
keepass2john db.kdbx > kp.hash
ssh2john id_rsa > ssh.hash
```

## Практический пример: NTLM из SAM

```bash
# 1. Извлекаем хэши (impacket)
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
# -> Administrator:500:aad3b...:31d6cfe0d16ae931b73c59d7e0c089c0:::
# 2. Ломаем NTLM
hashcat -m 1000 ntlm.txt rockyou.txt -r rules/best64.rule
# 3. Если не вышло — гибрид
hashcat -m 1000 ntlm.txt -a 6 rockyou.txt '?d?d?d?d'
```

## Практический пример: bcrypt

bcrypt намеренно медленный (cost factor). `-m 3200`:

```bash
hashcat -m 3200 bcrypt.txt rockyou.txt -w 3
# -w 3 = high workload; на GPU перебор ограничен
john --format=bcrypt bcrypt.txt --wordlist=rockyou.txt
```

Для bcrypt словарь важнее скорости: слабые пароли ломаются, сильные — нет.

## Инструменты и команды

```bash
sudo apt install hashcat john hashid
hashcat --example-hashes | less          # примеры форматов
hashcat -b -m 1000                       # бенчмарк
john --list=formats
# словари: /usr/share/wordlists/rockyou.txt.gz
```

## Частые ошибки

- **Неверный `-m`.** Самая частая причина «не ломается».
- **Забыть `--show`** и ломать уже сломанное.
- **Использовать CPU вместо GPU.** hashcat на CPU медленный.
- **Огромный словарь без правил.** Иногда правила важнее размера.
- **Ломать bcrypt «в лоб».** Нужен целевой словарь.
- **Не учитывать формат файла хэшей** (один хэш на строку, `user:hash`).

## Правила и маски: детально

**Правила (`-r`)** применяются к каждому слову словаря. Примеры встроенных правил:

- `best64.rule` — 64 популярных мутации.
- `dive.rule` — агрессивные мутации.
- `OneRuleToRuleThemAll.rule` — большое сообщество-правило.

Свойства правила задаются командами: `:` (без изменений), `u` (заглавные), `c` (капитализация), `l` (строчные), `$1` (добавить `1`), `^a` (вставить `a` в начало), `s@a@b` (заменить `a` на `b`), `d` (дублировать).

**Маски (`-a 3`):** `?l` (a-z), `?u` (A-Z), `?d` (0-9), `?s` (спецсимволы), `?a` (все печатные), `?b` (байты). Квантификаторы: `?d?d?d?d` — 4 цифры. Можно задавать пользовательские наборы: `-1 ?l?d -2 ?u` и использовать `?1`, `?2`.

```bash
# 8-значный пароль: 2 строчные + 4 цифры + 2 спецсимвола
hashcat -m 1000 h.txt -a 3 '?l?l?d?d?d?d?s?s'
# пользовательский набор
hashcat -m 1000 h.txt -a 3 -1 'abc123' '?1?1?1?1'
```

## Оптимизация и GPU

- `-w 1..4` — рабочая нагрузка (уровень оптимизации/температуры).
- `-O` — оптимизированное ядро (ограничивает длину пароля).
- `-d 1,2` — выбор устройств.
- `--force` — если драйвер ругается (осторожно).
- `-o out.txt` — сохранение результата.
- `--show` — показать уже взломанные.
- `--potfile-disable` — не использовать potfile.
- `--session` — возобновляемые сессии.

```bash
hashcat -m 1000 h.txt -a 6 rockyou.txt '?d?d?d?d' -O -w 3 -o cracked.txt
hashcat -m 1000 h.txt --show
```

## Извлечение хэшей из форматов

```bash
zip2john secret.zip > zip.hash
rar2john secret.rar > rar.hash
7z2hashcat.pl secret.7z > 7z.hash       # для hashcat
pdf2john secret.pdf > pdf.hash
office2john doc.docx > office.hash
keepass2john db.kdbx > kp.hash
ssh2john id_rsa > ssh.hash
bitlocker2john -i image.dd > bl.hash
```

## Стратегия: с чего начинать

Правильный порядок атак экономит часы:

1. **Идентификация** — `hashid`, длина, формат.
2. **Проверка potfile** — `--show` (вдруг уже взломано).
3. **Словарь + best64.rule** — покрывает большинство слабых паролей.
4. **Словарь + агрессивные правила** (OneRuleToRuleThemAll).
5. **Маска** под известный паттерн (если политика паролей известна).
6. **Гибрид** словарь+цифры/спецсимволы.
7. **Комбинация** двух словарей.
8. **bcrypt/argon2** — только целевой словарь.

Не начинайте с полного перебора (`-a 3 ?a?a?a?...`) — он непрактичен для длинных паролей.

## Словари и где их брать

- `rockyou.txt` — 14M паролей, база.
- `SecLists/Passwords/` — множество списков (leaked, common, etc.).
- `crackstation.txt` — огромный список (human-only).
- `weakpass`, `hashes.org` — базы.
- **Правила:** `best64`, `dive`, `OneRuleToRuleThemAll`.
- **Целевые словари:** из рекон-данных (имена, домены, термины компании).

```bash
# генерация кандидатов правилом
hashcat --stdout rockyou.txt -r rules/best64.rule > mutated.txt
```

## NTLM и Kerberoast

```bash
# NTLM (SAM/NTDS)
hashcat -m 1000 ntlm.txt rockyou.txt
# NetNTLMv2 (из ответов аутентификации)
hashcat -m 5600 netntlmv2.txt rockyou.txt
# Kerberoast (TGS-REP)
hashcat -m 13100 tgs.txt rockyou.txt
# AS-REP
hashcat -m 18200 asrep.txt rockyou.txt
```

Kerberoast/AS-REP-хэши часто ломаются быстро, если сервисные аккаунты используют слабые пароли.

## Как не застрять

- **Идентифицируйте хэш** (hashid/hash-identifier).
- **Выберите режим** hashcat.
- **Начните со словаря + правил.**
- **Затем маска/гибрид** под паттерн пароля.
- **bcrypt/argon2** — только целевой словарь.
- **Для архивов** сначала `*2john`.
- **Ограничьте ресурсы**, чтобы не забить машину.

## Квиз

```quiz
- question: "Какой режим hashcat для NTLM?"
  options:
    - "0"
    - "1000"
    - "1400"
    - "3200"
  answer: 1
- question: "Что делают правила (`.rule`) в hashcat?"
  options:
    - "сортируют словарь"
    - "мутируют слова словаря (регистр, замена, добавление цифр)"
    - "ускоряют GPU"
    - "определяют тип хэша"
  answer: 1
- question: "Чем извлечь хэш из zip-архива?"
  options:
    - "`unzip -p`"
    - "`zip2john`"
    - "`hashid`"
    - "`john --format=zip`"
  answer: 1
- question: "Почему bcrypt тяжело ломать?"
  options:
    - "он не является хэшем"
    - "он намеренно медленный (cost) и солёный"
    - "он шифрует данные"
    - "он короткий"
  answer: 1
- question: "Что эффективнее всего для паролей вида «слово + 4 цифры»?"
  options:
    - "чистая маска"
    - "гибридная атака словарь+маска (`-a 6`)"
    - "SHA-512"
    - "CRT"
  answer: 1
```

## Где пригодится

- **CTF** — почти всегда есть задача «взломай хэш/архив/дамп».
- **Пентест** — после дампа хэшей (SAM, /etc/shadow, БД) нужен их взлом для lateral movement.
- **Red team** — Kerberoast/AS-REP хэши, NetNTLMv2, NTLM relay.
- **Форензика** — восстановление паролей из конфигов и архивов.
- **Защита** — понимание скорости перебора мотивирует использовать bcrypt/argon2 и длинные пароли.
