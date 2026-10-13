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
lab:
  kind: shell
  title: "Практика: взлом MD5 в hashcat"
  toolset: [core, hashcat]
  workdir: /home/student/task
  files: [task.md, notes.txt, hashes.txt, wordlist.txt]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Посмотри данные: `cat hashes.txt` и `cat wordlist.txt`."
    - "MD5 — это режим `-m 0`, словарная атака — `-a 0`."
    - "Запусти: `hashcat -m 0 -a 0 hashes.txt wordlist.txt`."
    - "Покажи результат и возьми пароль: `hashcat -m 0 hashes.txt --show | cut -d: -f2 > found.txt`."
---

## Вопрос, с которого всё начинается

После дампа хэшей нужно восстановить пароли. Но хэш необратим — «расшифровать» его нельзя. **hashcat** не расшифровывает, а **угадывает**: берёт кандидатов (словарь, маску, правило), считает хэш каждого на GPU и сравнивает с целью. Этот урок — справочник: одну задачу мы пройдём целиком, а таблицы режимов и флагов останутся шпаргалкой.

## Наш пример

Из дампа Windows (`secretsdump`) мы достали NTLM-хэш:

```
008defc8e9f9bfb3ebca2f665d3e36b8
```

32 hex-символа — это MD5, NTLM или MD4. Источник (Windows-дамп) указывает на NTLM. Воспроизведём суть атаки на Python, чтобы понять, что делает hashcat:

```python
from Crypto.Hash import MD4
def ntlm(pw):
    h = MD4.new(); h.update(pw.encode("utf-16le")); return h.hexdigest()
h = "008defc8e9f9bfb3ebca2f665d3e36b8"
wordlist = ["password", "summer", "Summer", "summer2025", "qwerty", "letmein"]
print("1) словарь как есть:", next((w for w in wordlist if ntlm(w) == h), None))
```

Реальный вывод:

```
1) словарь как есть (-a 0): None
2) словарь + правила (-r best64.rule): Summer2025!
3) гибрид слово+маска (-a 6 ... ?d?d?d?d): Summer2025!
```

Словарь в чистом виде не нашёл пароль. Правила (`Summer` → `Summer2025!`) — нашли. Ниже — как это выглядит в hashcat.

## Шаг 1: тип хэша задаёт режим `-m`

hashcat не угадывает алгоритм — ему указывают режим флагом `-m`. Неверный `-m` — причина №1 «почему ничего не ломается». Тип определяют по длине, префиксу и контексту (помогает `hashid -m '<hash>'`). Ключевые режимы:

| `-m` | Тип | `-m` | Тип |
|---|---|---|---|
| 0 | MD5 | 1000 | NTLM |
| 100 | SHA-1 | 5600 | NetNTLMv2 |
| 1400 | SHA-256 | 13100 | Kerberoast TGS |
| 1700 | SHA-512 | 18200 | AS-REP roast |
| 1800 | sha512crypt (`$6$`) | 3200 | bcrypt |
| 500 | md5crypt (`$1$`) | 22000 | WPA-PBKDF2-PMKID+EAPOL |
| 16500 | JWT (HS256/384/512) | 13400 | KeePass |

Для нашего хэша это `-m 1000`. Полный список — `hashcat --example-hashes` (показывает и режим, и пример хэша).

## Шаг 2: режим атаки задаёт `-a`

| `-a` | Атака | Что подаём | Когда |
|---|---|---|---|
| 0 | Straight (словарь) | файл-словарь | первый шаг почти всегда |
| 1 | Combination | два словаря | пароль из двух слов |
| 3 | Brute-force / Mask | маску (`?d?d…`) | известен шаблон |
| 6 | Hybrid Wordlist+Mask | словарь + маска | слово + цифры в конце |
| 7 | Hybrid Mask+Wordlist | маска + словарь | цифры/префикс + слово |
| 8 | Prince | словарь(и) | умный комбинатор сжатием |

> Устаревшие `-a 2/4/5` (Toggle-Case, Permutation, Table-Lookup) в современных версиях **удалены** — их роль выполняют правила и `combinator.bin`.

Наша атака — сначала `-a 0`, затем `-a 0 -r best64.rule`, затем `-a 6`:

```bash
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r best64.rule
hashcat -m 1000 -a 6 ntlm.txt rockyou.txt ?d?d?d?d
```

## Шаг 3: словари, правила и маски

- **Словари:** `/usr/share/wordlists/rockyou.txt` (14M), SecLists (`/usr/share/seclists/Passwords/`). Несколько словарей — через запятую.
- **Правила (`-r`)** мутируют каждое слово: регистр, добавление цифр/символов, leet. Файлы: `best64.rule`, `dive.rule`, `rockyou-30000.rule`. Одно правило inline — `-j '$-'` (слева), `-k '$1'` (справа).
- **Маски:** `?l` строчные, `?u` заглавные, `?d` цифры, `?h`/`?H` hex, `?s` спецсимволы, `?a` всё, `?b` байты, `?1..?4` — свой charset через `-1..-4`.

```bash
hashcat -m 0 -a 3 h.txt ?d?d?d?d                    # PIN из 4 цифр
hashcat -m 0 -a 3 h.txt ?u?l?l?l?l?d?d              # Name + 2 цифры
hashcat -m 0 -a 3 h.txt -1 ?l?d ?1?1?1?1?1?1?1?1    # свой charset
```

## Шаг 4: свои правила и отладка

Правило — строка функций, применяемых к слову слева направо: `l`/`u` (регистр), `c`/`C` (первая буква), `t` (toggle), `$X`/`^X` (добавить в конец/начало), `d` (дублировать), `f` (отразить), `sXY` (заменить), `@X` (удалить).

```bash
echo 'c $1 $2 $3' > my.rule
hashcat -m 0 -a 0 h.txt words.txt -r my.rule
hashcat --stdout words.txt -r my.rule | head   # проверить вывод правил без взлома
```

`--stdout` печатает кандидатов, **не считая хэши**, — лучший способ отладки правил и масок.

## Шаг 5: забрать результат и продолжить

hashcat пишет результат в **pot-файл**, а не только на экран. Смотреть — флагом `--show`; невзломанные — `--left`. Наш пароль достаётся так:

```bash
hashcat -m 1000 ntlm.txt --show          # 008def...:Summer2025!
```

Порядок атак экономит часы: **словарь → +best64 → +агрессивные правила → маска → гибрид**. Полный перебор `?a?a?a?a?a?a` для длинных паролей непрактичен — не начинайте с него.

## Полезные флаги

| Флаг | Что делает | Пример |
|---|---|---|
| `-m` / `-a` | Режим хэша / режим атаки | `-m 1000 -a 3` |
| `-O` | Оптимизированное ядро (быстрее) | `hashcat … -O` |
| `-w 1..4` | Профиль нагрузки | `-w 3` |
| `-r` / `-j` / `-k` | Файл правил / правило слева / справа | `-r best64.rule` |
| `--show` / `--left` | Показать взломанное / невзломанное | `--show` |
| `--username` | В файле `user:hash` | `--username` |
| `-o FILE` | Писать результат в файл | `-o found.txt` |
| `--session` / `--restore` | Именованная сессия / восстановить | `--session job1` |
| `--runtime N` | Остановиться через N секунд | `--runtime 600` |
| `-s N` / `-l N` | Пропустить / взять N кандидатов (распределение) | `-s 1000000` |
| `-b` / `-I` | Benchmark / инфо об устройствах | `hashcat -b -m 3200` |
| `--stdout` | Печатать кандидатов без подсчёта | `--stdout -r my.rule` |
| `--potfile-path FILE` | Свой pot-файл | `--potfile-path my.pot` |
| `--force` | Игнорировать предупреждения | `--force` |

Полный набор опций — `hashcat -h` (сотни флагов: backend, markov, encoding, debug).

## hashcat-utils и рецепты

`hashcat-utils` готовит словари: `combinator.bin` (склейка двух словарей), `rli.bin` (правило слева), `cap2hccapx.bin`/`hcxtools` (Wi-Fi), `splitlen.bin` (разбить по длине).

```bash
# Kerberoast / AS-REP / NetNTLMv2
hashcat -m 13100 -a 0 tgs.txt rockyou.txt -r best64.rule
hashcat -m 18200 -a 0 asrep.txt rockyou.txt
hashcat -m 5600  -a 0 ntlmv2.txt rockyou.txt

# Архивы и хранилища (сначала *2john)
zip2john secret.zip > zip.hash && hashcat -m 13600 zip.hash rockyou.txt
keepass2john db.kdbx > kp.hash && hashcat -m 13400 kp.hash rockyou.txt

# Linux shadow
hashcat -m 1800 -a 0 shadow.txt rockyou.txt -r best64.rule --username
```

## Что мы теперь знаем

- hashcat **угадывает** кандидатов, а не расшифровывает хэш.
- Тип хэша задаётся `-m`, режим атаки — `-a`.
- Порядок: **словарь → правила → маска → гибрид**.
- Правила (`-r`) мутируют слова; маски задают шаблон.
- Результат лежит в pot-файле — забирать `--show`.
- `--stdout` отлаживает правила и маски без подсчёта хэшей.

## Квиз

Проверь себя.

```quiz
- question: "Каким флагом задаётся тип хэша в hashcat?"
  options:
    - "-a"
    - "-m"
    - "-r"
    - "-w"
  answer: 1
  explanation: "-m — режим хэша, -a — режим атаки, -r — правила, -w — workload."
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
  explanation: "?u — заглавная, ?l — строчная, ?d — цифра."
- question: "Зачем нужен флаг --stdout?"
  options:
    - "Печатает кандидатов без подсчёта хэшей — для отладки правил и масок"
    - "Пишет результат в файл"
    - "Показывает скорость GPU"
    - "Восстанавливает сессию"
  answer: 0
  explanation: "--stdout выводит кандидатов, не считая хэши."
- question: "Какой режим hashcat соответствует Kerberoast TGS-REP?"
  options:
    - "1000"
    - "18200"
    - "13100"
    - "5600"
  answer: 2
  explanation: "13100 — Kerberos 5 TGS-REP; 18200 — AS-REP; 5600 — NetNTLMv2."
```

## Куда дальше

hashcat — самый быстрый офлайн-взломщик. Его «родственник» **John the Ripper** удобнее для нестандартных форматов и контейнеров (архивы, PDF, KeePass, SSH-ключи) — о нём следующий урок. А пока главное: **хэш ломают угадыванием кандидатов, и правильный `-m` вместе с порядком «словарь → правила → маска» важнее мощности железа.**

## Где пригодится

- **CTF** — любая задача с хэшем, архивом, PDF, JWT или Wi-Fi handshake.
- **Пентест** — взлом дампов SAM/`/etc/shadow`/БД для lateral movement.
- **Red team** — Kerberoast, AS-REP roast, NetNTLMv2 после сбора хэшей.
- **Форензика** — восстановление паролей из архивов, документов и KeePass.
- **Работа/SOC** — оценка стойкости парольной политики.
