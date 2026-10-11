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

Онлайн-брут — это перебор логинов и паролей **по сети**, против живого сервиса. В отличие от офлайн-взлома хэшей, здесь нет дампа: вы бьёте прямо в форму логина, SSH, FTP, БД. Инструменты — hydra, medusa, patator. Этот урок — справочник с флагами и рецептами плюс жёсткие правила, чтобы не заблокировать аккаунт и не уронить сервис.

## Этика и безопасность онлайн-перебора

Онлайн-брут — самый «громкий» и рискованный шаг. Прежде чем запускать:

- **Считайте бюджет попыток.** Обычно есть lockout (5 попыток → блокировка) и rate-limit. Триггер блокировки может уронить доступ для реальных пользователей.
- **Никогда не лейте rockyou целиком** по сети: это почти гарантированно заблокирует аккаунт и засветит тест. Только **маленький курированный список**: дефолты сервиса + найденные/унаследованные креды + производные от них + пара самых частых.
- **Проверяйте UNAUTH-доступ** раньше брута: анонимный FTP, null-session SMB, Redis/Mongo без пароля, дефолтные админки.
- **Password spraying** (один пароль против многих логинов) безопаснее reverse brute-force (много паролей против одного логина): он обходит lockout-per-user.
- **Ограничьте потоки.** `-t 4` и `--rate`/`-W` вместо 64 потоков: меньше шансов заDoSить сервис.
- **Только авторизованный тест.** Онлайн-брут без разрешения — противозаконно.

## hydra: синтаксис

```bash
hydra [флаги] <цель> <модуль> [параметры модуля]
```

```bash
hydra -l admin -P passwords.txt ssh://10.0.0.5
hydra -L users.txt -P passwords.txt ftp://10.0.0.5
hydra -l admin -P passwords.txt 10.0.0.5 http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"
```

## hydra: флаги — таблица

| Флаг | Что делает | Пример |
|---|---|---|
| `-l USER` | один логин | `-l admin` |
| `-L FILE` | список логинов | `-L users.txt` |
| `-p PASS` | один пароль | `-p 'Summer2025!'` |
| `-P FILE` | список паролей | `-P pass.txt` |
| `-C FILE` | файл вида `login:pass` (combo) | `-C combos.txt` |
| `-e nsr` | доп. проверки: `n` пустой пароль, `s` логин как пароль, `r` обратный логин | `-e nsr` |
| `-s PORT` | нестандартный порт | `-s 2222` |
| `-t N` | число параллельных задач на цель (по умолчанию 16) | `-t 4` |
| `-T N` | параллельных целей (для `-M`) | `-T 4` |
| `-f` | стоп после первой пары (на цель) | `-f` |
| `-F` | стоп после первой пары (глобально) | `-F` |
| `-o FILE` | писать найденное в файл | `-o found.txt` |
| `-b FORMAT` | формат вывода (`json`, `jsonv1`) | `-b json` |
| `-O` | писать и пароли, и логины из файлов в `-o` | `-O` |
| `-V` / `-vV` | verbose: показывать каждую попытку | `-V` |
| `-d` | отладочный вывод | `-d` |
| `-q` | тихий режим (без баннера) | `-q` |
| `-R N` | восстановить прерванную сессию | `-R 1` |
| `-I` | игнорировать файл восстановления (начать заново) | `-I` |
| `-K` | не повторять попытки из restore-файла | `-K` |
| `-M FILE` | список целей (для `-T`) | `-M targets.txt` |
| `-x MIN:MAX:CHARSET` | brute-force генерация (например `-x 4:4:0-9`) | `-x 4:4:0-9` |
| `-u` | не выводить ошибки для каждой попытки | `-u` |
| `-w N` | таймаут (сек) | `-w 5` |
| `-W N` | время между попытками на задачу (rate-limit) | `-W 2` |
| `-c N` | время ожидания (сек) на попытку (соединение) | `-c 10` |
| `-S` | использовать SSL (для https-модулей) | `-S` |
| `-y` | отключить SSL | `-y` |
| `-4` / `-6` | использовать только IPv4 / IPv6 | `-6` |
| `-m OPT` | опции, специфичные для модуля | `-m 'DIR:/login'` |
| `-h` | справка по hydra | `-h` |
| `-U MODULE` | справка по конкретному модулю | `hydra -U http-post-form` |

## hydra: модули сервисов — таблица

| Модуль | Сервис | Пример |
|---|---|---|
| `ssh` | SSH | `ssh://10.0.0.5` |
| `sshkey` | SSH по приватному ключу | `sshkey://10.0.0.5` |
| `ftp` | FTP | `ftp://10.0.0.5` |
| `ftps` | FTP over SSL | `ftps://10.0.0.5` |
| `telnet` | Telnet | `telnet://10.0.0.5` |
| `smtp` | SMTP | `smtp://10.0.0.5` |
| `smtp-enum` | Перечисление пользователей SMTP | `smtp-enum://10.0.0.5` |
| `pop3` | POP3 | `pop3://10.0.0.5` |
| `imap` | IMAP | `imap://10.0.0.5` |
| `nntp` | NNTP | `nntp://10.0.0.5` |
| `http-get` | HTTP Basic/Digest | `10.0.0.5 http-get /admin/` |
| `http-post-form` | HTTP-форма (POST) | `10.0.0.5 http-post-form "/login:u=^USER^&p=^PASS^:F=bad"` |
| `http-get-form` | HTTP-форма (GET) | `10.0.0.5 http-get-form "/login:u=^USER^&p=^PASS^:F=bad"` |
| `https-get` | HTTPS Basic/Digest | `10.0.0.5 https-get /admin/` |
| `https-post-form` | HTTPS-форма (POST) | `10.0.0.5 https-post-form "/login:...:F=bad"` |
| `http-proxy` | HTTP-прокси | `http-proxy://10.0.0.5` |
| `smb` | SMB | `smb://10.0.0.5` |
| `rdp` | RDP | `rdp://10.0.0.5` |
| `mysql` | MySQL | `mysql://10.0.0.5` |
| `mssql` | MSSQL | `mssql://10.0.0.5` |
| `postgres` | PostgreSQL | `postgres://10.0.0.5` |
| `oracle-listener` | Oracle TNS-listener | `oracle-listener://10.0.0.5` |
| `oracle-sid` | Oracle (по SID) | `oracle-sid://10.0.0.5:ORCL` |
| `ldap2` / `ldap3` | LDAP | `ldap3://10.0.0.5` |
| `redis` | Redis | `redis://10.0.0.5` |
| `mongodb` | MongoDB | `mongodb://10.0.0.5` |
| `memcached` | Memcached | `memcached://10.0.0.5` |
| `snmp` | SNMP | `snmp://10.0.0.5` |
| `vnc` | VNC | `vnc://10.0.0.5` |
| `socks5` | SOCKS5 | `socks5://10.0.0.5` |
| `cvs` | CVS pserver | `cvs://10.0.0.5` |
| `svn` | Subversion | `svn://10.0.0.5` |
| `firebird` | Firebird | `firebird://10.0.0.5` |
| `icq` | ICQ | `icq://10.0.0.5` |
| `irc` | IRC | `irc://10.0.0.5` |
| `pcanywhere` | pcAnywhere | `pcanywhere://10.0.0.5` |
| `pcnfs` | PC-NFS | `pcnfs://10.0.0.5` |
| `rexec` | rexec | `rexec://10.0.0.5` |
| `rlogin` | rlogin | `rlogin://10.0.0.5` |
| `rsh` | rsh | `rsh://10.0.0.5` |
| `rtsp` | RTSP | `rtsp://10.0.0.5` |
| `s7-300` | Siemens S7-300 | `s7-300://10.0.0.5` |
| `sip` | SIP | `sip://10.0.0.5` |
| `teamspeak` | TeamSpeak | `teamspeak://10.0.0.5` |
| `xmpp` | XMPP | `xmpp://10.0.0.5` |
| `vmauthd` | VMware Auth Daemon | `vmauthd://10.0.0.5` |
| `adam6500` | ADAM 6000/6500 | `adam6500://10.0.0.5` |
| `asterisk` | Asterisk | `asterisk://10.0.0.5` |
| `cisco` | Cisco (login) | `cisco://10.0.0.5` |
| `cisco-enable` | Cisco enable | `cisco-enable://10.0.0.5` |
| `radmin2` | Radmin2 | `radmin2://10.0.0.5` |

Полный список: `hydra -h | grep -A200 'Supported services'` или `hydra -U <модуль>` (справка по модулю, например `hydra -U http-post-form`).

## hydra: http-post-form подробно

Формат:

```bash
hydra -l USER -P PASSES host http-post-form "/path:body:fail-string[:extra]"
```

- `/path` — путь формы логина (`/login`, `/api/auth`).
- `body` — тело POST; `^USER^` и `^PASS^` подставляются. `^USER64^`/`^PASS64^` — base64, `^USER^` в URL-encode через `^USER^` при `:H=` заголовках.
- `fail-string` — как распознать НЕУДАЧУ. Префиксы:
  - `F=текст` — провал, если в ответе есть текст (по умолчанию).
  - `S=текст` — успех, если есть текст.
  - `F=404` / `S=200` — по коду ответа.
- `:H=Cookie: x=1` — добавить заголовки (через `\n`).
- `:C=/cookie` — взять cookie из файла.
- `:c=COOKIE` — cookie-строка.

```bash
# классическая форма
hydra -l admin -P pass.txt 10.0.0.5 http-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid credentials"

# успех по редиректу/строке
hydra -l admin -P pass.txt 10.0.0.5 http-post-form \
  "/login:user=^USER^&pass=^PASS^:S=Welcome"

# с cookie и CSRF-токеном, взяв cookie из файла
hydra -l admin -P pass.txt 10.0.0.5 http-post-form \
  "/login:user=^USER^&pass=^PASS^&csrf=TOKEN:F=failed:H=Cookie: session=abc"

# https
hydra -S -l admin -P pass.txt 10.0.0.5 https-post-form \
  "/login:user=^USER^&pass=^PASS^:F=error"
```

Чтобы не угадывать fail-string — сделайте один запрос вручную (curl/Burp) с неверным паролем и посмотрите уникальную строку/код ответа.

## hydra: практические рецепты

```bash
# 1. SSH (маленький список!)
hydra -l root -P small.txt -t 4 -f ssh://10.0.0.5

# 2. FTP
hydra -L users.txt -P small.txt -t 4 ftp://10.0.0.5

# 3. HTTP Basic/Digest
hydra -l admin -P small.txt 10.0.0.5 http-get /admin/

# 4. HTTP POST-форма
hydra -l admin -P small.txt 10.0.0.5 http-post-form \
  "/login:user=^USER^&pass=^PASS^:F=incorrect"

# 5. MySQL
hydra -l root -P small.txt mysql://10.0.0.5

# 6. MSSQL
hydra -l sa -P small.txt mssql://10.0.0.5

# 7. PostgreSQL
hydra -l postgres -P small.txt postgres://10.0.0.5

# 8. SMB
hydra -l Administrator -P small.txt smb://10.0.0.5

# 9. RDP
hydra -l Administrator -P small.txt rdp://10.0.0.5

# 10. Проверка пустого пароля и логина-как-пароля
hydra -l admin -e ns -P small.txt ssh://10.0.0.5

# 11. Password spraying: один пароль против списка логинов
hydra -L users.txt -p 'Summer2025!' -t 2 -f ssh://10.0.0.5

# 12. Записать найденное в файл
hydra -l admin -P small.txt -o found.txt -f ssh://10.0.0.5
```

## medusa: синтаксис и эквиваленты

medusa — аналог hydra с другим набором модулей:

```bash
medusa -h HOST -u USER -P PASSES -M MODULE [флаги]
```

| medusa | Что делает (эквивалент hydra) |
|---|---|
| `-h HOST` | цель |
| `-H FILE` | список целей |
| `-u USER` / `-U FILE` | логин / список логинов |
| `-p PASS` / `-P FILE` | пароль / список паролей |
| `-C FILE` | combo-файл |
| `-M MODULE` | модуль (`ssh`, `ftp`, `http`, `smbnt`, `mssql`, `mysql`, `rdp`, `vnc`, `pop3`, `imap`, `smtp-auth`, `svn`, `pcanywhere`, `rexec`, `rlogin`, `nntp`, `web-form`, `telnet`, `sshv1`) |
| `-m 'OPT'` | опции модуля (напр. `-m DIR:/login`, `-m FORM:"...:F=bad"`) |
| `-t N` | потоков на цель |
| `-T N` | целей одновременно |
| `-L N` | параллельных логинов на цель |
| `-f` | стоп после первой находки на цель |
| `-F` | стоп после первой глобально |
| `-n PORT` | порт |
| `-s` | SSL |
| `-e ns` | пустой пароль (`n`), логин=пароль (`s`) |
| `-O FILE` | файл вывода |
| `-r N` | пауза между попытками (сек) |
| `-g N` | сдаться после N попыток (give-up) |
| `-R N` | продолжить прерванную сессию |
| `-w N` | таймаут (сек) |
| `-b` | подавить баннер |
| `-d` | debug |
| `-q` | quiet (только находки) |
| `-v N` | verbosity (0-6) |
| `-V` | версия |

```bash
medusa -h 10.0.0.5 -u admin -P small.txt -M ssh -t 4 -f
medusa -h 10.0.0.5 -u admin -P small.txt -M http -m DIR:/login -m FORM:"user=^USER^&pass=^PASS^:F=incorrect" -f
medusa -h 10.0.0.5 -u sa -P small.txt -M mssql -f
medusa -h 10.0.0.5 -u Administrator -P small.txt -M smbnt -f
```

Отличие medusa: `-t` — потоки на цель, `-T` — число целей. Модуль HTTP задаётся через `-m DIR:...` и `-m FORM:...`.

## patator: модульная структура

patator — самый гибкий: модуль задаётся первым аргументом, затем `host=`, `user=`, `password=FILE0`, где `FILE0` — плейсхолдер для первого `0=файл`.

```bash
patator MODULE host=... user=... password=FILE0 0=wordlist.txt [опции]
```

Популярные модули: `ssh_login`, `ftp_login`, `http_fuzz`, `smtp_login`, `pop3_login`, `imap_login`, `mysql_login`, `mssql_login`, `oracle_login`, `ldap_login`, `vnc_login`, `smb_login`, `rdp_login`, `telnet_login`, `dns_forward`, `tcp_fuzz`.

```bash
# SSH
patator ssh_login host=10.0.0.5 user=admin password=FILE0 0=small.txt \
  -x ignore:mesg='Authentication failed.'

# FTP
patator ftp_login host=10.0.0.5 user=admin password=FILE0 0=small.txt \
  -x ignore:mesg='Login incorrect'

# HTTP POST-форма (плейсхолдеры в теле)
patator http_fuzz url=http://10.0.0.5/login method=POST \
  body='user=admin&pass=FILE0' 0=small.txt \
  -x ignore:fgrep='Invalid credentials'

# HTTP Basic
patator http_fuzz url=http://10.0.0.5/admin method=GET \
  auth_type=basic user=admin password=FILE0 0=small.txt \
  -x ignore:code=401

# MySQL
patator mysql_login host=10.0.0.5 user=root password=FILE0 0=small.txt
```

Ключевые флаги patator:

| Флаг | Что делает | Пример |
|---|---|---|
| `host=`, `url=`, `user=`, `password=` | параметры модуля | `host=10.0.0.5 user=admin` |
| `port=` | нестандартный порт | `port=2222` |
| `FILE0`, `0=file` | первый список-плейсхолдер | `password=FILE0 0=pass.txt` |
| `FILE1`, `1=file` | второй список (например, user и pass) | `user=FILE1 1=users.txt` |
| `-x ignore:...` | правило игнорирования «нормального» ответа | `-x ignore:fgrep='Invalid'` |
| `-x stop:...` | правило остановки | `-x stop:code=200` |
| `-x reset:...` | сброс состояния между попытками | `-x reset:fgrep='try again'` |
| `-x free:...` | не освобождать ресурсы | `-x free:code=200` |
| `-x quit:...` | выйти сразу | `-x quit:code=200` |
| `-x time:...` | условие по времени ответа | `-x time=gt:1.0` |
| `-x code:...` | условие по HTTP-коду | `-x ignore:code=401` |
| `-t N` / `--threads` | число потоков | `-t 4` |
| `--rate-limit N` | лимит запросов в секунду | `--rate-limit 2` |
| `--timeout N` | таймаут (сек) | `--timeout 10` |
| `--max-retries N` | число повторов | `--max-retries 1` |
| `-l DIR` / `--log-dir` | каталог логов | `-l ./patator_logs` |
| `-e` / `--exit-on-error` | выход при ошибке | `-e` |
| `-q` | тихий режим | `-q` |
| `-R N` | повторить попытки N раз | `-R 2` |
| `-S FILE` | save/resume состояние | `-S state.txt` |
| `-b` | подавить баннер | `-b` |
| `--allow-ignore-failures` | не падать на ошибках | `--allow-ignore-failures` |

Главное преимущество patator: можно подать **два списка** (логины и пароли) и сложные условия игнорирования (`ignore:code=200`, `ignore:fgrep=...`).

## Генерация курированных словарей

Никогда не лейте rockyou по сети. Соберите маленький осмысленный список:

```bash
# логины из сервиса (enum) + дефолтные
printf 'admin\nroot\nadministrator\nuser\nguest\n' > users.txt

# дефолтные пароли сервиса + найденные креды + производные
cat > passes.txt <<'EOF'
admin
password
admin123
<PASSWORD_ИЗ_НАЙДЕННОГО_КОНФИГА>
EOF

# из веб-страницы (имена, термины)
cewl -d 2 -m 4 -w cewl.txt http://10.0.0.5

# мутации найденного пароля (сезон+год+символ)
printf 'Summer2025!\nSummer2025\nSummer25!\n' >> passes.txt
```

Правило: сначала **одна-две очевидные пары**, затем UNAUTH-проверки, и только потом маленький список. Пять попыток исчерпали — переходите к другому вектору.

## Сравнение: что выбрать

| Инструмент | Сильная сторона | Когда |
|---|---|---|
| **hydra** | огромный список модулей, простой синтаксис, `http-post-form` | дефолт для большинства сервисов и форм |
| **medusa** | параллельные цели (`-T`), стабильность, модули `smbnt`/`rdp` | много целей сразу, SMB/RDP |
| **patator** | два списка, гибкие условия `-x ignore/stop`, `--rate-limit` | сложные формы, точный контроль ошибок и скорости |

Практика: начинайте с hydra; если нужны два списка или сложный `ignore` — patator; если целей много и параллельно — medusa.

## Как не заблокировать аккаунт и не уронить сервис

- **`-t 4`** (или меньше), не 16/64. Для форм — `-t 1`–`2`.
- **`-W 2`** (hydra) или **`--rate-limit`** (patator) — пауза между попытками.
- **`-e ns`** — проверьте пустой пароль и логин=пароль: иногда это единственный рабочий вход.
- **`-f` / `-F`** — стоп после первой находки, не продолжайте перебор зря.
- **Считайте окно lockout.** Если политика — 5 попыток за 15 минут, ваш список должен быть ≤4, либо делайте password spraying.
- **Password spraying**: один пароль, много логинов, пауза между «волнами».
- **Не бруть одновременно** один аккаунт с разных инструментов — удвоите попытки и ускорите блокировку.
- **Проверяйте код ответа.** Иногда «неудача» и «успех» различаются редиректом, а не текстом — тестируйте вручную.

## Частые ошибки

- **Неверный fail-string** в `http-post-form` — hydra считает успехом всё подряд (или ничего). Сначала один ручной запрос.
- **Слишком много потоков** — сервис отдаёт 500/таймауты, результаты мусорные. Снизьте `-t`.
- **rockyou по сети** — блокировка аккаунта и бан IP. Только курированный список.
- **Забыли протокол/порт** — `ssh://host:2222`, `-s PORT`.
- **`-e nsr` на медленном сервисе** — лишние попытки; применяйте осознанно.
- **Cookie/CSRF не переданы** — форма логина без сессии всегда «провал». Возьмите cookie из браузера/Burp и передайте через `:H=Cookie:`.
- **Логин угадан, пароль нет** — не продолжайте бесконечно; переходите к другому вектору.

## Квиз

```quiz
- question: "Почему нельзя лить rockyou.txt целиком по сети против формы логина?"
  options:
    - "Это слишком медленно"
    - "Сработает lockout и аккаунт заблокируется, тест засветится"
    - "hydra не поддерживает rockyou"
    - "Словарь содержит неверные кодировки"
  answer: 1
- question: "Что означает F=Invalid credentials в hydra http-post-form?"
  options:
    - "Успех, если в ответе есть эта строка"
    - "Провал, если в ответе есть эта строка"
    - "Имя файла с паролями"
    - "Заголовок Cookie"
  answer: 1
- question: "Какой инструмент позволяет подать два списка (логины и пароли) с гибкими условиями игнорирования?"
  options:
    - "hashcat"
    - "john"
    - "patator"
    - "zip2john"
  answer: 2
- question: "Что такое password spraying?"
  options:
    - "Много паролей против одного логина"
    - "Один пароль против многих логинов с паузами"
    - "Взлом хэша на GPU"
    - "Извлечение пароля из архива"
  answer: 1
- question: "Зачем ставить hydra флаг -e ns?"
  options:
    - "Отключить SSL"
    - "Проверить пустой пароль (n) и логин как пароль (s)"
    - "Увеличить число потоков"
    - "Сохранить вывод в файл"
  answer: 1
```

## Где пригодится

- **CTF** — формы логина, basic-auth, SSH/FTP/MySQL с дефолтными кредами.
- **Пентест** — проверка парольной политики по сети, password spraying, слабые сервисные учётки.
- **Red team** — после сбора логинов (enum, OSINT) — аккуратный онлайн-подбор без блокировок.
- **Работа/SOC** — понимание, как быстро перебираются слабые пароли, и почему важны lockout и MFA.
- **Blue team** — детект: всплеск неудачных логинов, `401/403` подряд, один пароль против многих аккаунтов.
