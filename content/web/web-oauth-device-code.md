---
id: web-oauth-device-code
title: "OAuth device code flow: атаки и злоупотребление"
category: web
parent: web-oauth-oidc-saml
difficulty: hard
order: 1
tags: [oauth, device-code, phishing, flow, token]
prerequisites: [web-oauth-oidc-saml]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 35
summary: "Device Authorization Grant: как устроен, где ломается, фишинг через user_code и захват токенов."
---

Device Authorization Grant (device code flow, RFC 8628) создан для устройств без браузера: ТВ, приставки, CLI. Устройство просит у сервера пару `device_code`/`user_code`, показывает пользователю `user_code` и URL, пользователь вводит код в браузере и подтверждает. Устройство опрашивает сервер и получает токен. Flow удобен, но даёт **новую поверхность атаки**: фишинг кодов, слабая энтропия, отсутствие привязки к устройству, неверная валидация `client_id`.

## Теория: как течёт device flow

1. Устройство → `POST /device_authorization` с `client_id`, `scope`.
2. Сервер → `device_code`, `user_code` (например `WDJB-MJHT`), `verification_uri`, `interval`, `expires_in`.
3. Устройство показывает: «Зайдите на `https://verify.example` и введите `WDJB-MJHT`».
4. Пользователь логинится в браузере и подтверждает код.
5. Устройство опрашивает `POST /token` с `grant_type=urn:ietf:params:oauth:grant-type:device_code` и `device_code` → получает access/refresh token.

Точки доверия и атаки:
- `user_code` показывается/вводится вручную — **фишинг**.
- Нет привязки `device_code` к тому, кто подтвердил — **код можно передать другому**.
- `interval` не соблюдается клиентом → **rate-limit/DoS**.
- Проверка `client_id`/`redirect` может быть слабой.

## Атака: фишинг device code (реальный, рабочий)

1. Атакующий запускает легитимное устройство-приложение (или напрямую дёргает `/device_authorization`) и получает `user_code` + `device_code`.
2. Отправляет жертве ссылку вида «Ваш аккаунт требует подтверждения» → `https://verify.example/device` с просьбой ввести `WDJB-MJHT`.
3. Жертва вводит код в **настоящем** домене провайдера и подтверждает → авторизует устройство атакующего.
4. Атакующий опрашивает `/token` и получает токен доступа к аккаунту жертвы.

Это не баг провайдера сам по себе, но **недостаток UX-защиты**: предупреждений, показа client-имени, ограничений по scope, невозможности отозвать чужой код.

```bash
# 1. запрос device code
curl -s -X POST https://idp.example/oauth/device_authorization \
  -d "client_id=TVAPP&scope=openid profile email"

# 2. (жертва вводит user_code)

# 3. опрос токена
curl -s -X POST https://idp.example/oauth/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=...&client_id=TVAPP"
```

## Ошибки реализации, которые ищем

- **Слабый `user_code`.** 4 цифры/короткий алфавит → брут кода до подтверждения (нужно N попыток, обычно есть лимит).
- **Отсутствие привязки device↔user.** Любой может подтвердить код, если угадал/перехватил.
- **Не проверяется `client_id`.** Можно подставить чужой client и получить его scopes.
- **Нет подтверждения на устройстве.** Устройство сразу получает токен без явного consent.
- **Повторное использование `device_code`.** Должен быть одноразовым.
- **`verification_uri_complete`** (URL с кодом) — если утекает в логи/Referer, код перехватывается.
- **Отсутствие отображения запрашиваемых scope** — жертва не понимает, что авторизует.

## Разобранный пример: перехват токена через open redirect в verification_uri

Цель: провайдер принимает `verification_uri`/`redirect` без строгой проверки.

Шаг 1. Формируем device authorization с `redirect_uri`, ведущим на наш хост (если не проверяется):

```bash
curl -s -X POST https://idp.example/oauth/device_authorization \
  -d "client_id=legit&scope=openid&redirect_uri=https://attacker/cb"
```

Шаг 2. Жертва авторизует → сервер редиректит на наш `redirect_uri` с кодом/токеном.

Шаг 3. Забираем код, обмениваем на токен.

Если `redirect_uri` строго проверяется, ищем open redirect на разрешённом домене и через него уводим `code`.

## Дополнительные векторы

- **Device code + PKCE downgrade** — если PKCE не обязателен, перехваченный `code` обменивается без verifier.
- **Cross-client code use** — `device_code` одного client'а принимается другим.
- **Scope escalation** — устройство запрашивает scope, не показанный пользователю.
- **Replay `user_code`** — если не одноразовый, повторная авторизация.
- **Consent phishing** — комбинация device code + доверие к домену провайдера.
- **Опрос без `interval`** — `slow_down` игнорируется, возможен DoS/брут.

## Частые ошибки исследователя

- **Считать device flow «безопасным по умолчанию».** UX-фишинг реален и активно используется (MFA-fatigue-подобные кампании).
- **Не проверять энтропию `user_code`.** Короткие коды брутятся.
- **Не смотреть на `verification_uri_complete`.** Утечка кода через Referer/логи.
- **Забыть про `client_id`.** Подмена client — классика.
- **Игнорировать PKCE.** Без него перехваченный code обменивается напрямую.
- **Тестировать только happy-path.** Ломайте интервалы, повторы, регистры, лимиты.

## Device code flow: поля и их роль

Поток device code создан для устройств без браузера (TV, CLI), но именно поэтому он удобен для фишинга.

| Поле | Значение | Риск |
|------|----------|------|
| `device_code` | секрет опроса | утечка → перехват токена |
| `user_code` | короткий код для ввода | угадываемый/перебираемый |
| `verification_uri` | куда идти пользователю | open redirect |
| `verification_uri_complete` | URI с кодом внутри | утечка через Referer/лог |
| `expires_in` | срок жизни | слишком долгий |
| `interval` | период опроса | обход лимитов |

```bash
# 1) инициируем device flow
curl -s -X POST https://auth.example/device/code \
  -d 'client_id=app&scope=openid'
# {"device_code":"...","user_code":"WDJB-MJHT","verification_uri":"https://auth.example/device"}
# 2) опрашиваем токен
curl -s -X POST https://auth.example/token \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=...&client_id=app'
```

## Атака: device-code phishing (реальный сценарий)

```text
1) атакующий запускает device flow у себя и получает user_code (например, WDJB-MJHT)
2) отправляет жертве сообщение: «подтвердите вход в приложение, введите код WDJB-MJHT»
3) жертва заходит на легитимный verification_uri и вводит код
4) атакующий опрашивает /token и получает токены жертвы
```

Ключ: код вводится на **настоящем** домене провайдера, поэтому жертва ничего не подозревает. Проверяйте, ограничивает ли провайдер частоту и срок жизни кодов, и предупреждает ли интерфейс о незнакомых устройствах.

## Ошибки реализации, которые ищем

| Ошибка | Проверка |
|--------|----------|
| `user_code` короткий/предсказуемый | перебор вручную |
| нет лимита на опрос `/token` | частые запросы |
| `device_code` живёт долго | `expires_in` большой |
| `verification_uri` без валидации | open redirect |
| `verification_uri_complete` утекает | Referer/log |
| нет привязки к client_id | чужой client использует код |
| scope расширяется при обмене | запросить больше прав |

## Разобранный пример: перехват через open redirect

```text
# verification_uri_complete содержит код; если провайдер редиректит по нему
# и есть open redirect, код утекает:
https://auth.example/device?user_code=WDJB-MJHT&next=https://attacker.example
# 1) атакующий инициирует flow
# 2) жертва переходит по ссылке с кодом
# 3) код попадает на attacker (Referer/redirect)
# 4) атакующий обменивает device_code на токен
```

```bash
# проверка open redirect в verification_uri
curl -s -o /dev/null -w '%{redirect_url}\n' \
  'https://auth.example/device?next=https://attacker.example'
```

## Дополнительные векторы

- **Повторное использование user_code** — если код не инвалидируется после успешного входа.
- **Отсутствие уведомления** — пользователь не видит, что вошёл новый клиент.
- **Утечка через логи/Referer** — `verification_uri_complete` в URL.
- **Cross-client** — код, выданный для одного клиента, принимается другим.
- **Scope escalation** — обмен с расширенным scope.

```bash
# проверка повторного использования кода
curl -s -X POST https://auth.example/token -d '...device_code=SAME...'   # 1-й раз OK
curl -s -X POST https://auth.example/token -d '...device_code=SAME...'   # 2-й раз?
```

## Инструменты

```bash
# перебор/мониторинг device flow — скрипт на Python
python3 - <<'PY'
import requests, time
r = requests.post('https://auth.example/device/code', data={'client_id':'app'}).json()
print('user_code:', r['user_code'])
while True:
    t = requests.post('https://auth.example/token', data={
        'grant_type':'urn:ietf:params:oauth:grant-type:device_code',
        'device_code': r['device_code'], 'client_id':'app'}).json()
    if 'access_token' in t: print(t); break
    time.sleep(r.get('interval',5))
PY
# nuclei — OAuth-шаблоны
nuclei -u https://auth.example -tags oauth -j
```

## Что делать дальше / решение

1. **Поймите поток.** Где выдаётся код, как опрашивается токен.
2. **Проверьте user_code.** Длина, энтропия, лимит попыток.
3. **Проверьте interval/expires.** Можно ли опрашивать чаще/дольше.
4. **Проверьте verification_uri.** Open redirect, утечка в Referer.
5. **Проверьте привязку.** client_id, повторное использование, scope.
6. **Оцените фишинг.** Есть ли предупреждение о незнакомом устройстве.

## Практика и справочники

- **RFC 8628** — OAuth 2.0 Device Authorization Grant.
- **HackTricks** — «OAuth device code phishing».
- **PortSwigger Academy** — «OAuth» темы.
- **Microsoft/Google docs** — device flow best practices.

## Практические приоритеты в device flow

Начните с `user_code`: если он короткий и нет лимита попыток, его можно перебирать, а это прямой захват чужой сессии. Затем проверьте `interval` и `expires_in` — слишком долгий срок жизни и частый опрос расширяют окно атаки. Далее — `verification_uri`: любая валидация, основанная на редиректе, может превратиться в open redirect и утечку кода. И, наконец, оцените, предупреждает ли интерфейс пользователя о входе с незнакомого устройства — отсутствие такого предупреждения делает device-code фишинг особенно эффективным.

## Итог

Device code flow удобен для пользователей, но опасен тем, что код вводится на **легитимном** домене провайдера — жертва не видит подвоха. Проверяйте энтропию и лимиты `user_code`, срок жизни и интервал опроса, валидацию `verification_uri` и привязку к `client_id`. Любая из этих ошибок превращает вспомогательный флоу в рабочий вектор захвата аккаунта.

## Частые ошибки при тестировании device flow

- Считать, что «код вводится на своём домене — значит безопасно»: именно это и делает фишинг эффективным.
- Не проверять энтропию и лимит попыток `user_code`.
- Игнорировать `interval`/`expires_in` — они определяют окно атаки.
- Не смотреть, утекает ли `verification_uri_complete` через Referer и логи.
- Забывать про привязку к `client_id` и повторное использование кода.

## Кратко

Device code flow проверяется по пяти точкам: энтропия и лимиты `user_code`, срок жизни и интервал опроса, валидация `verification_uri`, привязка к `client_id` и предупреждение пользователя о новом устройстве. Любая слабость в них — рабочий вектор фишинга и захвата аккаунта.

## Квиз

```quiz
- question: "Для чего создан OAuth device code flow?"
  options:
    - "Для устройств без браузера (ТВ, CLI)"
    - "Для мобильных приложений"
    - "Для API-ключей"
    - "Для SSO"
  answer: 0
  explanation: "RFC 8628 — устройства ввода с ограничениями."
- question: "В чём основная атака на device flow?"
  options:
    - "Перехват TLS"
    - "Фишинг user_code: жертва авторизует устройство атакующего"
    - "SQL-инъекция"
    - "CSRF"
  answer: 1
  explanation: "Код вводится вручную, что позволяет социальную инженерию."
- question: "Почему важен размер user_code?"
  options:
    - "Он влияет на скорость"
    - "Короткий код можно перебрать до подтверждения"
    - "Он задаёт scope"
    - "Он шифрует токен"
  answer: 1
  explanation: "Слабая энтропия позволяет брут."
- question: "Что должно проверяться в запросе токена по device_code?"
  options:
    - "Цвет интерфейса"
    - "client_id и одноразовость device_code"
    - "User-Agent"
    - "Cookie"
  answer: 1
  explanation: "Иначе возможна подмена client и повторное использование кода."
- question: "Чем опасен verification_uri_complete?"
  options:
    - "Он медленный"
    - "URL содержит user_code и может утечь в Referer/логи"
    - "Он требует JS"
    - "Он ломает мобильные"
  answer: 1
  explanation: "Код в URL легко перехватить."
```

## Где пригодится

- **CTF (Web):** задачи на OAuth-потоки и перехват токенов.
- **Bug bounty:** ошибки device flow (client_id, redirect, энтропия) — валидные отчёты.
- **Пентест:** оценка реализации OAuth-провайдера и интеграций.
- **Работа (AppSec):** обязательный PKCE, предупреждения, привязка device↔user, лимиты.
