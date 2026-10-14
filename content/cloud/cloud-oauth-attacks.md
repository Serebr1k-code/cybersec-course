---
id: cloud-oauth-attacks
title: 'OAuth 2.0 / OIDC: redirect_uri, PKCE, code-injection и consent phishing'
category: cloud
parent: cloud-idp-attacks
difficulty: hard
order: 2
tags: [cloud, oauth, oidc, redirect-uri, pkce, consent-phishing, idp]
prerequisites: [cloud-okta-privesc]
useful_for:
  - 'Пентест OAuth/OIDC-интеграций'
  - 'Кража токенов через redirect_uri'
  - 'CTF cloud'
estimated_minutes: 45
summary: 'OAuth 2.0 и OIDC: authorization code flow, роль redirect_uri, PKCE и его отсутствие, code injection, open redirect и consent phishing. Сквозной пример — уязвимый клиент с недостаточной проверкой redirect_uri.'
lab:
  kind: shell
  title: 'Практика: разбор OAuth-запроса'
  toolset: [core]
  workdir: /home/student/oauth
  files: [task.md, authorize-url.txt, client.json, notes.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Изучи клиент: `cat client.json`. Посмотри, как задан redirect_uri.'
    - 'Изучи URL: `cat authorize-url.txt`. Найди, куда уходит код.'
    - 'Флаг — в notes.md: найди строку `nto` и запиши её в found.txt.'
---

## Вопрос, с которого всё начинается

Ты тестируешь интеграцию приложения с IdP через OAuth. Приложение открывает окно входа, пользователь соглашается, и приложение получает код, который обменивает на токен. Вопрос: где в этой цепочке ошибка, которая позволяет атакующему перехватить чужой токен? Ответ почти всегда один из трёх: **redirect_uri**, **PKCE** или **state**. Разберём каждый.

## Что такое OAuth 2.0 и OIDC

OAuth 2.0 — протокол делегирования доступа: приложение (клиент) получает от пользователя разрешение (authorization) действовать от его имени, не зная пароля. OIDC — надстройка над OAuth для аутентификации (добавляет `id_token`). Основной поток — **authorization code flow**: клиент отправляет пользователя на `/authorize`, тот логинится и соглашается, IdP редиректит обратно с `code`, клиент меняет `code` на `access_token` и `id_token` на `/token`. Вся безопасность держится на том, что `code` достаётся только законному клиенту.

## Сквозной пример: authorize-запрос

Смотрим параметры клиента и запроса:
```
$ cat client.json
{
  "client_id": "acme-web",
  "redirect_uris": ["https://app.acme.com/cb", "https://app.acme.com/cb/evil"]
}
```
```
$ cat authorize-url.txt
https://idp.acme.com/authorize?response_type=code
  &client_id=acme-web
  &redirect_uri=https://app.acme.com/cb/evil
  &scope=openid+email+offline_access
  &state=abc123
```
В списке `redirect_uris` есть лишний путь `/cb/evil`. Это красный флаг: если сервер разрешает подстановочные или слишком широкие URI, атакующий может увести `code` на контролируемый им адрес.

## redirect_uri: главный вектор

`redirect_uri` говорит IdP, куда вернуть `code`. Правильная проверка — **точное** совпадение с заранее зарегистрированным значением. Ошибки, которые эксплуатируются:
- префиксное совпадение (`https://app.acme.com` разрешает `https://app.acme.com.evil.com`);
- подстановочные домены (`https://*.acme.com`);
- open redirect внутри доверенного домена (`/cb?next=https://evil`);
- path traversal в пути callback.

Перехватив `code`, атакующий обменивает его на токен (если нет привязки к клиенту) и получает доступ к данным жертвы. Поэтому `redirect_uri` — первое, что проверяют при аудите OAuth.

## PKCE и почему его отсутствие опасно

PKCE (Proof Key for Code Exchange) привязывает `code` к клиенту: клиент генерирует `code_verifier`, отправляет его хеш (`code_challenge`) на `/authorize`, а на `/token` предъявляет исходный `code_verifier`. Без PKCE перехваченный `code` можно обменять без знания секрета — что критично для публичных клиентов (SPA, мобильные приложения). Если приложение не использует PKCE, кража `code` через redirect_uri становится полной компрометацией.

## state и CSRF

`state` — случайная строка, которую клиент проверяет при возврате. Она защищает от CSRF: без неё атакующий может подсунуть жертве свой `code`, и жертва «привяжет» к себе чужой аккаунт. Отсутствие/игнорирование `state` — отдельная уязвимость, часто идущая в паре с redirect_uri.

## Consent phishing и app-консент

Не всегда нужно ломать протокол. **Consent phishing** — это когда атакующий регистрирует своё OAuth-приложение с похожим именем и просит жертву «разрешить доступ». Пользователь жмёт «Согласен» — и приложение получает токены для чтения почты/файлов. Это легальный с точки зрения протокола доступ, поэтому защита — в политиках консента (требовать админского одобрения, ограничивать scope, проверять издателей приложений).

## Что проверять при аудите

- точное ли совпадение `redirect_uri`;
- используется ли PKCE и обязателен ли он;
- проверяется ли `state`;
- есть ли open redirect на callback-домене;
- привязан ли `code` к клиенту и одноразовый ли он;
- какие scope запрашиваются и есть ли `offline_access` (refresh-токены);
- настроен ли admin consent и проверка издателя приложений.

## Как проверить руками

Подставь `redirect_uri` на свой домен в authorize-запрос и посмотри, вернёт ли IdP `code` без ошибки:
```
$ curl -sI "https://idp.acme.com/authorize?response_type=code&client_id=acme-web&redirect_uri=https://evil.example/cb&scope=openid"
```
Если редирект ведёт на `evil.example` с `code` — проверка URI сломана.

## Что мы теперь знаем

- OAuth code flow отдаёт `code` клиенту; вся защита — в привязке `code` к клиенту.
- `redirect_uri` должен совпадать точно; префиксы/подстановки = кража `code`.
- PKCE обязателен для публичных клиентов; без него кража `code` фатальна.
- `state` защищает от CSRF; его отсутствие — отдельная уязвимость.
- Consent phishing не ломает протокол, а злоупотребляет доверием пользователя.

## Квиз

Проверь себя.

```quiz
- question: "Как должна проверяться redirect_uri?"
  options:
    - "Точным совпадением с зарегистрированным значением"
    - "По префиксу домена"
    - "По подстановочному домену"
    - "Не проверяется"
  answer: 0
  explanation: "Только точное совпадение; префиксы и подстановки позволяют увести code на чужой адрес."
- question: "Зачем нужен PKCE?"
  options:
    - "Привязывает code к клиенту через code_verifier/challenge"
    - "Шифрует трафик"
    - "Отключает MFA"
    - "Заменяет state"
  answer: 0
  explanation: "PKCE не даёт обменять перехваченный code без знания code_verifier."
- question: "От чего защищает параметр state?"
  options:
    - "От CSRF-подмены code"
    - "От перебора паролей"
    - "От XSS"
    - "От брутфорса"
  answer: 0
  explanation: "state — случайная строка, которую клиент сверяет при возврате; защищает от подсунутого code."
- question: "Что такое consent phishing?"
  options:
    - "Выдача консента вредоносному OAuth-приложению"
    - "Фишинг по SMS"
    - "Подмена DNS"
    - "SQL-инъекция"
  answer: 0
  explanation: "Пользователя убеждают одобрить доступ приложения, которое затем читает его данные."
- question: "Почему offline_access в scope повышает риск?"
  options:
    - "Выдаёт refresh-токен для долгого доступа"
    - "Отключает шифрование"
    - "Удаляет state"
    - "Ничем"
  answer: 0
  explanation: "Refresh-токен позволяет обновлять доступ без повторного входа — долгая персистентность."
```

## Куда дальше

В следующем уроке — AiTM-фишинг против облачного SSO: как обходят MFA через прокси-фреймворк и почему это стало массовым. А пока главное: OAuth доверяет redirect_uri и PKCE, и именно их проверяют первыми.

## Где пригодится

- Пентест OAuth/OIDC-интеграций и SSO.
- Разбор инцидентов с кражей токенов.
- CTF-задачи категории cloud.
