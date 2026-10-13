---
id: mobile-ios-oauth-sso
title: "OAuth 2.0 и SSO в мобильных приложениях: PKCE, редиректы, кража кода"
category: mobile
parent: mobile-advanced-ios
difficulty: expert
order: 4
tags: [mobile, oauth, sso, pkce, ios, android, redirect]
prerequisites: [mobile-universal-links, mobile-api-testing]
useful_for:
  - "Bug bounty: OAuth в мобильных приложениях"
  - "Пентест: аудит авторизации и SSO"
estimated_minutes: 48
summary: "Как устроен OAuth 2.0/OIDC в мобильном приложении, роль PKCE, ASWebAuthenticationSession, Custom Tabs, типовые ошибки (implicit flow, слабый redirect_uri, отсутствие PKCE) и кража кода/токена."
lab:
  kind: shell
  title: 'Практика: OAuth/SSO в iOS'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, oauth_flow.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`oauth_flow.txt` — лог OAuth-потока (PKCE).'
    - 'Ищи, где теряется `code_verifier` или переиспользуется `state`.'
    - 'В логе есть секрет — найди `nto{` и запиши в `found.txt`.'
---

## Вопрос, с которого всё начинается

Пользователь нажимает «Войти через Google», приложение открывает браузер, происходит вход, и приложение получает **токен** — ключ к аккаунту. Но как именно токен попадает из браузера в приложение? И что мешает другому приложению перехватить его по пути?

## Наш пример: DemoApp и вход через SSO

`DemoApp` использует вход через внешнего провайдера (SSO — Single Sign-On, «единый вход»). Схема типичная:

1. Приложение открывает системный браузер (или `ASWebAuthenticationSession`) на странице провайдера.
2. Пользователь вводит логин и пароль.
3. Провайдер редиректит обратно на **callback-URL** приложения с одноразовым кодом.
4. Приложение меняет код на токен по API.

Ключевое звено — шаг 3. Callback задаётся в настройках провайдера и в приложении. В нашем случае это custom URL scheme:

```
demosec://oauth/callback?code=SECRET
```

## Шаг 1: находим OAuth-конфигурацию

Первым делом ищем параметры OAuth в статике: `client_id`, `redirect_uri`, `scope`, эндпоинты. Они часто лежат в строках или plist:

```
$ strings -a DemoApp | grep -iE 'oauth|redirect|client_id|authorize'
demosec://oauth/callback
https://provider.example/authorize
https://provider.example/token
```

Мы видим callback `demosec://oauth/callback` и эндпоинты. Теперь понятно, куда вернётся код.

## Шаг 2: почему custom scheme опасен

Проблема в том, что custom scheme **не уникальна**: любое приложение на устройстве может зарегистрировать `demosec` и перехватить callback. Если провайдер разрешает `demosec://` как `redirect_uri`, злоумышленник регистрирует такую же схему и получает `code`, а затем меняет его на токен.

Это называется **OAuth code interception**. Провайдеры борются с ним двумя способами:

- требуют **PKCE** (Proof Key for Code Exchange) — одноразовый `code_verifier`, без которого код бесполезен;
- запрещают custom scheme в пользу **Universal Links** (`https://`) — их нельзя перехватить чужим приложением.

## Шаг 3: проверяем PKCE и redirect_uri

Что смотреть в запросе авторизации:

- Есть ли `code_challenge` и `code_challenge_method=S256`? Если нет — PKCE не используется, и перехват кода реален.
- Какой `redirect_uri` разрешён? Если провайдер допускает `http://localhost` или wildcard — возможен open redirect.
- Проверяется ли `state`? Параметр `state` защищает от CSRF; без него возможна подмена.

Перехватить запрос можно через прокси (см. `mobile-mitm-burp`): если pinning снят, мы увидим полный OAuth-обмен.

## Шаг 4: практический тест перехвата

Соберём цепочку на тестовом устройстве:

1. Регистрируем «evil»-приложение с той же схемой `demosec`.
2. Инициируем вход в `DemoApp`.
3. Evil-приложение перехватывает callback и получает `code`.
4. Меняем `code` на токен.

Если провайдер не требует PKCE, шаг 4 срабатывает — это критическая находка. Проверку удобно автоматизировать через `simctl openurl`:

```
$ xcrun simctl openurl booted "demosec://oauth/callback?code=test123"
```

Так проверяем, как приложение обрабатывает код: валидирует ли `state`, меняет ли код сразу.

## Шаг 5: токены в WebView и ASWebAuthenticationSession

Иногда приложение использует не системный браузер, а **WebView** — встроенный компонент для показа веб-страниц. Это хуже: WebView не изолирован от кода приложения, и если приложение внедряет в него JS-мост (`addJavascriptInterface`/`WKScriptMessageHandler`), возможен перехват. Современный правильный подход — `ASWebAuthenticationSession`, который использует системный браузер и изолирует сессию.

Признак плохой практики: вход открывается внутри WebView с адресной строкой приложения. Проверить легко — залогиниться и посмотреть, появляется ли системный браузер.

## Шаг 6: где утекают токены

Даже при правильном OAuth токен может утечь:

- **В логах** — `print`/`NSLog` токена.
- **В Keychain без защиты** — см. `mobile-ios-keychain`.
- **В `NSUserDefaults`** — незащищённый plist.
- **В аналитике** — токен уходит в сторонний SDK.
- **Через deep link** — приложение передаёт токен дальше по URL.

Проверяем `objection`:

```
com.demo.secapp # ios keychain dump
com.demo.secapp # ios nsuserdefaults get
```

И ищем токен в логах:

```
$ idevicesyslog | grep -iE 'token|access'
```

## Шаг 7: что писать в отчёте

OAuth-находка — это цепочка с чётким последствием: захват аккаунта (ATO). В отчёте покажи:

- используемый `redirect_uri` и его тип (custom scheme / Universal Link);
- наличие или отсутствие PKCE;
- воспроизводимый сценарий перехвата;
- куда попадает токен после получения.

Сильная находка — отсутствие PKCE при custom scheme: она позволяет украсть токен любого пользователя, кликнувшего по ссылке.

## Шаг 8: ASWebAuthenticationSession и полный чек-лист

Отдельно разберём «правильный» механизм входа — `ASWebAuthenticationSession`. Это системный компонент, который открывает браузер в изолированной сессии: приложение не видит, что вводит пользователь, и не может перехватить пароль. Оно получает только callback-URL. Если приложение использует этот компонент с Universal Links и PKCE — поток защищён. Если же вход реализован через собственный WebView или `WKWebView` с внедрённым JS-мостом, риск перехвата резко растёт.

Соберём чек-лист проверки SSO:

| Что проверяем | Признак проблемы |
|---------------|------------------|
| Тип callback | custom scheme без PKCE |
| PKCE | нет `code_challenge` |
| `state` | не проверяется |
| Компонент входа | собственный WebView |
| Хранение токена | `NSUserDefaults`, логи |
| Срок жизни токена | долгоживущий refresh без ротации |

Пройди по списку — и ты быстро поймёшь, есть ли в SSO-потоке реальная уязвимость или он настроен правильно. Даже один пункт «custom scheme без PKCE» уже даёт полноценный захват аккаунта, поэтому начинай именно с него. Остальные пункты уточняют масштаб проблемы и помогают правильно оценить критичность в отчёте.

## Шаг 9: PKCE руками — verifier и challenge

PKCE не даёт перехватить код авторизации: клиент придумывает случайный `code_verifier`, отправляет на `/authorize` его хеш (`code_challenge`), а на `/token` предъявляет сам verifier. Сервер сверяет хеш. Воспроизведём:

```
$ VERIFIER=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
$ echo "$VERIFIER"
hI5YfB2_ln8T-2wmbNU-iNUE77b2yo7UC3D5bfsuM2A
$ printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '='
qeiHZSsJhsA_-PySKBxmxDq-9kxz-xC8TmheGZGwCU4
```

Verifier — 43–128 символов из набора `[A-Za-z0-9-._~]`, challenge — base64url от SHA-256 без паддинга. В трафике ищи две вещи: `code_challenge_method=plain` (verifier идёт открытым текстом) и фиксированный/переиспользуемый verifier — тогда перехваченный `code` можно обменять на токен у себя.

## Что мы теперь знаем

- SSO-вход возвращает код на callback-URL приложения.
- Custom scheme не уникальна — callback можно перехватить чужим приложением.
- PKCE защищает код от перехвата; без него токен уязвим.
- Universal Links надёжнее custom scheme для callback.
- `state` защищает от CSRF; его нужно проверять.
- WebView для входа хуже, чем `ASWebAuthenticationSession`.
- Токен может утекать в логах, `NSUserDefaults`, аналитике и deep link.

## Квиз

Проверь себя.

```quiz
- question: Что такое OAuth callback-URL?
  options:
    - "Адрес, куда провайдер возвращает код после входа"
    - "Пароль пользователя"
    - "Ключ API"
    - "Адрес Keychain"
  answer: 0
  explanation: "После аутентификации провайдер редиректит на callback-URL с одноразовым кодом."
- question: Почему custom URL scheme опасна для OAuth?
  options:
    - "Она медленная"
    - "Она не уникальна, поэтому callback может перехватить другое приложение"
    - "Она не поддерживает HTTPS"
    - "Она ломает приложение"
  answer: 1
  explanation: "Любое приложение может зарегистрировать ту же схему и получить код."
- question: От чего защищает PKCE?
  options:
    - "От перехвата кода авторизации"
    - "От утечки Keychain"
    - "От jailbreak"
    - "От MITM"
  answer: 0
  explanation: "PKCE добавляет code_verifier, без которого перехваченный код бесполезен."
- question: Какой компонент считается безопаснее для входа?
  options:
    - "WebView"
    - "ASWebAuthenticationSession (системный браузер)"
    - "Собственный экран логина"
    - "NSUserDefaults"
  answer: 1
  explanation: "Системный браузер изолирует сессию, в отличие от встроенного WebView."
- question: Для чего нужен параметр state в OAuth?
  options:
    - "Для защиты от CSRF/подмены запроса"
    - "Для шифрования трафика"
    - "Для хранения пароля"
    - "Для сжатия"
  answer: 0
  explanation: "state связывает запрос и ответ, защищая от подмены."
```

## Куда дальше

Мы разобрали, как приложение получает токены. Но не менее важно, что остаётся на устройстве и в бэкапах. В следующем уроке `mobile-ios-backup` мы разберём, как извлекать данные из резервной копии iOS. А пока главное запомни: безопасность OAuth держится на PKCE и правильном `redirect_uri`, а custom scheme без PKCE — прямой путь к захвату аккаунта.

## Где пригодится

- **Пентест:** анализ SSO-потока и поиск перехвата токенов.
- **Bug bounty:** отсутствие PKCE и слабый redirect_uri — популярные находки.
- **CTF:** перехват OAuth-кода для получения доступа.
- **Аудит:** проверка корректности OAuth-конфигурации.
