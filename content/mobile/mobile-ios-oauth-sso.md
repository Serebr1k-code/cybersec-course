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
---

## Как мобильное приложение делает OAuth

Веб-OAuth предполагает браузер, который хранит сессию и cookie. Мобильное приложение — это отдельный клиент, и здесь есть два подхода: **встроенный WebView** (плохо) и **системный браузер / ASWebAuthenticationSession** (правильно). Разница принципиальна: во встроенном WebView приложение может читать вводимые пароли и токены, а cookie общие с приложением, что позволяет фишингу и перехвату.

Правильный поток (Authorization Code + PKCE):
1. Приложение генерирует `code_verifier` (случайная строка) и `code_challenge = BASE64URL(SHA256(code_verifier))`.
2. Открывает системный браузер на `https://idp.example.com/authorize?client_id=...&redirect_uri=app://callback&response_type=code&code_challenge=...&code_challenge_method=S256`.
3. Пользователь логинится, IdP редиректит на `redirect_uri` с `code`.
4. Приложение обменивает `code` + `code_verifier` на токен на `/token` (back channel).
5. Токен хранится в Keychain.

PKCE защищает от перехвата `code`: без `code_verifier` перехваченный код бесполезен.

## iOS: ASWebAuthenticationSession

```swift
let session = ASWebAuthenticationSession(
    url: authURL,
    callbackURLScheme: "app",
    completionHandler: { callbackURL, error in
        guard let url = callbackURL,
              let code = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                  .queryItems?.first(where: { $0.name == "code" })?.value
        else { return }
        self.exchange(code: code)
    })
session.prefersEphemeralWebBrowserSession = true
session.presentationContextProvider = self
session.start()
```

`prefersEphemeralWebBrowserSession = true` изолирует cookie — важно против session fixation. Если приложение вместо этого использует `WKWebView` с `loadRequest(authURL)` и перехватом навигации — это плохой признак: проверьте, не логирует ли оно URL с `code` и не читает ли формы.

## Android: Custom Tabs и AppAuth

```java
AuthorizationRequest req = new AuthorizationRequest.Builder(
        authConfig, "client_id", ResponseTypeValues.CODE, redirectUri)
    .setCodeVerifier(codeVerifier, codeChallenge, "S256")
    .build();
AuthorizationService svc = new AuthorizationService(context);
svc.startActivity(new AuthorizationIntent(req, context));
```

Проверка в `AndroidManifest`: `redirect_uri` — это custom scheme (`app://callback`) или App Link (`https://example.com/callback`). Первое перехватывается чужим приложением; второе — нет (если ассоциация настроена).

## Типовые ошибки

- **Implicit flow** (`response_type=token`) — токен приходит во fragment, утекает в историю/логи. Устарел, но встречается.
- **Нет PKCE** — перехваченный `code` можно обменять.
- **Слабый `redirect_uri`** — сервер принимает любой `redirect_uri` или подстановочные домены; код уводится на атакующего.
- **Custom scheme `redirect_uri`** — перехват другим приложением.
- **`client_secret` в приложении** — мобильный клиент публичный, секрет не защищён; если он используется, проверьте, не даёт ли это extra-доступ.
- **WebView для логина** — приложение видит пароль.
- **Токен в `NSUserDefaults`/логах** — утечка при бэкапе/логах.
- **Нет проверки `state`** — CSRF на callback.

## Практика: перехват и анализ потока

Настройте прокси (Burp/mitmproxy) с CA и перехватите авторизацию:

```bash
# iOS: доверьте CA в Settings > General > About > Certificate Trust
# Android: установите CA в системный store (root) для app-трафика
```

В Repeater смотрите:
- `response_type` — `code` или `token`;
- наличие `code_challenge` / `code_challenge_method=S256`;
- `redirect_uri` — точный ли он;
- заголовки `Referer`, логи.

Попробуйте подменить `redirect_uri` на свой:

```
GET /authorize?client_id=app&redirect_uri=https://evil.com/cb&response_type=code&...
```

Если сервер редиректит на `evil.com` — находка (open redirect / weak redirect).

Проверка обмена кода без PKCE:

```bash
curl -s -X POST https://idp.example.com/token \
  -d "grant_type=authorization_code&code=STOLEN&redirect_uri=app://callback&client_id=app"
# если возвращает access_token без code_verifier — PKCE не enforced
```

## Кража кода через custom scheme

Если `redirect_uri=app://callback`, любое приложение может зарегистрировать схему `app` и получить `code`. Для этого достаточно приложения-ловушки с intent-filter/URL scheme и, если код не защищён PKCE, обменять его на токен. Это классическая критичная находка в баг-баунти мобильных приложений.

Защита: использовать Universal Links/App Links для `redirect_uri` + обязательный PKCE + проверка `state`.

## Динамический анализ токена

Frida-хук на Keychain (iOS) для перехвата токена:

```javascript
var SecItemAdd = Module.findExportByName("Security", "SecItemAdd");
Interceptor.attach(SecItemAdd, {
  onEnter: function (args) {
    var attrs = new ObjC.Object(args[0]);
    console.log("[Keychain add] " + attrs.toString());
  }
});
```

Android — хук SharedPreferences/EncryptedSharedPreferences и OkHttp:

```javascript
Java.perform(function () {
  var SP = Java.use("android.app.SharedPreferencesImpl");
  SP.getString.implementation = function (k, d) {
    var v = this.getString(k, d);
    console.log("[SP] " + k + " = " + v);
    return v;
  };
});
```

Так вы увидите, как хранится и передаётся токен.

## Справочная таблица

| Элемент | Правильно | Опасно |
|---------|-----------|--------|
| Браузер | ASWebAuthenticationSession / Custom Tabs | встроенный WebView |
| Поток | Authorization Code + PKCE | implicit (`response_type=token`) |
| redirect_uri | Universal/App Link, точный | custom scheme, wildcard |
| state | обязателен | отсутствует |
| client_secret | не нужен | зашит в приложение |
| хранение токена | Keychain / Keystore | UserDefaults/SharedPreferences |

## Что дальше / решение

Проверьте: браузер (системный vs WebView), тип потока (code+PKCE vs implicit), `redirect_uri` (перехватываемость), `state`, хранение токена. Найденный перехват кода без PKCE — критично. Дальше — `mobile-cert-pinning-deep` (перехват трафика) и `mobile-storage-deep` (хранение токенов).

## OIDC и ID token: что проверять

Если приложение использует OpenID Connect, помимо `access_token` приходит `id_token` (JWT) с утверждениями о пользователе. Проверяйте:

- **Подпись `id_token`** — верифицируется ли она на клиенте/сервере? Мобильное приложение часто доверяет `id_token` без проверки.
- **`aud` (audience)** — совпадает ли с `client_id` приложения.
- **`iss` (issuer)** — ожидаемый IdP.
- **`nonce`** — привязан ли к сессии (защита от replay).
- **`exp`** — не истёк ли.

Разбор токена:

```bash
# декодировать payload JWT
cut -d. -f2 <<< "$ID_TOKEN" | base64 -d 2>/dev/null | jq .
```

Утилита `jwt_analyze` из вашего арсенала проверяет `alg=none`, слабые секреты и отсутствие claims — прогоните через неё найденный токен. Если приложение принимает `alg: none` или HS256 с публично известным секретом — критическая находка.

## Разбор реального баг-баунти сценария

Типовой отчёт о краже OAuth-кода выглядит так:

1. Приложение использует `redirect_uri=myapp://oauth/callback` (custom scheme).
2. Второе приложение регистрирует ту же схему `myapp` и перехватывает редирект.
3. Так как PKCE отсутствует, перехваченный `code` обменивается на `access_token` атакующего.
4. Итог — полный захват аккаунта жертвы.

Воспроизведение в лаборатории:

```bash
# приложение-ловушка с intent-filter на myapp:// (Android)
adb install trap.apk
# запустить жертву на авторизацию, перехватить callback
adb logcat -s TrapApp:D
# получить code и обменять его
curl -X POST https://idp/token -d "grant_type=authorization_code&code=...&client_id=app&redirect_uri=myapp://oauth/callback"
```

Если обмен успешен без `code_verifier` — подтверждено. Аналогично на iOS, но перехват custom scheme сложнее: система отдаёт ссылку первому зарегистрированному приложению, и порядок непредсказуем.

## Защитные меры и что рекомендовать

Для отчёта сформируйте рекомендации:

- Использовать **Authorization Code + PKCE** (S256) обязательно.
- `redirect_uri` — **Universal Link / App Link**, не custom scheme.
- Строгая **валидация `redirect_uri`** на сервере (точное совпадение, без wildcard).
- Проверка **`state`** (CSRF) и **`nonce`** (replay).
- **Системный браузер** (ASWebAuthenticationSession / Custom Tabs), не WebView.
- Хранение токенов — **Keychain / Keystore**, не UserDefaults/SharedPreferences.
- Короткое время жизни токенов + refresh с ротацией.
- Не логировать токены и `code`.

## Динамика: перехват ASWebAuthenticationSession и Custom Tabs

Проверьте, действительно ли используется системный браузер, а не WebView:

```javascript
// iOS: подменить класс браузера
Java.perform(function(){}); // n/a
// вместо этого в Frida (ObjC):
var ASWeb = ObjC.classes.ASWebAuthenticationSession;
if (ASWeb) {
  Interceptor.attach(ASWeb['- start'].implementation, {
    onEnter: function () { console.log("[oauth] ASWebAuthenticationSession.start"); }
  });
}
```

Если видите `WKWebView.loadRequest` с URL авторизации — приложение логинит во встроенном WebView, и это отдельная находка.

```javascript
Java.perform(function () {
  var WK = Java.use("android.webkit.WebView"); // Android
  WK.loadUrl.overload('java.lang.String').implementation = function (u) {
    if (u.indexOf("authorize") !== -1) console.log("[oauth] WebView: " + u);
    return this.loadUrl(u);
  };
});
```

## Мониторинг и тестовые матрицы

Составьте матрицу проверок для каждого способа авторизации (пароль, Google, Apple, корпоративный SSO) и зафиксируйте: поток, redirect_uri, наличие PKCE, хранение токена. Это делает отчёт системным и помогает не пропустить кейс, где один из методов входа реализован слабее остальных (частая ситуация: SSO через сторонний SDK ошибочно использует implicit flow).

## Итог: модель угроз мобильного OAuth

Сведите анализ к четырём вопросам. Кто видит `code` — перехватываем ли `redirect_uri`? Может ли атакующий обменять `code` — есть ли PKCE? Видит ли приложение пароль — используется ли системный браузер? Где живёт токен — Keychain/Keystore или незащищённое хранилище? Ответы на эти четыре вопроса покрывают подавляющее большинство реальных проблем мобильной авторизации. Дополнительно проверьте `state`/`nonce`, срок жизни токенов и логирование. Собранная матрица по каждому способу входа (пароль, соцсети, корпоративный SSO) делает отчёт полным и показывает, какой из потоков слабее остальных.

## Квиз

```quiz
- question: "Зачем нужен PKCE в мобильном OAuth?"
  options:
    - "Защищает от обмена перехваченного code без code_verifier"
    - "Шифрует пароль пользователя"
    - "Ускоряет логин"
    - "Заменяет TLS"
  answer: 0
- question: "Почему встроенный WebView для OAuth считается небезопасным?"
  options:
    - "Приложение может читать пароль и токены, cookie общие с приложением"
    - "Он медленный"
    - "Он не поддерживает HTTPS"
    - "Он требует джейлбрейка"
  answer: 0
- question: "Какая ошибка позволяет украсть OAuth-код чужим приложением?"
  options:
    - "redirect_uri на custom scheme без PKCE"
    - "Использование HTTPS"
    - "Наличие state"
    - "Хранение токена в Keychain"
  answer: 0
- question: "Что проверяет state в OAuth-потоке?"
  options:
    - "Защиту от CSRF на callback"
    - "Скорость сети"
    - "Версию TLS"
    - "Размер ответа"
  answer: 0
```

## Где пригодится

- **Bug bounty:** кража OAuth-кода, слабый redirect_uri, отсутствие PKCE.
- **Пентест:** аудит SSO и авторизации мобильного приложения.
- **Работа:** безопасная реализация логина в мобильном клиенте.
