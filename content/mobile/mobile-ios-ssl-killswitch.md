---
id: mobile-ios-ssl-killswitch
title: "SSL Kill Switch и обход pinning на iOS"
category: mobile
parent: mobile-ios-advanced
difficulty: hard
order: 2
tags: [ios, ssl, pinning, ssl-killswitch, frida, trustkit, mitm, security-framework]
prerequisites: [mobile-ios-basics, mobile-ssl-pinning]
useful_for:
  - "Пентест мобильных приложений (iOS)"
  - "Bug bounty iOS"
  - "Анализ трафика"
estimated_minutes: 50
summary: "Как обходить certificate pinning на iOS: SSL Kill Switch 2, Frida-хуки Security.framework, TrustKit, libcurl и нативный pinning; настройка MITM через Burp/mitmproxy."
---
## Введение

На iOS certificate pinning реализуется в нескольких местах: `Security.framework` (`SecTrustEvaluate`, `SecTrustEvaluateWithError`), `NSURLSession` delegate (`URLSession:didReceiveChallenge:`), сторонние библиотеки (TrustKit, AFNetworking), `libcurl` и нативный код. SSL Kill Switch — это твик/библиотека, которая патчит доверие к сертификатам в рантайме, заставляя приложение принимать любой сертификат. Вместе с Frida-хуками это основной способ перехватить iOS-трафик для анализа API.

Пентест-задача: настроить MITM-прокси (Burp/mitmproxy), заставить приложение ему доверять (установить CA и включить доверие), затем обойти pinning. Без jailbreak — только в своём процессе (Frida-gadget в перепакованном IPA) или через per-app proxy.

## Настройка MITM на iOS

```bash
# 1. Прокси в Wi-Fi настройках устройства -> IP:8080 (Burp)
# 2. Скачать CA: http://burp  (или http://mitm.it для mitmproxy)
# 3. Settings -> General -> VPN & Device Management -> установить профиль
# 4. Settings -> General -> About -> Certificate Trust Settings -> включить доверие
```

После этого обычные HTTPS-запросы видны в Burp. Если приложение использует pinning — соединение падает (`NSURLErrorServerCertificateUntrusted`, `-1202`).

## SSL Kill Switch 2

На jailbreak-устройстве твик `SSL Kill Switch 2` (Cydia) отключает pinning глобально: патчит `SecTrustEvaluate`/`SecTrustEvaluateWithError` и challenge-обработчики. Активируется в Settings → SSL Kill Switch 2 → «Disable Certificate Pinning».

Без jailbreak — встраиваем аналог через Frida. Скрипт хукает `SecTrustEvaluateWithError`:

```javascript
// frida-ios-pinning-bypass.js
if (ObjC.available) {
  var SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
  Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
    return 1; // always trusted
  }, 'bool', ['pointer', 'pointer']));

  var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
  Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
    if (result !== null) Memory.writeU32(result, 1); // kSecTrustResultProceed
    return 0; // errSecSuccess
  }, 'int', ['pointer', 'pointer']));
}
```

Запуск:

```bash
frida -U -f com.target.app -l frida-ios-pinning-bypass.js --no-pause
```

## Обход TrustKit и challenge-делегатов

TrustKit хукает на уровне `SecTrustEvaluateWithError` и хранит pinning-политику; обычно достаточно глобального хука выше. Для `NSURLSession` challenge-делегатов хукают метод класса:

```javascript
var cls = ObjC.classes.NSURLSession;
// перехват didReceiveChallenge на делегате приложения
```

Практичнее — использовать готовый скрипт `frida-ios-ssl-bypass` или Objection:

```bash
objection -g com.target.app explore
ios sslpinning disable
```

Objection патчит несколько точек (Security.framework, NSURLSession, TrustKit, libcurl) одной командой.

## Нативный pinning и libcurl

Если приложение пиннит нативно (сравнение хэшей сертификата в C++), Frida-хук `SecTrustEvaluate` не поможет. Тогда:

- ищут функции `SSL_CTX_set_verify`/`X509_verify_cert` (libcurl/OpenSSL) и хукают их;
- ищут сравнение `memcmp`/`CC_SHA256` с зашитым хэшем и подменяют результат;
- перехватывают `SSL_get_verify_result` (возврат `X509_V_OK`).

```bash
# найти символы pinning в бинарнике
nm -m AppBinary | grep -iE 'verify|pinn|ssl|trust'
strings AppBinary | grep -iE 'sha256/|pin'
```

## Полный сквозной пример

Цель: перехватить API-трафик приложения с pinning.

```bash
# 1. Настроить Burp и установить CA (см. выше)
# 2. Запустить приложение под Frida с обходом
frida -U -f com.target.app -l frida-ios-pinning-bypass.js --no-pause
# 3. В приложении выполнить действие (login)
# 4. В Burp видим POST /api/login с телом
# 5. Меняем параметр, повторяем — проверяем BOLA/IDOR (см. mobile-api-bola)
```

Если соединение всё ещё падает — проверьте, что приложение не использует нативный pinning и не проверяет proxy (некоторые детектят `CFNetworkCopySystemProxySettings`).

## Частые ошибки

- **CA не доверенный**: сертификат установлен, но `Certificate Trust Settings` не включён — Burp показывает ошибку доверия.
- **Хук не сработал**: символ называется `SecTrustEvaluateWithError` (iOS 12+) — хукать нужно его, а не только старый `SecTrustEvaluate`.
- **TrustKit с зашитым хэшем**: глобальный хук обычно проходит, но если нет — хукайте `TSKPinningValidator`.
- **Нативный pinning**: Frida по `Security` бесполезен — ищите SSL/OpenSSL-символы.
- **Proxy detection**: приложение проверяет настройки прокси и блокируется — обходите `CFNetworkCopySystemProxySettings`.
- **Без jailbreak**: системный Frida недоступен — перепакуйте IPA с frida-gadget (`objection patchipa`).

## Что дальше / решение

Порядок обхода: установить CA → попробовать Burp → при падении запустить Objection `ios sslpinning disable` → при неудаче Frida-хуки Security → при нативном pinning хукать OpenSSL/libcurl. Свяжите с `mobile-cert-pinning-deep` (Android-аналогия) и `mobile-api-testing`. Дальше — `mobile-ios-cycript` для runtime-интроспекции.

## Справочная таблица

| Точка pinning | Что хукать |
|---------------|-----------|
| Security.framework | `SecTrustEvaluate(WithError)` |
| NSURLSession | challenge delegate |
| TrustKit | `TSKPinningValidator` |
| AFNetworking | `AFSecurityPolicy` |
| libcurl/OpenSSL | `SSL_get_verify_result`, `X509_verify_cert` |

| Инструмент | Команда |
|-----------|---------|
| Objection | `ios sslpinning disable` |
| Frida | `frida -U -f pkg -l bypass.js` |
| Patch IPA | `objection patchipa --source app.ipa` |

## Обход pinning в Swift и Alamofire

Swift-приложения пиннят по-разному. `URLSession` с делегатом требует перехвата `urlSession(_:didReceive:completionHandler:)`; Alamofire использует `ServerTrustManager` и `PinnedCertificatesTrustEvaluator`. Хук на уровне `Security.framework` обычно покрывает всё, но если pinning реализован в Swift-обёртке, хукайте сам делегат:

```javascript
// перехват challenge в NSURLSession
var NSURLSession = ObjC.classes.NSURLSession;
var hook = ObjC.classes.NSURLSession["- URLSession:didReceiveChallenge:completionHandler:"];
Interceptor.attach(hook.implementation, {
  onEnter: function(args) {
    // args[2] = challenge, args[3] = completionHandler block
    var completion = new ObjC.Block(args[3]);
    completion.implementation = function(disposition, credential) {
      // 0 = NSURLSessionAuthChallengeUseCredential с нашим доверием
      completion(0, credential);
    };
  }
});
```

Для Alamofire проще заменить `ServerTrustManager.evaluator` или доверие в `PinnedCertificatesTrustEvaluator`.

## Продвинутые скрипты Frida

Комплексный скрипт обходит несколько слоёв сразу:

```javascript
if (ObjC.available) {
  ["SecTrustEvaluateWithError","SecTrustEvaluate"].forEach(function(n){
    var f = Module.findExportByName("Security", n);
    if (!f) return;
    Interceptor.replace(f, new NativeCallback(function(){ return 1; }, 'int', ['pointer','pointer']));
  });
  // libcurl / OpenSSL
  var verify = Module.findExportByName(null, "SSL_get_verify_result");
  if (verify) Interceptor.replace(verify, new NativeCallback(function(){ return 0; }, 'int', ['pointer']));
  // TrustKit
  if (ObjC.classes.TSKPinningValidator) {
    var cls = ObjC.classes.TSKPinningValidator;
    Interceptor.attach(cls["- evaluateTrust:forHostname:"].implementation, {
      onLeave: function(ret){ ret.replace(ptr(1)); }
    });
  }
}
```

Такой скрипт покрывает Security.framework, OpenSSL/libcurl и TrustKit одним запуском.

## Диагностика: почему MITM не работает

| Симптом | Причина | Действие |
|---------|---------|----------|
| TLS error -1202 | pinning | запустить обход |
| Пустой трафик | proxy не применён | проверить Wi-Fi-настройку |
| Только часть запросов | нативный стек | хукать libcurl/OpenSSL |
| Запросы к IP, не домену | pinning по IP/сертификату | хук verify |
| Приложение падает | proxy detection | хук CFNetworkCopySystemProxySettings |

```javascript
// обход proxy detection
var f = Module.findExportByName("CFNetwork", "CFNetworkCopySystemProxySettings");
if (f) Interceptor.replace(f, new NativeCallback(function(){ return NULL; }, 'pointer', []));
```

## Сравнение инструментов обхода

| Инструмент | Плюсы | Минусы |
|-----------|-------|--------|
| Objection | одна команда, много точек | нужен Frida/jailbreak |
| Frida-скрипт | гибкость, покрытие | нужен свой скрипт |
| SSL Kill Switch 2 | глобально, просто | только jailbreak |
| reFlutter | для Flutter | только Flutter |

## Кейс: перехват API банковского приложения

```bash
# 1. CA установлен, доверие включено
# 2. Запуск под Frida с комплексным обходом
frida -U -f com.bank.app -l ios-bypass.js --no-pause
# 3. Выполняем логин в приложении
# 4. В Burp видим POST /api/v1/auth/login с телом
# 5. Меняем deviceId/accountId, повторяем -> проверяем BOLA
# 6. Если трафик не появился — проверяем нативный pinning (nm | grep ssl)
```

Итог: перехваченный API-трафик даёт доступ к тестированию бизнес-логики (см. `mobile-api-bola`). Без обхода pinning банковские приложения практически «непрозрачны» для прокси.

## Рекомендации в отчёте

Pinning на iOS — эффективная защита, но обходится в рантайме на jailbreak-устройстве. Рекомендация: комбинировать pinning с серверной валидацией, certificate transparency, короткоживущими токенами и аттестацией (App Attest). Только pinning недостаточно против инструментированного клиента.

## Практикум: пошаговый обход pinning

Разберём полный цикл на примере банковского iOS-приложения.

Шаг 1. Подготовка MITM. В Wi-Fi-настройках устройства укажите прокси на ПК (Burp/mitmproxy). Скачайте CA (`http://burp` или `http://mitm.it`). Установите профиль и включите доверие в `Certificate Trust Settings`.

Шаг 2. Проверка. Запустите приложение, выполните вход. Если в прокси пусто и приложение показывает сетевую ошибку — pinning.

Шаг 3. Обход. Запустите под Frida комплексный скрипт (Security.framework + TrustKit + OpenSSL). Или Objection:

```bash
objection -g com.bank.app explore
ios sslpinning disable
```

Шаг 4. Повторная проверка. Выполните вход снова. В прокси должен появиться поток. Если нет — проверьте нативный pinning (`nm -D AppBinary | grep -i ssl`) и хукните `SSL_get_verify_result`/`X509_verify_cert`.

Шаг 5. Диагностика proxy detection. Если приложение падает при активном прокси, хукните `CFNetworkCopySystemProxySettings` (вернуть NULL).

Шаг 6. Анализ API. С перехваченным трафиком тестируйте бизнес-логику (см. `mobile-api-bola`).

## Без jailbreak

Системный Frida недоступен. Перепакуйте IPA с frida-gadget (`objection patchipa --source app.ipa`), подпишите и установите. Либо используйте VPN-режим mitmproxy.

## Что писать в отчёте

Pinning обходится инструментированным клиентом. Рекомендация — комбинировать pinning с App Attest, серверной валидацией и короткоживущими токенами.

## Квиз

```quiz
- question: "Какой символ Security.framework хукать для обхода pinning на iOS 12+?"
  options:
    - "SecTrustEvaluateWithError"
    - "CFNetworkCopySystemProxySettings"
    - "SSL_CTX_set_verify"
    - "NSLog"
  answer: 0
- question: "Что делает команда `ios sslpinning disable` в Objection?"
  options:
    - "Отключает pinning, патча несколько точек (Security, NSURLSession, TrustKit)"
    - "Сканирует порты"
    - "Делает бэкап"
    - "Дамп Keychain"
  answer: 0
- question: "Что нужно включить после установки CA-профиля на iOS?"
  options:
    - "Ничего"
    - "Certificate Trust Settings → доверие корню"
    - "Developer Mode"
    - "VPN"
  answer: 1
- question: "Где искать нативный pinning?"
  options:
    - "В Info.plist"
    - "В символах бинарника (SSL/OpenSSL/verify) и строках sha256/"
    - "В Manifest.db"
    - "В Keychain"
  answer: 1
- question: "Почему Burp может не видеть трафик даже с CA?"
  options:
    - "Приложение использует pinning или детектит proxy"
    - "Burp не работает с iOS"
    - "Нужен jailbreak для любого трафика"
    - "Нужно отключить Wi-Fi"
  answer: 0
```

## Где пригодится

- **Пентест iOS:** обязательный шаг для анализа API-трафика.
- **Bug bounty:** проверка API и логики через перехват.
- **Анализ:** разбор работы приложения.
- **CTF:** Mobile-задачи с pinning.
