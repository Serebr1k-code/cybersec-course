---
id: mobile-cert-pinning-deep
title: "Certificate pinning deep: OkHttp, TrustKit, нативный pinning"
category: mobile
parent: mobile-ssl-pinning
difficulty: expert
order: 4
tags: [pinning, ssl, okhttp, trustkit, network-security-config, frida, android]
prerequisites: [mobile-ssl-pinning, mobile-dynamic-frida]
useful_for:
  - "CTF Mobile (обход нестандартного pinning)"
  - "Bug bounty (MITM защищённого клиента)"
  - "Пентест мобильных приложений"
estimated_minutes: 45
summary: "Как устроен pinning на разных уровнях (network-security-config, OkHttp CertificatePinner, TrustKit, нативный OpenSSL/BoringSSL) и как обходить каждый слой."
---
## Введение

SSL pinning — это привязка доверия к конкретному сертификату или публичному ключу, а не к любому системному CA. Введение к pinning — в `mobile-ssl-pinning`; здесь разбираем **продвинутые** реализации и то, как обходить каждую. Это часто узкое место динамического анализа: без снятия pinning вы не увидите трафик приложения и не сможете тестировать API.

Pinning бывает на нескольких уровнях одновременно, и обход требует покрыть все. Если после Java-хуков трафик всё ещё не идёт — почти всегда виноват нативный слой или config-уровень.

## Уровни pinning

| Уровень | Реализация | Обход |
|---------|-----------|-------|
| Config | `network_security_config.xml` `<pin-set>` | патч/удаление конфига |
| Java-библиотека | OkHttp `CertificatePinner`, TrustKit, `HostnameVerifier` | Frida-хук |
| Кастомный | своя проверка цепочки/`TrustManager` | Frida-хук на конкретный метод |
| Нативный | OpenSSL/BoringSSL `X509_verify_cert`, `SSL_CTX_set_verify` | хук нативной функции |
| Double-pinning | Java + native вместе | обход обоих слоёв |

```bash
apktool d app.apk -o app
cat app/res/xml/network_security_config.xml 2>/dev/null
grep -rn 'networkSecurityConfig' app/AndroidManifest.xml
grep -rniE 'CertificatePinner|TrustKit|sha256/|pin-set|HostnameVerifier' app/smali app/res 2>/dev/null | head
```

## Java-уровень: OkHttp, TrustKit, HostnameVerifier

```javascript
Java.perform(function () {
  try {
    var CP = Java.use('okhttp3.CertificatePinner');
    CP.check.overload('java.lang.String', 'java.util.List').implementation = function (h, p) { return; };
    CP.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function (h, f) { return; };
  } catch (e) { console.log('okhttp3 not found: ' + e); }

  try {
    var TK = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
    TK.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) { return true; };
  } catch (e) {}

  var X509TM = Java.use('javax.net.ssl.X509TrustManager');
  // хук на конкретной реализации — ищем класс в jadx
});
```

Objection делает это одной командой: `android sslpinning disable` (и `ios sslpinning disable`).

## Нативный уровень: OpenSSL/BoringSSL

Если pinning реализован в `.so` через OpenSSL, Java-хуки не помогут.

```javascript
var symbols = ['X509_verify_cert', 'SSL_CTX_set_verify', 'X509_check_issued', 'SSL_get_verify_result'];
symbols.forEach(function (name) {
  var f = Module.findExportByName(null, name);
  if (f) {
    Interceptor.attach(f, { onLeave: function (ret) { ret.replace(ptr(1)); } });
  }
});
Module.enumerateExportsSync('libssl.so').forEach(function (e) {
  if (e.name.indexOf('verify') >= 0) console.log(e.name + ' @ ' + e.address);
});
```

Иногда pinning — сравнение хэшей сертификата в кастомной функции. Тогда хукайте `memcmp`/`strcmp`/`SSL_get_peer_certificate` и подменяйте результат.

## Config-уровень и double-pinning

```bash
# патч network security config: убрать <pin-set>, добавить системные CA
apktool b app -o app_patched.apk
apksigner sign --ks my.keystore app_patched.apk
```

Для **double-pinning** нужно снять оба слоя: сначала Java-хуки, затем нативные. Готовые скрипты: `frida-multiple-unpinning`, `disable-flutter-tls`, `frida-ios-dump` (iOS).

## iOS-уровень

На iOS pinning реализуют через `NSURLSession` делегаты (`didReceiveChallenge`), TrustKit, Alamofire `ServerTrustPolicy`, либо нативно (Security.framework). Обход:

```javascript
// хук проверки доверия
var C = ObjC.classes.NSURLSession;
// обычно хук на метод делегата urlSession:didReceiveChallenge:completionHandler:
// и принудительная отдача NSURLSessionAuthChallengeUseCredential
```

Либо Frida-скрипт `ios-ssl-bypass`, либо Objection `ios sslpinning disable`.

## Разобранный пример

```bash
# 1. Прокси настроен, CA установлен, но соединения нет -> pinning
grep -rniE 'CertificatePinner|X509_verify|pin-set' app/ | head
# 2. Комбинированный скрипт: OkHttp + TrustKit + OpenSSL
frida -U -f com.target.app -l unpin_all.js
# 3. Проверяем трафик в mitmproxy/Burp — теперь видно HTTPS
```

## Частые ошибки и подводные камни

- **Хукать только Java** — нативный pinning останется и оборвёт соединение.
- **Забыть про `network_security_config`** — иногда pinning задан только там.
- **Не искать double-pinning** — если после Java-хука трафик не идёт, смотрите нативку.
- **Ломать сигнатуру OkHttp-метода** — версии разные, проверяйте `overloads`.
- **Патчить APK без переподписи** — пересобранный APK не установится без `apksigner`.
- **Игнорировать Flutter/RN** — у них свой TLS-стек, нужен reFlutter/специальные хуки.

## Справочная таблица

| Инструмент | Назначение |
|-----------|-----------|
| Objection | `android/ios sslpinning disable` |
| frida-multiple-unpinning | комплексный скрипт |
| reFlutter | Flutter TLS |
| apk-mitm | автоматический патч APK |
| mitmproxy/Burp | просмотр трафика |

## Что дальше / решение

- Трафик не идёт после Java-хуков → ищите нативный pinning.
- Pinning только в config → патч + переподпись.
- Flutter/RN → специфичные инструменты.
- Сняли pinning → переходите к анализу API (IDOR/BOLA, логика).

## iOS pinning: реализации и обход

На iOS pinning встречается в нескольких формах:

- **NSURLSession delegate** `urlSession:didReceiveChallenge:completionHandler:` — кастомная проверка `serverTrust`. Обход — подмена completion на `NSURLSessionAuthChallengeUseCredential` с `serverTrust`.
- **TrustKit** — тот же делегат, но конфигурируемый.
- **Alamofire `ServerTrustPolicy`/`PinnedCertificatesTrustEvaluator`** — проверка внутри библиотеки.
- **Нативный Security.framework** — `SecTrustEvaluate`/`SecTrustEvaluateWithError`.

```javascript
// обход проверки доверия на уровне Security.framework
var SecTrustEvaluate = Module.findExportByName(null, 'SecTrustEvaluate');
if (SecTrustEvaluate) {
  Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
    return 0; // errSecSuccess
  }, 'int', ['pointer', 'pointer']));
}
```

Быстрый путь — Objection: `ios sslpinning disable`.

## Flutter и React Native: свой TLS-стек

Flutter использует BoringSSL внутри `libflutter.so` и по умолчанию **не доверяет** пользовательским CA и не использует системный прокси. Поэтому обычный MITM не работает. Решения:

```bash
# патч libflutter.so для доверия вашему CA
reFlutter app.apk
# либо хук на verify-функции внутри libflutter.so
```

React Native обычно использует OkHttp (Android) / NSURLSession (iOS) — тогда применимы стандартные Java/ObjC-хуки. Но если включён кастомный TLS (например, `react-native-ssl-pinning`), нужно хукать его мост.

## Автоматизация снятия pinning

- **apk-mitm** — автоматически патчит APK (network security config + smali), пересобирает и подписывает.
- **frida-multiple-unpinning** — один скрипт покрывает OkHttp, TrustKit, Conscrypt, нативку.
- **objection** — `android sslpinning disable` / `ios sslpinning disable`.
- **medusa / house** — фреймворки с готовыми модулями.

```bash
apk-mitm app.apk           # на выходе app-patched.apk
objection -g com.target.app explore -c "android sslpinning disable"
```

## Расширенный разобранный пример

Дано: банковское приложение, MITM не работает, в коде найден `CertificatePinner` и нативная проверка.

```javascript
// unpin_all.js
Java.perform(function () {
  try {
    var CP = Java.use('okhttp3.CertificatePinner');
    CP.check.overload('java.lang.String', 'java.util.List').implementation = function () {};
  } catch (e) {}
  try {
    var TM = Java.use('com.target.security.PinningTrustManager');
    TM.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String')
      .implementation = function () {};
  } catch (e) {}
});
['X509_verify_cert', 'SSL_get_verify_result', 'X509_check_issued'].forEach(function (n) {
  var f = Module.findExportByName(null, n);
  if (f) Interceptor.attach(f, { onLeave: function (r) { r.replace(ptr(1)); } });
});
```

```bash
frida -U -f com.target.app -l unpin_all.js
mitmproxy -p 8080   # теперь трафик виден
```

## Что делать дальше

- Если Java-хуки не помогли — ищите нативный слой и config.
- Для Flutter/RN — специфичные инструменты (reFlutter).
- После снятия pinning переходите к анализу API: IDOR/BOLA, логика, утечки.

## Проверка результата

После снятия pinning убедитесь, что трафик действительно виден и не оборван на середине:

```bash
mitmproxy -p 8080 --set confdir=~/.mitmproxy
# в приложении выполните действие, которое ходит в сеть
# в mitmproxy ищите запросы к api.* — они должны появляться
```

Если часть запросов видна, а часть нет — вероятно, остался второй слой pinning (нативный) или запрос идёт по другому стеку (WebView, Flutter). Зафиксируйте, какой именно канал защищён.

## Квиз

```quiz
- question: "Где может быть задан pinning помимо кода?"
  options:
    - "В network_security_config.xml (<pin-set>)"
    - "В AndroidManifest.xml"
    - "В strings.xml"
    - "В build.gradle"
  answer: 0
- question: "Какой класс OkHttp отвечает за pinning?"
  options:
    - "okhttp3.CertificatePinner"
    - "okhttp3.OkHttpClient"
    - "javax.net.ssl.SSLContext"
    - "android.webkit.WebView"
  answer: 0
- question: "Как обходить нативный pinning на OpenSSL/BoringSSL?"
  options:
    - "Хуками на X509_verify_cert / SSL_get_verify_result с подменой возврата"
    - "Java.use('CertificatePinner')"
    - "Переустановкой приложения"
    - "Отключением Wi-Fi"
  answer: 0
- question: "Что такое double-pinning?"
  options:
    - "Pinning одновременно на Java- и нативном уровне — нужен обход обоих"
    - "Двойной сертификат"
    - "Два прокси"
    - "Pinning только на iOS"
  answer: 0
- question: "Что нужно после патча network security config в декодированном APK?"
  options:
    - "Пересобрать (apktool b) и подписать (apksigner)"
    - "Просто установить"
    - "Запустить на симуляторе"
    - "Удалить META-INF"
  answer: 0
```

## Где пригодится

- **CTF Mobile:** снятие нестандартного pinning для получения трафика/флага.
- **Bug bounty:** MITM защищённых клиентов банков/платежей.
- **Пентест:** оценка MASVS-NETWORK, проверка стойкости pinning.
- **Работа:** понимание слоёв pinning при code review клиентов.
