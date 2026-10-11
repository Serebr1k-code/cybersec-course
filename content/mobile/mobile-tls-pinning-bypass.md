---
id: mobile-tls-pinning-bypass
title: "TLS pinning bypass: патч APK и Frida-скрипты"
category: mobile
parent: mobile-ssl-pinning
difficulty: hard
order: 3
tags: [tls, pinning, bypass, apk-patch, frida, apksigner, android]
prerequisites: [mobile-ssl-pinning, mobile-dynamic-frida]
useful_for:
  - "CTF Mobile (получение трафика/флага через MITM)"
  - "Bug bounty (перехват HTTPS защищённого клиента)"
  - "Пентест мобильных приложений"
estimated_minutes: 35
summary: "Два практических подхода к снятию TLS pinning: статический патч APK (Frida Gadget, правка конфига) и динамические Frida-скрипты; плюс настройка сертификата."
---
## Что такое certificate pinning и зачем обходить

Certificate pinning — механизм, при котором приложение доверяет **не любому** сертификату, подписанному системным CA, а только конкретному («закреплённому»): своему сертификату, публичному ключу или CA сервера. Это защита от MITM с пользовательским/подменённым CA. Для пентеста pinning — препятствие: без его обхода вы не увидите HTTPS-трафик и не найдёте уязвимости API. Обход обязателен на большинстве современных приложений.

Ментальная модель: pinning проверяет цепочку/ключ **в коде приложения**. Если код исполняется под вашим контролем (Frida, патч APK), проверку можно снять. Наиболее устойчив **нативный** pinning (в `.so`), но и он обходится.

## Типы pinning

| Тип | Что закреплено | Где искать |
|-----|----------------|-----------|
| Leaf pin | сам сертификат сервера | `network_security_config.xml` `<pin>` |
| CA pin | промежуточный/корневой CA | код + конфиг |
| Public-key pin (SPKI) | хэш публичного ключа | код (`sha256/...`) |
| TrustManager | кастомный `X509TrustManager` | `checkServerTrusted` |
| Нативный pin | проверка в `.so` | BoringSSL/Conscrypt, JNI |
| iOS | `SecTrustEvaluate`, AFNetworking | `Info.plist`/код |

```bash
grep -rn "CertificatePinner\|sha256/\|X509TrustManager\|checkServerTrusted\|setSSLSocketFactory" out_jadx | head
grep -rn "<pin" out/res/xml/network_security_config.xml
```

## Обход через Frida

Универсальные скрипты (напр. `frida-multiple-unpinning`, `frida-android-unpinning`) перехватывают типовые механизмы.

```javascript
Java.perform(function () {
  // OkHttp3 CertificatePinner
  try {
    var CP = Java.use('okhttp3.CertificatePinner');
    CP.check.overload('java.lang.String','java.util.List').implementation = function (h, p) {
      console.log('[+] bypass OkHttp pin ' + h); return;
    };
  } catch (e) {}

  // TrustManagerImpl (Conscrypt)
  try {
    var TM = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TM.verifyChain.implementation = function () { return arguments[0]; };
  } catch (e) {}

  // TrustManager
  try {
    var X = Java.use('javax.net.ssl.X509TrustManager');
    var TrustAll = Java.registerClass({
      name: 'com.x.TrustAll', implements: [X],
      methods: {
        checkClientTrusted: function () {},
        checkServerTrusted: function () {},
        getAcceptedIssuers: function () { return []; }
      }
    });
  } catch (e) {}
});
```

```bash
frida -U -f com.target.app -l unpin.js --no-pause
```

Быстрый старт — `objection ... android sslpinning disable`.

## Обход через патч APK

Когда Frida недоступна (или детектится), патчат `network_security_config.xml` и smali.

```bash
apktool d app.apk -o out
# 1. убрать пины из конфига
sed -i '/<pin-set/,/<\/pin-set>/d' out/res/xml/network_security_config.xml
# 2. заставить доверять user CA
# в <base-config> добавить:
#   <trust-anchors><certificates src="system"/><certificates src="user"/></trust-anchors>
# 3. пересобрать и подписать
apktool b out -o patched.apk
keytool -genkey -keystore k.keystore -alias k -keyalg RSA -keysize 2048 -validity 10000 -storepass pass -dname CN=x
zipalign -p 4 patched.apk patched-aligned.apk
apksigner sign --ks k.keystore --ks-pass pass patched-aligned.apk
adb install -r patched-aligned.apk
```

Минусы: ломается подпись (нужна переустановка, потеря данных), возможен anti-tamper, не работает для split APK без пересборки всех частей.

## Обход нативного pinning

Нативный pin (в `libssl.so`/кастомной `.so`) не ловится Java-хуками. Подходы:

- **Хук нативные функции:** `SSL_CTX_set_custom_verify`, `SSL_get_verify_result`, `X509_verify_cert`, `SSL_CTX_set_verify`.
- **Патч библиотеки:** найти проверку в дизассемблере и заменить (`NOP`/переход).
- **Frida Interceptor по символам:**

```javascript
var m = Process.getModuleByName('libssl.so');
['SSL_get_verify_result','X509_verify_cert','SSL_CTX_set_custom_verify'].forEach(function (n) {
  var p = Module.findExportByName('libssl.so', n);
  if (p) Interceptor.attach(p, { onLeave: function (r) { r.replace(ptr(0)); } });
});
```

Если символы скрыты (stripped), ищите по смещениям из реверса (`mobile-android-native`).

## iOS pinning bypass

```bash
objection -g com.target.app explore
ios sslpinning disable
```

Под капотом — хуки на `SecTrustEvaluate`, `SecTrustEvaluateWithError`, `URLSession:didReceiveChallenge:`, `AFSecurityPolicy`/`Alamofire`. Для Swift/нативного pinning может понадобиться ручной хук по символу (`mobile-ios-dynamic`).

## Проверка успеха обхода

Обход считается успешным, если:

1. Приложение продолжает работать (нет ошибок соединения).
2. В прокси (`mobile-mitm-burp`) виден расшифрованный HTTPS-трафик.
3. Повторяется стабильно после перезапуска.

Не ориентируйтесь только на вывод «bypass applied» — проверяйте реальный трафик.

## Разобранный пример: снять OkHttp pinning

```bash
$ grep -rn "CertificatePinner" out_jadx | head
NetworkModule.java: builder.certificatePinner(new CertificatePinner.Builder()
    .add("api.target.example","sha256/AAAA...=").build());
$ objection -g com.target.app explore --startup-command "android sslpinning disable"
(agent) [ssl] Hooking OkHttp3 CertificatePinner.check
(agent) [ssl] Hooking TrustManagerImpl.verifyChain
$ # в mitmproxy видим:
GET https://api.target.example/v1/me HTTP/1.1
Authorization: Bearer eyJ...   # трафик расшифрован
```

Pinning снят, трафик виден — можно тестировать API.

## Справочная таблица: методы обхода

| Механизм | Java-хук | Патч APK | Нативный хук |
|----------|----------|----------|--------------|
| OkHttp CertificatePinner | да | да (конфиг) | — |
| network_security_config pin | — | да | — |
| кастомный TrustManager | да | да | — |
| Conscrypt verifyChain | да | — | — |
| нативный pin (libssl) | нет | патч `.so` | да |
| iOS SecTrust | — | — | да (ObjC) |

## Типовые ошибки новичка

- **Только один метод.** Пиннинг бывает «многослойным» (OkHttp + нативный) — снимайте все.
- **Не проверять трафик.** «Bypass applied» ≠ «работает».
- **Забыть про user CA.** Без доверия CA прокси (system/Magisk) даже снятый pinning не даст расшифровки.
- **Игнорировать anti-tamper.** После патча APK приложение может отказаться работать.
- **Пропустить iOS.** Там другие API — нужны ObjC-хуки.

## Что дальше / решение

Порядок: определить тип pinning (конфиг/код/натив) → попробовать `objection`/Frida → при неудаче патч APK → при нативном — хук `.so`. После обхода — перейти к тестированию API (`mobile-api-testing`, `mobile-api-bola`). Связанные уроки: `mobile-ssl-pinning`, `mobile-cert-pinning-deep`, `mobile-mitm-burp`, `mobile-android-native`. Решение — когда HTTPS-трафик стабильно читается в прокси.

## Готовые скрипты и их адаптация

Наиболее известные публичные наборы: `frida-multiple-unpinning` (HTTP Toolkit), `frida-android-unpinning`, `universal-android-ssl-pinning-bypass`. Они хукают сразу десяток механизмов (OkHttp, Conscrypt, TrustManager, Appmattus, Netty, Squareup, нативные `SSL_get_verify_result`). Подключаются как обычный скрипт:

```bash
git clone https://github.com/httptoolkit/frida-android-unpinning
frida -U -f com.target.app -l frida-android-unpinning.js --no-pause
```

Проблемы: скрипт может конфликтовать с anti-Frida (детект) или ломать приложение при ошибке в хуке. Адаптируйте: уберите лишние хуки, оставьте только нужный, добавьте `try/catch`. Если приложение проверяет целостность перед запросом, одного unpinning недостаточно — снимайте и проверки целостности (`mobile-integrity`).

## Практический чек-лист обхода pinning

1. Определить, где pinning: `network_security_config.xml`, код (`CertificatePinner`, `X509TrustManager`), натив.
2. Убедиться, что прокси-CA доверен (system/Magisk на Android, профиль+Trust на iOS).
3. Попробовать `objection android sslpinning disable` / `ios sslpinning disable`.
4. Проверить трафик в прокси; если нет — применить Frida-скрипт.
5. При нативном pinning — хуки на `libssl`/`X509_verify_cert` или патч `.so`.
6. При детекте Frida — обойти детект (`mobile-frida-detection`) и повторить.
7. Зафиксировать: команда, скрипт, факт расшифровки трафика.

## Справочная таблица: диагностика «почему не работает»

| Симптом | Вероятная причина | Решение |
|---------|-------------------|---------|
| Пусто в прокси, приложение живо | pinning не снят | unpinning-скрипт |
| Ошибка сертификата в приложении | CA не доверен | system CA/Magisk |
| Приложение падает при инъекции | хук на отсутствующий класс | try/catch, точечный хук |
| Работает, но не для части домена | нативный pin | хук `.so` |
| Детект и выход | anti-Frida | переименовать/`gadget` |
| Только iOS не читается | не включён Trust | Certificate Trust Settings |

## Квиз

```quiz
- question: "Что делает TLS pinning?"
  options:
    - "Заставляет доверять только конкретному сертификату сервера"
    - "Ускоряет HTTPS"
    - "Шифрует пароли"
    - "Отключает Wi-Fi"
  answer: 0
  explanation: "Pinning мешает MITM, принимая лишь заданный ключ/сертификат."
- question: "Какая команда Objection снимает pinning на Android?"
  options:
    - "android sslpinning disable"
    - "android root disable"
    - "ios keychain dump"
    - "env"
  answer: 0
  explanation: "Команда ставит хуки на типовые реализации pinning."
- question: "Почему пользовательский CA не работает на Android 7+?"
  options:
    - "Приложения доверяют только системным CA по умолчанию"
    - "CA нельзя установить"
    - "TLS отключён"
    - "Нужен iOS"
  answer: 0
  explanation: "С Android 7 user-CA не учитывается для приложений без явной настройки."
- question: "Зачем переподписывать патченный APK?"
  options:
    - "Иначе система откажется установить/запустить"
    - "Чтобы ускорить"
    - "Чтобы сменить тему"
    - "Чтобы удалить pinning"
  answer: 0
  explanation: "Изменённый APK теряет исходную подпись."
- question: "Что позволяет Frida Gadget в APK без root?"
  options:
    - "Загружать Frida-скрипты в приложение"
    - "Удалять сертификаты"
    - "Сменить аккаунт"
    - "Разблокировать устройство"
  answer: 0
  explanation: "Gadget встраивается в APK и даёт Frida без root."
```

## Где пригодится

- **CTF Mobile:** перехват трафика/флага через MITM.
- **Bug bounty:** анализ защищённого клиента.
- **Пентест:** снятие клиентских защит.
- **Работа:** оценка устойчивости pinning.
