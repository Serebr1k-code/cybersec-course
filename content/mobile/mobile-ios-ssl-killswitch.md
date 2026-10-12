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

## Вопрос, с которого всё начинается

Ты настроил прокси, установил на устройство свой CA-сертификат — а приложение всё равно рвёт соединение и пишет «network error». Причина почти всегда одна: **certificate pinning** — приложение проверяет, что сервер предъявляет именно ожидаемый сертификат, и не доверяет твоему прокси. Как это обойти на iOS?

## Наш пример: DemoApp и его pinning

Вернёмся к `DemoApp`. В статике мы нашли строки и классы, связанные с сетью. Посмотрим на проверку сертификата:

```
$ strings -a DemoApp | grep -iE 'SecTrust|pin|cer'
SecTrustEvaluate
api.demo.example
```

Метод `SecTrustEvaluate` — это сердце проверки доверия на iOS. Когда приложение получает TLS-сертификат от сервера, система вызывает цепочку проверок, и `SecTrustEvaluate` выносит вердикт: доверять или нет. **Pinning** — это когда приложение не довольствуется системным вердиктом, а дополнительно сравнивает сертификат (или его хеш) с зашитым в приложении.

## Шаг 1: почему pinning мешает MITM

Обычный MITM (Man-in-the-Middle, «человек посередине») работает так: ты ставишь прокси (Burp/mitmproxy), устройство доверяет твоему CA, прокси подменяет сертификат сервера на свой, и трафик виден. Pinning ломает это звено: приложение видит, что сертификат подписан не ожидаемым ключом, и отклоняет соединение. Твой CA здесь ни при чём — приложению важен **конкретный** сертификат сервера.

## Шаг 2: SSL Kill Switch — готовый обход

Самый известный инструмент — **SSL Kill Switch 2**, твик для jailbreak-устройств. Он перехватывает проверки доверия на системном уровне и заставляет их всегда проходить. Устанавливается через Cydia/Sileo, включается в настройках. После включения приложения перестают замечать подмену сертификата.

Аналог для Objection:

```
$ objection -g com.demo.secapp explore
com.demo.secapp # ios sslpinning disable
(agent) Hooking SecTrustEvaluate
(agent) Hooking SecTrustEvaluateWithError
```

Objection хукает `SecTrustEvaluate` и связанные функции, подменяя вердикт на «доверять». Это быстрый путь: одна команда — и pinning снят.

## Шаг 3: Frida-хук на SecTrustEvaluate

Если Objection не сработал (кастомная проверка), пишем хук сами. Ключевая функция — `SecTrustEvaluate`, возвращает код `errSecSuccess` (0), если доверять:

```javascript
var SecTrustEvaluate = Module.findExportByName(null, 'SecTrustEvaluate');
if (SecTrustEvaluate) {
  Interceptor.attach(SecTrustEvaluate, {
    onLeave: function (retval) {
      retval.replace(0);   // errSecSuccess
    }
  });
}
```

Здесь `Module.findExportByName(null, ...)` ищет функцию во всех загруженных модулях (это C-функция из `Security.framework`), а `onLeave` меняет её возврат на `0` — «доверять». Тот же приём применяют к `SecTrustEvaluateWithError` и `SecTrustSetPolicies`.

## Шаг 4: если pinning реализован иначе

Иногда приложение не вызывает `SecTrustEvaluate` напрямую, а сравнивает хеш сертификата через `SecCertificateCopyData` и `CC_SHA256`. Тогда хукать нужно сравнение:

```javascript
var CC_SHA256 = Module.findExportByName(null, 'CC_SHA256');
Interceptor.attach(CC_SHA256, {
  onEnter: function (args) {
    this.out = args[1];   // буфер с результатом хеша
  },
  onLeave: function () {
    // подменяем вычисленный хеш на ожидаемый приложением
  }
});
```

Это сложнее: нужно знать ожидаемый хеш (он зашит в приложении) и подставить его. Часто проще найти саму функцию сравнения и вернуть «совпадает».

## Шаг 5: ATS и его обход

Отдельный слой — **ATS** (App Transport Security), политика iOS, запрещающая незашифрованный HTTP и слабые шифры. Мы уже видели в `Info.plist` нашего `DemoApp`:

```
$ python3 -c "import plistlib;d=plistlib.load(open('Info.plist','rb'));print(d['NSAppTransportSecurity'])"
{'NSAllowsArbitraryLoads': True}
```

`NSAllowsArbitraryLoads: True` означает, что ATS ослаблен и часть трафика может идти по HTTP. Это упрощает перехват: не нужен даже CA для таких запросов. Если ATS строгий, а pinning нет — достаточно установить CA; если есть pinning — обходим его хуком.

## Шаг 6: настройка перехвата

Полный порядок: включить прокси на устройстве (Wi-Fi → HTTP Proxy), установить и **доверить** CA-сертификат (Settings → General → About → Certificate Trust Settings), поставить Objection, выполнить `ios sslpinning disable`, запустить приложение и смотреть трафик в Burp. Если соединение всё равно рвётся — писать кастомный Frida-хук на конкретную проверку.

## Шаг 7: что смотреть в трафике

Когда pinning снят, приложение отдаёт всё: токены в заголовках `Authorization`, API-ключи, данные в теле запросов. Ищи:

- заголовки авторизации и их слабую защиту;
- параметры, передаваемые в открытом виде;
- эндпоинты, доступные без токена;
- ошибки сервера с внутренними деталями.

Это уже переход к тестированию API (см. `mobile-api-testing`).

## Шаг 8: если хук не сработал

Иногда после `ios sslpinning disable` соединение всё равно рвётся. Причины бывают разные. Во-первых, приложение может использовать **собственный** TLS-стек (например, BoringSSL внутри фреймворка), который не вызывает системный `SecTrustEvaluate`. Во-вторых, проверка может быть реализована в нативном коде и вызывать функции напрямую. В-третьих, приложение может проверять, что к нему не подключён отладчик, и отключаться.

Что делать: найти в статике, какая именно функция отвечает за проверку (по строкам и символам), и хукать её. Если это нативный код без экспорта, находят адрес в дизассемблере, вычисляют базовый адрес модуля и ставят хук по смещению. Это уже не «одна команда», а точечная работа, зато надёжная.

## Шаг 9: проверка результата

Как понять, что pinning действительно снят? Простейший признак — запросы в прокси появились, и приложение работает штатно. Дополнительно проверь, что сертификат сервера в цепочке — твой прокси-сертификат (Burp показывает свой issuer). Если видишь только CONNECT и `TLS handshake failed` — хук не сработал. Ещё один признак: приложение может «тихо» переключиться на резервный эндпоинт, поэтому стоит смотреть не только на появление трафика, но и на то, что функционал не деградировал. Если приложение продолжает работать, а в прокси видны расшифрованные запросы — цель достигнута. Если же трафик виден, но приложение через несколько секунд закрывается — значит, есть ещё одна проверка, которую нужно снять.

## Шаг 10: считаем pin, который надо обойти

Чтобы понять, что именно проверяет приложение, посчитай pin для своего MITM-сертификата. Самый распространённый вариант — SPKI-пиннинг (хеш публичного ключа, а не всего сертификата):

```
$ openssl x509 -in ca.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64
iLCSHnfZIMcQRfUoyTymSkyR25E4SrIzm/FW3VYMLsk=
```

Это значение — SHA-256 от DER-кодированного SubjectPublicKeyInfo. Именно его сравнивает приложение с захардкоженным (или полученным по pinning-заголовку) значением. Если хеш всего сертификата (`openssl x509 -outform der | openssl dgst -sha256`) отличается, значит pinning делается по сертификату, а не по ключу, — и подмена сертификата не поможет, нужен обход хуком или патч проверки. Зная формат pin, ты понимаешь, какой именно хук писать.

## Что мы теперь знаем

- Pinning заставляет приложение доверять только ожидаемому сертификату сервера.
- `SecTrustEvaluate` — центральная функция проверки доверия на iOS.
- SSL Kill Switch и `objection ios sslpinning disable` снимают pinning автоматически.
- Кастомный Frida-хук на `SecTrustEvaluate` возвращает `errSecSuccess` (0).
- Если pinning через сравнение хешей — хукают `CC_SHA256` или функцию сравнения.
- ATS (`NSAllowsArbitraryLoads`) — отдельный слой, облегчающий перехват.
- После снятия pinning трафик виден полностью.

## Квиз

Проверь себя.

```quiz
- question: Что такое certificate pinning?
  options:
    - "Шифрование трафика"
    - "Проверка приложением, что сервер предъявляет ожидаемый сертификат"
    - "Тип CA"
    - "Формат HTTP"
  answer: 1
  explanation: "Pinning не доверяет системному вердикту, а сверяет конкретный сертификат/его хеш."
- question: Какая функция iOS выносит вердикт о доверии сертификату?
  options:
    - "SecTrustEvaluate"
    - "CC_SHA256"
    - "NSUserDefaults"
    - "openURL"
  answer: 0
  explanation: "SecTrustEvaluate (и SecTrustEvaluateWithError) проверяет цепочку доверия."
- question: Какое значение возвращает SecTrustEvaluate при успехе?
  options:
    - "1"
    - "0 (errSecSuccess)"
    - "-1"
    - "true"
  answer: 1
  explanation: "errSecSuccess равен 0; хук подменяет возврат на 0, чтобы «доверять»."
- question: Что делает `objection ios sslpinning disable`?
  options:
    - "Отключает Wi-Fi"
    - "Хукает SecTrustEvaluate и снимает pinning"
    - "Удаляет сертификаты"
    - "Ставит jailbreak"
  answer: 1
  explanation: "Objection перехватывает проверки доверия и заставляет их проходить."
- question: Что означает NSAllowsArbitraryLoads в Info.plist?
  options:
    - "Запрет HTTP"
    - "Ослабленный ATS: разрешён незашифрованный HTTP"
    - "Включён pinning"
    - "Удалён Keychain"
  answer: 1
  explanation: "Это ослабление App Transport Security, упрощающее перехват трафика."
```

## Куда дальше

Pinning снят, трафик виден. Дальше — анализ API: какие эндпоинты, какие токены, где broken object level authorization (см. `mobile-api-testing`, `mobile-api-bola`). А пока главное запомни: pinning ломается хуком на `SecTrustEvaluate`, а `objection ios sslpinning disable` делает это одной командой.

## Где пригодится

- **Пентест:** перехват трафика защищённого приложения.
- **Bug bounty:** доказательство утечек в API.
- **CTF:** расшифровка трафика для получения флага.
- **Аудит:** проверка корректности pinning и ATS.
