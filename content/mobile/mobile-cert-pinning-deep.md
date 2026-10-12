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

## Вопрос, с которого всё начинается

Ты уже знаешь, что такое pinning и как в общем случае его снять. Но приложение использует нестандартный клиент: где-то проверка в конфиге, где-то в библиотеке, а где-то вообще в нативном коде. Как определить уровень и подобрать обход?

## Наш пример: приложение с pinning в трёх слоях

Возьмём защищённый клиент, в котором pinning реализован сразу на нескольких уровнях: конфигурация, HTTP-библиотека и нативный TLS-стек. Разберём каждый слой по отдельности — и поймём, почему «универсальный хук» иногда не помогает.

## Шаг 1: уровни pinning

Pinning встречается на четырёх уровнях, от простого к сложному:

1. **Network Security Config** — XML в ресурсах, `pin-set`.
2. **HTTP-библиотека** — `OkHttp CertificatePinner`, `Conscrypt`.
3. **Сторонняя библиотека** — TrustKit.
4. **Нативный TLS-стек** — OpenSSL/BoringSSL в `.so`.

Чем ниже уровень, тем сложнее обход: Java-хуки не видят нативный код. Поэтому первый шаг — **определить уровень**.

## Шаг 2: NSC pin-set

Простейший случай — pinning в конфиге. Файл `res/xml/network_security_config.xml` содержит:

```xml
<domain-config>
    <domain includeSubdomains="true">api.example.com</domain>
    <pin-set expiration="2027-01-01">
        <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
    </pin-set>
</domain-config>
```

Здесь приложение сравнивает хэш (SHA-256) открытого ключа сервера с ожидаемым. Обход — удалить блок `<pin-set>` из ресурсов и пересобрать APK. Либо хукнуть проверку в рантайме (Android реализует её на уровне сетевого стека, и она видна Java-хукам).

### Откуда берётся значение pin

Строка `AAAA...` — не случайный набор: это **хэш открытого ключа** сервера. Понимать, как его считают, полезно — иногда проще сравнить ожидаемый pin с реальным сертификатом, чем перехватывать проверку. Хэш берут не от всего сертификата, а от открытого ключа в формате DER (SPKI). Посчитаем сами:

```
$ openssl x509 -in c.pem -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary | openssl base64
EHK6rV0yqXTV+lrqqhrxMBA75pHqsSsEF3upIftoAa4=
```

Полученная строка — ровно то, что кладут в `<pin digest="SHA-256">` или в `CertificatePinner.add(host, "sha256/...")`. Если снять с сервера реальный ключ и посчитать такую же строку, её можно сравнить с зашитой в приложении: совпадение подтверждает, что pinning привязан именно к этому ключу.

Заодно проверим, какие TLS-библиотеки вообще есть в APK:

```
$ unzip -l app.apk | grep -iE '\.so' | grep -iE 'ssl|crypto|okhttp|trust'
```

Пустой список (типичная картина при системном Conscrypt) означает, что pinning — на Java-уровне, и хватает хука. Появление `libssl.so`/`libcrypto.so` — сигнал смотреть нативный уровень.

## Шаг 3: OkHttp CertificatePinner

Популярная библиотека **OkHttp** имеет собственный механизм pinning:

```java
CertificatePinner pinner = new CertificatePinner.Builder()
    .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .build();
OkHttpClient client = new OkHttpClient.Builder()
    .certificatePinner(pinner)
    .build();
```

Проверка происходит в методе `CertificatePinner.check(host, peerCertificates)`. Обход — перехватить его и ничего не делать:

```javascript
Java.perform(function () {
  var Pinner = Java.use("okhttp3.CertificatePinner");
  Pinner.check.overload("java.lang.String", "java.util.List")
    .implementation = function (host, certs) {
      console.log("[*] OkHttp pinner bypassed for " + host);
    };
});
```

Обратите внимание на `overload`: в разных версиях OkHttp сигнатура метода может отличаться (например, второй аргумент другого типа). Если хук не встаёт, Frida сообщит об ошибке — это подсказка уточнить сигнатуру.

## Шаг 4: TrustKit

**TrustKit** — библиотека, которая упрощает pinning. Она хранит конфигурацию (в т.ч. хэши) и проверяет сертификаты через свой `TrustManager`. Обход — найти методы TrustKit и перехватить их, либо (проще) перехватить стандартный `X509TrustManager`, если TrustKit делегирует проверку ему. Конфигурацию TrustKit можно также найти в ресурсах — там лежат ожидаемые хэши, и их наличие подсказывает, что pinning активен.

## Шаг 5: нативный pinning

Самый сложный слой — проверка в `.so` (OpenSSL/BoringSSL или собственный код). Признаки:

- приложение использует `libssl.so`/`libcrypto.so` или собственный `.so` с TLS;
- в jadx нет ни NSC `pin-set`, ни `CertificatePinner`, а трафик всё равно не перехватывается;
- в нативной библиотеке есть строки с хэшами или доменами.

Обход:

- **Хук нативной функции проверки** по имени или смещению (`Interceptor.attach`).
- **Подмена ожидаемого хэша** в памяти.
- **Перехват сравнения** — если проверка сводится к `memcmp`/`strcmp`, перехватить и вернуть «совпало».

Здесь пригодится всё, что мы разбирали про нативный реверс: `nm -D`, `strings`, Ghidra и `Interceptor`.

## Шаг 6: универсальный обход

На практике применяют комбинированный скрипт: он перехватывает `TrustManager`, OkHttp и Conscrypt сразу, а если не помогает — переходят к нативному уровню. Порядок действий:

1. **Определите уровень.** NSC → OkHttp → TrustKit → нативный.
2. **Начните с Objection** (`android sslpinning disable`) — он покрывает Java-уровни.
3. **Добавьте хук OkHttp**, если приложение его использует.
4. **Для нативного pinning** — хук `.so`.
5. **Проверьте трафик** в прокси после каждого шага.

Так вы не пишете всё сразу, а последовательно закрываете уровни, видя, где именно «застряло» соединение.

## Шаг 7: как определить уровень на практике

Полезные команды для разведки. Сначала смотрим, какие TLS-библиотеки вообще есть в APK:

```
$ unzip -l app.apk | grep -iE '\.so' | grep -iE 'ssl|crypto|okhttp|trust'
```

Если видите `libokhttp.so` или `libconscrypt` — Java-уровень; если `libssl.so`/`libcrypto.so` — вероятен нативный TLS. Дальше ищем конфигурацию и классы:

```
$ grep -rn 'pin-set\|CertificatePinner\|TrustKit' dec/ 2>/dev/null | head
```

Наличие `pin-set` в NSC, `CertificatePinner` в smali или строк TrustKit сразу указывает уровень. Если ничего не нашлось, а трафик не перехватывается — смотрите нативный код: `strings libfoo.so | grep -iE 'sha256|pin|sha/'`.

Такой триаж занимает минуты и избавляет от слепого перебора хуков.

## Шаг 8: почему в pin-set есть expiration

Обратите внимание на атрибут `expiration` в блоке `<pin-set>`. Он не случаен: pinning создаёт проблему — если сервер сменит сертификат, а приложение жёстко привязано к старому, оно перестанет работать. Поэтому задают срок: после `expiration` проверка отключается сама, и приложение может принять новый сертификат.

Для тестировщика это практический факт: посмотрите дату `expiration` — если она уже прошла, pinning, возможно, **неактивен**, и обход не нужен. А если дата близкая, разработчики готовятся к ротации ключей, и в конфиге могут быть сразу несколько `<pin>` (текущий и будущий) — тогда удалять нужно все.

## Что мы теперь знаем

По-простому:

1. Pinning бывает на четырёх уровнях: NSC, HTTP-библиотека, TrustKit, нативный TLS.
2. Java-хуки покрывают первые три; нативный уровень требует хука `.so`.
3. `CertificatePinner.check` — точка обхода для OkHttp; важна точная сигнатура.
4. Нативный pinning обходится перехватом функции или сравнения хэшей.
5. Сначала определяют уровень, потом подбирают обход.

## На что смотреть дальше

- **Определите уровень до хука.** Это половина успеха.
- **Смотрите ресурсы.** Хэши в NSC или TrustKit-конфиге — подсказка.
- **Проверяйте сигнатуры.** `overload` в Frida обязателен.
- **Нативный TLS — отдельная задача.** Java-хук здесь не поможет.

## Квиз

Проверь себя.

```quiz
- question: "Какой метод OkHttp отвечает за проверку pinning?"
  options:
    - "CertificatePinner.check"
    - "OkHttpClient.newCall"
    - "Request.Builder.get"
    - "Response.body"
  answer: 0
- question: "Где задаётся pinning в Network Security Config?"
  options:
    - "В блоке pin-set с хэшем ключа"
    - "В теге uses-permission"
    - "В теге activity"
    - "В strings.xml"
  answer: 0
- question: "Что такое TrustKit?"
  options:
    - "Библиотека для pinning, проверяющая сертификаты"
    - "Прокси-сервер"
    - "Формат APK"
    - "Тип эмулятора"
  answer: 0
- question: "Почему нативный pinning нельзя обойти Java-хуком?"
  options:
    - "Проверка выполняется в .so, вне Java-машины"
    - "Frida не поддерживает Android"
    - "Нужен Wi-Fi"
    - "Хук работает только на iOS"
  answer: 0
- question: "Зачем в Frida указывают overload?"
  options:
    - "Чтобы выбрать нужную сигнатуру метода среди нескольких"
    - "Чтобы ускорить скрипт"
    - "Чтобы сменить язык"
    - "Чтобы включить сеть"
  answer: 0
```

## Куда дальше

Мы разобрали pinning на всех уровнях. Дальше перейдём к инструментам Frida-скриптинга: как писать переиспользуемые скрипты, трассировать вызовы и автоматизировать рутину. А пока главное: pinning обходится по уровню, и умение определить уровень (конфиг, библиотека, нативный код) отличает быстрый обход от долгих переборов.

## Где пригодится

- **CTF Mobile:** обход нестандартного pinning для получения трафика.
- **Bug bounty:** MITM защищённых клиентов.
- **Пентест:** оценка стойкости pinning на разных уровнях.
- **Работа:** понимание, как разные библиотеки реализуют защиту транспорта.
