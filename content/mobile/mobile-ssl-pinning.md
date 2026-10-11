---
id: mobile-ssl-pinning
title: "Обход SSL Pinning: перехват HTTPS-трафика мобильного приложения"
category: mobile
parent: mobile-runtime-bypass
difficulty: medium
order: 2
tags: [android, ssl-pinning, mitm, frida, objection, certificate]
prerequisites: [mobile-dynamic-frida]
useful_for:
  - "CTF Mobile (перехват API-трафика)"
  - "Bug bounty (анализ мобильного API)"
  - "Пентест мобильных приложений"
estimated_minutes: 14
summary: "Почему прокси не видит трафик приложения, как работают certificate pinning и network security config, и как снять пиннинг через Frida/Objection, патч APK или системный сертификат."
---
## Что такое SSL Pinning и зачем его обходить

По умолчанию приложение доверяет системным корневым сертификатам, поэтому прокси с валидным для системы сертификатом может расшифровать HTTPS. SSL Pinning — механизм, при котором приложение доверяет только «зашитому» в него сертификату или публичному ключу сервера. Это защищает от перехвата через MITM-прокси: даже если вы добавите свой CA в систему, приложение откажется с ним работать. В пентесте и CTF pinning — первое, что нужно обойти, чтобы увидеть трафик. Цель модуля — освоить методы обхода pinning на Android и iOS.

## Уровни pinning

- **Certificate pinning** — приложение хранит сам сертификат (или его хеш) и сравнивает.
- **Public key pinning** — сравнивает публичный ключ (SPKI).
- **Leaf vs intermediate vs root** — что именно пинится.
- **Network Security Config** (Android) — XML с `pin-set`.
- **Нативный pinning** — проверка в `.so` через OpenSSL/BoringSSL.

Понимание уровня определяет метод обхода.

## Метод 1: Frida (универсальный)

Самый гибкий способ — перехватить функцию проверки и заставить её всегда возвращать «успех». Популярные скрипты: `frida-multiple-unpinning`, `universal-android-ssl-pinning-bypass`. Пример хука на OkHttp:

```javascript
Java.perform(function () {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
        console.log('Pinning bypassed for', a);
        return;
    };
});
```

Для нативного pinning перехватывайте `SSL_CTX_set_verify` или `X509_verify_cert` через `Interceptor`.

## Метод 2: Objection (быстро)

```bash
objection -g com.example.app explore
android sslpinning disable
```

Objection под капотом использует Frida и покрывает большинство популярных библиотек (OkHttp, TrustKit, Appmattus, Conscrypt). Это самый быстрый путь.

## Метод 3: Патч Network Security Config

Если pinning задан в `network_security_config.xml`, можно пропатчить его в smali и пересобрать APK:

```xml
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="system"/>
      <certificates src="user"/>
    </trust-anchors>
  </base-config>
</network-security-config>
```

Уберите `<pin-set>` и добавьте доверие к пользовательским сертификатам.

## Метод 4: Патч нативного кода

Если pinning в `.so`, найдите вызовы `SSL_CTX_set_custom_verify` или проверку хеша сертификата и пропатчьте (NOP/замена). В Ghidra найдите функцию, верните «успех».

## Настройка прокси и сертификата

```bash
# mitmproxy
mitmproxy -p 8080
# на устройстве прописать прокси на IP:8080
# установить сертификат mitmproxy в систему (Android 7+)
```

На Android 7+ пользовательские сертификаты не доверяются; используйте writable system или Magisk-модуль `MagiskTrustUserCerts`.

## iOS: особенности

На iOS pinning обходят через Frida (аналогичные скрипты) или через `objection`. Требуется джейлбрейк или пересборка приложения с отключённым pinning. Для `.ipa` иногда проще пропатчить бинарь.

## Типичные ошибки и подводные камни

- **Сертификат не в системном хранилище** — приложение его не видит.
- **Pinning в нативном коде** — Frida-скрипты для Java не помогут, нужен Interceptor.
- **Приложение детектит Frida** — комбинируйте с anti-anti-frida.
- **Неверная версия frida-server** — не запустится.
- **HTTP/2 и QUIC** — некоторые прокси не видят; используйте mitmproxy.
- **Забыть про Certificate Transparency** — редко, но бывает.
- **Патч ломает подпись** — пересоберите и подпишите.

## Справочная таблица

| Метод | Когда применять |
|-------|-----------------|
| Objection | быстрый обход популярных библиотек |
| Frida-скрипт | кастомный/нативный pinning |
| Патч NSC | pinning в XML |
| Патч `.so` | pinning в нативном коде |
| MagiskTrustUserCerts | доверие пользовательским CA |

## Что дальше / решение

План: сначала настройте прокси и системный сертификат, затем попробуйте Objection (`android sslpinning disable`), затем Frida-скрипты для конкретных библиотек, при нативном pinning — `Interceptor`. Если pinning в XML — патчите NSC. Держите под рукой коллекцию unpinning-скриптов. Без обхода pinning вы не увидите трафик, а значит — не найдёте IDOR/утечки в API, поэтому это обязательный шаг.

## Практический пример: обход pinning через Objection

Разберём сценарий. Вы настроили mitmproxy, добавили сертификат в систему, но приложение отказывается соединяться — pinning. Шаг 1: запускаем Objection: `objection -g com.example.app explore`. Шаг 2: выполняем `android sslpinning disable`. Шаг 3: приложение снова делает запросы, и в mitmproxy появляется расшифрованный HTTPS. Если не помогло, значит pinning в нативном коде — переходим к Frida и `Interceptor` на `SSL_CTX_set_verify`.

```javascript
var SSL_CTX_set_verify = Module.findExportByName('libssl.so', 'SSL_CTX_set_verify');
if (SSL_CTX_set_verify) {
    Interceptor.replace(SSL_CTX_set_verify, new NativeCallback(function () {
        return;
    }, 'void', ['pointer', 'int', 'pointer']));
}
```

Этот приём отключает проверку сертификата на уровне OpenSSL.

## Проблема Android 7+

Начиная с Android 7 приложения по умолчанию не доверяют пользовательским сертификатам. Поэтому даже без pinning ваш прокси-сертификат игнорируется. Решения: устройство с writable system (эмулятор), куда вы кладёте CA в `/system/etc/security/cacerts`; Magisk-модуль `MagiskTrustUserCerts`; или патч `network_security_config.xml`. Без этого шага обход pinning бессмысленен.

## Частые вопросы

«Objection не обходит?» — pinning нативный; нужен Frida. «Приложение детектит Frida?» — сначала обойдите детектор. «Не вижу трафик вообще?» — проверьте прокси и сертификат. «HTTP/2 не читается?» — используйте mitmproxy, он понимает h2. «iOS?» — джейлбрейк + Frida-скрипты.

## Что дальше / решение

Итог: обход pinning — обязательный шаг мобильного пентеста. Начните с Objection, при нативном pinning — Frida/Interceptor, при pinning в XML — патч NSC. Настройте системный сертификат (Android 7+). Без расшифрованного трафика вы не найдёте уязвимости в API, поэтому доведите этот шаг до конца.

## Расширенный чек-лист по обходу pinning

Порядок действий. Первое: настройте прокси и системный сертификат (Android 7+ — writable system или Magisk-модуль). Второе: попробуйте Objection (`android sslpinning disable`) — это покрывает OkHttp, TrustKit, Appmattus, Conscrypt. Третье: если не помогло, проверьте `network_security_config.xml` — возможно, pinning задан в XML, тогда патчите его. Четвёртое: если pinning в нативном коде, найдите вызовы `SSL_CTX_set_verify`/`X509_verify_cert` через Ghidra и перехватите их в Frida `Interceptor.replace`. Пятое: если приложение детектит Frida, сначала обойдите детектор. Шестое: проверьте, что трафик действительно идёт через прокси (HTTP/2, QUIC) — при QUIC может понадобиться отключить его на клиенте.

## Отдельные библиотеки pinning

Разные библиотеки требуют разных хуков: OkHttp — `okhttp3.CertificatePinner.check`; TrustKit — нативный `TSKPinningValidator`; Appmattus — `com.appmattus.certificatetransparency`; Conscrypt — `com.android.org.conscrypt`. Готовые unpinning-скрипты покрывают большинство; если библиотека кастомная, хукайте функцию сравнения сертификатов напрямую.

## Частые вопросы

«Трафик не расшифровывается, хотя pinning отключён?» — сертификат не в системном хранилище. «Приложение падает?» — детектор Frida. «Только часть запросов видно?» — QUIC/HTTP/2; отключите QUIC. «iOS?» — джейлбрейк + Frida-скрипты. «Как проверить, что обход сработал?» — в прокси появляются запросы.

## Что дальше / решение

Итог: обход pinning — обязательный шаг. Действуйте по каскаду: сертификат → Objection → патч NSC → нативный Interceptor → обход детекторов. Держите коллекцию unpinning-скриптов и умейте адаптировать их под конкретную библиотеку. Без расшифрованного трафика анализ API невозможен.

## Итог по SSL Pinning

Ключевые шаги: системный сертификат → Objection → патч NSC → нативный Interceptor → обход детекторов. Держите коллекцию unpinning-скриптов. Без расшифрованного трафика анализ API невозможен, поэтому доведите обход pinning до конца.

## Квиз

```quiz
- question: "Почему после установки CA-сертификата прокси трафик приложения не виден?"
  options:
    - "Прокси не поддерживает HTTPS"
    - "Включён SSL pinning: приложение проверяет конкретный сертификат сервера"
    - "Приложение использует HTTP"
    - "Сертификат установлен неправильно"
  answer: 1
- question: "Какой метод OkHttp чаще всего применяют для pinning?"
  options:
    - "TrustAllManager"
    - "CertificatePinner"
    - "HostnameVerifier"
    - "SSLContext"
  answer: 1
- question: "Что делает команда `android sslpinning disable` в Objection?"
  options:
    - "Удаляет сертификаты с устройства"
    - "Ставит Frida-хуки, снимающие pinning в рантайме"
    - "Пересобирает APK"
    - "Отключает Wi-Fi"
  answer: 1
- question: "Если Java-хуки не снимают pinning, где искать защиту?"
  options:
    - "В AndroidManifest.xml"
    - "В ресурсах"
    - "В нативном коде (`.so`), например в BoringSSL/OpenSSL"
    - "В Gradle-файлах"
  answer: 2
- question: "Почему Android 7+ не доверяет user-сертификатам для приложений с targetSdk ≥ 24?"
  options:
    - "Это баг Android"
    - "Так повысили безопасность: приложения доверяют только системным CA"
    - "Потому что user-сертификаты не поддерживают TLS"
    - "Потому что прокси требует root"
  answer: 1
```

## Где пригодится

- **CTF Mobile:** перехват API и поиск флага/токенов, спрятанных за пиннингом.
- **Bug bounty:** анализ мобильного API, IDOR/BOLA, поиск секретов в трафике — всё начинается с MITM.
- **Пентест:** оценка корректности реализации TLS в мобильном клиенте.
- **Работа:** проверка, что pinning настроен и не обходится тривиально (аудит защиты).
