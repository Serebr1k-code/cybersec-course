---
id: mobile-android-detect-proxy
title: 'Детект прокси: почему Burp «не работает»'
category: mobile
parent: mobile-android-runtime-detect
difficulty: medium
order: 3
tags: [android, proxy, burp, interception, network, bypass]
prerequisites: [mobile-android-network-security]
useful_for:
  - 'Пентест мобильных приложений (Android)'
  - 'Bug bounty Android'
  - 'CTF Mobile'
estimated_minutes: 38
summary: 'Как приложение замечает системный прокси, почему трафик не идёт через Burp и как перехватить его обходными способами.'
lab:
  kind: shell
  title: 'Практика: разбор детекта прокси'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, net_checks.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`net_checks.txt` — список сетевых проверок.'
    - 'Найди проверку, выдающую системный прокси.'
    - 'Рядом с ней — флаг `nto{...}`.'
---

## Вопрос, с которого всё начинается

Вы настроили Burp как прокси, установили сертификат — а приложение работает как ни в чём не
бывало и трафик не виден. Либо виден, но приложение показывает «подозрительная сеть». Как оно
понимает, что трафик перехватывают?

## Наш пример: проверка прокси

В коде видим:

```java
String host = System.getProperty("http.proxyHost");
String port = System.getProperty("http.proxyPort");
if (host != null) {
    // используется прокси
}
```

Системный прокси виден приложению через свойства `http.proxyHost`/`http.proxyPort` и через
`ProxySelector`. Если они заданы — приложение может отказаться работать или изменить поведение.

## Шаг 1: откуда приложение знает про прокси

Есть несколько источников. Первый — системные свойства Java (`http.proxyHost`,
`https.proxyHost`). Второй — `ProxySelector.getDefault()`. Третий — настройки Wi-Fi (прокси
задаётся в свойствах сети). Четвёртый — `ConnectivityManager` и `LinkProperties`, где указан
`ProxyInfo`. Приложение опрашивает эти источники и сравнивает с «обычным» состоянием.

## Шаг 2: как выглядит проверка

```java
ProxySelector ps = ProxySelector.getDefault();
List<Proxy> proxies = ps.select(new URI("https://example.com"));
for (Proxy p : proxies) {
    if (p.type() == Proxy.Type.HTTP) { /* прокси */ }
}
```

Если приложение видит HTTP-прокси, оно может отключить часть функций, требовать «чистую» сеть или
показывать предупреждение. Это не защита данных, а фильтр против перехвата.

## Шаг 3: почему Burp «не работает»

Даже если детект обойдён, трафик может не идти через прокси по другим причинам:

- Приложение использует собственный HTTP-стек, игнорирующий системный прокси (OkHttp с
  собственным `ProxySelector`, нативный `curl`).
- Включён certificate pinning — сертификат Burp отвергается (см. `mobile-ssl-pinning`).
- Приложение проверяет цепочку сертификатов или `networkSecurityConfig`.
- Используется QUIC/HTTP3, который идёт по UDP и не проксируется HTTP-прокси.

## Шаг 4: обход

- **Прозрачный прокси.** Перенаправление трафика на уровне iptables/`redsocks` на root-устройстве,
  без системных настроек прокси.
- **Frida.** Подменить результаты проверок прокси и `ProxySelector`.
- **Перехват на уровне сети.** Точка доступа с прозрачным прокси, маршрутизация на уровне роутера.
- **Отключить QUIC.** Заставить приложение использовать TCP (через firewall UDP 443).
- **Снять pinning.** Frida/objection/патч.

## Шаг 5: аудит

- Искать проверки `http.proxyHost`, `ProxySelector`, `LinkProperties`.
- Проверять, не ломает ли детект легитимные сценарии (корпоративный прокси!).
- Оценивать, есть ли pinning и `networkSecurityConfig`.
- Смотреть, не используется ли QUIC.

## Шаг 6: защита и пределы

Детект прокси повышает стоимость перехвата, но не защищает данные: на root-устройстве трафик
перенаправляется прозрачно. Настоящая защита — certificate pinning и шифрование на уровне
приложения. Детект же лишь усложняет MITM и отсекает простые попытки.

## Что мы теперь знаем

- Прокси виден через свойства, `ProxySelector`, `LinkProperties`.
- Приложение может отказаться работать через прокси.
- Burp не работает также из-за pinning и QUIC.
- Обход: прозрачный прокси, Frida, отключение QUIC, снятие pinning.
- Детект — фильтр, а не защита.

## Куда дальше

Мы разобрали детект прокси. Дальше — детект VPN, близкая проверка сетевого окружения.

## Шаг 7: NetworkSecurityConfig и его роль

Современный Android управляет доверием к сертификатам через `networkSecurityConfig`. Файл
`res/xml/network_security_config.xml` описывает, какие CA доверенные, разрешён ли cleartext и есть
ли pinning:

```xml
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="system"/>
      <certificates src="user" />
    </trust-anchors>
  </base-config>
  <domain-config>
    <domain includeSubdomains="true">api.example.com</domain>
    <pin-set>
      <pin digest="SHA-256">AAAA...=</pin>
    </pin-set>
  </domain-config>
</network-security-config>
```

Если в `trust-anchors` нет `src="user"`, пользовательский сертификат (Burp) не будет принят. Это
частая причина «Burp не работает», не связанная с детектом прокси. В аудите проверяйте конфиг: он
же показывает, включён ли pinning.

## Шаг 8: certificate pinning и его обход

Pinning означает, что приложение доверяет только конкретному сертификату/ключу сервера. Даже если
Burp выдаст валидный для системы сертификат, приложение его отвергнет. Обход: Frida-скрипты
(frida-multiple-unpinning, objection), патч smali, снятие проверки в нативном коде. Для pinning на
нативном уровне — hook `SSL_CTX_set_custom_verify`/`SSL_get_verify_result`. Подробнее —
`mobile-ssl-pinning`.

## Шаг 9: QUIC и HTTP/3

Многие приложения используют QUIC (HTTP/3) по UDP. Обычный HTTP-прокси его не видит, поэтому
трафик «пропадает». Решения: заблокировать UDP 443 (firewall), заставить приложение откатиться на
TCP; использовать прокси, поддерживающий QUIC; или анализировать на уровне пакетов с расшифровкой
ключей. Часто проще всего — блокировка UDP 443, после которой приложение идёт по HTTP/2 через
прокси.

## Шаг 10: реальный кейс

Кейс: приложение-банк не отправляло трафик через Burp. Причины оказались тройными: проверка
`http.proxyHost`, pinning и QUIC. Аналитики сначала обошли детект прокси (прозрачный прокси на
root), затем сняли pinning Frida-скриптом, затем заблокировали UDP 443, чтобы приложение ушло на
TCP. Только после этого трафик стал виден. Это типичная комбинация, которую стоит проверять
по очереди.

## Шаг 11: чек-лист

- Проверки `http.proxyHost`/`ProxySelector`/`LinkProperties`.
- `networkSecurityConfig` и `trust-anchors`.
- Наличие pinning.
- Использование QUIC.
- Свой HTTP-стек, игнорирующий системный прокси.
- Способы обхода: прозрачный прокси, Frida, блокировка UDP.

## Частые вопросы

**Почему Burp не видит трафик приложения?** Прокси-детект, pinning, QUIC или свой стек.

**Что делать первым?** Проверить `networkSecurityConfig` и снять pinning.

**Нужен ли root?** Для прозрачного прокси — часто да; для Frida — на эмуляторе/root-устройстве.

## Шаг 12: OkHttp и свой прокси

Большинство Android-приложений используют OkHttp. По умолчанию OkHttp берёт системный прокси, но
приложение может создать клиент с собственным `ProxySelector` или вовсе без прокси:

```java
OkHttpClient client = new OkHttpClient.Builder()
    .proxy(Proxy.NO_PROXY)
    .build();
```

`Proxy.NO_PROXY` заставляет OkHttp игнорировать системные настройки. Тогда Burp не увидит трафик,
даже если прокси настроен. Обход — прозрачное перенаправление на уровне iptables, потому что
приложение не спрашивает систему, куда идти, а ОС перенаправляет пакеты. В аудите ищите
`Proxy.NO_PROXY` и собственные `OkHttpClient` в коде.

## Шаг 13: нативный стек и pinning

Если приложение использует нативный HTTP-стек (например, `libcurl` или собственный TLS), прокси
тоже может игнорироваться. Плюс часто включают pinning на нативном уровне:
`SSL_CTX_set_verify` с кастомной проверкой или `SSL_CTX_set_custom_verify`. Обход — Frida-хуки на
эти функции, патч нативного кода или `frida-multiple-unpinning`. В Ghidra ищите строки
`SSL_get_verify_result`, `X509_verify_cert`, имена хостов и SHA-256 отпечатки.

## Шаг 14: инструменты перехвата

Кроме Burp, используют `mitmproxy`, `Charles`, `Fiddler`. Для прозрачного перехвата — `redsocks` +
iptables на root-устройстве: весь TCP перенаправляется на прокси без настройки системы. Для
эмулятора — прокси на уровне `-http-proxy` в AVD. Для сложных случаев — `objection` с командами
`android sslpinning disable` и `android proxy set`. Комбинируя инструменты, можно снять и детект, и
pinning, и увести трафик в прокси.

## Шаг 15: реальный кейс

Кейс: приложение использовало OkHttp с `Proxy.NO_PROXY` и pinning. Системный прокси не работал
вообще. Решение: root-эмулятор + iptables/redsocks для прозрачного перенаправления + Frida-скрипт
для снятия pinning. После этого трафик стал виден и позволил найти IDOR в API. Вывод: детект
прокси и pinning часто идут вместе и требуют комбинированного обхода.

## Шаг 16: чек-лист

- Проверки `http.proxyHost`/`ProxySelector`/`LinkProperties`.
- `Proxy.NO_PROXY` и собственные HTTP-клиенты.
- `networkSecurityConfig` и `trust-anchors`.
- Нативный pinning.
- QUIC/HTTP3.
- Инструменты: redsocks, objection, mitmproxy.

## Частые вопросы

**Почему прокси игнорируется, хотя настроен?** Приложение использует свой стек или `NO_PROXY`.

**Что делать, если pinning нативный?** Frida-хуки на функции проверки или патч.

**Нужен ли root?** Для прозрачного прокси и части хуков — часто да.

## Шаг 17: как это выглядит в Frida

Обход детекта прокси и pinning через Frida обычно начинают с универсального скрипта. Он хукает
`ProxySelector.getDefault`, `System.getProperty` для прокси-ключей и методы проверки сертификатов.
Пример идеи:

```javascript
Java.perform(function () {
  var System = Java.use('java.lang.System');
  System.getProperty.overload('java.lang.String').implementation = function (k) {
    if (k.indexOf('proxy') >= 0) return null;
    return this.getProperty(k);
  };
});
```

Такой хук возвращает «прокси нет» для всех проверок сразу. Для pinning используют готовые скрипты
(`frida-multiple-unpinning`) или `objection` (`android sslpinning disable`). Важно запускать
хуки до первого сетевого запроса — в `spawn`-режиме.

## Шаг 18: почему детект прокси так популярен

Прокси — самый простой способ перехватить трафик, поэтому приложения (особенно банки и
антифрод-сервисы) детектят его в первую очередь. Проверка дешёвая, ложных срабатываний немного
(обычный пользователь прокси не ставит), и она отсекает массовые попытки анализа. Именно поэтому
в аудите стоит ожидать эту проверку и заранее готовить прозрачный перехват.

## Шаг 19: итог

Детект прокси — фильтр против простого перехвата. Он не защищает данные, а лишь усложняет MITM,
который всё равно возможен через прозрачный прокси, снятие pinning и отключение QUIC. Проверяйте
`networkSecurityConfig`, pinning и QUIC в связке с проверками прокси — тогда трафик будет виден.
В следующем уроке мы разберём близкую проверку — детект VPN.

## Шаг 20: практический вывод

Порядок действий при перехвате Android-трафика прост. Сначала проверьте
`networkSecurityConfig` и снимите pinning. Затем заблокируйте UDP 443, чтобы отключить QUIC.
Потом настройте прозрачный прокси через iptables/redsocks. И только после этого боритесь с
детектом прокси через Frida. Если идти в обратном порядке, вы будете снимать проверки, но трафик
всё равно не увидите.

## Квиз

Проверь себя.

```quiz
- question: Что выдаёт системный прокси приложению?
  options:
    - Батарею
    - http.proxyHost/ProxySelector
    - Версию
    - IMEI
  answer: 1
  explanation: Свойства и ProxySelector описывают прокси.
- question: Почему Burp может не видеть трафик?
  options:
    - Из-за батареи
    - Из-за pinning, QUIC или своего стека
    - Из-за экрана
    - Из-за SIM
  answer: 1
  explanation: Pinning и QUIC обходят HTTP-прокси.
- question: Что такое прозрачный прокси?
  options:
    - Прокси без настроек, через iptables/redsocks
    - VPN
    - DNS
    - Firewall
  answer: 0
  explanation: Трафик перенаправляется на уровне ОС.
- question: Что надёжнее детекта прокси как защита?
  options:
    - Ничего
    - Certificate pinning
    - Смена пароля
    - Отключение Wi-Fi
  answer: 1
  explanation: Pinning защищает от подмены сертификата.
- question: Почему QUIC сложен для перехвата?
  options:
    - Он медленный
    - Он идёт по UDP и не проксируется HTTP-прокси
    - Он не шифруется
    - Он старый
  answer: 1
  explanation: HTTP-прокси работает с TCP.
```

## Где пригодится

- Перехват трафика Android-приложения.
- Обход anti-MITM защит.
- CTF Mobile: сетевой анализ.
