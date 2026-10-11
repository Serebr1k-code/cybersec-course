---
id: mobile-network-security
title: "Модуль: Сетевая защита мобильных приложений"
category: mobile
parent: mobile-ssl-pinning
difficulty: medium
order: 2
tags: [android, ios, network-security-config, mitm, proxy, emulator, detection]
prerequisites: [mobile-ssl-pinning]
useful_for:
  - "Пентест мобильных приложений"
  - "Bug bounty"
  - "Анализ трафика"
estimated_minutes: 25
summary: "Навигационный модуль: сетевые механизмы защиты и их обход — Network Security Config, детект эмулятора/прокси, продвинутый MITM-перехват."
---
## Зачем отдельная ветвь по сети

Перехват мобильного трафика — центральный этап пентеста API. Базовый урок `mobile-ssl-pinning` и `mobile-mitm-burp` дают настройку CA и первый обход pinning. Но на практике всё упирается в дополнительные барьеры: Android **Network Security Config** (NSC), который жёстко задаёт доверенные CA и cleartext-политику; детект эмулятора и прокси; нестандартные сценарии (transparent proxy, VPN-based перехват, HTTP/2/QUIC). Эта ветвь закрывает именно эти барьеры.

Ментальная модель: приложение защищается на нескольких уровнях — (1) транспорт (pinning), (2) конфигурация доверия (NSC/ATS), (3) окружение (детект прокси/эмулятора), (4) протокол (QUIC/HTTP3, сертификаты pinning на уровне фреймворка). Обход — по каждому уровню отдельно.

## Карта ветви

| Урок | Что закрывает |
|------|---------------|
| `mobile-network-security-config` | атаки на NSC и обход cleartext/trust-политик |
| `mobile-emulator-detection` | детект эмулятора/прокси/отладки и обход |
| `mobile-mitm-advanced` | продвинутый MITM: transparent proxy, VPN, HTTP/2, QUIC |

Смежные: `mobile-ssl-pinning`, `mobile-cert-pinning-deep`, `mobile-tls-pinning-bypass`, `mobile-mitm-burp`.

## Network Security Config (NSC)

NSC — XML-файл (`res/xml/network_security_config.xml`), на который ссылается манифест. Он определяет: доверенные CA (системные/пользовательские), pinning на уровне конфига (`<pin-set>`), cleartext-политику (`cleartextTrafficPermitted`), исключения по доменам. Ключевая деталь: если NSC явно указывает `trust-anchors` только как `system`, пользовательский CA (Burp) **не** принимается — это и есть механизм, из-за которого на Android 7+ MITM не работает «из коробки».

```xml
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="system"/>
      <!-- нет src="user" -> пользовательский CA игнорируется -->
    </trust-anchors>
  </base-config>
</network-security-config>
```

Разбор атак и обходов — в `mobile-network-security-config`.

## Детект окружения

Приложения проверяют: запущен ли прокси (`System.getProperty("http.proxyHost")`, `ProxySelector`), эмулятор ли это (`Build.FINGERPRINT` содержит `generic`/`sdk`, наличие `/dev/socket/qemud`, `ro.kernel.qemu`), включена ли отладка, есть ли Frida (порты 27042, строки `frida`). Эти проверки ломают MITM даже при обойденном pinning. Как обходить — в `mobile-emulator-detection`.

## Продвинутый MITM

Иногда обычного Burp-прокси недостаточно: приложение игнорирует системный прокси, использует HTTP/2/HTTP/3 (QUIC), делает сетевые вызовы в нативном коде. Тогда применяют transparent proxy (iptables + mitmproxy), VPN-based перехват (mitmproxy в режиме `wireguard`), или `r0capture`/Frida-хук `SSL_write`. Подробно — в `mobile-mitm-advanced`.

## Что дальше / решение

Порядок: настроить CA → если приложение игнорирует пользовательский CA, разобрать NSC (`mobile-network-security-config`) → если падает на детекте окружения, обойти его (`mobile-emulator-detection`) → если прокси не видит трафик, перейти на transparent/VPN (`mobile-mitm-advanced`). Решение по умолчанию: mitmproxy (transparent) + Frida-хуки, потому что это покрывает большинство сценариев.

## Справочная таблица

| Уровень защиты | Механизм | Обход |
|----------------|----------|-------|
| Транспорт | pinning | Frida/Objection |
| Доверие | NSC/ATS | патч NSC / системный CA |
| Окружение | proxy/emulator detect | Frida-хуки |
| Протокол | HTTP/2, QUIC | transparent proxy, хуки |

| Инструмент | Роль |
|-----------|------|
| mitmproxy | перехват, transparent/VPN |
| Burp | перехват, плагины |
| Frida | хуки SSL/прокси-проверок |
| `iptables` | redirect трафика |

## Квиз

```quiz
- question: "Что определяет Network Security Config?"
  options:
    - "Доверенные CA, cleartext-политику и pinning на уровне конфига"
    - "Список портов"
    - "Разрешения приложения"
    - "Версию Android"
  answer: 0
- question: "Почему на Android 7+ пользовательский CA не принимается по умолчанию?"
  options:
    - "NSC по умолчанию доверяет только system-анкорам"
    - "Android удаляет CA"
    - "Burp несовместим"
    - "Нужен jailbreak"
  answer: 0
- question: "Что из перечисленного — детект окружения?"
  options:
    - "Проверка наличия прокси или признаков эмулятора"
    - "Проверка пароля"
    - "Проверка версии iOS"
    - "Проверка размера APK"
  answer: 0
- question: "Когда нужен transparent proxy вместо обычного?"
  options:
    - "Когда приложение игнорирует системный прокси или использует QUIC"
    - "Всегда"
    - "Только на iOS"
    - "Только для HTTP"
  answer: 0
- question: "Какой инструмент удобен для transparent/VPN-перехвата?"
  options:
    - "mitmproxy"
    - "apktool"
    - "jadx"
    - "frida-ios-dump"
  answer: 0
```

## Где пригодится

- **Пентест:** систематизация сетевого перехвата.
- **Bug bounty:** обход NSC/детекта для тестирования API.
- **Анализ малвари:** перехват C2-трафика.
- **CTF:** Mobile-задачи на сеть.
