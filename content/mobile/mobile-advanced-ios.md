---
id: mobile-advanced-ios
title: "Модуль: Углублённый разбор iOS (IPA, dylib, OAuth)"
category: mobile
parent: mobile-ios-security
difficulty: hard
order: 4
tags: [mobile, ios, roadmap]
prerequisites: [mobile-ios-security]
useful_for:
  - "CTF Mobile: задачи под iOS"
  - "Пентест iOS-приложений: от IPA до рантайма"
estimated_minutes: 8
summary: "Навигационный модуль по глубокому анализу iOS: разбор IPA и Mach-O, универсальные ссылки, инъекция динамических библиотек и OAuth/SSO в мобильном приложении."
---

Этот модуль — углубление в iOS после базового джейлбрейка и Keychain. Здесь вы работаете не с «примером на симуляторе», а с настоящим IPA: разбираете Mach-O, смотрите подписанные entitlements, инжектите свои dylib в рантайм, разбираете универсальные ссылки и OAuth-редиректы. Всё это — те места, где мобильное приложение доверяет данным извне и где чаще всего живут реальные уязвимости.

## Что покрывает модуль

- **mobile-ios-ipa-analysis** — структура IPA, Mach-O (fat/thin), `otool`/`codesign`/`class-dump`, entitlements, встроенные фреймворки.
- **mobile-universal-links** — Universal Links и App Links: ассоциация домена, обход проверки, перехват ссылок.
- **mobile-ios-dylib-injection** — инъекция dylib через `LC_LOAD_DYLIB`, `DYLD_INSERT_LIBRARIES`, sideload и re-sign.
- **mobile-ios-oauth-sso** — OAuth 2.0 / OIDC и SSO на iOS: custom URL scheme, PKCE, кража кода через редирект.

## Почему такой порядок

Статика IPA даёт карту приложения: где код, какие entitlements, какие URL-схемы. Универсальные ссылки и OAuth — логическое продолжение: это точки входа, которые описываются в статике, но проверяются в рантайме. Инъекция dylib замыкает круг: это основной способ заглянуть внутрь iOS-приложения без джейлбрейка, пересобрав его под себя.

## Что вы будете уметь

- Разбирать IPA и определять, какие фреймворки и entitlements использует приложение.
- Проверять ассоциацию Universal Links и находить обходы.
- Инжектить свою библиотеку в iOS-приложение через re-sign.
- Находить ошибки в OAuth-редиректах и PKCE-потоке.

## Квиз

```quiz
- question: "Что содержит файл IPA?"
  options:
    - "Скомпилированный Mach-O-бинарник, ресурсы и подпись"
    - "Только DEX-байткод"
    - "Только исходный код Swift"
    - "Только сертификат разработчика"
  answer: 0
- question: "Какая переменная окружения заставляет dyld загрузить стороннюю библиотеку?"
  options:
    - "DYLD_INSERT_LIBRARIES"
    - "ANDROID_DATA"
    - "LD_PRELOAD на iOS не существует"
    - "FRIDA_PATH"
  answer: 0
- question: "Что защищает OAuth-поток от перехвата кода авторизации?"
  options:
    - "PKCE (code_verifier/code_challenge)"
    - "Публичный client_secret в коде"
    - "Отключение TLS"
    - "Строка User-Agent"
  answer: 0
```

## Где пригодится

- **CTF:** Mobile/iOS-задачи с IPA, перехватом ссылок и OAuth.
- **Пентест:** аудит iOS-приложения от разбора бинарника до проверки редиректов.
- **Bug bounty:** поиск open redirect и кражи токена через custom URL scheme.
