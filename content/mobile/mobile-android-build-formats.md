---
id: mobile-android-build-formats
title: 'Модуль: форматы сборки Android'
category: mobile
parent: mobile-android-anatomy
difficulty: medium
order: 3
tags: [mobile, android, module]
prerequisites: []
useful_for:
  - 'Навигация по ветке'
  - 'Пентест мобильных приложений'
estimated_minutes: 10
summary: 'Современные форматы сборки Android: split APK, App Bundle, multidex, динамическая загрузка кода и reflection.'
---

## О чём этот этап

Этот этап — про то, как устроено современное Android-приложение. Оно разбито на сплиты,
поставляется как AAB, содержит несколько DEX, может грузить код и вызывать методы динамически.

## Что вы освоите

- Разбирать split APK и AAB
- Понимать multidex
- Находить динамическую загрузку кода
- Раскрывать reflection

## Как проходить

Начните со split и AAB — это то, что вы получите от Play. Затем multidex и динамика.

## Квиз

Проверь себя.

```quiz
- question: Что такое AAB?
  options:
    - Формат APK
    - Формат публикации приложения
    - Протокол
    - Библиотека
  answer: 1
  explanation: AAB публикуется в Play.
- question: Почему появляется multidex?
  options:
    - Из-за картинок
    - Из-за лимита методов на DEX
    - Из-за сети
    - Из-за root
  answer: 1
  explanation: Лимит 64K методов.
- question: Что делает DexClassLoader?
  options:
    - Ставит root
    - Грузит DEX в рантайме
    - Шифрует сеть
    - Подписывает
  answer: 1
  explanation: Он загружает код динамически.
```

## Куда дальше

Мы разобрали, как приложение устроено. Дальше — кросс-платформенные фреймворки и другие платформы.

## Где пригодится

- Реверс современных приложений из Play.
- Понимание форматов сборки.
- CTF Mobile.
