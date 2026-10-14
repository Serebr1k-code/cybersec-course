---
id: mobile-platforms-android
title: "Модуль: Android и устройство: анатомия, root и доверие"
category: mobile
parent: mobile-platforms
difficulty: medium
order: 1
tags: [mobile, module, roadmap]
prerequisites: [mobile-platforms]
useful_for:
- Пентест Android-приложений.
- CTF Mobile.
- Аудит мобильной безопасности.
estimated_minutes: 10
summary: "Анатомию android-приложения, привилегии и аппаратное доверие, root/загрузчик и телеком-радиослой устройства"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Android и устройство: анатомия, root и доверие»: анатомию Android-приложения, привилегии и аппаратное доверие, root/загрузчик и телеком-радиослой устройства.

- **mobile-android-anatomy** — Анатомия Android-приложения: APK, манифест, DEX и smali.
- **mobile-android-root** — Модуль: Root, загрузчик и модификация устройства.
- **mobile-android-trust** — Модуль: привилегии и аппаратное доверие Android.
- **mobile-telecom** — Модуль: телеком и радиослой мобильного устройства.

## Почему такой порядок

Android — самая распространённая мобильная платформа: сначала разбираем анатомию APK, затем модель доверия и модификацию устройства.

## Что вы сможете после этапа

- Разбирать структуру APK и манифест.
- Оценивать привилегии и цепочку доверия Android.

## Квиз

Проверь себя.

```quiz
- question: Что описывает AndroidManifest.xml?
  options:
    - "Компоненты, разрешения и точки входа"
    - "Только иконки"
    - "DEX-байткод"
    - "Базу данных"
  answer: 0
  explanation: Манифест объявляет компоненты и разрешения приложения.
- question: Что даёт root на Android?
  options:
    - "Возможность модифицировать систему и обходить проверки"
    - "Ускорение сети"
    - "Шифрование диска"
    - "Смену языка"
  answer: 0
  explanation: Root снимает ограничения песочницы приложения.
- question: Где хранятся ключи аппаратного доверия Android?
  options:
    - "В TEE/StrongBox через Keystore"
    - "В AndroidManifest.xml"
    - "В DEX"
    - "В ресурсах"
  answer: 0
  explanation: Keystore опирается на TEE/StrongBox.
```

## Где пригодится

- Пентест Android-приложений.
- CTF Mobile.
- Аудит мобильной безопасности.
