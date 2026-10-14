---
id: forensics-mobile-android-deep
title: "Модуль: Android — геолокация, уведомления, GMS и реверс"
category: forensics
parent: forensics-mobile
difficulty: hard
order: 4
tags: [forensics, mobile, android, location, notifications, gms, baseband, roadmap]
prerequisites: [forensics-mobile]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Мобильная форензика"
estimated_minutes: 13
summary: "Этап ветки «мобильные»: глубокий Android — история геолокации, уведомления, сервисы Google, базовая станция и реверс приложений."
---

Базовый Android мы разобрали. Теперь — глубокие источники, которые дают максимум в
расследовании: где был телефон, что приходило в уведомления, что делали сервисы Google,
к какой соте подключался и как устроено приложение.

## Что покрывает этот модуль

- **Геолокация** — история местоположений.
- **Уведомления** — тексты и источники.
- **GMS** — сервисы Google и их данные.
- **Baseband/соты** — подключения к сети.
- **Реверс приложений** — разбор APK.

## Рекомендуемый порядок изучения

1. `mobile-android-location` — где был телефон.
2. `mobile-android-notifications` — что приходило.
3. `mobile-gms` — сервисы Google.
4. `forensics-mobile-baseband` — соты и модем.
5. `mobile-android-strongbox` — аппаратные ключи.
6. `mobile-app-reversing` — разбор приложения.

## Что вы будете уметь

- Извлекать историю геолокации.
- Читать уведомления.
- Анализировать данные GMS.
- Сопоставлять с сотовой сетью.
- Разбирать APK.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Путь |
|----------|--------------------|------|
| `cache.cell`/`cache.wifi` | где был | Google Maps |
| `notification_log.db` | что приходило | system |
| GMS-базы | активность сервисов | GMS |
| `modem`-логи | соты | baseband |
| APK | логика приложения | `jadx` |

## Куда дальше

Открывай урок **«Android-геолокация»** — начнём с местоположения.
