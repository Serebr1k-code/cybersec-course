---
id: mobile-storage-deep
title: "Хранилища, ключи и криптография"
category: mobile
parent: mobile-insecure-storage
difficulty: hard
order: 3
tags: [mobile, storage, keystore, crypto]
prerequisites: [mobile-insecure-storage]
useful_for:
  - "CTF: Mobile/Forensics"
  - "Пентест: хранение данных"
  - "Работа: криптоаудит"
estimated_minutes: 12
summary: "Этап про backup, Android Keystore и типичные ошибки криптографии."
---

Этот урок — **этап-навигатор** в ветке. Он короткий: его задача — объяснить, что вы будете изучать на этом этапе, почему темы идут именно в таком порядке и что вы сможете делать после прохождения.

## О чём этот этап

Первый этап глубокого анализа хранилищ: извлечение данных через backup/ADB, работа с Android Keystore и аппаратно-защищёнными ключами, и типичные ошибки криптографии в мобильных приложениях.

## Что вы освоите

- Backup-извлечение и злоупотребление ADB
- Android Keystore и аппаратно-защищённые ключи
- Ошибки криптографии в мобильных приложениях

## Как проходить

Начните с backup/ADB — быстрый доступ к данным. Затем Keystore и криптография: ищите слабые режимы, hardcoded IV/ключи и неверное использование API.

## Квиз

```quiz
- question: "Что позволяет извлечь резервная копия приложения?"
  options:
    - "Его приватные данные и настройки"
    - "Только иконки"
    - "Исходный код сервера"
    - "TLS-ключи сервера"
  answer: 0
  explanation: "Backup может содержать SharedPreferences, БД и файлы."
- question: "Где Android хранит ключи аппаратно?"
  options:
    - "В Android Keystore"
    - "В SharedPreferences"
    - "В APK"
    - "В логах"
  answer: 0
  explanation: "Keystore умеет держать ключи в защищённом железе (TEE/StrongBox)."
- question: "Что типично для ошибок криптографии в приложениях?"
  options:
    - "Hardcoded ключи и ECB-режим"
    - "Слишком длинный ключ"
    - "Использование TLS"
    - "Хеширование пароля"
  answer: 0
  explanation: "Зашитые ключи и ECB — классические слабости."
```

## Где пригодится

- **CTF:** Mobile/Forensics
- **Пентест:** хранение данных
- **Работа:** криптоаудит
