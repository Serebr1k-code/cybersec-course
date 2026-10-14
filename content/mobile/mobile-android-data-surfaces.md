---
id: mobile-android-data-surfaces
title: 'Модуль: поверхности утечки данных Android'
category: mobile
parent: mobile-android-ipc-runtime
difficulty: medium
order: 3
tags: [android, contentprovider, autofill, clipboard, shared-uid, leak, module]
prerequisites: [mobile-android-ipc-runtime]
useful_for:
  - 'Навигация по ветке'
  - 'Пентест мобильных приложений'
estimated_minutes: 18
summary: 'Навигационный модуль: как данные утекают через URI-permission grants, autofill, clipboard и общий UID — и как это искать в аудите.'
---

Даже когда компонент не экспортирован напрямую, данные могут утекать: приложение само отдаёт
доступ, менеджер паролей заполняет поля, буфер обмена хранит секреты, а два приложения делят один
UID. Этот модуль — про четыре таких канала.

## Что покрывает модуль

1. **URI-permission grants** — временный доступ к файлу через `content://`.
2. **Autofill** — как сервис автозаполнения видит и заполняет поля.
3. **Clipboard** — что остаётся в буфере обмена и кто это читает.
4. **Shared UID** — общий идентификатор приложений и его последствия.

## Почему такой порядок

Все четыре темы — про неявную передачу доступа. Сначала — явный grant (приложение само отдаёт
URI). Затем — autofill (доступ даёт сам пользователь, но приложение может его не ограничить).
Потом — clipboard (данные остаются в системе). И в конце — shared UID, где граница между
приложениями вообще стирается.

## Чему вы научитесь

- Понимать, как работает `FLAG_GRANT_READ_URI_PERMISSION` и когда он утекает.
- Видеть, как злоупотребить AutofillService.
- Проверять, не остаются ли секреты в буфере обмена.
- Оценивать риски общего UID.

## Связь с другими ветками

Для хранения данных — `mobile-insecure-storage`; для FileProvider — `mobile-android-fileprovider`;
для цепочек — `mobile-exploit-chains`.

## Квиз

Проверь себя.

```quiz
- question: Что даёт FLAG_GRANT_READ_URI_PERMISSION?
  options:
    - Постоянный root
    - Временный доступ к конкретному URI
    - Шифрование
    - Смену IMEI
  answer: 1
  explanation: Это временный grant на чтение переданного URI.
- question: Что видит AutofillService?
  options:
    - Только пароли
    - Структуру экрана и поля для заполнения
    - Ничего
    - Только сеть
  answer: 1
  explanation: Сервис получает AssistStructure с полями.
- question: Чем опасен общий UID?
  options:
    - Он медленный
    - Стирает границу между приложениями одного UID
    - Он шифрует данные
    - Он требует root
  answer: 1
  explanation: Приложения с общим UID видят данные друг друга.
```

## Где пригодится

- Пентест Android-приложений (утечки данных)
- Bug bounty Android
