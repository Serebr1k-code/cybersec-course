---
id: mobile-android-instant-apps
title: 'Android Instant Apps: поверхность атаки'
category: mobile
parent: mobile-android-art-formats
difficulty: hard
order: 3
tags: [android, instant-apps, app-links, deeplink, split-apk, surface]
prerequisites: [mobile-android-odex-unpack]
useful_for:
  - 'Пентест Android-приложений'
  - 'Аудит ссылок'
  - 'CTF Mobile'
estimated_minutes: 38
summary: 'Как работает запуск приложения без установки, из чего состоит Instant App и почему deep-link становится границей доверия.'
lab:
  kind: shell
  title: 'Практика: аудит App Links'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, applinks.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Осмотри файл: `ls -la`, затем `cat applinks.txt`.'
    - 'Определи, верифицирован ли домен приложения.'
    - 'Рядом с неверифицированным доменом лежит флаг — запиши в `found.txt`.'
---

## Вопрос, с которого всё начинается

Пользователь нажимает ссылку — и приложение открывается **мгновенно**, хотя оно не
установлено. Потом иконка исчезает. Это **Instant Apps**. Удобно — но если код приходит
по ссылке и запускается почти без установки, то **где здесь граница доверия и что
можно подсунуть пользователю?**

## Наш пример: ссылка, открывающая «мгновенное» приложение

Есть магазин, у которого есть обычное приложение и Instant-версия. Ссылка вида
`https://shop.example.com/item/42` открывает карточку товара, не устанавливая
приложение целиком.

```bash
$ adb shell pm list packages | grep instant
(пусто — пока не запускали)
```

Запустим ссылку и посмотрим, что изменилось:

```bash
$ adb shell am start -a android.intent.action.VIEW -d https://shop.example.com/item/42
Starting: Intent { act=android.intent.action.VIEW dat=https://shop.example.com/item/42 }
$ adb shell pm list packages | grep instant
package:com.example.shop.instant
```

Появился пакет `.instant`. Приложение загрузилось по ссылке.

## Шаг 1: из чего состоит Instant App

Instant App — это **не один APK**, а набор модулей: базовый плюс «фичи». При запуске
скачивается только нужная фича — поэтому быстро. Установка в обычном смысле не
происходит: код кладётся во временное хранилище и живёт ограниченное время.

```bash
$ adb shell pm path com.example.shop.instant
package:/data/app/~~tmp/com.example.shop.instant-1/base.apk
```

Ключевое: приложение живёт в ограниченной песочнице с урезанными разрешениями.

## Шаг 2: App Links — мост из браузера в приложение

Связь «ссылка → приложение» держится на **Android App Links**: приложение заявляет
домены, которые умеет открывать, и система проверяет их через `assetlinks.json` на
сайте.

```bash
$ adb shell dumpsys package domain-preferred-apps | grep -A3 shop
Package: com.example.shop
  Domains: shop.example.com
  Status: verified
```

Если верификация не проходит, система может спросить пользователя, каким приложением
открыть ссылку. Именно здесь появляется поверхность: **чужое приложение может
претендовать на тот же домен**, если проверка домена не настроена.

## Шаг 3: где ломается доверие

Три типовые проблемы Instant-приложений:

1. **Непроверенные App Links.** Если `assetlinks.json` отсутствует или неверен,
   система не гарантирует, что ссылку откроет именно нужное приложение. Злоумышленник
   регистрирует обработчик и получает переходы.
2. **Параметры deep-link без валидации.** Instant App разбирает URL и сразу выполняет
   действие. Если `?redirect=` или путь передаётся дальше без проверки — возможен
   переход на чужой экран или утечка токена.
3. **Доверие к «временному» контексту.** Раз приложение не установлено, часть проверок
   целостности может быть мягче; разработчики иногда ослабляют защиту в Instant-версии.

## Шаг 4: как это проверять

Практический чек-лист:

```bash
# какие ссылки приложение заявляет
$ adb shell dumpsys package com.example.shop.instant | grep -i -A2 "intent-filter"
# проверка assetlinks
$ curl -s https://shop.example.com/.well-known/assetlinks.json | head
```

Дальше — руками: собрать ссылки с неожиданными параметрами (`?redirect=`, `?url=`,
подмена пути) и посмотреть, что открывается. Инструмент тут не решает — решает
понимание потока «ссылка → разбор → действие».

## Что мы теперь знаем

- Instant App запускается по ссылке без установки, состоит из модулей.
- Работает в ограниченной песочнице с урезанными разрешениями.
- Связь с доменом держится на Android App Links и `assetlinks.json`.
- Непроверенный домен и невалидированные параметры — основные слабости.
- Проверять надо `dumpsys` + `assetlinks.json` + ручной перебор параметров ссылки.

## Квиз

Проверь себя.

```quiz
- question: Что такое Instant App?
  options:
    - Приложение из одного APK
    - Набор модулей, запускаемый по ссылке без полной установки
    - Виджет
    - Служба
  answer: 1
  explanation: Instant App скачивает нужную фичу по ссылке и живёт во временном хранилище.
- question: Что связывает домен с приложением?
  options:
    - Android App Links и assetlinks.json
    - SharedPreferences
    - AndroidManifest meta-data
    - SMS
  answer: 0
  explanation: Верификация домена идёт через assetlinks.json, заявленный в манифесте.
- question: Чем опасен непроверенный App Link?
  options:
    - Медленным запуском
    - Ссылку может перехватить чужое приложение
    - Потерей данных
    - Разрядом батареи
  answer: 1
  explanation: Без верификации домена обработчик может зарегистрировать кто угодно.
- question: Где искать заявленные ссылки?
  options:
    - В dumpsys package
    - В логах Wi-Fi
    - В кэше браузера
    - В контактах
  answer: 0
  explanation: dumpsys package показывает intent-filter и домены приложения.
- question: Что делать с параметрами deep-link?
  options:
    - Игнорировать
    - Проверять валидацию (redirect, url, путь) — возможна утечка или переход
    - Удалить
    - Зашифровать
  answer: 1
  explanation: Невалидированные параметры ссылки — типовой источник уязвимостей.
```

## Куда дальше

Мы закончили с форматами и поставкой. Дальше логично вернуться к анализу рантайма и
защите от него — хукингу и обнаружению. А пока запомни: **Instant App — это код по
ссылке; ссылка и есть граница доверия, которую надо проверять**.

## Где пригодится

- **Пентест:** Android, аудит deep-link и App Links
- **Аудит ссылок:** верификация доменов
- **CTF:** Mobile
