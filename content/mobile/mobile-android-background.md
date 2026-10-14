---
id: mobile-android-background
title: 'Модуль: фоновое выполнение Android и его абуз'
category: mobile
parent: mobile-android-ipc-runtime
difficulty: medium
order: 2
tags: [android, foreground-service, jobscheduler, syncadapter, accountmanager, persistence, module]
prerequisites: [mobile-android-ipc-runtime]
useful_for:
  - 'Навигация по ветке'
  - 'Пентест мобильных приложений'
estimated_minutes: 18
summary: 'Навигационный модуль: как приложение остаётся живым в фоне (foreground-сервисы, JobScheduler, SyncAdapter) и как через AccountManager утекают токены.'
---

Приложение, которое «закрыли», продолжает работать. Оно показывает постоянное уведомление,
синхронизируется по ночам, будит себя по расписанию и хранит аккаунты. Всё это — легальные
механизмы Android, но именно они дают атакующему персистентность и доступ к данным. Разберём
каждый по отдельности.

## Что покрывает модуль

1. **Foreground-сервисы** — сервис с уведомлением, который система не убивает.
2. **JobScheduler/WorkManager** — отложенные и периодические задачи.
3. **SyncAdapter** — фоновая синхронизация, привязанная к аккаунту.
4. **AccountManager** — хранение аккаунтов и выдача токенов.

## Почему такой порядок

Сначала — самый «громкий» механизм: foreground-сервис с уведомлением. Затем — тихие фоновые
задачи (JobScheduler). Потом — синхронизация, которая объединяет аккаунт и сеть. И в конце —
сам аккаунт и его токены, ради которых часто и затевается весь фон. Каждый следующий урок
опирается на предыдущий: job-ы используют аккаунты, sync — и то и другое.

## Чему вы научитесь

- Читать типы foreground-сервисов и их разрешения.
- Находить фоновые задачи и понимать, как они выживают после закрытия приложения.
- Видеть, где SyncAdapter может сливать данные.
- Проверять, не отдаёт ли AccountManager токены чужим вызовам.

## Связь с другими ветками

Для персистентности в целом смотрите `mobile-android-persistence`, для данных —
`mobile-data-leakage`, для цепочек — `mobile-exploit-chains`.

## Квиз

Проверь себя.

```quiz
- question: Какой механизм система «не убивает»?
  options:
    - Обычный сервис
    - Foreground-сервис с уведомлением
    - Broadcast
    - Activity
  answer: 1
  explanation: Foreground-сервис имеет повышенный приоритет и видимое уведомление.
- question: Чем JobScheduler отличается от AlarmManager?
  options:
    - Ничем
    - JobScheduler учитывает условия (сеть, заряд) и Doze
    - AlarmManager только для сети
    - JobScheduler работает без разрешений
  answer: 1
  explanation: JobScheduler планирует с учётом constraints, AlarmManager — точное время.
- question: Что хранит AccountManager?
  options:
    - Только пароли
    - Аккаунты и связанные с ними токены
    - Только контакты
    - Ничего
  answer: 1
  explanation: AccountManager хранит аккаунты и умеет выдавать auth-токены.
```

## Где пригодится

- Пентест Android-приложений (фон и персистентность)
- Bug bounty Android
