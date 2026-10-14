---
id: mobile-android-ipc-runtime
title: 'Модуль: IPC, фоновое выполнение и рантайм-поверхности Android'
category: mobile
parent: mobile-android-components
difficulty: medium
order: 6
tags: [android, ipc, intent, broadcast, background, detection, roadmap, module]
prerequisites: [mobile-exported-components]
useful_for:
  - 'Навигация по ветке'
  - 'Пентест мобильных приложений'
estimated_minutes: 20
summary: 'Навигационный модуль второго уровня: неявные интенты и рассылки, фоновое выполнение (сервисы, JobScheduler), поверхности утечки данных (autofill, clipboard, grants) и детект рантайма (debug/emulator/proxy/VPN).'
---

Первый уровень Android-IPC (экспортированные компоненты, Binder, PendingIntent) вы уже прошли.
Этот модуль собирает темы, которые живут *на стыке* IPC, фонового выполнения и проверок среды:
приложение думает, что общается само с собой или что его не видят, — а на деле его команды и
данные доступны снаружи.

## Что покрывает модуль

1. **Неявные интенты и рассылки** — перехват действий, protected/sticky broadcast, overlay.
2. **Фоновое выполнение** — foreground-сервисы, JobScheduler/WorkManager, SyncAdapter, AccountManager.
3. **Поверхности утечки данных** — URI-grants, autofill, clipboard, shared UID.
4. **Детект рантайма** — debug, emulator, proxy, VPN: как приложение прячется и как это снять.

## Почему такой порядок

Сначала — как приложение отдаёт команды наружу (интенты/рассылки). Затем — как оно остаётся
живым и что делает в фоне. Потом — где текут данные. И в конце — как оно проверяет среду, чтобы
вы понимали, почему на стенде что-то «не работает», и умели это обойти. Каждый блок — отдельный
модуль с четырьмя уроками.

## Чему вы научитесь

- Находить перехватываемые действия и незащищённые receiver-ы.
- Понимать, как фоновые механизмы используются для персистентности и абуза.
- Строить цепочки «данные наружу» через autofill/clipboard/grants.
- Обходить детект отладки, эмулятора и прокси.

## Связь с другими ветками

Продвинутые IPC-транзакции — в `mobile-android-binder`; защита приложений — в
`mobile-app-protection`; цепочки — в `mobile-exploit-chains`.

## Квиз

Проверь себя.

```quiz
- question: Что объединяет темы этого модуля?
  options:
    - Только сеть
    - Границы доверия в IPC, фоне и проверках среды
    - Только UI
    - Только криптография
  answer: 1
  explanation: Все четыре блока — про то, где доверие проходит не там, где кажется.
- question: С чего начинать модуль?
  options:
    - С детекта
    - С неявных интентов и рассылок
    - С clipboard
    - С VPN
  answer: 1
  explanation: Порядок: команды наружу → фон → утечки → детект.
- question: Куда идти за Binder-транзакциями?
  options:
    - mobile-android-binder
    - mobile-ios-ipc
    - mobile-clipboard
    - mobile-intro
  answer: 0
  explanation: Продвинутый Binder вынесен в отдельный урок mobile-android-binder.
```

## Где пригодится

- Пентест Android-приложений (IPC и рантайм)
- Bug bounty Android
