---
id: mobile-android-ipc-deep
title: "Модуль: Продвинутый Android IPC"
category: mobile
parent: mobile-android-components
difficulty: hard
order: 4
tags: [android, ipc, intent, service, binder, drozer, hijacking, fuzzing]
prerequisites: [mobile-exported-components]
useful_for:
  - "Пентест мобильных приложений (Android)"
  - "Bug bounty Android"
  - "CTF Mobile"
estimated_minutes: 25
summary: "Навигационный модуль: углублённые атаки на Android IPC — hijacking сервисов, task hijacking, intent redirection и fuzzing компонентов."
---
## Почему IPC — главная поверхность атаки Android

Android-приложения общаются через IPC: Intent-ы, Binder, Content Providers, Broadcast. Каждое `android:exported="true"` — это входная точка, которую может дёрнуть любое другое приложение (или adb). Базовый урок `mobile-exported-components` даёт обзор; здесь мы углубляемся в конкретные классы атак: перехват сервисов, захват задач (StrandHogg), редирект Intent-ов и автоматизированный фаззинг. Именно эти баги дают серьёзные находки в bug bounty и реальные цепочки в малвари.

Ментальная модель: IPC-атака = «я, недоверенное приложение, заставляю ваше приложение выполнить действие от своего имени или от имени пользователя». Чем выше привилегии целевого компонента, тем серьёзнее последствия (доступ к данным, UI-redress, эскалация).

## Карта ветви

| Урок | Атака | Последствие |
|------|-------|-------------|
| `mobile-service-hijacking` | экспорт/перехват Service | выполнение привилегированных операций |
| `mobile-task-hijacking` | StrandHogg, taskAffinity | UI-redress, фишинг, кража данных |
| `mobile-intent-redirection` | вложенный Intent | редирект в приватный компонент, утечка |
| `mobile-ipc-fuzzing` | автоматический фаззинг | поиск крашей и обходов |

Смежные: `mobile-intents-deeplinks` (deep links), `mobile-exported-provider` (провайдеры), `mobile-android-binder` (Binder/AIDL).

## Поверхность атаки: что искать

```bash
# все экспортированные компоненты и их разрешения
aapt dump xmltree app.apk AndroidManifest.xml | grep -A3 -iE 'activity|service|receiver|provider'
# или после apktool d
grep -rn "android:exported=\"true\"" app_src/AndroidManifest.xml
# компоненты с intent-filter без exported (неявно экспортированы до Android 12)
grep -n "intent-filter" app_src/AndroidManifest.xml
```

Ключевые вопросы: экспортирован ли компонент? есть ли `android:permission`? какой `protectionLevel` (`normal` — защита ноль)? есть ли `intent-filter` (делает компонент доступным по неявному Intent)?

## Binder и границы процессов

Большинство атак упираются в Binder: Activity/Service вызываются через `ActivityManager`, Content Providers — через `ContentProvider`-транзакции, Broadcast — через `ActivityManager.broadcastIntent`. Понимание того, что Intent сериализуется в Parcel, объясняет, почему опасны вложенные Intent-ы (`Parcelable`) и как возможен редирект.

```java
// уязвимый приём: принимаем вложенный Intent и запускаем его
Intent nested = getIntent().getParcelableExtra("next");
startActivity(nested);   // если nested контролируем мы — редирект куда угодно
```

## Инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `adb shell am` | запуск/отправка Intent |
| `drozer` | разведка и эксплуатация IPC |
| `aapt`/`apktool` | анализ манифеста |
| `objection` | `android hooking`, `android intent` |
| Frida | динамический перехват |

```bash
# drozer: список экспортированных компонентов
drozer console connect
dz> run app.package.attacksurface com.target.app
dz> run app.activity.info -a com.target.app
dz> run app.service.info -a com.target.app
```

## Что дальше / решение

Порядок: `mobile-service-hijacking` → `mobile-task-hijacking` → `mobile-intent-redirection` → `mobile-ipc-fuzzing`. Начинайте с `drozer app.package.attacksurface`, чтобы получить карту, затем проверяйте каждый компонент вручную. Для поиска крашей — фаззинг Intent-ами. Решение по умолчанию: эмулятор с root + drozer + Frida.

## Справочная таблица

| Тип компонента | Как вызвать | Риск при экспорте |
|----------------|-------------|-------------------|
| Activity | `am start -n pkg/.Act` | UI-redress, кража данных |
| Service | `am startservice -n pkg/.Svc` | привилегированные операции |
| Receiver | `am broadcast -a ACTION` | подделка событий |
| Provider | `content query --uri` | утечка/SQLi/traversal |

## Квиз

```quiz
- question: "Что делает компонент доступным для других приложений?"
  options:
    - "android:exported=true или intent-filter (до Android 12)"
    - "Наличие ресурсов"
    - "Подпись release-ключом"
    - "Обфускация"
  answer: 0
- question: "Какой инструмент даёт `app.package.attacksurface`?"
  options:
    - "nmap"
    - "drozer"
    - "Burp"
    - "jadx"
  answer: 1
- question: "Почему вложенный Intent опасен?"
  options:
    - "Позволяет редиректить в приватный компонент"
    - "Увеличивает размер APK"
    - "Ломает подпись"
    - "Снимает SELinux"
  answer: 0
- question: "Что означает protectionLevel=normal у разрешения?"
  options:
    - "Разрешение выдаётся автоматически без запроса — защиты почти нет"
    - "Требует root"
    - "Только для системы"
    - "Только для отладки"
  answer: 0
- question: "Как отправить Broadcast из adb?"
  options:
    - "am start"
    - "am broadcast -a ACTION"
    - "content query"
    - "pm list"
  answer: 1
```

## Где пригодится

- **Пентест Android:** систематизация IPC-атак.
- **Bug bounty:** exported-компоненты — частые находки.
- **Анализ малвари:** понимание, как малварь злоупотребляет IPC.
- **CTF:** Mobile-задачи на компоненты.
