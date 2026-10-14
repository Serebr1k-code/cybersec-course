---
id: mobile-gms
title: 'Google Mobile Services: данные сервисов и аккаунты'
category: forensics
parent: forensics-mobile-android-deep
difficulty: hard
order: 3
tags: [forensics, mobile, android, gms, google, accounts]
prerequisites: [forensics-mobile]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Какие данные хранят Google Mobile Services, где их искать и как они помогают в расследовании.'
lab:
  kind: shell
  title: 'Практика: Google Mobile Services'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

Google-сервисы (GMS) знают о телефоне больше всех: аккаунты, синхронизация, локации,
поиск. Их данные — ценный источник. Разберём.

## Наш пример: GMS-данные

## Шаг 1: что такое GMS

GMS — набор сервисов Google (Play, аккаунты, синхронизация, безопасность). Они хранят
данные в собственных базах под `com.google.android.gms`.

## Шаг 2: где искать

```
$ find /data/data/com.google.android.gms -name '*.db' | head
```

Внутри: аккаунты, настройки, кэши, данные безопасности.

## Шаг 3: аккаунты

```
$ sqlite3 /data/data/com.google.android.gms/databases/accounts.db '.tables'
```

Даёт список Google-аккаунтов, связанных с устройством — идентификация владельца.

## Шаг 4: данные безопасности

GMS ведёт:
- **Find My Device** (последние локации);
- **Safe Browsing** (предупреждения);
- **Play Protect** (обнаружения).

```
$ grep -ri 'playprotect\|safebrowsing' /data/data/com.google.android.gms/ | head
```

## Шаг 5: что искать

- список аккаунтов;
- историю синхронизации;
- локации Find My Device;
- обнаружения Play Protect;
- установки из Play.

## Что мы теперь знаем

- GMS хранит аккаунты, синхронизацию, локации.
- Базы — под `com.google.android.gms`.
- Аккаунты идентифицируют владельца.
- Play Protect/Find My Device дают данные безопасности.
- Данные синхронизируются с облаком Google.

## Если не сработало

- Данные в облаке? Нужен доступ к аккаунту.
- Нет root? Используй извлечение.
- Нужен контекст? Смотри другие приложения.

## Квиз

Проверь себя.

```quiz
- question: Что такое GMS?
  options:
    - 'игра'
    - 'набор сервисов Google на Android'
    - 'формат файла'
    - 'сеть'
  answer: 1
  explanation: 'GMS — Google Mobile Services.'
- question: Что хранит accounts.db GMS?
  options:
    - 'обои'
    - 'список Google-аккаунтов устройства'
    - 'пароль Wi-Fi'
    - 'шрифты'
  answer: 1
  explanation: 'База аккаунтов связывает устройство с владельцем.'
- question: Что даёт Find My Device?
  options:
    - 'обои'
    - 'последние локации устройства'
    - 'шрифты'
    - 'музыку'
  answer: 1
  explanation: 'Сервис хранит местоположения устройства.'
- question: Где искать данные GMS?
  options:
    - 'в /etc'
    - 'в com.google.android.gms'
    - 'в /boot'
    - 'в реестре'
  answer: 1
  explanation: 'Данные GMS лежат в каталоге своего пакета.'
```
