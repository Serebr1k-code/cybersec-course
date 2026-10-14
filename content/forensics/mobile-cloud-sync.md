---
id: mobile-cloud-sync
title: 'Облачная синхронизация мобильных: что уходит с устройства'
category: forensics
parent: forensics-mobile-data
difficulty: medium
order: 3
tags: [forensics, mobile, cloud, sync, icloud, google]
prerequisites: [forensics-mobile]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Что синхронизируют iOS/Android с облаком, где локальные следы и как оценить, какие данные ушли.'
lab:
  kind: shell
  title: 'Практика: Облачная синхронизация мобильных'
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

Часть данных телефона уже в облаке (iCloud/Google). Это меняет расследование: данные
вне устройства, но локальные следы остаются. Разберём.

## Наш пример: синхронизация

## Шаг 1: что синхронизируется

- **iOS**: фото, контакты, заметки, сообщения (Messages in iCloud), здоровье, keychain
  (iCloud Keychain);
- **Android**: контакты, фото (Google Photos), данные приложений (Auto Backup), настройки.

## Шаг 2: локальные следы

Даже при выгруженных данных остаются:

- метаданные (что синхронизировано);
- заглушки файлов;
- логи синхронизации.

```
$ find /data -iname '*backup*' | head
```

## Шаг 3: Google Auto Backup

Android делает резервные копии приложений в Google Drive:

```
$ adb shell bmgr list transports
```

Восстановление — через аккаунт Google.

## Шаг 4: iCloud

- данные доступны через iCloud.com/аккаунт;
- «Advanced Data Protection» — E2E, недоступно даже Apple;
- бэкапы iCloud содержат данные приложений.

## Шаг 5: что искать

- какие данные ушли в облако;
- когда синхронизировалось;
- что осталось локально;
- можно ли получить облачные данные (доступ к аккаунту).

## Что мы теперь знаем

- Многое синхронизируется в облако.
- Локальные следы и заглушки остаются.
- Android — Auto Backup в Drive.
- iOS — iCloud, с E2E при ADP.
- Оценка утечки = доступ к аккаунту.

## Если не сработало

- Нет доступа к аккаунту? Работай с локальными следами.
- ADP включён? Облако недоступно.
- Нужны данные? Восстанови из бэкапа.

## Квиз

Проверь себя.

```quiz
- question: Что синхронизируется с облаком на iOS?
  options:
    - 'только фото'
    - 'фото, контакты, сообщения, keychain и др.'
    - 'только музыка'
    - 'ничего'
  answer: 1
  explanation: 'iCloud синхронизирует широкий набор данных.'
- question: Что такое Android Auto Backup?
  options:
    - 'игра'
    - 'резервное копирование приложений в Google Drive'
    - 'сеть'
    - 'формат'
  answer: 1
  explanation: 'Auto Backup сохраняет данные приложений в Drive.'
- question: Что делает Advanced Data Protection?
  options:
    - 'ускоряет'
    - 'включает E2E, недоступное даже Apple'
    - 'шифрует диск'
    - 'сканирует сеть'
  answer: 1
  explanation: 'ADP делает облачные данные end-to-end зашифрованными.'
- question: Что остаётся локально при синхронизации?
  options:
    - 'ничего'
    - 'метаданные, заглушки, логи'
    - 'обои'
    - 'шрифты'
  answer: 1
  explanation: 'Локальные следы синхронизации сохраняются.'
```
