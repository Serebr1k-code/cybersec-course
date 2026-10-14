---
id: mobile-ios-keychain-deep
title: 'iOS Keychain: секреты и их извлечение'
category: forensics
parent: forensics-mobile-ios-deep
difficulty: hard
order: 2
tags: [forensics, mobile, ios, keychain, secrets]
prerequisites: [forensics-mobile]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Что хранит iOS keychain, как он защищён и как извлечь секреты из бэкапа или живого устройства.'
lab:
  kind: shell
  title: 'Практика: iOS Keychain'
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

Пароли, токены, ключи Wi-Fi — всё это в **keychain** iOS. Извлечь его — цель многих
расследований. Разберём, что возможно.

## Наш пример: keychain из бэкапа

## Шаг 1: что хранит keychain

- пароли сайтов и Wi-Fi;
- токены приложений;
- ключи шифрования;
- сертификаты.

## Шаг 2: защита

Keychain защищён аппаратным **Secure Enclave** и привязан к паролю устройства.
Обычное извлечение невозможно — нужен либо пароль, либо уязвимость.

## Шаг 3: из шифрованного бэкапа

Шифрованный бэкап содержит `keychain-backup.plist`:

```
$ iphone_backup_decrypt -i Backup/UDID -o out -p <password>
$ ls out/
keychain-backup.plist  ...
```

Пароль бэкапа разблокирует keychain-записи, доступные для бэкапа.

## Шаг 4: из живого устройства

С jailbreak:

```
$ ssh root@iphone
# sqlite3 /var/Keychains/keychain-2.db '.tables'
```

Но современные записи привязаны к Secure Enclave — часть недоступна.

## Шаг 5: что искать

- пароли Wi-Fi (полезно для расследования сети);
- токены сессий;
- сертификаты;
- ключи приложений;
- записи, доступные только на устройстве (не в бэкапе).

## Что мы теперь знаем

- Keychain хранит пароли, токены, ключи.
- Защищён Secure Enclave и паролем устройства.
- Шифрованный бэкап даёт часть записей.
- Jailbreak даёт доступ к базе (частично).
- Некоторые записи не покидают устройство.

## Если не сработало

- Нет пароля бэкапа? Keychain недоступен.
- Нужны все записи? Только живое разблокированное устройство.
- Нужны Wi-Fi? Часть паролей в бэкапе.

## Квиз

Проверь себя.

```quiz
- question: Что хранит iOS keychain?
  options:
    - 'обои'
    - 'пароли, токены, ключи'
    - 'музыку'
    - 'видео'
  answer: 1
  explanation: 'Keychain — защищённое хранилище секретов iOS.'
- question: Чем защищён keychain?
  options:
    - 'паролем сайта'
    - 'Secure Enclave и паролем устройства'
    - 'обоями'
    - 'сетью'
  answer: 1
  explanation: 'Аппаратная защита не даёт извлечь ключи напрямую.'
- question: Где keychain в шифрованном бэкапе?
  options:
    - 'в Manifest.db'
    - 'в keychain-backup.plist'
    - 'в обои'
    - 'в сети'
  answer: 1
  explanation: 'Пароль бэкапа разблокирует записи keychain.'
- question: Все ли записи доступны из бэкапа?
  options:
    - 'да'
    - 'нет, часть привязана к устройству'
    - 'иногда'
    - 'только Wi-Fi'
  answer: 1
  explanation: 'Некоторые ключи не покидают Secure Enclave.'
```
