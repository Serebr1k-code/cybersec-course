---
id: forensics-ios-backup
title: 'iOS-бэкапы: структура и извлечение данных'
category: forensics
parent: forensics-mobile-ios-deep
difficulty: medium
order: 1
tags: [forensics, mobile, ios, backup, manifest]
prerequisites: [forensics-mobile]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как устроен iOS-бэкап, что в Manifest.db и как извлечь из него данные приложений без jailbreak.'
lab:
  kind: shell
  title: "Практика: разбор iOS-бэкапа"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, ios_backup_files.txt]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "iOS-бэкап — дерево файлов + манифест Manifest.db (file_id → domain/path)."
    - "Домен вида `AppDomain-com.example.stealer` — стороннее приложение."
    - "`grep nto ios_backup_files.txt > answer.txt`."
---

## Вопрос, с которого всё начинается

Самый доступный способ получить данные с iPhone — **бэкап**. Но структура нетривиальна:
файлы названы хешами. Разберём, как её читать.

## Наш пример: iTunes/Finder-бэкап

## Шаг 1: структура

```
$ ls ~/Library/Application\ Support/MobileSync/Backup/<UDID>/
Manifest.db  Manifest.plist  Status.plist  00/  01/ ...
```

Файлы разложены по двум символам хеша. Имена — SHA-1 от domain+path.

## Шаг 2: Manifest.db

Ключ к бэкапу — `Manifest.db` (SQLite):

```
$ sqlite3 Manifest.db 'SELECT fileID, domain, relativePath FROM Files LIMIT 5;'
1a2b...  AppDomain-com.apple.Maps  Library/Caches/cache.cell
```

`fileID` — имя файла в бэкапе, `domain` — приложение/система, `relativePath` — путь.

## Шаг 3: извлечение

```
$ sqlite3 Manifest.db 'SELECT fileID FROM Files WHERE domain="HomeDomain" AND relativePath LIKE "%SMS%"'
```

Затем файл лежит в `Backup/<UDID>/<первые 2 символа fileID>/<fileID>`.

## Шаг 4: шифрованный бэкап

Если бэкап зашифрован, нужен пароль:

```
$ iphone_backup_decrypt -i Backup/UDID -o out -p <password>
```

Шифрованные бэкапы содержат **больше** (в т.ч. keychain).

## Шаг 5: что искать

- SMS/звонки (`HomeDomain/Library/SMS`);
- базы приложений (`AppDomain-*`);
- локации (`AppDomain-com.apple.Maps`);
- health, заметки, фото.

## Что мы теперь знаем

- iOS-бэкап разложен по хешам файлов.
- `Manifest.db` связывает fileID↔domain↔path.
- Файл лежит по пути из первых символов fileID.
- Шифрованный бэкап требует пароля и даёт больше.
- Даёт SMS, приложения, локации.

## Если не сработало

- Manifest повреждён? Проверь Status.plist.
- Бэкап зашифрован? Нужен пароль.
- Нужен keychain? Только шифрованный бэкап/живое устройство.

## Квиз

Проверь себя.

```quiz
- question: Что связывает fileID с путём в iOS-бэкапе?
  options:
    - 'Status.plist'
    - 'Manifest.db'
    - 'обои'
    - 'шрифты'
  answer: 1
  explanation: 'Manifest.db содержит таблицу Files с domain/relativePath.'
- question: Как названы файлы в бэкапе?
  options:
    - 'по имени'
    - 'хешем (fileID)'
    - 'по дате'
    - 'по размеру'
  answer: 1
  explanation: 'Файлы переименованы в хеши и разложены по каталогам.'
- question: Чем полезен шифрованный бэкап?
  options:
    - 'ничем'
    - 'содержит больше данных, включая keychain'
    - 'быстрее'
    - 'меньше'
  answer: 1
  explanation: 'Пароль открывает дополнительные данные.'
- question: Что можно достать из бэкапа?
  options:
    - 'только фото'
    - 'SMS, базы приложений, локации'
    - 'только музыку'
    - 'ничего'
  answer: 1
  explanation: 'Бэкап содержит данные приложений и системные артефакты.'
```
