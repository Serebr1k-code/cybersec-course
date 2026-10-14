---
id: mobile-ios-location
title: 'iOS-геолокация: где был iPhone'
category: forensics
parent: forensics-mobile-ios-deep
difficulty: medium
order: 3
tags: [forensics, mobile, ios, location, significant-locations]
prerequisites: [forensics-mobile]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Где iOS хранит историю местоположений: Significant Locations, кэш карт и приложения.'
lab:
  kind: shell
  title: 'Практика: iOS-геолокация'
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

iPhone знает, где был владелец. Данные о локациях есть даже при выключенных настройках.
Разберём, где искать.

## Наш пример: iOS-бэкап

## Шаг 1: Significant Locations

iOS хранит «значимые места»:

```
$ find Backup/UDID -name 'Cache.sqlite'
.../HomeDomain/Library/Caches/com.apple.routined/Cache.sqlite
```

`Cache.sqlite` (routined) — история значимых мест с частотой и временем.

## Шаг 2: читаем

```
$ sqlite3 Cache.sqlite '.tables'
$ sqlite3 Cache.sqlite 'SELECT * FROM ZRTCLLOCATIONMO LIMIT 3;'
```

Записи содержат координаты, время, тип места.

## Шаг 3: кэш карт

```
.../AppDomain-com.apple.Maps/Library/Caches/com.apple.Maps/
```

Maps хранит кэш локаций и поисковых запросов.

## Шаг 4: другие источники

- фото с GPS (EXIF);
- приложения (трекеры, доставка);
- `Health` (маршруты тренировок);
- `CallHistory` (нет GPS, но привязка).

## Шаг 5: что искать

- домашний/рабочий адрес;
- частые посещения;
- маршруты;
- сопоставление времени с событиями.

## Что мы теперь знаем

- iOS хранит Significant Locations (routined).
- `Cache.sqlite` содержит координаты и время.
- Maps кэширует локации и запросы.
- Фото/Health — независимые источники.
- Сопоставляй время с событиями.

## Если не сработало

- Данные выключены? Смотри кэш и фото.
- Нужна точность? Комбинируй источники.
- Нет бэкапа? Работай с живым устройством.

## Квиз

Проверь себя.

```quiz
- question: Что хранит Cache.sqlite routined?
  options:
    - 'обои'
    - 'значимые места с координатами и временем'
    - 'пароли'
    - 'музыку'
  answer: 1
  explanation: 'Significant Locations хранятся в базе routined.'
- question: Что ещё даёт геолокацию на iPhone?
  options:
    - 'обои'
    - 'фото с GPS и Health'
    - 'шрифты'
    - 'сеть'
  answer: 1
  explanation: 'EXIF фото и тренировки содержат координаты.'
- question: Где кэш карт Apple?
  options:
    - 'в /etc'
    - 'в AppDomain-com.apple.Maps'
    - 'в /boot'
    - 'в реестре'
  answer: 1
  explanation: 'Maps хранит кэш локаций и запросов.'
- question: Зачем сопоставлять локации со временем?
  options:
    - 'для красоты'
    - 'чтобы связать места с событиями'
    - 'для скорости'
    - 'незачем'
  answer: 1
  explanation: 'Временная привязка подтверждает хронологию.'
```
