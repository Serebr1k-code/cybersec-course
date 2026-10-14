---
id: mobile-android-location
title: 'Android-геолокация: история местоположений'
category: forensics
parent: forensics-mobile-android-deep
difficulty: hard
order: 1
tags: [forensics, mobile, android, location, gps]
prerequisites: [forensics-mobile]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Где Android хранит историю местоположений и как её извлечь: Google Maps, system-базы и кэш вышек/Wi-Fi.'
lab:
  kind: shell
  title: 'Практика: Android-геолокация'
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

Нужно установить, где был человек. Android хранит историю локаций в нескольких местах,
даже если «История местоположений» выключена. Разберём.

## Наш пример: извлечение Android

## Шаг 1: где искать

- **Google Maps** — `cache.cell`, `cache.wifi`, `local_time_line`;
- **система** — базы `com.google.android.gms`;
- **приложения** — треки, чекины;
- **фото** — EXIF с GPS.

## Шаг 2: Google Maps

```
$ find /data/data -iname '*cache*' | grep -i maps
/data/data/com.google.android.apps.maps/databases/cache.cell
```

`cache.cell` — привязка к сотам, `cache.wifi` — к Wi-Fi-точкам. Оба дают грубую
геолокацию, даже без GPS.

## Шаг 3: timeline

`local_time_line` хранит хронологию перемещений:

```
$ sqlite3 local_time_line 'SELECT * FROM timeline LIMIT 3;'
```

Это фактически дневник поездок.

## Шаг 4: EXIF в фото

```
$ exiftool /sdcard/DCIM/Camera/IMG_001.jpg | grep -i gps
GPS Latitude : 55.75
```

Фото — независимый источник локации с точным временем.

## Шаг 5: что искать

- кластеры точек (где останавливался);
- маршруты (перемещения);
- время (когда был);
- сопоставление с другими артефактами.

## Что мы теперь знаем

- Maps хранит `cache.cell`/`cache.wifi`/timeline.
- Системные базы GMS тоже содержат локации.
- EXIF фото — независимый источник.
- Даже без GPS есть геолокация по сотам/Wi-Fi.
- Сопоставляй источники.

## Если не сработало

- История удалена? Смотри кэш и фото.
- Нет доступа к /data? Нужен root/извлечение.
- Нужна точность? Комбинируй GPS и соты.

## Квиз

Проверь себя.

```quiz
- question: Что хранит cache.cell?
  options:
    - 'обои'
    - 'привязку к сотовым вышкам (геолокация)'
    - 'пароли'
    - 'сеть'
  answer: 1
  explanation: 'cache.cell связывает устройство с сотами для локации.'
- question: Где история перемещений Google Maps?
  options:
    - 'в local_time_line'
    - 'в /etc'
    - 'в браузере'
    - 'в шрифтах'
  answer: 0
  explanation: 'local_time_line хранит таймлайн перемещений.'
- question: Какой независимый источник GPS-локации?
  options:
    - 'обои'
    - 'EXIF фотографий'
    - 'сеть'
    - 'шрифты'
  answer: 1
  explanation: 'Фото с GPS несут координаты и время.'
- question: Можно ли определить локацию без GPS?
  options:
    - 'нет'
    - 'да, по сотам и Wi-Fi'
    - 'только по IP'
    - 'никак'
  answer: 1
  explanation: 'Привязка к сотам/Wi-Fi даёт грубую геолокацию.'
```
