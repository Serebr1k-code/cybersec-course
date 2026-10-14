---
id: macos-launchservices
title: 'LaunchServices: что и когда запускалось в macOS'
category: forensics
parent: forensics-macos-artifacts-deep
difficulty: medium
order: 1
tags: [macos, launchservices, quarentine, plist, execution, forensics]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как читать базу com.apple.LaunchServices и атрибут com.apple.quarantine, чтобы восстановить запуск и загрузку приложений.'
lab:
  kind: shell
  title: 'Практика: LaunchServices'
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

В macOS нет реестра, но есть похожий по смыслу механизм — **LaunchServices**. Он
запоминает, какие приложения установлены, где лежат и что открывалось. Если нужно
понять, запускали ли подозрительный файл, начинать надо отсюда.

## Наш пример: подозрительное приложение

## Шаг 1: где лежат данные

Основной файл — plist:

```
$ ls -la ~/Library/Preferences/com.apple.LaunchServices*
-rw------- 1 user staff 123456 Jan 14 03:30 com.apple.LaunchServices.QuarantineEventsV2
```

`QuarantineEventsV2` — это **журнал карантина**: запись о каждом скачанном файле,
который macOS пометил как «из интернета».

## Шаг 2: читаем карантин

```
$ sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 \
  'SELECT datetime(LSQuarantineTimeStamp+978307200,"unixepoch"), LSQuarantineAgentName, LSQuarantineDataURLString FROM LSQuarantineEvent;'
2026-01-14 03:28:11|Safari|https://203.0.113.5/payload.dmg
```

Здесь видно: файл `payload.dmg` скачан Safari в 03:28 с адреса `203.0.113.5` — тот же
IP, что и в других наших находках. macOS хранит время в **Apple epoch** (секунды с
2001-01-01), поэтому прибавляем `978307200`.

## Шаг 3: атрибут карантина на файле

Каждый скачанный файл получает расширенный атрибут:

```
$ xattr -l /Users/user/Downloads/payload.dmg
com.apple.quarantine: 0083;65a3b1f0;Safari;|com.apple.Safari
```

Формат: флаги;hex-время;приложение;UUID. `65a3b1f0` — unix-время скачивания. Это
позволяет датировать файл, даже если его метки изменены.

## Шаг 4: какие приложения запускались

Список известных приложений и связей расширений лежит в бинарных plist:

```
$ plutil -p ~/Library/Preferences/com.apple.LaunchServices/com.apple.LaunchServices.secure.plist | head
{
  "LSHandlers" => [
    { "LSHandlerContentType" => "public.jpeg",
      "LSHandlerRoleAll" => "com.apple.Preview" }
  ]
}
```

`plutil -p` превращает бинарный plist в читаемый вид. Отсюда видно, какое приложение
открывает какой тип файла — если ассоциация подменена, это признак перехвата.

## Шаг 5: сопоставляем

Собираем цепочку: скачано `03:28` → запущено? Проверяем в `~/Library/Preferences/`
и в системных логах:

```
$ log show --predicate 'process == "CoreServicesUIAgent"' --start "2026-01-14 03:00" | grep -i payload
```

Запуск неподписанного приложения macOS обычно показывает предупреждение — оно
попадает в unified log.

## Что мы теперь знаем

- LaunchServices хранит связи приложений и журнал карантина.
- `QuarantineEventsV2` = кто, когда и откуда скачал файл.
- Время в Apple epoch: +978307200 секунд.
- `xattr` показывает атрибут `com.apple.quarantine` на файле.
- `plutil -p` читает бинарные plist.

## Если не сработало

- База пуста? Проверь `~/Library/Preferences/` всех пользователей.
- Файл без атрибута? Возможно, скачан через API без карантина (curl).
- Нужен запуск? Смотри unified log и `knowledgeC.db`.

## Квиз

Проверь себя.

```quiz
- question: Что хранит QuarantineEventsV2?
  options:
    - 'пароли'
    - 'журнал скачанных файлов с источником'
    - 'сетевые маршруты'
    - 'обои'
  answer: 1
  explanation: 'Это журнал карантина: кто, когда и откуда скачал файл.'
- question: Как перевести Apple epoch в unix?
  options:
    - 'умножить на 8'
    - 'прибавить 978307200'
    - 'вычесть 1000'
    - 'никак'
  answer: 1
  explanation: 'Apple epoch начинается с 2001-01-01; разница 978307200 секунд.'
- question: Какая команда показывает атрибут карантина файла?
  options:
    - 'ls -la'
    - 'xattr -l'
    - 'stat'
    - 'cat'
  answer: 1
  explanation: 'xattr перечисляет расширенные атрибуты, включая com.apple.quarantine.'
- question: Чем полезен plutil?
  options:
    - 'удаляет файлы'
    - 'читает и конвертирует бинарные plist'
    - 'сжимает диск'
    - 'шифрует'
  answer: 1
  explanation: 'plutil -p печатает бинарный plist в читаемом виде.'
```
