---
id: macos-icloud
title: 'iCloud-синхронизация: что уходит с устройства'
category: forensics
parent: forensics-macos-system
difficulty: medium
order: 5
tags: [macos, icloud, sync, bird, cloud, forensics]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Что синхронизирует iCloud, где лежат локальные следы (bird, Mobile Documents) и как оценить, какие данные ушли в облако.'
lab:
  kind: shell
  title: 'Практика: iCloud-синхронизация'
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

Файла на диске нет — возможно, он уже в iCloud. macOS синхронизирует документы, фото,
заметки, переписку. Для расследования это значит: часть данных **вне устройства**, но
локальные следы синхронизации остаются. Разберём их.

## Наш пример: iCloud Drive

## Шаг 1: где локальные данные

```
$ ls ~/Library/Mobile\ Documents/
com~apple~CloudDocs  com~apple~Notes  ...
```

Каталог `Mobile Documents` — локальное зеркало iCloud-контейнеров. Файлы могут быть
«выгружены» (только заглушка) или полными, в зависимости от статуса.

## Шаг 2: статус синхронизации

```
$ brctl status | head
iCloud Drive: enabled
```

`brctl` (bird control) управляет синхронизацией. Из его вывода видно, что включено,
что синхронизируется и есть ли ошибки.

## Шаг 3: журнал bird

Процесс синхронизации — `bird`. Он логирует:

```
$ log show --predicate 'process == "bird"' --last 1d | grep -i 'upload\|download' | head
2026-01-14 03:29:00 bird[400]: upload /Users/user/Documents/report.pdf
```

Отсюда видно, что и когда уходило в облако. Это критично: данные, ушедшие в iCloud,
находятся вне зоны вашего контроля.

## Шаг 4: заметки, фото, сообщения

Помимо файлов, iCloud синхронизирует:

- **Notes** (`~/Library/Group Containers/group.com.apple.notes/`);
- **Photos** (`~/Pictures/Photos Library.photoslibrary`);
- **Messages** (при включённом «Messages in iCloud»).

Локальные базы остаются, даже если контент выгружен.

## Шаг 5: оценка утечки

Ключевой вопрос расследования: ушли ли данные наружу? Проверяем:

```
$ brctl log --short | grep -i 'uploaded' | tail
```

И сопоставляем время загрузки с событиями инцидента. Файл, загруженный в iCloud за
минуту до удаления, — явный признак подготовки.

## Что мы теперь знаем

- `~/Library/Mobile Documents` — локальное зеркало iCloud.
- `brctl` управляет и показывает статус синхронизации.
- `bird` логирует загрузку/скачивание.
- Notes/Photos/Messages тоже синхронизируются.
- Загрузка перед удалением — признак эксфильтрации через облако.

## Если не сработало

- Данные выгружены? Заглушки сохраняют имена и метаданные.
- Нужно содержимое? Только через аккаунт Apple ID.
- Логи ротированы? Смотри архив unified log.

## Квиз

Проверь себя.

```quiz
- question: Где macOS хранит локальное зеркало iCloud?
  options:
    - 'в /etc'
    - 'в ~/Library/Mobile Documents'
    - 'в /boot'
    - 'в реестре'
  answer: 1
  explanation: 'Mobile Documents содержит контейнеры iCloud-приложений.'
- question: Какой процесс отвечает за синхронизацию iCloud?
  options:
    - 'cron'
    - 'bird'
    - 'nginx'
    - 'sshd'
  answer: 1
  explanation: 'bird (brctl) управляет синхронизацией iCloud.'
- question: Что логирует bird?
  options:
    - 'пароли'
    - 'загрузку и скачивание файлов'
    - 'сетевые маршруты'
    - 'обои'
  answer: 1
  explanation: 'Журнал bird фиксирует upload/download операций.'
- question: Почему загрузка файла в iCloud перед удалением подозрительна?
  options:
    - 'это норма'
    - 'может быть эксфильтрацией данных в облако'
    - 'экономит место'
    - 'ускоряет систему'
  answer: 1
  explanation: 'Данные уходят с устройства и становятся недоступны локально.'
```
