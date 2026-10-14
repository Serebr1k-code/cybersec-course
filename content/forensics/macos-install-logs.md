---
id: macos-install-logs
title: 'Логи установок macOS: что ставили и когда'
category: forensics
parent: forensics-macos-artifacts-deep
difficulty: medium
order: 4
tags: [macos, install, pkg, receipts, forensics]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 40
summary: 'Как по /var/log/install.log и базам receipts восстановить историю установки ПО и обновлений macOS.'
lab:
  kind: shell
  title: 'Практика: Логи установок macOS'
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

На Mac появилось неизвестное приложение. Когда его поставили и что ещё менялось в тот
момент? macOS ведёт подробный журнал установок и базу «квитанций» (receipts). Это
позволяет восстановить всю историю инсталляций.

## Наш пример: подозрительная установка

## Шаг 1: основной журнал установок

```
$ grep -i 'install' /var/log/install.log | tail -5
2026-01-14 03:29:55+00 mac Installer: Package name is SuspiciousApp
2026-01-14 03:29:56+00 mac Installer: Installing at base path /
2026-01-14 03:30:01+00 mac Installer: The install was successful.
```

Здесь видно имя пакета и время. Тот же интервал `03:29–03:30`, что и другие события.

## Шаг 2: квитанции установок

macOS хранит receipts в `/var/db/receipts/`:

```
$ ls /var/db/receipts/ | grep -i suspicious
com.suspicious.app.bom
com.suspicious.app.plist
```

Каждая квитанция — `.bom` (bill of materials, список файлов) и `.plist` (метаданные).
Посмотрим метаданные:

```
$ plutil -p /var/db/receipts/com.suspicious.app.plist | head
{
  "PackageFileName" => "SuspiciousApp.pkg",
  "InstallPrefixPath" => "/",
  "InstallDate" => 2026-01-14 03:29:55 +0000
}
```

## Шаг 3: список файлов пакета

`.bom` — это архив со списком установленных файлов:

```
$ lsbom /var/db/receipts/com.suspicious.app.bom | head
.	.	drwxr-xr-x	root	admin
./Applications/SuspiciousApp.app	...
```

Так узнаёшь **все** файлы, которые принёс пакет, даже если приложение потом удалили.

## Шаг 4: обновления системы

Обновления macOS тоже логируются:

```
$ grep -i 'softwareupdate\|macOS' /var/log/install.log | tail -3
2026-01-14 02:00:00+00 mac softwareupdated: Downloaded macOS update
```

Необычное обновление в нерабочее время — повод проверить.

## Шаг 5: сопоставляем с карантином

Установленный пакет был откуда-то скачан. Связываем с `QuarantineEventsV2`:

```
$ sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 \
  'SELECT LSQuarantineDataURLString FROM LSQuarantineEvent WHERE LSQuarantineAgentName="Safari";'
https://203.0.113.5/SuspiciousApp.pkg
```

Скачано с `203.0.113.5` в 03:28, установлено в 03:29 — полная цепочка.

## Что мы теперь знаем

- `/var/log/install.log` — журнал установок и обновлений.
- `/var/db/receipts/` хранит `.bom` и `.plist` каждой установки.
- `.bom` перечисляет все файлы пакета.
- `plutil -p` читает метаданные receipt.
- Связка с карантином даёт источник пакета.

## Если не сработало

- Журнал ротирован? Проверь `.gz`-версии.
- Установка вручную (drag&drop .app)? Тогда receipt нет — смотри карантин и `mdls`.
- Нужны удалённые файлы? Восстанавливай из Time Machine.

## Квиз

Проверь себя.

```quiz
- question: Где macOS хранит журнал установок?
  options:
    - 'в /etc/passwd'
    - 'в /var/log/install.log'
    - 'в /boot'
    - 'в реестре'
  answer: 1
  explanation: 'install.log фиксирует установку пакетов и обновлений.'
- question: Что такое .bom в /var/db/receipts?
  options:
    - 'пароль'
    - 'список файлов установленного пакета'
    - 'сетевой маршрут'
    - 'обои'
  answer: 1
  explanation: 'bill of materials перечисляет файлы, которые принёс пакет.'
- question: Как связать пакет с источником загрузки?
  options:
    - 'никак'
    - 'через QuarantineEventsV2'
    - 'через /etc/hosts'
    - 'через free'
  answer: 1
  explanation: 'Журнал карантина хранит URL скачивания пакета.'
- question: Почему важны квитанции, если приложение удалили?
  options:
    - 'они занимают место'
    - 'они сохраняют список файлов и дату установки'
    - 'они шифруют'
    - 'они ускоряют'
  answer: 1
  explanation: 'Receipts остаются после удаления приложения и хранят его следы.'
```
