#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gB forensics gaps: macOS user artifacts (hub + 6 lessons)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _fgaps_common import emit  # noqa: E402

HUBS = {}
LESSONS = {}

HUBS["forensics-macos-artifacts-deep"] = r'''---
id: forensics-macos-artifacts-deep
title: "Модуль: пользовательские артефакты macOS"
category: forensics
parent: forensics-macos-artifacts
difficulty: hard
order: 2
tags: [macos, launchservices, spotlight, notifications, safari, imessage, forensics, roadmap]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ macOS-хостов"
estimated_minutes: 13
summary: "Этап ветки «macOS»: где система хранит пользовательскую активность — запуск приложений, поиск, уведомления, установки, браузер и сообщения."
---

macOS хранит историю активности в десятках SQLite-баз и plist-файлов, разбросанных по
`~/Library`. Этот модуль — про шесть источников, которые чаще всего дают ответы в
расследовании.

## Что покрывает этот модуль

- **LaunchServices** — что и когда запускалось и открывалось.
- **Spotlight** — индекс и поисковые запросы.
- **Уведомления** — тексты тостов и их источники.
- **Установки** — что инсталлировали и откуда.
- **Safari** — история, загрузки, кэш.
- **iMessage** — переписка и вложения.

## Рекомендуемый порядок изучения

1. `macos-launchservices` — базовый «журнал запусков».
2. `macos-spotlight` — индекс как источник метаданных.
3. `macos-notification-db` — тексты уведомлений.
4. `macos-install-logs` — история установок.
5. `macos-safari` — браузерные артефакты.
6. `macos-imessage` — сообщения.

## Что вы будете уметь

- Читать базы LaunchServices и Spotlight.
- Восстанавливать тексты уведомлений.
- Находить историю установок ПО.
- Извлекать историю Safari и переписку iMessage.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Путь |
|----------|--------------------|------|
| `com.apple.LaunchServices` | что запускалось | `~/Library/Preferences/` |
| `store.db` (Spotlight) | поисковые запросы | `~/Library/Application Support/com.apple.spotlight/` |
| `record.db` | уведомления | `~/Library/Group Containers/group.com.apple.usernoted/db2/` |
| `history.db` (Safari) | история браузера | `~/Library/Safari/` |
| `chat.db` (iMessage) | переписка | `~/Library/Messages/` |

## Куда дальше

Открывай урок **«LaunchServices: что запускалось»** — начнём с самого
универсального журнала macOS.
'''

LESSONS["macos-launchservices"] = dict(
parent="forensics-macos-artifacts-deep", order=1, diff="medium", mins=45,
title="LaunchServices: что и когда запускалось в macOS",
tags="[macos, launchservices, quarentine, plist, execution, forensics]",
prereq="[forensics-macos-artifacts]",
summary="Как читать базу com.apple.LaunchServices и атрибут com.apple.quarantine, чтобы восстановить запуск и загрузку приложений.",
body=r'''
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
''')

LESSONS["macos-spotlight"] = dict(
parent="forensics-macos-artifacts-deep", order=2, diff="medium", mins=45,
title="Spotlight: индекс macOS как источник метаданных",
tags="[macos, spotlight, metadata, index, forensics]",
prereq="[forensics-macos-artifacts]",
summary="Что хранит индекс Spotlight, как читать store.db и использовать метаданные файлов, даже если сами файлы удалены.",
body=r'''
## Вопрос, с которого всё начинается

Файл удалён, но macOS его «помнит». Индекс **Spotlight** хранит метаданные обо всём,
что когда-либо было в системе: имена, пути, размеры, даты. Это архив теней удалённых
файлов. Разберёмся, как его читать.

## Наш пример: удалённый документ

## Шаг 1: где индекс

```
$ ls ~/Library/Application\ Support/com.apple.spotlight/
index.V2  store.db  ...
```

`store.db` — это SQLite-база индекса. Откроем и посмотрим таблицы:

```
$ sqlite3 store.db '.tables'
...
```

## Шаг 2: метаданные через mdls

Проще всего — встроенный инструмент `mdls`, он читает метаданные файла:

```
$ mdls -name kMDItemDisplayName -name kMDItemContentCreationDate /Users/user/Documents/report.pdf
kMDItemDisplayName = "report.pdf"
kMDItemContentCreationDate = 2026-01-14 03:31:02 +0000
```

`kMDItem*` — это атрибуты Spotlight. Их десятки: автор, где создан, какой программой,
сколько раз открывали.

## Шаг 3: поиск через mdfind

Найти файлы по метаданным:

```
$ mdfind -onlyin /Users/user 'kMDItemWhereFroms == "*203.0.113.5*"'
/Users/user/Downloads/payload.dmg
```

`kMDItemWhereFroms` — откуда файл скачан. Так можно найти всё, что пришло с
подозрительного адреса, даже если оно переименовано.

## Шаг 4: удалённые файлы в индексе

Если файл удалили, но индекс не перестроили, запись может остаться:

```
$ sqlite3 store.db 'SELECT * FROM ... LIMIT 5;'
```

Структура `store.db` недокументирована, поэтому на практике используют утилиты вроде
`mac_apt` или `Spotlight`-парсеры. Они извлекают имена, пути и даты удалённых файлов.

## Шаг 5: что ещё в индексе

Spotlight индексирует не только документы, но и:

- почту (`kMDItemContentType = com.apple.mail.emlx`);
- историю браузера (заголовки страниц);
- переписку;
- музыку/фото с метаданными.

Поэтому `mdfind` — быстрый способ найти «всё про X» по всей системе.

## Что мы теперь знаем

- Spotlight хранит индекс метаданных в `store.db` и `index.V2`.
- `mdls` показывает атрибуты одного файла.
- `mdfind` ищет по метаданным по всей системе.
- `kMDItemWhereFroms` = источник скачивания.
- Удалённые файлы могут остаться в индексе.

## Если не сработало

- Индекс отключён? Проверь `mdutil -s /`.
- Индекс перестроен? Используй бэкап Time Machine.
- Нужны детали? Парси `store.db` утилитами mac_apt.

## Квиз

Проверь себя.

```quiz
- question: Где хранится индекс Spotlight?
  options:
    - 'в /etc/passwd'
    - 'в store.db / index.V2'
    - 'в /boot'
    - 'в реестре'
  answer: 1
  explanation: 'Индекс лежит в ~/Library/Application Support/com.apple.spotlight/.'
- question: Что делает mdfind?
  options:
    - 'удаляет файлы'
    - 'ищет по метаданным Spotlight'
    - 'сжимает диск'
    - 'шифрует'
  answer: 1
  explanation: 'mdfind — CLI-поиск по индексу Spotlight.'
- question: Что означает kMDItemWhereFroms?
  options:
    - 'размер файла'
    - 'откуда файл скачан'
    - 'автор'
    - 'формат'
  answer: 1
  explanation: 'Атрибут хранит URL-источник загрузки файла.'
- question: Почему Spotlight важен для форензики?
  options:
    - 'он быстрый'
    - 'хранит метаданные даже удалённых файлов'
    - 'он шифрует'
    - 'он только для фото'
  answer: 1
  explanation: 'Индекс может сохранить следы файлов, которых уже нет на диске.'
```
''')

LESSONS["macos-notification-db"] = dict(
parent="forensics-macos-artifacts-deep", order=3, diff="medium", mins=40,
title="База уведомлений macOS: тексты тостов и их источники",
tags="[macos, notifications, usernoted, sqlite, forensics]",
prereq="[forensics-macos-artifacts]",
summary="Как читать record.db уведомлений macOS: восстановить тексты тостов, приложения-источники и время.",
body=r'''
## Вопрос, с которого всё начинается

Пользователю приходили уведомления — от почты, мессенджеров, приложений. macOS хранит
их историю в базе **usernoted**. Для расследования это золото: в тостах видны
сообщения, имена, коды, даже одноразовые пароли. Разберём, как их достать.

## Наш пример: база уведомлений

## Шаг 1: находим базу

```
$ ls ~/Library/Group\ Containers/group.com.apple.usernoted/db2/
db  db-shm  db-wal
```

Основная база — `db`, рядом WAL-журнал (свежие изменения могут быть ещё в нём).

## Шаг 2: смотрим таблицы

```
$ sqlite3 db '.tables'
app  app_metadata  dbinfo  record
```

Таблица `record` — сами уведомления, `app` — приложения-источники.

## Шаг 3: извлекаем уведомления

```
$ sqlite3 db 'SELECT a.identifier, r.data FROM record r JOIN app a ON a.app_id=r.app_id LIMIT 5;'
com.apple.mail|bplist00...Your code is 482913...
com.apple.iChat|bplist00...Meeting at 15:00...
```

Поле `data` — бинарный plist. Прочитаем его:

```
$ plutil -p data.bin | grep -i 'body\|title'
"body" => "Your code is 482913"
"title" => "Verification"
```

## Шаг 4: время и источник

Время в `record` — Apple epoch. Приложение-источник даёт контекст: уведомление от
`com.apple.mail` — это почта, от `com.apple.iChat` — сообщения.

```
$ sqlite3 db 'SELECT datetime(delivered_date+978307200,"unixepoch"), app_id FROM record ORDER BY delivered_date DESC LIMIT 3;'
2026-01-14 03:31:02|42
```

## Шаг 5: что искать

Уведомления раскрывают:

- коды двухфакторной аутентификации;
- имена отправителей и темы;
- названия файлов/ссылок;
- ошибки приложений.

Это часто быстрее, чем разбирать сами приложения.

## Что мы теперь знаем

- Уведомления хранятся в `record.db` (Group Containers/usernoted).
- `record.data` — бинарный plist с текстом тоста.
- `plutil -p` превращает его в читаемый вид.
- Время — Apple epoch (+978307200).
- Тексты могут содержать OTP, имена, ссылки.

## Если не сработало

- База пуста? Проверь WAL (`db-wal`) — свежие записи там.
- Нужны вложения? Смотри соседние каталоги Group Containers.
- База зашифрована? На современных macOS часть данных защищена — нужен доступ
  пользователя.

## Квиз

Проверь себя.

```quiz
- question: Где macOS хранит историю уведомлений?
  options:
    - 'в /etc/hosts'
    - 'в record.db (usernoted)'
    - 'в /boot'
    - 'в /var/log'
  answer: 1
  explanation: 'База уведомлений лежит в group.com.apple.usernoted.'
- question: Что содержит поле data записи уведомления?
  options:
    - 'пароль диска'
    - 'бинарный plist с текстом тоста'
    - 'IP-адрес'
    - 'размер файла'
  answer: 1
  explanation: 'data — это bplist с title/body уведомления.'
- question: Чем полезны уведомления в расследовании?
  options:
    - 'они занимают место'
    - 'могут содержать OTP, имена и ссылки'
    - 'они шифруют диск'
    - 'они ускоряют систему'
  answer: 1
  explanation: 'В текстах тостов часто попадаются коды и контакты.'
- question: Где искать самые свежие записи, если базы «нет»?
  options:
    - 'в db-wal'
    - 'в /tmp'
    - 'в реестре'
    - 'в /etc/passwd'
  answer: 0
  explanation: 'WAL-журнал SQLite хранит не зафиксированные изменения.'
```
''')

LESSONS["macos-install-logs"] = dict(
parent="forensics-macos-artifacts-deep", order=4, diff="medium", mins=40,
title="Логи установок macOS: что ставили и когда",
tags="[macos, install, pkg, receipts, forensics]",
prereq="[forensics-macos-artifacts]",
summary="Как по /var/log/install.log и базам receipts восстановить историю установки ПО и обновлений macOS.",
body=r'''
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
''')

LESSONS["macos-safari"] = dict(
parent="forensics-macos-artifacts-deep", order=5, diff="medium", mins=45,
title="Safari-форензика: история, загрузки и кэш",
tags="[macos, safari, browser, history, downloads, forensics]",
prereq="[forensics-macos-artifacts]",
summary="Как читать History.db, Downloads.plist и кэш Safari, восстанавливать посещения, загрузки и сессии.",
body=r'''
## Вопрос, с которого всё начинается

Пользователь скачал вредоносный файл. Через какой браузер, с какого сайта и что ещё он
смотрел? Safari хранит историю в SQLite и plist. Разберём три источника: историю,
загрузки и сессии.

## Наш пример: история Safari

## Шаг 1: база истории

```
$ ls ~/Library/Safari/History.db
-rw-r--r-- 1 user staff 245760 Jan 14 03:30 History.db
$ sqlite3 History.db '.tables'
history_items  history_visits  ...
```

`history_items` — сами страницы, `history_visits` — когда их открывали.

## Шаг 2: извлекаем посещения

```
$ sqlite3 History.db 'SELECT datetime(v.visit_time+978307200,"unixepoch"), i.url FROM history_visits v JOIN history_items i ON i.id=v.history_item ORDER BY v.visit_time DESC LIMIT 5;'
2026-01-14 03:27:40|https://203.0.113.5/download.html
2026-01-14 03:28:10|https://203.0.113.5/payload.dmg
```

Время — Apple epoch. Видно, что за минуту до скачивания пользователь был на
`203.0.113.5` — это точка входа.

## Шаг 3: список загрузок

```
$ plutil -p ~/Library/Safari/Downloads.plist | head
{
  "DownloadHistory" => [
    { "DownloadEntryPath" => "/Users/user/Downloads/payload.dmg",
      "DownloadEntryURL" => "https://203.0.113.5/payload.dmg",
      "DownloadEntryDateAdded" => 2026-01-14 03:28:10 +0000 }
  ]
}
```

`Downloads.plist` — журнал загрузок. Даже если файл удалили, запись остаётся.

## Шаг 4: сессии и окна

Safari хранит открытые вкладки:

```
$ plutil -p ~/Library/Safari/LastSession.plist | grep -i url | head
```

Отсюда видно, что было открыто в момент завершения работы.

## Шаг 5: кэш и авто-заполнение

Кэш страниц (`~/Library/Caches/com.apple.Safari/`) может содержать тела ответов, а
`AutoFill` — сохранённые формы (без паролей). Это помогает восстановить содержимое
страницы, которой уже нет.

## Что мы теперь знаем

- `History.db` — история посещений (время в Apple epoch).
- `Downloads.plist` — журнал загрузок с URL.
- `LastSession.plist` — открытые вкладки.
- Кэш хранит тела страниц.
- Цепочка «сайт → скачивание → установка» восстанавливается полностью.

## Если не сработало

- Файлы пусты? Проверь `~/Library/Safari/` всех пользователей.
- Приватный режим? История не пишется — ищи в кэше и сети.
- Кэш очищен? Смотри Time Machine и системные логи.

## Квиз

Проверь себя.

```quiz
- question: Где Safari хранит историю посещений?
  options:
    - 'в /etc/hosts'
    - 'в History.db'
    - 'в /boot'
    - 'в реестре'
  answer: 1
  explanation: 'History.db — SQLite с history_items и history_visits.'
- question: Что хранит Downloads.plist?
  options:
    - 'пароли'
    - 'журнал загрузок с URL и датой'
    - 'маршруты'
    - 'обои'
  answer: 1
  explanation: 'В DownloadHistory есть путь, URL и дата каждой загрузки.'
- question: В каком формате время в Safari?
  options:
    - 'unix epoch'
    - 'Apple epoch (+978307200)'
    - 'Windows FILETIME'
    - 'текст'
  answer: 1
  explanation: 'Safari использует Apple epoch, начинающийся с 2001-01-01.'
- question: Что можно найти в кэше Safari?
  options:
    - 'пароль диска'
    - 'тела страниц, которых уже нет'
    - 'сетевые маршруты'
    - 'логи ядра'
  answer: 1
  explanation: 'Кэш может содержать сохранённые ответы сервера.'
```
''')

LESSONS["macos-imessage"] = dict(
parent="forensics-macos-artifacts-deep", order=6, diff="hard", mins=45,
title="iMessage-форензика: переписка, вложения и адресаты",
tags="[macos, imessage, chat, sqlite, forensics]",
prereq="[forensics-macos-artifacts]",
summary="Как читать chat.db iMessage: сообщения, вложения, время и участники переписки.",
body=r'''
## Вопрос, с которого всё начинается

Расследуется инцидент, и ключевые указания пришли в переписке. iMessage хранит всё в
одной базе `chat.db`. Но её структура неочевидна, а время в особом формате. Разберём,
как достать сообщения.

## Наш пример: база chat.db

## Шаг 1: находим базу

```
$ ls ~/Library/Messages/chat.db
-rw-r--r-- 1 user staff 1048576 Jan 14 03:35 chat.db
```

## Шаг 2: таблицы

```
$ sqlite3 chat.db '.tables'
chat  handle  message  message_attachment_join  attachment  ...
```

- `handle` — участники (номера, email);
- `message` — сами сообщения;
- `attachment` — вложения;
- `chat` — диалоги.

## Шаг 3: читаем сообщения

```
$ sqlite3 chat.db 'SELECT datetime(date/1000000000+978307200,"unixepoch"), is_from_me, text FROM message ORDER BY date DESC LIMIT 5;'
2026-01-14 03:33:02|0|Переведи на счёт 203.0.113.5
2026-01-14 03:30:11|1|ok
```

Важно: время в `chat.db` — Apple epoch **в наносекундах**, поэтому делим на
`1000000000`. `is_from_me=1` — исходящее, `0` — входящее.

## Шаг 4: связываем с участниками

```
$ sqlite3 chat.db 'SELECT h.id, m.text FROM message m JOIN handle h ON h.ROWID=m.handle_id LIMIT 3;'
+15551234567|Переведи на счёт...
```

Так видно, кто отправил каждое сообщение.

## Шаг 5: вложения

```
$ sqlite3 chat.db 'SELECT a.filename, a.transfer_name FROM attachment a;'
~/Library/Messages/Attachments/.../photo.jpg|photo.jpg
```

Вложения лежат в `~/Library/Messages/Attachments/`. По `transfer_name` и пути
восстанавливаешь, что пересылали. Проверь и удалённые вложения — ссылки в базе могут
сохраниться.

## Что мы теперь знаем

- `chat.db` — единая база iMessage.
- Таблицы: handle (участники), message (сообщения), attachment (файлы).
- Время в наносекундах Apple epoch: `date/1e9 + 978307200`.
- `is_from_me` различает входящие и исходящие.
- Вложения — в `~/Library/Messages/Attachments/`.

## Если не сработало

- База защищена? На современных macOS нужен доступ с правами пользователя (Full Disk
  Access).
- Нужны удалённые сообщения? Смотри WAL (`chat.db-wal`) и бэкапы iPhone.
- Вложение удалено? Ищи по хешу в других местах.

## Квиз

Проверь себя.

```quiz
- question: Где хранится переписка iMessage?
  options:
    - 'в /etc/passwd'
    - 'в ~/Library/Messages/chat.db'
    - 'в /boot'
    - 'в реестре'
  answer: 1
  explanation: 'chat.db — SQLite-база сообщений macOS.'
- question: Как перевести время message.date в unix?
  options:
    - 'умножить на 8'
    - 'date/1e9 + 978307200'
    - 'вычесть 1000'
    - 'никак'
  answer: 1
  explanation: 'date хранится в наносекундах Apple epoch.'
- question: Что означает is_from_me=0?
  options:
    - 'сообщение удалено'
    - 'входящее сообщение'
    - 'исходящее сообщение'
    - 'ошибка'
  answer: 1
  explanation: 'is_from_me=0 — сообщение получено, 1 — отправлено.'
- question: Где лежат вложения iMessage?
  options:
    - 'в /tmp'
    - 'в ~/Library/Messages/Attachments/'
    - 'в /etc'
    - 'в /boot'
  answer: 1
  explanation: 'Вложения хранятся в каталоге Attachments внутри Messages.'
```
''')

emit(HUBS, LESSONS)
