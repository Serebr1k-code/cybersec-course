---
id: macos-notification-db
title: 'База уведомлений macOS: тексты тостов и их источники'
category: forensics
parent: forensics-macos-artifacts-deep
difficulty: medium
order: 3
tags: [macos, notifications, usernoted, sqlite, forensics]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Как читать record.db уведомлений macOS: восстановить тексты тостов, приложения-источники и время.'
lab:
  kind: shell
  title: 'Практика: База уведомлений macOS'
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

## Где именно лежит база уведомлений

На современных macOS уведомления хранятся не в `~/Library/Notifications`, а в контейнере
системного демона `usernoted`:

```
$ ls -la ~/Library/Group\ Containers/group.com.apple.usernoted/db2/
-rw-r--r--  db
-rw-r--r--  db-shm
-rw-r--r--  db-wal
```

Это SQLite. Файлы `-shm`/`-wal` — журналы WAL, в которых могут остаться **свежие** записи,
ещё не перенесённые в основную базу. При копировании забирай все три, иначе потеряешь
последние события.

## Схема и разбор через sqlite3

Смотрим таблицы:

```
$ sqlite3 ~/Library/Group\ Containers/group.com.apple.usernoted/db2/db '.tables'
app        db_info    delivered  record     requests
```

Ключевые таблицы: `app` (источник уведомления) и `record` (само уведомление). Полезные
поля в `record`: `data` (двоичный blob), `delivered_date` (время в эпоху Cocoa), `app_id`.

```
$ sqlite3 .../db "SELECT app_id, delivered_date, hex(data) FROM record ORDER BY delivered_date DESC LIMIT 3;"
com.apple.MobileSMS|733000000.0|62706C6973743030D101025D...
```

Префикс `62706c6973743030` — это ASCII `bplist00`, то есть `data` содержит **binary plist**.
Дату `delivered_date` переводим из эпохи Cocoa (секунды от 2001-01-01 UTC):

```
$ python3 -c "import datetime;print(datetime.datetime(2001,1,1)+datetime.timedelta(seconds=733000000))"
2024-03-22 19:06:40
```

## Извлекаем текст уведомления

Blob — бинарный plist с полями `req` (request) и `titl`/`subt`/`body`. Разбираем:

```
$ sqlite3 .../db "SELECT data FROM record WHERE app_id='com.apple.MobileSMS' LIMIT 1;" > n.bin
$ python3 - <<'PY'
import plistlib
raw = open('n.bin','rb').read()
# в базе blob может быть обёрнут: находим начало bplist
i = raw.find(b'bplist')
pl = plistlib.loads(raw[i:])
print(pl.get('req', {}).get('titl'), '|', pl.get('req', {}).get('body'))
PY
Привет | Как дела?
```

Так восстанавливаются **тексты уведомлений**, включая те, что пользователь смахнул, но не
удалил из базы.

## Привязка к источнику и контексту

`app_id` — обратный домен приложения (`com.apple.MobileSMS`, `com.tinyspeck.slackmacgap`).
По нему видно, какие программы слали уведомления. Соединяем с другими артефактами:

```
$ sqlite3 .../db "SELECT a.identifier, count(*) FROM record r JOIN app a ON a.id=r.app_id GROUP BY 1 ORDER BY 2 DESC;"
com.apple.MobileSMS       412
com.apple.mail            88
com.google.Chrome         37
```

Всплеск уведомлений от конкретного приложения в узкое окно — сигнал (например, массовая
рассылка фишинга через почтовый клиент).

## Таблица: артефакты уведомлений на macOS

| Артефакт | Путь | Что даёт |
|---|---|---|
| База уведомлений | `group.com.apple.usernoted/db2/db` | тексты, источники, время |
| WAL/SHM | рядом с базой | свежие, ещё не сброшенные записи |
| Настройки уведомлений | `com.apple.ncprefs.plist` | какие приложения и как уведомляют |
| Focus/Do Not Disturb | `~/Library/DoNotDisturb/DB/` | режимы «не беспокоить» |
| Центр уведомлений (iOS) | `BulletinBoard/*.db` | аналог на телефоне |

`ncprefs.plist` показывает, какие приложения имеют право слать уведомления, — полезно, чтобы
понять, было ли подозрительное приложение «тихим» (уведомления отключены) или нет.

## Практический сценарий расследования

Задача: подтвердить, что пользователю приходило уведомление о входе в банк. Ищем по тексту:

```
$ sqlite3 .../db "SELECT app_id, delivered_date, hex(data) FROM record;" | grep -i -A0 'вход\|код\|подтверд'
```

Если база большая, удобнее выгрузить все blob-ы, декодировать в plist и искать по строкам
скриптом. Так же ловятся уведомления от мессенджеров, которые пользователь «удалил» из чата:
сам чат может быть очищен, а запись в базе уведомлений — остаться.

## Ограничения

Во-первых, **ретеншн**: система периодически чистит старые записи, поэтому глубокая история
может отсутствовать. Во-вторых, база зашита от чтения: без **Full Disk Access** (или root)
SQLite вернёт ошибку доступа — это часть TCC. В-третьих, текст в `data` иногда обрезан или
хранит только заголовок. В-четвёртых, на новых версиях macOS путь и схема менялись, поэтому
всегда проверяй `.tables` на конкретной машине, а не полагайся на память.

## Если сработало: что зафиксировать

Сохрани исходную базу целиком (для целостности), экспорт записей в CSV с временами, и
отдельно — декодированные тексты. В отчёте укажи: источник (`app_id`), точное время
(`delivered_date` в локальной зоне), и цитату текста. Это превращает уведомление в
проверяемое доказательство.

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
