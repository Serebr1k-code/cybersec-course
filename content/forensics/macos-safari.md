---
id: macos-safari
title: 'Safari-форензика: история, загрузки и кэш'
category: forensics
parent: forensics-macos-artifacts-deep
difficulty: medium
order: 5
tags: [macos, safari, browser, history, downloads, forensics]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Как читать History.db, Downloads.plist и кэш Safari, восстанавливать посещения, загрузки и сессии.'
lab:
  kind: shell
  title: 'Практика: Safari-форензика'
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

## История Safari: схема базы

История хранится в `~/Library/Safari/History.db` — это SQLite с двумя ключевыми таблицами:
`history_items` (уникальные URL) и `history_visits` (каждое посещение со временем). Связь
многие-к-одному: один URL — много визитов.

```
$ sqlite3 ~/Library/Safari/History.db '.tables'
history_items        history_visits       history_tombstones
metadata             ...
```

`history_tombstones` — интересная таблица: в неё попадают удалённые записи. Даже если
пользователь «очистил историю», часть следов может сохраниться здесь.

## Восстанавливаем хронологию

Время в Safari — эпоха Cocoa (секунды от 2001-01-01). Прибавляем 978307200 для перевода в
Unix-время прямо в запросе:

```
$ sqlite3 ~/Library/Safari/History.db \
"SELECT datetime(v.visit_time + 978307200, 'unixepoch') AS t, i.url, v.title
 FROM history_visits v JOIN history_items i ON i.id = v.history_item
 ORDER BY v.visit_time DESC LIMIT 5;"
2026-01-14 03:41:12|https://mail.example.com/inbox|Входящие
2026-01-14 03:40:58|https://cdn.example.net/update.exe|— 
```

Обрати внимание на второй URL: прямой запрос `.exe` из браузера — типичный шаг загрузки
вредоносного файла. Сопоставь время визита со временем появления файла на диске.

## Загрузки и список карантина

Загрузки хранятся отдельно, в `~/Library/Safari/Downloads.plist`:

```
$ plutil -p ~/Library/Safari/Downloads.plist | head -30
{
  "DownloadHistory" => [
    { "URL" => "https://cdn.example.net/update.exe",
      "Path" => "/Users/user/Downloads/update.exe",
      "DownloadEntryDate" => 2026-01-14 03:41:20 +0000 }
  ]
}
```

Ключевой артефакт — **метка карантина** в расширенных атрибутах скачанного файла. macOS
помечает всё, что пришло из интернета:

```
$ xattr -p com.apple.quarantine ~/Downloads/update.exe
0083;5a1b2c3d;Safari;1B2C3D4E-...
```

Поле после второго `;` — приложение-источник (`Safari`), а hex-число — время в формате
HEX Unix. Это доказывает **каким браузером** и **когда** файл был скачан, даже если историю
Safari очистили.

## Кэш и localStorage

`~/Library/Caches/com.apple.Safari/` содержит `Cache.db` (в новых версиях — WebKit-кэш),
где оседают тела ответов. Полезно, когда страница уже удалена, а её содержимое — в кэше.

```
$ sqlite3 ~/Library/Caches/com.apple.Safari/Cache.db \
"SELECT datetime(time_stamp + 978307200,'unixepoch'), url FROM cfurl_cache_response LIMIT 5;"
```

WebKit-хранилища (`LocalStorage`, `IndexedDB`, `WebSQL`) лежат в
`~/Library/WebKit/com.apple.Safari/WebsiteData/` и могут содержать токены сессий и данные
веб-приложений — иногда это единственное место, где сохранился ключ.

## Таблица: артефакты Safari

| Артефакт | Путь | Что даёт |
|---|---|---|
| История | `~/Library/Safari/History.db` | посещения, время, заголовки |
| Удалённые визиты | `History.db` → `history_tombstones` | следы после очистки |
| Загрузки | `~/Library/Safari/Downloads.plist` | URL, путь, время |
| Карантин | `xattr com.apple.quarantine` на файле | источник и время загрузки |
| Кэш | `~/Library/Caches/com.apple.Safari/Cache.db` | тела ответов |
| Веб-данные | `~/Library/WebKit/com.apple.Safari/WebsiteData/` | localStorage, IndexedDB |
| Закладки | `~/Library/Safari/Bookmarks.plist` | избранное и закладки |
| Последняя сессия | `~/Library/Safari/LastSession.plist` | открытые вкладки |

`LastSession.plist` особенно полезен при анализе «зависшей» машины: он показывает, какие
вкладки были открыты в момент завершения работы — снимок активности пользователя.

## Практический сценарий

Задача: понять, что скачивал пользователь перед заражением. Строим объединённый таймлайн:

```
$ sqlite3 ~/Library/Safari/History.db "SELECT datetime(visit_time+978307200,'unixepoch'), i.url FROM history_visits v JOIN history_items i ON i.id=v.history_item WHERE visit_time > 730000000;" > tl.txt
$ for f in ~/Downloads/*; do echo "$(xattr -p com.apple.quarantine "$f" 2>/dev/null) $f"; done >> tl.txt
$ sort tl.txt | tail -20
```

Совпадение времени визита к URL и появления файла с меткой карантина от Safari — почти
прямое доказательство цепочки «зашёл на сайт → скачал → запустил».

## Ограничения

Во-первых, **TCC**: чтение `~/Library/Safari` требует Full Disk Access, иначе доступ
закрыт. Во-вторых, **приватные окна** не пишут историю в основную базу, но могут оставлять
следы в кэше и веб-данных. В-третьих, **очистка** может удалить и tombstones, если была
«полной». В-четвёртых, на новых macOS данные Safari синхронизируются с iCloud, поэтому часть
истории может отсутствовать локально, но быть в облачном бэкапе устройства.

## Если сработало: фиксируем цепочку

Собери в отчёт три вещи: URL (источник), путь и хеш скачанного файла, и метку карантина
(приложение + время). Три независимых источника, сходящиеся во времени, — это цепочка
доказательств, а не совпадение.

## Приватные окна и что от них остаётся

Пользователи считают приватные окна Safari «невидимыми». Форензически это не так. История
посещений действительно не пишется в `History.db`, но:

- **кэш** (`Cache.db`) может содержать тела ответов из приватной сессии;
- **веб-данные** (localStorage, IndexedDB) иногда сохраняются после закрытия;
- **сетевые артефакты** — DNS-кэш, логи роутера, прокси — видят соединения;
- **метка карантина** на скачанном файле не различает приватный и обычный режим.

Поэтому отсутствие записи в истории — не доказательство того, что сайт не посещали.

## Коррелируем с DNS и сетевыми артефактами

Если истории нет, работаем снизу — по сети. На macOS DNS-кэш можно посмотреть так:

```
$ sudo dscacheutil -cachedump -entries Host
$ log show --predicate 'process == "mDNSResponder"' --last 1h | grep -i "query"
```

Записи `mDNSResponder` показывают, какие имена разрешались. Домен C2, появившийся в логах
DNS в то же время, что и запуск подозрительного процесса, — сильная зацепка даже без истории
браузера.

## Восстановление удалённых записей SQLite

Даже после `DELETE` строки могут остаться в **свободных страницах** файла базы. Пока не
прошла `VACUUM`, данные физически на диске. Их извлекают по `unallocated`-пространству базы:

```
$ sqlite3 ~/Library/Safari/History.db "PRAGMA freelist_count;"   # сколько свободных страниц
$ strings History.db | grep -E 'https?://' | tail -20
```

`strings` по файлу базы часто возвращает URL из удалённых записей — простой, но действенный
приём. Для более полного восстановления используют карвинг по страницам SQLite или утилиты
вроде `undark`.

## Таймлайн: объединяем всё

Собираем единый таймлайн из истории, загрузок, карантина и веб-данных, отсортированный по
времени. Это показывает **поведение** пользователя, а не разрозненные факты:

```
$ (sqlite3 History.db "SELECT visit_time+978307200, 'visit', i.url FROM history_visits v JOIN history_items i ON i.id=v.history_item;"; \
   plutil -convert json -o - Downloads.plist | python3 -c "import json,sys;[print(x.get('DownloadEntryDate',''),'dl',x.get('URL','')) for x in json.load(sys.stdin).get('DownloadHistory',[])]") | sort -n | tail
```

Так видно цепочку: поиск → переход на сайт → скачивание → запуск.

## Ограничения

Кэш Safari на новых версиях переехал в WebKit-формат и не всегда читается старыми запросами
к `cfurl_cache_response`. Приватные сессии оставляют меньше следов. А если включён iCloud
для Safari, часть данных уходит в облако и локально отсутствует. Всегда указывай, какие
источники ты проверил и какие оказались пустыми — это часть доказательной базы.

## Итог

Safari оставляет связанный набор артефактов: историю, загрузки, карантин, кэш и веб-данные.
Ни один из них по отдельности не полон, но вместе они восстанавливают маршрут пользователя
от поиска до запуска скачанного файла. Работай на копии образа и проверяй каждый источник.

## Проверка целостности при извлечении

Копируй `History.db` вместе с журналами `-wal` и `-shm`, иначе потеряешь незакоммиченные
визиты. Считай SHA-256 каждого файла до и после анализа и работай только с копией, чтобы
исключить изменение улики. Для больших образов удобно извлекать артефакты по путям из
таблицы выше и сразу складывать их в отдельный каталог с хешами и исходными путями.

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
