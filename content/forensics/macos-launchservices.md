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

## QuarantineEventsV2: схема и запросы

Журнал карантина — это SQLite-база, и её схема стабильна. Главная таблица —
`LSQuarantineEvent` со столбцами:

| Столбец | Что содержит |
|---|---|
| `LSQuarantineEventIdentifier` | UUID записи |
| `LSQuarantineTimeStamp` | время в Apple epoch (с 2001-01-01) |
| `LSQuarantineAgentName` | приложение-загрузчик (Safari, Chrome, curl) |
| `LSQuarantineAgentBundleIdentifier` | bundle id загрузчика |
| `LSQuarantineOriginURLString` | страница, с которой началась загрузка |
| `LSQuarantineDataURLString` | прямой URL файла |
| `LSQuarantineTypeNumber` | тип события (загрузка, письмо и т.п.) |

Полезные запросы:

```
$ sqlite3 QuarantineEventsV2 \
  'SELECT datetime(LSQuarantineTimeStamp+978307200,"unixepoch"), LSQuarantineAgentName, LSQuarantineDataURLString FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp;'
```

`Origin` важнее, чем `Data`: часто файл тянется с CDN, а страница-источник указывает
на фишинг. Если `LSQuarantineAgentName` = `curl`, значит загрузку инициировал скрипт, а
не браузер, — сильный признак автоматизации.

## LSHandlers и secure.plist

Помимо журнала, LaunchServices хранит **связи** типов файлов с приложениями. Они
лежат в бинарных plist:

```
$ plutil -p ~/Library/Preferences/com.apple.LaunchServices/com.apple.LaunchServices.secure.plist
```

Внутри — массив `LSHandlers`, где каждая запись связывает тип (`LSHandlerContentType`)
или схему URL (`LSHandlerURLScheme`) с приложением (`LSHandlerRoleAll`). Аномалии:

- незнакомое приложение забирает `http`/`https` — перехват браузера;
- расширение `.pdf` открывается подозрительным бинарником;
- запись ссылается на путь в `/tmp` или `~/Library/Application Support`.

Всё это признаки перехвата ассоциаций и запуска чужого кода.

## Атрибуты xattr и происхождение файла

Атрибут `com.apple.quarantine` переносится вместе с файлом и переживает копирование
(если копировать утилитой, сохраняющей xattr). Формат:

```
com.apple.quarantine: <flags>;<hex-time>;<agent>;<uuid>
```

Флаги — битовая маска: `0001` (заблокирован), `0002` (пользователь подтвердил),
`0040` (тип «downloaded»), `0080` (неизвестный источник). Например, `0083` = набор
флагов, означающий загрузку из интернета. Если файл найден **без** атрибута, но с
признаками загрузки — атрибут сняли (`xattr -d com.apple.quarantine`), а это само по
себе улика заметания.

## Сопоставление с другими артефактами macOS

Карантин отвечает на «что скачали», но не «что запустили». Связывай его с:

- **Unified log** (`log show`) — запуск приложений, предупреждения Gatekeeper;
- **KnowledgeC.db** — история активности приложений по времени;
- **FSEvents** (`.fseventsd`) — создание/изменение файлов в директориях;
- **TCC.db** — какие приложения получили доступ к камере/микрофону/диску;
- **Spotlight-индекс** — следы существования удалённого файла.

Комбинация «карантин (скачан) → FSEvents (появился) → KnowledgeC (запущен)» строит
полный таймлайн выполнения.

## Ограничения

- **Карантин ставит не всё.** Файлы, созданные локально или распакованные из архива
  (не скачанные напрямую), могут не иметь записи.
- **Записи стары.** База ограничена по количеству; старые события вытесняются.
- **Apple epoch.** Забыть про +978307200 — частая ошибка, времена уедут на 31 год.
- **Бинарные plist.** Читать только через `plutil`, иначе увидишь мусор.
- **Файл может быть удалён.** Тогда работают FSEvents и Spotlight.

## Структура QuarantineEventsV2

`QuarantineEventsV2` — это база SQLite с единственной таблицей `LSQuarantineEvent`.
Полезные столбцы:

| Столбец | Смысл |
|---|---|
| `LSQuarantineEventIdentifier` | UUID события |
| `LSQuarantineTimeStamp` | время в Apple epoch (сек с 2001-01-01) |
| `LSQuarantineAgentName` | кто скачал (Safari, Chrome, curl) |
| `LSQuarantineAgentBundleIdentifier` | bundle-id загрузчика |
| `LSQuarantineDataURLString` | **откуда** скачан файл |
| `LSQuarantineOriginURLString` | страница-источник |
| `LSQuarantineSenderName` | отправитель (для почты/мессенджеров) |
| `LSQuarantineTypeNumber` | тип события |

Отсюда восстанавливается полный путь загрузки: `OriginURL` (страница) → `DataURL`
(сам файл) → `AgentName` (чем) → время. Это одна из самых ценных «цепочек доставки» в
macOS-форензике.

## Apple epoch и конвертация

macOS (и многое другое в экосистеме Apple) считает время в секундах от **2001-01-01
00:00:00 UTC**. Чтобы получить unix-время, прибавляем `978307200`:

```
$ python3 -c "print(1705192091 - 978307200)"   # unix -> apple
$ sqlite3 db 'SELECT datetime(LSQuarantineTimeStamp+978307200,"unixepoch") FROM LSQuarantineEvent;'
```

Обратный переход: `unix = apple + 978307200`. Ошибка в этом смещении «сдвигает» время на
31 год — типичная ошибка новичка. В `xattr` время хранится **в hex** как unix-секунды:

```
$ printf '%d\n' 0x65a3b1f0
1705193968
$ date -d @1705193968
```

## Атрибут quarantine: разбор формата

`com.apple.quarantine` имеет вид `flags;hex_time;agent;uuid`:

```
$ xattr -l payload.dmg
com.apple.quarantine: 0083;65a3b1f0;Safari;A1B2C3D4-...
```

- `flags` — битовая маска (какие типы данных получены, был ли файл открыт);
- `hex_time` — unix-время скачивания в hex;
- `agent` — приложение, скачавшее файл;
- `uuid` — идентификатор события, связывает файл с записью в `QuarantineEventsV2`.

Связка «файл → UUID → запись в базе» позволяет доказать происхождение файла, даже если
его mtime подделан.

## LaunchServices plist: LSHandlers

Файл `com.apple.LaunchServices.secure.plist` (бинарный) хранит ассоциации «тип файла →
приложение». Читается через `plutil -p` или `plutil -convert xml1`:

```
$ plutil -p ~/Library/Preferences/com.apple.LaunchServices/com.apple.LaunchServices.secure.plist | head -20
$ plutil -convert xml1 -o - file.plist
```

Подмена ассоциации (например, `.txt` открывается сторонним приложением) — признак
перехвата. Смотри `LSHandlerContentType` и `LSHandlerRoleAll`.

## Практический разбор и чек-лист

1. Найти `QuarantineEventsV2` у всех пользователей.
2. Выгрузить события за окно инцидента (с конвертацией Apple epoch).
3. Проверить `xattr` на найденных файлах — связать с событием по UUID.
4. Прочитать `LaunchServices.secure.plist` — нет ли подменённых ассоциаций.
5. Сопоставить с `knowledgeC.db` и unified log — был ли реальный запуск.
6. Задокументировать цепочку «страница → файл → запуск».

## Связь LaunchServices с Gatekeeper

Карантин — это ещё и механизм **Gatekeeper**: при первом запуске скачанного приложения
система сверяет подпись и показывает предупреждение. Если приложение неподписано, запись
об этом остаётся в unified log (`CoreServicesUIAgent`, `syspolicyd`), а сам факт запуска
фиксируется в `knowledgeC.db`. Поэтому цепочку стоит доводить до конца:

```
$ log show --predicate 'process == "syspolicyd"' --start "2026-01-14 03:00" | grep -i payload
$ sqlite3 /private/var/db/CoreDuet/Knowledge/knowledgeC.db \
  "SELECT ZVALUESTRING FROM ZOBJECT WHERE ZVALUESTRING LIKE '%payload%';"
```

Так видно не только «скачали», но и «пытались запустить» — это разные стадии инцидента, и
в отчёте их важно разделять.

## Где физически лежит база LaunchServices

Пользователи часто ищут «реестр macOS» в одном файле и не находят. На самом деле
данные LaunchServices разбросаны:

- `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` — журнал
  карантина (SQLite);
- `~/Library/Preferences/com.apple.LaunchServices/` — каталог с plist-ами связей;
- `/private/var/folders/<xx>/<yyyy>/0/com.apple.LaunchServices-<uid>.csstore` —
  **основная база** связей (проприетарный формат);
- `~/Library/Application Support/com.apple.sharedfilelist/` — списки «недавних»
  для приложений.

Каталог `/private/var/folders/` — это `$TMPDIR` пользователя, и он **не входит** в
обычный Time Machine-бэкап. Поэтому `.csstore` часто отсутствует в копиях, а
`QuarantineEventsV2` остаётся — учитывай это при анализе.

## csstore: главная база связей

`.csstore` — бинарная база (CoreServices Store), в которой лежат зарегистрированные
приложения, их bundle id и ассоциации. Она не читается `plutil`, но её можно
разобрать специализированными инструментами:

```
$ ls -la /private/var/folders/*/*/0/com.apple.LaunchServices-*.csstore
-rw-r--r--  1 user staff  912384 Jan 14 03:40 com.apple.LaunchServices-501.csstore
```

Внутри — список приложений с путями и датами регистрации. Если приложение
«зарегистрировалось» позже, чем появилось на диске, это может указывать на ручное
вмешательство. Для чтения используй `mac_apt` или плагин Apollo (`launch_services`).

## Восстановление удалённых записей карантина

SQLite хранит удалённые строки в свободных страницах, и их можно вытащить:

```
$ sqlite3 QuarantineEventsV2 'PRAGMA freelist_count;'
$ strings QuarantineEventsV2 | grep -i 'http'
```

Дополнительно проверь WAL и SHM-файлы (`-wal`, `-shm`) — там могут быть ещё не
сброшенные записи. Если база повреждена, `sqlite3 .recover` вытащит максимум:

```
$ sqlite3 broken.db '.recover' | grep -i 'quarantine'
```

Так восстанавливаются записи о загрузках, которые злоумышленник пытался стереть,
удалив строки из базы.

## Инструменты для macOS-форензики

Ручные запросы — база, но для системного анализа есть готовые парсеры:

| Инструмент | Что даёт |
|---|---|
| `mac_apt` | единый парсер артефактов macOS |
| `APOLLO` | плагины по LaunchServices, quarantine, TCC |
| `MVT` (Mobile Verification Toolkit) | iocs-сверка, в т.ч. macOS |
| `plutil` | чтение бинарных plist |
| `log` / `log show` | unified log, фильтры по процессу |
| `sqlite3` | прямые запросы к базам |

Типовой прогон:

```
$ mac_apt -i /evidence/root -o /out -t LAUNCHSERVICES,QUARANTINE
```

Инструмент сам конвертирует Apple epoch и выдаёт CSV/таблицы, что удобно для отчёта.

## Разбор кейса: от загрузки до запуска

Соберём цепочку целиком:

1. `QuarantineEventsV2` показывает: `payload.dmg` скачан `03:28:11` с
   `203.0.113.5` агентом `Safari`.
2. `xattr` на найденном файле подтверждает hex-время `65a3b1f0` = `03:28`.
3. `FSEvents` фиксирует монтирование DMG и появление `.app` в `/Applications`.
4. `KnowledgeC.db` показывает запуск приложения в `03:31`.
5. `unified log` содержит предупреждение Gatekeeper о неподписанном разработчике.

Пять независимых источников, согласованных по времени, — это доказательная база, а не
догадка. Если один источник «молчит», а остальные указывают на запуск — источник
подчистили.

## Как отличить легитимную загрузку от вредоносной

Не каждый `QuarantineEvent` — инцидент. Признаки подозрительного:

- загрузчик — `curl`/`wget`, а не браузер (скриптовая загрузка);
- `DataURL` — голый IP-адрес, а не домен;
- файл в `/tmp`, `~/Library/Application Support`, скрытой папке;
- отсутствие подписи и нотаризации;
- время — вне рабочих часов;
- сразу после загрузки — запуск (по KnowledgeC/unified log).

Комбинация нескольких признаков превращает «скачал файл» в «выполнил полезную
нагрузку».

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
