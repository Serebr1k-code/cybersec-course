---
id: macos-persistence
title: "Persistence на macOS: LaunchAgents и LaunchDaemons"
category: forensics
parent: forensics-macos-deep
difficulty: hard
order: 4
tags: [macos, persistence, launchagents, launchdaemons, plist, forensics]
prerequisites: [forensics-macos-deep, forensics-macos-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "macOS forensics"
  - "Threat Hunting"
estimated_minutes: 55
summary: "Как macOS запускает программы автоматически и как по plist-файлам LaunchAgents/LaunchDaemons найти закрепление злоумышленника."
lab:
  kind: shell
  title: "Практика: найти закрепление в plist"
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md, com.apple.softwareupdated.plist]
  check: "grep -q 'nto{' found.txt"
  hints:
    - 'Посмотри список автозапуска: `cat com.apple.softwareupdated.plist`.'
    - 'Найди путь к запускаемой программе: `grep -i ProgramArguments com.apple.softwareupdated.plist`.'
    - 'Проверь строки с меткой: `grep nto com.apple.softwareupdated.plist`.'
    - 'Собери ответ: `grep nto com.apple.softwareupdated.plist > found.txt`.'
---

## Вопрос, с которого всё начинается

На macOS-хосте после инцидента нужно понять: что запускается автоматически? На Windows ты бы
пошёл смотреть Run-ключи реестра и задачи планировщика. У macOS та же роль у **launchd** —
системного менеджера, который по plist-файлам запускает программы при входе, по таймеру или
при событии. Если злоумышленник закрепился, почти наверняка он оставил такой plist.

## Наш пример: подозрительный LaunchAgent

Тебе попал файл автозапуска:

```
~/Library/LaunchAgents/com.apple.softwareupdated.plist
```

Имя мимикрирует под системный процесс Apple, но лежит в пользовательской папке — уже странно.
Разберём его целиком.

## Что такое plist

**plist** (property list) — это формат описания настроек macOS. Это либо XML, либо бинарный
формат `bplist00`, либо JSON. Запускаемая программа задаётся в словаре `<dict>`, где ключи —
это имена настроек, а значения — строки, числа, массивы или булевы флаги. Ключевые для нас:

| Ключ | Что значит |
|------|------------|
| `Label` | уникальное имя задачи |
| `ProgramArguments` | команда и аргументы запуска |
| `Program` | путь к бинарнику (альтернатива массиву) |
| `RunAtLoad` | запускать при загрузке задачи |
| `KeepAlive` | держать процесс живым, перезапускать |
| `StartInterval` | запуск каждые N секунд |
| `StartCalendarInterval` | запуск по расписанию |
| `WatchPaths` | запуск при изменении пути |
| `Disabled` | отключена ли задача |

## Шаг 1: три места автозапуска

launchd читает plist из нескольких каталогов, и это важно для расследования:

```
/Library/LaunchDaemons/      # системные демоны, старт при загрузке, от root
/Library/LaunchAgents/       # агенты всех пользователей, старт при логине
~/Library/LaunchAgents/      # агенты конкретного пользователя
```

Пользовательский `~/Library/LaunchAgents/` — любимое место вредоносов: туда не нужен root.
Системный `LaunchDaemons` требует root, но зато даёт запуск до входа пользователя.

## Шаг 2: читаем наш plist

```
$ cat com.apple.softwareupdated.plist
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>Label</key><string>com.apple.softwareupdated</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>/Users/jdoe/Library/Caches/.upd/agent</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  ...
```

Читаем по-человечески: задача с меткой `com.apple.softwareupdated` при загрузке запускает
`/bin/sh -c /Users/jdoe/Library/Caches/.upd/agent`. Бинарник спрятан в скрытом каталоге
`.upd` внутри `Library/Caches` — это классический приём: имя похоже на кэш, а `KeepAlive`
означает, что процесс будет перезапускаться, даже если его убить.

## Шаг 3: что искать в любом plist

Смотри не на `Label` (его подделывают), а на **`ProgramArguments` / `Program`**. Признаки
вредоносного закрепления:

- запуск через `/bin/sh -c` с длинной командой;
- бинарник в `/tmp`, `/var/tmp`, `~/Library/Caches`, скрытой папке с точкой;
- base64-строка прямо в аргументах (`echo <blob> | base64 -d | sh`);
- скачивание из сети (`curl`, `osascript`);
- `RunAtLoad` + `KeepAlive` на непонятный бинарник;
- несоответствие `Label` и реального пути (Apple-имя, но путь пользователя).

## Шаг 4: как перечислять задачи

Ручной обход каталогов:

```
$ ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons
```

Загруженные сейчас задачи (включая те, чьи plist удалили, но процесс жив):

```
$ launchctl list | grep -v com.apple
```

Для бинарных plist используй `plutil -p file.plist` — он выведет их как XML/текст. Для
проверки подписи бинарника, на который ссылается задача, — `codesign -dv --verbose=4 <bin>`:
неподписанный или самоподписанный бинарник в автозапуске почти всегда подозрителен.

## Шаг 5: таймстемпы как улика

Дата создания plist (`stat -f '%SB %N'`) показывает, когда закрепились. Сопоставь её с
первым запуском процесса и с событиями в unified log — получишь момент компромисса.
Удалённый, но оставшийся в `launchctl list` агент указывает на попытку замести следы.

## Что мы теперь знаем

- Автозапуск macOS живёт в plist-файлах, которые читает launchd.
- Ключевые поля — `ProgramArguments`/`Program`, `RunAtLoad`, `KeepAlive`.
- Пользовательский `~/Library/LaunchAgents/` — типовое место закрепления.
- Ищи запуск через shell, бинарники в кэше/скрытых папках, подмену `Label`.
- `launchctl list` и `plutil -p` помогают искать даже удалённые задачи.

## Сравнение с Windows и Linux

Полезно держать в голове аналогию: механизм закрепления есть в каждой ОС, и навык переносится.

| ОС | Механизм автозапуска | Где смотреть |
|----|----------------------|--------------|
| Windows | Run-ключи, Task Scheduler, службы | реестр, `schtasks`, Services |
| Linux | systemd units/timers, cron | `/etc/systemd/system`, crontab |
| macOS | launchd: LaunchAgents/Daemons | `/Library/Launch*`, `~/Library/LaunchAgents` |

Отличие macOS в том, что launchd — единая точка для всех видов запуска: по загрузке, по
таймеру, по событию файловой системы. Поэтому если на Mac что-то стартует само — это почти
всегда plist.

## Разбор реального случая

Представь, что после фишинга пользователь открыл «документ», который установил агент.
Типичная цепочка выглядит так: пользователь запускает подписанный, но вредоносный файл; тот
создаёт `~/Library/LaunchAgents/com.apple.helper.plist` с `RunAtLoad`; launchd подхватывает
plist и запускает полезную нагрузку при каждом логине. Имя `com.apple.*` выбрано, чтобы
оператор при беглом взгляде принял задачу за системную.

Что выдаёт эту схему:

- plist создан **после** установки приложения (сравни время создания файлов);
- `ProgramArguments` ведёт в `~/Library/Caches` или `/tmp`, а не в `/Applications`;
- бинарник **не подписан** или подписан ad-hoc (`codesign -dv` вернёт `Signature=adhoc`);
- в `Label` есть `com.apple.`, но Apple такой задачи не выпускает.

## Проверка подписи и нотаризации

Современный macOS не запустит неподписанный бинарник без обхода Gatekeeper. Поэтому вредонос
либо злоупотребляет легитимным подписанным бинарником (`osascript`, `bash`), либо просит
пользователя снять защиту. Проверка:

```
$ codesign -dv --verbose=4 /path/to/binary
Authority=Developer ID Application: ...
TeamIdentifier=ABCDE12345
```

Отсутствие `Authority` — красный флаг. Самоподписанный или ad-hoc бинарник в автозапуске —
почти наверняка вредонос.

## Мини-практика: перечислить все задачи

На живой системе удобно пройтись по всем каталогам и распечатать метку и программу:

```
$ for d in ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons; do
    echo "== $d"; ls -1 "$d" 2>/dev/null; done
```

Затем для каждой задачи — `plutil -p`, и глазами по `ProgramArguments`. Такой обход находит
даже те plist, которые не отображаются в графических «Элементах входа». А `launchctl list`
покажет задачи, загруженные в память, включая те, чей файл уже удалён.

## Другие механизмы автозапуска на macOS

launchd — не единственный способ. Зная все места, ты не пропустишь закрепление:

- **Login Items** — список приложений, стартующих при входе; хранится в
  `com.apple.loginitems.plist` и в базе `BackgroundItems` (на новых версиях macOS).
- **Cron и periodic** — классические Unix-задачи: `/etc/crontab`, `/etc/periodic/`,
  пользовательские `crontab -l`. На macOS они работают наряду с launchd.
- **Login/Logout hooks** — `com.apple.loginwindow` с хуками `LoginHook`/`LogoutHook`.
- **StartupItems** — устаревший, но иногда встречающийся каталог `/Library/StartupItems`.
- **Профили конфигурации (MDM)** — `profiles` могут добавлять задачи централизованно.

Полноценный аудит автозапуска проверяет **все** эти точки, а не только LaunchAgents.

## Периодические задачи

`StartInterval` и `StartCalendarInterval` в plist запускают программу по расписанию — это
эквивалент cron. Вредоносы любят такие задачи: они работают без действий пользователя и
незаметны в списке «Элементов входа». Если в plist стоит `StartInterval` со значением в
секундах (например 300), задача будет обращаться «домой» каждые пять минут — это ещё и
маяк (beacon) для C2.

## Мини-разбор: три подозрительных plist

| Label | ProgramArguments | Почему подозрительно |
|-------|------------------|----------------------|
| `com.apple.softwareupdated` | `/bin/sh -c ~/Library/Caches/.upd/agent` | Apple-имя + бинарник в скрытом кэше |
| `com.user.sync` | `/usr/bin/osascript -e 'do shell script ...'` | запуск через osascript из plist |
| `com.adobe.helper` | `/tmp/.adobe/helper` | бинарник в `/tmp`, общий каталог |

Общее у всех трёх: реальная цель не совпадает с именем задачи. Именно это и проверяй.

## Что делать при обнаружении

Обнаружив подозрительный plist, действуй аккуратно, чтобы не потерять улики: сохрани копию
plist и бинарника, зафиксируй хеши (`shasum -a 256`), запиши время создания файлов и
идентификатор задачи. Не удаляй задачу сразу — сначала пойми, что она запускает и куда
обращается. Для нейтрализации задачу выгружают (`launchctl bootout`) и только потом удаляют
файл. Спешка здесь стоит утраченного образца.

## Полный сценарий аудита автозапуска

Пройдём весь путь, который стоит повторять на любом подозрительном Mac.

Сначала собери список файлов автозапуска из всех каталогов launchd. Затем для каждого plist
прочитай `Label` и `ProgramArguments` через `plutil -p`. Отфильтруй всё, что ссылается на
бинарники вне `/System`, `/usr` и `/Applications`. Для оставшихся проверь подпись через
`codesign -dv`. Неподписанные, ad-hoc и ссылающиеся на `/tmp` или скрытые каталоги — в
приоритет.

Дальше посмотри, что из этого реально **загружено**:

```
$ launchctl list | awk 'NR>1 {print $3}' | grep -v '^com.apple'
```

Загруженная задача без файла на диске — сильный признак, что plist удалили, но процесс
остался. Проверь его `PID` и открытые файлы: `lsof -p <pid>`. Так можно дойти до полезной
нагрузки, которую «спрятали», убрав plist.

Наконец, восстанови хронологию: время создания plist, время первого запуска процесса и
запись в unified log о запуске. Совпадение дат даёт точный момент компромисса, а имя задачи
и путь бинарника — вектор. Закончи аудит копированием артефактов и хешей для отчёта.

## Почему это важно именно на macOS

Apple-экосистема часто считается «безопасной по умолчанию», и это расслабляет. Но
пользовательский LaunchAgent не требует ни root, ни специальных разрешений — достаточно
записи в домашний каталог. А поскольку имена задач принято делать в стиле `com.apple.*` или
`com.<vendor>.*`, подделка почти не бросается в глаза. Единственная надёжная защита при
расследовании — читать, **что задача запускает**, а не доверять её имени. Привычка сверять
`ProgramArguments` с реальным расположением подписанного бинарника ловит большинство схем
закрепления.

## Квиз

Проверь себя.

```quiz
- question: "В каком каталоге вредонос чаще всего закрепляется без прав root?"
  options:
    - "/Library/LaunchDaemons/"
    - "~/Library/LaunchAgents/"
    - "/System/Library/LaunchDaemons/"
    - "/private/var/db/launchd/"
  answer: 1
  explanation: "Пользовательский ~/Library/LaunchAgents/ не требует root и стартует при логине пользователя."
- question: "Какой ключ plist заставляет задачу запускаться при загрузке?"
  options:
    - "StartInterval"
    - "WatchPaths"
    - "RunAtLoad"
    - "Disabled"
  answer: 2
  explanation: "RunAtLoad запускает программу сразу при загрузке задачи launchd."
- question: "Что сильнее всего намекает на вредоносный LaunchAgent?"
  options:
    - "Label похож на com.apple.*"
    - "ProgramArguments запускает /bin/sh -c с бинарником в скрытой папке кэша"
    - "Указан StartInterval"
    - "Файл лежит в ~/Library"
  answer: 1
  explanation: "Запуск через shell скрытого бинарника из кэша — классический признак закрепления; Label легко подделать."
- question: "Чем вывести содержимое бинарного plist в читаемом виде?"
  options:
    - "cat file.plist"
    - "plutil -p file.plist"
    - "xxd file.plist"
    - "strings -n 2 file.plist"
  answer: 1
  explanation: "plutil -p разбирает и бинарный, и XML plist в человекочитаемый вид."
```

## Куда дальше

Теперь ты умеешь находить закрепление на macOS. В следующем уроке разберём `knowledgeC.db` —
базу, которая расскажет, когда пользователь был активен и какие приложения запускал. Главное
запомни: **смотри не на имя задачи, а на то, что она реально запускает**.

## Где пригодится

- DFIR на macOS: поиск персистентности после компромисса.
- CTF-категория Forensics с дампом файловой системы macOS.
- Threat hunting: периодический аудит автозапуска парка Mac.
