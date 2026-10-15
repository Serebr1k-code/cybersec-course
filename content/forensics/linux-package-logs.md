---
id: linux-package-logs
title: 'Логи менеджера пакетов: что устанавливали и когда'
category: forensics
parent: forensics-linux-deep
difficulty: medium
order: 4
tags: [linux, dpkg, apt, rpm, yum, packages, forensics]
prerequisites: [forensics-linux-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ Linux-хостов'
estimated_minutes: 45
summary: 'Как по dpkg/apt и rpm/yum восстановить историю установки ПО, найти свежие и подозрительные пакеты.'
lab:
  kind: shell
  title: 'Практика: Логи менеджера пакетов'
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

На сервере обнаружен неизвестный инструмент. Откуда он? Установлен вручную, пришёл с
обновлением или его поставил злоумышленник? Менеджер пакетов ведёт журнал — и это
один из самых недооценённых форензик-артефактов Linux.

## Наш пример: неизвестный netcat-форк

Предположим, на хосте лежит бинарник `/usr/bin/nc.traditional` странного вида. Смотрим
историю пакетов Debian/Ubuntu.

## Шаг 1: основной журнал dpkg

```
$ grep -i 'netcat\|nc\.' /var/log/dpkg.log
2026-01-14 03:20:11 install netcat-traditional:amd64 <none> 1.10-47
```

Строка говорит: `install`, пакет `netcat-traditional`, версия `1.10-47`, время
`03:20` — ровно в те же минуты, что и подозрительный вход по SSH. Совпадение по
времени — сильный сигнал.

## Шаг 2: журнал apt

`apt` пишет отдельный лог с более человекочитаемыми записями:

```
$ grep -i netcat /var/log/apt/history.log
Start-Date: 2026-01-14  03:20:08
Commandline: apt-get install -y netcat-traditional
```

Здесь виден **Commandline** — как именно вызывалась установка. `-y` означает
«соглашаться автоматически» — типично для скрипта, а не человека.

## Шаг 3: rpm/yum (RHEL/CentOS)

На rpm-системах другой путь:

```
$ grep -i nmap /var/log/dnf.log
2026-01-14T03:22:10Z DDEBUG Installed: nmap-7.94-1.el9.x86_64
```

А полный список установленного — через базу rpm:

```
$ rpm -qa --last | head -5
nmap-7.94-1.el9.x86_64            Thu 14 Jan 2026 03:22:10 AM UTC
```

`--last` сортирует по времени установки — свежие пакеты сразу на виду.

## Шаг 4: что осталось от пакета

Даже если пакет удалили, dpkg хранит следы:

```
$ grep -i netcat /var/log/dpkg.log | grep -E 'remove|purge'
2026-01-14 03:40:02 remove netcat-traditional:amd64 1.10-47 <none>
```

Установили в `03:20`, удалили в `03:40` — короткое окно использования. Само удаление
тоже улика: злоумышленник заметает следы.

## Шаг 5: сопоставляем всё

Собираем таймлайн:

```
03:20:08  apt install netcat-traditional
03:20:11  dpkg install
03:22:10  dnf install nmap
03:40:02  dpkg remove netcat-traditional
```

Каждая строка — независимое подтверждение. Если менеджер пакетов не использовался
(бинарник просто скопирован), в логах ничего не будет — тогда смотрим `~/.bash_history`
и временные метки самого файла (`stat`).

## Что мы теперь знаем

- `/var/log/dpkg.log` — установки/удаления Debian/Ubuntu.
- `/var/log/apt/history.log` — команды apt, включая Commandline.
- `dnf.log` / `rpm -qa --last` — RHEL-семейство.
- Установка и удаление в коротком окне — признак заметания следов.
- Нет записи в пакетном менеджере = бинарник скопирован вручную.

## Если не сработало

- Логи ротированы? Проверь `dpkg.log.1`, `.gz`.
- Файл скопирован вручную? Смотри `stat`, `bash_history`, `auditd`.
- Контейнер? Пакеты могли ставиться в образ — тогда смотри Dockerfile/слой.

## Полный набор артефактов менеджеров пакетов

Кроме `dpkg.log` есть ещё несколько источников — их стоит проверять вместе:

| Артефакт | Что содержит |
|---|---|
| `/var/log/dpkg.log` | install/remove/purge/upgrade (Debian/Ubuntu) |
| `/var/log/apt/history.log` | команды apt + Requested-By |
| `/var/log/apt/term.log` | вывод установки (иногда с предупреждениями) |
| `/var/lib/dpkg/status` | текущее состояние всех пакетов |
| `/var/lib/dpkg/info/` | файлы и скрипты (maintainer scripts) |
| `/var/log/dnf.log`, `yum.log` | RHEL/Fedora |
| `/var/lib/rpm/` | база rpm |
| `/var/log/apt/eipp.log.xz` | расширенная история apt |

`/var/lib/dpkg/info/*.list` хранит список файлов пакета — по нему видно, что именно
«приехало» вместе с пакетом, включая конфиги и скрипты.

## dpkg: логи и статус

```
$ grep -E 'install |remove |purge ' /var/log/dpkg.log | tail
$ grep -A3 -B1 'netcat' /var/log/dpkg.log.1 /var/log/dpkg.log
$ dpkg -l | awk '$1=="ii"{print $2, $3}' | head     # установленные пакеты
```

Обрати внимание на **время и версию**: свежий install пакета, которого нет в базовом
образе, — подозрительно. Особенно если это тул вроде `nmap`, `netcat`, `socat`, `tcpdump`,
`chisel`, `frp`.

## apt: history и term

`apt/history.log` даёт командную строку, что критично для восстановления намерения:

```
$ grep -E 'Start-Date|Commandline|Install:|Remove:' /var/log/apt/history.log | tail -20
Start-Date: 2026-01-14  03:20:08
Commandline: apt-get install -y nmap socat
Requested-By: www-data (33)
Install: nmap:amd64 (7.94), socat:amd64 (1.7.4.1)
```

`Requested-By: www-data` означает, что установку запустил веб-сервер — почти наверняка
через RCE веб-приложения. Это прямой индикатор компромисса.

## rpm/yum/dnf

На RHEL-семействе:

```
$ rpm -qa --last | head -10
$ grep -iE 'Installed|Erased' /var/log/dnf.log | tail
$ dnf history list | head
$ rpm -qi nmap | grep -E 'Install Date|Vendor'
```

`dnf history` показывает целые транзакции с командами — аналог apt history.

## Верификация целостности пакета

Чтобы понять, изменён ли бинарник после установки:

```
$ debsums -c                       # Debian: файлы, не совпадающие с пакетом
$ rpm -Va | grep -v '^S.5'         # RHEL: проверка всех файлов
$ dpkg -V                          # пересчёт хэшей установленных пакетов
```

Если `debsums`/`rpm -V` показывает расхождение — файл пакета подменён (троянизация).

## Ручная установка: следы без менеджера

Если бинарник скопирован вручную (curl/wget), в dpkg/apt его не будет. Тогда:

```
$ stat /usr/bin/suspicious | grep -E 'Modify|Change'
$ grep -aiE 'wget|curl|chmod \+x|scp' ~/.bash_history /root/.bash_history
$ find / -newermt '2026-01-14 03:00' -type f -not -path '/proc/*' 2>/dev/null | head
$ grep -a 'execve' /var/log/audit/audit.log | grep suspicious | tail
```

`find -newermt` по времени инцидента — быстрый способ найти всё, что появилось в окне.

## Практический разбор и чек-лист

1. Найти подозрительный бинарник (`find`, `stat`, `debsums`).
2. Проверить `dpkg.log`/`apt/history.log`/`dnf.log` на его пакет.
3. Если пакет есть — взять время, версию, Commandline, Requested-By.
4. Проверить `remove`/`purge` в коротком окне (заметание следов).
5. Если пакета нет — искать ручную установку (`bash_history`, `auditd`, `find -newermt`).
6. Проверить целостность (`debsums -c`, `rpm -Va`).

## Ограничения

- Логи ротируются и сжимаются — проверяй `.1`, `.gz` (`zgrep`).
- В контейнерах пакеты ставятся в слой образа — смотри `Dockerfile`/`docker history`.
- Умный атакующий чистит `dpkg.log` — тогда опирайся на `auditd`, `find`, метки файлов.
- `Requested-By` может отсутствовать у старых версий apt.

## Полная карта пакетных логов

Разные дистрибутивы и разные версии менеджеров пишут в разные файлы. Держи карту:

| Система | Основные файлы |
|---|---|
| Debian/Ubuntu | `/var/log/dpkg.log`, `/var/log/apt/history.log`, `/var/log/apt/term.log` |
| RHEL/CentOS/Fedora | `/var/log/dnf.log`, `/var/log/yum.log`, `/var/log/dnf.rpm.log` |
| SUSE | `/var/log/zypp/history`, `/var/log/zypper.log` |
| Arch | `/var/log/pacman.log` |
| Alpine | `/var/log/apk.log` |

Кроме логов есть **базы** установленного: `dpkg -l`, `rpm -qa`. Логи показывают
**историю**, базы — **текущее состояние**. Для расследования нужны оба: лог скажет
«когда и как поставили», база — «стоит ли сейчас».

## Чтение dpkg.log: формат строк

Строки `dpkg.log` имеют фиксированный формат:

```
2026-01-14 03:20:11 install netcat-traditional:amd64 <none> 1.10-47
2026-01-14 03:40:02 remove  netcat-traditional:amd64 1.10-47 <none>
```

Поля: дата, время, действие (`install`/`upgrade`/`remove`/`purge`/`configure`), пакет с
архитектурой, старая версия, новая версия. `<none>` означает «версии не было» (при
установке) или «версии не стало» (при удалении).

Полезные выборки:

```
$ grep -E ' (install|remove|purge) ' /var/log/dpkg.log | tail -20
$ grep -iE 'nc|nmap|socat|tcpdump' /var/log/dpkg.log
```

Ротация: старые записи в `dpkg.log.1`, `dpkg.log.2.gz` — проверяй и их.

## RPM-системы глубже

`rpm -qa --last` сортирует по времени установки, но не показывает удалённые пакеты.
Историю удалений ищи в логах:

```
$ grep -iE 'Erase|Install|Obsoleted' /var/log/dnf.log | tail
$ rpm -q --last --qf '%{INSTALLTIME:date} %{NAME}\n' | head
```

Проверка целостности установленных файлов — важный шаг:

```
$ rpm -Va | grep -v '^.........'    # изменённые файлы пакетов
```

Если файл пакета изменён (`rpm -Va` показывает `5` в поле хеша), это признак подмены
бинарника или конфига.

## Пакеты vs ручная установка

Не всё приходит через менеджер пакетов. Различай:

- **пакет** — есть запись в логе и в базе, файлы отслеживаются;
- **ручная установка** (`make install`, `dpkg -i` без регистрации, скрипт) — может не
  оставить записи;
- **скопированный бинарник** — вообще нет следов в пакетном менеджере.

Для «ручных» артефактов работают другие источники:

```
$ stat /usr/local/bin/suspicious      # времена создания/изменения
$ ls -la /usr/local/bin/              # что появилось свежее
$ cat ~/.bash_history | grep -i 'curl\|wget\|chmod'
$ ls -la /tmp/                        # место выгрузки
```

## Инструменты

- `dpkg -S <file>` — какому пакету принадлежит файл;
- `dpkg -l` / `apt list --installed` — список пакетов;
- `rpm -qf <file>` / `rpm -qa --last` — RPM-аналоги;
- `debsums` / `rpm -Va` — проверка целостности;
- `apt-mark showmanual` — что ставили вручную (Debian);
- `unattended-upgrades` логи — автоматические обновления (чтобы не путать с атакой).

## Сводный пример расследования

Соберём всё в один практический сценарий. На сервере найден подозрительный
`/usr/bin/nc.traditional`, и нужно понять его происхождение:

1. `grep -i netcat /var/log/dpkg.log` → установлен `03:20:11`;
2. `grep -i netcat /var/log/apt/history.log` → `Commandline: apt-get install -y ...`;
3. `last -a | head` → вход по SSH с `203.0.113.5` в `03:19`;
4. `dpkg -S /usr/bin/nc.traditional` → файл принадлежит пакету `netcat-traditional`;
5. `grep -i netcat /var/log/dpkg.log | grep remove` → удалён в `03:40`.

Пять источников сходятся: злоумышленник вошёл, поставил netcat, использовал и удалил.
Отсутствие записи о пакете заставило бы искать артефакты ручной установки — `stat`,
`bash_history`, `/tmp`.

## Квиз

Проверь себя.

```quiz
- question: Какой файл хранит установки/удаления пакетов в Debian/Ubuntu?
  options:
    - '/etc/passwd'
    - '/var/log/dpkg.log'
    - '/var/log/kern.log'
    - '/etc/apt/sources.list'
  answer: 1
  explanation: 'dpkg.log фиксирует install/remove/purge с версиями и временем.'
- question: Что даёт /var/log/apt/history.log помимо dpkg.log?
  options:
    - 'ничего'
    - 'Commandline — как именно вызывалась установка'
    - 'пароли'
    - 'сетевые соединения'
  answer: 1
  explanation: 'apt history.log содержит точную командную строку установки.'
- question: Чем подозрительно «установил и через 20 минут удалил»?
  options:
    - 'это норма'
    - 'короткое окно использования и заметание следов'
    - 'диск перегреется'
    - 'обновление ядра'
  answer: 1
  explanation: 'Быстрая установка-удаление типична для одноразового инструмента.'
- question: Бинарника нет ни в dpkg.log, ни в apt — что вероятнее?
  options:
    - 'пакет установлен штатно'
    - 'файл скопирован вручную, в обход менеджера пакетов'
    - 'система не Linux'
    - 'лог повреждён'
  answer: 1
  explanation: 'Отсутствие записи означает ручную загрузку/копирование файла.'
```
