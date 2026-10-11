---
id: forensics-log-analysis
title: "Анализ логов глубоко: journald, syslog, auth"
category: forensics
parent: forensics-logs
difficulty: medium
order: 3
tags: [logs, journald, syslog, auth-log, nginx, apache, linux, forensics]
prerequisites: [forensics-logs]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "SOC / Threat Hunting"
estimated_minutes: 50
summary: "Глубокий анализ системных и сервисных логов Linux: journald, syslog, auth.log, cron, web-серверы — что искать при расследовании и как коррелировать."
---
Логи — хроника системы и сервисов Linux. При расследовании они позволяют восстановить входы, запуск команд, обращения к файлам и выявить аномалии. В отличие от Windows EVTX, Linux-логи разнородны: journald, syslog, auth.log, cron, web-серверы. Этот урок — про их глубокий анализ и корреляцию.

## journald

Современный systemd-лог, бинарный и структурированный. Читается `journalctl` с мощными фильтрами.

```bash
$ journalctl -u ssh --since "2024-03-01" --until "2024-03-02"
$ journalctl -p err -b                 # ошибки текущей загрузки
$ journalctl _PID=1234                 # по PID
$ journalctl _COMM=sshd                # по процессу
$ journalctl -o json-pretty | jq 'select(._COMM=="sshd")'
$ journalctl -k                        # только ядро
$ journalctl --disk-usage              # размер
$ journalctl -o short-iso-precise --utc
```

journald может быть энергонезависимым (`/var/log/journal`) или в памяти (`/run/log/journal`) — во втором случае после перезагрузки логи теряются.

## syslog, auth.log, secure

Классические текстовые логи (`/var/log/`):

| Файл | Содержимое |
|------|-----------|
| `auth.log`/`secure` | SSH-входы, sudo, su |
| `syslog`/`messages` | общие события |
| `cron` | задачи |
| `kern.log` | ядро |
| `dpkg.log` | установка пакетов |
| `wtmp`/`btmp`/`lastlog` | бинарные логи входов |

```bash
$ grep 'Failed password' auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head
$ grep 'Accepted' auth.log
$ grep -E 'sudo|COMMAND=' auth.log | tail
$ grep -E 'useradd|new user' auth.log
# бинарные логи входов
$ last -f wtmp | head
$ lastb -f btmp | head          # неудачные
$ lastlog | head
```

## Cron и systemd-таймеры

Персистентность часто через задачи/таймеры.

```bash
$ cat /etc/crontab; ls /etc/cron.*; crontab -l
$ ls /var/spool/cron/crontabs/
$ systemctl list-timers --all
$ ls /etc/systemd/system/*.timer /etc/systemd/system/*.service
$ grep -r 'wget\|curl\|nc\|/tmp/' /etc/cron* /var/spool/cron 2>/dev/null
```

## Web-логи

```bash
$ awk '{print $1}' access.log | sort | uniq -c | sort -rn | head
$ awk '$9==404{print $1}' access.log | sort | uniq -c | sort -rn | head
$ grep -iE 'cmd=|\.\./|union.*select|eval' access.log | head
```

## Корреляция и таймлайн

Сведите источники в один таймлайн (см. `forensics-plaso`), но для быстрого анализа используйте общие ключи: IP, имя пользователя, время.

```bash
# объединить auth.log и access.log по IP
$ comm -12 <(grep 'Failed' auth.log | awk '{print $(NF-3)}' | sort -u) \
           <(awk '{print $1}' access.log | sort -u)
# пробелы во времени (индикатор очистки)
$ awk '{print $1,$2,$3}' auth.log | uniq | head
```

## Аудит (auditd)

`auditd` фиксирует системные вызовы и доступ к файлам — самый детальный источник.

```bash
$ ausearch -m EXECVE -ts recent | head
$ ausearch -k suspicious_key
$ aureport --summary
$ cat /etc/audit/audit.rules
```

## Разобранный пример

Дан сервер Linux. Нужно найти компрометацию.

```bash
# 1. Брутфорс SSH
$ grep 'Failed password' auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -1
   5400 203.0.113.9
# 2. Успешный вход
$ grep 'Accepted' auth.log | grep 203.0.113.9
# 3. Что делал (sudo)
$ grep 'COMMAND=' auth.log | grep -iE 'wget|curl|chmod|useradd' | head
# 4. Закрепление
$ grep -r 'evil' /etc/cron* /var/spool/cron 2>/dev/null
$ systemctl list-timers | grep -i evil
# 5. Web
$ grep '203.0.113.9' access.log | grep -iE 'cmd=|shell' | head
# 6. Auditd
$ ausearch -ts recent -m EXECVE | grep -i evil | head
```

## Справочная таблица

| Лог | Инструмент |
|-----|-----------|
| journald | `journalctl` |
| auth/syslog | `grep`/`awk` |
| wtmp/btmp | `last`/`lastb` |
| cron | `crontab`/`cat` |
| auditd | `ausearch`/`aureport` |
| web | `awk`/`goaccess` |

## Частые ошибки

- **Читать journald как текст** — он бинарный; используйте `journalctl`.
- **Игнорировать wtmp/btmp** — там история входов.
- **Пропустить cron/systemd** — там персистентность.
- **Не проверять auditd** — самый детальный источник.
- **Забывать про ротацию** — `zcat access.log.*.gz`.
- **Не нормализовать время** — сравнение в UTC.

## Что дальше / решение

Конвейер: `journalctl`/`grep` (события) → `last`/`lastb` (входы) → cron/systemd (закрепление) → auditd (детали) → таймлайн. Связка: `forensics-logs` (приёмы), `forensics-linux-artifacts` (артефакты), `forensics-web-forensics` (веб), `forensics-plaso` (таймлайн).

## Дополнительные источники

| Источник | Что даёт |
|----------|----------|
| `/var/log/btmp` | неудачные входы |
| `/var/log/lastlog` | последний вход каждого пользователя |
| `/var/log/dpkg.log` | установка пакетов |
| `/var/log/apt/history.log` | команды apt |
| `~/.bash_history` | история команд |
| `/var/log/audit/` | auditd |
| `/var/log/sudo.log` | sudo-команды |
| `/var/log/faillog` | неудачи входа |
| `/proc/*/cmdline` | живые процессы |

```bash
# история команд с временем (если HISTTIMEFORMAT)
$ cat /root/.bash_history | grep -iE 'wget|curl|nc|chmod'
# apt-история (установленные инструменты)
$ grep -iE 'install' /var/log/apt/history.log | tail
# неудачные входы
$ lastb -f /var/log/btmp | head
```

## Корреляция по времени и пользователю

```bash
# все события пользователя bob
$ grep -r 'bob' /var/log/auth.log /var/log/syslog | head
# окно инцидента
$ journalctl --since "2024-03-01 12:00" --until "2024-03-01 12:30" -o short-iso
# совпадение IP в разных логах
$ grep -rhoE '([0-9]{1,3}\.){3}[0-9]{1,3}' /var/log/auth.log /var/log/nginx/access.log | sort | uniq -c | sort -rn | head
```

## Сводный чек-лист

1. `journalctl` — системные события (окно инцидента).
2. `auth.log`/`secure` — SSH/sudo.
3. `last`/`lastb` — входы.
4. cron/systemd — закрепление.
5. `bash_history` — команды.
6. apt/dpkg — установленное ПО.
7. auditd — детали syscall.
8. Web-логи — веб-активность.

## Ограничения

- **Ротация** — старые логи сжаты/удалены.
- **Очистка** — `history -c`, `rm /var/log/*`; ищите пробелы.
- **journald в памяти** — теряется после перезагрузки.
- **auditd может быть не настроен** — нет деталей.
- **Часовые пояса** — нормализуйте в UTC.

## Анализ системных вызовов (auditd)

`auditd` фиксирует `EXECVE` (запуск), `SYSCALL`, `PATH`, `CWD`, `USER_AUTH`, `USER_CMD`. По этим записям восстанавливают точную команду, PID, пользователя и файлы.

```bash
# выполнение процессов
$ ausearch -m EXECVE -ts recent | grep -A2 'a0='
# доступ к файлу по ключу
$ ausearch -k etc_passwd
# вход/выход
$ ausearch -m USER_AUTH,USER_LOGIN -ts today | head
# сводный отчёт
$ aureport --auth --summary
$ aureport -f --summary | head
```

## Инструменты: сводка

| Инструмент | Задача |
|-----------|--------|
| `journalctl` | journald |
| `ausearch`/`aureport` | auditd |
| `last`/`lastb`/`lastlog` | входы |
| `grep`/`awk`/`jq` | текст/JSON |
| `goaccess` | web-логи |
| `plaso`/`psort` | супертаймлайн |

## Практические приёмы

- **Начните с аномалий** (`uniq -c`/`sort -rn`).
- **Окно инцидента** — сузьте по времени.
- **Коррелируйте по IP/пользователю**.
- **Проверяйте пробелы** во времени (очистка).
- **Смотрите `auth.log` + `access.log` вместе**.
- **Сохраняйте вывод** для отчёта.
- **Учитывайте ротацию** (`zcat`).

## Отчёт по логам

Укажите: источник логов, окно расследования, найденные аномалии (брутфорс, сканирование, закрепление), атрибуцию (IP/пользователь/время), корреляцию с ФС/памятью. Для каждого вывода — конкретная строка лога как доказательство.

## Квиз

```quiz
- question: "Какой файл в Debian/Ubuntu содержит аутентификацию?"
  options:
    - "/var/log/syslog"
    - "/var/log/auth.log"
    - "/var/log/kern.log"
    - "/var/log/dpkg.log"
  answer: 1
- question: "Как прочитать бинарный журнал journald с образа?"
  options:
    - "cat /var/log/journal"
    - "journalctl -D /mnt/var/log/journal"
    - "grep"
    - "strings"
  answer: 1
- question: "Что указывает на перебор SSH?"
  options:
    - "много 'Failed password' с одного IP"
    - "много 'Accepted'"
    - "строки sudo"
    - "записи cron"
  answer: 0
- question: "Какой признак очистки логов?"
  options:
    - "логи растут"
    - "пропуски во времени и обнулённые/удалённые файлы"
    - "много записей"
    - "ротация"
  answer: 1
- question: "Зачем смотреть сжатые ротации (.gz)?"
  options:
    - "они меньше"
    - "они содержат прошлые события, возможно до атаки"
    - "они зашифрованы"
    - "они не нужны"
  answer: 1
```

## Где пригодится

- **CTF:** задачи на восстановление цепочки по логам.
- **DFIR:** расследование компрометации Linux-хоста.
- **SOC:** детект по auth/web-логам.
- **Threat Hunting:** поиск аномалий и корреляция.
- **Судебная экспертиза:** доказательство входов и действий.
