---
id: forensics-linux-artifacts
title: "Артефакты Linux: история, cron, bash-логи"
category: forensics
parent: forensics-win-misc
difficulty: hard
order: 3
tags: [linux, artifacts, bash-history, cron, persistence, dfir]
prerequisites: [forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ серверов"
estimated_minutes: 45
summary: "Ключевые артефакты Linux: история shell, журналы, cron/systemd, авторизация, аудит и следы персистентности."
---

## Что оставляет атакующий на Linux

Linux-серверы компрометируются через веб-RCE, SSH-брутфорс, уязвимости сервисов. После получения доступа атакующий выполняет команды, закрепляется, двигается латерально. Артефакты разбросаны по файловой системе: история shell, cron, systemd, логи, файлы в `/tmp`, изменения в `/etc`, persistence-механизмы.

## История shell

```bash
# bash
cat ~/.bash_history
# zsh
cat ~/.zsh_history
# все пользователи
find /home -name "*history" -exec ls -la {} \;
# история root
cat /root/.bash_history
```

Тонкости:

- **HISTFILE=/dev/null** — атакующий отключает историю.
- **`set +o history`** — временно.
- **История пишется при выходе** — если сессия оборвана, последние команды могут отсутствовать.
- **`HISTTIMEFORMAT`** — timestamps, если включено.
- **Файлы могут быть удалены** — восстановимы из `~/.bash_history` inode/снапшота.

Другие истории: `~/.python_history`, `~/.mysql_history`, `~/.psql_history`, `~/.lesshst`, `~/.viminfo`, `~/.nano_history`.

## Cron и планировщики

Persistence через cron — классика:

```bash
# Системные cron
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/
# Пользовательские
crontab -l -u <user>
ls -la /var/spool/cron/crontabs/
# Логи cron
grep CRON /var/log/syslog
```

Ищите: команды с `curl`/`wget`, реверс-шеллы, обращения к `/tmp`, base64, незнакомые скрипты.

## Systemd и таймеры

```bash
# Юниты
ls -la /etc/systemd/system/ /lib/systemd/system/
systemctl list-units --type=service --state=running
systemctl list-timers --all
# Пользовательские юниты
ls -la ~/.config/systemd/user/
# Недавно изменённые
find /etc/systemd -mtime -7
```

Атакующие создают `.service`/`.timer` с `ExecStart=` на свой payload.

## Авторизация и вход

```bash
# Debian/Ubuntu
cat /var/log/auth.log
# RHEL/CentOS
cat /var/log/secure
# Успешные/неудачные входы
grep -E "Accepted|Failed|Invalid" /var/log/auth.log
# Последние входы
last -a | head
lastb | head        # неудачные
# Текущие сессии
who
w
```

Ищите: входы с необычных IP, во внеурочное время, от новых пользователей, `sudo`-команды.

## Персистентность: где искать

- **~/.ssh/authorized_keys** — добавленные ключи.
- **/etc/passwd, /etc/shadow** — новые пользователи, UID 0.
- **/etc/sudoers, /etc/sudoers.d/** — новые правила.
- **~/.bashrc, ~/.profile** — автозапуск.
- **/etc/rc.local, /etc/init.d/** — старый автозапуск.
- **LD_PRELOAD, /etc/ld.so.preload** — перехват библиотек.
- **PAM-модули** (`/lib/security/`) — бэкдоры.
- **SSH-конфиг** (`/etc/ssh/sshd_config`) — изменения.
- **Setuid-бинарники** (`find / -perm -4000`).

```bash
# Новые пользователи
awk -F: '$3==0 {print}' /etc/passwd
# Изменённые конфиги
find /etc -mtime -7 -type f
# SUID
find / -perm -4000 -type f 2>/dev/null
```

## Журналы systemd (journald)

```bash
journalctl -u sshd --since "2024-01-01" --until "2024-01-02"
journalctl -p err -b
journalctl --list-boots
# Поиск подозрительного
journalctl | grep -iE 'curl|wget|nc |/tmp/'
```

Journald хранит бинарные журналы (`/var/log/journal/`), их можно экспортировать (`journalctl -o json`).

## Практический пример: разбор сервера

1. **История** всех пользователей → команды атакующего.
2. **Cron/systemd** → persistence.
3. **auth.log** → вход и sudo.
4. **authorized_keys** → новые ключи.
5. **/tmp, /dev/shm** → dropped файлы.
6. **SUID/new users** → эскалация.
7. **Таймлайн** по mtime.

## Инструменты и команды

```bash
# Утилиты
last, lastb, who, w
journalctl
# Инструменты DFIR: UAC (Unix-like Artifacts Collector)
./uac -p full -o /evidence
# chkrootkit/rkhunter для rootkit
chkrootkit
rkhunter --check
```

## auditd: системный аудит

**auditd** — подсистема аудита ядра Linux. Правила (`/etc/audit/rules.d/`) определяют, какие системные вызовы логировать (execve, открытие файлов, изменение прав). Логи — `/var/log/audit/audit.log`.

```bash
# Аудит запуска процессов
ausearch -m EXECVE -ts recent
# Аудит доступа к файлу
ausearch -f /etc/shadow
# Отчёты
aureport --auth
aureport --executable
# Живые правила
auditctl -l
```

Ключевое: auditd пишет **даже при отключённой shell-истории** — если атакующий запускал команды, `EXECVE`-записи их содержат.

## Инструменты DFIR: UAC

**UAC (Unix-like Artifacts Collector)** — bash-скрипт, собирающий десятки артефактов с Linux/Unix: истории, cron, systemd, логи, сеть, пользователей, persistence.

```bash
./uac -p full -o /evidence/out      # полный сбор
./uac -p ir_triage -o /evidence/ir  # triage
```

Аналоги: **Linux Explorer** (Velociraptor), **dfir_ntfs**, ручной сбор.

## Сетевые и процессные артефакты

- **`/proc/<pid>/`** — живые процессы, cmdline, окружение, открытые файлы (может не быть в образе).
- **`/var/log/syslog`**, **`kern.log`** — системные события.
- **`netstat`/`ss`** — соединения (для живого анализа).
- **`/etc/hosts`** — может быть изменён (редирект).
- **`/etc/resolv.conf`** — DNS.
- **iptables/nftables** — правила (persistence/redirect).
- **`~/.ssh/known_hosts`** — куда подключались.

## Пакетные менеджеры и установка ПО

```bash
# История установок (apt)
grep -E "install|remove" /var/log/dpkg.log
zcat /var/log/apt/history.log.*.gz | grep -i install
# yum/dnf
grep -i install /var/log/dnf.log /var/log/yum.log
# Изменённые файлы пакетов (Debian)
debsums -c 2>/dev/null
```

Атакующие устанавливают инструменты (`nmap`, `netcat`, компиляторы) — это видно в логах. Отсутствие `nmap` в списке, но его бинарник на диске — подозрительно.

## Инструменты и команды

```bash
# UAC (Unix-like Artifacts Collector)
./uac -p full -o /evidence/out
# Сбор вручную
cat /var/log/auth.log; journalctl -u sshd
last -a; lastb | head; who; w
find / -perm -4000 -type f 2>/dev/null      # SUID
find /etc -mtime -7 -type f                 # изменённые конфиги
ls -la /tmp /dev/shm /var/tmp               # dropped файлы
cat ~/.bash_history ~/.zsh_history
crontab -l; ls /etc/cron.*; systemctl list-timers
cat ~/.ssh/authorized_keys
# chkrootkit/rkhunter
chkrootkit; rkhunter --check --sk
```

## Скрытые файлы и обфускация

- **Файлы с ведущей точкой** (`.hidden`).
- **Имена с пробелами/юникодом** (`..`, `\u200b`).
- **Файлы в `/dev/shm`, `/run`, `/tmp`** — в памяти, не на диске.
- **Удалённые, но открытые файлы** (`lsof +L1`).
- **Процессы с обфусцированным cmdline** (`/proc/<pid>/cmdline`).
- **Изменённые бинарники** (`debsums`, сравнение с пакетом).

```bash
ls -la /tmp /dev/shm /var/tmp /run
lsof +L1 2>/dev/null | head          # deleted-but-open
cat /proc/*/cmdline | tr '\0' ' '
debsums -c 2>/dev/null               # изменённые файлы пакетов
```

## Логи: сопоставление источников

| Лог | Содержимое |
|---|---|
| `/var/log/auth.log` | аутентификация, sudo |
| `/var/log/syslog` | системные события |
| `/var/log/kern.log` | ядро |
| `/var/log/dpkg.log` | установка пакетов |
| `journalctl` | всё (systemd) |
| `/var/log/nginx/access.log` | веб-доступ |
| `/var/log/mysql/` | СУБД |

Коррелируйте: вход в `auth.log` → команды в `bash_history` → сеть в `syslog`/journald → веб-запросы в nginx. Единый таймлайн даёт полную картину.

## Итог

Форензика Linux — это комбинация shell-историй, cron/systemd, логов и проверки persistence. Начинайте с историй (команды атакующего), затем persistence (cron/systemd/authorized_keys), затем логи входа и dropped-файлы. Не забывайте про `/tmp`, `/dev/shm`, SUID и новые пользователи. `UAC` автоматизирует сбор; `auditd` даёт системный уровень.

## Частые ошибки

- **Только `.bash_history`.** Есть zsh, python, mysql истории.
- **Игнорировать systemd-таймеры.** Не только cron.
- **Смотреть один лог.** auth.log + syslog + journald.
- **Забыть `/tmp`, `/dev/shm`.** Там payload'ы.
- **Не проверить authorized_keys.**
- **Не искать SUID/new users.**

## Как не застрять

- **Истории shell** — команды атакующего.
- **Cron + systemd** — persistence.
- **auth.log/journald** — вход.
- **authorized_keys/sudoers/passwd** — закрепление.
- **/tmp, /dev/shm** — dropped файлы.
- **Соберите таймлайн.**

## Квиз

```quiz
- question: "Где хранится история команд bash?"
  options:
    - "~/.bash_history"
    - "/var/log/auth.log"
    - "/etc/passwd"
    - "/proc"
  answer: 0
- question: "Как найти новых UID-0 пользователей?"
  options:
    - "awk -F: '$3==0' /etc/passwd"
    - "last"
    - "journalctl"
    - "crontab -l"
  answer: 0
- question: "Какой файл содержит добавленные SSH-ключи?"
  options:
    - "/etc/shadow"
    - "~/.ssh/authorized_keys"
    - "/etc/crontab"
    - "/var/log/syslog"
  answer: 1
- question: "Где логи входов в Debian/Ubuntu?"
  options:
    - "/var/log/auth.log"
    - "/etc/passwd"
    - "~/.bashrc"
    - "/tmp"
  answer: 0
- question: "Какой механизм persistence НЕ типичен для Linux?"
  options:
    - "cron"
    - "systemd timer"
    - "authorized_keys"
    - "реестр Windows"
  answer: 3
```

## Где пригодится

- **CTF Forensics** — задачи с образами Linux.
- **DFIR** — расследование компрометации серверов.
- **Анализ серверов** — аудит и hunting.
- **SOC** — детекты на persistence.
- **Пентест** — понимание следов.
