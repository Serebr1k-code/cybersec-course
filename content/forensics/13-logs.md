---
id: forensics-logs
title: "Анализ логов и поиск аномалий"
category: forensics
parent: forensics-win-logs
difficulty: medium
order: 1
tags: [logs, grep, jq, web-logs, auth, anomaly]
prerequisites: [forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "SOC / SIEM"
  - "Incident Response"
estimated_minutes: 50
summary: "Приёмы анализа журналов: web-логи, auth, JSON-логи, grep/jq/awk, выявление брутфорса, сканирования и эксфильтрации."
---
Логи — это хроника того, что система и приложения делали. В форензике логи позволяют восстановить действия атакующего (входы, запуск команд, обращения к файлам) и обнаружить аномалии (брутфорс, сканирование, эксфильтрация). Этот урок — про практические приёмы анализа логов: `grep`/`jq`/`awk`, web-логи nginx/apache, `auth.log`, JSON-логи и выявление типовых атак.

## Типы логов и что в них искать

| Лог | Путь (типичный) | Что искать |
|-----|-----------------|-----------|
| `auth.log` / `secure` | `/var/log/` | SSH-брутфорс, sudo, su, новые пользователи |
| `syslog` / `messages` | `/var/log/` | сбои служб, OOM, kernel-события |
| `journald` | бинарный, `journalctl` | всё выше + systemd-юниты |
| nginx `access.log` | `/var/log/nginx/` | сканы, LFI/RCE, webshell-запросы |
| nginx `error.log` | `/var/log/nginx/` | ошибки, попытки эксплуатации |
| Apache `access.log` | `/var/log/apache2/` | то же + `%{User-Agent}` |
| cron | `/var/log/cron`, `syslog` | закрепление через задачи |
| Windows EVTX | `winevt\Logs` | вход, процессы, службы (см. `forensics-evtx-deep`) |

## grep: базовый инструмент

```bash
# неудачные SSH-входы
$ grep 'Failed password' /var/log/auth.log | wc -l
# топ атакующих IP
$ grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head
# успешные входы
$ grep 'Accepted' /var/log/auth.log
# новые пользователи
$ grep -E 'useradd|adduser|new user' /var/log/auth.log
```

Флаги `grep`, полезные для логов: `-c` (счётчик), `-i` (регистр), `-v` (инвертировать), `-E`/`-P` (regex), `-o` (только совпадение), `-A/-B/-C N` (контекст), `-r` (рекурсия), `-a` (бинарный как текст), `--color=always`.

## awk и сортировка: агрегация

```bash
# top-10 URL в nginx access.log (поле 7)
$ awk '{print $7}' access.log | sort | uniq -c | sort -rn | head
# коды ответов
$ awk '{print $9}' access.log | sort | uniq -c | sort -rn
# IP с 404 (сканер каталогов)
$ awk '$9==404 {print $1}' access.log | sort | uniq -c | sort -rn | head
# подсчёт трафика по IP
$ awk '{a[$1]+=$10} END {for(i in a) print a[i], i}' access.log | sort -rn | head
```

`sort -rn` (числовая обратная сортировка) + `uniq -c` — базовый паттерн «частота по значению».

## jq: JSON-логи

Современные приложения и облака пишут JSON. `jq` извлекает поля:

```bash
# CloudTrail: кто что делал
$ jq -r '.Records[] | [.eventTime,.eventName,.userIdentity.arn,.sourceIPAddress] | @tsv' trail.json | head
# только ошибки доступа
$ jq '.Records[] | select(.errorCode!=null)' trail.json | head
# фильтр по времени и событию
$ jq '.Records[] | select(.eventName=="CreateUser")' trail.json
# nginx JSON-лог: топ UA
$ jq -r '.request_uri' access.json.log | sort | uniq -c | sort -rn | head
```

Полезные флаги `jq`: `-r` (raw, без кавычек), `-c` (компактно, одна строка), `-s` (slurp, весь поток как массив), `@tsv`/`@csv` (форматирование), `select()`/`map()`/`group_by()`.

## Обнаружение атак

**Брутфорс SSH:** много `Failed password` с одного IP за короткое время, затем `Accepted password`.

```bash
$ grep 'Failed password' auth.log | awk '{print $(NF-3)}' | sort | uniq -c | awk '$1>20'
$ grep -E 'Failed|Accepted' auth.log | tail -50
```

**Сканирование и эксплуатация веба:** всплеск 404, длинные пути, шаблоны уязвимостей.

```bash
$ grep -iE '\.\./|/etc/passwd|union.*select|<script|/wp-admin|\.git' access.log
$ awk '$9==200 && $7 ~ /\.(php|jsp)$/ {print}' access.log
```

**Webshell:** POST на один файл с постоянным размером ответа 200.

```bash
$ awk '$6=="POST" {print $1,$7,$9,$10}' access.log | sort | uniq -c | sort -rn | head
```

**Эксфильтрация:** аномально большой исходящий трафик или DNS-запросы с длинными поддоменами (см. `forensics-exfil`).

## journald

`journalctl` читает бинарный журнал с мощной фильтрацией:

```bash
$ journalctl -u ssh --since "2024-03-01" --until "2024-03-02"
$ journalctl -p err -b                  # ошибки текущей загрузки
$ journalctl _PID=1234                  # по PID
$ journalctl -o json-pretty | jq 'select(._COMM=="sshd")'
$ journalctl --disk-usage               # размер
$ journalctl -k                         # только ядро
```

## Разобранный пример

Дан `access.log` скомпрометированного nginx.

```bash
# 1. Аномальные коды
$ awk '{print $9}' access.log | sort | uniq -c | sort -rn
  12034 200
   3211 404
     12 500
# 2. Сканер: IP с массой 404
$ awk '$9==404 {print $1}' access.log | sort | uniq -c | sort -rn | head -3
   3201 203.0.113.9
# 3. Что искал
$ grep '203.0.113.9' access.log | grep -oE 'GET [^ ]+' | sort -u | head
GET /.git/config
GET /backup.sql
GET /phpmyadmin/
# 4. RCE-попытки
$ grep -iE 'eval|system|base64|cmd=' access.log | head
203.0.113.9 - - [..] "GET /upload.php?cmd=id HTTP/1.1" 200 33
# 5. Найденный webshell: POST с постоянным размером
$ awk '$6=="POST" && $9==200 {print $1,$7,$10}' access.log | sort | uniq -c | sort -rn | head
```

Итог: IP `203.0.113.9` сканировал каталоги, затем эксплуатировал `upload.php?cmd=` и использовал webshell через POST.

## Частые ошибки

- **Читать логи как текст целиком** — на гигабайтах используйте `grep -c`/`awk`/`zcat`.
- **Ротированные и сжатые логи.** `zcat access.log.*.gz | grep ...`, помните про `logrotate`.
- **Игнорировать часовой пояс и формат времени** — сравнивайте в UTC.
- **Смотреть только access.log** — webshell-артефакты и в `error.log`, и в ФС.
- **Верить, что логов нет** — атакующий мог очистить; ищите пробелы во времени и артефакты `clear`.
- **Забывать про `last`/`lastlog`/`wtmp`** — бинарные логи входов.

## Что дальше / решение

Начните с аномалий (`uniq -c`/`sort -rn`), затем углубитесь в конкретный IP/время (`grep` по контексту). Связка: `forensics-log-analysis` (системные логи Linux глубоко), `forensics-web-forensics` (сервер целиком), `forensics-evtx-deep` (Windows), `forensics-plaso` (супертаймлайн с логами). Конвейер: `wc -l` → `uniq -c` по полям → `grep` по подозрительному → реконструкция сессии.

## Корреляция логов с другими артефактами

Логи редко дают полную картину в одиночку — коррелируйте их с файловой системой и артефактами выполнения. Пример цепочки: `access.log` показал POST на `upload.php` → в ФС появился файл с временем из лога → Sysmon/EVTX зафиксировал создание процесса `php` с сетевым соединением → `last`/`auth.log` показал вход того же IP.

```bash
# совпадение времени: лог vs mtime файла
$ grep 'upload.php' access.log | awk '{print $4}' | tr -d '['
$ stat -c '%y' /var/www/html/upload.php
# корреляция IP из auth.log и access.log
$ comm -12 <(grep 'Failed' auth.log | awk '{print $(NF-3)}' | sort -u) \
           <(awk '{print $1}' access.log | sort -u)
```

Именно корреляция позволяет доказать, что «сканирующий» IP и «залогинившийся» — одно лицо, и связать сетевую активность с файловыми изменениями.

## Автоматизация и правила

Для больших объёмов логов используйте агрегаторы и правила:

```bash
# GoAccess: интерактивная статистика по access.log
$ goaccess access.log --log-format=COMBINED -o report.html
# grep-паттерны известных атак одним файлом
$ grep -iEf patterns.txt access.log
# JSON-логи: сводка по полю через jq + sort
$ jq -r '.client_ip' access.json.log | sort | uniq -c | sort -rn | head
```

В SIEM-подходе правила (Sigma, Elastic) описывают аномалии декларативно; в ручном расследовании их заменяют скрипты `awk`/`jq`/`grep`. Держите набор «сигнатурных» паттернов (webshell-пути, LFI, шаблоны сканеров) под рукой — это ускоряет первичный триаж.

## Временная база и нормализация

Web-серверы по умолчанию пишут локальное время (иногда без TZ в логе), syslog — тоже, `journalctl` хранит UTC. Прежде чем сравнивать с MFT/EVTX (UTC), приведите всё к одной зоне:

```bash
$ journalctl -o short-iso-precise --utc -u nginx | head
$ TZ=UTC date -d "$(grep ... access.log | ...)" +%s
```

Без нормализации вы рискуете перепутать порядок «эксплуатация → загрузка webshell → закрепление».

## Квиз

```quiz
- question: "Какой инструмент лучше всего подходит для разбора JSON-логов?"
  options:
    - "`grep`"
    - "`jq`"
    - "`awk`"
    - "`strings`"
  answer: 1
- question: "Что означает всплеск кодов 404 от одного IP?"
  options:
    - "Обычный пользователь"
    - "Вероятно, сканер/фаззер перебирает пути"
    - "Атака через SQLi"
    - "Сбой DNS"
  answer: 1
- question: "Признак успешного брутфорса в auth.log?"
  options:
    - "Много строк 'Failed password' без успехов"
    - "Успешный вход с IP, где ранее было много неудач"
    - "Ровно один 'Accepted publickey'"
    - "Пустой лог"
  answer: 1
- question: "Как посмотреть логи за последний час в systemd?"
  options:
    - "`cat /var/log/syslog`"
    - '`journalctl --since "1 hour ago"`'
    - "`tail -f messages`"
    - "`dmesg`"
  answer: 1
- question: "Почему важно нормализовать таймзону при построении таймлайна?"
  options:
    - "Чтобы уменьшить размер логов"
    - "Чтобы события из разных источников корректно упорядочились во времени"
    - "Чтобы включить шифрование"
    - "Это не нужно"
  answer: 1
```

## Где пригодится

- **CTF:** задачи «дан access.log — найди атаку/флаг».
- **SOC / SIEM:** первые шаги триажа алерта, проверка гипотез.
- **Incident Response:** восстановление хронологии и scope компромисса.
- **Threat Hunting:** поиск аномалий по логам до срабатывания сигнатуры.
