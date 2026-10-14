---
id: forensics-web-forensics
title: "Веб-форензика: артефакты сервера и приложения"
category: forensics
parent: forensics-logs
difficulty: medium
order: 2
tags: [web, nginx, apache, php, webshell, access-log, server-forensics]
prerequisites: [forensics-logs]
useful_for:
  - "CTF Forensics категория"
  - "Incident Response (веб-компрометация)"
  - "Анализ веб-серверов"
estimated_minutes: 40
summary: "Анализ скомпрометированного веб-сервера: логи nginx/apache, webshells, артефакты PHP/Python/Node, базы, cron и восстановление цепочки атаки."
lab:
  kind: shell
  title: "Практика: разбор журнала веб-атаки"
  toolset: [core]
  workdir: /home/student/task
  files: [task.md, notes.txt, access.log]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Начни с поиска инструмента: `grep -i sqlmap access.log`."
    - "Посмотри, какие запросы слал этот IP."
    - "Ищи строку с внешним Referer — там спрятан флаг."
    - "Запиши флаг: `grep evil.example access.log > found.txt` (в строке есть флаг)."

---

## Вопрос, с которого всё начинается

Сайт `example.com` (nginx + PHP) «взломали»: на страницах появился посторонний код.
Нужно восстановить: как проникли, что загрузили, как закрепились и что украли. У нас
есть логи веб-сервера и доступ к файлам.

Компрометация веб-сервера — один из самых частых инцидентов. В этом уроке мы соберём
цепочку атаки по шагам, от сканирования до выполнения команд.

## Наш пример: аномальный IP

Смотрим `access.log` — журнал каждого запроса:

```bash
$ awk '$9==404{print $1}' access.log | sort | uniq -c | sort -rn | head -1
   8421 203.0.113.9
```

`awk '$9==404{print $1}'` оставляет только IP тех, кто получил код 404 (страница не
найдена), `sort | uniq -c` считает частоту. Один IP дал 8421 «не найдено» — это **сканер**,
перебирающий пути.

## Шаг 1: что искал сканер

```bash
$ grep '203.0.113.9' access.log | grep -oE 'GET [^ ]+' | sort -u | tail
GET /uploads/shell.php
GET /backup.sql
GET /.git/config
```

Сканер ищет утечки и уже существующие шеллы. Дальше — эксплуатация.

## Шаг 2: загрузка webshell

```bash
$ grep '203.0.113.9' access.log | grep -i 'POST'
203.0.113.9 - - [..] "POST /upload.php HTTP/1.1" 200 45
```

POST на `upload.php` с кодом 200 — файл успешно загружен. **Webshell** — это вредоносный
скрипт на сервере, через который выполняют команды.

## Шаг 3: находим файл шелла

```bash
$ find /var/www -name 'shell.php' -ls
-rw-r--r-- 1 www-data www-data 1240 Mar  1 12:01 /var/www/uploads/shell.php
$ grep -lE 'eval|system' /var/www/uploads/shell.php
/var/www/uploads/shell.php
```

`find -ls` показывает недавно созданный файл, `grep` подтверждает опасные функции
(`eval`, `system` — выполнение кода). Время создания (`Mar 1 12:01`) совпадает с POST в
логе — привязка доказана.

## Шаг 4: выполнение команд

```bash
$ grep 'uploads/shell.php' access.log | head
203.0.113.9 - - [..] "GET /uploads/shell.php?c=id HTTP/1.1" 200 33
```

Обращения к шеллу с параметром `c=id` — злоумышленник выполняет команды. Цепочка
замкнулась: сканер → загрузка через `upload.php` → выполнение через `shell.php`.

## Шаг 5: закрепление

Проверяем типичные механизмы персистентности:

```bash
$ grep -rn 'auto_prepend_file' /var/www /etc/php 2>/dev/null
$ ls -la /etc/cron.d/ /var/spool/cron/crontabs/ 2>/dev/null
$ find /var/www -name '*.php' -newermt '2024-03-01' -ls
```

`.user.ini` с директивой `auto_prepend_file` заставляет PHP выполнять чужой код при
каждом запросе — закрепление без явного файла-шелла. Cron и systemd-таймеры — другой
частый способ.

## Шаг 6: базы и конфиги

```bash
$ grep -iE 'union|select.*into outfile|load_file' /var/log/mysql/*.log | head
$ cat /var/www/html/wp-config.php | grep -iE 'DB_|SECRET'
```

SQL-инъекции видны в логах запросов, `INTO OUTFILE` — в ошибках. Конфиги (`wp-config.php`,
`.env`) содержат креды БД, которые атакующий мог прочитать или изменить.

## Шаг 7: общий конвейер

```bash
# топ URI
$ awk '{print $7}' access.log | sort | uniq -c | sort -rn | head
# всплеск ошибок
$ awk '$9==500 {print $7}' access.log | sort | uniq -c | sort -rn | head
# большие ответы (возможная выгрузка данных)
$ awk '$10>1000000 {print}' access.log | head
```

Сопоставляя время в логах с временем изменения файлов (`stat`), вы привязываете запрос к
конкретному созданному файлу — это и есть доказательство.

## Артефакты интерпретаторов и баз

- **PHP**: `error_log`, файлы сессий (`/var/lib/php/sessions`), `.user.ini`, OPcache.
- **Python/Node**: логи приложений, `__pycache__`, переменные окружения.
- **Базы**: `general_log` MySQL/PostgreSQL, ошибки запросов.
- **Cron/systemd**: задачи и таймеры (закрепление).

```bash
$ ls -la /var/lib/php/sessions/
$ grep -i 'select\|outfile' /var/log/mysql/error.log | head
$ crontab -l; systemctl list-timers
```

## Инструменты

| Задача | Инструмент |
|--------|-----------|
| Анализ access.log | `awk`, `grep`, `goaccess` |
| Поиск webshell | `grep`, `YARA`, `php-malware-finder` |
| Сканирование webroot | `find`, `clamav` |
| Анализ обфускации | `de4php` |
| Анализ БД-логов | `pt-query-digest`, grep |

```bash
$ php-malware-finder /var/www
$ yara -r webshell_rules.yar /var/www
```

## Отчёт и рекомендации

В отчёте фиксируйте: точку входа (уязвимость), время эксплуатации, загруженные файлы с
хешами, выполненные команды, закрепление, эксфильтрацию и IOC. Рекомендации: обновить
уязвимое ПО, удалить шеллы, сменить креды, включить WAF и аудит целостности файлов
(AIDE/OSSEC), проверить cron и systemd. Хороший отчёт позволяет коллеге повторить
каждый шаг и прийти к тому же выводу.

## Восстановление цепочки атаки

Типовая последовательность и как её увидеть:

```bash
# 1. Сканирование: IP с массой 404
$ awk '$9==404{print $1}' access.log | sort | uniq -c | sort -rn | head -3
# 2. Эксплуатация: запросы с payload
$ grep -iE 'union.*select|\.\./|cmd=|eval' access.log | head
# 3. Загрузка: POST multipart на upload-скрипты
$ grep 'POST' access.log | grep -iE 'upload|file' | head
# 4. Выполнение: обращения к созданному файлу
$ grep -iE 'shell|cmd|backdoor' access.log | head
# 5. Эксфильтрация: крупные ответы
$ awk '$10>1000000 {print}' access.log | head
```

## Что искать в error.log

`error.log` дополняет картину: ошибки PHP содержат пути к скриптам, ошибки nginx —
попытки обхода. Иногда сам код шелла выводит ошибки с путём к себе:

```bash
$ grep -iE 'PHP (Warning|Fatal)|eval|system' error.log | head
```

Сопоставив запись в error.log по времени с файлом в webroot, вы подтверждаете, что
именно этот файл выполнялся.

## Проверка целостности и бэкапы

Чтобы найти изменённые файлы, сверяйте их с эталоном. Если есть резервная копия или
пакет из репозитория, `diff` и хеши сразу покажут модификации:

```bash
$ sha256sum /var/www/html/index.php
$ diff -r /var/www/html /backup/html | head
$ find /var/www -name '*.zip' -o -name '*.bak' -ls
```

Модифицированный легитимный файл (`index.php` с бэкдором внутри) опаснее отдельного
шелла: его труднее заметить. А `backup.zip` в webroot часто утекает вместе с кредами.

## Инструмент: sqlmap — автоматизация SQL-инъекций

`sqlmap` находит и эксплуатирует SQL-инъекции: определяет СУБД, извлекает данные, при удаче — выполняет команды. В лаборатории он разбирает сохранённый HTTP-запрос.

Ключи, которые пригодятся:
* `sqlmap -r req.txt -p id` — тестировать параметр `id` из сохранённого запроса;
* `sqlmap -u '<url>' --batch` — без интерактива;
* `sqlmap -r req.txt --dbs` — перечислить базы; `--tables -D <db>` — таблицы;
* `--dump` — выгрузить данные таблицы.

## Что мы теперь знаем

- `access.log` даёт IP, время, URI, код и размер каждого запроса.
- Сканер выдаёт всплеск 404 с одного IP.
- POST на upload-скрипт с кодом 200 — вероятная загрузка шелла.
- Webshell ищут по времени создания и опасным функциям (`eval`, `system`).
- Закрепление живёт в `.user.ini`, cron, systemd; следы SQLi — в логах БД.

## На что смотреть дальше

- **Смотреть не только `access.log`** — код шелла и артефакты в файловой системе и `error.log`.
- **Сверять время** логов и mtime файлов — без этого нет привязки.
- **Проверять `.user.ini`/`.htaccess`** — закрепление без явного файла.
- **Не анализировать живую систему без снятия образа** — улики изменятся.
- **Сверять хеши** файлов с эталонными — так находят скрытые модификации.

## Квиз

Проверь себя.

```quiz
- question: "Как найти webshell по содержимому?"
  options:
    - "`grep -rlniE 'eval\\(|system\\(' /var/www/`"
    - "`nmap /var/www/`"
    - "`exiftool`"
    - "`file`"
  answer: 0
- question: "Что в access.log указывает на успешную атаку?"
  options:
    - "404 на /admin"
    - "200 на подозрительном пути (shell.php, cmd=)"
    - "301"
    - "500"
  answer: 1
- question: "Где чаще всего прячется webshell?"
  options:
    - "в /etc/passwd"
    - "в webroot, недавно созданный файл"
    - "в ядре"
    - "в DNS"
  answer: 1
- question: "Что проверить для персистентности на веб-сервере?"
  options:
    - "только лог"
    - "cron, systemd, `.user.ini`/`.htaccess`"
    - "EXIF"
    - "Prefetch"
  answer: 1
- question: "Как найти exploited-параметр?"
  options:
    - "по размеру лога"
    - "grep по паттернам атак и кодам 200"
    - "по User-Agent браузера"
    - "по IP"
  answer: 1
```

## Куда дальше

Веб-сервер мог быть не отдельной машиной, а контейнером или облачным инстансом. В
следующем уроке мы разберём облачную форензику: как восстановить действия атакующего по
CloudTrail и снапшотам. А пока запомни: **время в логе плюс mtime файла — это
доказательство**.

## Где пригодится

- **CTF:** задачи с логами/дампом веб-сервера.
- **Incident Response:** разбор взлома сайта.
- **SOC:** обнаружение веб-атак.
- **Пентест:** пост-эксплуатационный анализ.
- **Хостинг-безопасность:** поиск webshell у клиентов.
