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
---
Компрометация веб-сервера — один из самых частых инцидентов. Форензика веба отвечает на вопросы: как проникли, что загрузили, как закрепились и что украли. Источники — логи nginx/apache, файлы веб-приложения, базы, cron и артефакты интерпретаторов. Этот урок — про восстановление цепочки атаки на сервере.

## Логи веб-сервера

**Access log** фиксирует каждый запрос: IP, время, метод, URI, код, размер, User-Agent, Referer. **Error log** — ошибки PHP/Python/nginx, часто содержит пути к шеллам.

```bash
$ tail -20 /var/log/nginx/access.log
203.0.113.9 - - [01/Mar/2024:12:00:01 +0000] "GET /upload.php?cmd=id HTTP/1.1" 200 33 "-" "curl/7.68"
# топ URI
$ awk '{print $7}' access.log | sort | uniq -c | sort -rn | head
# топ IP
$ awk '{print $1}' access.log | sort | uniq -c | sort -rn | head
# всплеск 404 (сканер)
$ awk '$9==404 {print $1}' access.log | sort | uniq -c | sort -rn | head
# POST-запросы с кодом 200 (вероятный webshell)
$ awk '$6=="POST" && $9==200 {print $1,$7,$10}' access.log | sort | uniq -c | sort -rn | head
```

Для Apache формат другой (`%h %l %u %t \"%r\" %>s %b`), но принцип тот же. Разбор формата — `%{User-Agent}i`, `%{Referer}i`.

## Поиск webshell

Webshell — вредоносный скрипт на сервере. Признаки: недавно созданные/изменённые файлы в webroot, обфусцированный код, вызовы системных функций, POST с постоянным размером ответа.

```bash
# файлы, изменённые за последние дни
$ find /var/www -type f -mtime -7 -ls
# поиск опасных функций в PHP
$ grep -rlE 'eval\(|system\(|passthru\(|shell_exec\(|base64_decode\(|assert\(|preg_replace.*/e' /var/www
# файлы с необычными правами
$ find /var/www -type f -perm -o+w -ls
# файлы, скрытые по имени
$ find /var/www -name '.*.php' -o -name '*.phtml' -o -name '*.php5'
```

```bash
# обфускация: длинные строки, eval, base64
$ grep -rlP '\$[a-zA-Z_]+\s*\(\s*\$_(GET|POST|REQUEST)' /var/www
# индекс подозрительных по времени
$ find /var/www -type f -newermt '2024-03-01' ! -newermt '2024-03-02' -ls
```

## Артефакты интерпретаторов

- **PHP**: `error_log`, `session`-файлы (`/var/lib/php/sessions`), `.user.ini`, OPcache.
- **Python/Node**: логи приложений, `__pycache__`, окружение.
- **Базы**: логи запросов MySQL/PostgreSQL, `general_log`.
- **Cron/systemd**: закрепление через задачи.

```bash
$ ls -la /var/lib/php/sessions/
$ cat /var/log/mysql/error.log | grep -i 'select\|outfile'
$ crontab -l; ls /etc/cron.*; systemctl list-timers
$ grep -r 'wget\|curl' /etc/cron* /var/spool/cron 2>/dev/null
```

## Восстановление цепочки атаки

Типовая цепочка: сканирование → эксплуатация уязвимости → загрузка webshell → выполнение команд → закрепление → эксфильтрация.

```bash
# 1. Сканирование: IP с массой 404/разных URI
$ awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -3
# 2. Эксплуатация: запросы с payload
$ grep -iE 'union.*select|\.\./|/etc/passwd|cmd=|eval' access.log | head
# 3. Загрузка: POST multipart на upload-скрипты
$ grep 'POST' access.log | grep -iE 'upload|file' | head
# 4. Выполнение: обращение к созданному файлу
$ grep -iE 'shell|cmd|backdoor' access.log | head
# 5. Эксфильтрация: крупные ответы или обращения к БД
$ awk '$10>1000000 {print}' access.log | head
```

Сопоставляя время в логах с mtime файлов (`stat`), вы привязываете запрос к конкретному созданному файлу.

## Инструменты

| Задача | Инструмент |
|--------|-----------|
| Анализ access.log | `awk`, `grep`, `goaccess` |
| Поиск webshell | `grep`, `YARA`, `NeoPI`, `php-malware-finder` |
| Сканирование webroot | `find`, `clamav` |
| Анализ JS/PHP обфускации | `de4php`, `phpjiami-decoder` |
| YARA по webroot | `yara -r rules/ /var/www` |
| Анализ БД-логов | `pt-query-digest`, grep |

```bash
$ php-malware-finder /var/www
$ yara -r webshell_rules.yar /var/www
```

## Разобранный пример

Скомпрометирован `example.com` (nginx + PHP).

```bash
# 1. Аномальный IP
$ awk '$9==404{print $1}' access.log | sort | uniq -c | sort -rn | head -1
   8421 203.0.113.9
# 2. Что искал
$ grep '203.0.113.9' access.log | grep -oE 'GET [^ ]+' | sort -u | tail
GET /uploads/shell.php
# 3. Загрузка
$ grep '203.0.113.9' access.log | grep -i 'POST'
203.0.113.9 - - [..] "POST /upload.php HTTP/1.1" 200 45
# 4. Файл шелла
$ find /var/www -name 'shell.php' -ls
-rw-r--r-- 1 www-data www-data 1240 Mar  1 12:01 /var/www/uploads/shell.php
$ grep -lE 'eval|system' /var/www/uploads/shell.php
# 5. Дальнейшие команды
$ grep 'uploads/shell.php' access.log | head
"...GET /uploads/shell.php?c=id HTTP/1.1" 200 33
```

Итог: IP `203.0.113.9` сканировал, загрузил `shell.php` через `upload.php`, затем выполнял команды — полная цепочка восстановлена.

## Частые ошибки

- **Смотреть только access.log** — webshell-код и артефакты в ФС и error.log.
- **Не сверять время** логов и mtime файлов — без этого нет привязки.
- **Игнорировать cron/systemd** — там часто закрепление.
- **Не проверять БД-логи** — SQLi/`INTO OUTFILE` видны там.
- **Верить, что «файл выглядит нормально»** — обфускация может быть в одну строку.
- **Анализировать живую систему без снятия образа** — улики изменятся.

## Что дальше / решение

Конвейер: `awk`/`grep` по access.log → поиск webshell (`find`/`grep`/YARA) → сверка времени → анализ БД/cron → реконструкция цепочки. Связка: `forensics-logs` (общие приёмы), `forensics-log-analysis` (системные логи), `forensics-sqlite`/`forensics-database` (базы), `forensics-malware-yara` (сигнатуры).

## Анализ баз данных и артефактов приложений

Скомпрометированное веб-приложение оставляет следы в БД и конфигах. SQL-инъекции видны в логах запросов, `INTO OUTFILE` — в ошибках; веб-приложения хранят сессии и данные в SQLite/MySQL/PostgreSQL.

```bash
# MySQL: включить/посмотреть general log (если сохранился)
$ grep -iE 'union|select.*into outfile|load_file' /var/log/mysql/*.log | head
# сессии PHP
$ ls /var/lib/php/sessions/ && grep -rl 'admin' /var/lib/php/sessions/ | head
# SQLite приложения (Laravel/WordPress)
$ sqlite3 app.db "SELECT name FROM sqlite_master WHERE type='table';"
# WordPress: пользователи и опции
$ mysql -e "SELECT user_login,user_pass FROM wp_users;" appdb
# логи веб-приложения (фреймворк)
$ tail -50 storage/logs/laravel.log
```

Проверяйте конфиги (`wp-config.php`, `.env`) — там креды БД и секретные ключи, которые атакующий мог прочитать или изменить.

## Закрепление на веб-сервере

Типовые механизмы персистентности:

- **Cron**: `/etc/cron.d/`, `crontab -l`, `/var/spool/cron/crontabs/`.
- **Systemd**: юниты/таймеры в `/etc/systemd/system/`.
- **.htaccess** с `AddType`/`auto_prepend_file` — выполнение произвольного PHP.
- **`.user.ini`** (`auto_prepend_file`) — PHP-закрепление без .htaccess.
- **Модификация легитимных файлов** — бэкдор внутри `index.php`.
- **Web shell в upload-каталоге** — самый частый.

```bash
$ grep -rn 'auto_prepend_file' /var/www /etc/php 2>/dev/null
$ ls -la /etc/cron.d/ /var/spool/cron/crontabs/ 2>/dev/null
$ find /var/www -name '*.php' -newermt '2024-03-01' -ls
$ grep -rlP 'eval\s*\(\s*(base64_decode|gzinflate|str_rot13)' /var/www
```

## Отчёт и рекомендации

В отчёте по вебу фиксируйте: точку входа (уязвимость), время эксплуатации, загруженные файлы с хешами, команды, закрепление, эксфильтрацию и IOC. Рекомендации: обновить уязвимое ПО, удалить шеллы, сменить креды, включить WAF и аудит, проверить cron/systemd и целостность файлов (AIDE/OSSEC). Для детекта — правила на POST в upload-каталоги, обращения к webshell-именам, аномальные `auto_prepend_file`.

## Частые ошибки (дополнительно)

- **Не проверять `.user.ini`/`.htaccess`** — закрепление без явного файла-шелла.
- **Игнорировать логи приложения** (Laravel/WordPress) — там полный контекст.
- **Не сверять хеши** файлов с эталонными — так находят модификации.
- **Забывать про резервные копии** — `backup.zip` в webroot часто утекает.

## Квиз

```quiz
- question: "Как найти webshell по содержимому?"
  options:
    - "`grep -rlniE 'eval\(|system\(' /var/www/`"
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
    - "cron, systemd, authorized_keys, ld.so.preload"
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

## Где пригодится

- **CTF:** задачи с логами/дампом веб-сервера.
- **Incident Response:** разбор взлома сайта.
- **SOC:** обнаружение веб-атак.
- **Пентест:** пост-эксплуатационный анализ.
- **Хостинг-безопасность:** поиск webshell у клиентов.
