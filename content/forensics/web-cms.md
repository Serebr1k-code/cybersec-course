---
id: web-cms
title: 'CMS-форензика: WordPress, Joomla и следы компромисса'
category: forensics
parent: forensics-web-apps
difficulty: medium
order: 1
tags: [forensics, web, cms, wordpress, joomla]
prerequisites: [forensics-web-forensics]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как расследовать компромисс CMS: логи доступа, изменённые файлы, веб-шеллы, плагины и пользователи.'
lab:
  kind: shell
  title: 'Практика: CMS-форензика'
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

Сайт на WordPress «сломался» или рассылает спам. Скорее всего, загружен шелл или
изменён плагин. Разберём, где искать следы.

## Наш пример: WordPress

## Шаг 1: версия и компоненты

Уязвимости ищут по версиям ядра и плагинов:

```
$ curl -s http://target/wp-includes/version.php | grep wp_version
$ ls /var/www/html/wp-content/plugins/
```

Устаревший плагин — частый вход.

## Шаг 2: изменённые файлы

Злоумышленник меняет файлы. Сравни с эталоном:

```
$ diff -rq /var/www/html /opt/wordpress-clean/ | grep differ
Files /var/www/html/wp-content/themes/x/functions.php differ
```

`functions.php` с лишним кодом — классика.

## Шаг 3: веб-шеллы

Ищем исполняемые файлы в неожиданных местах:

```
$ find /var/www/html -name '*.php' -newermt '2026-01-14 03:00' | head
```

И подозрительный код:

```
$ grep -rE 'eval\(|base64_decode\(|system\(' /var/www/html/wp-content/uploads/
```

## Шаг 4: пользователи и логины

```
$ wp user list --role=administrator
```

Новый админ-аккаунт — признак компромисса. Сопоставь с логом входов:

```
$ grep 'wp-login' /var/log/apache2/access.log | grep POST | tail
```

## Шаг 5: что искать

- изменённые/новые PHP-файлы;
- шелл-паттерны (`eval`, `base64_decode`);
- новые админы;
- подозрительные запросы (POST на `wp-login`, доступ к `uploads/*.php`);
- устаревшие плагины.

## Что мы теперь знаем

- Версии ядра/плагинов — вектор.
- Изменённые файлы ловятся сравнением с эталоном.
- Шеллы ищут по времени и паттернам.
- Новый админ — признак компромисса.
- Логи показывают входы и запросы.

## Если не сработало

- Нет эталона? Скачай чистую версию CMS.
- Шелл обфусцирован? Ищи кодировки и eval.
- Нужен доступ? Проверь cron и wp-config.php.

## Квиз

Проверь себя.

```quiz
- question: Где чаще всего прячут веб-шелл в WordPress?
  options:
    - 'в /etc'
    - 'в uploads или изменённых файлах темы/плагина'
    - 'в /boot'
    - 'в шрифтах'
  answer: 1
  explanation: 'Uploads и файлы тем/плагинов — типичные места шеллов.'
- question: Как найти изменённые файлы?
  options:
    - 'по цвету'
    - 'сравнением с эталонной копией (diff -rq)'
    - 'по размеру'
    - 'никак'
  answer: 1
  explanation: 'Diff с чистой версией показывает отличия.'
- question: Признак компромисса в пользователях?
  options:
    - 'старый админ'
    - 'новый админ-аккаунт'
    - 'много редакторов'
    - 'смена пароля'
  answer: 1
  explanation: 'Неожиданный администратор — признак взлома.'
- question: Что искать в логах?
  options:
    - 'GET на главную'
    - 'POST на wp-login и доступ к uploads/*.php'
    - 'GET на favicon'
    - 'ничего'
  answer: 1
  explanation: 'Брутфорс логина и запуск PHP из uploads — подозрительны.'
```
