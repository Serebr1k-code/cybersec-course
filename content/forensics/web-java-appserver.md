---
id: web-java-appserver
title: 'Java-серверы: Tomcat, JBoss и следы эксплуатации'
category: forensics
parent: forensics-web-apps
difficulty: hard
order: 2
tags: [forensics, web, tomcat, jboss, java, logs]
prerequisites: [forensics-web-forensics]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Как расследовать компромисс Java-серверов: логи, деплои WAR, десериализация и веб-шеллы.'
lab:
  kind: shell
  title: 'Практика: Java-серверы'
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

Корпоративное Java-приложение (Tomcat/JBoss) скомпрометировано. Такие серверы известны
уязвимостями (десериализация, менеджер). Где следы? Разберём.

## Наш пример: Tomcat

## Шаг 1: логи

```
$ ls /var/log/tomcat*/
catalina.out  localhost_access_log.2026-01-14.txt
```

`catalina.out` — общий лог, `localhost_access_log` — запросы.

```
$ grep -iE 'exception|deserial' catalina.out | tail
```

Исключения десериализации — признак эксплуатации.

## Шаг 2: менеджер

Tomcat Manager (`/manager/html`) позволяет деплоить WAR:

```
$ grep '/manager/html' localhost_access_log.2026-01-14.txt | tail
203.0.113.5 - - "POST /manager/html/upload HTTP/1.1" 200
```

Загрузка WAR с внешнего IP — почти наверняка атака.

## Шаг 3: деплои

Смотрим, что развёрнуто и когда:

```
$ ls -la /var/lib/tomcat/webapps/
shell.war   (Jan 14 03:30)
```

Новый WAR-файл = внедрённый веб-шелл.

## Шаг 4: десериализация

Уязвимости Java-десериализации (ysoserial) выполняют команды. Признаки:

- большие бинарные тела в логах;
- вызовы `Runtime.exec`;
- аномальные процессы Java (сеть, файлы).

```
$ ps aux | grep java
```

## Шаг 5: что искать

- новые/изменённые WAR/class-файлы;
- обращения к `/manager`, `/jmx-console`, `/wls-wsat`;
- исключения десериализации;
- исходящие соединения от Java.

## Что мы теперь знаем

- Tomcat логи: catalina.out + access-log.
- Manager позволяет деплоить WAR (вектор).
- Новый WAR = шелл.
- Десериализация даёт RCE.
- Ищем аномалии в логах и файлах.

## Если не сработало

- Логи усечены? Смотри access-log по датам.
- WAR зашифрован? Распакуй и смотри class-файлы.
- Нужен процесс? Анализируй память Java.

## Квиз

Проверь себя.

```quiz
- question: Что такое catalina.out?
  options:
    - 'база данных'
    - 'основной лог Tomcat'
    - 'шелл'
    - 'сеть'
  answer: 1
  explanation: 'catalina.out — общий лог контейнера Tomcat.'
- question: Чем опасен Tomcat Manager?
  options:
    - 'ничем'
    - 'позволяет деплоить WAR (RCE)'
    - 'шифрует'
    - 'ускоряет'
  answer: 1
  explanation: 'Через manager можно загрузить вредоносный WAR.'
- question: Признак эксплуатации десериализации?
  options:
    - 'GET на главную'
    - 'исключения десериализации и большие бинарные тела'
    - 'много картинок'
    - 'ничего'
  answer: 1
  explanation: 'Гаджет-цепи оставляют исключения в логах.'
- question: Что искать в webapps?
  options:
    - 'обои'
    - 'новые/изменённые WAR'
    - 'шрифты'
    - 'музыку'
  answer: 1
  explanation: 'Лишний WAR — внедрённое приложение/шелл.'
```
