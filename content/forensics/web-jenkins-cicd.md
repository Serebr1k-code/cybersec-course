---
id: web-jenkins-cicd
title: 'Jenkins и CI-серверы: расследование компромисса'
category: forensics
parent: forensics-web-infra
difficulty: hard
order: 4
tags: [forensics, web, jenkins, cicd, rce]
prerequisites: [forensics-web-forensics]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Как расследовать компромисс Jenkins: скрипт-консоль, креденшелы, джобы и следы выполнения команд.'
lab:
  kind: shell
  title: 'Практика: Jenkins и CI-серверы'
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

Jenkins даёт **RCE по дизайну** (скрипт-консоль, пайплайны). Компромисс CI-сервера
критичен: у него доступ к коду, секретам и продакшену. Разберём.

## Наш пример: Jenkins

## Шаг 1: доступ и логи

```
$ ls /var/log/jenkins/
jenkins.log
$ grep -i 'script\|groovy' jenkins.log | tail
```

Jenkins логирует запуск скриптов и джоб.

## Шаг 2: скрипт-консоль

`/script` позволяет выполнять Groovy на сервере:

```
$ grep 'script' /var/log/jenkins/access_log* | tail
203.0.113.5 - "POST /script HTTP/1.1" 200
```

Внешний доступ к `/script` — почти наверняка RCE.

## Шаг 3: креденшелы

Jenkins хранит секреты. Проверь:

- список credentials (кто добавлял);
- `config.xml` джоб (команды);
- историю изменений джоб.

```
$ ls /var/lib/jenkins/credentials.xml
```

## Шаг 4: джобы

Злоумышленник может создать джобу, выполняющую команды:

```
$ grep -rl 'curl\|bash -i' /var/lib/jenkins/jobs/*/config.xml
```

## Шаг 5: что искать

- обращения к `/script`, `/manage`;
- новые/изменённые джобы;
- утечку креденшелов;
- команды, тянущие внешние скрипты;
- новые пользователи/API-токены.

## Что мы теперь знаем

- Jenkins = RCE по дизайну (Groovy).
- `/script` и `/manage` — опасные эндпоинты.
- Креденшелы хранятся на сервере.
- Джобы содержат команды.
- Ищем скрипты, джобы, токены.

## Если не сработало

- Логи усечены? Смотри audit-плагин.
- Креденшелы зашифрованы? Нужен ключ Jenkins.
- Нужен контекст? Читай историю SCM.

## Квиз

Проверь себя.

```quiz
- question: Почему Jenkins опасен при компромиссе?
  options:
    - 'он медленный'
    - 'даёт RCE через скрипт-консоль и доступ к секретам'
    - 'он красивый'
    - 'он шифрует'
  answer: 1
  explanation: 'Groovy-скрипты выполняются на сервере с его правами.'
- question: Какой эндпоинт даёт RCE?
  options:
    - '/favicon'
    - '/script (Groovy)'
    - '/robots.txt'
    - '/index'
  answer: 1
  explanation: 'Скрипт-консоль выполняет произвольный Groovy.'
- question: Где искать креденшелы Jenkins?
  options:
    - 'в /etc/passwd'
    - 'в credentials.xml'
    - 'в браузере'
    - 'в шрифтах'
  answer: 1
  explanation: 'Jenkins хранит креденшелы в своём каталоге.'
- question: Признак компромисса CI?
  options:
    - 'успешная сборка'
    - 'новые джобы и команды, тянущие внешние скрипты'
    - 'много логов'
    - 'долгая сборка'
  answer: 1
  explanation: 'Внедрённые джобы выполняют код атакующего.'
```
