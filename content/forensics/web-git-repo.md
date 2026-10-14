---
id: web-git-repo
title: 'Git-репозитории: история, секреты и утечки'
category: forensics
parent: forensics-web-infra
difficulty: medium
order: 3
tags: [forensics, web, git, secrets, repository]
prerequisites: [forensics-web-forensics]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как расследовать git-репозиторий: история коммитов, утёкшие секреты, удалённые ветки и .git на сервере.'
lab:
  kind: shell
  title: 'Практика: Git-репозитории'
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

Из репозитория утекли секреты, или на сервере торчит `.git`. Git хранит **всю**
историю — даже то, что удалили. Разберём.

## Наш пример: репозиторий

## Шаг 1: история

```
$ git log --oneline --all | head
a1b2c3d add deploy key
9f8e7d6 fix
```

`--all` включает все ветки. Удалённые коммиты могут оставаться в reflog.

## Шаг 2: поиск секретов в истории

Секреты могли удалить позже, но они в истории:

```
$ git log -p --all | grep -iE 'AKIA|password|BEGIN.*PRIVATE KEY' | head
```

Или инструментами (`gitleaks`, `trufflehog`).

## Шаг 3: .git на сервере

Если `.git` доступен по HTTP, можно восстановить исходники:

```
$ curl -s http://target/.git/HEAD
ref: refs/heads/main
$ curl -s http://target/.git/config
```

Иногда доступны `objects` — репозиторий целиком.

## Шаг 4: авторство и время

```
$ git log --format='%an %ae %ad %s' | head
Ivan ivan@corp.local Thu Jan 14 03:20:00 2026 +0000 add deploy key
```

Необычный автор/время — зацепка.

## Шаг 5: что искать

- секреты в истории (ключи, пароли, токены);
- коммиты вне обычного графика;
- форс-пуш/переписанную историю (reflog);
- доступный `.git` на продакшене;
- ссылки на внешние репозитории.

## Что мы теперь знаем

- Git хранит всю историю, включая удалённое.
- `git log -p --all` ищет секреты.
- Доступный `.git` = утечка исходников.
- Автор/время коммитов — зацепки.
- Reflog хранит «потерянные» коммиты.

## Если не сработало

- История переписана? Смотри reflog и бэкапы.
- .git недоступен? Ищи зеркала/форки.
- Нужен масштаб? Используй gitleaks/trufflehog.

## Квиз

Проверь себя.

```quiz
- question: Почему git важен для форензики?
  options:
    - 'он красивый'
    - 'хранит всю историю, включая удалённые секреты'
    - 'он быстрый'
    - 'он шифрует'
  answer: 1
  explanation: 'История коммитов сохраняет удалённые позже данные.'
- question: Как искать секреты в истории?
  options:
    - 'git log -p --all | grep'
    - 'ls'
    - 'ping'
    - 'cp'
  answer: 0
  explanation: 'Полный diff истории выявляет ключи/пароли.'
- question: Чем опасен доступный .git на сервере?
  options:
    - 'ничем'
    - 'позволяет восстановить исходный код'
    - 'ускоряет'
    - 'шифрует'
  answer: 1
  explanation: 'Через .git/objects можно выкачать репозиторий.'
- question: Что такое reflog?
  options:
    - 'журнал ссылок, хранящий «потерянные» коммиты'
    - 'обои'
    - 'сеть'
    - 'шелл'
  answer: 0
  explanation: 'Reflog хранит историю перемещений HEAD.'
```
