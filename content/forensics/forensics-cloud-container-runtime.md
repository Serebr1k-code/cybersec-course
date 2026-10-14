---
id: forensics-cloud-container-runtime
title: 'Рантаймы контейнеров: runc, containerd и CVEs побега'
category: forensics
parent: forensics-cloud-compute
difficulty: hard
order: 2
tags: [forensics, cloud, container, runc, containerd, crio]
prerequisites: [forensics-cloud-multi]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Как расследовать компромисс контейнерного рантайма: версии, CVE побега, логи и следы на хосте.'
lab:
  kind: shell
  title: 'Практика: Рантаймы контейнеров'
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

Контейнер скомпрометирован, и есть подозрение на **побег** через уязвимость рантайма
(runc/containerd). Как это проверить и что искать? Разберём.

## Наш пример: узел Kubernetes

## Шаг 1: что такое рантайм

Рантайм запускает контейнеры:

- **runc** — низкоуровневый (создаёт namespaces/cgroups);
- **containerd** — управляет жизненным циклом;
- **CRI-O** — альтернатива для Kubernetes.

## Шаг 2: известные CVE

Исторически громкие:

- **CVE-2019-5736** (runc) — перезапись бинарника runc на хосте;
- **CVE-2022-0492** (cgroups) — побег при определённых правах;
- **CVE-2024-21626** (runc) — утечка файловых дескрипторов.

Проверь **версию** рантайма:

```
$ runc --version
runc version 1.0.0-rc9
```

Старая версия = потенциально уязвима.

## Шаг 3: логи рантайма

```
$ journalctl -u containerd | grep -i 'exec\|start'
```

containerd/runc логируют создание/запуск контейнеров и exec-сессии.

## Шаг 4: следы на хосте

- новые процессы на хосте, запущенные из контейнера;
- смонтированные пути хоста в контейнер;
- изменённый бинарник `runc` (`sha256sum`);
- подозрительные cgroup-манипуляции.

## Шаг 5: что искать

- версии рантайма vs. известные CVE;
- аномальные exec в контейнер;
- доступ к `docker.sock`/`containerd.sock`;
- процессы, «вышедшие» из namespace.

## Что мы теперь знаем

- Рантайм: runc (низкий), containerd/CRI-O (управление).
- Известны CVE побега (2019-5736, 2022-0492, 2024-21626).
- Версия рантайма — ключ к оценке.
- Логи containerd фиксируют запуск/exec.
- Следы — на хосте (процессы, монтирования, изменённый runc).

## Если не сработало

- Версия свежая? Проверь другие векторы (privileged, sock).
- Логи усечены? Смотри audit хоста.
- Нужен дамп? Анализируй память хоста.

## Квиз

Проверь себя.

```quiz
- question: Что такое runc?
  options:
    - 'веб-сервер'
    - 'низкоуровневый рантайм контейнеров'
    - 'база данных'
    - 'браузер'
  answer: 1
  explanation: 'runc создаёт и запускает контейнеры (namespaces/cgroups).'
- question: Чем опасен CVE-2019-5736?
  options:
    - 'ничем'
    - 'перезаписью бинарника runc на хосте (побег)'
    - 'ускоряет'
    - 'шифрует'
  answer: 1
  explanation: 'Уязвимость позволяла заменить runc и выполнить код на хосте.'
- question: Что проверять в первую очередь?
  options:
    - 'цвет'
    - 'версию рантайма'
    - 'обои'
    - 'музыку'
  answer: 1
  explanation: 'Версия показывает, применимы ли известные CVE.'
- question: Где искать следы запуска контейнеров?
  options:
    - 'в /etc/passwd'
    - 'в логах containerd/docker'
    - 'в браузере'
    - 'в шрифтах'
  answer: 1
  explanation: 'Рантайм логирует создание/exec контейнеров.'
```
