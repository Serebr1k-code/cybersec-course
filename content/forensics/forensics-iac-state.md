---
id: forensics-iac-state
title: 'IaC state: terraform.tfstate и CloudFormation как улика'
category: forensics
parent: forensics-cloud-devsecops
difficulty: hard
order: 1
tags: [cloud, iac, terraform, cloudformation, state, forensics]
prerequisites: [forensics-cloud-identity]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Cloud Security'
estimated_minutes: 50
summary: 'Что содержит IaC state (Terraform/CloudFormation), почему это ценный источник улик и секретов, и как восстановить историю развёртывания инфраструктуры.'
lab:
  kind: shell
  title: 'Практика: IaC state'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

Инфраструктура в облаке разворачивается кодом. Значит, где-то есть **состояние** этой
инфраструктуры — файл, который описывает, что реально создано. Этот файл часто ценнее
самих логов. Что в нём и как его использовать?

## Наш пример: terraform.tfstate

Находим в бэкенде (обычно S3-бакет) файл состояния:

```
$ aws s3 cp s3://tf-state/prod/terraform.tfstate ./state.json
$ head -c 300 state.json
{ "version": 4, "terraform_version": "1.6.0",
  "resources": [ { "type": "aws_instance", "name": "web", ... } ] }
```

Это **state** — снимок того, что Terraform создал в облаке.

## Что содержит state

- **список ресурсов**: инстансы, сети, базы, бакеты;
- **их атрибуты**: id, адреса, настройки;
- **иногда секреты**: пароли БД, ключи, токены — если они попали в атрибуты;
- **историю версий** (если бэкенд версионируется).

Именно секреты в state — частая причина утечек: файл лежит в S3 и доступен шире, чем
следовало бы.

## Шаг 1: найти все state-файлы

```
$ aws s3 ls s3://tf-state/ --recursive
prod/terraform.tfstate
prod/terraform.tfstate.backup
dev/terraform.tfstate
```

**Backup-файл** — предыдущее состояние. Сравнив их, можно увидеть, что **изменилось**:
какой ресурс добавили или удалили.

## Шаг 2: сравнить состояния

```
$ diff <(jq '.resources[].type' dev/terraform.tfstate) \
       <(jq '.resources[].type' prod/terraform.tfstate)
```

Разница показывает, где инфраструктура разошлась с ожидаемой (**drift**) — например,
атакующий вручную создал инстанс, которого нет в коде.

## Шаг 3: CloudFormation как аналог

У AWS есть свой IaC — CloudFormation. Его **stack events** хранят историю:

```
$ aws cloudformation describe-stack-events --stack-name prod-web
2026-03-10T03:10:00Z  CREATE_IN_PROGRESS  AWS::EC2::Instance  web
```

По событиям видно, **когда** и **что** создавалось/менялось, и кто это сделал (в связке с
CloudTrail).

## Шаг 4: связь с CloudTrail

IaC говорит «что должно быть», CloudTrail — «кто и что делал». Вместе они дают полную
картину: сравнение «описано в state» и «изменено вручную» выявляет несанкционированные
ресурсы.

## Ловушка: state устаревает

State — это **последнее применённое** состояние, а не текущее. Если изменения делали
вручную, state их не знает. Поэтому его всегда сверяют с реальностью (`terraform plan`,
описание ресурсов в облаке).

## Что мы теперь знаем

- IaC state описывает реально созданные ресурсы.
- В state могут быть секреты — это частая утечка.
- Backup-файл и история показывают изменения.
- Drift = расхождение кода и реальности.
- CloudFormation stack events дают историю развёртывания.

## Квиз

Проверь себя.

```quiz
- question: Что содержит terraform.tfstate?
  options:
    - 'только код'
    - 'описание созданных ресурсов и их атрибутов (иногда секреты)'
    - 'только логи'
    - 'SMART'
  answer: 1
  explanation: 'State — снимок ресурсов, включая атрибуты вроде паролей БД.'
- question: Что такое drift в IaC?
  options:
    - 'ускорение'
    - 'расхождение между кодом/state и реальной инфраструктурой'
    - 'сжатие'
    - 'резервная копия'
  answer: 1
  explanation: 'Ручные изменения создают ресурсы, которых нет в state.'
- question: Чем полезен terraform.tfstate.backup?
  options:
    - 'ничем'
    - 'это предыдущее состояние, по нему видно изменения'
    - 'это пароль'
    - 'это лог'
  answer: 1
  explanation: 'Сравнение текущего и backup-состояний показывает, что менялось.'
- question: Что дают CloudFormation stack events?
  options:
    - 'пароли'
    - 'историю развёртывания ресурсов'
    - 'скорость диска'
    - 'MAC-адреса'
  answer: 1
  explanation: 'Stack events фиксируют, когда и что создавалось/менялось.'
```

## Куда дальше

Дальше — **менеджеры секретов**: где секреты хранятся правильно и кто к ним обращался. А
пока запомни: `terraform.tfstate` — это карта инфраструктуры и потенциальный кладезь
секретов.

## Где пригодится

- **Cloud Security** — аудит инфраструктуры как кода.
- **DFIR / Incident Response** — поиск несанкционированных ресурсов.
- **CTF Forensics** — задачи с IaC state.
