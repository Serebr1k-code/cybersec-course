---
id: cloud-iac-state
title: 'IaC-состояние: Terraform state как источник истины'
category: forensics
parent: forensics-cloud-data
difficulty: hard
order: 3
tags: [forensics, cloud, iac, terraform, state]
prerequisites: [forensics-cloud-multi]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как использовать IaC-состояние (Terraform state) в расследовании: что развёрнуто, дрейф и следы изменений.'
lab:
  kind: shell
  title: 'Практика: IaC-состояние'
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

Что реально развёрнуто в облаке? Инфраструктура описана кодом (IaC), а её фактическое
состояние — в **state**. Это «источник истины» для расследования. Разберём.

## Наш пример: Terraform

## Шаг 1: что такое IaC и state

IaC (Terraform/CloudFormation/Pulumi) описывает инфраструктуру в коде. Terraform хранит
**state** — карту «код ↔ реальные ресурсы»:

```
$ terraform state list
aws_s3_bucket.data
aws_iam_user.deploy
```

## Шаг 2: state как улика

State содержит:

- все управляемые ресурсы;
- их атрибуты (в т.ч. **секреты** — иногда в открытом виде!);
- историю (в S3-бэкенде — версии).

```
$ terraform show -json | jq '.. | .password? // empty'
```

Секреты в state — частая утечка.

## Шаг 3: дрейф (drift)

**Дрейф** — расхождение кода и реальности. Если кто-то создал ресурс вручную (или
атакующий), он не в коде:

```
$ terraform plan
Note: objects have changed outside of Terraform
```

Это признак постороннего вмешательства.

## Шаг 4: бэкенд и история

State хранится в **бэкенде** (S3/GCS) с версионированием:

```
$ aws s3api list-object-versions --bucket tfstate --prefix terraform.tfstate
```

История версий показывает, **что** и **когда** менялось.

## Шаг 5: что искать

- ресурсы, которых нет в коде (созданы атакующим);
- секреты в state;
- изменения в истории state;
- права/роли, добавленные вне пайплайна.

## Что мы теперь знаем

- IaC описывает инфраструктуру кодом.
- State — карта ресурсов и их атрибутов.
- State может содержать секреты.
- Дрейф = расхождение кода и реальности (вмешательство).
- История state (бэкенд) показывает изменения.

## Если не сработало

- State недоступен? Смотри код и облачные API.
- Нет версионирования? Сравни с кодом.
- Нужны секреты? Ищи в state и менеджере.

## Квиз

Проверь себя.

```quiz
- question: Что хранит Terraform state?
  options:
    - 'только код'
    - 'карту ресурсов и их атрибутов'
    - 'обои'
    - 'музыку'
  answer: 1
  explanation: 'State связывает код с реальными ресурсами.'
- question: Что такое дрейф?
  options:
    - 'сеть'
    - 'расхождение кода и реальной инфраструктуры'
    - 'шифрование'
    - 'пароль'
  answer: 1
  explanation: 'Drift указывает на изменения вне IaC.'
- question: Чем опасен state?
  options:
    - 'он большой'
    - 'может содержать секреты в открытом виде'
    - 'он медленный'
    - 'он в облаке'
  answer: 1
  explanation: 'State нередко хранит пароли/ключи ресурсов.'
- question: Что показывает история версий state?
  options:
    - 'погоду'
    - 'что и когда менялось в инфраструктуре'
    - 'обои'
    - 'шрифты'
  answer: 1
  explanation: 'Версии state в бэкенде фиксируют изменения.'
```
