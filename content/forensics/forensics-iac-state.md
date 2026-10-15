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

## Анатомия terraform.tfstate

State — это JSON с чёткой структурой. Понимание полей превращает его в источник таймлайна:

```
{
  "version": 4,
  "terraform_version": "1.6.0",
  "serial": 42,
  "lineage": "9f8e7d6c-...",
  "outputs": { "db_endpoint": { "value": "db.prod.internal:5432" } },
  "resources": [
    {
      "mode": "managed",
      "type": "aws_db_instance",
      "name": "prod",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        { "attributes": { "username": "admin", "password": "Sup3rS3cret!" } }
      ]
    }
  ]
}
```

| Поле | Смысл |
|------|-------|
| `version` | версия формата state (сейчас 4) |
| `terraform_version` | какой версией применяли |
| `serial` | **счётчик применений**, растёт на каждый `apply` |
| `lineage` | уникальный id цепочки state (по нему связывают копии) |
| `outputs` | выходные значения — часто эндпоинты и секреты |
| `resources[].instances[].attributes` | реальные атрибуты ресурса, включая пароли |

`serial` и `lineage` — золото для форензика: по `serial` видно, **сколько раз**
инфраструктуру меняли, а по `lineage` — что два файла относятся к одной цепочке.

## Где вообще лежит state: бэкенды

State не всегда рядом с кодом — его хранят в **бэкенде**. Типовые места:

- **local** — файл `terraform.tfstate` рядом с конфигом;
- **S3** (+ DynamoDB для блокировки) — самый частый вариант;
- **azurerm** — blob-контейнер в Azure;
- **gcs** — бакет в Google Cloud;
- **Terraform Cloud / remote** — управляемый бэкенд.

```
$ aws s3 ls s3://acme-tf-state/prod/ --recursive
prod/terraform.tfstate
prod/terraform.tfstate.backup
prod/terraform.tfstate.20260310.tfstate   # версия из versioning
```

При версионировании бакета каждая перезапись создаёт **новую версию** файла — это готовый
таймлайн применений. Скачиваешь версии, сравниваешь `serial` — видишь порядок изменений.

## Поиск секретов в state

Секреты попадают в state, когда их пишут в атрибуты ресурсов. Искать их просто:

```
$ jq -r '.. | objects | .password? // empty' state.json
Sup3rS3cret!
$ grep -iE 'password|secret|token|key|credential' state.json | head
```

Частые источники секретов в state: пароли RDS, ключи IAM-пользователей, приватные ключи
SSH, токены провайдеров, содержимое user-data. Отдельно проверяй `outputs` — там
намеренно выводят чувствительные значения.

## State как таймлайн развёртывания

Изменения инфраструктуры фиксируются не только в state, но и в версиях бэкенда:

```
$ aws s3api list-object-versions --bucket acme-tf-state \
    --prefix prod/terraform.tfstate --query 'Versions[].[VersionId,LastModified]'
[["v3...","2026-03-10T03:14:00Z"],["v2...","2026-02-01T10:00:00Z"]]
```

Сопоставляя время версий с CloudTrail-событиями `PutObject`, видно, **кто** и **когда**
менял инфраструктуру. А сопоставив содержимое версий — **что именно** изменилось:
появился ли инстанс, которого нет в репозитории (drift / бэкдор-ресурс).

## CloudFormation: состояние в самом облаке

У CloudFormation нет отдельного файла state — состояние хранится в сервисе. Улики там:

- **stack events** — журнал создания/обновления/удаления ресурсов;
- **drift detection** — встроенное сравнение шаблона и реальности;
- **stack resources** — текущий список ресурсов с их физическими id.

```
$ aws cloudformation describe-stack-events --stack-name prod-web \
    --query 'StackEvents[].[Timestamp,ResourceStatus,ResourceType,LogicalResourceId]'
```

Аномалия: `UPDATE_IN_PROGRESS` в 03:14, которого не должно было быть — кто-то менял стек
вручную или через скомпрометированный ключ.

## Ловушки IaC-форензика

- **State устаревает** — это последнее применённое, а не текущее состояние; сверяй с
  реальностью (`terraform plan`, `describe-*`).
- **Секреты зашифрованы** — некоторые бэкенды шифруют state (KMS/SSE); без ключа не
  прочесть, но факт `PutObject` всё равно виден в CloudTrail.
- **State удалён** — `terraform destroy` затирает state; тогда остаются только версии в
  бакете и события CloudTrail.
- **Несколько workspace** — prod/dev/staging хранят **разные** state; не пропусти нужный.
- **State-файл в git** — если его случайно закоммитили, история git хранит все версии и
  секреты навсегда.

## Практический чеклист

1. Найти все бэкенды и скачать все state-файлы (включая `.backup` и версии).
2. Проверить `serial`/`lineage` — оценить число применений и связать копии.
3. `grep`/`jq` по секретам в `attributes` и `outputs`.
4. Сопоставить версии state с CloudTrail `PutObject` — кто и когда менял.
5. Сверить state с реальными ресурсами — искать drift и «лишние» ресурсы.
6. Для CloudFormation — выгрузить stack events и включить drift detection.

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
