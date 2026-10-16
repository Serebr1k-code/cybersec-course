---
id: cloud-terraform-state
title: "Terraform state и backend: секреты, доступ и подмена"
category: cloud
parent: cloud-iac-deep
difficulty: hard
order: 1
tags: [cloud, terraform, state, backend, iac, secrets, s3, gcs]
prerequisites: [cloud-iac-deep, cloud-terraform]
useful_for:
  - "Пентест Infrastructure as Code"
  - "Кража секретов из Terraform state"
  - "Атаки на backend"
estimated_minutes: 45
summary: "Terraform state: где лежит, что содержит, как читать и подменять. Backend S3/GCS/Azure, шифрование, блокировки и извлечение секретов через terraform show/state pull."
lab:
  kind: shell
  title: "Практика: секреты в Terraform state"
  toolset: [core]
  workdir: /home/student/iac
  files: [task.md, terraform.tfstate, main.tf, backend.tf, notes.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Осмотрись: `ls -la` и `cat backend.tf` — где хранится state?"
    - "Terraform пишет в state **все** атрибуты ресурсов в открытом виде, включая пароли. Поищи: `grep -i password terraform.tfstate`."
    - "Настоящий флаг лежит в блоке outputs. Найди его: `grep nto terraform.tfstate`."
    - "Выдели значение между кавычками: `grep secret_output terraform.tfstate | cut -d'\"' -f4 > found.txt`."
---
## Задача

В `cloud-terraform` мы нашли открытый бакет со state. Но чаще бакет закрыт, а у нас есть лишь **частичные права** — например, `s3:GetObject` на один ключ. Задача: вытащить секреты из state, имея только чтение объекта, и понять, как устроен **backend** — место, где state физически хранится. Разберём на AWS S3-backend.

## Данные: backend и наши права

Смотрим конфиг Terraform, чтобы понять, куда пишется state:

```
$ grep -A6 'backend "s3"' *.tf
backend "s3" {
  bucket         = "acme-tfstate-prod"
  key            = "prod/terraform.tfstate"
  region         = "us-east-1"
  dynamodb_table = "acme-tf-lock"
  encrypt        = true
}
```

Читаем так: state лежит в S3 (`bucket`/`key`), блокировка — в DynamoDB (`dynamodb_table`), шифрование включено (`encrypt`). `encrypt = true` — это шифрование **на диске** (SSE), а не шифрование полей: скачав объект, мы получим открытый JSON.

У нас есть узкие креды:

```
$ aws sts get-caller-identity
{ "Arn": "arn:aws:iam::123456789012:user/readonly-auditor" }
$ aws s3api get-object --bucket acme-tfstate-prod --key prod/terraform.tfstate state.json
{ "ContentLength": 4096, "ServerSideEncryption": "aws:kms" }
```

`get-object` сработал: нам хватило `s3:GetObject` на этот ключ. Листинг бакета нам недоступен, но он и не нужен — ключ известен из конфига.

## Пробуем в лоб: читаем JSON руками

State — это JSON. Смотрим outputs и ресурсы:

```
$ jq '.outputs' state.json
{
  "rds_password": { "value": "Pr0d-DB-P@ss", "type": "string" },
  "admin_role_arn": { "value": "arn:aws:iam::123456789012:role/org-admin" }
}
```

Пароль БД и ARN админской роли. В самом state-файле лежат ещё и все атрибуты ресурсов. Но грепать JSON руками неудобно — есть штатный способ.

## Приём: terraform state pull

Команда `terraform state pull` скачивает текущий state из backend и печатает его в stdout, используя те же креды, что и провайдер. Это удобнее прямого `s3api`:

```
$ terraform state pull > state.json
$ terraform state list
aws_db_instance.prod
aws_iam_access_key.deployer
module.app.tls_private_key.ssh
```

`state list` показывает адреса ресурсов. Дальше — `terraform show` по конкретному адресу:

```
$ terraform show -json state.json | jq '..|.values?|select(.password?) | .password'
"Pr0d-DB-P@ss"
```

Так мы достаём значения без ручного парсинга и без знания структуры.

## Полный прогон: от чтения объекта до ключа деплоера

1. **Находим backend.** `grep backend` в конфиге → bucket и key.
2. **Качаем state.** `s3api get-object` или `terraform state pull`.
3. **Перечисляем ресурсы.** `terraform state list` → видим `aws_iam_access_key.deployer`.
4. **Достаём секрет.** `terraform show -json` → `secret_key` и `access_key_id`.
5. **Проверяем.** Ключ деплоера может иметь широкие права:

```
$ aws sts get-caller-identity
{ "Arn": "arn:aws:iam::123456789012:user/deployer" }
$ aws iam list-attached-user-policies --user-name deployer
{ "AttachedPolicies": [ { "PolicyName": "PowerUserAccess" } ] }
```

Одно чтение объекта дало ключ с `PowerUserAccess`.

## Подмена state (когда есть запись)

Если у нас не только чтение, но и `s3:PutObject` (или `terraform state push`), state можно изменить — и пайплайн применит наше значение. Классика: подменить атрибут ресурса, чтобы следующий `apply` сделал не то.

```
$ terraform state push modified.tfstate
```

Защита — **версионирование бакета** (старые версии остаются) и **DynamoDB-блокировка** (одновременная запись запрещена). Но версионирование лишь фиксирует факт, а блокировка мешает только параллельной записи.

## GCS и Azure backend

Тот же принцип у других провайдеров. GCS:

```
$ gsutil cp gs://acme-tfstate/prod/default.tfstate .
```

Azure (azurerm backend) — состояние в Blob-контейнере; читается `az storage blob download`. Проверяйте, нет ли на контейнер публичного доступа или лишних ролей.

## Частые ошибки вокруг state

- **Считать `encrypt = true` достаточной защитой.** Это шифрование диска, а не полей; кто прочитал объект — прочитал секреты.
- **Держать state в том же бакете, что и статику.** Достаточно одной ошибки в политике бакета.
- **Коммитить `terraform.tfstate` в git.** Секреты уходят в историю навсегда.
- **Не ротировать после утечки.** Пароль из state продолжает работать.
- **Давать `GetObject` на state «на всякий случай».** Чтение state = чтение всех секретов стека.

## Защита и что ломает атаку

- **Приватный backend** + доступ только сервисному аккаунту пайплайна.
- **SSE-KMS** — но помните: это защита «на диске», не полей.
- **Секреты по ссылке** (Secrets Manager) вместо значений в ресурсах.
- **Ротация** любого секрета, попавшего в state.
- **Версионирование + мониторинг** записи в бакет state.

## Если не сработало

- **Нет `s3:GetObject`** — читать нечего, ищем другой путь (роль, CI).
- **Backend в Terraform Cloud** — нужен API-токен платформы.
- **Секретов нет** — но остаются outputs и адреса ресурсов: это карта инфраструктуры.
- **State зашифрован KMS без `kms:Decrypt`** — содержимое не читается.

## Мини-сценарий: чтение state целиком

1. **Находим backend.** `grep -A6 'backend "s3"' *.tf` → bucket `acme-tfstate-prod`, key `prod/terraform.tfstate`.
2. **Проверяем права.** У нас `s3:GetObject` на этот ключ (листинг закрыт, но ключ известен).
3. **Качаем.** `aws s3api get-object --bucket acme-tfstate-prod --key prod/terraform.tfstate state.json`.
4. **Перечисляем.** `terraform state list` → `aws_db_instance.prod`, `aws_iam_access_key.deployer`.
5. **Достаём секрет.** `terraform show -json state.json | jq '..|.values?|select(.secret_key?)'` → `secret_key` деплоера.
6. **Проверяем.** `aws sts get-caller-identity` → `user/deployer` с `PowerUserAccess`.
7. **Подмена (если есть запись).** `terraform state push modified.tfstate` — пайплайн применит наше значение.

Одно право чтения объекта отдало ключ с широкими правами.

## Разбор: state — это секреты по определению

Многие считают state «служебным файлом» и не думают о нём как о хранилище секретов. Но Terraform записывает в state **значения** ресурсов — включая пароли, ключи и сертификаты, которые в конфиге были переменными. Поэтому доступ к state равен доступу к секретам всей инфраструктуры. Из этого следуют три правила. Первое: backend должен быть приватным, а `GetObject` на него — только у пайплайна. Второе: секреты не хранят в IaC значениями, а ссылаются на Secrets Manager. Третье: любой секрет, попавший в state, считается скомпрометированным и ротируется. `encrypt = true` защищает диск, но не отменяет первых трёх правил.

## Что мы теперь знаем

1. Backend определяет, где лежит state и как он блокируется.
2. `terraform state pull`/`show -json` — штатный способ вытащить значения.
3. `encrypt = true` шифрует диск, а не поля state.
4. При наличии записи state можно подменить.
5. Защита — приватный backend, секреты по ссылке, ротация.
6. Версионирование и lock фиксируют изменение, но не мешают чтению.

Проще говоря: state — это второй «файл конфигурации», только с реальными секретами вместо переменных.

## На что смотреть дальше

- `backend`-блок: bucket, key, таблица блокировки, `encrypt`.
- `aws_iam_access_key` и `tls_private_key` в state.
- Outputs с паролями и токенами.
- Права на бакет state: кому разрешён `GetObject`/`PutObject`.
- Версионирование и мониторинг записи.

## Быстрая проверка

Четыре команды покрывают весь вектор — от поиска backend до вытаскивания outputs:

```bash
grep -A6 'backend "' *.tf          # где лежит state
terraform state pull > s.json      # скачать state
terraform state list               # перечислить ресурсы
jq '.outputs' s.json               # вытащить outputs (часто с кредами)
```

## Шифрование state и KMS

В зрелых облачных настройках state лежит в бакете с включённым шифрованием (SSE)
и, что важнее, с **клиентским** шифрованием через KMS. В `backend` это выглядит так:

```hcl
terraform {
  backend "s3" {
    bucket         = "acme-tfstate"
    key            = "prod/terraform.tfstate"
    kms_key_id     = "arn:aws:kms:eu-west-1:111122223333:key/abcd-..."
  }
}
```

Ключевой вывод для атакующего: даже если бакет открыт, зашифрованный объект не
читается без прав на `kms:Decrypt`. Поэтому проверяй не только политику S3, но и
политику KMS — часто именно она остаётся единственной преградой. Симметричная
ошибка защитника — выдать `kms:Decrypt` всей учётной записи «чтобы работало».

## Terraform Cloud и remote backend

State не всегда в S3. Если команда использует **HCP Terraform / Terraform Cloud**,
он хранится на их стороне, и в файлах остаётся только имя workspace. Локально при
этом может лежать `.terraform/terraform.tfstate` — метаданные с указанием, куда
идти за настоящим state. Это подсказка: сначала прочитай её, чтобы понять backend,
а потом иди за данными туда, где они реально лежат.

Ещё один частый источник — `terraform.tfstate.backup` рядом с основным файлом.
Копию забывают удалять, а в ней остаются те же секреты в открытом виде. Всегда
проверяй оба: `terraform.tfstate` и `terraform.tfstate.backup`.

Практический чек-лист: найди backend в `*.tf`, проверь права на бакет **и** на
KMS-ключ, поищи `.backup` и `terraform.tfstate.d/`, и только потом делай вывод,
что секреты недоступны.

## Квиз

Проверь себя.

```quiz
- question: "Что делает terraform state pull?"
  options:
    - "Скачивает текущий state из backend и печатает его"
    - "Применяет изменения"
    - "Форматирует конфиг"
    - "Удаляет ресурсы"
  answer: 0
  explanation: "state pull читает state из backend."
- question: "Что означает encrypt = true в backend-блоке?"
  options:
    - "Шифрование state на диске, а не отдельных полей"
    - "Шифрование всех полей state"
    - "Блокировку записи"
    - "Сжатие state"
  answer: 0
  explanation: "SSE шифрует объект целиком; поля внутри открыты."
- question: "Зачем в S3-backend нужна таблица DynamoDB?"
  options:
    - "Для блокировки state от одновременной записи"
    - "Для шифрования"
    - "Для хранения паролей"
    - "Для логирования"
  answer: 0
  explanation: "DynamoDB обеспечивает lock."
- question: "Какое право позволяет подменить state?"
  options:
    - "s3:PutObject (или terraform state push)"
    - "s3:ListBucket"
    - "sts:GetCallerIdentity"
    - "iam:ListRoles"
  answer: 0
  explanation: "Запись в бакет state позволяет подменить содержимое."
- question: "Что делать с ключом, найденным в state?"
  options:
    - "Ротировать: считать скомпрометированным"
    - "Игнорировать"
    - "Переименовать ресурс"
    - "Включить версионирование"
  answer: 0
  explanation: "Секрет из state надо ротировать."
```

## Куда дальше

В следующем уроке (`cloud-cicd-github-actions`) мы вернёмся к CI и разберём инъекции в workflow — как текст из issue или PR превращается в команду на раннере. А пока главное: state — это полный слепок инфраструктуры, и даже права только на чтение одного объекта отдают ключи.

## Где пригодится

- **Bug bounty:** открытые бакеты и Blob-контейнеры со state.
- **Red team:** от чтения state к ключам аккаунта.
- **Пентест:** аудит IaC-backend.
- **Работа/DevSecOps:** приватный backend, KMS, секреты по ссылке, ротация.
- **Дальше по дереву:** `cloud-terraform`, `cloud-cloudformation`.
