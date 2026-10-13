---
id: cloud-terraform
title: "Terraform и IaC: state, провайдеры и злоупотребление инфраструктурой как кодом"
category: cloud
parent: cloud-supply-chain
difficulty: hard
order: 2
tags: [cloud, terraform, iac, state, drift, supply-chain, secrets]
prerequisites: [cloud-supply-chain, cloud-credential-hunting]
useful_for:
  - "Поиск секретов в Terraform state"
  - "Атака на IaC-пайплайны"
  - "Понимание инфраструктуры как кода"
estimated_minutes: 50
summary: "Как атаковать Terraform/IaC: секреты в state и plan-файлах, злоупотребление провайдерами, drift и подмена модулей. Практические приёмы и типовые ошибки."
lab:
  kind: shell
  title: "Практика: Terraform и IaC"
  toolset: [core]
  workdir: /home/student/tf
  files: [task.md, notes.md, terraform.tfstate, main.tf]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "`terraform.tfstate` часто содержит секреты в открытом виде."
    - "Поищи в state: `grep nto terraform.tfstate`."
    - "Сохрани флаг: `grep nto terraform.tfstate > found.txt`."

---
## Задача

В `cloud-supply-chain` мы подкладывали код через зависимости. Но в облаке есть ещё один «файл, которому все доверяют», — **Terraform state**. Terraform — это инструмент **IaC** (Infrastructure as Code): инфраструктура (серверы, сети, базы) описывается в текстовых файлах и создаётся командами, а не руками в консоли.

Задача: найти `terraform.tfstate` и посмотреть, что в нём лежит. Часто это самый быстрый путь к секретам всего аккаунта. Разберём на конкретном публичном бакете.

## Данные: бакет, который «просто хранит состояние»

У цели есть S3-бакет `acme-tfstate-prod` — по имени видно, что он для состояния Terraform. Проверяем доступ к листингу:

```
$ aws s3 ls s3://acme-tfstate-prod/ --no-sign-request
2025-03-14 09:11:02       8192 terraform.tfstate
2025-03-14 09:11:02       4096 terraform.tfstate.backup
```

`--no-sign-request` — это анонимный запрос, без наших кредов. Он вернул содержимое бакета: листинг открыт всему интернету. Скачиваем state:

```
$ aws s3 cp s3://acme-tfstate-prod/terraform.tfstate . --no-sign-request
download: s3://acme-tfstate-prod/terraform.tfstate to ./terraform.tfstate
```

## Почему state — это сокровищница

**State-файл** — это «память» Terraform: он хранит соответствие между описанными в коде ресурсами и реальными объектами в облаке. Чтобы управлять ресурсами, Terraform записывает в state **всё их состояние** — включая то, что в коде было переменной.

Опасность в том, что в state попадают значения, которые в конфиге выглядели безобидно:

- пароли баз данных (генерируются и сохраняются);
- приватные ключи (`tls_private_key`);
- секреты, вписанные через `variable`;
- выводы (`output`) — их часто используют, чтобы «пробросить» креды в другие стеки.

State — это **plaintext-слепок всего, чем управляет Terraform**.

## Пробуем в лоб: ищем в state секреты

Ищем в скачанном файле характерные строки:

```
$ grep -oE '(password|secret|access_key|private_key)"?: ?"[^"]+' terraform.tfstate | head
password": "P@ssw0rd-prod-2025"
secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
private_key": "-----BEGIN RSA PRIVATE KEY-----"
```

Пароль БД, секретный ключ AWS и приватный RSA-ключ — всё в открытом виде. State не шифрует значения на уровне полей: шифрование (если есть) — только «на диске» бакета.

## Приём: достаём конкретные ресурсы и outputs

Чтобы не грепать вслепую, используем штатные команды Terraform — они умеют читать state и показывать структуру. Если у нас есть доступ к директории с конфигом:

```
$ terraform state list
aws_db_instance.prod
aws_iam_user.deployer
aws_iam_access_key.deployer
module.app.tls_private_key.ssh

$ terraform output -json
{
  "db_endpoint": {"value": "prod-db.abc.us-east-1.rds.amazonaws.com"},
  "deployer_access_key": {"value": "AKIAIOSFODNN7EXAMPLE"}
}
```

`terraform output` — выводы стека; `deployer_access_key` — это IAM-ключ деплоера, доступный любому, кто прочитал state. Если конфига нет, state всё равно парсится вручную: `terraform show -json terraform.tfstate | jq '..|.attributes?|select(.)'`.

## Полный прогон: от открытого бакета до админского ключа

1. **Находим бакет.** По имени `*tfstate*`/`*terraform*`; проверяем листинг `--no-sign-request`.
2. **Скачиваем state.** `aws s3 cp ... --no-sign-request`.
3. **Парсим.** `grep` по секретам либо `terraform show -json`.
4. **Достаём outputs.** Часто там готовые креды для «проброса» между стеками.
5. **Проверяем ключ.** Если это IAM-ключ:

```
$ AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=... aws sts get-caller-identity
{ "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/deployer" }
```

6. **Смотрим права.** `aws iam list-attached-user-policies --user-name deployer` → возможно, `AdministratorAccess`.

Так один забытый публичный бакет превращается в полный контроль над аккаунтом.

## Приём 2: подмена state

Чтение state — не единственный вектор. Если у нас есть **запись** в бакет с state, мы можем его подменить — и Terraform поверит. Сценарий: подменяем в state атрибут ресурса, и следующий `terraform apply` в пайплайне применит наше значение.

Простой пример: в state у ресурса `aws_iam_user.deployer` меняем имя на `admin` — и пайплайн «обновит» не того пользователя. Более прямой путь — подменить в state секрет, который пайплайн потом «пробрасывает» дальше. Защита от этого — **версионирование бакета** и `DynamoDB lock`, но они лишь фиксируют факт изменения, а не мешают ему.

## Где ещё живёт state

- **S3 backend** — самый частый; смотрите `backend "s3"` в `*.tf`.
- **GCS / Azure Blob backend** — то же самое у GCP/Azure.
- **Terraform Cloud / GitLab-managed state** — если есть токен платформы.
- **Локальный `terraform.tfstate`** — иногда коммитится в git (ищите `grep -r tfstate`).

Проверить backend из конфига:

```
$ grep -A5 'backend "' *.tf
backend "s3" {
  bucket = "acme-tfstate-prod"
  key    = "terraform.tfstate"
  region = "us-east-1"
}
```

## Защита и что ломает атаку

- **Шифрование state + строгий доступ.** State должен лежать в приватном бакете с `SSE-KMS` и политикой «только пайплайн».
- **Не хранить секреты в IaC.** Пароли — из Secrets Manager, ссылкой, а не значением.
- **`sensitive = true`** помечает вывод как чувствительный, но **не шифрует** его в state — это лишь скрывает его в CLI.
- **Блокировка state** (`DynamoDB lock`) защищает от одновременной записи, но не от чтения.
- **Ротация.** Любой секрет, попавший в state, надо считать скомпрометированным и ротировать.

## Если не сработало

- **Бакет закрыт, но есть `s3:GetObject`** — качаем напрямую, не листингуя.
- **State зашифрован KMS** — без `kms:Decrypt` содержимое не читается.
- **Backend Terraform Cloud** — нужен токен платформы.
- **Секретов нет** — смотрим outputs и имена ресурсов: они дают карту инфраструктуры для дальнейшей разведки.

## Мини-сценарий: открытый бакет со state

1. **Находим бакет.** Имя `acme-tfstate-prod` намекает на Terraform. `aws s3 ls s3://acme-tfstate-prod/ --no-sign-request` → листинг открыт.
2. **Качаем.** `aws s3 cp s3://acme-tfstate-prod/terraform.tfstate . --no-sign-request`.
3. **Парсим.** `grep -oE '(password|secret_key|private_key)"?: ?"[^"]+' terraform.tfstate` → пароль БД, секретный ключ AWS, приватный RSA.
4. **Outputs.** Если есть конфиг: `terraform output -json` → `deployer_access_key`.
5. **Проверяем.** `aws sts get-caller-identity` с найденным ключом → `user/deployer`.
6. **Эскалация.** `aws iam list-attached-user-policies --user-name deployer` → возможно, `AdministratorAccess`.

Один забытый публичный бакет — и весь аккаунт открыт.

## Что мы теперь знаем

1. State — plaintext-память Terraform со всеми значениями ресурсов.
2. Открытый бакет со state = утечка паролей, ключей и outputs.
3. `terraform state list`/`output` — штатный способ вытащить данные.
4. `sensitive` скрывает вывод в CLI, но не в state.
5. Защита — приватный бакет, KMS, секреты по ссылке, ротация.

## На что смотреть дальше

- Бакеты с `tfstate`/`terraform` в имени и их листинг.
- `backend`-блоки в `*.tf` — куда пишется state.
- `output`-блоки — часто содержат креды для «проброса».
- `tls_private_key` и `aws_iam_access_key` в state.
- Коммиты `*.tfstate` в git-истории.

## Квиз

Проверь себя.

```quiz
- question: "Почему terraform.tfstate опасен при утечке?"
  options:
    - "Он хранит значения ресурсов в открытом виде, включая пароли и ключи"
    - "Он ускоряет сборку"
    - "Он шифрует инфраструктуру"
    - "Он содержит только имена"
  answer: 0
  explanation: "State — plaintext-слепок состояния всех ресурсов."
- question: "Что делает флаг sensitive = true для секрета?"
  options:
    - "Скрывает значение в выводе CLI, но НЕ шифрует его в state"
    - "Шифрует секрет в state"
    - "Удаляет секрет"
    - "Отправляет секрет в KMS"
  answer: 0
  explanation: "sensitive влияет на отображение, а не на хранение."
- question: "Какая команда выводит outputs стека Terraform?"
  options:
    - "terraform output"
    - "terraform apply"
    - "terraform init"
    - "terraform fmt"
  answer: 0
  explanation: "terraform output показывает значения outputs."
- question: "Где чаще всего лежит state в AWS?"
  options:
    - "В S3-бакете, указанном в backend-блоке"
    - "В DynamoDB"
    - "В Lambda"
    - "В CloudFront"
  answer: 0
  explanation: "Стандартный backend — S3 (плюс DynamoDB для блокировки)."
- question: "Что делать с секретом, найденным в state?"
  options:
    - "Считать его скомпрометированным и ротировать"
    - "Игнорировать"
    - "Зашифровать бакет задним числом"
    - "Удалить файл"
  answer: 0
  explanation: "Попавший в state секрет надо ротировать."
```

## Куда дальше

В следующем уроке (`cloud-supply-chain-sbom`) мы посмотрим, как проверить подлинность артефактов — и как эту проверку обмануть. А пока главное: state — это не «служебный файл», а полный слепок твоей инфраструктуры с секретами, и открытый к нему доступ равен компрометации аккаунта.

## Где пригодится

- **Bug bounty:** открытые бакеты с tfstate.
- **Red team:** от IaC-бэкенда к ключам аккаунта.
- **Пентест:** аудит Terraform-инфраструктуры.
- **Работа/DevSecOps:** приватный backend, KMS, секреты по ссылке.
- **Дальше по дереву:** `cloud-terraform-state`, `cloud-cloudformation`.
