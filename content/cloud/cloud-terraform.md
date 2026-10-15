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

## Terraform: как устроен state

Terraform хранит в state **всё**, что знает об инфраструктуре: ID ресурсов, их атрибуты, outputs, а часто и **секреты** — потому что провайдеры возвращают чувствительные значения (пароли БД, ключи) как атрибуты ресурсов. State — это JSON, и его надо рассматривать как «дамп инфраструктуры с секретами».

Backend'ы, где живёт state:

| Backend | Где лежит | Риск |
|---|---|---|
| local | файл `terraform.tfstate` | утечка через git/бэкап |
| S3 | бакет | публичный ACL, отсутствие шифрования |
| GCS | бакет | те же проблемы |
| Azure RM | blob | SAS-токены, публичный доступ |
| Terraform Cloud | SaaS | токены API, workspace-доступ |
| consul/etcd | key-value | незащищённый KV |

Главный мисконфиг — **публичный бакет с state**. `aws s3 ls s3://company-tf-state --no-sign-request` иногда срабатывает, и вы получаете дамп всей инфраструктуры.

## Что искать в state

Откройте `terraform.tfstate` (или скачайте из бакета) и ищите:

- **`"type": "aws_db_instance"`** → `password`, `username`, `endpoint`.
- **`"type": "aws_iam_access_key"`** → `secret`, `id` (полноценные AWS-креды!).
- **`"type": "aws_instance"`** → `user_data` (часто с секретами), IP, SSH-ключи.
- **`outputs`** → иногда там лежат пароли и токены, если разработчик их выводит.
- **`"sensitive": true`** — не защита: в state значение всё равно открыто.

```bash
# быстрый поиск секретов
grep -Ei '"(password|secret|token|access_key|private_key)"' terraform.tfstate
# через jq — все IAM-ключи
jq '.resources[] | select(.type=="aws_iam_access_key") | .instances[].attributes' terraform.tfstate
```

State в S3 версионируется — иногда старые версии содержат **удалённые**, но всё ещё валидные ключи. Проверьте `aws s3api list-object-versions`.

## Подмена state: атака на доверие

State можно не только читать, но и **подменять**. Если бакет доступен на запись, атакующий может:

- добавить фиктивный ресурс (например, свой IAM-пользователь с админскими правами),
- изменить атрибуты существующего ресурса,
- удалить ресурс из state, чтобы Terraform его «пересоздал» под контролем атакующего.

При следующем `terraform apply` CI/CD-пайплайн применит изменения — и вы получите персистентность через легитимный процесс. Это особенно опасно, если пайплайн работает с широкими правами.

## Где ещё живёт state и секреты

- **`.terraform/` каталог**: провайдеры, плагины, кэш модулей.
- **`terraform.tfstate.backup`**: предыдущая версия — часто забыта и доступна.
- **`*.tfvars`**: переменные, иногда с паролями в открытом виде; проверьте git-историю.
- **CI-логи**: `terraform plan` печатает значения, включая чувствительные (иногда замаскированные, но не всегда).
- **Модули**: remote-модули могут тянуть секреты из публичных источников.

Проверьте git-историю репозитория инфраструктуры: `git log -p -- '*.tfvars'` — пароли могли быть закоммичены и удалены, но остались в истории.

## Защита и что ломает атаку

- **Шифрование state**: S3 SSE-KMS, шифрование на клиенте.
- **Строгий доступ**: IAM-политика на бакет, никакого `public-read`.
- **Remote backend с блокировкой**: DynamoDB lock, чтобы исключить подмену.
- **Не хранить секреты в state**: `aws_secretsmanager_secret_version` вместо литералов; генерация паролей через `random_password` с `ephemeral`.
- **Версионирование с ограниченным доступом**: старые версии тоже содержат секреты.
- **Ротация** всего, что когда-либо попало в state.

Если state зашифрован KMS и доступ к бакету ограничен — вектор закрыт. Если бакет публичный, любая из найденных строк может быть живыми кредами, которые надо немедленно проверить (и ротировать в отчёте).

## Чек-лист атаки на IaC

1. Найдите репозиторий инфраструктуры (GitHub/GitLab, поиск по `terraform`).
2. Определите backend (в `backend.tf` или `.terraform/terraform.tfstate`).
3. Проверьте доступность бакета/контейнера анонимно.
4. Скачайте state, извлеките секреты (`grep`/`jq`).
5. Проверьте старые версии (версионирование).
6. Протестируйте найденные креды (не в лоб, а точечно).
7. Проверьте запись в бакет (подмена state) — только если авторизовано.

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
