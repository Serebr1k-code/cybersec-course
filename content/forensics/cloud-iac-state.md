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
  title: "Практика: дрейф Terraform state"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, iac_state_drift.csv]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "Terraform state — источник истины о развёрнутом."
    - "Бакет с public-read вместо private — дрейф."
    - "`grep nto iac_state_drift.csv > answer.txt`."
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

## Разбор terraform.tfstate

State — это JSON, в котором Terraform хранит соответствие «ресурс в конфиге →
реальный объект в облаке». Он содержит идентификаторы, атрибуты и, что важнее
для расследования, значения, которые в конфиге помечены `sensitive`.

```
$ jq '.resources[] | {type, name, id}' terraform.tfstate | head -20
{
  "type": "aws_iam_user",
  "name": "deploy",
  "id": "deploy"
}
{
  "type": "aws_db_instance",
  "name": "prod",
  "id": "db-prod-01"
}
```

Ключевая особенность: state **всегда содержит секреты в открытом виде**, даже
если в `.tf` они через `sensitive = true` или приходят из переменных. Пароли
RDS, приватные ключи TLS, access keys — всё оседает в state как plaintext.

```
$ jq -r '.. | .password? // empty' terraform.tfstate | sort -u
SuperSecret123!
```

## Таблица: поля state и их значение

| Поле | Смысл для расследования |
|---|---|
| `resources[].type` | тип ресурса (aws_iam_user, aws_s3_bucket) |
| `resources[].instances[].attributes` | фактические значения (в т.ч. секреты) |
| `serial` | номер ревизии — растёт при каждом apply |
| `lineage` | UUID состояния, привязан к бэкенду |
| `terraform_version` | версия, которой делали apply |
| `outputs` | вычисленные значения (часто с секретами) |

По `serial` можно определить, **сколько раз применяли** конфиг после
подозрительного коммита. Резкий рост serial в нерабочее время — сигнал.

## Дрейф (drift) как улика

Дрейф — расхождение между state и реальностью. Атакующий часто меняет ресурс
руками (через консоль/CLI), не трогая конфиг, чтобы не оставить след в git.
Тогда `terraform plan` покажет изменение, которого никто не ожидал:

```
$ terraform plan -detailed-exitcode
aws_iam_user.deploy: Refreshing state...
~ aws_iam_policy.deploy
    policy: "{\"Version\":\"2012-10-17\",...\"Action\":\"*\"}"
    -> "{\"Version\":\"2012-10-17\",...\"Action\":\"s3:GetObject\"}"
Plan: 0 to add, 1 to change, 0 to destroy.
```

Политика, расширенная до `Action: "*"` вне конфига, — прямое доказательство
ручного вмешательства с правами администратора.

## Бэкенды и история версий

Удалённый бэкенд (S3, GCS, Terraform Cloud) хранит **историю версий state**.
Это критично: старые версии показывают состояние до и после атаки.

```
$ aws s3api list-object-versions --bucket tfstate-prod \
    --prefix prod/terraform.tfstate | jq '.Versions[] | {VersionId,LastModified}'
{ "VersionId": "aBc...", "LastModified": "2026-03-11T03:45:12Z" }
{ "VersionId": "xYz...", "LastModified": "2026-03-10T18:00:00Z" }
```

Скачивай соседние версии и делай `diff` — увидишь точный набор изменённых
атрибутов. Разница между версиями от 10-го и 11-го числа и есть карта атаки.

## Границы метода и типичные ошибки

- **Локальный state не версионируется.** Если бэкенд локальный (`backend
  "local"`), истории нет — сохраняй копию сразу при обнаружении.
- **Шифрование бэкенда.** S3-бэкенд часто с SSE-KMS; нужен доступ к ключу,
  иначе версии не прочитать.
- **`sensitive` не шифрует.** Атрибут только скрывает вывод в CLI, в файле
  значение остаётся открытым — не полагайся на него как на защиту.
- **State может быть неполным.** Ресурсы, созданные вне Terraform (import),
  в state попадут только после `terraform import`.

## Если сработало

Найден расширенный IAM-политик или новый ключ в state — фиксируй радиус:

```
$ jq -r '.resources[] | select(.type=="aws_iam_access_key") | .instances[].attributes.id' \
    terraform.tfstate
AKIAIOSFODNN7EXAMPLE
```

Затем сопоставь этот ключ с облачными логами: по нему видны все вызовы API,
совершённые атакующим. Каждая запись — точка на таймлайне инцидента.

## Парсинг state программно

Ручной просмотр JSON не масштабируется: реальный state — это тысячи строк.
Извлекаем только чувствительное одной командой:

```
$ jq -r '
  .resources[]
  | select(.type | test("aws_iam|aws_db|aws_secretsmanager"))
  | "\(.type)\t\(.name)\t\(.instances[0].attributes.id // "-")"
' terraform.tfstate
aws_iam_user	deploy	deploy
aws_iam_access_key	ci	AKIAIOSFODNN7EXAMPLE
aws_db_instance	prod	db-prod-01
```

Дальше ищем секреты по ключам, которые их выдают:

```
$ jq -r 'paths(scalars) as $p | select($p[-1]|test("password|secret|token|key";"i"))
         | "\($p|join(".")) = \(getpath($p))"' terraform.tfstate
resources.0.instances.0.attributes.password = SuperSecret123!
```

Такой «рекурсивный поиск по именам полей» находит секреты, даже если они
вложены глубоко и не помечены `sensitive`.

## Сравнение версий state

Ключевой приём — `diff` двух версий. Он показывает точный набор изменений,
внесённых между apply:

```
$ diff <(jq -S . v_before.tfstate) <(jq -S . v_after.tfstate)
<     "Action": "s3:GetObject"
>     "Action": "*"
```

Сортировка ключей (`jq -S`) убирает шум от перестановки полей. Если в диффе
появился ресурс, которого нет ни в одном `.tf`, — его создали вручную через
`terraform import` или прямым вызовом API, а затем записали в state.

## Провайдер-специфика

Разные облака хранят разное:

| Провайдер | Что искать в state |
|---|---|
| AWS | `aws_iam_access_key.secret`, `aws_db_instance.password` |
| GCP | `google_service_account_key.private_key` (PEM) |
| Azure | `azurerm_key_vault_secret.value` |
| Kubernetes | `kubernetes_secret.data` (base64) |

У GCP приватный ключ сервисного аккаунта лежит целиком в PEM — это готовый
к использованию credential. У Azure значение Key Vault-секрета доступно
только при наличии прав на vault, но в state оно всё равно сохраняется.

## Ограничения и подводные камни

- **State не является источником истины о правах.** Он отражает конфиг
  Terraform, а не реальные IAM-политики, если кто-то правил их руками.
- **`moved`/`import` блоки** маскируют историю: ресурс мог быть переименован,
  и в старых версиях state он лежит под другим именем.
- **Remote state data sources** подтягивают чужие state — секреты соседнего
  проекта могут «протечь» в ваш при инспекции.
- **Чувствительность к версии.** Схема state меняется между версиями
  Terraform; парси `terraform_version` перед разбором.

## State как карта инфраструктуры

Для расследования state — это ещё и **инвентарь**: он перечисляет все
управляемые ресурсы с их связями. Быстрая сводка:

```
$ jq -r '.resources[].type' terraform.tfstate | sort | uniq -c | sort -rn
      12 aws_iam_policy
       8 aws_s3_bucket
       3 aws_db_instance
       1 aws_iam_access_key
```

Один `aws_iam_access_key` там, где ожидаются только роли, — повод проверить:
возможно, ключ создан атакующим для persistence. `depends_on` и ссылки между
ресурсами (`${aws_iam_role.x.arn}`) показывают, что с чем связано.

## Триггеры алертов

Настрой мониторинг на изменения state вне пайплайна:

- `serial` вырос без записи о плановом apply;
- появился ресурс типа `aws_iam_access_key`/`google_service_account_key`;
- IAM-политика получила `Action: "*"` или `Resource: "*"`;
- бакет стал `acl = "public-read"`.

Такой алерт ловит атаку в момент изменения, а не постфактум.

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
