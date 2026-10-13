---
id: cloud-enum-methodology
title: "Разведка облака: cloudfox, enumerate-iam, pacu"
category: cloud
parent: cloud-network-deep
difficulty: hard
order: 3
tags: [cloud, recon, enumeration, cloudfox, pacu, enumerate-iam, privesc]
prerequisites: [cloud-network-deep, cloud-privesc-iam]
useful_for:
  - "Систематическая разведка облачного аккаунта"
  - "Поиск путей эскалации по правам"
  - "Пентест AWS/GCP/Azure с нуля"
estimated_minutes: 55
summary: "Методика облачной разведки: определить идентичность, выгрузить права, найти ресурсы и секреты, построить пути эскалации. Инструменты cloudfox, enumerate-iam, pacu, ScoutSuite, Prowler и их применение."
lab:
  kind: shell
  title: "Практика: разведка облака (enumerate-iam/cloudfox)"
  toolset: [core, enumerate-iam]
  workdir: /home/student/enum
  files: [task.md, notes.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Прогони перечисление прав: `enumerate-iam --access-key AKIA... --secret ...`."
    - "Инструмент покажет, какие API доступны твоим кредам."
    - "Найди флаг: сохрани вывод и `grep nto enum.txt > found.txt`."

---

## Задача

Ты получил облачные креды (например, вытащил их из Cognito) и не знаешь, что они открывают. Как не начать «тыкать» API наугад и не пропустить путь эскалации? В облаке права определяют всё: что видно, что можно читать, куда можно двигаться. Задача урока — провести **систематическую разведку**: понять, кто ты, что можешь, что существует, где секреты и какие есть пути привилегий.

## Пять вопросов облачной разведки

Разведка сводится к пяти вопросам:

1. **Идентичность.** Кто ты? `aws sts get-caller-identity` / `gcloud auth list` / `az account show`. Тип принципала (пользователь, роль, federated, service account) определяет, как применяются права.
2. **Права.** Что можешь? Явные политики плюс **симуляция** (`iam:SimulatePrincipalPolicy`) плюс **перебор** (`enumerate-iam`). Права приходят и из групп, и из ресурсных политик.
3. **Ресурсы.** Что существует? S3/Storage, EC2/VM, Lambda/Functions, БД, секреты, контейнеры.
4. **Секреты.** Что можно прочитать? Secrets Manager, Parameter Store, Key Vault, env-переменные, бакеты с конфигами.
5. **Пути эскалации.** Как вырасти? `cloudfox`, `pacu privesc scan`, `PMapper`, `Cloudsplaining`.

Ключевая идея: **права — это граф.** Политики ссылаются на роли, роли на сервисы, сервисы на ресурсы. Разведка строит граф, а эскалация — это поиск пути в нём.

## Данные, с которыми работаем

Базовые команды AWS:

```bash
$ aws sts get-caller-identity
{"UserId":"AIDA...","Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/ci-deploy"}
$ aws iam list-attached-user-policies --user-name ci-deploy
```

Мы — IAM-пользователь `ci-deploy`. Уже подсказка: CI-пользователь часто имеет права на деплой и `PassRole`.

`enumerate-iam` перебирает действия, чтобы найти разрешения, которые не видны в явных политиках:

```bash
$ python3 enumerate-iam.py --access-key "$AWS_ACCESS_KEY_ID" \
    --secret-key "$AWS_SECRET_ACCESS_KEY" --session-token "$AWS_SESSION_TOKEN" | tee enum.txt
[+] 47 actions allowed
    iam:CreatePolicyVersion, iam:PassRole, ec2:RunInstances, lambda:UpdateFunctionCode ...
```

## Шаг 1: смотрим явные политики

```bash
$ aws iam list-user-policies --user-name ci-deploy
$ aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/CiDeploy --version-id v3 \
    --query 'PolicyVersion.Document.Statement[].Action'
["iam:CreatePolicyVersion","iam:PassRole","ec2:RunInstances"]
```

Список совпадает с перебором. Обрати внимание на `iam:CreatePolicyVersion` — это классический путь эскалации.

## Шаг 2: обзор аккаунта инструментами

```bash
$ cloudfox aws --profile default permissions
$ cloudfox aws --profile default secrets
$ pacu
> import_keys default
> run iam__enum_permissions
> run iam__privesc_scan
```

`cloudfox` показывает роли, бакеты с секретами и потенциальные эскалации; `pacu iam__privesc_scan` анализирует права и находит известные пути.

## Шаг 3: эксплуатация найденного пути

`iam:CreatePolicyVersion` позволяет перезаписать собственную политику версией с полными правами:

```bash
$ aws iam create-policy-version --policy-arn arn:aws:iam::123456789012:policy/CiDeploy \
    --policy-document file://admin.json --set-as-default
$ aws iam list-users   # теперь работает
```

Мы получили админа.

## Полный прогон от начала до конца

1. `get-caller-identity` → пользователь `ci-deploy`.
2. `list-attached-user-policies` + `enumerate-iam` → `iam:CreatePolicyVersion`, `iam:PassRole`.
3. `cloudfox`/`pacu` → подтверждение пути эскалации.
4. `create-policy-version` с admin-документом → админ.
5. Карта: identity → policies → resources → выбранный путь.

## GCP и Azure: аналоги

**GCP:**

```bash
$ gcloud auth list
$ gcloud projects get-iam-policy my-project --format=json
$ gcloud asset search-all-resources --scope=projects/my-project
```

Инструменты: `gcp_scanner`, `gcpwn`, `ScoutSuite`, `cloudfox gcp`.

**Azure:**

```bash
$ az account show
$ az role assignment list --assignee <object-id> --all -o table
$ az resource list -o table
```

Инструменты: `MicroBurst`, `ROADtools` (Entra ID), `AzureHound` → BloodHound, `cloudfox azure`. Общий принцип один: идентичность → права → ресурсы → секреты → эскалация.

## Если не сработало

- **Начинать с ресурсов, а не с прав.** Без понимания прав не поймёшь, что доступно.
- **Игнорировать группы.** `list-attached-user-policies` не показывает права из групп — используй `enumerate-iam` или `get-account-authorization-details`.
- **Забывать ресурсные политики.** S3 bucket policy, KMS key policy, Secrets resource policy дают доступ независимо от IAM.
- **Считать симуляцию истиной.** `simulate-principal-policy` не учитывает SCP, resource policies и условия.
- **Шуметь.** Массовый перебор триггерит GuardDuty (`Discovery:IAMUser/AnomalousBehavior`).
- **Пропускать регионы.** Ресурсы могут быть в неочевидных регионах; `cloudfox` сканирует все.

## Автоматизация и визуализация

Разведка быстро становится объёмной, поэтому её автоматизируют. **PMapper** строит граф прав и отвечает на вопрос «есть ли путь от X к админу». **AzureHound + BloodHound** делают то же для Entra ID. **Cartography** грузит облако в Neo4j. **Cloudsplaining** ищет опасные политики, **Prowler** проверяет сотни контролей. Практика: собери данные один раз (`aws iam get-account-authorization-details` выгружает всё одним вызовом) и обрабатывай локально.

## Приоритизация: от карты к цели

Разведка даёт карту, но не все пути равны. Оценивай **стоимость** и **заметность** каждого пути. Короткие пути вперёд (сразу к админу — `iam:CreatePolicyVersion` на свою политику, `iam:PassRole` + `ec2:RunInstances`, `roleAssignments/write` в Azure) ценнее длинной цепочки. Тихие пути (чтение секретов) лучше громких (создание пользователей и ключей). Пути к данным и к pivot важнее «ещё одного сервиса». Построй таблицу «путь → требуемые права → результат → заметность» и выбирай по ней; часто самый короткий путь оказывается и самым шумным.

## OPSEC разведки

Разведка — это множество API-вызовов, и она заметна. **GuardDuty** имеет findings `Discovery:IAMUser/AnomalousBehavior` и `Recon:IAMUser/*`, реагирующие на перебор. **CloudTrail** фиксирует каждый вызов с твоим principal. Рекомендации: предпочитай `enumerate-iam` (тише) сотням `describe`; не вызывай `GetAccountAuthorizationDetails` без нужды; ограничивай регионы. Помни, что защита может увидеть разведку и отреагировать — ротацией ключей или блокировкой.

## Практический чек-лист

1. Идентичность: `get-caller-identity`/`auth list`/`account show`.
2. Права: явные политики, группы, роли, boundaries; дополни `enumerate-iam`.
3. Ресурсы: инвентаризация по сервисам (`cloudfox`/`ScoutSuite`).
4. Секреты: Secrets Manager, Parameter Store, Key Vault, бакеты, история развёртываний.
5. Пути эскалации: `pacu privesc scan`, `Cloudsplaining`, `PMapper`.
6. Карта: граф identity→role→resource→secret.
7. Приоритет: кратчайший путь к цели.
8. OPSEC: оцени, что уже залогировано.

Этот чек-лист гарантирует, что ты не пропустишь ни один из пяти вопросов.

## Что мы теперь знаем

- Разведка — пять вопросов: identity, permissions, resources, secrets, privesc paths.
- Права — граф; эскалация — путь в нём.
- `enumerate-iam` находит права из групп, которых нет в явных политиках.
- `cloudfox`/`pacu`/`PMapper`/`Cloudsplaining` автоматизируют обзор и поиск путей.
- Разведка шумная: GuardDuty и CloudTrail фиксируют перебор.

## На что смотреть дальше

- **cloud-privesc-iam**: конкретные пути эскалации IAM.
- **cloud-aws-config**: аудит конфигураций.
- **cloud-logging-detection**: слои детекта, которые заметят разведку.

## Глазами защитника

Разведку ограничивают узкими правами: не давать `*:List*` и `*:Describe*` на весь аккаунт. Включают логирование API-вызовов и следят за всплесками перечисления. GuardDuty и аналоги детектируют поведение, похожее на `enumerate-iam`. Для защитника важно, что разведка почти всегда видна в CloudTrail, поэтому аномальный объём read-вызовов — сигнал.

## Частые вопросы

**Какие пять вопросов облачной разведки?**

Кто я (identity), что мне разрешено (права), что вокруг (ресурсы), что ценно (данные), как эскалировать (пути).

**Как понять свои права без перебора?**

В AWS — `enumerate-iam` и `cloudfox`; в GCP — `gcp-iam-collector`; в Azure — `az rest` по role assignments. Перебор API тоже работает, но шумнее.

**Что такое cloudfox?**

Инструмент, который собирает карту аккаунта: роли, ресурсы, потенциальные пути эскалации. Экономит ручной перебор.

**Почему разведка шумная?**

Каждый API-вызов пишется в логи. Массовые `Describe` и `List` с одной роли — заметный паттерн для GuardDuty.

**Как снизить шум?**

Использовать существующие роли, ограничить частоту, применять известные пути вместо полного перебора, читать конфиги вместо API где можно.

**Что приоритизировать?**

Секреты, бакеты, БД, роли с `PassRole` и `actAs`, затем пути к администраторам.

**Как визуализировать?**

Строить граф связей роль → ресурс → цель; так видны кратчайшие пути эскалации.

**Как защититься?**

Узкие права, детект аномального перечисления, мониторинг GuardDuty, аудит.

## Разбор: от identity к пути эскалации

Атакующий получает временные креды роли. Он запускает `enumerate-iam` и получает список разрешённых действий: `s3:GetObject`, `iam:PassRole`, `ec2:RunInstances`. Комбинация `PassRole` и `RunInstances` — известный путь к эскалации: он запускает EC2 с более мощной ролью и читает её креды. Cloudfox строит этот путь автоматически. Защита — не давать `PassRole` вместе с `RunInstances` и детектировать перечисление.

## Что чаще всего упускают

Шумность: полный перебор API пишется в логи и поднимает GuardDuty. Второе — конфиги вместо API: часть информации (имена бакетов, эндпоинты) можно получить дешевле и тише. Третье — приоритизацию: перечислять всё подряд дороже, чем сразу идти к секретам и путям `PassRole` и `actAs`. Вывод: строй карту по известным путям, а не перебирай вслепую.

**Можно ли разведать аккаунт вообще без API-вызовов?**

Частично: по именам бакетов, DNS, публичным репозиториям и конфигам. Но права и ресурсы обычно требуют API.

**Что делать, если прав мало?**

Искать косвенные пути: роль с `PassRole`, доступ к секретам, возможность создавать ресурсы.

## Квиз

Проверь себя.

```quiz
- question: "С чего начинается облачная разведка?"
  options:
    - "С определения идентичности (кто мы)"
    - "С перебора всех бакетов"
    - "С создания ключей"
    - "С удаления логов"
  answer: 0
  explanation: "Идентичность определяет, как применяются права и что дальше проверять."
- question: "Зачем нужен enumerate-iam?"
  options:
    - "Чтобы перебором выявить разрешённые действия, включая приходящие из групп"
    - "Чтобы создать пользователя"
    - "Чтобы отключить CloudTrail"
    - "Чтобы сменить регион"
  answer: 0
  explanation: "Перебор действий даёт полную картину разрешений, которые не видны в явных политиках."
- question: "Что ищет pacu iam__privesc_scan?"
  options:
    - "Комбинации прав, ведущие к эскалации привилегий"
    - "Открытые порты"
    - "Публичные DNS"
    - "Пароли в коде"
  answer: 0
  explanation: "Модуль анализирует права и находит известные пути эскалации."
- question: "Почему simulate-principal-policy не является истиной?"
  options:
    - "Он не учитывает SCP, resource policies и условия"
    - "Он не работает"
    - "Он требует root"
    - "Он только для S3"
  answer: 0
  explanation: "Симуляция даёт оценку IAM-политик, но не всей модели авторизации."
- question: "Почему права из групп легко пропустить?"
  options:
    - "list-attached-user-policies показывает только прямые политики пользователя"
    - "Группы не существуют"
    - "Они зашифрованы"
    - "Они только для админов"
  answer: 0
  explanation: "Права наследуются из групп, поэтому нужен перебор или get-account-authorization-details."
```

## Куда дальше

В следующем уроке мы разберём **API Gateway** — как шлюз публикует бэкенд и где ошибается в авторизации. А пока главное запомни: **разведка — это граф прав, а не список сервисов; сначала определи, кто ты и что можешь, потом ищи путь.**

## Где пригодится

- **Пентест:** систематическая разведка любого облачного аккаунта.
- **Red team:** поиск кратчайшего пути к цели.
- **Blue team:** аудит прав и детект перебора.
- **Bug bounty:** понимание объёма доступа облачных кредов.
