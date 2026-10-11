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
---

## Зачем этот урок

Когда у вас появляются облачные креды, самое важное — не начать случайно «тыкать» API, а провести **систематическую разведку**. В облаке права определяют всё: что вы видите, что можете читать, куда можете двигаться. Без карты прав вы либо пропустите путь эскалации, либо наделаете шума. Облачная разведка — это дисциплина: определить, **кто вы**, **что можете**, **что существует**, **где секреты** и **какие есть пути привилегий**. Этот урок — про методику и инструменты, которые её автоматизируют: `enumerate-iam`, `cloudfox`, `pacu`, `ScoutSuite`, `Prowler`, `Cloudsplaining`, `PMapper`.

## Что такое облачная разведка

Разведка делится на пять вопросов:

1. **Идентичность.** Кто вы? `aws sts get-caller-identity` / `gcloud auth list` / `az account show`. Тип принципала (пользователь, роль, federated, service account) определяет, как права применяются.
2. **Права.** Что вы можете? Явные политики (`get-user-policy`, `list-attached-user-policies`, `get-role`) плюс **симуляция** (`iam:SimulatePrincipalPolicy`) плюс **перебор** (`enumerate-iam`). Ресурсные политики тоже важны.
3. **Ресурсы.** Что существует? S3/Storage, EC2/VM, Lambda/Functions, БД, секреты, контейнеры. Инвентаризация через `describe`/`list` или `cloudfox`/`ScoutSuite`.
4. **Секреты.** Что можно прочитать? Secrets Manager, Parameter Store, Key Vault, env-переменные, бакеты с конфигами.
5. **Пути эскалации.** Как вырасти? `cloudfox`, `pacu privesc scan`, `PMapper`, `Cloudsplaining` находят комбинации прав, ведущие к админу.

Ключевая идея: **права — это граф**. Политики ссылаются на роли, роли на сервисы, сервисы на ресурсы. Разведка строит этот граф, а эскалация — это поиск пути в нём.

## Инструменты и команды

Базовые команды AWS:

```bash
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name alice
aws iam list-user-policies --user-name alice
aws iam get-policy-version --policy-arn <arn> --version-id v1
aws iam list-roles --query 'Roles[].{Name:RoleName,Arn:Arn}'

# Симуляция: могу ли я выполнить действие?
aws iam simulate-principal-policy --policy-source-arn <my-arn> \
  --action-names s3:GetObject iam:PassRole ec2:RunInstances
```

`enumerate-iam` — перебор действий:

```bash
python3 enumerate-iam.py --access-key ASIA... --secret-key ... --session-token ...
# Печатает список разрешённых действий и сервисов
```

`cloudfox` — быстрый обзор аккаунта:

```bash
cloudfox aws --profile default all-checks
cloudfox aws --profile default permissions
cloudfox aws --profile default endpoints
cloudfox aws --profile default secrets
```

`pacu` — фреймворк:

```bash
pacu
> import_keys default
> run iam__enum_permissions
> run iam__privesc_scan
> run aws__enum_account
```

`ScoutSuite` / `Prowler` — аудит:

```bash
scout aws --profile default
prowler aws -M json-ocsf -o /tmp/prowler
```

## Разобранный пример: от ключа к карте прав

Сценарий: получены AWS-креды (например, из Cognito). Проводим разведку.

Шаг 1 — кто мы:

```bash
aws sts get-caller-identity
{"UserId":"AIDA...","Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/ci-deploy"}
```

Это IAM-пользователь `ci-deploy`. Уже подсказка: CI-пользователь часто имеет права на деплой и PassRole.

Шаг 2 — явные политики:

```bash
aws iam list-attached-user-policies --user-name ci-deploy
aws iam list-user-policies --user-name ci-deploy
aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/CiDeploy --version-id v3 \
  --query 'PolicyVersion.Document'
```

Шаг 3 — перебор, чтобы найти неявные разрешения (включая из групп):

```bash
python3 enumerate-iam.py --access-key "$AWS_ACCESS_KEY_ID" \
  --secret-key "$AWS_SECRET_ACCESS_KEY" --session-token "$AWS_SESSION_TOKEN" | tee enum.txt
grep -iE 'iam:|sts:|lambda:|s3:' enum.txt | head
```

Шаг 4 — `cloudfox` для обзора:

```bash
cloudfox aws --profile default permissions
cloudfox aws --profile default secrets
# Показывает роли, бакеты с секретами, потенциальные эскалации
```

Шаг 5 — `pacu iam__privesc_scan` анализирует права и находит известные пути эскалации (например, `iam:CreatePolicyVersion`, `iam:PassRole`+`ec2:RunInstances`, `iam:CreateAccessKey`).

Шаг 6 — эксплуатация найденного пути. Например, `iam:CreatePolicyVersion` на политику с правами админа:

```bash
aws iam create-policy-version --policy-arn arn:aws:iam::123456789012:policy/CiDeploy \
  --policy-document file://admin.json --set-as-default
```

Шаг 7 — записываем карту: identity → policies → найденные ресурсы → выбранный путь эскалации.

## GCP и Azure: аналоги

**GCP:**

```bash
gcloud auth list
gcloud projects list
gcloud projects get-iam-policy my-project --format=json
gcloud iam service-accounts list
# Asset inventory для широкого обзора
gcloud asset search-all-resources --scope=projects/my-project
gcloud asset search-all-iam-policies --scope=projects/my-project
```

Инструменты: `gcp_scanner`, `gcpwn`, `ScoutSuite` (gcp), `cloudfox gcp`.

**Azure:**

```bash
az account show
az role assignment list --assignee <object-id> --all -o table
az resource list -o table
az keyvault list
```

Инструменты: `MicroBurst`, `ROADtools` (Entra ID), `AzureHound` → BloodHound, `ScoutSuite` (azure), `cloudfox azure`.

Общий принцип одинаков: идентичность → права → ресурсы → секреты → эскалация.

## Частые ошибки и подводные камни

- **Начинать с ресурсов, а не с прав.** Без понимания прав вы не поймёте, что доступно.
- **Игнорировать группы.** Права приходят из групп и ролей; `list-attached-user-policies` показывает не всё — используйте `enumerate-iam` или `get-account-authorization-details`.
- **Забывать ресурсные политики.** S3 bucket policy, KMS key policy, Secrets resource policy могут давать доступ независимо от IAM.
- **Считать симуляцию истиной.** `simulate-principal-policy` не учитывает SCP, resource policies и условия — это оценка, не гарантия.
- **Шуметь.** Массовый перебор API триггерит GuardDuty (`Discovery:IAMUser/AnomalousBehavior`) и CloudTrail. Для OPSEC комбинируйте `enumerate-iam` (тише) с точечными проверками.
- **Пропускать регионы.** Ресурсы могут быть в неочевидных регионах; `cloudfox` сканирует все.
- **Не документировать.** Карта прав — главный результат разведки; без неё вы повторите работу.

## Защита и детект

- **Минимальные права.** Регулярный аудит: кто что может; `Cloudsplaining` находит опасные политики.
- **Permission boundaries.** Ограничивают максимум прав роли.
- **Детект.** CloudTrail: всплеск `List*`/`Get*`/`Describe*` от одного принципала. GuardDuty: `Discovery:IAMUser/*`, `Recon:IAMUser/*`. Алерты на `SimulatePrincipalPolicy`, `GetAccountAuthorizationDetails`, на перебор.
- **SCP и deny policies** как границы.
- **Мониторинг доступа к секретам** (Secrets Manager/Parameter Store/Key Vault).

## Автоматизация, визуализация и отчёты

Разведка облака быстро становится объёмной, поэтому её автоматизируют и визуализируют:

- **Визуализация графа.** `PMapper` (AWS) строит граф прав и отвечает на вопрос «есть ли путь от X к админу». `AzureHound` + BloodHound делают то же для Entra ID/Azure. `Cartography` загружает облако в Neo4j для произвольных запросов.
- **Аудит конфигураций.** `ScoutSuite` собирает мульти-облачный отчёт, `Prowler` проверяет сотни контролей, `Steampipe` позволяет запрашивать облако SQL-ом.
- **Анализ политик.** `Cloudsplaining` (AWS) ищет опасные политики и «least privilege» нарушения, `Policy Sentry` генерирует минимальные политики.
- **Фреймворк.** `pacu` — интерактивная среда с модулями `enum`, `privesc`, `exfil`, `persistence`. Полезен для повторяемых операций.

Практика: соберите данные один раз (JSON), затем обрабатывайте локально. Например, `aws iam get-account-authorization-details` выгружает все политики, роли и группы одним вызовом — из него можно построить карту без сотен запросов. Для GCP аналог — `gcloud asset` экспорт; для Azure — `az graph query` (Azure Resource Graph) для быстрого перечисления ресурсов.

## OPSEC разведки

Разведка — это множество API-вызовов, и она заметна:

- **GuardDuty** имеет findings `Discovery:IAMUser/AnomalousBehavior` и `Recon:IAMUser/*`, реагирующие на перебор.
- **CloudTrail** фиксирует каждый вызов с вашим principal; аномальные `List*`/`Get*` от одного пользователя — сигнал.
- **CloudWatch/Alerting** может иметь правила на `GetAccountAuthorizationDetails` (громкий вызов).
- **Рекомендации:** предпочитайте `enumerate-iam` (имитирует ошибки доступа, тише) вместо сотен `describe`; не вызывайте `GetAccountAuthorizationDetails` без нужды; работайте в часы низкой активности, если это согласовано; ограничивайте регионы.

Для пентеста важнее полнота картины, но помните, что защита может увидеть разведку и отреагировать (ротация ключей, блокировка).

## Практический чек-лист облачной разведки

1. Идентичность: `get-caller-identity`/`auth list`/`account show`; определите тип принципала.
2. Права: явные политики, группы, роли, permission boundaries; дополните `enumerate-iam`.
3. Ресурсы: инвентаризация по сервисам; используйте `cloudfox`/`ScoutSuite` для обзора.
4. Секреты: Secrets Manager, Parameter Store, Key Vault, бакеты, env, history развёртываний.
5. Пути эскалации: `pacu privesc scan`, `Cloudsplaining`, `PMapper`.
6. Карта: постройте граф identity→role→resource→secret.
7. Приоритет: выберите кратчайший путь к цели.
8. OPSEC: оцените, что уже залогировано, и не усугубляйте.

Этот чек-лист превращает разведку в повторяемый процесс и гарантирует, что вы не пропустите ни один из пяти вопросов.

## Приоритизация: от карты к цели

Разведка даёт карту, но не все пути равны. Приоритизация — это оценка **стоимости** и **заметности** каждого пути к цели:

- **Короткие пути вперёд.** Путь, который сразу даёт админа (`iam:CreatePolicyVersion` на собственную политику, `iam:PassRole` + `ec2:RunInstances`, `roleAssignments/write` в Azure), ценнее длинной цепочки из пяти шагов.
- **Тихие пути.** Чтение секретов тише, чем создание пользователей/ключей. Создание сущностей (`CreateUser`, `CreateAccessKey`, `CreateServiceAccountKey`) — громкие события, их легко алертить.
- **Пути, ведущие к данным.** Если цель — данные, приоритет у доступов к БД/Storage/секретам, а не к «ещё одному сервису».
- **Пути к pivot.** Доступ к CI, к management account, к сети с более слабой защитой — мост к новым сегментам.
- **Временные ограничения.** Временные креды истекают; используйте их для разведки, а персистентность стройте осознанно.

Практический приём: постройте таблицу «путь → требуемые права → результат → заметность» и выбирайте по ней. Часто самый короткий путь оказывается и самым шумным; тогда权衡: для пентеста важен воспроизводимый результат, но для red team — ещё и незаметность. Документируйте выбор и его обоснование: это отличает системную работу от перебора.

## Что дальше / решение

Разведка — первый шаг после получения кредов, и она определяет всё дальнейшее. Пройдите пять вопросов: identity, permissions, resources, secrets, privesc paths. Используйте `enumerate-iam` для полноты прав, `cloudfox` для обзора, `pacu iam__privesc_scan`/`Cloudsplaining`/`PMapper` для путей эскалации. Задокументируйте карту и выберите самый короткий путь к цели. Если путь требует ресурса, которого нет, — вернитесь к разведке: вы что-то пропустили. Записывайте найденные пути как attack steps и держите OPSEC в уме.

## Квиз

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
```

## Где пригодится

- **Пентест:** систематическая разведка любого облачного аккаунта.
- **Red team:** поиск кратчайшего пути к цели.
- **Blue team:** аудит прав и детект перебора.
- **Bug bounty:** понимание объёма доступа облачных кредов.
