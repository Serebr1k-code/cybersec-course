---
id: cloud-iam-policy-eval
title: "Оценка IAM-политик: boundaries, conditions и confused deputy"
category: cloud
parent: cloud-iam-attack
difficulty: hard
order: 4
tags: [cloud, iam, policy, evaluation, permission-boundary, conditions, confused-deputy]
prerequisites: [cloud-iam-attack, cloud-privesc-iam]
useful_for:
  - "Точное понимание, что разрешено"
  - "Поиск обходов через conditions"
  - "Аудит политик и границ"
estimated_minutes: 50
summary: "Как облако оценивает права: explicit deny, SCP, permission boundaries, session policies, resource policies и conditions. Как читать логику и находить обходы через conditions и confused deputy."
---

## Зачем этот урок

Облачная авторизация — это не просто список разрешений. Это **многослойная логика оценки**: identity-based политики, resource-based политики, permission boundaries, SCP/org policies, session policies и условия (conditions). Непонимание этой логики ведёт к двум ошибкам: вы либо считаете себя ограниченным, когда есть обход, либо уверены в доступе, которого нет. Этот урок — про точную модель оценки IAM, порядок deny/allow, роль условий и типовой класс «confused deputy», который эксплуатирует доверие между сервисами.

## Как облако оценивает права

Базовое правило (AWS и аналоги): **явный Deny > Allow > неявный Deny**. Если действие не разрешено явно — оно запрещено. Поверх identity-политик действуют дополнительные слои:

- **Identity-based policy** — что разрешено принципалу (пользователь, роль).
- **Resource-based policy** — что разрешено на ресурсе (S3 bucket policy, KMS key policy, Lambda resource policy). Может разрешить доступ даже без identity-политики.
- **Permission boundary** — максимум прав identity; пересечение с identity-политикой.
- **SCP / org policy** — граница на уровне организации/OU; не выдаёт прав, только ограничивает.
- **Session policy** — ограничение для конкретной сессии (AssumeRole).
- **Conditions** — уточняют, когда правило действует (`aws:SourceIp`, `aws:PrincipalArn`, `aws:RequestedRegion`, `aws:MultiFactorAuthPresent`, `aws:SourceArn`, `aws:SourceAccount`).

Итоговое право = allow из identity или resource, **пересечённое** со всеми границами (boundary, SCP), минус явные deny, с учётом условий. Ошибка в любом слое меняет результат.

**Confused deputy** — класс проблем, где сервис с привилегиями действует по запросу от менее привилегированного. Защита — условия `aws:SourceArn`/`aws:SourceAccount` (или `ExternalId`) в trust policy. Если их нет, чужой сервис/аккаунт может использовать доверие.

## Инструменты и команды

Симуляция:

```bash
# Что я могу по identity-политике
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::123:role/myrole \
  --action-names s3:GetObject iam:PassRole kms:Decrypt

# Симуляция по контексту (IP, MFA)
aws iam simulate-principal-policy --policy-source-arn <arn> \
  --action-names s3:GetObject \
  --context-entries ContextKeyName=aws:SourceIp,ContextKeyValues=1.2.3.4,ContextKeyType=ip

# Симуляция произвольной политики
aws iam simulate-custom-policy --policy-input-list file://policy.json \
  --action-names s3:GetObject
```

Чтение политик и границ:

```bash
aws iam get-role --role-name myrole --query 'Role.{Trust:AssumeRolePolicyDocument,PermissionsBoundary:PermissionsBoundary}'
aws iam get-account-authorization-details > authz.json
aws iam get-policy-version --policy-arn <arn> --version-id v1 --query 'PolicyVersion.Document'

# Key policy KMS
aws kms get-key-policy --key-id <id> --policy-name default
# Bucket policy
aws s3api get-bucket-policy --bucket mybucket
```

Поиск обходов conditions:

```bash
# Ищем условия, которые можно выполнить
aws iam get-account-authorization-details --query 'Policies[].PolicyVersionList[].Document' | \
  grep -iE 'Condition|aws:SourceIp|aws:PrincipalArn|aws:SourceArn'
```

## Разобранный пример: обход условия и confused deputy

Сценарий: роль `deploy-role` доверяет `codebuild.amazonaws.com`, но без условия `aws:SourceArn`. Политика разрешает `s3:*` при условии `aws:SourceIp` = офисный CIDR.

Шаг 1 — читаем trust policy:

```bash
aws iam get-role --role-name deploy-role --query 'Role.AssumeRolePolicyDocument'
# {"Statement":[{"Effect":"Allow","Principal":{"Service":"codebuild.amazonaws.com"},"Action":"sts:AssumeRole"}]}
```

Условия `aws:SourceArn` нет — это **confused deputy**: любой CodeBuild-проект (в том числе в другом аккаунте, если он может вызвать сервис) может ассумировать роль. Если у вас есть CodeBuild-проект, который может использовать эту роль, вы получаете её права.

Шаг 2 — читаем condition в permissions-политике:

```bash
aws iam get-policy-version --policy-arn <arn> --version-id v1 --query 'PolicyVersion.Document'
# {"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*",
#   "Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}]}
```

Условие — по IP. Обходы: (1) если запрос идёт через VPC endpoint/NAT, `aws:SourceIp` может быть внутренним; (2) некоторые сервисы (например, S3 через VPC endpoint) могут подставлять свой IP; (3) если вы можете запустить ресурс в доверенном CIDR, условие выполняется.

Шаг 3 — проверяем boundary и SCP:

```bash
aws iam get-role --role-name deploy-role --query 'Role.PermissionsBoundary'
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
```

Если boundary ограничивает `s3:*` до конкретных бакетов, а SCP — до регионов, итоговое право уже.

Шаг 4 — симулируем:

```bash
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::123:role/deploy-role \
  --action-names s3:GetObject --resource-arns arn:aws:s3:::target/config
```

Шаг 5 — эксплуатация. Если условие выполнимо (вы в CIDR или через endpoint), получаете доступ. Если confused deputy подтверждён — используйте сервис-триггер.

## Варианты атак и обходы

- **Отсутствие `aws:SourceArn`/`SourceAccount`.** Confused deputy: любой сервис-триггер.
- **Условие по `aws:SourceIp`.** Обходится через VPC endpoints, NAT, запуск ресурса в CIDR, прокси.
- **Условие по `aws:PrincipalArn`.** Проверьте, можно ли создать принципала с подходящим ARN (например, роль с тем же именем в другом пути).
- **Условие по `aws:MultiFactorAuthPresent`.** Иногда обходится через long-term ключи или сервисные сессии.
- **Resource policy поверх identity.** S3 bucket policy может разрешить доступ без identity-allow.
- **Boundary-дыры.** Boundary задаёт максимум, но если он широкий — не помогает.
- **SCP-исключения.** Проекты/аккаунты вне SCP — слабое звено.
- **`iam:PassRole` без условий.** Позволяет передать роль сервису.
- **Wildcard в Resource.** `Resource: "*"` с allow на действие — широкий доступ.

## Частые ошибки и подводные камни

- **Считать simulate истиной.** Он не учитывает SCP, resource policies и часть условий — это оценка, не гарантия.
- **Забывать про resource policies.** Они могут дать доступ вопреки identity-политике.
- **Путать boundary и SCP.** Boundary — на identity; SCP — на аккаунт/OU.
- **Игнорировать условия.** Условие может как ограничивать, так и быть выполнимым.
- **Не проверять deny.** Явный deny перебивает всё; `Deny` в boundary часто останавливает эскалацию.
- **Ошибка в контексте.** `--context-entries` нужны для условий; без них симуляция даст неверный результат.

## Защита и детект

- **Явные условия доверия.** `aws:SourceArn`/`aws:SourceAccount` в trust policies; `ExternalId` для третьих сторон.
- **Permission boundaries** на все роли, создаваемые не-админами.
- **SCP как граница** и deny policies.
- **Минимизируйте wildcard.** Конкретные действия и ресурсы.
- **Регулярный аудит.** `Cloudsplaining`, `PMapper`, `get-account-authorization-details`.
- **Детект.** CloudTrail на `AssumeRole` из неожиданных сервисов, `PutRolePolicy`, `CreatePolicyVersion`, изменения trust policy. GuardDuty `Persistence:IAMUser/*`, `PrivilegeEscalation:IAMUser/*`.
- **Мониторинг confused deputy.** Алерты на AssumeRole сервисными principal из чужих аккаунтов.

## Практические классы ошибок в политиках

Опыт пентеста облака показывает, что большинство обходов IAM сводится к нескольким повторяющимся классам:

1. **Wildcard в Action/Resource.** `"Action":"*"` или `"Resource":"*"` — либо слишком широко, либо позволяет неожиданные действия (`iam:*`, `s3:*`). Даже если кажется, что wildcard «только для чтения», проверяйте, какие действия он покрывает.
2. **Confused deputy.** Trust policy без `aws:SourceArn`/`aws:SourceAccount`/`ExternalId` позволяет другому сервису/аккаунту использовать роль.
3. **Условие, которое легко выполнить.** `aws:SourceIp` (обход через инфраструктуру), `aws:RequestedRegion` (смена региона), `aws:PrincipalTag` (если теги можно ставить).
4. **PassRole без условий.** Позволяет передать роль сервису, который создаёт ресурс от её имени.
5. **Boundary, который ничего не ограничивает.** Широкий boundary = отсутствие boundary.
6. **Resource policy поверх identity.** S3/KMS/Secrets resource policy может дать доступ в обход ожиданий.
7. **Cross-account доверие.** Доверие внешнему аккаунту без условий — путь в чужой аккаунт.
8. **Deny, который не покрывает.** Deny на одно действие при наличии соседнего, дающего тот же эффект (`iam:PutRolePolicy` vs `iam:AttachRolePolicy`).

Зная эти классы, вы быстро сканируете политику и находите слабое место. `Cloudsplaining` и `PMapper` автоматизируют часть, но ручное чтение всё ещё необходимо для условий и контекста.

## Как отличить реальную эскалацию от ложной

Не всякое «широкое» право ведёт к эскалации. Проверяйте три вопроса: (1) **достижимо ли действие** — есть ли у вас ресурс/цель, к которой применимо право; (2) **не блокирует ли граница** — SCP/boundary/deny могут отсечь; (3) **даёт ли результат рост привилегий** — например, `s3:GetObject` на публичный бакет не эскалация, а `iam:CreatePolicyVersion` на свою политику — да. Ложные срабатывания типичны при автоматическом анализе: инструмент помечает «потенциальную эскалацию», но условия или границы делают её невозможной. Поэтому всегда подтверждайте симуляцией и, где безопасно, реальным вызовом на тестовом ресурсе. Это отличает качественный отчёт от «списка от инструмента».

## Типовые ключи условий и их слабости

Условия — самая частая точка обхода. Разберём ключевые:

- **`aws:SourceIp`** — фильтр по IP. Обход: VPC endpoints, NAT, запуск ресурса в доверенном CIDR, прокси. Плюс, если запрос идёт от сервиса AWS, SourceIp может быть внутренним.
- **`aws:PrincipalArn`** — по ARN принципала. Обход: создание принципала с подходящим ARN (например, роли с тем же именем в другом пути) при наличии `iam:CreateRole`.
- **`aws:RequestedRegion`** — ограничение региона. Обход: глобальные сервисы (IAM, S3, Route 53) вне региональных ограничений.
- **`aws:MultiFactorAuthPresent`** — требует MFA. Обход: long-term креды, сервисные сессии, `sts:GetSessionToken` без MFA.
- **`aws:SourceArn`/`aws:SourceAccount`** — защита от confused deputy. Отсутствие этих условий — уязвимость.
- **`aws:PrincipalTag`/`aws:ResourceTag`** — по тегам. Обход: если вы можете ставить теги (`iam:TagRole`, `ec2:CreateTags`).
- **`aws:SecureTransport`** — только HTTPS. Слабое условие, редко помогает.
- **`aws:CurrentTime`/`aws:EpochTime`** — временные окна. Обход: выждать окно.

При анализе политики выписывайте каждое условие и спрашивайте: «могу ли я сделать так, чтобы оно выполнилось?». Часто ответ «да» — и это и есть обход. Если условий нет вовсе — действие доступно всем, кому выдан allow.

## Что дальше / решение

Оценка IAM — это чтение многослойной логики, а не одного списка. Для каждого пути к цели выясните: identity-политики, resource policies, boundary, SCP, session policy и условия. Проверьте условия на выполнимость и ищите confused deputy (отсутствие `SourceArn`). Симуляция — быстрый фильтр, но не финал. Найденный обход эксплуатируйте и документируйте: укажите, какой слой не сработал и почему. Это делает находку убедительной и объясняет, как её закрыть.

## Квиз

```quiz
- question: "Каков приоритет в оценке IAM?"
  options:
    - "Явный Deny > Allow > неявный Deny"
    - "Allow > Deny"
    - "Неявный Deny > Allow"
    - "Нет приоритета"
  answer: 0
  explanation: "Explicit deny всегда побеждает; без allow — неявный запрет."
- question: "Что такое confused deputy?"
  options:
    - "Привилегированный сервис действует по запросу менее привилегированного принципала"
    - "Ошибка в пароле"
    - "Потеря ключа"
    - "Смена региона"
  answer: 0
  explanation: "Защита — условия aws:SourceArn/SourceAccount или ExternalId."
- question: "Чем permission boundary отличается от SCP?"
  options:
    - "Boundary ограничивает identity, SCP — аккаунт/OU"
    - "Это одно и то же"
    - "Boundary выдаёт права"
    - "SCP только для S3"
  answer: 0
  explanation: "Boundary — максимум прав конкретного принципала; SCP — граница организации."
- question: "Почему условие по aws:SourceIp можно обойти?"
  options:
    - "Через VPC endpoints, NAT или запуск ресурса в доверенном CIDR"
    - "Оно не работает"
    - "Оно шифруется"
    - "Оно требует root"
  answer: 0
  explanation: "Источник запроса можно изменить через инфраструктуру."
```

## Где пригодится

- **Пентест:** точное понимание доступов.
- **Red team:** обход conditions и confused deputy.
- **Blue team:** аудит политик и границ.
- **Сертификация:** AWS Security Specialty.
