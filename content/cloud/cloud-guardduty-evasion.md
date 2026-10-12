---
id: cloud-guardduty-evasion
title: "GuardDuty, Defender for Cloud и SCC: evasion и слепые зоны"
category: cloud
parent: cloud-defense-deep
difficulty: expert
order: 1
tags: [cloud, guardduty, defender, scc, detection, evasion, opsec]
prerequisites: [cloud-defense-deep, cloud-cloudtrail-evasion]
useful_for:
  - "Снижение обнаруживаемости облачных атак"
  - "Понимание источников детекта"
  - "Red team OPSEC в облаке"
estimated_minutes: 55
summary: "Как работают облачные детект-сервисы (GuardDuty, Defender for Cloud, Security Command Center), какие источники они используют, где слепые зоны и как снизить заметность, не отключая детект напрямую."
---
## Задача

В `cloud-cloudtrail-evasion` мы разбирали общие слепые зоны. Теперь — про **конкретные детект-сервисы**: AWS GuardDuty, Microsoft Defender for Cloud и GCP Security Command Center (SCC). Задача: понять, **из каких источников** они берут данные, что реально ловят и как снизить заметность, не отключая детект. Разберём на AWS.

## Данные: источники GuardDuty

GuardDuty не «смотрит в ресурсы» напрямую. Он анализирует три потока данных:

- **CloudTrail management events** — вызовы API управления.
- **VPC Flow Logs** — метаданные сетевых соединений (кто с кем, сколько байт).
- **DNS logs** — DNS-запросы из VPC.

Важно: GuardDuty читает эти логи **независимо** от того, включены ли у вас свои flow logs. Он подписывается на потоки AWS. Но если **регион не включён** в GuardDuty или сервис работает вне VPC (например, Lambda в другом контексте), поток может отсутствовать.

Смотрим, включён ли детектор и где:

```
$ aws guardduty list-detectors
[ "abcd1234efgh5678" ]
$ aws guardduty get-detector --detector-id abcd1234efgh5678 \
    --query '{status:Status,findings:FindingPublishingFrequency}'
{ "status": "ENABLED", "findings": "SIX_HOURS" }
```

Один детектор. Проверяем, покрывает ли он все регионы: `list-detectors` возвращает детекторы **только текущего региона**. Если в других регионах детекторов нет — там GuardDuty молчит.

## Пробуем в лоб: что нас выдаёт

GuardDuty строит **baseline** (норму) для каждого принципала и ищет отклонения. Типичные findings:

- `Recon:IAMUser/UserPermissions` — серия `List*`/`Describe*` (разведка прав).
- `UnauthorizedAccess:IAMUser/TorIPCaller` — вызовы с Tor.
- `Exfiltration:S3/ObjectRead.Unusual` — аномальное чтение S3.
- `CredentialAccess:IAMUser/AnomalousBehavior` — нетипичное чтение секретов.

Проверим собственные findings:

```
$ aws guardduty list-findings --detector-id abcd1234efgh5678 --query 'FindingIds' --output text
$ aws guardduty get-findings --detector-id abcd1234efgh5678 --finding-ids <id> \
    --query 'Findings[0].{Type:Type,Region:Region,Severity:Severity}'
{ "Type": "Recon:IAMUser/UserPermissions", "Region": "us-east-1", "Severity": 5.0 }
```

Разведка прав засветилась. Значит, нельзя «перебирать всё подряд» с одного принципала.

## Приём: снижение заметности без отключения

**1. Не перебирать.** Вместо `ListRoles`/`ListUsers`/`DescribeInstances` подряд — точечные вызовы тех прав, что уже есть. Меньше вызовов — меньше отклонений от baseline.

**2. Работать из ожидаемого контекста.** GuardDuty поднимает severity, когда источник — Tor/VPN/новый IP. Если действие идёт из-под уже используемой роли сервиса (Lambda, EC2) в обычном регионе — выглядит как норма.

**3. Двигаться в непокрытых регионах.** Если детектор включён только в `us-east-1`, действия в `af-south-1` не анализируются. Проверка:

```
$ for r in us-east-1 eu-west-1 af-south-1; do
    echo -n "$r: "; aws guardduty list-detectors --region $r --query 'Detectors' --output text; done
us-east-1: abcd1234efgh5678
eu-west-1:
af-south-1:
```

Пусто у `eu-west-1` и `af-south-1` — там GuardDuty не работает.

**4. Минимизировать data-plane шум.** Чтение S3 через один `GetObject` заметно меньше, чем массовый `ListObjects` + скачивание тысяч объектов.

**5. Использовать легитимные каналы.** Разрешения на бэкап/снапшот дают данные «легально» и выглядят как рутина (см. `cloud-exfiltration`).

## Полный прогон: от finding до тихой работы

1. **Проверяем покрытие.** `list-detectors` по регионам → находим непокрытые.
2. **Смотрим свои findings.** `get-findings` → что именно засветилось.
3. **Меняем паттерн.** Точечные вызовы вместо перебора.
4. **Переносим активность.** Работаем в регионе без детектора.
5. **Проверяем снова.** Через некоторое время findings не появляются.

## Defender for Cloud и SCC

Те же принципы, другие источники:

- **Defender for Cloud** (Azure) анализирует Activity Log, сигналы агента VM, Defender for Identity, Defender for Endpoint. Слепые зоны — VM без агента, подписки без Defender-плана, data-plane без diagnostic settings.
- **SCC** (GCP) использует Cloud Audit Logs, Cloud IDS и Security Health Analytics. Слепые зоны — проекты/папки вне SCC, сервисы без включённого логирования.

Проверка покрытия Azure:

```
$ az security pricing list --query '[].{name:name,tier:pricingTier}' -o table
Name                     Tier
VirtualMachines          Free
StorageAccounts          Free
```

`Free` вместо `Standard` означает, что расширенный детект для этого типа ресурсов **не включён**.

## Защита и что ломает атаку (глазами защитника)

- **GuardDuty/Defender/SCC во всех регионах и аккаунтах.**
- **Делегированный админ** для org-wide управления.
- **Авто-реакция** на findings (изоляция учётки/ресурса).
- **Baseline-мониторинг** каждого сервисного принципала.
- **Включённые агенты и планы** на всех ресурсах.

## Если не сработало

- **GuardDuty везде и с авто-реакцией** — уклоняться сложно, нужна легенда.
- **Defender Standard на всех ресурсах** — слепых зон мало.
- **Findings обрабатываются людьми** — активность расследуют.

## Мини-сценарий: finding и его обход

1. **Получаем finding.** `aws guardduty get-findings --detector-id <id> --finding-ids <id>` → `Recon:IAMUser/UserPermissions`, severity 5.
2. **Разбираем причину.** Мы вызывали `ListRoles`, `ListUsers`, `DescribeInstances` подряд с одного принципала — классический паттерн разведки.
3. **Проверяем покрытие.** `for r in us-east-1 af-south-1; do aws guardduty list-detectors --region $r; done` → в `af-south-1` детекторов нет.
4. **Меняем паттерн.** Вместо перебора — только нужные вызовы; меньше отклонений от baseline.
5. **Меняем регион.** Часть работы переносим в непокрытый регион — там GuardDuty не анализирует.
6. **Проверяем результат.** Через время `list-findings` пуст.

Вывод: обход GuardDuty — это про **покрытие** (регион/аккаунт) и **поведение** (паттерн). Отключать сервис не нужно и опасно.

## Разбор: детект ограничен покрытием и нормой

У GuardDuty две границы. Первая — **покрытие**: он включён не везде. Если детектор есть только в `us-east-1`, действия в `eu-west-1` или `af-south-1` не анализируются, хотя CloudTrail туда пишет. Вторая — **baseline**: GuardDuty ловит отклонения от нормы конкретного принципала. Действие, которое для «шумного» сервисного аккаунта обычно, для тихого пользователя — аномалия, и наоборот. Отсюда стратегия: работать в непокрытых регионах и не выходить за рамки типичного поведения роли. Отключать GuardDuty не нужно — это и громко, и обычно блокируется, а результат даёт меньший.

## Что мы теперь знаем

1. GuardDuty питается CloudTrail, VPC Flow Logs и DNS-логами.
2. Он ищет отклонения от baseline, а не только отдельные вызовы.
3. Непокрытые регионы/аккаунты — главная слепая зона.
4. Defender и SCC используют свои источники, но принцип тот же.
5. OPSEC — менять паттерн и не выделяться, а не отключать детект.

## Частые ошибки

- **Детектор только в одном регионе** — остальные не анализируются.
- **Defender/SCC на тарифе Free** — расширенный детект выключен.
- **Нет авто-реакции** — findings копятся без действий.
- **Игнорирование baseline** — аномалия принципала не замечается.
- **Findings без владельца** — никто не разбирает алерты.

## На что смотреть дальше

- Покрытие детекторов по регионам/подпискам/проектам.
- Уровни планов (Free vs Standard).
- Наличие авто-реакции на findings.
- Агенты на VM/контейнерах.
- Наш собственный baseline: сколько вызовов в час норма.

## Быстрая проверка

```bash
for r in us-east-1 eu-west-1 af-south-1; do echo -n "$r: "; aws guardduty list-detectors --region $r --query Detectors --output text; done
aws guardduty get-findings --detector-id <id> --finding-ids <id>
az security pricing list --query '[].{n:name,t:pricingTier}' -o table
```

## Квиз

Проверь себя.

```quiz
- question: "Из каких источников GuardDuty берёт данные?"
  options:
    - "CloudTrail, VPC Flow Logs и DNS-логи"
    - "Только пароли"
    - "Только SSH"
    - "Только S3"
  answer: 0
  explanation: "GuardDuty анализирует эти три потока."
- question: "Что такое baseline для GuardDuty?"
  options:
    - "Норма поведения принципала, от которой ищут отклонения"
    - "Список пользователей"
    - "Набор паролей"
    - "Тип инстанса"
  answer: 0
  explanation: "GuardDuty сравнивает активность с нормой."
- question: "Какая главная слепая зона GuardDuty?"
  options:
    - "Регионы/аккаунты, где детектор не включён"
    - "Отсутствие интернета"
    - "Слишком много логов"
    - "Наличие MFA"
  answer: 0
  explanation: "Без включённого детектора регион не анализируется."
- question: "Что означает pricingTier: Free у Defender for Cloud?"
  options:
    - "Расширенный детект для этого ресурса не включён"
    - "Ресурс удалён"
    - "Ресурс защищён лучше"
    - "Включён MFA"
  answer: 0
  explanation: "Free не даёт расширенных сигналов."
- question: "Как снижать заметность при включённом GuardDuty?"
  options:
    - "Не перебирать права и не выделяться на фоне нормы"
    - "Отключить CloudTrail"
    - "Сменить пароль root"
    - "Удалить findings"
  answer: 0
  explanation: "OPSEC — сливаться с baseline."
```

## Куда дальше

В следующем уроке (`cloud-log-pipeline`) мы разберём сам лог-пайплайн и его целостность: что происходит, если логи подменяют, и как это детектится. А пока главное: детект-сервисы питаются логами — там, где логов нет, детекта тоже нет.

## Где пригодится

- **Red team:** OPSEC при включённом детекте.
- **Blue team:** покрытие регионов и планов.
- **Пентест:** оценка зрелости детекта.
- **Работа/DevSecOps:** делегированный админ, авто-реакция, агенты.
- **Дальше по дереву:** `cloud-cloudtrail-evasion`, `cloud-log-pipeline`.
