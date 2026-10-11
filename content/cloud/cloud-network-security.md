---
id: cloud-network-security
title: "Облачные сети: security groups, NACL и firewall"
category: cloud
parent: cloud-network-deep
difficulty: medium
order: 1
tags: [cloud, network, security-group, nacl, firewall, isolation, perimeter]
prerequisites: [cloud-network-deep, cloud-aws-vpc]
useful_for:
  - "Оценка сетевой изоляции облака"
  - "Поиск открытых наружу сервисов"
  - "Понимание периметра AWS/GCP/Azure"
estimated_minutes: 45
summary: "Как читать сетевую изоляцию в трёх облаках: security groups, NACL, firewall rules, подсети и маршруты. Как находить сервисы, доступные из интернета, и планировать внутреннее продвижение."
---

## Зачем этот урок

Облачная сеть определяет, что достижимо снаружи и что — изнутри. В AWS это VPC с security groups и NACL; в GCP — VPC с firewall rules и иерархией; в Azure — Virtual Network с Network Security Groups (NSG) и Azure Firewall. Хотя названия разные, задачи одинаковые: найти **сервисы, открытые в интернет**, и понять **внутреннюю топологию** для lateral movement. Этот урок — сквозной: он учит читать сетевую модель любого из трёх облаков и превращать её в карту атаки. Без этого вы будете угадывать, какие порты доступны, вместо того чтобы знать.

## Модель сети в трёх облаках

| Облако | Сеть | Правила уровня ресурса | Правила уровня подсети | Периметр |
|--------|------|------------------------|------------------------|----------|
| AWS | VPC | Security Group (stateful) | NACL (stateless) | IGW/NAT/endpoints |
| GCP | VPC (global) | (нет аналога SG на ресурсе) | Firewall rules (stateful, приоритеты) | Cloud NAT, LB |
| Azure | VNet | NSG на NIC (опц.) | NSG на подсети | Azure Firewall, LB |

Ключевые различия, которые важны для атакующего:

- **AWS:** SG на ресурсе и NACL на подсети; SG stateful, NACL stateless.
- **GCP:** firewall rules применяются к инстансам по тегам/сервисным аккаунтам, а не к подсети; есть **иерархия** (org → folder → project) и приоритеты. `default-allow-*` правила в default-сети — классика.
- **Azure:** NSG на подсети и/или NIC; правила с приоритетом; есть `AzureFirewallSubnet` и service tags.

Во всех трёх облаках есть **правила «по умолчанию»**: AWS default SG может разрешать трафик внутри группы; GCP default network создаёт `default-allow-internal`, `default-allow-ssh`, `default-allow-rdp`, `default-allow-icmp`; Azure создаёт базовые правила `AllowVnetInBound`/`AllowAzureLoadBalancerInBound`/`DenyAllInBound`. Эти дефолты — источник находок.

## Инструменты и команды

AWS:

```bash
aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0
aws ec2 describe-network-acls
aws ec2 describe-route-tables
aws ec2 describe-subnets --query 'Subnets[].{Id:SubnetId,Public:MapPublicIpOnLaunch}'
```

GCP:

```bash
gcloud compute firewall-rules list \
  --format='table(name,direction,sourceRanges.list(),allowed[].map().firewall_rule().list(),targetTags.list())'
gcloud compute networks subnets list --format='table(name,region,ipCidrRange)'
gcloud compute instances list --format='table(name,networkInterfaces[].accessConfigs[].natIP)'
```

Azure:

```bash
az network nsg list --query '[].{Name:name,RG:resourceGroup}'
az network nsg rule list -g myrg --nsg-name mynsg -o table
az network vnet subnet list --vnet-name myvnet -g myrg --query '[].{Name:name,Prefix:addressPrefix,NSG:networkSecurityGroup.id}'
az network public-ip list --query '[].{Name:name,IP:ipAddress}'
```

Поиск «широких» правил:

```bash
# AWS: SG с 0.0.0.0/0 на чувствительных портах
aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0 \
  --query 'SecurityGroups[].{Name:GroupName,Ports:IpPermissions[].FromPort}'

# GCP: firewall с 0.0.0.0/0
gcloud compute firewall-rules list --filter='sourceRanges:0.0.0.0/0' \
  --format='table(name,allowed[].map().firewall_rule().list(),targetTags.list())'

# Azure: NSG-правила Allow с source *
az network nsg rule list -g myrg --nsg-name mynsg \
  --query '[?access==`Allow` && (sourceAddressPrefix==`*` || sourceAddressPrefix==`0.0.0.0/0` || sourceAddressPrefix==`Internet`)].{Name:name,Port:destinationPortRange}'
```

## Разобранный пример: от периметра к внутренним сервисам

Сценарий: read-only креды в AWS. Нужно понять периметр.

Шаг 1 — находим SG с `0.0.0.0/0`:

```bash
aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0 \
  --query 'SecurityGroups[].{Name:GroupName,Id:GroupId,Ports:IpPermissions[].FromPort}'
[{"Name":"web","Id":"sg-1","Ports":[80,443]},
 {"Name":"bastion","Id":"sg-2","Ports":[22]},
 {"Name":"db","Id":"sg-3","Ports":[3306]}]
```

Шаг 2 — находим ресурсы с этими SG и их публичные IP:

```bash
aws ec2 describe-instances --filters Name=instance.group-id,Values=sg-3 \
  --query 'Reservations[].Instances[].{Id:InstanceId,IP:PublicIpAddress,Az:Placement.AvailabilityZone}'
```

Шаг 3 — проверяем NACL для подсети (SG разрешает, но NACL может блокировать):

```bash
aws ec2 describe-network-acls --filters Name=association.subnet-id,Values=subnet-0db \
  --query 'NetworkAcls[].Entries'
```

Шаг 4 — строим маршруты, чтобы понять достижимость и выход в интернет:

```bash
aws ec2 describe-route-tables --query 'RouteTables[].{Id:RouteTableId,Routes:Routes[].{D:DestinationCidrBlock,G:GatewayId,N:NatGatewayId}}'
```

Шаг 5 — итог: список «открыто наружу» (`sg-1:80/443`, `sg-2:22`, `sg-3:3306`) и карта подсетей. Бастион на 22 — вход; БД на 3306 — цель, если она реально в public-подсети (часто нет, но SG это предполагает). Для GCP повторите с `firewall-rules`, для Azure — с NSG.

## Варианты атак и обходы

- **`0.0.0.0/0` на чувствительных портах.** SSH/RDP/БД в интернете — прямые цели.
- **Default network GCP.** `default-allow-ssh`/`default-allow-rdp` с `0.0.0.0/0` открывают доступ к любым инстансам с тегами.
- **GCP target tags.** Правило применяется только к инстансам с тегом; если тег убран/добавлен, доступность меняется. Проверяйте, у каких инстансов есть «широкие» теги.
- **Azure NSG приоритеты.** Правило `Allow` с меньшим номером перекрывает `Deny`; ищите `sourceAddressPrefix: *`.
- **Service tags.** `Internet`/`VirtualNetwork`/`AzureLoadBalancer` — проверяйте, не открывают ли они лишнее.
- **SGs chaining.** Правило `source: sg-x` открывает доступ ресурсам с этим SG; компромисс одного — путь к другому.
- **IPv6.** `::/0` — та же открытость.
- **Отсутствие egress-ограничений.** Если egress открыт, вы можете exfil-ить данные наружу (`cloud-exfiltration`).
- **Flow logs выключены.** Отсутствие логов не мешает атаке, но снижает детект — полезно знать для OPSEC.

## Частые ошибки и подводные камни

- **Путать уровни.** В GCP нет SG на ресурсе; в Azure NSG может быть на подсети и на NIC одновременно.
- **Считать, что «правило есть» = «порт открыт».** Нужны маршрут и отсутствие блокирующего правила.
- **Забывать про приоритеты.** В GCP и Azure порядок/приоритет решает.
- **Игнорировать default-сеть/правила.** В GCP default network часто оставлена включённой.
- **Не проверять egress.** Открытый исходящий трафик = канал эксфильтрации.
- **Пробовать сканировать без прав.** Без `describe`-прав ориентируйтесь на внешнее сканирование (nmap) и не тратьте время на API.

## Защита и детект

- **Закрывайте 22/3389/БД от интернета.** SSM Session Manager (AWS), IAP (GCP), Bastion/Azure Firewall (Azure).
- **Наименьшие правила.** Конкретные CIDR и SG/теги вместо `0.0.0.0/0`.
- **Убирайте default-сеть и default-правила.** Явные сети с явными правилами.
- **Egress-фильтрация.** Ограничивайте исходящий трафик; используйте private endpoints.
- **Детект.** AWS VPC Flow Logs, GCP VPC Flow Logs, Azure NSG Flow Logs/Network Watcher. GuardDuty `Recon:EC2/Portscan`, `UnauthorizedAccess:EC2/SSHBruteForce`. Алерты на новые `0.0.0.0/0` правила, на изменения NSG/firewall.
- **IaC-контроль.** Правила сети — в коде, с ревью; дрейф ловится через Config/Cloud Asset.

## Разведка периметра без прав API

Не всегда есть права `describe`-API. Тогда периметр изучается снаружи, и это тоже методичная работа:

- **Внешнее сканирование.** `nmap -Pn -sV -p- <cidr>` или masscan для широкого диапазона. Осторожно: агрессивное сканирование триггерит GuardDuty/Defender и может быть расценено как шум; согласуйте.
- **DNS-разведка.** Публичные A/AAAA-записи сервисов; CNAME на `*.elb.amazonaws.com`, `*.cloudfront.net`, `*.azurewebsites.net`, `*.run.app` раскрывают облако и тип ресурса.
- **TLS-сертификаты.** SAN-имена из сертификатов (crt.sh) дают список внутренних имён, иногда с указанием среды.
- **ASN и IP-диапазоны.** По ASN провайдера можно понять, какие диапазоны принадлежат организации.
- **Публичные бакеты.** Через перебор имён и `ListBucket`-поведение можно найти открытые хранилища (`cloud-storage-s3`).

Даже без API вы получаете список достижимых сервисов. Сопоставьте его с известными уязвимостями сервисов и найдите вход.

## Практический чек-лист аудита облачной сети

1. Определите провайдера и уровень доступа к API (есть ли `describe`/`list`).
2. Выпишите все подсети/VPC/VNet и отметьте публичные.
3. Найдите правила с `0.0.0.0/0` и `::/0` на чувствительных портах.
4. Проверьте default-сеть и default-правила (GCP особенно).
5. Постройте маршруты: где IGW/NAT/peering/TGW/VNet peering.
6. Найдите ресурсы с публичными IP и их SG/NSG.
7. Проверьте egress: открыт ли исходящий трафик (канал эксфильтрации).
8. Отметьте, включены ли flow logs (детект и OPSEC).

Этот чек-лист даёт полную картину периметра и внутренней топологии за один проход и служит основой для планирования.

## Flow logs: что они говорят защите и что — вам

Flow logs (AWS VPC Flow Logs, GCP VPC Flow Logs, Azure NSG Flow Logs) фиксируют метаданные соединений: source/dest IP, порты, протокол, объём, действие (ACCEPT/REJECT). Они не содержат payload, но позволяют восстановить картину сканирования и lateral movement. Для пентестера это важно по двум причинам: (1) ваши сканы и подключения оставят след, и (2) если flow logs включены и утекают в S3/Storage, где у вас есть доступ, — вы можете читать чужую сетевую активность. Практические детали: AWS пишет flow logs в CloudWatch Logs или S3 (с определённым форматом полей); GCP — в Cloud Logging; Azure — в Storage/Log Analytics. Если flow logs не включены, детект сетевой активности слабый — это, с точки зрения атаки, «слепая зона», но и признак незрелой защиты. При пентесте отметьте в отчёте наличие/отсутствие flow logs: это влияет на обнаруживаемость и на возможность расследования.

## Практический вывод по сетевой безопасности

Сетевая изоляция в облаке — это не одна настройка, а комбинация: правила на ресурсе (SG/NSG), правила на подсети (NACL), маршруты (IGW/NAT/peering), периметры (VPC-SC/PrivateLink) и egress-контроль. Ошибка в любом слое открывает путь. Поэтому аудит всегда идёт сверху вниз: от «что видно из интернета» до «что достижимо из точки опоры». Записывайте результат как граф и периодически сверяйтесь с ним при планировании следующих шагов — он меняется по мере получения новых доступов.

## Что дальше / решение

Сетевая модель — это карта. Сначала найдите открытое наружу, затем постройте внутреннюю топологию: подсети, маршруты, связи (peering, TGW, VNet peering). Сопоставьте открытые порты с сервисами и ищите слабые версии. Если у вас есть точка опоры внутри — используйте egress для выхода и внутренние правила для продвижения. Если прав на API нет — работайте внешним сканированием. Записывайте периметр и внутренние сегменты как находки; они объясняют, как связаны хосты.

## Квиз

```quiz
- question: "Чем SG в AWS отличается от NACL?"
  options:
    - "SG stateful на ресурсе, NACL stateless на подсети"
    - "Это одно и то же"
    - "NACL только в Azure"
    - "SG только для egress"
  answer: 0
  explanation: "SG отслеживает соединения; NACL не отслеживает и требует правил в обе стороны."
- question: "Какие правила GCP по умолчанию создаёт default network?"
  options:
    - "default-allow-internal, default-allow-ssh, default-allow-rdp, default-allow-icmp"
    - "Только deny all"
    - "Только HTTP"
    - "Никаких"
  answer: 0
  explanation: "Default network создаёт набор разрешающих правил, включая SSH/RDP с 0.0.0.0/0."
- question: "Почему Azure NSG приоритет важен?"
  options:
    - "Правило с меньшим номером (выше приоритет) перекрывает остальные"
    - "Приоритет не существует"
    - "Приоритет только для Deny"
    - "Приоритет только для egress"
  answer: 0
  explanation: "NSG обрабатывает правила по приоритету; Allow с меньшим номером побеждает."
- question: "Что даёт открытый egress?"
  options:
    - "Канал для эксфильтрации данных"
    - "Только входящий доступ"
    - "Смену региона"
    - "Шифрование"
  answer: 0
  explanation: "Без ограничения исходящего трафика данные можно вывести наружу."
```

## Где пригодится

- **Пентест:** оценка периметра и внутренней сети облака.
- **Red team:** планирование lateral movement.
- **Blue team:** аудит сетевых правил и flow logs.
- **Сертификации:** AWS Security, Azure AZ-500, GCP Security.
