---
id: cloud-aws-vpc
title: "AWS VPC: security groups, endpoints и сетевая изоляция"
category: cloud
parent: cloud-aws-deep
difficulty: medium
order: 1
tags: [cloud, aws, vpc, security-group, nacl, endpoints, networking]
prerequisites: [cloud-aws-deep, cloud-fundamentals]
useful_for:
  - "Оценка сетевой изоляции AWS-аккаунта"
  - "Поиск открытых из интернета сервисов"
  - "Планирование lateral movement в VPC"
estimated_minutes: 45
summary: "Как читать VPC: подсети, маршруты, security groups, NACL, VPC endpoints и peering. Как находить открытые наружу сервисы и понимать, что достижимо изнутри."
---

## Зачем этот урок

В AWS почти вся сетевая изоляция — это **VPC**: виртуальная сеть с подсетями, таблицами маршрутизации, security groups и NACL. Для пентестера VPC — это карта: она отвечает на два вопроса. Первый — **что открыто из интернета** (то есть куда можно постучаться снаружи). Второй — **что достижимо изнутри** (то есть куда можно пойти, получив первую точку опоры). Без чтения VPC вы будете угадывать, какие порты открыты и куда ведёт lateral movement. Этот урок — про то, как читать VPC-конфигурацию и превращать её в план атаки.

## Как устроена VPC

Иерархия:

- **VPC** — сеть с CIDR-блоком (например, `10.0.0.0/16`).
- **Subnet** — подсеть в одной зоне доступности; бывает public (есть маршрут в Internet Gateway) и private.
- **Route table** — правила маршрутизации: `0.0.0.0/0 → igw` (интернет), `0.0.0.0/0 → nat` (исходящий через NAT), `10.1.0.0/16 → pcx` (peering), `pl-xxxx → vpce` (endpoint).
- **Internet Gateway (IGW)** — вход/выход в интернет для public-подсетей.
- **NAT Gateway** — исходящий интернет для private-подсетей (входящий трафик не проходит).
- **Security Group (SG)** — stateful-фаервол на уровне ENI (инстанса/сервиса). Только allow-правила.
- **Network ACL (NACL)** — stateless-фаервол на уровне подсети. Есть allow и deny, обрабатывается по номерам правил.
- **VPC Endpoint** — приватный доступ к сервисам AWS (S3, DynamoDB, SSM) без выхода в интернет. Бывает Gateway и Interface.
- **Peering / Transit Gateway** — связи между VPC и аккаунтами.

Ключевое отличие SG от NACL: SG **stateful** (ответный трафик разрешён автоматически) и применяется к ресурсу; NACL **stateless** (нужны правила в обе стороны) и применяется к подсети. Эта разница — источник мисконфигов: например, SG разрешает, но NACL блокирует ответ, и соединение не устанавливается.

## Инструменты и команды

Разведка сети:

```bash
# VPC и подсети
aws ec2 describe-vpcs --query 'Vpcs[].{Id:VpcId,Cidr:CidrBlock,Default:IsDefault}'
aws ec2 describe-subnets --query 'Subnets[].{Id:SubnetId,Cidr:CidrBlock,Az:AvailabilityZone,Public:MapPublicIpOnLaunch}'

# Таблицы маршрутов
aws ec2 describe-route-tables \
  --query 'RouteTables[].{Id:RouteTableId,Routes:Routes[].{Dest:DestinationCidrBlock,GW:GatewayId,Target:TransitGatewayId}}'

# Security groups с их правилами
aws ec2 describe-security-groups \
  --query 'SecurityGroups[].{Name:GroupName,Id:GroupId,Ingress:IpPermissions,Egress:IpPermissionsEgress}'

# NACL
aws ec2 describe-network-acls \
  --query 'NetworkAcls[].{Id:NetworkAclId,Subnet:Associations[].SubnetId,Entries:Entries}'

# Endpoints
aws ec2 describe-vpc-endpoints --query 'VpcEndpoints[].{Id:VpcEndpointId,Service:ServiceName,Type:VpcEndpointType}'

# Peering
aws ec2 describe-vpc-peering-connections
```

Поиск открытых из интернета SG:

```bash
aws ec2 describe-security-groups \
  --filters Name=ip-permission.cidr,Values=0.0.0.0/0 \
  --query 'SecurityGroups[].{Name:GroupName,Ports:IpPermissions[].FromPort}'
```

Поиск инстансов с публичным IP:

```bash
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].{Id:InstanceId,IP:PublicIpAddress,SG:SecurityGroups[].GroupId,Subnet:SubnetId}' \
  --output table
```

## Разобранный пример: чтение изоляции аккаунта

Сценарий: у вас есть read-only креды (например, из Cognito). Нужно понять, куда можно постучаться.

Шаг 1 — находим public-подсети и их маршруты:

```bash
aws ec2 describe-subnets --query 'Subnets[?MapPublicIpOnLaunch==`true`].{Id:SubnetId,Cidr:CidrBlock}'
[{"Id":"subnet-0aa","Cidr":"10.0.1.0/24"},{"Id":"subnet-0bb","Cidr":"10.0.2.0/24"}]
```

Шаг 2 — смотрим SG, открытые на `0.0.0.0/0`:

```bash
aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0 \
  --query 'SecurityGroups[].{Name:GroupName,Id:GroupId,Ports:IpPermissions[].FromPort}'
# [{"Name":"web-sg","Id":"sg-111","Ports":[80,443]},
#  {"Name":"legacy-ssh","Id":"sg-222","Ports":[22]}]
```

Шаг 3 — находим инстансы с этими SG и публичными IP:

```bash
aws ec2 describe-instances \
  --filters Name=instance.group-id,Values=sg-222 \
  --query 'Reservations[].Instances[].{Id:InstanceId,IP:PublicIpAddress,State:State.Name}'
```

Шаг 4 — смотрим NACL для подсети инстанса. Даже если SG разрешает 22, NACL может блокировать — тогда порт недостижим:

```bash
aws ec2 describe-network-acls \
  --filters Name=association.subnet-id,Values=subnet-0bb \
  --query 'NetworkAcls[].Entries'
```

Шаг 5 — понимаем внутреннюю достижимость. Private-подсети идут в интернет через NAT, значит исходящий трафик возможен, но входящий — нет. Endpoints для S3/SSM означают, что сервисы внутри обращаются к AWS без интернета. Peering-связи показывают, куда можно двигаться после получения точки опоры.

Итог: карта «открыто наружу» + «достижимо изнутри». Это и есть основа для планирования — например, `sg-222` с 22/tcp на legacy-инстансе может быть входом.

## Варианты атак и обходы

- **`0.0.0.0/0` на чувствительных портах.** SSH/RDP/БД, открытые в интернет, — прямые цели.
- **`MapPublicIpOnLaunch` + public SG.** Автоматически даёт публичный IP новым инстансам — риск для команд, которые «на минутку» поднимают отладку.
- **Security group chaining.** SG может разрешать трафик от другого SG (`source: sg-xxx`); компромисс инстанса с этим SG открывает следующий сегмент.
- **VPC peering как путь.** Если VPC соединены peering, а SG разрешает CIDR соседней VPC, из одного аккаунта можно дойти до другого.
- **NAT instance (не gateway).** Устаревший NAT-инстанс с широким SG может стать точкой входа и pivot.
- **Endpoint policies.** VPC endpoint без policy-ограничения позволяет обратиться к S3/DynamoDB от имени роли; атакующий может использовать его как канал эксфильтрации, даже без интернета.
- **SSH через SSM вместо открытых портов.** Отсутствие 22 в SG не значит «нет доступа» — `ssm:StartSession` даёт shell (`cloud-aws-ssm`).

## Частые ошибки и подводные камни

- **Путать SG и NACL.** SG stateful и на ресурсе; NACL stateless и на подсети. Неверная интерпретация ведёт к ложным выводам.
- **Считать private-подсеть полностью изолированной.** NAT даёт исходящий интернет, а endpoints — доступ к AWS.
- **Забывать про IPv6.** SG с `::/0` — та же открытость, что `0.0.0.0/0`.
- **Игнорировать default VPC.** В default VPC подсети часто public, а default SG может быть настроен нестрого.
- **Не проверять `Describe*`-права.** Без них вы не прочитаете VPC; тогда ориентируйтесь на внешнее сканирование.
- **Ложные «открытые порты».** SG разрешает, но NACL/маршрут блокирует; всегда проверяйте связку.

## Защита и детект

- **Не открывайте 22/3389/3306 в интернет.** Используйте SSM Session Manager или VPN/bastion.
- **Наименьшие SG.** Правило `source: sg-xxx` вместо широких CIDR; отдельные SG на роль сервиса.
- **NACL как второй барьер.** Особенно для БД-подсетей.
- **VPC endpoints с policy.** Ограничивайте endpoint policy конкретными бакетами/таблицами и ролями.
- **Flow Logs.** VPC Flow Logs в CloudWatch/S3 фиксируют принятый и отклонённый трафик — основа для детекта и IR. GuardDuty findings `Recon:EC2/Portscan`, `UnauthorizedAccess:EC2/SSHBruteForce`.
- **AWS Config.** Правила на «SG с 0.0.0.0/0» и «public subnet с чувствительным сервисом».

## IPv6, default VPC и «скрытая» открытость

Две темы, которые чаще всего упускают при чтении сети:

- **IPv6.** Если у подсети есть IPv6 CIDR и маршрут `::/0 → igw`, а SG разрешает `::/0`, то ресурс **открыт в интернет по IPv6**, даже если IPv4-правила строгие. Многие сканеры по умолчанию проверяют только IPv4 и пропускают такие цели. Всегда запрашивайте `Ipv6CidrBlock` и правила с `Ipv6Ranges`.
- **Default VPC.** В новом аккаунте AWS создаёт default VPC с public-подсетями в каждой зоне и default SG. Если default SG не настроен строго, любой запущенный «на пробу» инстанс получает публичный IP и может быть доступен. Default VPC — частый источник находок при оценке свежих/заброшенных аккаунтов.

Проверка:

```bash
# IPv6 у подсетей и SG
aws ec2 describe-subnets --query 'Subnets[].{Id:SubnetId,V6:Ipv6CidrBlockAssociationSet}'
aws ec2 describe-security-groups --filters Name=ip-permission.ipv6-cidr,Values=::/0 \
  --query 'SecurityGroups[].{Name:GroupName,Id:GroupId}'

# Default VPC и её подсети
aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[].VpcId'
```

## Продвинутые пути: peering, Transit Gateway, endpoints

После получения точки опоры внутренняя топология определяет, куда двигаться:

- **VPC Peering.** Прямая связь двух VPC. Если SG разрешает CIDR соседа, вы можете обратиться к его ресурсам. Peering не транзитивен: A↔B и B↔C не дают A↔C автоматически, но B становится хабом.
- **Transit Gateway (TGW).** Центральный маршрутизатор между множеством VPC и on-premises. Если ваша VPC подключена к TGW, вы можете достигать всех остальных участников — при условии, что маршруты и SG разрешают. TGW часто соединяет облако с корпоративной сетью, что делает его мостом в ДЦ.
- **VPC Endpoints.** Interface-endpoint создаёт ENI в вашей подсети с приватным IP сервиса AWS. Если endpoint policy не ограничивает действия, вы можете обращаться к S3/DynamoDB/SSM от имени своей роли из изолированной подсети. Это и удобно для атаки (нет нужды в интернете), и опасно (канал эксфильтрации).
- **Route 53 Resolver / Private Hosted Zones.** Внутренние DNS-имена раскрывают структуру: имена сервисов, окружения (`prod`, `staging`), иногда регионы. `describe-hosted-zones` при наличии прав даёт карту внутренних имён.

Практический подход: после чтения VPC постройте граф «подсеть → SG → ресурс → маршрут → другая подсеть/VPC/on-prem». Именно этот граф, а не список портов, показывает реальные пути lateral movement.

## Что дальше / решение

VPC — это карта, а не цель. После её чтения у вас есть список открытых наружу сервисов (потенциальные входы) и понимание внутренней топологии (пути lateral movement). Дальше: сопоставьте открытые порты с версиями сервисов, проверьте default VPC и legacy-инстансы, поищите peering-связи в другие аккаунты. Если у вас есть RCE на инстансе в private-подсети — используйте NAT для исходящих соединений и VPC endpoints для доступа к AWS. Если есть `ssm:StartSession` — забудьте про открытые порты: SSM даёт доступ внутрь без них. Записывайте карту как network segment и pivot-пути.

## Квиз

```quiz
- question: "Чем security group отличается от NACL?"
  options:
    - "SG stateful и на уровне ресурса, NACL stateless и на уровне подсети"
    - "Это одно и то же"
    - "SG работает только для IPv6"
    - "NACL нельзя менять"
  answer: 0
  explanation: "SG отслеживает соединения и привязан к ENI; NACL stateless и привязан к подсети."
- question: "Что означает маршрут 0.0.0.0/0 → NAT Gateway?"
  options:
    - "Подсеть имеет исходящий интернет, но не входящий"
    - "Подсеть полностью в интернете"
    - "Подсеть изолирована"
    - "Подсеть использует IPv6"
  answer: 0
  explanation: "NAT даёт исходящий трафик; входящий из интернета не проходит."
- question: "Как SG разрешает трафик от другого ресурса, не открывая его всему интернету?"
  options:
    - "Указанием source как security group id"
    - "Указанием 0.0.0.0/0"
    - "Отключением NACL"
    - "Через route table"
  answer: 0
  explanation: "Source: sg-xxx разрешает трафик только от ресурсов с этим SG."
- question: "Почему VPC endpoint без policy опасен?"
  options:
    - "Он позволяет обращаться к сервисам AWS и может служить каналом эксфильтрации"
    - "Он открывает SSH"
    - "Он отключает логи"
    - "Он меняет регион"
  answer: 0
  explanation: "Endpoint без ограничений даёт доступ к S3/DynamoDB из изолированной подсети."
```

## Где пригодится

- **Пентест AWS:** карта периметра и внутренней сети.
- **Red team:** планирование lateral movement.
- **Blue team:** аудит SG/NACL и Flow Logs.
- **Сертификация:** AWS Security Specialty.
