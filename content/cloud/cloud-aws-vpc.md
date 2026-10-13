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
estimated_minutes: 55
summary: "Как читать VPC: подсети, маршруты, security groups, NACL, VPC endpoints и peering. Как находить открытые наружу сервисы и понимать, что достижимо изнутри."
lab:
  kind: shell
  title: "Практика: security group, открытый в интернет"
  toolset: [core]
  workdir: /home/student/vpc
  files: [task.md, notes.md, describe-security-groups.json]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Ищи в `describe-security-groups.json` правило с `CidrIp: 0.0.0.0/0` на чувствительный порт (22/3389)."
    - "У найденной группы в Tags лежит секрет."
    - "Достань флаг: `grep nto describe-security-groups.json > found.txt`."

---

## Задача

В AWS почти вся сетевая изоляция — это **VPC**: виртуальная сеть с подсетями, маршрутами, security groups и NACL. Для пентестера VPC — это **карта**: она отвечает на два вопроса. Что открыто из интернета (куда постучаться снаружи)? Что достижимо изнутри (куда идти после первой точки опоры)?

Цель урока: имея только read-only креды, построить эту карту и найти реальный вход.

## Данные, с которыми работаем

Разберём иерархию:
- **VPC** — сеть с CIDR (`10.0.0.0/16`);
- **Subnet** — подсеть в одной зоне; public (есть маршрут в Internet Gateway) или private;
- **Route table** — правила: `0.0.0.0/0 → igw` (интернет), `0.0.0.0/0 → nat` (исходящий);
- **Security Group (SG)** — stateful-фаервол на уровне ресурса, только allow;
- **Network ACL (NACL)** — stateless-фаервол на уровне подсети, есть allow и deny.

Наш инструмент — read-only креды и AWS CLI. Начинаем с подсетей:

```bash
$ aws ec2 describe-subnets --query 'Subnets[?MapPublicIpOnLaunch==`true`].{Id:SubnetId,Cidr:CidrBlock}'
[{"Id":"subnet-0aa","Cidr":"10.0.1.0/24"},{"Id":"subnet-0bb","Cidr":"10.0.2.0/24"}]
```

Две public-подсети: их инстансы автоматически получают публичный IP.

## Шаг 1: ищем SG, открытые в интернет

Ключевой запрос — фильтр по правилу `0.0.0.0/0` (весь интернет):

```bash
$ aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0 \
    --query 'SecurityGroups[].{Name:GroupName,Id:GroupId,Ports:IpPermissions[].FromPort}'
[{"Name":"web-sg","Id":"sg-111","Ports":[80,443]},
 {"Name":"legacy-ssh","Id":"sg-222","Ports":[22]}]
```

`web-sg` с 80/443 — нормально. А `legacy-ssh` с портом **22**, открытым всему интернету, — потенциальный вход.

## Шаг 2: находим инстансы с этими SG

```bash
$ aws ec2 describe-instances --filters Name=instance.group-id,Values=sg-222 \
    --query 'Reservations[].Instances[].{Id:InstanceId,IP:PublicIpAddress,State:State.Name}'
[{"Id":"i-0abc123","IP":"203.0.113.44","State":"running"}]
```

Инстанс `i-0abc123` работает и имеет публичный IP `203.0.113.44`. Проверяем снаружи:

```bash
$ nc -vz 203.0.113.44 22
Connection to 203.0.113.44 22 port [tcp/ssh] succeeded!
```

Порт действительно открыт. SG разрешает — но это ещё не всё.

## Шаг 3: проверяем NACL и маршрут

SG **stateful** (ответный трафик разрешён автоматически), а NACL **stateless** — правила нужны в обе стороны. Даже если SG пускает 22, NACL может блокировать:

```bash
$ aws ec2 describe-network-acls --filters Name=association.subnet-id,Values=subnet-0bb \
    --query 'NetworkAcls[].Entries[].{Num:RuleNumber,Cidr:CidrBlock,Action:RuleAction,Egress:Egress}'
[{"Num":100,"Cidr":"0.0.0.0/0","Action":"allow","Egress":false},
 {"Num":100,"Cidr":"0.0.0.0/0","Action":"allow","Egress":true}]
```

NACL разрешает и входящий, и исходящий — не мешает. Вход подтверждён на всех уровнях: маршрут → SG → NACL.

## Полный прогон от начала до конца

1. Нашли public-подсети (`MapPublicIpOnLaunch=true`).
2. Отфильтровали SG с `0.0.0.0/0` → `legacy-ssh` на 22.
3. Нашли инстанс `i-0abc123` с публичным IP.
4. Проверили NACL — не блокирует.
5. Подтвердили открытый SSH снаружи → потенциальный вход.

## Шаг 4: внутренняя достижимость — маршруты и endpoints

Теперь смотрим, что доступно **изнутри** после получения точки опоры. Private-подсети обычно идут в интернет через **NAT Gateway**:

```bash
$ aws ec2 describe-route-tables \
    --query 'RouteTables[].Routes[?DestinationCidrBlock==`0.0.0.0/0`].{Dest:DestinationCidrBlock,GW:GatewayId,NAT:NatGatewayId}'
[{"Dest":"0.0.0.0/0","GW":"igw-0aa"},{"Dest":"0.0.0.0/0","NAT":"nat-0bb"}]
```

Одна подсеть имеет прямой интернет (IGW), другая — только исходящий через NAT (входящий не проходит). Плюс **VPC endpoints** — приватный доступ к сервисам AWS без интернета:

```bash
$ aws ec2 describe-vpc-endpoints --query 'VpcEndpoints[].{Id:VpcEndpointId,Service:ServiceName}'
[{"Id":"vpce-0cc","Service":"com.amazonaws.us-east-1.s3"}]
```

Endpoint на S3 означает: из изолированной подсети можно обращаться к S3. Если его **policy** не ограничивает действия, это и удобно для атаки (нет нужды в интернете), и опасно (канал эксфильтрации).

## Если не сработало: скрытая открытость

- **IPv6.** Если у подсети есть IPv6 CIDR, маршрут `::/0 → igw` и SG разрешает `::/0` — ресурс **открыт в интернет по IPv6**, даже если IPv4-правила строгие. Многие сканеры проверяют только IPv4. Всегда смотри `Ipv6Ranges`:

```bash
$ aws ec2 describe-security-groups --filters Name=ip-permission.ipv6-cidr,Values=::/0 \
    --query 'SecurityGroups[].GroupName'
["ipv6-open-sg"]
```

- **Default VPC.** В новом аккаунте AWS создаёт default VPC с public-подсетями в каждой зоне. Если default SG не настроен строго, любой запущенный «на пробу» инстанс получает публичный IP.
- **Security group chaining.** SG может разрешать трафик от **другого SG** (`source: sg-xxx`) — компромисс инстанса с этим SG открывает следующий сегмент.
- **SSH через SSM вместо открытых портов.** Отсутствие 22 в SG не значит «нет доступа» — `ssm:StartSession` даёт shell без сетевого порта.
- **VPC peering / Transit Gateway.** Peering соединяет VPC напрямую; TGW — центральный маршрутизатор между множеством VPC и on-premises. Если твоя VPC подключена к TGW, ты можешь достигать остальных участников — вплоть до корпоративной сети.

## Частые ошибки и подводные камни

- **Путать SG и NACL.** SG stateful и на ресурсе, NACL stateless и на подсети — неверная трактовка ведёт к ложным выводам.
- **Считать private-подсеть изолированной.** NAT даёт исходящий интернет, а endpoints — доступ к AWS.
- **Забывать про IPv6.** Правило `::/0` — та же открытость, что `0.0.0.0/0`, и её часто не замечают.
- **Игнорировать default VPC.** В ней подсети часто public, а default SG настроен нестрого.
- **Верить списку портов без проверки маршрута.** SG разрешает, но NACL или route table может блокировать — всегда проверяйте связку.

## Что мы теперь знаем

- SG stateful и на ресурсе; NACL stateless и на подсети — их надо читать **вместе**.
- Маршрут `0.0.0.0/0 → igw` = интернет; `→ nat` = только исходящий.
- SG-фильтр `ip-permission.cidr=0.0.0.0/0` находит открытые в интернет порты.
- IPv6 `::/0` — такая же открытость, которую часто пропускают.
- VPC endpoints дают доступ к AWS без интернета — потенциальный канал эксфильтрации.
- `ssm:StartSession` даёт shell без открытых портов; peering/TGW расширяют достижимость.

## На что смотреть дальше

- **aws-cognito**: как из identity pool получить read-only креды для такой разведки.
- **aws-ssm**: Session Manager как путь внутрь без открытых портов.
- **cloud-network-security**: сетевые барьеры других облаков и их обход.

## Шаг 5: SG-to-SG — путь к внутреннему сегменту

Открытый порт в интернет — не единственная находка. Security group может разрешать трафик
**от другого SG** (`source: sg-xxx`) — тогда инстанс закрыт снаружи, но доступен любому
ресурсу с этим SG. Это ступенька lateral movement: скомпрометировав один узел, ты идёшь к
следующему, который снаружи вообще не виден.

Ищем такие правила:

```bash
$ aws ec2 describe-security-groups \
    --query 'SecurityGroups[?length(IpPermissions[?UserIdGroupPairs[0].GroupId!=null])>`0`].{Name:GroupName,From:IpPermissions[].UserIdGroupPairs[].GroupId}'
[{"Name":"db-sg","From":["sg-111"]}]
```

Здесь `db-sg` (база) пускает только `sg-111` (веб-сервер). Веб-сервер доступен из интернета —
значит, путь такой: интернет → `sg-111` → `db-sg`. Прямого «открытого порта в базу» нет, но
цепочка его заменяет. Чтобы понять, куда идти, читай `IpPermissions` каждого SG целиком, а не
только фильтр `0.0.0.0/0`.

## Таблица: где искать открытость (шпаргалка)

| Что проверяем | Запрос AWS CLI |
|---|---|
| Public-подсети | `describe-subnets --filters Name=MapPublicIpOnLaunch,Values=true` |
| SG, открытые наружу (IPv4) | `describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0` |
| SG, открытые наружу (IPv6) | `describe-security-groups --filters Name=ip-permission.ipv6-cidr,Values=::/0` |
| SG-to-SG цепочки | `describe-security-groups` → смотри `UserIdGroupPairs` |
| Маршруты в интернет | `describe-route-tables` → `DestinationCidrBlock=0.0.0.0/0` |
| NACL-блокировки | `describe-network-acls` → `Entries[].RuleAction=deny` |
| Endpoints к AWS | `describe-vpc-endpoints` |
| Peering / Transit Gateway | `describe-vpc-peering-connections`, `describe-transit-gateway-attachments` |

Держи эту таблицу под рукой: это базовый набор команд для построения карты VPC за пару минут.

## Защита: чек-лист сетевой гигиены

- **Не открывать 22/3389 в `0.0.0.0/0`.** Для админ-доступа использовать SSM Session Manager.
- **Закрывать IPv6-правила так же строго, как IPv4.** `::/0` — такая же открытость.
- **Правила «SG → SG» делать узкими:** конкретный порт, а не «всё».
- **Default SG менять:** запрещать весь трафик, кроме явно нужного.
- **VPC endpoints ограничивать policy:** привязывать к конкретному бакету/таблице и роли.
- **Включить Flow Logs** (логи сетевого трафика) — они покажут, что реально ходило, а не только что разрешено.
- **Аудит peering/TGW:** каждое подключение расширяет достижимость, его нужно осознанно одобрять.

Правило простое: сеть в AWS безопасна не тогда, когда «SG настроен», а когда **каждый уровень
— маршрут, SG, NACL, endpoint — согласованно закрыт**, и ты это проверил, а не предположил.

## Квиз

Проверь себя.

```quiz
- question: "Чем security group отличается от NACL?"
  options:
    - "SG stateful и на уровне ресурса, NACL stateless и на уровне подсети"
    - "Это одно и то же"
    - "SG работает только для IPv6"
    - "NACL нельзя изменять"
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
- question: "Почему IPv6-правило ::/0 часто упускают?"
  options:
    - "Сканеры по умолчанию проверяют только IPv4, а ресурс может быть открыт по IPv6"
    - "IPv6 не используется в AWS"
    - "Оно всегда закрыто"
    - "Оно относится к NACL"
  answer: 0
  explanation: "Ресурс открыт по IPv6, даже если IPv4-правила строгие; это легко пропустить."
```

## Куда дальше

В следующем уроке мы разберём **Cognito** — как из identity pool получить временные креды, которыми и делается такая разведка VPC. А пока главное запомни: **VPC — это карта**, и настоящий вход находится там, где сходятся маршрут, SG и NACL, а не там, где просто «открыт порт».

## Где пригодится

- **Пентест AWS:** карта периметра и внутренней сети.
- **Red team:** планирование lateral movement.
- **Blue team:** аудит SG/NACL и Flow Logs.
- **Сертификация:** AWS Security Specialty.
