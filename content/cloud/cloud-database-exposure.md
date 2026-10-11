---
id: cloud-database-exposure
title: "Открытые управляемые БД: RDS, Cosmos DB, Cloud SQL"
category: cloud
parent: cloud-storage-s3
difficulty: medium
order: 2
tags: [cloud, database, rds, cosmos, cloud-sql, exposure, misconfig]
prerequisites: [cloud-storage-s3, cloud-fundamentals]
useful_for:
  - "Поиск и эксплуатация открытых облачных БД"
  - "Понимание сетевых контролей managed-БД"
  - "Bug bounty: утечки через базы данных"
estimated_minutes: 45
summary: "Как находить публично доступные управляемые базы (RDS, Cosmos DB, Cloud SQL), какие контроли их защищают и как их обходят типовые мисконфиги."
---

Managed-базы (RDS, Cosmos DB, Cloud SQL, Azure SQL) — частый источник утечек. Провайдер даёт сетевые контроли, но по умолчанию их легко настроить неправильно. Урок — про обнаружение, эксплуатацию открытых баз и извлечение данных и кредов.

## Типовые конфигурации-мисконфиги

| БД | Опасная настройка | Последствие |
|----|-------------------|-------------|
| RDS (AWS) | `PubliclyAccessible=true` + SG `0.0.0.0/0` | Прямой доступ из интернета |
| Cosmos DB (Azure) | firewall `0.0.0.0`–`255.255.255.255` или `Allow Azure services` | Широкий доступ |
| Cloud SQL (GCP) | public IP + `0.0.0.0/0` в authorized networks | Прямой доступ |
| Azure SQL | firewall rule `0.0.0.0`–`255.255.255.255` | Широкий доступ |
| Redis/Mongo self-hosted | нет auth, открытый порт | Полный доступ |

## Обнаружение

```bash
# Сканирование диапазонов облаков на порты БД
nmap -Pn -p 3306,5432,1433,27017,6379,5984,9200 --open <CIDR>

# AWS: найти публичные RDS
aws rds describe-db-instances \
  --query "DBInstances[].{ID:DBInstanceIdentifier,Public:PubliclyAccessible,Endpoint:Endpoint.Address}"

# GCP: Cloud SQL с public IP
gcloud sql instances list --format="table(name,ipAddresses[].ipAddress,settings.ipConfiguration)"

# Azure SQL firewall
az sql server firewall-rule list -g <RG> -s <SERVER>
```

Публичные IP managed-баз часто в диапазонах провайдера (`52.x` AWS, `34.x` GCP и т.п.) — сканируйте и сопоставляйте с DNS.

## Разобранный пример: RDS с открытым security group

1. Сканирование находит открытый 5432 (PostgreSQL).
2. Пробуем подключиться и перебрать **небольшой** набор дефолтных кредов (не мега-wordlist):

```bash
psql -h <HOST> -U postgres -c "SELECT version();"
# популярные: postgres/postgres, admin/admin, root/<пусто>
```

3. Если аутентификация настроена на `trust` или пароль слабый — заходим.
4. Перечисляем БД и таблицы:

```sql
\l
\c appdb
\dt
SELECT * FROM users LIMIT 10;
```

5. Дальше — по методологии БД (см. `svc-database`): чтение файлов, RCE через расширения.

## Cosmos DB: ключ доступа

Cosmos DB долго имела проблему с **ключом доступа**: строка подключения даёт полный контроль над базой. Утёкший `AccountKey` в коде/логах = полный доступ к данным:

```bash
# Строка подключения вида
# AccountEndpoint=https://acct.documents.azure.com:443/;AccountKey=BASE64==;
```

Также Cosmos поддерживает **аналитическое хранилище** и **RBAC**, но по умолчанию многие используют master key. Ищите строки подключения в коде, CI и логах:

```bash
grep -rE 'AccountEndpoint=|AccountKey=' . --hidden
```

## Redis/Mongo/Elastic в облаке

Не только managed-БД, но и self-hosted на облачных VM:

```bash
redis-cli -h <HOST> INFO          # открытый Redis
mongo --host <HOST>               # открытый MongoDB
curl http://<HOST>:9200/_cat/indices  # Elasticsearch
```

Открытый Redis/Mongo — классика (см. `svc-database`), и в облаке такие инстансы встречаются регулярно. Redis без auth → RCE через запись webshell/cron.

## Что делать после доступа

Managed-БД — это **хост** в первую очередь:

- OS/версия, права пользователя.
- Данные: пользователи, токены, PII.
- **Креды внутри БД**: строки подключения к другим сервисам, API-ключи.
- Для Postgres — `COPY ... TO PROGRAM` при суперпользователе; для MSSQL — `xp_cmdshell`; для MySQL — UDF.
- Для облачных БД — проверьте роль/идентичность инстанса (иногда у RDS есть доступ к S3 через роль).

```bash
# Пример: у RDS есть IAM-роль -> доступ к S3 через нее
aws rds describe-db-instances --query 'DBInstances[].AssociatedRoles'
```

## Частые ошибки

- **Мега-wordlist по сети.** Онлайн-брут на RTT EV-отрицателен; сначала дефолты и утечки, потом — стоп.
- **Не проверять `PubliclyAccessible` в RDS.** Даже при открытом SG инстанс может быть приватным по флагу.
- **Забыть про SSL-режим.** Некоторые базы отключают SSL и принимают трафик открыто.
- **Игнорировать Cosmos master key.** Часто это единственный нужный секрет.
- **Не смотреть в БД за новыми кредами.** Внутри часто лежат ключи к другим системам.
- **Путать публичный IP и публичный доступ.** IP может быть, а SG — закрывать порт.

## Что дальше / решение

- Нашли открытый порт БД → пробуйте дефолты, затем стоп.
- Нашли строку подключения Cosmos → полный доступ к данным.
- Получили доступ → ищите креды внутри БД и роль инстанса.
- Смежные уроки: `cloud-storage-s3`, `svc-database`, `cloud-privesc-iam`.

## Инструменты и команды обнаружения

```bash
nmap -Pn -p 3306,5432,1433,27017,6379,9200 <target>
nc -nv <target> 6379 <<< "INFO"
redis-cli -h <target> INFO
mongosh --host <target> --eval 'db.adminCommand({listDatabases:1})'
psql "host=<target> user=postgres dbname=postgres"
mysql -h <target> -u root -p''
```

## Cosmos DB: ключ доступа

Cosmos DB имеет primary/secondary key, дающий полный доступ. Ключ часто лежит в App Service/Functions config. Извлечение и использование:

```bash
az cosmosdb keys list --name db --resource-group rg --type keys
# с ключом — доступ к данным через SDK/REST
```

Если у Cosmos включён доступ по ключу, а ключ утёк (или доступен через SSRF) — это полный доступ к базе, включая запись.

## Разобранный пример 2: RDS с открытым SG

1. Security group разрешает `0.0.0.0/0` на 3306.
2. `nmap` подтверждает открытый порт.
3. Подбор слабого пароля (admin/admin, root/root) — малый набор.
4. Вход, `SHOW DATABASES`, поиск PII и хешей.
5. Проверка прав: `SELECT user,host FROM mysql.user`.
6. Проверка на FILE-привилегию → запись файла (UDF → RCE).

## Защита

- Приватные endpoint, security groups с белыми списками.
- IAM-аутентификация вместо паролей.
- Шифрование, ротация секретов.
- Аудит доступа (RDS Enhanced Monitoring, Cosmos diagnostics).

## Практическое задание

Поднимите MySQL в Docker с открытым портом и слабым паролем. Подключитесь, выгрузите данные, проверьте привилегии. Затем ограничьте доступ и убедитесь, что подключение пропало. Это базовый навык работы с открытыми БД.

## Redis/Mongo/Elastic в облаке

Открытые Redis (6379) без пароля дают `CONFIG SET dir`/`dbfilename` → запись файла → RCE. MongoDB (27017) без auth — полный дамп. Elasticsearch (9200) — данные и потенциальный RCE через скрипты. В облаке они часто стоят за security group, но при мисконфиге доступны из интернета. Проверяйте `redis-cli INFO`, `mongosh` и `curl :9200/_cat/indices`.

## Чек-лист работы с открытой БД

1. Подтвердить доступ (баннер, `SELECT 1`, `PING`).
2. Определить тип и версию.
3. Проверить UNAUTH-режим (Redis/Mongo) — вход без пароля.
4. Малый набор default-кред (root/root, admin/admin, postgres/postgres).
5. Перечислить базы, таблицы, найти PII и хеши.
6. Проверить привилегии (FILE, xp_cmdshell, COPY TO PROGRAM).
7. Оценить RCE-путь, зафиксировать доказательства.
8. Не изменять данные без необходимости.

## Проверка UNAUTH и слабых паролей

Сначала проверьте доступ без пароля (Redis `PING`, Mongo `db.runCommand({ping:1})`, Elastic `GET /`). Затем — малый набор default-кред. Никогда не используйте большой словарь онлайн: это EV-отрицательно. Если три попытки не сработали — зафиксируйте «hardened» и переходите дальше. Для RDS проверьте публичную доступность: `nslookup <endpoint>` должен давать приватный IP.

## Быстрая проверка

```bash
nmap -Pn -p 3306,5432,14337,27017,6379,9200 <target>
redis-cli -h <target> PING
mongosh --host <target> --eval 'db.adminCommand({ping:1})'
curl -s http://<target>:9200/_cat/indices
```

UNAUTH-доступ — первая и главная проверка. Затем — малый набор default-кред. Три неудачи → фиксируйте «hardened» и двигайтесь дальше.

## Квиз

```quiz
- question: "Какой флаг RDS делает инстанс доступным из интернета при открытом security group?"
  options:
    - "MultiAZ"
    - "PubliclyAccessible=true"
    - "StorageEncrypted"
    - "DeletionProtection"
  answer: 1
  explanation: "PubliclyAccessible определяет, получит ли инстанс публичный IP."
- question: "Что даёт утёкший AccountKey Cosmos DB?"
  options:
    - "Только чтение метаданных"
    - "Полный доступ к базе данных"
    - "Только биллинг"
    - "Ничего"
  answer: 1
  explanation: "Master key даёт полный контроль над Cosmos DB."
- question: "Какая стратегия перебора кредов правильная для сетевой БД?"
  options:
    - "Мега-wordlist rockyou"
    - "Небольшой набор: дефолты, найденные в утечках, популярные"
    - "Без пароля вообще"
    - "Только брут по SSH"
  answer: 1
  explanation: "Онлайн-брут на RTT неэффективен; сначала дефолты и утечки, затем стоп."
- question: "Почему managed-БД нужно рассматривать как хост?"
  options:
    - "Потому что она виртуальная"
    - "Потому что внутри есть ОС, права, данные и часто новые креды"
    - "Потому что у неё нет ОС"
    - "Потому что она не логируется"
  answer: 1
  explanation: "База — это система с ОС и данными, из которой можно двигаться дальше."
- question: "Где в GCP настраивается список сетей, которым разрешён доступ к Cloud SQL?"
  options:
    - "security group"
    - "authorized networks в ipConfiguration"
    - "Route 53"
    - "IAM role"
  answer: 1
  explanation: "Cloud SQL использует authorized networks в настройках ipConfiguration."
```

## Где пригодится

- **Bug bounty** — открытые БД, утечки данных.
- **Пентест** — оценка сетевой экспозиции managed-сервисов.
- **IR/Blue team** — расследование утечек через базы.
- **DevSecOps** — аудит firewall и public access.
- **Сертификации** — облачные security-сертификаты.
