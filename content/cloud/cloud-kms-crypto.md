---
id: cloud-kms-crypto
title: "KMS и CryptoKey: использование ключей и обход"
category: cloud
parent: cloud-privesc-iam
difficulty: expert
order: 1
tags: [cloud, kms, crypto, key-policy, grants, encryption, decrypt]
prerequisites: [cloud-privesc-iam, cloud-storage-s3]
useful_for:
  - "Использование облачных ключей для расшифровки"
  - "Эскалация через key policies и grants"
  - "Понимание шифрования в облаке"
estimated_minutes: 50
summary: "Как устроены KMS/Key Vault/CryptoKey, key policies и grants, и как использовать чужие ключи как оракул для расшифровки данных, выдавать себе доступ и обходить границы доверия."
---

## Зачем этот урок

Облачное шифрование (KMS в AWS, Key Vault в Azure, Cloud KMS в GCP) защищает данные: диски, бакеты, секреты, БД. Ключи **нельзя экспортировать** (в типичной конфигурации), но их можно **использовать**: расшифровать данные, сгенерировать data key, перешифровать. Для атакующего это означает, что «шифрование» — не барьер, если у вас есть право использовать ключ. Более того, key policies и grants — это модель доступа, которую можно эксплуатировать: выдать себе доступ через `CreateGrant`, обойти границы доверия, использовать ключ как оракул. Этот урок — про устройство KMS и практические приёмы работы с ключами.

## Как устроены KMS и ключи

**AWS KMS:**

- **Customer Managed Key (CMK)** — ключ с key policy (resource-based).
- **Key policy** — кто может использовать/управлять ключом. Обязательно должна разрешать `kms:*` для root аккаунта (иначе ключ «осиротеет»).
- **Grants** — временные разрешения на использование ключа для конкретного принципала.
- **Alias** — имя ключа (`alias/prod-db`).
- **Права:** `kms:Decrypt`, `kms:Encrypt`, `kms:GenerateDataKey`, `kms:ReEncrypt*`, `kms:CreateGrant`, `kms:PutKeyPolicy`, `kms:ScheduleKeyDeletion`, `kms:GetKeyPolicy`.
- **Encryption context** — дополнительные данные, привязанные к шифрованию; без них decrypt не сработает.

**Azure Key Vault / Managed HSM:** ключи с access policies/RBAC (`Crypto User`), операции encrypt/decrypt/sign/wrap.

**GCP Cloud KMS:** keyrings, crypto keys, IAM на уровне keyring/key; `cloudkms.cryptoKeyVersions.useToDecrypt`.

Ключевые идеи для атаки:

- **Ключ — оракул.** `Decrypt` позволяет расшифровать данные, зашифрованные этим ключом, даже без его экспорта.
- **Grants** можно создавать, если есть `kms:CreateGrant` — это выдаёт доступ другим принципалам (или себе, через роль).
- **Key policy** может быть слишком широкой (cross-account, wildcard principal).
- **Encryption context** — если известен, decrypt проходит; часто он предсказуем (имя бакета/таблицы).
- **ScheduleKeyDeletion** — destructive; ключ удаляется, данные становятся недоступны.

## Инструменты и команды

Разведка:

```bash
aws kms list-keys
aws kms list-aliases
aws kms describe-key --key-id <id>
aws kms get-key-policy --key-id <id> --policy-name default
aws kms list-grants --key-id <id>
```

Использование ключа:

```bash
# Расшифровать blob (например, data key или секрет)
aws kms decrypt --ciphertext-blob fileb://cipher.bin \
  --encryption-context purpose=db --output text --query Plaintext | base64 -d

# Сгенерировать data key
aws kms generate-data-key --key-id alias/prod --key-spec AES_256

# Перешифровать
aws kms re-encrypt --ciphertext-blob fileb://cipher.bin \
  --destination-key-id alias/other
```

Выдача доступа через grant:

```bash
aws kms create-grant --key-id <id> --grantee-principal arn:aws:iam::123:role/myrole \
  --operations Decrypt Encrypt GenerateDataKey
```

Azure:

```bash
az keyvault key list --vault-name myvault
az keyvault key decrypt --vault-name myvault --name mykey --algorithm RSA-OAEP --value <base64>
```

GCP:

```bash
gcloud kms keys list --keyring myring --location global
gcloud kms decrypt --key mykey --keyring myring --location global \
  --ciphertext-file cipher.bin --plaintext-file plain.bin
```

## Разобранный пример: расшифровка секрета чужим ключом

Сценарий: у вас есть роль с `kms:Decrypt` на ключ `alias/prod-secrets`, но нет доступа к самому секрету. Секрет зашифрован этим ключом (например, в бакете или в БД).

Шаг 1 — находим ключ и проверяем права:

```bash
aws kms list-aliases --query 'Aliases[?AliasName==`alias/prod-secrets`]'
aws kms describe-key --key-id alias/prod-secrets --query 'KeyMetadata.{Id:KeyId,Enabled:Enabled}'
aws kms list-grants --key-id <id>
```

Шаг 2 — находим зашифрованный blob. Он может быть в S3, в Parameter Store, в переменных окружения приложения. Например:

```bash
aws s3 cp s3://prod-config/secret.enc ./secret.enc
```

Шаг 3 — определяем encryption context. Часто это имя сервиса/бакета; иногда указано в коде приложения. Если контекст неверный, decrypt вернёт `InvalidCiphertextException`.

```bash
aws kms decrypt --ciphertext-blob fileb://secret.enc \
  --encryption-context purpose=config --output text --query Plaintext | base64 -d
```

Шаг 4 — если контекста нет, а decrypt не срабатывает, пробуем варианты контекста (часто `service=s3`, `bucket=...`). Иногда контекст пустой.

Шаг 5 — получив plaintext (например, пароль БД или API-ключ), двигаемся дальше. Ключ-оракул дал данные без экспорта ключа.

Шаг 6 — **эскалация через grant.** Если у вас есть `kms:CreateGrant` на ключ с широкими возможностями, создайте grant для своей роли (или роли, которую вы контролируете) на `Decrypt`/`GenerateDataKey` — это расширяет доступ. Если у вас есть `kms:PutKeyPolicy`, вы можете выдать себе `kms:*` на ключ.

## Варианты атак и обходы

- **Decrypt как оракул.** Расшифровка данных без экспорта ключа.
- **CreateGrant.** Выдача доступа себе/другому принципалу.
- **PutKeyPolicy.** Полный контроль над ключом (если разрешено).
- **Cross-account key policy.** Wildcard principal или доверие внешнему аккаунту.
- **Encryption context bypass.** Контекст часто известен из кода/имени ресурса.
- **ReEncrypt.** Перешифровать чужой blob под свой ключ — если есть доступ к обоим.
- **Data key reuse.** `GenerateDataKey` даёт ключ для шифрования данных; если приложение использует его небезопасно, можно расшифровать.
- **ScheduleKeyDeletion.** Destructive: удаление ключа делает данные нечитаемыми (ransomware-подобный эффект).
- **Azure/GCP аналоги.** `Crypto User`/`useToDecrypt`, доступ через access policy/RBAC.
- **KMS через сервис.** Некоторые сервисы расшифровывают данные за вас (например, Lambda decrypt env) — используйте их как прокси.

## Частые ошибки и подводные камни

- **Считать ключ неприступным.** Право использовать ключ = доступ к данным.
- **Забывать про encryption context.** Без него decrypt не сработает.
- **Путать key policy и IAM.** Key policy — resource-based и обязательна для KMS; IAM-политика дополняет.
- **Игнорировать grants.** Grant может дать доступ в обход key policy.
- **Пробовать экспорт ключа.** CMK не экспортируется; используйте операции.
- **Не проверять регион.** KMS-ключи региональны; data key из другого региона не расшифруется.

## Защита и детект

- **Узкие key policies.** Конкретные принципалы, минимум `kms:*`; запрет wildcard.
- **Ограничьте `CreateGrant`/`PutKeyPolicy`.** Эти права равны контролю над ключом.
- **Encryption context обязателен** и проверяется в политике (`kms:EncryptionContext:...`).
- **Grants с условиями** и сроком жизни.
- **Разделение ключей** по назначению (не один ключ на всё).
- **Детект.** CloudTrail: `Decrypt` (всплеск), `CreateGrant`, `PutKeyPolicy`, `ScheduleKeyDeletion`, `DisableKey`. GuardDuty `CredentialAccess`/`Exfiltration` при аномальном использовании KMS. Алерты на создание grant и изменение key policy.
- **Мониторинг расшифровок.** Аномальный объём `Decrypt` — сигнал эксфильтрации.

## Сравнение KMS в трёх облаках

| Аспект | AWS KMS | Azure Key Vault/HSM | GCP Cloud KMS |
|--------|---------|---------------------|---------------|
| Управление доступом | Key policy + IAM + grants | Access policies / RBAC | IAM на keyring/key |
| Использование | Decrypt/Encrypt/GenerateDataKey | encrypt/decrypt/wrap/unwrap | encrypt/decrypt |
| Экспорт ключа | нет (CMK) | нет (кроме BYOK-сценариев) | нет |
| Делегирование | CreateGrant | роли Crypto User/Officer | IAM-привязки |
| Контекст | encryption context | — | additional authenticated data |
| Удаление | ScheduleKeyDeletion (7–30 дней) | purge (если нет protection) | destroy version |
| Аудит | CloudTrail | Activity Log | Cloud Audit Logs |

Общий принцип един: **право использовать ключ = доступ к данным**. Различаются только названия прав и механизм делегирования (grants vs roles). Поэтому техника переносится: найдите ключ, определите, кто может им пользоваться, найдите зашифрованные данные и контекст, используйте ключ как оракул; при наличии права делегирования — расширьте доступ. В Azure обратите внимание на отдельную плоскость Key Vault (см. `cloud-azure-keyvault`), в GCP — на IAM-привязки на уровне key.

## Практический чек-лист работы с ключами

1. Инвентаризация ключей и алиасов (`list-keys`, `list-aliases`).
2. Для каждого — key policy/resource policy и grants: кто может Decrypt/Encrypt/GenerateDataKey/CreateGrant/PutKeyPolicy.
3. Найдите зашифрованные blob-ы: S3, Parameter Store/Secrets Manager, БД, env приложений, бэкапы.
4. Определите encryption context (из кода, имени ресурса, документации).
5. Проверьте `kms:Decrypt` симуляцией, затем реальным вызовом на тестовом blob.
6. Оцените `CreateGrant`/`PutKeyPolicy` как путь эскалации.
7. Проверьте cross-account доступ в key policy.
8. Оцените destructive-риск (`ScheduleKeyDeletion`) — только для отчёта, не применяйте.
9. Зафиксируйте, какие данные удалось расшифровать.

Этот чек-лист ведёт от ключа к данным и показывает, где модель доступа слаба.

## Итог: ключ — это доступ, а не сейф

Сформулируем главную мысль. Облачный KMS спроектирован так, чтобы **использовать** ключ, не экспортируя его. Это правильно для безопасности (ключ не утечёт), но означает, что любой, у кого есть право на операции, получает доступ к данным. Поэтому при оценке всегда спрашивайте: кто может `Decrypt`/`Encrypt`/`GenerateDataKey`, кто может `CreateGrant`/`PutKeyPolicy`, где лежат зашифрованные данные и известен ли encryption context. Комбинация «право + данные + контекст» = расшифровка. Для эскалации достаточно `CreateGrant` или `PutKeyPolicy`. Для защиты — узкие политики, обязательный контекст, разделение ключей и мониторинг расшифровок.

## Что дальше / решение

KMS — это оракул, а не сейф: если у вас есть право использовать ключ, вы получаете данные. Начните с инвентаризации ключей и прав: `kms:Decrypt`/`GenerateDataKey` для чтения, `CreateGrant`/`PutKeyPolicy` для эскалации. Найдите зашифрованные blob-ы (S3, Parameter Store, БД, env) и попробуйте расшифровать, подобрав encryption context. Через grants можно расширить доступ. Найденные данные (пароли, токены) ведут дальше по цепочке. Записывайте, какие ключи и права использованы, и какие данные получены.

## Квиз

```quiz
- question: "Почему KMS-ключ не защищает данные от того, у кого есть kms:Decrypt?"
  options:
    - "Ключ работает как оракул: расшифровка доступна без экспорта"
    - "Ключ всегда экспортируется"
    - "Decrypt не существует"
    - "Ключ публичный"
  answer: 0
  explanation: "Право Decrypt позволяет расшифровать данные этим ключом."
- question: "Что позволяет сделать kms:CreateGrant?"
  options:
    - "Выдать доступ к ключу другому принципалу"
    - "Экспортировать ключ"
    - "Удалить аккаунт"
    - "Сменить регион"
  answer: 0
  explanation: "Grant выдаёт разрешения на операции с ключом."
- question: "Что нужно для успешного Decrypt помимо прав?"
  options:
    - "Правильный encryption context"
    - "Пароль root"
    - "Публичный IP"
    - "SAS-токен"
  answer: 0
  explanation: "Encryption context должен совпадать с тем, что использовался при шифровании."
- question: "Какое право даёт полный контроль над ключом?"
  options:
    - "kms:PutKeyPolicy"
    - "kms:DescribeKey"
    - "kms:ListKeys"
    - "kms:GetKeyPolicy"
  answer: 0
  explanation: "PutKeyPolicy позволяет изменить key policy и выдать себе любые права."
```

## Где пригодится

- **Пентест:** работа с зашифрованными данными.
- **Red team:** эскалация через grants/key policy.
- **Blue team:** аудит KMS-политик и детект расшифровок.
- **Сертификация:** AWS Security Specialty.
