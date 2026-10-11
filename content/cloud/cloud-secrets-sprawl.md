---
id: cloud-secrets-sprawl
title: "Разросшиеся секреты: репозитории, логи, артефакты и снапшоты"
category: cloud
parent: cloud-cross-deep
difficulty: medium
order: 1
tags: [cloud, secrets, sprawl, trufflehog, git, logs, artifacts]
prerequisites: [cloud-cross-deep, cloud-credential-hunting]
useful_for:
  - "Поиск утёкших облачных кредов"
  - "Bug bounty: секреты в публичных источниках"
  - "Аудит секретов в организации"
estimated_minutes: 45
summary: "Secrets sprawl: где в облаке утекают секреты — Git-история, логи, артефакты, переменные среды, снапшоты, мобильные приложения. Инструменты поиска и валидации."
---

## Зачем этот урок

«Secrets sprawl» — расползание секретов по всей инфраструктуре: один и тот же AWS-ключ лежит в Git-истории, в логе CI, в переменной среды контейнера, в мобильном приложении и в бэкапе диска. Облачные среды особенно уязвимы, потому что секреты легко «прописать» в переменные и забыть. Для атакующего это самый дешёвый способ получить первые креды: не нужно эксплуатировать уязвимость — нужно найти ключ. Этот урок — про систематический поиск и валидацию утёкших секретов.

## Где утекают секреты

- **Git-история** — коммиты с ключами, удалённые, но оставшиеся в истории.
- **CI-логи** — вывод команд с секретами, незамаскированные переменные.
- **Артефакты** — собранные пакеты, конфиги, `.env`.
- **Переменные среды** — в контейнерах, VM, сервисах.
- **Логи** — приложений, прокси, API-шлюзов.
- **Снапшоты/бэкапы** — диски с кредами.
- **Клиенты** — мобильные/SPA-приложения с ключами.
- **Публичные репозитории и paste-сайты** — утечки.

## Инструменты и команды

```bash
# TruffleHog (поиск и валидация)
trufflehog git https://github.com/org/repo --only-verified
trufflehog filesystem /path --only-verified
trufflehog s3 --bucket company-backups

# gitleaks (по истории)
gitleaks detect --source . --report-format json --report-path leaks.json
gitleaks detect --source . -v

# Поиск в Git-истории вручную
git log -p | grep -iE 'AKIA|aws_secret|password|token' | head
git log --all --oneline -- '**/.env'
git rev-list --all | xargs git grep -I 'AKIA' 2>/dev/null | head

# Проверка AWS-ключа
aws sts get-caller-identity --profile leaked   # если валиден

# Проверка GCP-ключа
gcloud auth activate-service-account --key-file leaked.json && gcloud projects list

# Проверка Azure
az login --service-principal -u <appId> -p <secret> --tenant <tenant>
```

## Разобранный пример: Git-история → AWS-ключ

Сценарий: репозиторий содержит удалённый `.env` в истории.

```bash
git clone https://github.com/org/app && cd app
git log --all --oneline -- '.env'
# a1b2c3d add config
# d4e5f6a remove .env (oops)

git show d4e5f6a^:.env
# AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
# AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Валидируем
AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=wJal... aws sts get-caller-identity
# {"UserId":"AIDA...","Account":"111122223333","Arn":"arn:aws:iam::111122223333:user/dev"}
```

Ключ действует. Дальше — перечислить права, найти S3/RDS/секреты. `trufflehog --only-verified` делает это автоматически: он проверяет ключи и показывает только рабочие.

## Логи и артефакты

```bash
# CI-логи (если есть доступ)
gh run view <run-id> --log | grep -iE 'token|secret|password'

# Артефакты
unzip artifact.zip -d art && grep -rIE 'AKIA|secret|password' art | head

# Переменные среды в k8s
kubectl get pods -o json | jq '.items[].spec.containers[].env[]? | {name,value}'
kubectl get secret -A -o json | jq -r '.items[] | .metadata.namespace + "/" + .metadata.name'
```

Секреты в переменных среды контейнеров видны изнутри пода (`env`) и через API k8s, если есть доступ к секретам.

## Чек-лист атаки

1. Сканировать Git-историю (`gitleaks`, `trufflehog git`).
2. Проверить CI-логи и артефакты.
3. Проверить переменные среды и секреты k8s.
4. Проверить логи приложений/прокси.
5. Проверить снапшоты/бэкапы (см. урок про EBS).
6. Проверить клиентские приложения (JS/APK).
7. Валидировать найденные секреты (sts/gcloud/az).

## Обход защит и edge cases

- **История переписана.** Если сделали `git filter-repo`, старые коммиты могут быть недоступны, но форки/зеркала хранят их.
- **Ротация.** Ключ может быть отозван; `trufflehog --only-verified` отфильтрует мёртвые.
- **Masked secrets.** В логах CI секреты маскируются; ищите незамаскированные (иногда часть значения видна).
- **Encrypted secrets.** В k8s секреты base64, не шифрованы (если нет encryption at rest).
- **Мобильные приложения.** Ключи в APK/IPA; используйте apktool/jadx.

## Частые ошибки и подводные камни

- Сканировать только HEAD, а не всю историю.
- Не валидировать ключи: мёртвые ключи тратят время.
- Игнорировать логи и артефакты.
- Забыть про форки и зеркала репозиториев.
- Путать base64 (k8s secret) с шифрованием.

## Защита и детект

- Pre-commit hooks (gitleaks) для блокировки секретов.
- Ротация и короткий срок жизни кредов; OIDC вместо долгоживущих ключей.
- Секрет-менеджеры (Secrets Manager/Key Vault/Secret Manager) вместо переменных.
- Мониторинг публичных утечек (GitHub secret scanning, trufflehog в CI).
- Шифрование секретов k8s at rest.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — ключи в Git-истории. Второй — секреты в переменных среды. Третий — незамаскированные логи CI. Четвёртый — секреты в артефактах. Пятый — ключи в мобильных приложениях. Все ведут к компрометации аккаунта.

## Практическое задание

1. Создайте репозиторий, закоммитьте `.env`, удалите его и найдите в истории.
2. Прогоните `gitleaks` и `trufflehog` по репозиторию.
3. Создайте «мёртвый» ключ и проверьте, что `--only-verified` его отфильтрует.
4. Извлеките секрет k8s и декодируйте base64.

## Что дальше / решение

Из утечек получаем рабочие креды. Дальше — перечислять права и эскалировать. Зафиксируйте источник (какой файл/лог) в графе — это помогает оценить масштаб утечки. Валидируйте ключи перед использованием, чтобы не тратить время на мёртвые.

## Разобранный пример 2: секреты в мобильном приложении

Мобильные приложения — богатый источник облачных секретов: API-ключи Firebase, AWS Cognito identity pool, статические токены.

```bash
# Распаковываем APK
apktool d app.apk -o app_decoded
grep -rInE 'AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24}' app_decoded/ | head
# app_decoded/res/values/strings.xml: <string name="firebase_api_key">AIzaSyD...</string>
# app_decoded/assets/config.json: {"aws_cognito_pool":"us-east-1:..."}

# Или через jadx (декомпиляция)
jadx -d out app.apk
grep -rInE 'AKIA|api_key|secret|token' out/sources | head
```

Найденный Firebase apiKey + открытые rules дают доступ к базе (см. урок про Firebase). Cognito identity pool с guest-доступом выдаёт AWS-креды без аутентификации. Статический `sk_live_` — платёжный ключ. Мобильные приложения редко защищены обфускацией секретов, поэтому это быстрый путь к первым кредам.

## Секреты в облачных сервисах и IaC

Помимо Git и логов, секреты «расползаются» по облачным сервисам: переменные функций, конфиги приложений, параметры deployment'ов, state Terraform.

```bash
# AWS Lambda: переменные окружения
aws lambda get-function-configuration --function-name app \
  --query 'Environment.Variables'

# AWS SSM Parameter Store: незашифрованные параметры
aws ssm describe-parameters --query 'Parameters[?Type==`String`].Name'
aws ssm get-parameters-by-path --path "/app" --recursive --with-decryption

# Azure App Service: настройки приложения
az webapp config appsettings list --name app --resource-group rg \
  --query '[].{name:name,value:value}'

# GCP Cloud Run: переменные
gcloud run services describe app --region us-central1 --format='value(spec.template.spec.containers[0].env)'

# Kubernetes: secrets
kubectl get secret -A -o json | jq -r '.items[] | .metadata.namespace+"/"+.metadata.name'
```

Переменные окружения функций и сервисов читаются при наличии прав на конфигурацию. Незашифрованные SSM-параметры (`Type: String`, а не `SecureString`) видны шире. Конфиги App Service и Cloud Run часто содержат строки подключения. Kubernetes secrets — base64. Все эти места стоит проверять систематически: секрет, «спрятанный» в переменной среды, ничем не защищён от того, у кого есть права на чтение конфигурации.

## Приоритизация и валидация находок

Секретов будет много, и не все рабочие. Порядок действий: сначала валидируйте самые «влиятельные» типы.

1. **Долгоживущие облачные ключи** (AKIA/ASIA, SA JSON) — проверяйте `sts get-caller-identity`.
2. **Секреты приложений** (JWT signing, Stripe live, SendGrid) — проверяйте через API.
3. **Токены CI/CD** (GitHub PAT, GitLab, runner) — проверяйте scope.
4. **Пароли БД** — проверяйте подключением, но осторожно (шумно).
5. **Сессионные/refresh-токены** — проверяйте срок.

Не тратьте время на мёртвые ключи: `trufflehog --only-verified` делает это автоматически. Для каждого рабочего секрета фиксируйте источник и права — это определяет следующий шаг.

## Квиз

```quiz
- question: "Почему Git-история — источник секретов?"
  options:
    - "Удалённые файлы остаются в старых коммитах"
    - "Git шифрует секреты"
    - "Git публикует ключи автоматически"
    - "История недоступна"
  answer: 0
  explanation: "История хранит все версии файлов, включая удалённые."
- question: "Что делает trufflehog --only-verified?"
  options:
    - "Проверяет ключи и показывает только рабочие"
    - "Шифрует находки"
    - "Удаляет секреты"
    - "Сканирует только HEAD"
  answer: 0
  explanation: "Валидация отсеивает мёртвые креды."
- question: "Чем опасны секреты в переменных среды контейнера?"
  options:
    - "Видны изнутри пода и через API k8s"
    - "Они зашифрованы"
    - "Они недоступны"
    - "Они одноразовые"
  answer: 0
  explanation: "Переменные среды читаются процессом и через API."
- question: "Как хранятся секреты k8s по умолчанию?"
  options:
    - "В base64 (не шифрованы без encryption at rest)"
    - "В KMS"
    - "В HSM"
    - "Зашифрованы AES-256"
  answer: 0
  explanation: "Base64 — это кодирование, не шифрование."
```

## Где пригодится

- **Bug bounty:** утечки в публичных репозиториях.
- **Red team:** первые креды без эксплуатации.
- **Blue team:** secret scanning и ротация.
- **Аудит:** оценка масштаба утечки.
