---
id: cloud-cicd-deep
title: "Модуль: CI/CD глубоко — GitLab, ArgoCD и pwn-requests"
category: cloud
parent: cloud-credential-hunting
difficulty: hard
order: 3
tags: [cloud, gitlab, argocd, github-actions, ci, cd, oidc, module]
prerequisites: [cloud-cicd-secrets]
useful_for:
  - "Атаки на CI/CD-инфраструктуру"
  - "Кража облачных кредов из пайплайнов"
  - "Пентест GitOps-развёртываний"
estimated_minutes: 16
summary: "Подмодуль CI/CD: GitLab CI, ArgoCD и злоупотребление GitHub Actions (pwn requests). Как пайплайны выдают облачные креды и как их перехватить."
---

Этот подмодуль — часть ветки «Основы облака → идентичность, секреты и логи». Он собирает три урока о современных CI/CD-системах, через которые почти всегда проходят облачные креды: GitLab CI, ArgoCD (GitOps) и GitHub Actions.

## Что покрывает подмодуль

1. **GitLab CI** (`cloud-gitlab-ci`) — runners, `.gitlab-ci.yml`, protected variables, маскирование и runner-token.
2. **ArgoCD** (`cloud-argocd`) — GitOps, repo-креды, cluster-доступ, `argocd` CLI и слабые пароли админки.
3. **GitHub Actions: pwn requests** (`cloud-github-actions-pwn`) — `pull_request_target`, `workflow_run`, `issue_comment` и инъекции в выражения.

## Почему такой порядок

GitLab — самый распространённый self-hosted CI в корпорациях: компрометация runner даёт все переменные проекта. ArgoCD идёт вторым: в GitOps-модели он держит доступ к кластеру и репозиториям, что делает его «мастер-ключом». GitHub Actions замыкает модуль: это самая частая точка входа в публичных репозиториях через pwn-requests и инъекции в `${{ }}`.

## Как проходить

- Разбирайте примеры с `gitlab-runner`, `argocd`, `gh` и `act`.
- Обратите внимание на разницу между `pull_request` и `pull_request_target` — это ядро эксплуатации.
- Проверяйте, где именно раскрываются секреты: в логах, в артефактах или в переменных среды.

## Чему вы научитесь

- Извлекать переменные CI и захватывать runner-token GitLab.
- Использовать ArgoCD для доступа к кластеру и репозиториям.
- Эксплуатировать pwn-requests и workflow-injection в GitHub Actions.

## Квиз

```quiz
- question: "Чем опасен pull_request_target в GitHub Actions?"
  options:
    - "Запускается с секретами базовой ветки на PR из форка"
    - "Удаляет репозиторий"
    - "Отключает 2FA"
    - "Меняет OIDC-провайдера"
  answer: 0
  explanation: "В отличие от pull_request, он имеет доступ к секретам и GITHUB_TOKEN с широкими правами."
- question: "Что даёт компрометация ArgoCD?"
  options:
    - "Доступ к репозиториям и кластеру Kubernetes через его креды"
    - "Только чтение логов"
    - "Биллинг"
    - "DNS-записи"
  answer: 0
  explanation: "ArgoCD хранит repo-креды и cluster-конфиги, часто с широкими правами."
- question: "Где GitLab хранит секреты пайплайна?"
  options:
    - "В CI/CD variables проекта/группы (часть — protected/masked)"
    - "В KMS"
    - "В CloudTrail"
    - "В VPC"
  answer: 0
  explanation: "Переменные видны в job'ах; masked скрывают значения в логах, protected — только для protected-веток."
```

## Где пригодится

- **Red team:** кража облачных кредов через CI/CD.
- **Bug bounty:** публичные репозитории с pwn-requests.
- **Пентест инфраструктуры:** захват GitLab/ArgoCD.
- **Supply chain:** компрометация сборки и деплоя.
