---
id: forensics-cloud-devsecops
title: "Модуль: облачный DevSecOps — IaC, секреты, CI/CD"
category: forensics
parent: forensics-cloud
difficulty: hard
order: 4
tags: [cloud, iac, terraform, secrets, cicd, forensics, roadmap]
prerequisites: [forensics-cloud-identity]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Cloud Security"
estimated_minutes: 12
summary: "Этап ветки «облачная форензика»: следы в Infrastructure-as-Code (state Terraform/CloudFormation), менеджерах секретов (Vault/KMS) и CI/CD-пайплайнах."
---

Инфраструктура в облаке описывается **кодом** (IaC), а секреты хранятся в **менеджерах
секретов**. И код, и менеджеры оставляют следы: state-файлы, аудит-логи, историю пайплайнов.
Этот модуль учит расследовать облако через его «стройку» — IaC, секреты и CI/CD.

## Что покрывает этот модуль

- **IaC state** — Terraform/CloudFormation: что разворачивалось и когда.
- **Секреты** — Vault/KMS/Secrets Manager: кто читал секрет.
- **CI/CD** — пайплайны как точка входа и источник артефактов.

## Рекомендуемый порядок изучения

1. `forensics-iac-state` — что описывает инфраструктуру.
2. `forensics-secrets-manager` — кто и когда трогал секреты.
3. `forensics-cicd` — пайплайны как вектор и как улика.

## Что вы будете уметь

- Читать Terraform state и историю CloudFormation.
- Анализировать аудит-логи менеджеров секретов.
- Находить следы в CI/CD-пайплайнах.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Источник |
|----------|--------------------|----------|
| terraform.tfstate | какие ресурсы созданы | backend |
| CloudFormation stack events | история развёртывания | AWS |
| Vault audit log | кто читал секрет | Vault |
| pipeline logs | что запускалось | CI/CD |

## Куда дальше

Открывай урок **«IaC state: terraform.tfstate как улика»** — начнём с описания
инфраструктуры как кода.
