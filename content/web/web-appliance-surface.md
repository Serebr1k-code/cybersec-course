---
id: web-appliance-surface
title: "Модуль: Appliance и CI/CD"
category: web
parent: web-enterprise-apps
difficulty: medium
order: 2
tags: [web, module, roadmap]
prerequisites: [web-enterprise-apps]
useful_for:
- Пентест периметра.
- Bug bounty.
- Red team.
estimated_minutes: 10
summary: "Ci/cd и scm-поверхности, edge/vpn-appliance и корпоративные appliance-cve"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Appliance и CI/CD»: CI/CD и SCM-поверхности, edge/VPN-appliance и корпоративные appliance-CVE.

- **web-cicd-surfaces** — CI/CD и SCM как поверхность атаки: Gitea, TeamCity, Nexus, Artifactory, ArgoCD.
- **web-edge-appliances** — Edge- и VPN-appliance: F5 BIG-IP, Fortinet, Ivanti.
- **web-appliance-cves** — Корпоративные appliance-CVE: WebLogic, vCenter, Citrix, MOVEit, VPN.

## Почему такой порядок

Appliance и CI/CD часто стоят на периметре и содержат известные CVE — их разбирают отдельно.

## Что вы сможете после этапа

- Сопоставлять appliance с известными CVE.
- Оценивать риск CI/CD-серверов.

## Квиз

Проверь себя.

```quiz
- question: Почему appliance-CVE критичны?
  options:
    - "Устройства на периметре часто не патчатся"
    - "Они быстрые"
    - "Они дешевле"
    - "Они без сети"
  answer: 0
  explanation: Edge-устройства долго остаются уязвимыми.
- question: Чем опасен CI/CD-сервер?
  options:
    - "Исполняет код и хранит секреты"
    - "Шифрует диск"
    - "Логирует DNS"
    - "Сжимает файлы"
  answer: 0
  explanation: В пайплайне живут секреты и права.
- question: Что такое edge-appliance?
  options:
    - "Устройство на границе сети (VPN/балансировщик)"
    - "Формат файла"
    - "СУБД"
    - "Протокол"
  answer: 0
  explanation: Edge-appliance стоит на входе в сеть.
```

## Где пригодится

- Пентест периметра.
- Bug bounty.
- Red team.
