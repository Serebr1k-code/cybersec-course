---
id: cloud-aliyun-deep
title: 'Модуль: Alibaba Cloud (Aliyun) глубоко — RAM, OSS, ECS и роли'
category: cloud
parent: cloud-provider-breadth
difficulty: hard
order: 7
tags: [cloud, aliyun, alibaba, ram, oss, ecs, ack, module]
prerequisites: [cloud-provider-breadth]
useful_for:
  - 'Пентест сред на Alibaba Cloud'
  - 'Разбор утёкших AccessKey'
  - 'CTF cloud'
estimated_minutes: 18
summary: 'Подмодуль об Alibaba Cloud: RAM-политики и роли, OSS-бакеты и публичные политики, ECS-метаданные и захват роли через SSRF, ACK/RRSA. Один сюжет — утёкший AccessKey и путь к роли.'
---

Этот подмодуль углубляет Alibaba Cloud (Aliyun). По духу платформа близка к AWS: IAM называется RAM, объектное хранилище — OSS, виртуальные машины — ECS, Kubernetes — ACK. Поэтому, если вы знаете AWS, здесь меняются только имена, а логика атаки остаётся: креденшел → права → ресурс → эскалация.

## Что покрывает подмодуль

1. **RAM, ресурсы и поверхность атаки** (`cloud-aliyun-basics`) — общая карта Alibaba Cloud и что даёт утёкший AccessKey.
2. **RAM: пользователи, роли, STS и confused deputy** (`cloud-aliyun-ram`) — чтение политик, TrustPolicy и AssumeRole.
3. **OSS: ACL, bucket policy и публичные бакеты** (`cloud-aliyun-oss`) — почему бакет открывается без ключей.
4. **ECS/ACK: метаданные, SSRF и захват роли** (`cloud-aliyun-ecs`) — как SSRF превращается в креды роли.

## Почему такой порядок

Сначала — идентичность и политики (что умеет ключ), затем — данные (что открыто), потом — вычисления и метаданные (где взять роль). Это повторяет реальный путь: ключ → права → данные → захват.

## Как проходить подмодуль

Держите таблицу соответствий: RAM-user≈IAM-user, AccessKey≈access key, OSS≈S3, ECS≈EC2, ACK≈EKS, RRSA≈IRSA. После каждого урока фиксируйте, какой креденшел был входом и какой ресурс — целью.

## Квиз

Проверь себя.

```quiz
- question: "Как называется IAM-система Alibaba Cloud?"
  options:
    - "RAM"
    - "OSS"
    - "ECS"
    - "STS"
  answer: 0
  explanation: "RAM (Resource Access Management) — пользователи, группы, роли и политики Alibaba Cloud."
- question: "Что определяет, кому разрешён AssumeRole в Alibaba?"
  options:
    - "TrustPolicy роли"
    - "ACL бакета"
    - "Регион"
    - "Имя AccessKey"
  answer: 0
  explanation: "Политика доверия роли описывает principal-ов, которым разрешено её взять."
- question: "По какому адресу ECS-инстанс получает метаданные и креды роли?"
  options:
    - "100.100.100.200"
    - "169.254.169.254"
    - "127.0.0.1"
    - "8.8.8.8"
  answer: 0
  explanation: "Служба метаданных Alibaba Cloud доступна по адресу 100.100.100.200."
```

## Куда дальше

После Alibaba логично перейти к провайдерам попроще — IBM Cloud, DigitalOcean, Hetzner, Vultr, где вся защита часто сводится к одному долгоживущему API-токену. А пока главное: в Alibaba ключ — вход, а роль и доверие — то, что превращает вход в эскалацию.

## Где пригодится

- Пентест компаний на Alibaba Cloud.
- Разбор утечек AccessKey из кода и CI.
- CTF-задачи категории cloud.
