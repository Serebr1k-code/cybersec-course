# content/cloud — Gap Analysis (SECOND INDEPENDENT PASS, pass B)

Inventory: 123 md files (105 content lessons + 18 module/hub pages).
Verdict: **STRONG** on AWS/Azure/GCP core, K8s, CI/CD, identity, SSRF, IR.
Large advanced frontier remains: provider breadth (OCI/Alibaba/IBM/Cloudflare/DO),
SaaS identity (Okta/M365/Workspace/SAML/OAuth/MFA/PRT), deep per-provider service
surfaces (Azure data/AI/network/Governance, AWS analytics/AI/IoT/billing, GCP data/AI/network),
service mesh + CNI, container runtimes beyond runc, IaC beyond Terraform/Bicep/CFN,
CI/CD beyond GH/GitLab/Jenkins/ArgoCD, and emerging (confidential computing, AI/LLM in cloud).

One bullet per MISSING lesson: `- <proposed-id> — <short title>`.

## Provider breadth — non-big-3 clouds (entirely missing)
- cloud-oci-basics — Oracle Cloud (OCI): compartments, tenancy, IAM, поверхность атаки
- cloud-oci-iam — OCI IAM: policies, dynamic groups, instance principals и эскалация
- cloud-oci-object-storage — OCI Object Storage: pre-authenticated requests и мисконфиги
- cloud-oci-vcn — OCI VCN: security lists, NSG, gateways и сетевая изоляция
- cloud-oci-functions — OCI Functions и API Gateway: инъекции и захват resource principal
- cloud-aliyun-basics — Alibaba Cloud (Aliyun): RAM, ресурсы и поверхность атаки
- cloud-aliyun-ram — Alibaba RAM: пользователи, роли, STS и confused deputy
- cloud-aliyun-oss — Alibaba OSS: ACL, bucket policy и публичные бакеты
- cloud-aliyun-ecs — Alibaba ECS/ACK: metadata, SSRF и захват роли
- cloud-ibm-cloud — IBM Cloud: IAM, API keys, service IDs и ресурсы
- cloud-ibm-cos — IBM Cloud Object Storage: HMAC-ключи и публичный доступ
- cloud-do-linode — DigitalOcean / Linode / Vultr: API-токены, дроплеты и снапшоты
- cloud-hetzner-ovh — Hetzner / OVH / Scaleway: bare-metal API и захват аккаунта
- cloud-vultr-objectstorage — Vultr/DO Spaces: S3-совместимые бакеты и мисконфиги
- cloud-cloudflare-workers — Cloudflare Workers/KV/R2/D1: edge-код, секреты и SSRF
- cloud-cloudflare-zero-trust — Cloudflare Zero Trust / Access: обход и захват туннелей
- cloud-vercel-netlify — Vercel / Netlify / Render: env-секреты, edge-функции, деплой
- cloud-supabase-planetscale — Supabase / PlanetScale / Neon: RLS, connection strings, анон-ключи
- cloud-heroku-railway — Heroku / Railway / Fly.io: dynos, env vars и API-токены

## SaaS identity & enterprise IdP (major gap)
- cloud-okta-attacks — Okta: API-токены, OIDC-приложения, обход MFA и захват тенанта
- cloud-okta-privesc — Okta privilege escalation: admin-роли, app-консент и impersonation
- cloud-entra-conditional-access — Entra ID Conditional Access: обход политик и device compliance
- cloud-entra-pim — Entra PIM: активация ролей, approval-обход и постоянные назначения
- cloud-entra-identity-protection — Entra Identity Protection / risky sign-ins и слепые зоны
- cloud-entra-connect — Entra Connect / hybrid identity: DCSync-мост и синхронизация
- cloud-golden-saml — Golden SAML: подделка SAML-токенов и персистентность
- cloud-saml-attacks — SAML: XSW, подпись, комментарии, IdP-initiated и обход
- cloud-oauth-attacks — OAuth 2.0/OIDC: redirect_uri, PKCE, code-injection, consent phishing
- cloud-prt-theft — Primary Refresh Token (PRT): кража, использование и Azure-доступ
- cloud-mfa-bypass — Обход MFA в облаке: fatigue, AiTM, legacy-протоколы, FIDO-обходы
- cloud-aitm-phishing — Adversary-in-the-Middle phishing против облачных SSO (Evilginx)
- cloud-m365-exchange — Microsoft 365 / Exchange Online: mail rules, eDiscovery, tenant takeover
- cloud-m365-sharepoint — M365 SharePoint/OneDrive/Teams: sharing-ссылки, анонимный доступ
- cloud-google-workspace — Google Workspace: OAuth-apps, DWD, super-admin и захват
- cloud-scim-provisioning — SCIM-провижининг: токены, маппинг ролей и инъекции
- cloud-service-principals — Service principals & app secrets: сроки, роли и захват
- cloud-keycloak — Keycloak: realms, client-scopes, admin-консоль и мисконфиги
- cloud-auth0-ping — Auth0 / Ping / OneLogin / JumpCloud: конфиги и кража пользователей
- cloud-duo-bypass — Duo / MFA-провайдеры: enrollment, обход и weak-факторы
- cloud-azure-ad-b2c — Entra External ID / B2C: user flows, кастомные политики и атаки
- cloud-kerberos-cloud — Kerberos в облачной гибридке: AS-REP, kerberoast, делегирование
- cloud-cloud-sso-deep — Глубокий SSO: token exchange, on-behalf-of, межтенантное доверие

## AWS — missing service surfaces
- cloud-aws-cloudfront — AWS CloudFront: OAI/OAC, origin-экспозиция, подписанные URL
- cloud-aws-waf-shield — AWS WAF & Shield: обход правил, rate-based, логирование
- cloud-aws-alb-elb — AWS ELB/ALB/NLB: listener rules, request smuggling, health-checks
- cloud-aws-api-gateway-deep — API Gateway deep: authorizers, usage-планы, Lambda-интеграции
- cloud-aws-eventbridge — EventBridge: правила, cross-account шины и инъекция событий
- cloud-aws-step-functions — Step Functions: определения, PassRole и захват через workflow
- cloud-aws-kinesis — Kinesis / Firehose: политики стримов, cross-account и exfil
- cloud-aws-glue-athena — Glue & Athena: каталоги, работа с данными и кража через запросы
- cloud-aws-redshift — Redshift: кластеры, IAM-роли, COPY-команды и exfil в S3
- cloud-aws-emr — EMR: кластеры, bootstrap-скрипты и эскалация через роль
- cloud-aws-bedrock — AWS Bedrock: модель-доступ, prompt injection и кража данных
- cloud-aws-sagemaker — SageMaker: notebooks, endpoints, роли и эскалация
- cloud-aws-iot-core — AWS IoT Core: policies, thing-сертификаты и захват через правила
- cloud-aws-greengrass — Greengrass / IoT Edge: деплой, компоненты и захват устройств
- cloud-aws-apprunner — App Runner / Elastic Beanstalk: env, роли и развёртывание
- cloud-aws-batch-mwaa — Batch / MWAA (Airflow): DAG-инъекции и захват роли
- cloud-aws-directory — AWS Directory Service / Managed AD: доверие и эскалация
- cloud-aws-ram — AWS RAM: расшаривание ресурсов и confused deputy
- cloud-aws-transit-gateway — Transit Gateway / PrivateLink / VPN / Direct Connect
- cloud-aws-control-tower — Control Tower / Landing Zone: guardrails и их обход
- cloud-aws-inspector-macie — Inspector / Macie / Security Hub / Detective: evasion и слепые зоны
- cloud-aws-access-analyzer — IAM Access Analyzer: findings, обход и внешний доступ
- cloud-aws-sts-deep — AWS STS глубоко: AssumeRole, session policies, tags, chained roles
- cloud-aws-iam-conditions — IAM conditions глубоко: confused deputy, source-IP, MFA-обход
- cloud-aws-acm-cloudhsm — ACM & CloudHSM: сертификаты, ключи и их использование
- cloud-aws-cost-abuse — Cryptojacking и abuse AWS: квота-эскалация, billing и детект
- cloud-aws-appsync-amplify — AppSync / Amplify: GraphQL-authz и захват бэкенда
- cloud-aws-cognito-deep — Cognito deep: identity pool, IAM-маппинг, обход и кража токенов
- cloud-aws-lakeformation — Lake Formation: гранулярные права и обход таблиц
- cloud-aws-secrets-rotation — Secrets Manager rotation: Lambda-ротация и её подмена

## Azure — missing service surfaces
- cloud-azure-cosmos — Cosmos DB: ключи, RBAC, Gremlin/SQL-инъекции и утечка
- cloud-azure-service-bus — Service Bus / Event Grid / Event Hubs: политики и инъекции
- cloud-azure-synapse — Synapse Analytics: workspace, Spark, linked-services и exfil
- cloud-azure-data-factory — Data Factory: pipelines, IR, managed identity и захват
- cloud-azure-front-door — Front Door / CDN / WAF: origin, правила и обход
- cloud-azure-firewall-bastion — Azure Firewall / Bastion / Private Link / NSG: обход изоляции
- cloud-azure-automation — Automation Accounts / Runbooks: Run As, гибридные worker'ы
- cloud-azure-arc — Azure Arc: подключённые машины, расширения и захват
- cloud-azure-container-apps — Container Apps / Container Instances: managed identity и escape
- cloud-azure-acr — Azure Container Registry: доступ, подписи и отравление образов
- cloud-azure-api-management — API Management: политики, subscriptions, backend и SSRF
- cloud-azure-ai-services — Azure AI / Cognitive Services / OpenAI: ключи, prompt injection
- cloud-azure-ml — Azure Machine Learning: workspaces, compute, datastores и эскалация
- cloud-azure-managed-disks — Managed Disks / Azure Files / NetApp: снапшоты и кража данных
- cloud-azure-app-config — App Configuration / Feature Flags: секреты и захват
- cloud-azure-policy-blueprints — Azure Policy / Blueprints / Management Groups: границы и обход
- cloud-azure-lighthouse — Azure Lighthouse: делегирование и межтенантный доступ
- cloud-azure-devops-deep — Azure DevOps deep: service connections, agent pools, variable groups
- cloud-azure-defender — Microsoft Defender for Cloud: рекомендации, обход и слепые зоны
- cloud-azure-purview — Purview / DLP: метки, обнаружение и обход классификации
- cloud-azure-functions-deep — Azure Functions deep: bindings, Durable Functions, ключи
- cloud-azure-logic-apps-deep — Logic Apps deep: connectors, инъекции и кража identity
- cloud-azure-stack — Azure Stack / Azure Local / Edge: гибридные поверхности
- cloud-azure-monitor — Azure Monitor / Log Analytics: KQL, рабочие области и слепые зоны
- cloud-azure-aks-deep — AKS deep: node pools, pod identity, CSI-driver и escape
- cloud-azure-sql-mi — Azure SQL / Managed Instance: firewall, AAD-auth и exfil

## GCP — missing service surfaces
- cloud-gcp-cloud-armor — GCP Cloud Armor / WAF: правила, обход и логирование
- cloud-gcp-vpc-sc — VPC Service Controls: периметры, обход и слепые зоны
- cloud-gcp-artifact-registry — Artifact Registry: доступ, подписи и отравление
- cloud-gcp-cloud-build — Cloud Build: триггеры, SA, подмена сборки и exfil
- cloud-gcp-cloud-deploy — Cloud Deploy / Cloud Run deep: delivery-pipelines и захват
- cloud-gcp-appengine — App Engine: версии, сервис-аккаунты и эскалация
- cloud-gcp-pubsub — Pub/Sub: политики топиков, push-подписки и инъекции
- cloud-gcp-cloud-scheduler-tasks — Cloud Scheduler / Tasks: инъекции и злоупотребление
- cloud-gcp-vertex-ai — Vertex AI: notebooks, pipelines, model-доступ и prompt injection
- cloud-gcp-dataproc-dataflow — Dataproc / Dataflow: кластеры, шаблоны и захват SA
- cloud-gcp-composer — Cloud Composer (Airflow): DAG-инъекции и кража
- cloud-gcp-spanner-firestore — Spanner / Firestore / Bigtable / Memorystore: доступ и утечка
- cloud-gcp-apigee — Apigee / API Gateway: прокси, политики и SSRF
- cloud-gcp-shared-vpc — Shared VPC / VPC peering / Interconnect: сетевые границы
- cloud-gcp-cloud-nat-fw — GCP firewall rules / Cloud NAT / Cloud DNS: обход и захват
- cloud-gcp-binary-auth — Binary Authorization / Container Analysis: обход подписи
- cloud-gcp-scc — Security Command Center: findings, обход и слепые зоны
- cloud-gcp-cert-authority — Certificate Authority Service / Cloud KMS deep
- cloud-gcp-logging-monitoring — Cloud Logging / Monitoring / audit: слепые зоны атакующего
- cloud-gcp-anthos — Anthos / GKE Enterprise / Config Management: гибрид и захват
- cloud-gcp-assured — Assured Workloads / Access Transparency: границы и их обход

## Kubernetes — missing surfaces
- cloud-k8s-service-mesh — Service mesh (Istio/Linkerd): mTLS, sidecar, обход и подмена
- cloud-k8s-helm — Helm: чарты, templates, secrets и злоупотребление релизами
- cloud-k8s-kustomize — Kustomize / overlays: подмена конфигов и секретов
- cloud-k8s-ingress — Ingress-контроллеры (NGINX/Traefik): аннотации, path-обход и SSRF
- cloud-k8s-cni — CNI (Calico/Cilium/Flannel): обход политик и захват плоскости
- cloud-k8s-apiserver — Kubernetes API server: authn/authz, агрегация, anonymous и abuse
- cloud-k8s-audit — Kubernetes audit-логи: включение, слепые зоны и evasion
- cloud-k8s-webhook — Admission webhooks / validating/mutating: обход и злоупотребление
- cloud-k8s-cert-manager — cert-manager / external-secrets / sealed-secrets
- cloud-k8s-velero-backup — Velero / снапшоты кластера: кража секретов через бэкапы
- cloud-k8s-dashboard — Kubernetes Dashboard / Headlamp: анонимный доступ и захват
- cloud-k8s-node — Атаки на ноды: kubelet, containerd, node-провижининг и кража
- cloud-k8s-scheduler-controller — kube-scheduler / kube-controller-manager / kube-proxy abuse
- cloud-k8s-gateway-api — Gateway API / CRD-роутинг: мисконфиги и обход
- cloud-k8s-multitenancy — Мультитенантность кластера: изоляция namespace и её обход
- cloud-k8s-cve-history — Kubernetes CVE-история: эскалации и практические цепочки
- cloud-k8s-windows — Windows-ноды в Kubernetes: hostProcess, эскалация и escape
- cloud-k8s-kubeflow — Kubeflow / ML-платформы в кластере: notebooks и захват

## Container runtimes & supply chain
- cloud-containerd-crio — containerd / CRI-O deep: сокеты, плагины и побег
- cloud-podman-rootless — Podman / rootless-контейнеры: границы и обход
- cloud-kata-gvisor — Kata Containers / gVisor / Firecracker: изоляция и её обход
- cloud-oci-spec — OCI-спецификация: config, layers, hooks и злоупотребление
- cloud-docker-compose-swarm — Docker Compose / Swarm: секреты, оверлеи и захват
- cloud-buildah-kaniko — Buildah / Kaniko / img: сборка в кластере и отравление
- cloud-distroless — Distroless / scratch-образы: поверхность и техники
- cloud-image-layer-secrets — Слои образов: поиск секретов и восстановление удалённых файлов
- cloud-ebpf-security — eBPF: наблюдение, побег и обход детекта
- cloud-registry-attacks — Docker Registry / Harbor: auth, квоты и подмена тегов
- cloud-supply-slsa — SLSA / in-toto / provenance: уровни и обход аттестации
- cloud-supply-renovate — Renovate / Dependabot / автообновления: supply-chain-вектор

## Serverless platforms & patterns
- cloud-knative — Knative / OpenFaaS / Fission: события, SSRF и захват
- cloud-lambda-extensions — Lambda extensions / runtime API / layers: злоупотребление
- cloud-function-url — Function URL / API-триггеры: authz и SSRF
- cloud-serverless-framework — Serverless Framework / SST / SAM: конфиги и секреты
- cloud-serverless-gpu — Serverless GPU / AI-inference: захват дорогих ресурсов
- cloud-faas-egress — Serverless egress / VPC-интеграция: обход изоляции

## IaC beyond Terraform/Bicep/CFN
- cloud-pulumi — Pulumi: стеки, secrets-provider и злоупотребление
- cloud-aws-cdk — AWS CDK: синтез, bootstrap-роли и escalation
- cloud-ansible — Ansible: inventory, vault, become и захват парка
- cloud-chef-puppet — Chef / Puppet / SaltStack: серверы, креды и захват
- cloud-crossplane — Crossplane / Kubernetes-IaC: провайдеры и escalation
- cloud-terragrunt-atlantis — Terragrunt / Atlantis / Spacelift: автоматизация и захват
- cloud-terraform-cloud — Terraform Cloud / Enterprise: workspaces, run-triggers, токены
- cloud-packer — Packer / образ-билдеры: подмена артефактов

## CI/CD beyond GH/GitLab/Jenkins/ArgoCD
- cloud-cicd-teamcity — TeamCity: агенты, токены и RCE
- cloud-cicd-circleci — CircleCI: контексты, orbs и кража секретов
- cloud-cicd-buildkite-travis — Buildkite / Travis / Drone: агенты и секреты
- cloud-cicd-bamboo — Bamboo / Bitbucket Pipelines: креды и инъекции
- cloud-cicd-tekton — Tekton / Argo Workflows / Rollouts: пайплайны в кластере
- cloud-cicd-spinnaker-flux — Spinnaker / Flux: CD-плоскость и захват
- cloud-cicd-selfhosted-runners — Self-hosted runners: persistence и кража между репозиториями
- cloud-cicd-oidc-deep — OIDC-доверие CI→облако deep: условия sub/aud и подделка
- cloud-cicd-artifact-poison — Отравление артефактов и кэшей пайплайна

## Networking & egress
- cloud-vpc-peering — VPC peering / Transit / Hub-spoke: изоляция и её обход
- cloud-privatelink — PrivateLink / Private Service Connect / Private Endpoint
- cloud-vpn-hybrid — Site-to-Site VPN / Direct Connect / ExpressRoute: гибридные мосты
- cloud-dns-deep — Облачный DNS deep: subdomain takeover, zone-делегирование, DNSSEC
- cloud-load-balancer-attacks — Балансировщики: smuggling, header-инъекции, origin-bypass
- cloud-egress-control — Egress-контроль / firewall / NAT: exfil и его обход
- cloud-service-mesh-net — Service mesh как сетевой слой: mTLS-обход и перехват
- cloud-bgp-routing — BGP / маршрутизация в облаке: hijack и аномалии

## Data, analytics & messaging
- cloud-snowflake — Snowflake: роли, shares, external stages и утечка
- cloud-databricks — Databricks: workspace, tokens, кластеры и exfil
- cloud-kafka-msk — Kafka / MSK / Confluent / Event Hubs: ACL, SASL и инъекции
- cloud-airflow-dag — Airflow / Dagster / Prefect: DAG-инъекции и кража соединений
- cloud-dbt-looker — dbt / Looker / Tableau / Power BI: доступ к данным и утечка
- cloud-data-lake — Data lake / Lakehouse: каталоги, права и обход
- cloud-streaming-exfil — Стриминговая exfiltration: Kinesis/PubSub/EventHub каналы

## AI / ML / LLM in cloud
- cloud-llm-prompt-injection — Prompt injection в облачных LLM-сервисах и агентах
- cloud-ai-model-theft — Кража моделей: веса, endpoints, извлечение через API
- cloud-ai-supply-chain — AI supply chain: модели, датасеты, ноутбуки и pickle-RCE
- cloud-rag-security — RAG / vector-DB: утечка через embeddings и инъекции
- cloud-ai-agent-abuse — Автономные AI-агенты с облачными правами: злоупотребление

## Secrets management (beyond native)
- cloud-vault — HashiCorp Vault: auth-методы, policies, seal/unseal и захват
- cloud-cyberark — CyberArk / PAM: сейфы, эпитеты и обход
- cloud-sops-sealed — SOPS / sealed-secrets / git-crypt: ключи и обход
- cloud-external-secrets — External Secrets Operator: провайдеры и подмена
- cloud-secret-scanning — TruffleHog / gitleaks / git-secrets: пайплайны и обход

## Post-exploitation & attack technique depth
- cloud-account-takeover — Полный захват облачного аккаунта: от ключа до persistence
- cloud-persistence-deep — Облачная персистентность deep: backdoor-роли, identity, webhooks
- cloud-lateral-cloud — Lateral movement в облаке: cross-service, cross-region, cross-account
- cloud-cryptojacking — Cryptojacking: развёртывание майнеров и evasion
- cloud-resource-hijack — Hijacking ресурсов: GPU/квота/Compute abuse
- cloud-session-token-theft — Кража облачных session-токенов и refresh-цепочек
- cloud-api-abuse — Abuse облачных API: rate, pagination, bulk-операции
- cloud-credential-broker — Облачные креденшел-брокеры и цепочки имперсонации
- cloud-ssrf-cloud-metadata — SSRF→metadata deep: IMDSv2, GCP, Azure, egress-обход
- cloud-worm-backup-bypass — Обход WORM/immutability бэкапов и object-lock

## Governance, compliance & emerging
- cloud-cspm-cnapp — CSPM/CNAPP: Prowler, ScoutSuite, Wiz, Orca — настройка и обход
- cloud-compliance-frameworks — FedRAMP / SOC2 / PCI / HIPAA / GDPR в облаке
- cloud-data-residency — Data residency / sovereignty / региональные границы
- cloud-confidential-computing — Confidential computing: enclaves, attestation и атаки
- cloud-pq-crypto — Пост-квантовая криптография в облачных KMS/сертификатах
- cloud-wasm-edge — WebAssembly в облаке/edge: sandbox и его обход
- cloud-5g-mec — 5G / MEC / edge-cloud: поверхность и интеграция
- cloud-quantum-hardware — Квантовые облачные сервисы (Braket/Azure Quantum): доступ
