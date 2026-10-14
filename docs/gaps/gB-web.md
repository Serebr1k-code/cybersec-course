# Web — missing / thin lesson topics (gap pass gB, independent second pass)

Inventory at time of analysis: **186 lessons** in `content/web/*.md`.
Verdict: **STRONG** on core attack classes (injection families, deserialization per-language,
auth/JWT/OAuth/SAML/WebAuthn, client-side, SSRF, smuggling, cache, WAF, DB dialects, tooling).
Gaps are concentrated in **product/CVE-specific exploitation**, **enterprise & appliance apps**,
**supply chain**, **cloud-native/API-gateway surfaces**, **additional DB engines**, **protocol depth**,
**modern web frameworks**, and **AI/agent surfaces**.

Legend: `[MISSING]` = no lesson covers it; `[THIN]` = covered only as a sub-section inside a broader lesson.

---

## 1. CMS & E-commerce platforms

- `[MISSING]` `web-wordpress` — WordPress: xmlrpc.php, wp-json/REST, wp-cron, user enum, auth cookie forgery
- `[MISSING]` `web-wordpress-plugins` — WordPress plugin/theme vulnerability classes (file upload, SQLi, LFI in plugins)
- `[MISSING]` `web-drupal` — Drupal: Drupalgeddon 1/2/3 (SA-CORE-2014-005, 2018-002, 2018-003)
- `[MISSING]` `web-joomla` — Joomla: com_ component exploitation, object injection, CVE chains
- `[MISSING]` `web-magento` — Magento / Adobe Commerce: SQLi, CosmicSting, RCE via admin
- `[MISSING]` `web-prestashop` — PrestaShop: SQLi, file upload, RCE
- `[MISSING]` `web-opencart` — OpenCart: path traversal, SQLi, RCE
- `[MISSING]` `web-typo3` — TYPO3: deserialization, backend RCE
- `[MISSING]` `web-craftcms` — Craft CMS: SSRF, RCE, Yii gadget chains
- `[MISSING]` `web-ghost-cms` — Ghost CMS: SSRF, admin API abuse
- `[MISSING]` `web-umbraco` — Umbraco CMS: auth bypass, deserialization
- `[MISSING]` `web-sitecore` — Sitecore: auth bypass, deserialization
- `[MISSING]` `web-cms-fingerprint` — CMS/plugin fingerprinting and version mapping

## 2. Server-side frameworks & app servers

- `[MISSING]` `web-laravel` — Laravel: Ignition debug RCE (CVE-2021-3129), APP_KEY/unserialize, env leak
- `[MISSING]` `web-django` — Django: DEBUG leaks, SSTI, pickle sessions, ORM injection
- `[MISSING]` `web-flask-werkzeug` — Flask/Werkzeug debugger PIN derivation and console RCE
- `[MISSING]` `web-rails` — Ruby on Rails: mass assignment, Marshal sessions, secret_key_base
- `[MISSING]` `web-spring-boot-actuator` — Spring Boot Actuator: env, heapdump, jolokia, gateway SpEL RCE
- `[MISSING]` `web-spring-cloud-gateway` — Spring Cloud Gateway/Function SpEL RCE (CVE-2022-22947/22963)
- `[MISSING]` `web-nextjs` — Next.js: middleware bypass, SSRF, cache poisoning, `__NEXT_DATA__`
- `[MISSING]` `web-nuxt` — Nuxt.js: SSR SSRF, server routes
- `[MISSING]` `web-express-node` — Express/Node middleware misconfig, prototype pollution → RCE
- `[MISSING]` `web-fastapi-starlette` — FastAPI/Starlette: path traversal, debug
- `[MISSING]` `web-symfony` — Symfony: debug toolbar, profiler, secret leaks
- `[MISSING]` `web-grails` — Grails: deserialization, SpEL
- `[MISSING]` `web-coldfusion` — Adobe ColdFusion: CVE-2023-26360/26364, CFML injection
- `[MISSING]` `web-phpmyadmin` — phpMyAdmin: auth bypass, LFI, RCE CVEs
- `[MISSING]` `web-adminer` — Adminer: SSRF, file read, DB pivots
- `[MISSING]` `web-roundcube` — Roundcube webmail: XSS, session, CVE-2024-42009
- `[MISSING]` `web-owa-exchange` — Outlook Web Access / OWA attacks
- `[MISSING]` `web-jquery` — jQuery: prototype pollution, selector XSS, CVE-2020-11022/11023
- `[MISSING]` `web-react-spa` — React/JSX XSS (`dangerouslySetInnerHTML`), RSC RCE class
- `[MISSING]` `web-angular-vue-deep` — Angular/Vue deep: expression sandbox, template gadgets
- `[MISSING]` `web-aspnet-deep` — ASP.NET: machineKey/padding oracle, ViewState MAC bypass, deser chains
- `[MISSING]` `web-struts2-deep` — Struts2 OGNL: S2-045/057/059 variants and payload engineering
- `[MISSING]` `web-node-module-sandbox` — Node.js vm/worker sandbox escapes

## 3. Enterprise collaboration & appliance apps

- `[MISSING]` `web-sharepoint` — SharePoint: ToolShell, ViewState deser, workflow, layout pages
- `[MISSING]` `web-exchange-proxylogon` — Exchange: ProxyLogon / ProxyShell / ProxyNotShell
- `[MISSING]` `web-confluence` — Confluence: CVE-2022-26134 (OGNL), CVE-2023-22515/22518
- `[MISSING]` `web-jira` — Jira: CVE-2019-8449, CVE-2023-22527 template injection
- `[MISSING]` `web-weblogic` — WebLogic: T3/IIOP deser, CVE-2020-14882/14750
- `[MISSING]` `web-jboss-wildfly` — JBoss/WildFly: jmx-console, deser, CVE-2017-12149
- `[MISSING]` `web-vcenter` — VMware vCenter: CVE-2021-21972/21985, CVE-2023-34048
- `[MISSING]` `web-esxi` — ESXi: OpenSLP, CVE-2021-21974
- `[MISSING]` `web-citrix-adc` — Citrix ADC/NetScaler: CitrixBleed, CVE-2023-3519
- `[MISSING]` `web-fortinet-ssl-vpn` — Fortinet FortiGate SSL-VPN CVEs
- `[MISSING]` `web-ivanti-connect` — Ivanti Connect Secure: CVE-2023-46805/21887
- `[MISSING]` `web-moveit` — MOVEit Transfer: CVE-2023-34362 SQLi→deser
- `[MISSING]` `web-f5-bigip` — F5 BIG-IP iControl REST: CVE-2022-1388
- `[MISSING]` `web-pulse-secure` — Pulse Secure / Ivanti VPN exploitation
- `[MISSING]` `web-sonicwall` — SonicWall SSL-VPN CVEs
- `[MISSING]` `web-appliance-web` — Generic network-appliance web panel exploitation

## 4. DevOps, monitoring & CI/CD web surfaces

- `[MISSING]` `web-grafana` — Grafana: CVE-2021-43798 LFI, CVE-2024-9264 SQLi→RCE
- `[MISSING]` `web-kibana` — Kibana: CVE-2019-7609, prototype pollution, RCE
- `[MISSING]` `web-splunk` — Splunk: CVE-2023-46214, dashboard XSS→RCE
- `[MISSING]` `web-zabbix` — Zabbix: SQLi, CVE-2022-23131 auth bypass
- `[MISSING]` `web-nagios` — Nagios: CVE-2018-15708, config/command injection
- `[MISSING]` `web-gitlab` — GitLab: CVE-2023-2825 traversal, CVE-2021-22205 ExifTool RCE
- `[MISSING]` `web-gitea-gogs` — Gitea/Gogs: auth bypass, RCE
- `[MISSING]` `web-jenkins-script-console` — Jenkins: script console, CVE-2024-23897 file read
- `[MISSING]` `web-teamcity` — TeamCity: auth bypass (CVE-2023-42793), RCE
- `[MISSING]` `web-bamboo` — Bamboo: CVE-2019-15003, RCE
- `[MISSING]` `web-sonarqube` — SonarQube: auth bypass, RCE
- `[MISSING]` `web-nexus` — Nexus Repository: CVE-2019-7238, CVE-2024-4956 traversal
- `[MISSING]` `web-artifactory` — JFrog Artifactory: CVE-2024-41801, anonymous access
- `[MISSING]` `web-harbor` — Harbor: CVE-2022-46463, registry abuse
- `[MISSING]` `web-rundeck` — Rundeck: CVE-2023-31080, job injection
- `[MISSING]` `web-argocd` — Argo CD: CVE-2022-29165, repo SSRF
- `[MISSING]` `web-awx-ansible` — AWX/Ansible Tower: CVE-2024-4215
- `[MISSING]` `web-rancher` — Rancher: CVE-2021-36782, CVE-2022-31247
- `[MISSING]` `web-portainer` — Portainer: auth bypass, Docker API abuse
- `[MISSING]` `web-k8s-dashboard` — Kubernetes Dashboard: token abuse, RCE
- `[MISSING]` `web-prometheus` — Prometheus: config/relabel abuse, SSRF
- `[MISSING]` `web-elastic-kibana-apis` — Elasticsearch/Kibana API exposure deeper

## 5. Supply chain & package security

- `[MISSING]` `web-supply-chain` — Web supply-chain attack overview and kill chain
- `[MISSING]` `web-dependency-confusion` — Dependency confusion in npm/PyPI/NuGet/Maven
- `[MISSING]` `web-typosquatting` — Typosquatting / combosquatting / brandjacking
- `[MISSING]` `web-package-poisoning` — Malicious package install hooks and postinstall RCE
- `[MISSING]` `web-cdn-hijacking` — CDN / polyfill.io / third-party JS hijacking
- `[MISSING]` `web-malicious-extensions` — Malicious browser extensions / marketplace
- `[MISSING]` `web-sbom-provenance` — SBOM, provenance, SLSA, sigstore verification
- `[MISSING]` `web-build-pipeline` — CI/CD build-pipeline compromise (SolarWinds-style)
- `[MISSING]` `web-subresource-integrity` — SRI bypass and script injection
- `[MISSING]` `web-js-secret-hunting` — JS bundle/source-map secret hunting

## 6. Injection — additional engines & variants

- `[MISSING]` `web-thymeleaf` — Thymeleaf SSTI (Spring) — preprocessing / expression injection
- `[MISSING]` `web-smarty` — Smarty SSTI (`{php}` / static method abuse)
- `[MISSING]` `web-razor` — Razor/Blazor SSTI
- `[MISSING]` `web-pug-ejs-nunjucks` — Pug/EJS/Nunjucks/Handlebars server template injection
- `[MISSING]` `web-header-injection` — HTTP header injection / response splitting (CRLF deeper)
- `[MISSING]` `web-email-injection` — Email header / SMTP injection via web forms
- `[MISSING]` `web-log-injection` — Log injection, log forging, log4j-style poisoning
- `[MISSING]` `web-xml-injection` — XML injection beyond XXE (XPath/XQuery, XSLT chains)
- `[MISSING]` `web-blind-injection` — Blind XPath/LDAP/NoSQL boolean and time-based extraction
- `[MISSING]` `web-odata-injection` — OData `$filter` injection
- `[MISSING]` `web-graphql-nosql` — GraphQL argument injection into backend stores
- `[MISSING]` `web-elasticsearch-injection` — Elasticsearch query DSL injection
- `[MISSING]` `web-orm-leaks` — ORM leak primitives (Sequelize/Hibernate/Entity Framework)
- `[MISSING]` `web-jndi-rmi-deep` — JNDI/RMI/LDAP referral and marshalsec deeper
- `[MISSING]` `web-expression-other` — Other EL engines (Velocity, MVEL, JUEL, Groovy)

## 7. Deserialization — additional chains & formats

- `[MISSING]` `web-fastjson-jackson` — Fastjson/Jackson autoType and polymorphic deser
- `[MISSING]` `web-xstream` — XStream deserialization RCE
- `[MISSING]` `web-hessian-amf` — Hessian / AMF / BlazeDS deserialization
- `[MISSING]` `web-java-rmi-jmx` — Java RMI/JMX exploitation and registry abuse
- `[MISSING]` `web-dotnet-binaryformatter` — .NET BinaryFormatter/LosFormatter/TypeConfuseDelegate
- `[MISSING]` `web-dotnet-viewstate-mac` — ViewState MAC bypass and machineKey recovery
- `[MISSING]` `web-yaml-deser` — YAML deserialization across languages (SnakeYAML, PyYAML, ruby)
- `[MISSING]` `web-messagepack-protobuf` — MessagePack/protobuf object injection
- `[MISSING]` `web-custom-gadget-chain` — Building custom gadget chains (gadget discovery workflow)
- `[MISSING]` `web-php-phar-deep` — PHAR metadata deser in unexpected sinks

## 8. Authentication & identity — additional

- `[MISSING]` `web-kerberos-spnego` — Kerberos/SPNEGO/Negotiate on web apps
- `[MISSING]` `web-ntlm-web` — NTLM auth over HTTP, coercion, relay chains
- `[MISSING]` `web-mtls` — mTLS client-certificate attacks and bypass
- `[MISSING]` `web-api-key-leak` — API key leakage, enumeration, rotation gaps
- `[MISSING]` `web-account-takeover` — Full account-takeover chains (reset + MFA + session)
- `[MISSING]` `web-user-enumeration` — User enumeration via timing/errors/reset flows
- `[MISSING]` `web-credential-stuffing` — Credential stuffing, brute-force protection bypass
- `[MISSING]` `web-password-policy-bypass` — Password-policy and reset-token weaknesses
- `[MISSING]` `web-sso-misconfig` — SSO/OIDC misconfiguration and token leakage
- `[MISSING]` `web-cas` — CAS protocol attacks (ticket forgery, service validation)
- `[MISSING]` `web-scim` — SCIM provisioning abuse and cross-tenant issues
- `[MISSING]` `web-saml-xsw` — SAML XSW variants (deep) — extends existing SAML lesson
- `[MISSING]` `web-oauth-token-theft` — OAuth authorization-code/token theft via redirect & referrer
- `[MISSING]` `web-totp` — TOTP/HOTP weaknesses, code reuse, seed leakage

## 9. Client-side & browser — additional

- `[MISSING]` `web-uxss` — Universal XSS (uXSS) in browser internals
- `[MISSING]` `web-cspt` — Client-Side Path Traversal (CSPT) → API abuse
- `[MISSING]` `web-svg-attacks` — SVG-based XSS, SSRF, XXE
- `[MISSING]` `web-iframe-sandbox` — iframe sandbox escape and allow-list bypass
- `[MISSING]` `web-browser-cache` — Browser cache poisoning/leak (beyond web cache)
- `[MISSING]` `web-history-manipulation` — History manipulation and URL spoofing
- `[MISSING]` `web-clipboard-dragdrop` — Clipboard and drag-and-drop data theft
- `[MISSING]` `web-file-opaque-origin` — file:// and opaque-origin quirks
- `[MISSING]` `web-samesite-bypass` — SameSite cookie bypass techniques
- `[MISSING]` `web-browser-extension` — Browser extension security and messaging
- `[MISSING]` `web-electron` — Electron app security (nodeIntegration, preload, IPC)
- `[MISSING]` `web-spectre-browser` — Spectre/transient-execution in the browser
- `[MISSING]` `web-dompurify-bypass` — DOMPurify/sanitizer bypass (extends mXSS)
- `[MISSING]` `web-dom-clobbering-deep` — DOM clobbering gadget engineering
- `[MISSING]` `web-postmessage-deep` — postMessage gadget chains and origin confusion
- `[MISSING]` `web-wasm-client` — WebAssembly client-side attack surface

## 10. Protocol-level & HTTP depth

- `[MISSING]` `web-http1-pipelining` — HTTP/1.1 pipelining smuggling and desync
- `[MISSING]` `web-http2-connect` — HTTP/2 CONNECT method tunneling
- `[MISSING]` `web-webtransport` — WebTransport protocol attacks
- `[MISSING]` `web-sse-abuse` — Server-Sent Events abuse and exfiltration
- `[MISSING]` `web-alt-svc-poisoning` — Alt-Svc header poisoning
- `[MISSING]` `web-quic-0rtt` — QUIC 0-RTT replay and migration
- `[MISSING]` `web-hpack` — HPACK header compression attacks
- `[MISSING]` `web-request-tunneling` — Request tunneling / hop-by-hop abuse
- `[MISSING]` `web-webdav` — WebDAV: PROPFIND, PUT, LOCK abuse
- `[MISSING]` `web-gopher-ssrf` — gopher/dict/file protocol smuggling (extends SSRF)
- `[MISSING]` `web-rmi-iiop-t3` — Non-HTTP enterprise protocols over web (RMI, IIOP, T3)
- `[MISSING]` `web-ftp-smtp-web` — FTP/SMTP/IMAP abuse via web SSRF
- `[MISSING]` `web-tls-misconfig` — TLS/SNI/certificate validation misconfig (extends existing)
- `[MISSING]` `web-cache-key-manipulation` — Cache-key injection and unkeyed-input abuse
- `[MISSING]` `web-http-desync-generic` — Generic HTTP desync methodology & tooling

## 11. Cloud-native, serverless & edge

- `[MISSING]` `web-api-gateway-misconfig` — API Gateway (AWS/Azure/Kong) misconfig
- `[MISSING]` `web-service-mesh` — Istio/Envoy/Linkerd misconfig and header trust
- `[MISSING]` `web-cdn-security` — CDN security, origin exposure, cache rules
- `[MISSING]` `web-cloud-waf-bypass` — Cloud WAF (Cloudflare/AWS/Akamai) bypass
- `[MISSING]` `web-firebase` — Firebase: open DB, misconfigured rules, storage
- `[MISSING]` `web-supabase` — Supabase: RLS misconfig, service-role key leak
- `[MISSING]` `web-cloud-storage` — S3/GCS/Azure Blob exposure via web apps
- `[MISSING]` `web-container-webapp` — Containerized web-app escape paths
- `[MISSING]` `web-serverless-iam` — Serverless IAM privesc via web-triggered functions
- `[MISSING]` `web-lambda-edge-abuse` — Edge/Lambda@Edge abuse (extends edge-computing)

## 12. API security — additional

- `[MISSING]` `web-owasp-api-top10` — OWASP API Security Top 10 mapped to labs
- `[MISSING]` `web-grpc-web` — gRPC-Web and browser→gRPC pivots
- `[MISSING]` `web-json-rpc` — JSON-RPC: batching, method enumeration
- `[MISSING]` `web-xmlrpc` — XML-RPC: pingback, SSRF, brute-force amplification
- `[MISSING]` `web-soap-wsdl` — SOAP/WSDL: XXE, injection, WS-Security bypass
- `[MISSING]` `web-api-versioning` — API versioning abuse and shadow endpoints
- `[MISSING]` `web-rate-limit-bypass` — API rate-limit bypass techniques
- `[MISSING]` `web-openapi-abuse` — OpenAPI/Swagger-driven automated exploitation
- `[MISSING]` `web-gateway-authz-bypass` — Gateway authz bypass and path confusion
- `[MISSING]` `web-mqtt-amqp-web` — MQTT/AMQP management over WebSocket
- `[MISSING]` `web-kafka-ui` — Kafka UI / Connect REST exposure

## 13. Databases — additional engines

- `[MISSING]` `web-db2` — IBM DB2 injection and file access
- `[MISSING]` `web-firebird` — Firebird SQL injection
- `[MISSING]` `web-sybase` — Sybase ASE injection
- `[MISSING]` `web-clickhouse` — ClickHouse injection and file read
- `[MISSING]` `web-cockroachdb` — CockroachDB injection
- `[MISSING]` `web-h2-database` — H2 database SQLi → Java code execution
- `[MISSING]` `web-hsqldb-derby` — HSQLDB/Derby in-JVM SQLi RCE
- `[MISSING]` `web-cassandra-cql` — Cassandra CQL injection
- `[MISSING]` `web-couchdb` — CouchDB: admin party, query-server RCE
- `[MISSING]` `web-neo4j-cypher` — Neo4j Cypher injection
- `[MISSING]` `web-influxdb-flux` — InfluxDB/Flux injection
- `[MISSING]` `web-memcached` — Memcached exposure, SSRF amplification
- `[MISSING]` `web-dynamodb-firestore` — DynamoDB/Firestore injection
- `[MISSING]` `web-bigquery-snowflake` — BigQuery/Snowflake/Snowflake SQLi
- `[MISSING]` `web-pg-extensions` — PostgreSQL extensions (dblink, plpython, COPY PROGRAM)
- `[MISSING]` `web-oracle-java` — Oracle Java stored procedures
- `[MISSING]` `web-mssql-linked-deep` — MSSQL linked servers & AD pivots (extends existing)

## 14. File handling, archives & media

- `[MISSING]` `web-rfi` — Remote File Inclusion
- `[MISSING]` `web-symlink-attacks` — Symlink/hardlink and race file attacks
- `[MISSING]` `web-imagemagick-exiftool` — ImageMagick/ExifTool RCE via metadata
- `[MISSING]` `web-pdf-generation` — PDF generation abuse (wkhtmltopdf, headless Chrome SSRF)
- `[MISSING]` `web-svg-xxe` — SVG XXE and SVG file-upload chains
- `[MISSING]` `web-archive-cracking` — Encrypted archive/ZIP cracking and ZipCrypto
- `[MISSING]` `web-upload-to-deser` — Upload→deserialization→RCE chains
- `[MISSING]` `web-path-normalization` — Path normalization bypass matrix
- `[MISSING]` `web-unicode-filename` — Unicode filename and extension bypass
- `[MISSING]` `web-http-file-upload` — PUT/multipart/parser-differential upload abuse

## 15. Web servers, proxies & infra

- `[MISSING]` `web-apache-cve` — Apache httpd: CVE-2021-41773/42013, mod_proxy SSRF
- `[MISSING]` `web-iis` — IIS: tilde short-name, WebDAV, CVE-2017-7269
- `[MISSING]` `web-tomcat` — Tomcat: manager/ghostcat, CVE-2020-1938
- `[MISSING]` `web-jetty` — Jetty: CVE-2021-28164/34412
- `[MISSING]` `web-nginx-deep` — nginx: alias traversal, off-by-slash, misconfig
- `[MISSING]` `web-haproxy-envoy-traefik` — reverse-proxy/proxy misconfig family
- `[MISSING]` `web-trusted-proxy` — Trusted-proxy/X-Forwarded-* trust abuse
- `[MISSING]` `web-webshell` — Web shells: kinds, deployment, detection evasion
- `[MISSING]` `web-app-persistence` — Web-app persistence (cron, startup, session backdoors)
- `[MISSING]` `web-server-config-review` — Web-server config review checklist

## 16. Recon & tooling — additional

- `[MISSING]` `web-google-dorking` — Google/Bing dorking for web assets
- `[MISSING]` `web-shodan-censys` — Shodan/Censys/Fofa recon for web
- `[MISSING]` `web-wayback-recon` — Wayback/archive recon for old endpoints
- `[MISSING]` `web-github-recon` — GitHub/GitLab code-search recon
- `[MISSING]` `web-js-analysis` — JavaScript static analysis and endpoint extraction
- `[MISSING]` `web-source-map-leaks` — Source-map and build-artifact leaks
- `[MISSING]` `web-api-discovery` — API endpoint discovery workflow
- `[MISSING]` `web-vhost-param-enum` — vhost + hidden parameter enumeration
- `[MISSING]` `web-content-discovery` — Content/directory discovery methodology
- `[MISSING]` `web-screenshot-crawl` — Headless crawl + screenshot triage
- `[MISSING]` `web-fuzzing-advanced` — Advanced fuzzing (filter/wordlist/grammar)
- `[MISSING]` `web-mobile-app-api-recon` — Mobile app → web API recon bridge

## 17. Business logic, automation & abuse

- `[MISSING]` `web-email-verification-bypass` — Email/phone verification bypass
- `[MISSING]` `web-otp-bypass` — OTP bypass (reuse, race, response manipulation)
- `[MISSING]` `web-coupon-discount-abuse` — Coupon/discount/promo abuse
- `[MISSING]` `web-refund-inventory-abuse` — Refund/inventory/quantity abuse
- `[MISSING]` `web-trial-referral-abuse` — Trial/referral/loyalty abuse
- `[MISSING]` `web-scraping-antibots` — Scraping, anti-bot and bot-detection bypass
- `[MISSING]` `web-rate-limit-logic` — Logic-level rate-limit and state-machine abuse
- `[MISSING]` `web-signature-replay` — Webhook/signature replay and timestamp flaws

## 18. AI / LLM / agentic web

- `[MISSING]` `web-llm-indirect-injection` — Indirect prompt injection via fetched content
- `[MISSING]` `web-llm-rag-poisoning` — RAG corpus poisoning and retrieval abuse
- `[MISSING]` `web-llm-tool-abuse` — Tool/function-call abuse and SSRF via plugins
- `[MISSING]` `web-llm-data-exfil` — LLM data exfiltration via markdown/images
- `[MISSING]` `web-llm-model-extraction` — Model extraction / prompt leaking
- `[MISSING]` `web-mcp-security` — Model Context Protocol server security
- `[MISSING]` `web-ai-guardrail-bypass` — Guardrail/jailbreak bypass classes
- `[MISSING]` `web-ai-supply-chain` — AI/ML supply-chain (models, weights, datasets)

## 19. Misc / exotic

- `[MISSING]` `web-shellshock` — Shellshock (CVE-2014-6271) via CGI
- `[MISSING]` `web-waf-fingerprint` — WAF fingerprinting and rule mapping
- `[MISSING]` `web-cors-deep-misconfig` — CORS misconfig beyond the basics (internal networks)
- `[MISSING]` `web-dns-takeover-deep` — Subdomain takeover provider matrix (extends existing)
- `[MISSING]` `web-http-request-smuggling-lab` — Smuggling lab matrix (CL.TE/TE.CL/CL.0/H2)
- `[MISSING]` `web-open-redirect-chain` — Open-redirect → OAuth/token theft chains
- `[MISSING]` `web-cache-poison-deep` — Cache poisoning gadget engineering
- `[MISSING]` `web-csp-bypass-deep` — CSP bypass with script gadgets (extends existing)
- `[MISSING]` `web-desync-client-side` — Client-side desync deep (extends existing CSD)
- `[MISSING]` `web-prototype-pollution-server` — Server-side prototype pollution (extends existing)
- `[MISSING]` `web-graphql-authz-deep` — GraphQL field-level authz and IDOR
- `[MISSING]` `web-websocket-deep` — WebSocket cross-site hijacking and tunneling
- `[MISSING]` `web-sqli-waf-bypass` — SQLi WAF bypass payload engineering
- `[MISSING]` `web-blind-ssrf-oob` — Blind SSRF via OOB (DNS/HTTP) interaction
- `[MISSING]` `web-host-header-deep` — Host header password-reset poisoning (extends existing)
- `[MISSING]` `web-webhooks-deep` — Webhook SSRF/signature/replay deep (extends existing)
- `[MISSING]` `web-jwt-alg-confusion` — JWT alg confusion / key confusion deep (extends existing)
- `[MISSING]` `web-clickjacking-deep` — Clickjacking with CSP frame-ancestors bypass

---

## Summary

- Total candidate topics: **~260**
- Highest-value blocks (by exploitability density): CMS/enterprise CVE apps (§1, §3), DevOps web surfaces (§4),
  supply chain (§5), server-side frameworks (§2), additional DB engines (§13), cloud-native/API-gateway (§11, §12).
- Suggested authoring order: §1 → §3 → §4 → §2 → §5 → §13 → §12 → §11 → §6/§7 → remainder.
