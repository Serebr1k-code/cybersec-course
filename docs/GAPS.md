# Content Gap Backlog — master (all 12 categories)

Merged from the 12 independent per-category gap analyses (`docs/gaps/gB-<cat>.md`).
Each bullet is a proposed NEW lesson id: `- <proposed-id> — <title>`. Duplicate ids
within a category were dropped (first occurrence kept). These are CANDIDATE topics —
re-verify `content/<cat>/<id>.md` does not already exist before authoring.

Note: 5 ids are proposed by more than one category file (a topic surfaced from two angles):
`web-webshell` (web + forensics), `cloud-google-workspace` (cloud + forensics),
`mobile-android-strongbox`, `mobile-ios-keychain-deep`, `mobile-baseband` (mobile + forensics).
The owning id prefix is authoritative; de-dup again globally before authoring.

## Totals per category

- **web**: 258
- **pwn**: 178
- **reversing**: 179
- **crypto**: 135
- **stego**: 185
- **forensics**: 253
- **network**: 152
- **osint**: 153
- **cloud**: 215
- **hardware**: 156
- **misc**: 305
- **mobile**: 330
- **GRAND TOTAL**: 2499


## web

Total unique proposed lessons: **258**

### 1. CMS & E-commerce platforms

- web-wordpress — WordPress: xmlrpc.php, wp-json/REST, wp-cron, user enum, auth cookie forgery
- web-wordpress-plugins — WordPress plugin/theme vulnerability classes (file upload, SQLi, LFI in plugins)
- web-drupal — Drupal: Drupalgeddon 1/2/3 (SA-CORE-2014-005, 2018-002, 2018-003)
- web-joomla — Joomla: com_ component exploitation, object injection, CVE chains
- web-magento — Magento / Adobe Commerce: SQLi, CosmicSting, RCE via admin
- web-prestashop — PrestaShop: SQLi, file upload, RCE
- web-opencart — OpenCart: path traversal, SQLi, RCE
- web-typo3 — TYPO3: deserialization, backend RCE
- web-craftcms — Craft CMS: SSRF, RCE, Yii gadget chains
- web-ghost-cms — Ghost CMS: SSRF, admin API abuse
- web-umbraco — Umbraco CMS: auth bypass, deserialization
- web-sitecore — Sitecore: auth bypass, deserialization
- web-cms-fingerprint — CMS/plugin fingerprinting and version mapping

### 2. Server-side frameworks & app servers

- web-laravel — Laravel: Ignition debug RCE (CVE-2021-3129), APP_KEY/unserialize, env leak
- web-django — Django: DEBUG leaks, SSTI, pickle sessions, ORM injection
- web-flask-werkzeug — Flask/Werkzeug debugger PIN derivation and console RCE
- web-rails — Ruby on Rails: mass assignment, Marshal sessions, secret_key_base
- web-spring-boot-actuator — Spring Boot Actuator: env, heapdump, jolokia, gateway SpEL RCE
- web-spring-cloud-gateway — Spring Cloud Gateway/Function SpEL RCE (CVE-2022-22947/22963)
- web-nextjs — Next.js: middleware bypass, SSRF, cache poisoning,  __NEXT_DATA__
- web-nuxt — Nuxt.js: SSR SSRF, server routes
- web-express-node — Express/Node middleware misconfig, prototype pollution → RCE
- web-fastapi-starlette — FastAPI/Starlette: path traversal, debug
- web-symfony — Symfony: debug toolbar, profiler, secret leaks
- web-grails — Grails: deserialization, SpEL
- web-coldfusion — Adobe ColdFusion: CVE-2023-26360/26364, CFML injection
- web-phpmyadmin — phpMyAdmin: auth bypass, LFI, RCE CVEs
- web-adminer — Adminer: SSRF, file read, DB pivots
- web-roundcube — Roundcube webmail: XSS, session, CVE-2024-42009
- web-owa-exchange — Outlook Web Access / OWA attacks
- web-jquery — jQuery: prototype pollution, selector XSS, CVE-2020-11022/11023
- web-react-spa — React/JSX XSS ( dangerouslySetInnerHTML ), RSC RCE class
- web-angular-vue-deep — Angular/Vue deep: expression sandbox, template gadgets
- web-aspnet-deep — ASP.NET: machineKey/padding oracle, ViewState MAC bypass, deser chains
- web-struts2-deep — Struts2 OGNL: S2-045/057/059 variants and payload engineering
- web-node-module-sandbox — Node.js vm/worker sandbox escapes

### 3. Enterprise collaboration & appliance apps

- web-sharepoint — SharePoint: ToolShell, ViewState deser, workflow, layout pages
- web-exchange-proxylogon — Exchange: ProxyLogon / ProxyShell / ProxyNotShell
- web-confluence — Confluence: CVE-2022-26134 (OGNL), CVE-2023-22515/22518
- web-jira — Jira: CVE-2019-8449, CVE-2023-22527 template injection
- web-weblogic — WebLogic: T3/IIOP deser, CVE-2020-14882/14750
- web-jboss-wildfly — JBoss/WildFly: jmx-console, deser, CVE-2017-12149
- web-vcenter — VMware vCenter: CVE-2021-21972/21985, CVE-2023-34048
- web-esxi — ESXi: OpenSLP, CVE-2021-21974
- web-citrix-adc — Citrix ADC/NetScaler: CitrixBleed, CVE-2023-3519
- web-fortinet-ssl-vpn — Fortinet FortiGate SSL-VPN CVEs
- web-ivanti-connect — Ivanti Connect Secure: CVE-2023-46805/21887
- web-moveit — MOVEit Transfer: CVE-2023-34362 SQLi→deser
- web-f5-bigip — F5 BIG-IP iControl REST: CVE-2022-1388
- web-pulse-secure — Pulse Secure / Ivanti VPN exploitation
- web-sonicwall — SonicWall SSL-VPN CVEs
- web-appliance-web — Generic network-appliance web panel exploitation

### 4. DevOps, monitoring & CI/CD web surfaces

- web-grafana — Grafana: CVE-2021-43798 LFI, CVE-2024-9264 SQLi→RCE
- web-kibana — Kibana: CVE-2019-7609, prototype pollution, RCE
- web-splunk — Splunk: CVE-2023-46214, dashboard XSS→RCE
- web-zabbix — Zabbix: SQLi, CVE-2022-23131 auth bypass
- web-nagios — Nagios: CVE-2018-15708, config/command injection
- web-gitlab — GitLab: CVE-2023-2825 traversal, CVE-2021-22205 ExifTool RCE
- web-gitea-gogs — Gitea/Gogs: auth bypass, RCE
- web-jenkins-script-console — Jenkins: script console, CVE-2024-23897 file read
- web-teamcity — TeamCity: auth bypass (CVE-2023-42793), RCE
- web-bamboo — Bamboo: CVE-2019-15003, RCE
- web-sonarqube — SonarQube: auth bypass, RCE
- web-nexus — Nexus Repository: CVE-2019-7238, CVE-2024-4956 traversal
- web-artifactory — JFrog Artifactory: CVE-2024-41801, anonymous access
- web-harbor — Harbor: CVE-2022-46463, registry abuse
- web-rundeck — Rundeck: CVE-2023-31080, job injection
- web-argocd — Argo CD: CVE-2022-29165, repo SSRF
- web-awx-ansible — AWX/Ansible Tower: CVE-2024-4215
- web-rancher — Rancher: CVE-2021-36782, CVE-2022-31247
- web-portainer — Portainer: auth bypass, Docker API abuse
- web-k8s-dashboard — Kubernetes Dashboard: token abuse, RCE
- web-prometheus — Prometheus: config/relabel abuse, SSRF
- web-elastic-kibana-apis — Elasticsearch/Kibana API exposure deeper

### 5. Supply chain & package security

- web-supply-chain — Web supply-chain attack overview and kill chain
- web-dependency-confusion — Dependency confusion in npm/PyPI/NuGet/Maven
- web-typosquatting — Typosquatting / combosquatting / brandjacking
- web-package-poisoning — Malicious package install hooks and postinstall RCE
- web-cdn-hijacking — CDN / polyfill.io / third-party JS hijacking
- web-malicious-extensions — Malicious browser extensions / marketplace
- web-sbom-provenance — SBOM, provenance, SLSA, sigstore verification
- web-build-pipeline — CI/CD build-pipeline compromise (SolarWinds-style)
- web-subresource-integrity — SRI bypass and script injection
- web-js-secret-hunting — JS bundle/source-map secret hunting

### 6. Injection — additional engines & variants

- web-thymeleaf — Thymeleaf SSTI (Spring) — preprocessing / expression injection
- web-smarty — Smarty SSTI ( {php}  / static method abuse)
- web-razor — Razor/Blazor SSTI
- web-pug-ejs-nunjucks — Pug/EJS/Nunjucks/Handlebars server template injection
- web-header-injection — HTTP header injection / response splitting (CRLF deeper)
- web-email-injection — Email header / SMTP injection via web forms
- web-log-injection — Log injection, log forging, log4j-style poisoning
- web-xml-injection — XML injection beyond XXE (XPath/XQuery, XSLT chains)
- web-blind-injection — Blind XPath/LDAP/NoSQL boolean and time-based extraction
- web-odata-injection — OData  $filter  injection
- web-graphql-nosql — GraphQL argument injection into backend stores
- web-elasticsearch-injection — Elasticsearch query DSL injection
- web-orm-leaks — ORM leak primitives (Sequelize/Hibernate/Entity Framework)
- web-jndi-rmi-deep — JNDI/RMI/LDAP referral and marshalsec deeper
- web-expression-other — Other EL engines (Velocity, MVEL, JUEL, Groovy)

### 7. Deserialization — additional chains & formats

- web-fastjson-jackson — Fastjson/Jackson autoType and polymorphic deser
- web-xstream — XStream deserialization RCE
- web-hessian-amf — Hessian / AMF / BlazeDS deserialization
- web-java-rmi-jmx — Java RMI/JMX exploitation and registry abuse
- web-dotnet-binaryformatter — .NET BinaryFormatter/LosFormatter/TypeConfuseDelegate
- web-dotnet-viewstate-mac — ViewState MAC bypass and machineKey recovery
- web-yaml-deser — YAML deserialization across languages (SnakeYAML, PyYAML, ruby)
- web-messagepack-protobuf — MessagePack/protobuf object injection
- web-custom-gadget-chain — Building custom gadget chains (gadget discovery workflow)
- web-php-phar-deep — PHAR metadata deser in unexpected sinks

### 8. Authentication & identity — additional

- web-kerberos-spnego — Kerberos/SPNEGO/Negotiate on web apps
- web-ntlm-web — NTLM auth over HTTP, coercion, relay chains
- web-mtls — mTLS client-certificate attacks and bypass
- web-api-key-leak — API key leakage, enumeration, rotation gaps
- web-account-takeover — Full account-takeover chains (reset + MFA + session)
- web-user-enumeration — User enumeration via timing/errors/reset flows
- web-credential-stuffing — Credential stuffing, brute-force protection bypass
- web-password-policy-bypass — Password-policy and reset-token weaknesses
- web-sso-misconfig — SSO/OIDC misconfiguration and token leakage
- web-cas — CAS protocol attacks (ticket forgery, service validation)
- web-scim — SCIM provisioning abuse and cross-tenant issues
- web-saml-xsw — SAML XSW variants (deep) — extends existing SAML lesson
- web-oauth-token-theft — OAuth authorization-code/token theft via redirect & referrer
- web-totp — TOTP/HOTP weaknesses, code reuse, seed leakage

### 9. Client-side & browser — additional

- web-uxss — Universal XSS (uXSS) in browser internals
- web-cspt — Client-Side Path Traversal (CSPT) → API abuse
- web-svg-attacks — SVG-based XSS, SSRF, XXE
- web-iframe-sandbox — iframe sandbox escape and allow-list bypass
- web-browser-cache — Browser cache poisoning/leak (beyond web cache)
- web-history-manipulation — History manipulation and URL spoofing
- web-clipboard-dragdrop — Clipboard and drag-and-drop data theft
- web-file-opaque-origin — file:// and opaque-origin quirks
- web-samesite-bypass — SameSite cookie bypass techniques
- web-browser-extension — Browser extension security and messaging
- web-electron — Electron app security (nodeIntegration, preload, IPC)
- web-spectre-browser — Spectre/transient-execution in the browser
- web-dompurify-bypass — DOMPurify/sanitizer bypass (extends mXSS)
- web-dom-clobbering-deep — DOM clobbering gadget engineering
- web-postmessage-deep — postMessage gadget chains and origin confusion
- web-wasm-client — WebAssembly client-side attack surface

### 10. Protocol-level & HTTP depth

- web-http1-pipelining — HTTP/1.1 pipelining smuggling and desync
- web-http2-connect — HTTP/2 CONNECT method tunneling
- web-webtransport — WebTransport protocol attacks
- web-sse-abuse — Server-Sent Events abuse and exfiltration
- web-alt-svc-poisoning — Alt-Svc header poisoning
- web-quic-0rtt — QUIC 0-RTT replay and migration
- web-hpack — HPACK header compression attacks
- web-request-tunneling — Request tunneling / hop-by-hop abuse
- web-webdav — WebDAV: PROPFIND, PUT, LOCK abuse
- web-gopher-ssrf — gopher/dict/file protocol smuggling (extends SSRF)
- web-rmi-iiop-t3 — Non-HTTP enterprise protocols over web (RMI, IIOP, T3)
- web-ftp-smtp-web — FTP/SMTP/IMAP abuse via web SSRF
- web-tls-misconfig — TLS/SNI/certificate validation misconfig (extends existing)
- web-cache-key-manipulation — Cache-key injection and unkeyed-input abuse
- web-http-desync-generic — Generic HTTP desync methodology & tooling

### 11. Cloud-native, serverless & edge

- web-api-gateway-misconfig — API Gateway (AWS/Azure/Kong) misconfig
- web-service-mesh — Istio/Envoy/Linkerd misconfig and header trust
- web-cdn-security — CDN security, origin exposure, cache rules
- web-cloud-waf-bypass — Cloud WAF (Cloudflare/AWS/Akamai) bypass
- web-firebase — Firebase: open DB, misconfigured rules, storage
- web-supabase — Supabase: RLS misconfig, service-role key leak
- web-cloud-storage — S3/GCS/Azure Blob exposure via web apps
- web-container-webapp — Containerized web-app escape paths
- web-serverless-iam — Serverless IAM privesc via web-triggered functions
- web-lambda-edge-abuse — Edge/Lambda@Edge abuse (extends edge-computing)

### 12. API security — additional

- web-owasp-api-top10 — OWASP API Security Top 10 mapped to labs
- web-grpc-web — gRPC-Web and browser→gRPC pivots
- web-json-rpc — JSON-RPC: batching, method enumeration
- web-xmlrpc — XML-RPC: pingback, SSRF, brute-force amplification
- web-soap-wsdl — SOAP/WSDL: XXE, injection, WS-Security bypass
- web-api-versioning — API versioning abuse and shadow endpoints
- web-rate-limit-bypass — API rate-limit bypass techniques
- web-openapi-abuse — OpenAPI/Swagger-driven automated exploitation
- web-gateway-authz-bypass — Gateway authz bypass and path confusion
- web-mqtt-amqp-web — MQTT/AMQP management over WebSocket
- web-kafka-ui — Kafka UI / Connect REST exposure

### 13. Databases — additional engines

- web-db2 — IBM DB2 injection and file access
- web-firebird — Firebird SQL injection
- web-sybase — Sybase ASE injection
- web-clickhouse — ClickHouse injection and file read
- web-cockroachdb — CockroachDB injection
- web-h2-database — H2 database SQLi → Java code execution
- web-hsqldb-derby — HSQLDB/Derby in-JVM SQLi RCE
- web-cassandra-cql — Cassandra CQL injection
- web-couchdb — CouchDB: admin party, query-server RCE
- web-neo4j-cypher — Neo4j Cypher injection
- web-influxdb-flux — InfluxDB/Flux injection
- web-memcached — Memcached exposure, SSRF amplification
- web-dynamodb-firestore — DynamoDB/Firestore injection
- web-bigquery-snowflake — BigQuery/Snowflake/Snowflake SQLi
- web-pg-extensions — PostgreSQL extensions (dblink, plpython, COPY PROGRAM)
- web-oracle-java — Oracle Java stored procedures
- web-mssql-linked-deep — MSSQL linked servers & AD pivots (extends existing)

### 14. File handling, archives & media

- web-rfi — Remote File Inclusion
- web-symlink-attacks — Symlink/hardlink and race file attacks
- web-imagemagick-exiftool — ImageMagick/ExifTool RCE via metadata
- web-pdf-generation — PDF generation abuse (wkhtmltopdf, headless Chrome SSRF)
- web-svg-xxe — SVG XXE and SVG file-upload chains
- web-archive-cracking — Encrypted archive/ZIP cracking and ZipCrypto
- web-upload-to-deser — Upload→deserialization→RCE chains
- web-path-normalization — Path normalization bypass matrix
- web-unicode-filename — Unicode filename and extension bypass
- web-http-file-upload — PUT/multipart/parser-differential upload abuse

### 15. Web servers, proxies & infra

- web-apache-cve — Apache httpd: CVE-2021-41773/42013, mod_proxy SSRF
- web-iis — IIS: tilde short-name, WebDAV, CVE-2017-7269
- web-tomcat — Tomcat: manager/ghostcat, CVE-2020-1938
- web-jetty — Jetty: CVE-2021-28164/34412
- web-nginx-deep — nginx: alias traversal, off-by-slash, misconfig
- web-haproxy-envoy-traefik — reverse-proxy/proxy misconfig family
- web-trusted-proxy — Trusted-proxy/X-Forwarded-* trust abuse
- web-webshell — Web shells: kinds, deployment, detection evasion
- web-app-persistence — Web-app persistence (cron, startup, session backdoors)
- web-server-config-review — Web-server config review checklist

### 16. Recon & tooling — additional

- web-google-dorking — Google/Bing dorking for web assets
- web-shodan-censys — Shodan/Censys/Fofa recon for web
- web-wayback-recon — Wayback/archive recon for old endpoints
- web-github-recon — GitHub/GitLab code-search recon
- web-js-analysis — JavaScript static analysis and endpoint extraction
- web-source-map-leaks — Source-map and build-artifact leaks
- web-api-discovery — API endpoint discovery workflow
- web-vhost-param-enum — vhost + hidden parameter enumeration
- web-content-discovery — Content/directory discovery methodology
- web-screenshot-crawl — Headless crawl + screenshot triage
- web-fuzzing-advanced — Advanced fuzzing (filter/wordlist/grammar)
- web-mobile-app-api-recon — Mobile app → web API recon bridge

### 17. Business logic, automation & abuse

- web-email-verification-bypass — Email/phone verification bypass
- web-otp-bypass — OTP bypass (reuse, race, response manipulation)
- web-coupon-discount-abuse — Coupon/discount/promo abuse
- web-refund-inventory-abuse — Refund/inventory/quantity abuse
- web-trial-referral-abuse — Trial/referral/loyalty abuse
- web-scraping-antibots — Scraping, anti-bot and bot-detection bypass
- web-rate-limit-logic — Logic-level rate-limit and state-machine abuse
- web-signature-replay — Webhook/signature replay and timestamp flaws

### 18. AI / LLM / agentic web

- web-llm-indirect-injection — Indirect prompt injection via fetched content
- web-llm-rag-poisoning — RAG corpus poisoning and retrieval abuse
- web-llm-tool-abuse — Tool/function-call abuse and SSRF via plugins
- web-llm-data-exfil — LLM data exfiltration via markdown/images
- web-llm-model-extraction — Model extraction / prompt leaking
- web-mcp-security — Model Context Protocol server security
- web-ai-guardrail-bypass — Guardrail/jailbreak bypass classes
- web-ai-supply-chain — AI/ML supply-chain (models, weights, datasets)

### 19. Misc / exotic

- web-shellshock — Shellshock (CVE-2014-6271) via CGI
- web-waf-fingerprint — WAF fingerprinting and rule mapping
- web-cors-deep-misconfig — CORS misconfig beyond the basics (internal networks)
- web-dns-takeover-deep — Subdomain takeover provider matrix (extends existing)
- web-http-request-smuggling-lab — Smuggling lab matrix (CL.TE/TE.CL/CL.0/H2)
- web-open-redirect-chain — Open-redirect → OAuth/token theft chains
- web-cache-poison-deep — Cache poisoning gadget engineering
- web-csp-bypass-deep — CSP bypass with script gadgets (extends existing)
- web-desync-client-side — Client-side desync deep (extends existing CSD)
- web-prototype-pollution-server — Server-side prototype pollution (extends existing)
- web-graphql-authz-deep — GraphQL field-level authz and IDOR
- web-websocket-deep — WebSocket cross-site hijacking and tunneling
- web-sqli-waf-bypass — SQLi WAF bypass payload engineering
- web-blind-ssrf-oob — Blind SSRF via OOB (DNS/HTTP) interaction
- web-host-header-deep — Host header password-reset poisoning (extends existing)
- web-webhooks-deep — Webhook SSRF/signature/replay deep (extends existing)
- web-jwt-alg-confusion — JWT alg confusion / key confusion deep (extends existing)
- web-clickjacking-deep — Clickjacking with CSP frame-ancestors bypass

### Summary

## pwn

Total unique proposed lessons: **178**

### 1. Architectures

- pwn-x86-32 — 32-bit x86 exploitation: cdecl, ret2libc i386, mmap, stack layout
- pwn-arm32 — ARM32 (AArch32): AAPCS, Thumb, mode switching, gadgets
- pwn-arm-pac — ARM Pointer Authentication (PAC): signing, gadgets, PAC bypass
- pwn-arm-mte — ARM MTE (Memory Tagging Extension): tagging, bypass techniques
- pwn-powerpc — PowerPC (32/64): ABI, GOT/TOC, ROP
- pwn-sparc — SPARC exploitation: register windows, ROP
- pwn-s390x — IBM Z s390x: ABI, exploitation basics
- pwn-sh4 — SuperH (SH-4) exploitation
- pwn-avr-mcu — AVR/MSP430/8051 embedded MCU exploitation
- pwn-xtensa — Xtensa/ESP32 exploitation
- pwn-riscv64 — RISC-V 64 deep (extends existing RISC-V basics)
- pwn-wasm — WebAssembly pwn: memory corruption, sandbox escape
- pwn-aarch64-deep — ARM64/AArch64 deep exploitation (extends basics)
- pwn-mips64 — MIPS64 (extends existing MIPS)

### 2. Allocators (non-glibc)

- pwn-jemalloc — jemalloc internals and exploitation
- pwn-tcmalloc — tcmalloc internals and exploitation
- pwn-macos-malloc — macOS malloc zones (nano/tiny/small/large)
- pwn-android-scudo — Android Scudo allocator exploitation
- pwn-partitionalloc — Chrome PartitionAlloc (and MiraclePtr bypass)
- pwn-hardened-malloc — GrapheneOS hardened_malloc
- pwn-mimalloc — mimalloc exploitation
- pwn-dlmalloc — dlmalloc / legacy ptmalloc
- pwn-windows-segment-heap — Windows Segment Heap deep (extends existing)
- pwn-kernel-slab-allocators — SLAB/SLUB/SLOB comparison and targeting

### 3. Kernel breadth

- pwn-macos-kernel — macOS/XNU kernel exploitation (kext, IOKit)
- pwn-ios-kernel — iOS kernel exploitation (PAC, KTRR, PPL)
- pwn-android-kernel — Android kernel exploitation (GKI, SELinux)
- pwn-freebsd-kernel — FreeBSD kernel exploitation
- pwn-kaslr-bypass — KASLR bypass techniques
- pwn-kpti-bypass — KPTI/Meltdown mitigation bypass
- pwn-dirty-pagetable — Dirty Pagetable page-table technique
- pwn-kernel-data-only — Data-only kernel attacks
- pwn-kernel-info-leak — Kernel info-leak primitives
- pwn-usb-raw-gadget — USB stack exploitation (raw-gadget)
- pwn-wifi-driver — Wi-Fi driver / mac80211 exploitation
- pwn-block-layer — Block-layer / filesystem driver exploitation
- pwn-kctf — kernelCTF methodology and targets
- pwn-bpf-verifier — eBPF verifier bug exploitation (extends eBPF)
- pwn-msg-msg — msg_msg / System V IPC kernel primitives (extends kernel intro)
- pwn-kernel-heap-spray — Kernel heap spray and object replacement

### 4. Windows exploitation

- pwn-windows-rop — Windows x64 ROP deep (gadget finding, CFG-aware)
- pwn-windows-aslr-bypass — Windows ASLR bypass / info leaks
- pwn-windows-cfg-cet — Windows CFG/XFG/CET bypass
- pwn-windows-driver — Windows driver exploitation (HEVD-style, IOCTL)
- pwn-windows-pool — Windows kernel pool (paged/non-paged, Big Pool)
- pwn-windows-token-stealing — Token stealing and privesc primitives
- pwn-windows-iop — I/O ring and undocumented kernel primitives
- pwn-hyperv-escape — Hyper-V VM escape
- pwn-vbs-hvci — VBS/HVCI bypass
- pwn-ppl-wdac — PPL / WDAC / Code Integrity bypass
- pwn-windows-lfh-deep — LFH deep (extends Windows heap)

### 5. macOS / iOS userspace

- pwn-macos-arm64 — Apple Silicon (arm64e) exploitation
- pwn-macos-sandbox — macOS sandbox escape
- pwn-macos-hardened-runtime — Hardened runtime / library-validation bypass
- pwn-ios-pac — iOS PAC / PPL bypass
- pwn-ios-sandbox — iOS sandbox escape
- pwn-baseband — Baseband/firmware exploitation

### 6. Browser & JIT

- pwn-v8 — V8 exploitation deep (map/type confusion, typer, wasm)
- pwn-spidermonkey — SpiderMonkey exploitation
- pwn-jsc — JavaScriptCore exploitation
- pwn-jit-spray — JIT spraying and JIT-specific bugs
- pwn-browser-sandbox — Chrome/Firefox renderer sandbox escape
- pwn-browser-ipc-mojo — Browser IPC / Mojo exploitation
- pwn-browser-dom — DOM/Blink type confusion
- pwn-wasm-browser — WASM in-browser exploitation
- pwn-browser-gc — GC/rope/optimizer bug classes

### 7. Mitigations & bypass depth

- pwn-relro-bypass — RELRO/FULL RELRO bypass
- pwn-fortify-bypass — FORTIFY_SOURCE bypass
- pwn-cet-shadow-stack — CET/shadow-stack bypass (extends existing)
- pwn-cfi-bypass — CFI/CFG bypass (extends existing)
- pwn-sanitizer-bypass — ASan/MSan/UBSan bypass engineering (extends ASan)
- pwn-stack-protector-deep — Stack canary/SSP deep bypass
- pwn-safe-linking-deep — Safe-linking bypass (extends glibc mitigations)
- pwn-memory-tagging — Software memory tagging (HWASan/MTE) bypass

### 8. Exploitation primitives & techniques

- pwn-jop — Jump-Oriented Programming
- pwn-cop — Call-Oriented Programming
- pwn-dop — Data-Oriented Programming
- pwn-coop — Counterfeit Object-Oriented Programming
- pwn-data-only-attacks — Data-only attacks (no control flow)
- pwn-info-leak-primitives — Info-leak primitive taxonomy
- pwn-uninitialized-memory — Uninitialized-memory exploitation
- pwn-refcount-bugs — Reference-count / lifetime bugs
- pwn-null-deref — Null-pointer-deref exploitation (mmap_min_addr bypass)
- pwn-type-confusion — Type-confusion exploitation (general)
- pwn-vtable-hijack — vtable hijacking (extends C++)
- pwn-rop-automation — ROP-chain automation (ROPgadget/ropper scripting)
- pwn-shellcode-windows — Windows shellcode (PEB walk, syscalls)
- pwn-shellcode-arm — ARM/AArch64 shellcode
- pwn-shellcode-staged — Staged/multi-stage shellcode
- pwn-blinding — Blind exploitation without a binary/leak

### 9. Fuzzing & vulnerability discovery

- pwn-syzkaller — syzkaller kernel fuzzing
- pwn-structure-aware-fuzz — Structure-aware / grammar fuzzing
- pwn-differential-fuzz — Differential fuzzing
- pwn-fuzz-harness — Fuzzing harness design and corpus building
- pwn-oss-fuzz — OSS-Fuzz integration workflow
- pwn-coverage-instrumentation — Coverage instrumentation (sancov, LCOV, AFL)
- pwn-mutation-strategies — Mutation strategies and dictionaries
- pwn-hybrid-fuzz — Hybrid fuzzing (fuzz + concolic)

### 10. Symbolic / concolic execution

- pwn-z3-smt — Z3/SMT solving for exploitation
- pwn-klee — KLEE symbolic execution
- pwn-triton — Triton DBA framework
- pwn-manticore — Manticore symbolic execution
- pwn-concolic — Concolic execution (S2E, angr-deeper)
- pwn-angr-deep — angr advanced (extends existing angr)

### 11. DBI, emulation & analysis

- pwn-dynamorio — DynamoRIO instrumentation
- pwn-intel-pin — Intel PIN
- pwn-frida-exploit — Frida for exploitation and instrumentation
- pwn-qemu-tcg — QEMU TCG internals and custom devices
- pwn-instrumentation-frameworks — DBI framework comparison and use
- pwn-patch-diffing — Patch diffing for n-day (extends existing n-day)
- pwn-bindiff-diaphora — Binary diffing (BinDiff/Diaphora)
- pwn-decompiler-exploit-dev — Decompiler-assisted exploit development
- pwn-symbolic-diff — Symbolic program diffing

### 12. Real-world CVE exploitation

- pwn-sudo-baron-samedit — CVE-2021-3156 sudo heap overflow
- pwn-pwnkit — CVE-2021-4034 polkit pkexec
- pwn-dirty-cow — CVE-2016-5195 Dirty COW
- pwn-looney-tunables — CVE-2023-4911 glibc ld.so
- pwn-overlayfs-escape — CVE-2021-3493 / CVE-2023-0386 overlayfs
- pwn-nftables-cve — CVE-2023-32233 / CVE-2024-1086 nf_tables
- pwn-netfilter-cve — CVE-2022-0185 / CVE-2022-2588 netfilter
- pwn-io-uring-cve — io_uring CVEs
- pwn-kernel-cve-roundup — Recent Linux kernel CVEs (Sequoia, etc.)
- pwn-windows-cve-roundup — Windows CVEs (CLFS, PrintNightmare, etc.)
- pwn-eternalblue — MS17-010 EternalBlue
- pwn-zerologon — CVE-2020-1472 Zerologon
- pwn-container-escape-cve — runc/Docker escape CVEs
- pwn-k8s-escape-cve — Kubernetes escape CVEs

### 13. VM / hypervisor & sandbox escape

- pwn-qemu-escape — QEMU VM escape (device emulation bugs)
- pwn-vmware-escape — VMware Workstation/ESXi escape
- pwn-virtualbox-escape — VirtualBox escape
- pwn-firecracker-escape — Firecracker/microVM escape
- pwn-gvisor-escape — gVisor sandbox escape
- pwn-chrome-sandbox — Chrome sandbox escape
- pwn-firefox-sandbox — Firefox content sandbox escape
- pwn-nsjail-seccomp — seccomp/nsjail escape (extends existing)

### 14. Language & runtime exploitation

- pwn-cpython-internals — CPython internals exploitation (PyObject, refcount)
- pwn-jvm — JVM exploitation (bytecode, JIT, unsafe)
- pwn-dotnet-runtime — .NET runtime exploitation
- pwn-php-internals — PHP internals memory corruption (Zend)
- pwn-lua — Lua interpreter exploitation
- pwn-ruby — Ruby VM exploitation
- pwn-perl — Perl interpreter exploitation
- pwn-objective-c-swift — Objective-C/Swift exploitation
- pwn-nodejs-runtime — Node.js/V8-runtime native exploitation
- pwn-go-runtime-deep — Go runtime deep (extends Rust/Go)
- pwn-rust-unsafe — Rust unsafe/UB exploitation (extends Rust/Go)

### 15. Hardware & embedded

- pwn-firmware-exploit — Firmware exploitation (embedded ROP)
- pwn-iot-exploitation — IoT device exploitation workflow
- pwn-automotive-ecu — Automotive ECU / CAN exploitation
- pwn-fpga-bitstream — FPGA/bitstream attacks
- pwn-embedded-trustzone — TrustZone / secure-world exploitation

### 16. Side channels & transient execution

- pwn-spectre — Spectre exploitation and gadgets
- pwn-meltdown — Meltdown and variants
- pwn-transient-execution — Transient-execution attack taxonomy
- pwn-cache-timing — Cache-timing side channels
- pwn-side-channel-assisted — Side-channel-assisted exploitation
- pwn-microarch-attacks — Microarchitectural attack primitives (MDS, etc.)

### 17. Remote / network exploitation

- pwn-remote-exploitation — Remote exploitation methodology
- pwn-network-protocol — Network-protocol parsers (HTTP/DNS/SMB parsing bugs)
- pwn-pre-auth-rce — Pre-auth RCE classes and targets
- pwn-http-parser-bugs — HTTP parser differential/memory bugs
- pwn-exploit-reliability — Exploit reliability and brute-force (fork servers)

### 18. CTF recipes — additional

- pwn-heap-ctf-recipe — Heap CTF recipe index
- pwn-kernel-ctf-recipe — Kernel CTF recipe index
- pwn-browser-ctf-recipe — Browser/JIT CTF recipe index
- pwn-vm-escape-ctf — VM-escape CTF recipe
- pwn-misc-ctf — Misc pwn (custom VMs, interpreters, weird ABIs)
- pwn-asan-ctf — ASan-instrumented CTF challenges

### 19. Misc / exotic

- pwn-compiler-miscompilation — Compiler miscompilation bugs
- pwn-memory-safety-model — Memory-safety model and taxonomy
- pwn-gc-bugs — GC/allocator interaction bugs
- pwn-stack-migration — Stack migration/clash deep (extends existing)
- pwn-return-to-csu-deep — ret2csu / ret2dlresolve engineering (extends existing)
- pwn-partial-relro — Partial-RELRO / GOT overwrite deep (extends existing)
- pwn-nonx-stack — Non-exec stack bypass (extends NX)
- pwn-exploit-dev-workflow — End-to-end exploit-dev workflow / toolchain
- pwn-symbol-restoration — Symbol restoration / binary recovery for stripped targets
- pwn-ctf-remote-harness — Remote harness interaction and reliability

### Summary

## reversing

Total unique proposed lessons: **179**

### Architectures & ISA breadth

- reversing-asm-arm64 — ARM64/AArch64 ассемблер вручную (registers, AAPCS64, addressing modes, NEON/SVE)
- reversing-asm-arm32 — ARM32/Thumb и режимы переключения (Thumb-2, IT-блоки)
- reversing-riscv-advanced — RISC-V advanced: расширения, компрессия, привилегированные режимы
- reversing-powerpc — Реверс PowerPC/POWER (big-endian, AltiVec, ABI)
- reversing-sparc — Реверс SPARC (register windows, delay slots)
- reversing-mips-delay-slots — MIPS advanced: branch delay slots, MIPS16/microMIPS, HI/LO
- reversing-s390x — Реверс IBM z/Architecture (s390x): CISC, instructions formats
- reversing-avr-8bit — Реверс AVR / 8-bit MCU (ATmega, Harvard architecture, GPIO)
- reversing-xtensa — Реверс Xtensa (ESP32) и проприетарные DSP-ядра
- reversing-superh — Реверс SuperH (SH-2/SH-4) — Sega/embedded
- reversing-6502-8bit — Реверс 6502/Z80 и ретро-платформ (NES/C64/Game Boy)
- reversing-endianness-pitfalls — Endianness, unaligned access и ловушки чтения структур
- reversing-fpu-simd — Векторные/FPU-инструкции: SSE/AVX, NEON, SVE в дизассемблере
- reversing-gpu-shaders — Реверс GPU-шейдеров и compute-ядер (SPIR-V, DXBC, PTX)

### Executable / container formats

- reversing-coff-omf — Реверс COFF/OMF/ar и объектных файлов (.obj/.o/.lib)
- reversing-intel-hex-srec — Форматы прошивок Intel HEX, SREC, TI-TXT и конвертация
- reversing-dyld-shared-cache — dyld shared cache: извлечение и анализ системных библиотек macOS/iOS
- reversing-fat-binaries — Fat/universal binaries (Mach-O fat, lipo) и многоплатформенные образы
- reversing-dex-internals — DEX изнутри: заголовки, пулы, bytecode, multidex, compact DEX
- reversing-oat-art — Android OAT/ART: AOT-компиляция, vdex, ART-байткод и профили
- reversing-apk-structure — Анатомия APK/AAB/IPA: манифест, ресурсы, split-APK, подписи
- reversing-pe-net-metadata — Метаданные .NET в PE: CLR-заголовки, #~ streams, tokens
- reversing-msi-installers — Реверс MSI/InstallShield/NSIS/Inno-установщиков
- reversing-elf-notes-abi — ELF notes, GNU properties, ABI-теги и их роль
- reversing-wasm-advanced — WASM advanced: компонентная модель, WIT, SIMD, memory64
- reversing-archive-formats — Архивные/контейнерные форматы в malware (zip-крипт, 7z, CAB, RAR)
- reversing-pdf-js-reversing — Реверс вредоносного PDF (JS, шрифты, уязвимые фильтры)
- reversing-office-macros — Реверс VBA/макросов и OLE-структур (docx/xlsm, VBA stomping)

### Language runtimes & bytecode

- reversing-v8-bytecode — Реверс V8: Ignition bytecode, TurboFan IR, snapshots, code cache
- reversing-jsc-spidermonkey — Реверс JavaScriptCore/SpiderMonkey и обфускации JS-движков
- reversing-hermes-flutter — Реверс Hermes bytecode (React Native) и Dart/Flutter AOT
- reversing-dotnet-aot-readytorun — .NET ReadyToRun/AOT и native-образы (R2R, NativeAOT)
- reversing-graalvm-native — Реверс GraalVM native-image (substrate)
- reversing-luajit-bytecode — Реверс LuaJIT bytecode и trace-компиляции
- reversing-beam-erlang — Реверс Erlang/Elixir BEAM-байткода
- reversing-yarv-ruby — Реверс Ruby YARV bytecode (iseq) и обфускаций
- reversing-php-opcode — Реверс PHP opcode/opcache и обфусцированного PHP
- reversing-perl-python-advanced — Реверс Perl-байткода и продвинутых Python-обфускаций (pyarmor)
- reversing-kotlin-native — Реверс Kotlin/Native и Kotlin Multiplatform
- reversing-swift-demangle-advanced — Swift advanced: mangling, метаданные типов, протоколы witness tables
- reversing-dlang-nim-zig — Реверс D/Nim/Zig/Odin-бинарников
- reversing-haskell-ocaml — Реверс Haskell/OCaml (thunks, runtime, GHC-ABI)
- reversing-ada-fortran — Реверс Ada/Fortran и научного HPC-кода
- reversing-jvm-bytecode-deep — уже есть; добавить invokedynamic, method handles, StackMapTable, module-info
- reversing-python-bytecode — уже есть; добавить .pyc версии, marshal, bytecode VM-обфускации (pyc)

### Windows internals

- reversing-win-syscalls-ssn — Windows syscalls: SSN, stub-паттерны, direct/indirect syscalls
- reversing-win-peb-teb — PEB/TEB, LDR-структуры и ручной обход загрузчика
- reversing-win-api-hooking — Реверс хуков: IAT/inline/veh/trampoline и их снятие
- reversing-win-com-rpc — Реверс COM/RPC/DCOM: IDL, интерфейсы, MIDL-стабы
- reversing-win-pdb-dwarf — PDB/DWARF, восстановление символов, публичные символы MS
- reversing-win-seh-cpp — Реверс C++-исключений: SEH, EH unwind, RTTI, vtable
- reversing-win-drivers-irp — Реверс Windows-драйверов: IRP, dispatch, IOCTL-фаззинг
- reversing-win-registry-services — Реверс служб, планировщика задач и autorun-механизмов
- reversing-win-signed-code — Authenticode, каталоги, обход проверки подписи

### macOS / iOS / Apple

- reversing-macos-codesign-entitlements — Код-сайнинг, entitlements, hardened runtime macOS
- reversing-objc-runtime — Objective-C runtime: objc_msgSend, class-метаданные, swizzling
- reversing-ios-arm64e-pac — ARM64e и Pointer Authentication (PAC) на iOS
- reversing-ios-xnu-kernel — Реверс ядра XNU и kext/dext
- reversing-ios-jailbreak-detect — Jailbreak/root-detection и её обход (iOS)
- reversing-ios-appattest — App Attest/DeviceCheck и целостность приложения
- reversing-macos-notarization — Notarization/Gatekeeper и обход нотаризации

### Android / mobile

- reversing-android-root-detect — Root/emulator/frida-detection на Android и её обход
- reversing-android-smali-dex-edit — Правка smali/DEX и repackaging (apktool, baksmali)
- reversing-android-packers — Android-упаковщики (Bangcle, Legu, Tencent) и распаковка
- reversing-android-dynamic-instrumentation — Динамическая инструментация Android (frida, xposed, zygisk)
- reversing-android-native-symbols — Восстановление символов .so, JNI-регистрация, anti-hook
- reversing-mobile-tls-pinning — SSL-pinning и её обход (Android/iOS)
- reversing-mobile-keystore — Android Keystore / iOS Keychain: извлечение секретов
- reversing-ios-ipa-swiftui — Реверс SwiftUI/Combine приложений

### Malware analysis (families & tradecraft)

- reversing-c2-beacon-config — Извлечение конфигов C2-биконов (Cobalt Strike, Sliver, Mythic)
- reversing-malleable-c2 — Malleable C2-профили и реверс C2-протокола
- reversing-shellcode-loaders — Реверс загрузчиков shellcode (donut, sRDI, PE2Shellcode)
- reversing-process-injection — Реверс техник инъекций (hollowing, APC, early-bird, mapping)
- reversing-powershell-deobfuscation — Деобфускация PowerShell (Invoke-Obfuscation, AMSI-обход)
- reversing-dotnet-malware — Реверс .NET-малвари (dnSpy, ConfuserEx, стабы)
- reversing-ransomware-family — Реверс ransomware-семейств и анализ крипто-схемы
- reversing-banker-infostealer — Реверс infostealer/банкеров (webinjects, hooking)
- reversing-botnet-loader — Реверс botnet-загрузчиков и DGA (domain generation algorithms)
- reversing-apt-tooling — Реверс APT-инструментария и TTP-маппинг (MITRE ATT&CK)
- reversing-lolbins — Реверс LOLBins/lofl и abusе встроенных утилит
- reversing-malware-anti-analysis — Malware anti-analysis: anti-debug/anti-VM/anti-sandbox в бою
- reversing-unpacking-vmprotect-malware — Распаковка VMProtect/Themida-малвари
- reversing-config-extraction-yara — Извлечение IOC и генерация YARA/Sigma из бинарника
- reversing-memory-forensics — Реверс через дампы памяти (Volatility, in-memory malware)
- reversing-firmware-malware — Реверс прошивочных имплантов (LoJax, BlackLotus/UEFI)
- reversing-wiper-destructive — Реверс вайперов и деструктивного ПО
- reversing-ransomware-key-recovery — уже есть  reversing-ransomware ;   добавить восстановление ключей и NoCry-подходы

### Dynamic analysis, debugging & tracing

- reversing-gdb-python-api — GDB Python API и автоматизация отладки
- reversing-windbg-extensions — WinDbg extensions и скриптование (pykd, JS)
- reversing-ftrace-perf-uprobes — Реверс через ftrace/perf/uprobes/USDT на Linux
- reversing-ebpf-tracing-tools — bpftrace/bcc для реверса и трассировки
- reversing-snapshot-fuzzing — Snapshot-фаззинг (nyx, kAFL) и его применение в реверсе
- reversing-ptrace-advanced — ptrace advanced: syscall-stops, PTRACE_SEIZE, remote syscalls
- reversing-wine-wsl — Реверс в Wine/WSL/эмуляторах Windows API
- reversing-core-dump-analysis — Анализ core dump и post-mortem реверс
- reversing-live-memory-patching — Runtime-патчинг в памяти и горячие правки
- reversing-instrumentation-frameworks — Сравнение Frida/DynamoRIO/Pin/QBDI/eBPF по задачам
- reversing-intel-pt — добавить decoding (libipt), perf-интеграцию, ARM ETM-трейсы в проде

### Static analysis, decompilation & tooling

- reversing-binary-ninja — Binary Ninja: BNIL, HLIL, скриптование API
- reversing-hexrays-microcode — Hex-Rays microcode: устройство и оптимизации
- reversing-ghidra-pcode-emulator — Эмулятор P-Code в Ghidra для деобфускации
- reversing-decompiler-internals — Внутренности декомпилятора: SSA, variable recovery, type inference
- reversing-type-recovery — Восстановление типов и структур (Retypd, HexRays)
- reversing-signature-flirt-lumina — FLIRT/Lumina/FunctionID: сигнатуры и matching
- reversing-bindiff-diaphora-advanced — Продвинутый бинарный диффинг (BinDiff, Diaphora, patch-diff)
- reversing-capstone-keystone — Программный дизасм/ассембл: Capstone, Keystone, Unicorn как стек
- reversing-radare2-scripting — Автоматизация radare2/rizin: r2pipe, сценарии
- reversing-cfg-recovery — Восстановление графа потока управления (CFG) и его сложности
- reversing-symbolic-exec-recipe-advanced — уже есть  reversing-symbolic-recipe ;   добавить масштабные binary-задачи и symcc

### Symbolic execution, fuzzing & program analysis

- reversing-fuzzing-aflpp — Coverage-guided фаззинг: AFL++ (persistent, cmplog, custom mutators)
- reversing-fuzzing-libfuzzer-honggfuzz — libFuzzer/Honggfuzz и интеграция с sanitizers
- reversing-hybrid-fuzzing — Гибридный фаззинг (concolic + coverage, symcc, QSYM)
- reversing-directed-fuzzing — Направленный фаззинг и достижение конкретных путей
- reversing-structure-aware-fuzzing — Structure-aware / grammar-фаззинг (protobuf, JSON, форматы)
- reversing-kernel-fuzzing — Фаззинг ядра (syzkaller, KASAN, KCOV)
- reversing-symbolic-miasm-bap — Miasm/BAP/angr-альтернативы и сравнение IR
- reversing-klee-s2e — KLEE/S2E и символьное исполнение системного уровня
- reversing-program-slicing — Программные срезы и data-flow analysis для реверса
- reversing-triton-advanced — Triton advanced: AST-символика, taint, callback-API

### Anti-analysis, obfuscation, packers & protectors

- reversing-anti-disassembly — Anti-disassembly: overlapping/junk bytes, bogus flow, opaque
- reversing-string-obfuscation — Строковые обфускации: stack-strings, XOR, API hashing
- reversing-ollvm-tigress — OLLVM/Tigress/Hikari и деобфускация их выходов
- reversing-movfuscator — Movfuscator и mov-only деобфускация
- reversing-virtualization-custom — Кастомные VM-протекторы: девиртуализация handler-ов
- reversing-tls-callbacks — TLS-callbacks, DllMain-трюки и раннее исполнение
- reversing-self-decrypting-code — Саморасшифровывающийся код и многослойные стабы
- reversing-metamorphism — Метаморфизм/полиморфизм и нормализация кода
- reversing-jit-obfuscation — JIT-обфускация (VMProtect-подобная в runtime)
- reversing-cfg-guard-cet — CFG/Control-Flow Guard и Intel CET как препятствие реверсу
- reversing-license-schemes — Лицензионные схемы: hardware-id, offline-активация, floating license
- reversing-commercial-protectors — добавить пошаговую распаковку каждого (Themida/Enigma/Obsidium)

### Kernel, hypervisor & low-level

- reversing-linux-kernel-modules — Реверс LKM: symbol-версии, kprobes, ftrace-hooks
- reversing-rootkit-techniques — Реверс руткитов: DKOM, SSDT, syscall-патчинг, eBPF-руткиты
- reversing-macos-kexts — Реверс kext/dext macOS
- reversing-hypervisor-esxi — Реверс ESXi/KVM/Hyper-V и гипервизорных руткитов
- reversing-smm-uefi — Реверс SMM/UEFI DXE-драйверов и прошивочных имплантов
- reversing-trustzone-tee — Реверс TrustZone/TEE (OP-TEE, Trusty) и secure world
- reversing-secure-boot-chain — Реверс цепочки доверия: Secure Boot, измеряемая загрузка
- reversing-microcode-firmware — Реверс микрокода/CPU-микроархитектуры (ME/PSP)

### Firmware, embedded & hardware

- reversing-bootloader-uboot — Реверс загрузчиков (U-Boot, coreboot, Barebox)
- reversing-rtos-zephyr-vxworks — Реверс Zephyr/VxWorks/ThreadX (кроме FreeRTOS)
- reversing-embedded-linux-iot — Реверс embedded-Linux и IoT-прошивок (buildroot, openwrt)
- reversing-fpga-bitstream — Реверс FPGA-битстримов и HDL (Verilog/VHDL)
- reversing-chip-decapping — Инвазивный реверс: decapping, die-shot, ROM-извлечение
- reversing-baseband-modem — Реверс baseband/модемной прошивки
- reversing-obd-j1939-doip — Реверс автомобильных протоколов сверх CAN/UDS (J1939, DoIP, FlexRay, LIN)
- reversing-ics-scada-protocols — Реверс ICS/SCADA-протоколов (Modbus, DNP3, IEC 61850, EtherNet/IP)
- reversing-radio-sdr-protocols — Реверс радио-протоколов (кроме базового SDR): LoRa, Zigbee, BLE
- reversing-smartcard-emv — Реверс смарт-карт/EMV (APDU, JavaCard, GlobalPlatform)

### Protocols, formats & data

- reversing-json-xml-binary — Реверс бинарных сериализаций: msgpack, CBOR, BSON, Avro, ASN.1
- reversing-game-netcode — Реверс игрового netcode и реплеев
- reversing-db-file-formats — Реверс файлов БД и хранилищ (SQLite, LevelDB, LMDB, ESE)
- reversing-custom-vm-formats — Реверс кастомных контейнеров/VM-образов и скриптовых байткодов
- reversing-messaging-protocols — Реверс MQTT/AMQP/CoAP/Kafka-протоколов
- reversing-bluetooth-l2cap — Реверс BLE/L2CAP/GATT-стеков и трейсинга
- reversing-protocols — добавить TLS-record, QUIC, HTTP/2-3 на уровне бинарного парсинга

### Games, DRM & anti-cheat

- reversing-unity-il2cpp — Реверс Unity IL2CPP и Mono-игр (Il2CppDumper)
- reversing-unreal-engine — Реверс Unreal Engine (пакеты, Blueprints, UAsset)
- reversing-steam-drm — Реверс Steam DRM/Steamworks и обход
- reversing-eac-battleye — Реверс ядерных античитов (EAC, BattlEye) — user/kernel
- reversing-anticheat-emulation — Эмуляция античит-проверок и обход в песочнице
- reversing-cheat-driver — Реверс и анализ читерских драйверов
- reversing-denuvo-advanced — Denuvo advanced: VM-девиртуализация и anti-debug в бою

### AI / ML & emerging

- reversing-ml-models — Реверс ML-моделей (ONNX, TFLite, safetensors, PyTorch)
- reversing-model-extraction — Извлечение модели/весов и watermarking
- reversing-neural-obfuscation — Обфускация через нейросети и её реверс
- reversing-quantum-binaries — Реверс квантовых/FPGA-гибридных бинарников
- reversing-supply-chain-artifacts — Реверс артефактов supply-chain (npm/pypi/maven, typosquat)

### Methodology, tooling & workflow

- reversing-workflow-automation — Автоматизация реверс-workflow (headless, CI, batch)
- reversing-collaboration-knowledge — Совместный реверс: базы знаний, symbol-sharing, аннотации
- reversing-legal-ethics — Правовые/этические границы реверса и ответственное раскрытие
- reversing-ctf-pwn-recon — Реверс как recon для pwn: определение митигаций и векторов
- reversing-compiler-optimizations — Понимание оптимизаций компилятора (inlining, LTO, vectorization)
- reversing-devirtualization-languages — Девиртуализация интерпретаторов (Python/JS/PHP VM)
- reversing-time-constrained — Реверс под давлением времени (CTF/IR): приоритизация
- reversing-reporting-remediation — Отчётность по реверс-находкам и ремедиация
- reversing-embedded-debug-probes — OpenOCD/Black Magic/J-Link и скриптовый реверс на живом железе
- reversing-side-channel-firmware — Side-channel/glitching в реверсе прошивок (кроме базового)
- reversing-hardware-schematic-recon — Recon по плате: чтение схем, datasheet, pinout

### Ranked TOP 25 gaps (reversing)

## crypto

Total unique proposed lessons: **135**

### Classical & historical

- crypto-classical-polybius-bifid — Polybius square, Bifid/Trifid, Nihilist, ADFGX/ADFGVX
- crypto-classical-transposition-deep — Транспозиции: route, Myszkowski, двойная, turning grille, Scytale
- crypto-classical-multi-table — Porta, Beaufort, Gronsfeld, Autokey, running-key, VIC-шифр
- crypto-classical-homophonic-book — Гомофонические подстановки и book/NULL-шифры
- crypto-classical-solitaire-chaocipher — Solitaire (Pontifex), Chaocipher, Bazeries
- crypto-classical-statistics — Kasiski, индекс совпадений, Friedman, авточастотный анализ
- crypto-historical-machines — Lorenz SZ40/42, Purple, Colossus, SIGSALY, Navajo code talkers
- crypto-classical-deep — уже есть;   добавить автоматизацию и скрипты (pycipher, simon singh)

### Symmetric ciphers & cryptanalysis families

- crypto-des-3des-deep — DES/3DES: S-boxes, ключевое расписание, differential на DES
- crypto-aes-structure — AES изнутри: S-box/GF(2^8), key schedule, MixColumns-математика
- crypto-impossible-boomerang — Impossible differential, boomerang, rectangle-атаки
- crypto-truncated-differential — Truncated/дифференциально-линейный и zero-correlation криптоанализ
- crypto-algebraic-cube — Алгебраические и cube-атаки (Gröbner, SAT-based)
- crypto-slide-rotational — Slide, rotational и reflection-атаки на блочные шифры
- crypto-related-key-attacks — Related-key и known/chosen-key атаки
- crypto-aes-key-schedule-attacks — Атаки на расписание ключей (AES/DES)
- crypto-lightweight-ciphers — Легковесные шифры: PRESENT, Speck/Simon, GIFT, ASCON
- crypto-regional-ciphers — Национальные шифры: SM4, GOST/Магма, ARIA, Camellia, SEED
- crypto-block-cipher-modes-siv — Nonce-misuse-resistant режимы: SIV, GCM-SIV, OCB, EAX
- crypto-tweakable-deep — Tweakable-шифры и конструкция (Threefish, XEX/Adiantum)
- crypto-feistel-advanced — Feistel advanced: unbalanced, Luby-Rackoff, тип-1/2/3

### Stream ciphers & PRNG engineering

- crypto-gsm-a5-3g — Мобильные потоковые: A5/1, A5/2, KASUMI, SNOW 3G, ZUC
- crypto-lfsr-e0-trivium — E0 (Bluetooth), Trivium, Grain, SNOW, корреляционные атаки
- crypto-algebraic-attacks-stream — Быстрая корреляция, алгебраические и guess-and-determine атаки
- crypto-prng-glibc-xorshift — glibc rand, xorshift, PCG, splitmix и восстановление состояния
- crypto-drbg-backdoors — DRBG: CTR-DRBG/Hash-DRBG, Dual_EC_DRBG и бэкдоры
- crypto-rng-entropy — Энтропия, источники случайности, /dev/urandom, seed-recovery
- crypto-hardware-rng — Аппаратные RNG (RDSEED, TRNG) и их уязвимости
- crypto-rng-cves — Реальные RNG-баги (Debian OpenSSL, Android SecureRandom, ROCA)
- crypto-mt19937-deep — уже есть;   добавить MT-на-нативных (C++/PHP) и частичные выходы

### Hashes, MACs & password hashing

- crypto-sha2-sha3-internals — SHA-2/SHA-3 изнутри: compression, permutation, rate/capacity
- crypto-blake-ripemd-whirlpool — BLAKE2/BLAKE3, RIPEMD, Whirlpool, SM3, GOST-hash
- crypto-hash-preimage-herding — Preimage/second-preimage, herding, multicollisions
- crypto-hash-mitm — Meet-in-the-middle и birthday-атаки на хэши
- crypto-mac-wc-umac — Wegman-Carter, UMAC, KMAC и универсальное хэширование
- crypto-aead-gmac-poly1305-deep — GMAC/Poly1305 изнутри и подделка (forbidden/partitioning oracle)
- crypto-password-hashing-engineering — Инженерия KDF: cost-параметры, pepper, параллелизм, Argon2 modes
- crypto-hash-forge — уже есть;   добавить chosen-prefix collision и PDF/PS-эксплойты

### RSA (advanced/implementation)

- crypto-rsa-roca-bateman — ROCA (CVE-2017-15361), De Laurentis, Bateman и weak-key detection
- crypto-rsa-oaep-manger-deep — OAEP/Manger изнутри и полный chain восстановления
- crypto-rsa-signature-forgery — Подделка подписей: Bleichenbacher '06, e=3, PKCS#1 v1.5
- crypto-rsa-crt-fault-deep — Атаки по ошибкам RSA-CRT (Bellcore) и их детект
- crypto-rsa-side-channel-remote — Удалённые side-channel атаки на RSA (timing, Manger oracle)
- crypto-rsa-keygen-mistakes — Ошибки генерации ключей: shared primes, слабая энтропия, gcd-batch
- crypto-rsa-coppersmith-deep — уже есть;   добавить multivariate Coppersmith и modular-корни

### ECC, DH & discrete log

- crypto-ecc-anomalous-smart — Аномальные кривые и атака Smart/Semaev
- crypto-ecc-mov-freyruck — MOV/Frey-Rück и спаривательные атаки на ECDLP
- crypto-ecc-twist-attacks — Twist-атаки, invalid-curve в ECDH-реализациях, point validation
- crypto-ecc-fault-attacks — Fault-атаки на ECC (safe-error, C-safe-error)
- crypto-secp256k1-bitcoin — secp256k1 и Bitcoin-специфика (uncompressed/compressed, Taproot)
- crypto-dh-parameter-validation — Валидация параметров DH: safe primes, q-order, RFC-ошибки
- crypto-discrete-log-advanced — Продвинутый DLP: NFS/index calculus, function fields
- crypto-ecdsa-advanced — уже есть;   добавить curve-recovery из сигнатур и biased-nonce advanced

### Lattices, number theory & hard problems

- crypto-lattice-tooling-fpylll — fpylll/Sage-инструменты: BKZ-параметры, reduction-практика
- crypto-knapsack-subset-sum — Knapsack/подмножество-суммы и LLL-атаки (Merkle-Hellman)
- crypto-hidden-number-problem — Hidden Number Problem, ECDSA/DH через LLL
- crypto-babai-cvp — Babai rounding/nearest plane, CVP/SVP-практика
- crypto-modular-square-roots — Извлечение квадратных корней, Tonelli-Shanks, p≡3 mod 4
- crypto-nt-probability-stats — Вероятность/статистика для крипто (birthday, Марков, энтропия)
- crypto-nt-p-adic — p-адические числа, подъём Гензеля и их применение
- crypto-nt-elliptic-pairing-math — Weil/Tate-спаривания: математика и вычисление

### Protocols (real-world implementations)

- crypto-webauthn-fido2 — WebAuthn/FIDO2/passkeys: attestation, CBOR, COSE, origin binding
- crypto-oauth-oidc-crypto — OAuth2/OIDC: JWT/JWE, PKCE, ID-token, key confusion
- crypto-saml-crypto — SAML: XML-DSig, canonicalization, XML-signature wrapping
- crypto-dnssec-dns-crypto — DNSSEC: RRSIG, DS-chain, NSEC/NSEC3, zone-walking
- crypto-email-crypto-dkim — SPF/DKIM/DMARC/ARC и S/MIME/PGP-подписи
- crypto-ipsec-ike — IPsec/IKEv2: SA, PSK-vs-cert, известные ошибки
- crypto-openvpn-wireguard-advanced — OpenVPN/WireGuard advanced: обфускация, ротация ключей
- crypto-bluetooth-ble-pairing — Bluetooth/BLE pairing: LE Legacy, LE Secure Connections, MITM
- crypto-emv-payment — EMV/платёжные протоколы: ARQC, DDA/CDA, contactless-атаки
- crypto-nfc-mifare — MIFARE/ISO14443 crypto (Crypto1, DESFire) и клонирование
- crypto-tls13-quic — TLS 1.3/QUIC: 0-RTT, PSK, ECH, key-update, tlsfuzzer
- crypto-tls-real-bugs — Реальные баги: ROBOT, DROWN, FREAK, Sweet32, Raccoon, Lucky13
- crypto-tor-onion-crypto — Tor: onion-service crypto, hidden-service v3, rendezvous
- crypto-totp-hotp-scram — TOTP/HOTP, SCRAM, Digest/NTLM и их подделка
- crypto-hsm-pkcs11 — HSM/PKCS#11/TPM: интерфейсы, атаки, key-attestation
- crypto-age-minisign — Современные утилиты: age, minisign, signify, NaCl/libsodium
- crypto-tls-attacks — уже есть;   добавить certificate-transparency/OCSP/ACME

### ZK, MPC, FHE & advanced constructions

- crypto-bulletproofs-range-proofs — Bulletproofs, range-proofs, set-membership
- crypto-halo2-marlin-sonic — Halo2/Marlin/Sonic и рекурсивные SNARK-ы
- crypto-zk-rollup-evm — zkEVM, zk-rollups и доказательства исполнения
- crypto-fiat-shamir-weak — Weak Fiat-Shamir и атаки на non-interactive proofs
- crypto-garbled-circuits-ot — Garbled circuits, oblivious transfer, PSI
- crypto-mpc-in-the-head — MPC-in-the-head, Ligero/Aurora и пост-квантовые ZK
- crypto-mpc-2pc-libraries — 2PC/MPC-библиотеки (MP-SPDZ, ABY) и их уязвимости
- crypto-threshold-signatures — Threshold-подписи: FROST, GG18/GG20, DKG-протоколы
- crypto-fhe-schemes-deep — BFV/BGV/CKKS/TFHE изнутри: шум, bootstrapping, параметры
- crypto-fhe-attacks — Атаки на FHE/гомоморфные схемы и параметрические ошибки
- crypto-threshold-mpc — уже есть;   добавить secure-aggregation и federated-crypto

### Post-quantum & quantum

- crypto-pq-falcon-rainbow — Falcon, Rainbow/HFE (multivariate) и их атаки
- crypto-pq-bike-hqc — BIKE/HQC (code-based, не McEliece) и NIST-финалисты
- crypto-pq-sidh-attack — Атака Кастана на SIDH/SIKE и её последствия
- crypto-pq-lattice-attacks — Атаки на LWE/Kyber: primal/dual, BKZ, sparse-secret
- crypto-pq-hybrid-migration — Гибридный обмен ключей и миграция на PQC в TLS/SSH
- crypto-pq-ctf — PQ-задачи на CTF: Kyber/Dilithium/NTRU в бою
- crypto-quantum-gates-circuits — Квантовые гейты/схемы, Qiskit, квантовое моделирование
- crypto-quantum-error-correction — Квантовая коррекция ошибок и отказоустойчивость
- crypto-quantum-annealing — Квантовый отжиг и его крипто-последствия
- crypto-shor-grover — уже есть;   добавить ресурсные оценки и практические квантовые атаки

### Side-channels (hardware & microarchitectural)

- crypto-sidechannel-dpa-cpa — DPA/CPA advanced: preprocessing, template attacks
- crypto-sidechannel-ml — ML-based side-channel (нейросети на трассах)
- crypto-sidechannel-acoustic-thermal — Акустические/тепловые/оптические утечки
- crypto-sidechannel-glitching — Voltage/clock/EM glitching, laser fault injection
- crypto-sidechannel-rowhammer — Rowhammer, DRAM-утечки и крипто-последствия
- crypto-sidechannel-spectre-meltdown — Spectre/Meltdown/Hertzbleed/Plundervolt в крипто
- crypto-sidechannel-remote-timing — Удалённые timing-атаки на TLS/сеть (Lucky13, Raccoon)
- crypto-sidechannel-coldboot-dma — Cold-boot, DMA-атаки и извлечение ключей из памяти
- crypto-sidechannel-tvla — TVLA (test vector leakage assessment) и оценка утечек
- crypto-cache-attacks — уже есть;   добавить remote-cache и cloud-co-residency

### Blockchain & cryptocurrency crypto

- crypto-bitcoin-schnorr-musig — Schnorr/BIP340, Taproot, MuSig, threshold-schnorr
- crypto-multisig-scripts — Multisig, P2SH/P2WSH, скрипты и их баги
- crypto-wallet-cracking — Взлом кошельков: weak seeds, keystore, brainwallet
- crypto-ethereum-keystore — Ethereum keystore/scrypt, BIP44-пути, HD-derivation
- crypto-smart-contract-crypto — Криптография смарт-контрактов (keccak, ecrecover, signatures)
- crypto-blockchain-forensics — Blockchain-форензика и deanonymization
- crypto-vanity-address-attacks — Vanity-адреса, слабая энтропия и коллизии
- crypto-hd-wallets — уже есть;   добавить multi-chain derivation и hardware-wallet-атаки

### Encoding, tooling & engineering

- crypto-tooling-sage — SageMath/PARI-GP/sympy/gmpy2 для крипто-CTF
- crypto-tooling-pycryptodome — Практические библиотеки: pycryptodome, cryptography, pyca, z3
- crypto-tooling-cracking-rules — hashcat-правила, маски, PRINCE, distributed/GPU-кластеры
- crypto-tooling-fpga-hpc — FPGA/HPC-крекинг и облачный GPU (crackstation, cloud)
- crypto-encoding-esoteric — Esoteric-кодировки: Morse, Baudot, Punycode, UTF-7, esolang
- crypto-constant-time — Constant-time программирование и предотвращение timing-утечек
- crypto-secure-coding — Безопасное использование crypto-API (CWE-327/328/330, misuse)
- crypto-key-management — Управление ключами: rotation, escrow, derivation, secret-management
- crypto-static-analysis-crypto — Поиск крипто-ошибок в коде (semgrep, CryptoGuard, CodeQL)
- crypto-fips-standards — NIST/FIPS/SP800, сертификация и соответствие
- crypto-ctf-recipe — CTF-рецепты крипто: классификация задач и стратегии
- crypto-drive-css-aacs — DRM-крипто: DVD CSS, AACS, HDCP и их взлом
- crypto-satellite-tetra — Спутниковые/радио-крипто: TETRA, DMR, DVB, GPS-спуфинг
- crypto-post-crypto-world — Крипто-агильность и подготовка к квантовому переходу
- crypto-hardware-tokens — Аппаратные токены (YubiKey, Nitrokey) и их крипто-интерфейсы
- crypto-formal-verification — Формальная верификация крипто-протоколов (ProVerif, Tamarin)
- crypto-protocol-design-pitfalls — Ошибки проектирования протоколов и их разбор
- crypto-encodings — уже есть;   добавить кастомные алфавиты и многослойные

### Ranked TOP 25 gaps (crypto)

## stego

Total unique proposed lessons: **185**

### A. Fundamentals, theory & codes

- stego-reversible-data-hiding — Reversible / lossless data hiding (RDH) overview
- stego-difference-expansion — Difference expansion (DE) embedding
- stego-histogram-shifting — Histogram shifting / histogram modification
- stego-cover-selection — Cover selection & cover synthesis theory
- stego-security-models — Security models: Cachin's criterion, KL-divergence, detectability
- stego-game-theory — Steganographic game theory & adversarial detection bounds
- stego-taxonomy — Steganography vs watermarking vs fingerprinting vs covert channels
- stego-fragile-robust — Fragile vs semi-fragile vs robust embedding
- stego-perceptual-models — Perceptual models (HVS/HAS) for embedding
- stego-ecc — Error-correcting codes in stego (Reed–Solomon, BCH, turbo)
- stego-matrix-embedding — Matrix embedding beyond F5 (Hamming, BCH codes)
- stego-wet-paper-codes — Wet paper codes
- stego-minimum-distortion — Minimum-distortion embedding framework (cost functions)
- stego-key-management — Key management & password derivation in stego tools
- stego-capacity-security-tradeoff — Capacity vs security vs robustness tradeoff
- stego-legal-ethics — Legal, ethical & policy aspects of steganography
- stego-steganographic-file-system — Deniable / hidden filesystem theory (covered partially by stego-filesystem)

### B. Image steganography (formats & domains)

- stego-jpeg2000 — JPEG 2000 (JP2/J2K) wavelet stego
- stego-jpegxr — JPEG XR (HD Photo) stego
- stego-jpegxl — JPEG XL (JXL) stego
- stego-webp-lossless — WebP lossless (VP8L) embedding deep
- stego-avif-image — AVIF image stego deep
- stego-grayscale — Grayscale / monochrome image stego
- stego-cmyk — CMYK / print-color-space stego
- stego-multispectral — Multispectral & hyperspectral image stego
- stego-thermal-ir — Thermal / infrared image stego
- stego-stereo-anaglyph — Stereo / anaglyph / depth-map stego
- stego-panorama-360 — Panoramic / 360° image stego
- stego-raw-bayer — RAW Bayer-pattern sensor stego
- stego-dft-domain — DFT / log-polar domain embedding
- stego-dct-qim — QIM in DCT domain
- stego-svd — SVD-based image stego
- stego-fractal — Fractal-based image stego
- stego-chaos — Chaos-theory based embedding/encryption
- stego-ica-pca — ICA/PCA-based embedding
- stego-edge-adaptive-hugo — HUGO/WOW edge-adaptive deep (covered by stego-adaptive — extend)
- stego-robust-crop-resize — Robustness to crop/resize/recompression
- stego-print-scan — Print-scan resilient stego
- stego-invertible-nn — Invertible neural network stego (HiDDeN, UDH)
- stego-diffusion-cover — Diffusion-model generated covers
- stego-gan-steganalysis — GAN-based steganalysis

### C. Audio steganography

- stego-midi — MIDI steganography (note/pitch/velocity/timing)
- stego-flac-alac — FLAC / ALAC lossless audio stego
- stego-ogg-opus — Ogg Vorbis / Opus stego
- stego-aac — AAC audio stego
- stego-id3-tags — ID3v2 / APIC / chapter tag stego
- stego-audio-watermark — Audio watermarking (AudioSeal, robust schemes)
- stego-speech-lpc — LPC / formant / vocoder speech stego
- stego-audio-qim — QIM audio embedding
- stego-audio-nn — Neural audio stego
- stego-analog-media — Vinyl / cassette / tape analog stego
- stego-ultrasonic — Ultrasonic / acoustic covert channel

### D. Video & animation

- stego-av1 — AV1 video stego
- stego-vvc-h266 — VVC / H.266 video stego
- stego-h264-mv — H.264/H.265 motion-vector deep embedding
- stego-video-watermark — Video watermarking
- stego-gif-lzw — GIF LZW / dictionary stego
- stego-mjpeg — MJPEG / frame-sequence stego
- stego-subtitle-srt — Subtitle (SRT/ASS/VTT) stego
- stego-video-nn — Neural video stego

### E. Text & linguistic

- stego-json-whitespace — JSON whitespace / key-order stego
- stego-yaml — YAML stego
- stego-markdown — Markdown stego
- stego-csv-tsv — CSV/TSV stego
- stego-snow — SNOW whitespace stego tool
- stego-homoglyph — Homoglyph / IDN stego
- stego-unicode-tags — Unicode Tags block (U+E0000) stego
- stego-bidi-control — Bidirectional control-character stego
- stego-rtl-override — RTL override / mirroring stego
- stego-text-nn — Neural text stego
- stego-zerowidth-deep — Zero-width / variation-selector deep (covered by emoji — extend)

### F. Documents & office containers

- stego-odf — OpenDocument (ODT/ODS/ODP) stego
- stego-epub — EPUB ebook stego
- stego-chm — CHM help-file stego
- stego-xlsx-hidden — Spreadsheet hidden rows/sheets/defined-names stego
- stego-pptx — PowerPoint stego
- stego-pdf-incremental — PDF incremental-update stego
- stego-pdf-objectstream — PDF object-stream / xref-stream stego
- stego-office-customxml — OOXML custom-XML-parts stego
- stego-rtf — RTF stego
- stego-latex — LaTeX source stego
- stego-ps-eps — PostScript / EPS stego
- stego-word-fields — Word field-codes / tracked-changes stego
- stego-vba-macro — VBA macro stego
- stego-xps-oxps — XPS/OXPS document stego

### G. Archives, binaries & filesystems

- stego-zip-aes — ZIP AES / encrypted-archive stego
- stego-tar — TAR padding/header stego
- stego-cab-msi — CAB/MSI stego
- stego-udf — UDF filesystem stego
- stego-git-objects — Git object / packfile stego
- stego-docker-layers — Docker image layer stego
- stego-package-managers — npm/pip/apt package stego
- stego-registry — Windows Registry value stego
- stego-ntfs-timestamps — NTFS timestamp stego
- stego-firmware-rom — Firmware / ROM padding stego
- stego-pe-deep — PE resource/section/overlay deep
- stego-elf-notes — ELF section/note/overlay stego
- stego-macho — Mach-O stego
- stego-dotnet-il — .NET assembly / IL stego
- stego-java-class — Java class / JAR stego
- stego-wasm-module — WebAssembly module stego
- stego-memory-dump — Stego in memory dumps
- stego-swap-hibernation — Stego in swap / hibernation files

### H. Network & protocol covert channels

- stego-tls — TLS / HTTPS covert channel
- stego-ipv6-header — IPv6 header / extension-header covert channel
- stego-ipv4-options — IPv4 options / record-route covert channel
- stego-doh-dot — DNS-over-HTTPS / DNS-over-TLS covert channel
- stego-grpc-protobuf — gRPC / protobuf varint covert channel
- stego-websocket — WebSocket frame covert channel
- stego-ntp — NTP timestamp covert channel
- stego-ssh-channel — SSH covert channel
- stego-vpn-tunnel — VPN / tunneled payload stego
- stego-tor-i2p — Tor / I2P covert channels
- stego-dhcp — DHCP option covert channel
- stego-arp-mac — ARP / MAC-address covert channel
- stego-routing-proto — BGP / OSPF routing-protocol covert channel
- stego-sip-deep — SIP signaling covert channel
- stego-sms-pdu — SMS / PDU covert channel
- stego-quic-deep — QUIC packet-number/header covert channel

### I. RF, wireless, physical buses

- stego-sdr-iq — SDR / IQ-sample stego
- stego-satellite — Satellite-signal covert channel
- stego-usb-traffic — USB traffic covert channel
- stego-serial-uart — Serial / UART covert channel
- stego-can-bus — CAN bus covert channel
- stego-modbus-ics — Modbus / ICS protocol covert channel
- stego-powerline — Powerline-communication stego
- stego-bluetooth — Bluetooth / BLE covert channel
- stego-wifi-80211 — Wi-Fi 802.11 frame covert channel
- stego-lte-5g — LTE / 5G signaling covert channel
- stego-magnetic-media — Magnetic-media stego
- stego-uv-ink — UV / invisible-ink document stego
- stego-microdot — Paper microdot / microprint stego
- stego-gcode — 3D-print G-code stego
- stego-cad-step — CAD / STEP / STL stego (extend stego-3d-models)
- stego-gis-geojson — GIS / GeoJSON / KML stego
- stego-qr-micro — Micro QR / structured-append stego
- stego-datamatrix — DataMatrix / Aztec / PDF417 symbologies

### J. Modern & emerging

- stego-blockchain-l2 — Blockchain L2 / rollup / calldata stego
- stego-nft-metadata — NFT metadata stego
- stego-ipfs-deep — IPFS / content-addressed stego
- stego-model-weights — Stego in ML model weights
- stego-llm-token — LLM token / sampling covert channel
- stego-prompt-channel — Prompt-based covert channel
- stego-ai-watermark — AI content watermarking (SynthID etc.)
- stego-c2pa — C2PA / Content Credentials provenance stego
- stego-quantum — Quantum-state steganography
- stego-dna-protein — DNA / protein stego deep (extend stego-dna)
- stego-hologram-ar — Hologram / AR-marker stego
- stego-game-save — Game save-file stego
- stego-puzzle-board — Puzzle / chessboard / game stego
- stego-currency-security — Currency / security-printing features
- stego-iot-firmware — IoT firmware image stego

### K. Steganalysis

- stegoanalysis-ws — Weighted Stego (WS) analysis
- stegoanalysis-ensemble — Ensemble / FLD classifiers (SRM+EC)
- stegoanalysis-rich-models — DCTR / JRM / GFR rich models
- stegoanalysis-targeted-f5 — Targeted structural attack on F5
- stegoanalysis-quantitative — Quantitative steganalysis (payload-length estimation)
- stegoanalysis-cover-source-mismatch — Cover-source mismatch
- stegoanalysis-cnn — Deep CNN steganalysis (SRNet, Zhu-Net)
- stegoanalysis-universal — Universal / blind steganalysis
- stegoanalysis-timing — Timing-channel detection
- stegoanalysis-network — Network covert-channel detection
- stegoanalysis-hypothesis — Statistical hypothesis-testing framework
- stegoanalysis-color — Color-image specific detectors
- stegoanalysis-audio — Audio steganalysis (SAS)
- stegoanalysis-video — Video steganalysis
- stegoanalysis-steg-expose — StegExpose / Aletheia detection workflow

### L. Tools, workflow & CTF methodology

- stego-tool-cyberchef — CyberChef magic & recipes for stego
- stego-tool-stegoveritas — Stegoveritas workflow
- stego-tool-forensically — Forensically / Aperi'Solve web tools
- stego-tool-png-suite — pngcheck/pngcrush/optipng/zopfli
- stego-tool-jpeg-suite — jpegtran/jpegoptim manipulation
- stego-tool-openstego — OpenStego/Camouflage/wbStego
- stego-tool-deepsound — DeepSound / SilentEye audio
- stego-tool-binwalk-deep — binwalk deep / signature extraction
- stego-tool-foremost — foremost / scalpel recovery
- stego-tool-audacity — Audacity / Sonic Visualiser spectrogram workflow
- stego-tool-gimp — GIMP channel / bit-plane manipulation
- stego-tool-python — Python (PIL/numpy/scipy) stego scripting
- stego-tool-zsteg-deep — zsteg deep bit-order / module coverage
- stego-ctf-decision-tree — CTF stego decision tree
- stego-ctf-unknown-file — Unknown-file triage workflow
- stego-ctf-multi-layer — Multi-layer / chained stego puzzle solving
- stego-ctf-flag-hunt — Systematic flag hunting in containers
- stego-ctf-anti-tool — Challenges that break common tools

## forensics

Total unique proposed lessons: **253**

### A. Disk, filesystem & storage

- fs-refs — ReFS (Resilient File System) forensics
- fs-udf-iso — UDF / ISO9660 forensics
- fs-f2fs — F2FS (Android flash) forensics
- fs-squashfs — SquashFS (embedded) forensics
- fs-jffs2-ubifs — JFFS2 / UBIFS flash filesystems
- fs-nilfs-minix — NILFS / Minix / exotic filesystems
- fs-cifs-smb — SMB/CIFS share forensics
- fs-nfs — NFS share forensics
- fs-cloud-sync — Cloud-sync client (Dropbox/OneDrive/GDrive) artifacts
- fs-ssd-trim — SSD / TRIM / wear-leveling forensics
- fs-hpa-dco — HPA / DCO hidden disk areas
- fs-bad-sectors — Bad-sector & sector-reallocation forensics
- fs-san-nas — SAN / NAS device forensics
- fs-mdadm — Software RAID (mdadm) reconstruction deep
- fs-tpm — TPM / measured-boot forensics
- fs-carving-fragmented — Advanced carving of fragmented files
- fs-ntfs-compression — NTFS compression & sparse-file forensics
- fs-ntfs-logfile — $LogFile / transaction journal deep
- fs-ext4-deleted — ext4 deleted-inode & extent recovery
- fs-btrfs-snapshot — Btrfs snapshot / subvolume forensics
- fs-zfs-arc-zil — ZFS ARC / ZIL / SLOG forensics
- fs-apfs-snapshot — APFS snapshot / checkpoint forensics
- fs-apfs-encryption — APFS encryption & keybag forensics
- fs-fat-slack — FAT volume-slack & cluster-chain forensics
- fs-timestamp-semantics — $STANDARD_INFO vs $FILE_NAME timestamp semantics
- fs-bitlocker-recovery — BitLocker recovery-key / TPM-sealed forensics
- fs-veracrypt-header — VeraCrypt header & hidden-volume forensics
- fs-luks-header — LUKS header & key-slot forensics

### B. Windows artifacts

- win-dpapi — DPAPI masterkeys / CREDHIST forensics
- win-credential-vault — Credential Manager / Windows Vault
- win-rdp-artifacts — RDP bitmap cache & RDP event logs
- win-dns-cache — DNS client cache & DNS Client logs
- win-windows-search — Windows Search (Windows.edb) forensics
- win-activity-timeline — Windows Timeline (ActivitiesCache.db)
- win-notification-db — Notification / Action Center DB
- win-cortana-search — Cortana / search-history artifacts
- win-wer — Windows Error Reporting (WER) artifacts
- win-ntds — NTDS.dit & AD database forensics
- win-sysvol-gpo — SYSVOL / GPO forensic analysis
- win-com-hijack — COM hijacking artifacts
- win-ifeo — IFEO / AppInit_DLLs / AppCertDLLs
- win-print-spooler — Print spooler & print-job forensics
- win-winrm-logs — WinRM / WSMan event logs
- win-smb-artifacts — SMB server/client-side artifacts
- win-edr-logs — EDR/AV product log forensics (CrowdStrike/S1/MDE)
- win-sysmon-tuning — Sysmon configuration & event tuning
- win-srum-deep — SRUM ESE deep parsing
- win-amcache-deep — Amcache ESE deep parsing
- win-appcompat-deep — AppCompatCache / ShimCache deep
- win-powershell-transcript — PowerShell transcription & module logging
- win-scheduled-tasks-deep — Task Scheduler deep artifacts
- win-service-artifacts — Service creation/change forensics
- win-boot-config — BCD / UEFI boot forensics
- win-prefetch-deep — Prefetch parsing & volume serials
- win-evtx-tampering — EVTX tampering / gap detection
- win-registry-recovery — Registry hive slack & transaction recovery
- win-quarantine — AV quarantine vault analysis
- win-windows-update — Windows Update / servicing-stack logs
- win-lsa-secrets — LSA secrets & cached-credential forensics
- win-wmi-persistence — WMI repository persistence deep
- win-app-compat — Application Compatibility cache (extend)

### C. Linux artifacts

- linux-proc-forensics — /proc & /sys live forensics
- linux-ssh-artifacts — SSH known_hosts/authorized_keys/lastlog/wtmp
- linux-systemd-persistence — systemd units/timers persistence
- linux-ebpf-forensics — eBPF-based observability & forensics
- linux-auditd-deep — auditd rules & audit-log analysis deep
- linux-journald-binary — journald binary-log analysis
- linux-package-logs — apt/dpkg/yum/rpm history forensics
- linux-container-escape — Container-escape artifacts
- linux-kernel-modules — Loadable kernel module forensics
- linux-shell-history — bash/zsh/fish history & timestamp forensics
- linux-syslog-rsyslog — syslog/rsyslog pipeline forensics
- linux-file-timestamps — atime/mtime/ctime/crtime forensics
- linux-deleted-open — Deleted-but-open file recovery via /proc
- linux-network-artifacts — lsof/ss/netstat connection forensics
- linux-selinux-apparmor — SELinux / AppArmor denial forensics
- linux-accounts-sudo — passwd/shadow/sudoers/group forensics
- linux-sshd-logs — sshd auth & session forensics
- linux-initramfs — initramfs/initrd forensics

### D. macOS & Apple

- macos-keychain — Keychain forensics
- macos-knowledgec — knowledgeC.db usage forensics
- macos-tcc — TCC.db privacy-consent forensics
- macos-xprotect — XProtect / Gatekeeper / MRT logs
- macos-persistence — LaunchAgents/Daemons persistence
- macos-launchservices — LaunchServices & quarantine DB
- macos-spotlight — Spotlight index forensics
- macos-unified-log-deep — Unified logging deep (logarchive)
- macos-timemachine — Time Machine forensics
- macos-notification-db — Notification Center DB forensics
- macos-memory — macOS memory forensics
- macos-apple-silicon — Apple Silicon / SEP / Secure Enclave forensics
- macos-imessage — iMessage / SMS (chat.db) forensics
- macos-safari — Safari history/downloads forensics
- macos-icloud — iCloud / CloudKit local artifacts
- macos-quarantine-deep — quarantine events deep parsing
- macos-install-logs — Install.log & package-receipt forensics

### E. Mobile

- mobile-android-fbe — Android File-Based Encryption & Keystore
- mobile-android-strongbox — Android Keystore / StrongBox / hardware-backed keys
- mobile-ios-unifiedlog — iOS Unified Logs forensics
- mobile-ios-keychain-deep — iOS keychain deep parsing
- mobile-sim-usim — SIM / USIM card forensics
- mobile-baseband — Baseband / IMSI-catcher artifacts
- mobile-gms — Google Play Services / GMS artifacts
- mobile-android-notifications — Android notification history
- mobile-android-location — Android location history
- mobile-ios-location — iOS location (Cache.sqlite, routined)
- mobile-whatsapp — WhatsApp forensics deep
- mobile-signal-telegram — Signal / Telegram forensics
- mobile-chipoff-jtag — Chip-off / JTAG / ISP extraction
- mobile-ufed-workflow — Cellebrite UFED / AXIOM workflow
- mobile-android-backup — Android backup (adb/AB) forensics
- mobile-ios-backup — iOS backup (iTunes/Finder) forensics deep
- mobile-app-reversing — Mobile app reversing for forensics
- mobile-jailbreak-artifacts — Jailbreak / root artifacts
- mobile-cloud-sync — Mobile cloud (iCloud/Google) acquisition
- mobile-screen-lock — Screen-lock bypass & BFU/AFU states

### F. Memory forensics

- mem-linux — Linux memory forensics (Volatility3 Linux)
- mem-macos — macOS memory forensics
- mem-acquisition — Memory acquisition (WinPmem, LiME, AVML, DumpIt)
- mem-swap-pagefile — Swap / pagefile analysis
- mem-kernel-hooks — SSDT/IDT/kernel-hook detection
- mem-dkom — DKOM & hidden-process detection
- mem-kernel-modules — Kernel-module analysis from memory
- mem-network — Network-connection recovery from memory
- mem-registry-hives — Registry-hive recovery from memory
- mem-timelining — Memory timeline construction
- mem-dyld-cache — Mach-O / dyld shared cache in memory
- mem-shellcode — Shellcode detection & disassembly in memory
- mem-credential-deep — Credential extraction deep (extend mem-keys)

### G. Network forensics

- net-kerberos — Kerberos ticket (Golden/Silver) forensics
- net-smb — SMB protocol forensics
- net-dns — DNS forensics & tunneling detection
- net-dhcp — DHCP lease forensics
- net-arp-mac — ARP / MAC & layer-2 forensics
- net-http2-3 — HTTP/2 & HTTP/3 forensic analysis
- net-ics-scada — ICS/SCADA protocol forensics (Modbus/DNP3)
- net-iot-protocols — MQTT / CoAP / IoT protocol forensics
- net-voip — VoIP / RTP forensics
- net-vpn — VPN / tunnel traffic analysis
- net-c2-reversing — C2 protocol reverse engineering
- net-tcp-reassembly — TCP reassembly & file extraction
- net-flow-beaconing — Flow analysis & beaconing detection
- net-wireless-80211 — Wi-Fi / 802.11 capture forensics
- net-cloud-vpcflow — VPC Flow Logs / cloud network forensics
- net-firewall-proxy — Firewall / proxy log forensics
- net-tls-decrypt-deep — TLS decryption deep (keylog/SSLKEYLOGFILE)

### H. Malware & code analysis

- mal-static — Static malware analysis workflow
- mal-dynamic-sandbox — Dynamic / sandbox analysis (Cuckoo/CAPE)
- mal-unpacking — Unpacking & packer/crypter analysis
- mal-shellcode — Shellcode analysis & emulation
- mal-dotnet — .NET malware analysis (dnSpy/de4dot)
- mal-go-rust — Go / Rust malware analysis
- mal-linux-malware — Linux malware analysis
- mal-macos-malware — macOS malware analysis
- mal-mobile-malware — Mobile malware analysis
- mal-obfuscation — Obfuscation / deobfuscation techniques
- mal-config-extraction — Malware config extraction deep
- mal-botnet-panel — Botnet / C2-panel analysis
- mal-script-js — JavaScript / script-malware analysis
- mal-anti-analysis — Anti-analysis / anti-VM / anti-debug
- mal-ioc-enrichment — IOC extraction & threat-intel enrichment
- mal-emulation — Emulation-based analysis (Qiling/Speakeasy)
- mal-firmware-malware — Firmware/BIOS malware analysis

### I. Timeline & correlation

- tl-cross-artifact — Cross-artifact correlation
- tl-entity-resolution — Entity resolution & deduplication
- tl-timezone-dst — Timezone & DST handling in timelines
- tl-clock-skew — Clock skew / drift correction
- tl-visualization — Timeline visualization (Timesketch deep)
- tl-provenance — Artifact provenance & confidence scoring

### J. Anti-forensics & counter-forensics

- af-secure-delete — Secure deletion & file-wiping detection
- af-encryption-hiding — Encryption/container hiding of evidence
- af-vm-detection — VM / sandbox evasion artifacts
- af-artifact-destruction — Artifact destruction & recovery
- af-metadata-scrubbing — Metadata scrubbing & detection
- af-trail-obfuscation — Trail-obfuscation techniques
- af-detection-methodology — Detecting anti-forensic activity
- af-timestomping-deep — Timestomping detection deep (extend)

### K. Cloud, containers & CI/CD

- cloud-m365-ual — M365 / Office 365 Unified Audit Log forensics
- cloud-okta — Okta / IdP authentication forensics
- cloud-google-workspace — Google Workspace audit forensics
- cloud-salesforce — Salesforce / SaaS audit forensics
- cloud-serverless — Serverless (Lambda/Functions) forensics
- cloud-storage — S3 / Blob / GCS storage forensics
- cloud-iam — Cloud IAM / identity forensics
- cloud-container-runtime — Container-runtime forensics (Falco/eBPF)
- cloud-vm-hypervisor — Cloud VM / hypervisor forensics
- cloud-cicd — CI/CD pipeline forensics
- cloud-iac-state — IaC / Terraform state-file forensics
- cloud-secrets-manager — Secrets-manager access forensics

### L. Web, app & database

- web-webshell — Webshell detection & forensics
- web-server-logs — IIS / Apache / Nginx log analysis
- web-waf-cdn — WAF / CDN log forensics
- web-cms — CMS (WordPress etc.) forensics
- web-java-appserver — Java app-server (Tomcat) forensics
- web-api-gateway — API-gateway / access-log forensics
- web-elasticsearch — Elasticsearch / NoSQL forensics
- web-oracle-db — Oracle database forensics
- web-mongodb-redis — MongoDB / Redis forensics
- web-jenkins-cicd — Jenkins / CI forensics
- web-git-repo — Git repository forensics

### M. Documents & media

- doc-ooxml-internals — OOXML internals (revisions/comments/track-changes)
- doc-odf — OpenDocument forensics
- doc-rtf — RTF forensics
- doc-xps — XPS/OXPS forensics
- media-video-forensics — Video forensics & frame analysis
- media-audio-forensics — Audio forensics (ENF, voice, splicing)
- media-deepfake — Deepfake / synthetic-media detection
- media-provenance — C2PA / media-provenance forensics
- media-qr-barcode — QR / barcode forensics
- media-3d-model — 3D-model / CAD forensics
- media-printer — Printer / document-authenticity forensics

### N. Specialized / niche

- spec-automotive — Automotive / vehicle forensics (CAN, infotainment)
- spec-drone — Drone / UAV forensics
- spec-iot — IoT device forensics
- spec-ics — ICS / SCADA forensics
- spec-console — Game-console forensics
- spec-smarttv — Smart-TV forensics
- spec-crypto-wallet — Cryptocurrency / wallet forensics
- spec-gps — GPS / navigation-device forensics
- spec-wearable — Wearable / smartwatch forensics
- spec-medical-device — Medical-device forensics
- spec-satellite — Satellite / spacecraft forensics
- spec-dvr-camera — DVR / IP-camera / CCTV forensics
- spec-pos — POS / ATM / payment-terminal forensics

### O. Incident response & process

- ir-picerl — SANS PICERL IR lifecycle
- ir-threat-hunting — Threat-hunting methodology
- ir-tabletop — IR tabletop exercises
- ir-containment-eradication — Containment / eradication / recovery
- ir-root-cause — Root-cause analysis
- ir-triage-collection — Triage collection (KAPE/Velociraptor)
- ir-soar-automation — SOAR & automated IR
- ir-forensic-readiness — Forensic readiness & preparation
- ir-communication — Incident communication & escalation
- ir-legal-regulatory — Legal / regulatory aspects (GDPR, breach notice)
- ir-mitre-attack — MITRE ATT&CK mapping (extend)
- ir-purple-team — Purple-team / detection validation

### P. Tools & platforms

- tool-eric-zimmerman — Eric Zimmerman tools suite
- tool-kape — KAPE triage collection
- tool-velociraptor — Velociraptor DFIR
- tool-osquery — osquery forensics
- tool-cyberchef — CyberChef for forensics
- tool-magnet-axiom — Magnet AXIOM
- tool-cellebrite — Cellebrite UFED / Physical Analyzer
- tool-xways — X-Ways Forensics
- tool-ftk-encase — FTK / EnCase
- tool-grr — GRR Rapid Response
- tool-dfir-orc — DFIR ORC / artifact collection
- tool-regripper — RegRipper registry parsing
- tool-hindsight — Hindsight browser forensics
- tool-bulk-extractor — bulk_extractor
- tool-fiwalk — fiwalk / DFXML
- tool-ntfs-tools — ntfs-3g / nTFS / MFTECmd
- tool-plaso-deep — plaso/log2timeline deep (extend)

## network

Total unique proposed lessons: **152**

### Telecom & Cellular

- network-5g-nr — 5G NR: gNB, RRC/NAS, registration, network slicing attacks
- network-5g-nas — 5G NAS signalling: registration, PDU session, downgrade to 4G
- network-5g-core — 5G SA core (AMF/SMF/UPF): SBI/HTTP2 interfaces, exposure
- network-5g-security — 5G security architecture: SUCI, AKA', null-scheme, gNB spoofing
- network-nr-sidelink — 5G sidelink / D2D (PC5) attacks
- network-ss7 — SS7/MAP signalling: location tracking, SMS interception, CAMEL
- network-diameter — Diameter deep: S6a/Gx/Gy/Rx, AVP fuzzing, relay abuse
- network-gtp-attacks — GTP-C/GTP-U: tunnel creation, spoofing, DoS, TEID abuse
- network-3g-umts — UMTS/3G: UTRAN, KASUMI, node-B interfaces
- network-ims-volte — IMS/VoLTE: P-CSCF/S-CSCF, SIP registration hijack
- network-sim-esim — SIM/eSIM/UICC: applets, OTA provisioning, KI/OPc extraction
- network-cellular-imsi-catcher — IMSI-catcher deep: downgrade, detection, Stingray
- network-lte-layers — LTE MAC/RLC/PDCP layer analysis
- network-telecom-sigint — Telecom SIGINT workflow: capture → decode → attribute

### SDR / RF / Radio

- network-sdr-basics — SDR fundamentals: RTL-SDR/HackRF, GNU Radio, gqrx
- network-rf-signal-id — RF signal identification & demodulation (ASK/FSK/PSK)
- network-rf-replay — RF replay attacks: keyfobs, gates, remote controls (RollJam)
- network-sub-ghz — Sub-GHz ISM attacks: 315/433/868 MHz devices
- network-lora-lorawan — LoRa/LoRaWAN: join procedure, ABP/OTAA keys, replay
- network-dect — DECT: base stations, encryption, cordless phone attacks
- network-tetra — TETRA: trunked radio, TEA1 weakness, intercept
- network-pager-pocsag — POCSAG/FLEX pager interception and decoding
- network-adsb — ADS-B/Mode-S: aircraft tracking, spoofing, injection
- network-ais — AIS maritime: spoofing, gaps, vessel identity abuse
- network-gnss-spoofing — GPS/GNSS spoofing & jamming: meaconing, time attacks
- network-aprs — APRS / amateur packet radio
- network-rfid-mifare-deep — MIFARE Classic/Ultralight/DesFire crypto deep
- network-rfid-125khz — HID Prox / EM4100 cloning and access control
- network-nfc-relay — NFC relay for contactless payment / access
- network-uwb — Ultra-wideband (UWB): ranging, relay, secure distance bounding
- network-bluetooth-ble-audio — BLE Audio / LE Audio attacks
- network-sdr-iot — SDR for IoT: proprietary protocols on the wire

### Automotive & Vehicle Buses

- network-can-bus — CAN bus: frames, arbitration, sniffing, bus topology
- network-can-injection — CAN injection, replay and fuzzing
- network-can-fd — CAN-FD: extended frames and security
- network-uds — UDS (ISO 14229) diagnostics: services, security access
- network-obd2 — OBD-II: PIDs, DTCs, mode exploitation
- network-doip — DoIP (ISO 13400) over Ethernet
- network-flexray — FlexRay: cycle, static/dynamic segments
- network-lin-bus — LIN bus: master/slave, attacks
- network-most-bus — MOST bus: infotainment ring
- network-j1939 — SAE J1939: heavy vehicles, DM messages
- network-automotive-ethernet — Automotive Ethernet / 100BASE-T1
- network-keyless-relay — Keyless entry relay (PKES) and RollJam
- network-ev-charging — EV charging security: CCS, OCPP, ISO 15118
- network-automotive-telematics — Telematics/T-Box attacks (OTA, eCall)

### ICS / OT / SCADA depth

- network-modbus-deep — Modbus/TCP deep: function codes, coils, spoofing
- network-dnp3 — DNP3: frames, unsolicited responses, Secure Auth
- network-s7comm — S7comm / S7comm-plus: Siemens PLC protocol
- network-profinet — PROFINET: RT/IRT, DCP, device discovery
- network-ethercat — EtherCAT: datagrams, mailbox, attacks
- network-opcua — OPC UA: binary/JSON, security policies, certificate abuse
- network-iec61850 — IEC 61850: MMS/GOOSE/SV substation protocols
- network-iec104 — IEC 60870-5-104: telecontrol, ASDUs
- network-bacnet — BACnet: building automation, BBMD, attacks
- network-hart-ip — HART-IP: process instrumentation
- network-ics-purdue — Purdue model / ICS segmentation & zoning
- network-ics-safety — ICS safety instrumented systems (SIS) basics

### Modern enterprise app protocols

- network-grpc — gRPC / protobuf over HTTP/2: framing, reflection
- network-websocket — WebSocket: upgrade, framing, hijack, tunneling
- network-webrtc — WebRTC / STUN / TURN / ICE: IP leak, TURN abuse
- network-smb2-deep — SMB2/3 protocol deep: negotiation, dialects, compression
- network-smb-signing — SMB signing & encryption: downgrade, relay enablers
- network-msrpc — MS-RPC / DCERPC over TCP: opnums, interface UUIDs
- network-dcerpc-epm — DCERPC endpoint mapper (135) enumeration
- network-winrm-wire — WinRM / WS-Man: SOAP over 5985/5986
- network-rdp-protocol — RDP protocol deep: NLA/CredSSP, RDP relay
- network-ssh-wire — SSH wire protocol: KEX, auth methods, channels
- network-tls13-deep — TLS 1.3 handshake deep: 0-RTT, PSK, ECH
- network-kafka-wire — Kafka wire protocol: brokers, ACLs, exposure
- network-redis-wire — RESP / Redis wire protocol and exposure
- network-memcached — Memcached protocol and amplification
- network-ldap-wire — LDAP ASN.1 wire deep: filters, referrals
- network-kerberos-asn1 — Kerberos ASN.1 message structure deep
- network-amqp-deep — AMQP 0-9-1 / 1.0 deep
- network-mqtt-deep — MQTT 3/5 deep: QoS, retained, wildcard abuse
- network-coap-deep — CoAP: methods, observe, DTLS
- network-modbus-encap — Modbus RTU/ASCII over serial/TCP encapsulation

### Routing & Switching depth

- network-ospf-deep — OSPF deep: LSAs, areas, authentication, injection
- network-isis — IS-IS: levels, TLVs, routing attacks
- network-vrrp-hsrp — FHRP: VRRP/HSRP/GLBP takeover attacks
- network-igmp-multicast — IGMP/multicast: snooping, rogue querier
- network-ptp-1588 — PTP/IEEE 1588 time sync attacks
- network-mpls-attacks — MPLS label spoofing, LDP, VPN leaking
- network-bgp-security — BGPsec/ROA/RPKI validation and bypass
- network-sdn-openflow — SDN/OpenFlow: controller, flow-table attacks
- network-dhcp-snooping — DHCP snooping / DAI / IP source guard bypass
- network-private-vlan — Private VLAN / protected port escapes

### Tunneling & Pivoting

- network-http-tunnel — HTTP(S) tunneling: reGeorg, Chisel, Neo-reGeorg
- network-chisel-ligolo — Chisel / Ligolo-ng pivoting deep
- network-doh-tunnel — DNS-over-HTTPS tunneling (dnstt, DoH exfil)
- network-websocket-tunnel — WebSocket-based tunnels (wstunnel)
- network-icmp-tunnel-deep — ICMP tunnel internals (ptunnel, hans)
- network-dns-exfil — Data exfiltration over DNS (TXT/A/AAAA chunking)
- network-tor-bridges — Tor bridges/pluggable transports (obfs4, meek)
- network-gost-softether — GOST / SoftEther tunneling
- network-nat-traversal — NAT traversal / hole punching (STUN/TURN/UPnP)
- network-proxy-chains — Proxy chaining & SOCKS5 auth (proxychains)

### Scanning & fingerprinting

- network-ipv6-scanning — IPv6 scanning: alive6, nmap -6, address enumeration
- network-p0f-fingerprint — TCP/IP stack fingerprinting (p0f, OS inference)
- network-firewall-fingerprint — Firewall rule inference / scan-based mapping
- network-reflection-amplification — Reflection/amplification catalogue (DNS/NTP/CLDAP/memcached)
- network-dos-taxonomy — DoS/DDoS taxonomy: volumetric, protocol, app-layer
- network-syn-flood — SYN flood / TCP state exhaustion
- network-zmap-masscan-deep — Internet-scale scanning: zmap, masscan tuning
- network-service-version-detect — Service/version detection internals (nmap probes)

### Data-center / overlay / cloud fabrics

- network-geneve — GENEVE encapsulation and attacks
- network-iscsi — iSCSI: discovery, CHAP, LUN access
- network-nvme-of — NVMe over Fabrics (TCP/RDMA)
- network-fcoe — FCoE / storage-area networking
- network-infiniband-roce — InfiniBand / RoCE: fabric, PKeys
- network-docker-network — Container networking: netns, veth, CNI, docker.sock
- network-k8s-network — Kubernetes networking: CNI, kube-proxy, service mesh wire
- network-service-mesh — Service mesh (Istio/Linkerd) mTLS and sidecar
- network-network-namespaces — Linux netns/veth/bridge internals
- network-tun-tap — TUN/TAP devices and packet injection
- network-ebpf-xdp — eBPF/XDP for network monitoring & bypass

### Wireless depth

- network-wifi-6e7 — Wi-Fi 6/6E/7 (802.11ax/be) security
- network-wifi-direct — Wi-Fi Direct / P2P group attacks
- network-wifi-mesh — Wi-Fi mesh / roaming (802.11r/k/v) abuse
- network-wpa3-deep — WPA3/SAE deep: Dragonblood, H2E, transition
- network-wifi-enterprise — WPA2/3-Enterprise (802.1X) credential theft
- network-thread-matter — Thread / Matter smart-home protocol
- network-zwave-deep — Z-Wave: S0/S2, inclusion, sniffing
- network-wireless-ids — Wireless IDS / rogue AP detection
- network-wigle-geolocation — Wi-Fi geolocation databases (WiGLE)

### VoIP & real-time media

- network-sip-deep — SIP deep: methods, proxies, registration hijack
- network-rtp-srtp — RTP/SRTP: media streams, keying
- network-sccp-skinny — SCCP / Skinny: Cisco IP phones
- network-h323 — H.323: RAS, call signalling
- network-voip-toll-fraud — VoIP toll fraud & registration abuse

### Analysis & tooling internals

- network-scapy-deep — Scapy: crafting/sniffing deep
- network-tshark-lua — tshark/Wireshark Lua dissectors
- network-zeek-scripting — Zeek scripting (event model, analyzers)
- network-suricata-rules — Suricata rule writing & tuning
- network-pcap-format — pcap/pcapng format internals
- network-tc-netem — Traffic control / netem impairment for testing
- network-raw-sockets — Raw sockets / AF_PACKET programming
- network-network-automation — Ansible/NETCONF/RESTCONF device automation
- network-netfilter — Netfilter/nftables/iptables internals

### Protocol fundamentals / misc

- network-http1-deep — HTTP/1.1 deep: pipelining, keep-alive, chunking
- network-telnet-protocol — Telnet option negotiation deep
- network-tftp-protocol — TFTP protocol internals
- network-xinetd-rservices — Legacy inetd/r-services wire behaviour
- network-socks5-protocol — SOCKS5 protocol deep
- network-ppp-lcp — PPP/LCP/NCP negotiation deep
- network-radius-protocol — RADIUS protocol deep: attributes, proxying
- network-tacacs — TACACS+ protocol and auth
- network-ipv4-options — IPv4 options / source routing abuse
- network-tcp-options — TCP options: timestamps, SACK, MPTCP
- network-sctp — SCTP: multihoming, chunks, SIGTRAN
- network-dccp — DCCP / transport alternatives

## osint

Total unique proposed lessons: **153**

### Social / messaging platform breadth

- osint-social-whatsapp — WhatsApp: numbers, groups, business, status
- osint-social-snapchat — Snapchat: snaps, map, stories
- osint-social-pinterest — Pinterest: boards, pins, interests
- osint-social-tumblr — Tumblr blogs and reblogs
- osint-social-threads — Threads (Meta) OSINT
- osint-social-bluesky — Bluesky / AT Protocol: DIDs, feeds, PDS
- osint-social-nostr — Nostr: relays, npub, events
- osint-social-matrix — Matrix / Element: rooms, homeservers
- osint-social-signal — Signal-adjacent: number registration, linked devices
- osint-social-line — LINE: stickers, timeline, ID search
- osint-social-viber — Viber public accounts and communities
- osint-social-wechat — WeChat: public accounts, mini-programs
- osint-social-weibo — Weibo: posts, super-topics, geotags
- osint-social-qq — QQ: groups, QZone
- osint-social-gab-parler — Gab / Parler / Rumble / Odysee
- osint-social-truth — Truth Social / Gettr
- osint-social-4chan — 4chan / imageboards / Kiwi Farms
- osint-social-quora — Quora / StackExchange communities
- osint-social-medium — Medium / Substack newsletters
- osint-social-gaming — Gaming platforms: Steam, Xbox, PSN, Riot
- osint-social-dating — Dating apps: Tinder, Bumble, Grindr
- osint-social-fitness — Strava / fitness & route sharing
- osint-social-music — Spotify / SoundCloud / Last.fm
- osint-social-review — Review sites: Yelp, Google Maps, TripAdvisor
- osint-social-forums — Forums: vBulletin/XenForo/Discourse
- osint-social-goodreads — Goodreads / Letterboxd / niche interest sites
- osint-social-live — Live streaming: Kick, Trovo, DLive
- osint-social-linkedin-deep — LinkedIn deep: Sales Navigator, alumni, skills graph

### People & records depth

- osint-voter-records — Voter registration records
- osint-court-records — Court records: PACER, RECAP, state courts
- osint-property-records — Property / deed / assessor records
- osint-vehicle-records — DMV / vehicle registration records
- osint-vital-records — Vital records: birth/marriage/death
- osint-criminal-records — Criminal background / inmate lookup
- osint-bankruptcy-liens — Bankruptcy, liens, judgments
- osint-immigration-records — Immigration / visa / corporate registries
- osint-professional-licenses — Professional licensing boards
- osint-unclaimed-property — Unclaimed property / escheat
- osint-genealogy — Genealogy: FamilySearch, Ancestry, obituaries
- osint-dna-genealogy — Genetic genealogy (GEDmatch, GEDCOM)
- osint-phone-carrier — Phone carrier / HLR / number portability lookup
- osint-phone-deep — Phone deep: phoneinfoga, WhatsApp/Telegram registration
- osint-email-verification — Email verification / deliverability / MX probing
- osint-identity-graph — Identity graph building & entity resolution
- osint-people-timeline — Building a person timeline from records

### Geospatial & imagery depth

- osint-sar-imagery — SAR / radar satellite imagery
- osint-satellite-3d — 3D reconstruction / photogrammetry
- osint-skyline-analysis — Skyline / mountain / landmark matching
- osint-streetview-deep — Street View / Mapillary / KartaView deep
- osint-gis-analysis — GIS with QGIS: layers, spatial joins
- osint-historical-maps — Historical maps & map overlays
- osint-building-height — Building height / floor / vantage estimation
- osint-drone-imagery — Drone / UAV imagery analysis
- osint-coordinate-systems — Geodetic datums & coordinate conversion
- osint-geolocation-obscure — Hard geolocation (desert, sea, night)
- osint-weather-verification — Weather/cloud verification for media
- osint-vehicle-geolocation — Vehicle-based geolocation (rails, roads, signs)

### Media verification & provenance

- osint-c2pa — C2PA / Content Credentials verification
- osint-media-provenance — Media provenance chain-of-custody
- osint-video-forensics — Video forensics: frame analysis, re-encode detect
- osint-audio-forensics — Audio forensics: splicing, ENF, voiceprint
- osint-ai-image-detection — AI-generated image detection
- osint-video-reverse — Reverse video search
- osint-image-enhancement — Image enhancement / deblur / super-res
- osint-stego-media — Steganography in OSINT media
- osint-synthetic-voice — Voice cloning / vishing detection
- osint-verification-deep — Advanced disinformation & verification tradecraft

### SaaS / enterprise tenant enumeration

- osint-m365-enum — Microsoft 365 tenant recon (user enum, domains)
- osint-azure-tenant — Azure AD tenant ID discovery
- osint-okta-enum — Okta org enumeration
- osint-google-workspace — Google Workspace enumeration
- osint-slack-enum — Slack workspace enumeration
- osint-jira-confluence — Jira / Confluence / Atlassian recon
- osint-saas-tenant — Generic SaaS tenant enumeration
- osint-cloud-tenant-id — Cloud account/tenant ID harvesting
- osint-mobile-app-recon — Mobile app store / APK recon
- osint-api-discovery — API endpoint & spec discovery
- osint-iac-recon — IaC / Terraform state exposure
- osint-container-registry — Container registry recon (Docker Hub, GHCR)
- osint-cicd-recon — CI/CD pipeline recon (Jenkins/GitLab/Actions)
- osint-kubernetes-recon — Exposed Kubernetes dashboards/APIs
- osint-identity-provider — SSO/IdP discovery & metadata harvesting

### Threat intel & underground

- osint-misp — MISP: events, galaxies, sharing
- osint-stix-taxii — STIX/TAXII feeds
- osint-mitre-attack — MITRE ATT&CK mapping & CTI
- osint-apt-tracking — APT tracking & attribution
- osint-ransomware-leaks — Ransomware leak-site monitoring
- osint-darkweb-markets — Dark web marketplace recon
- osint-forum-monitoring — Underground forum monitoring
- osint-cred-markets — Credential marketplace monitoring
- osint-telegram-bot — Telegram bot automation for collection
- osint-social-listening — Social listening / brand monitoring
- osint-ioc-pivoting — Advanced IOC pivoting & graphing
- osint-malware-repos — Malware sample repos (MalwareBazaar, VT)

### Blockchain depth

- osint-crypto-clustering — Address clustering heuristics
- osint-crypto-mixers — Mixer/tumbler tracing
- osint-defi-forensics — DeFi protocol forensics
- osint-nft-tracing — NFT tracing & wash trading
- osint-monero-tracing — Monero / privacy-coin tracing limits
- osint-lightning-network — Lightning Network analysis
- osint-exchange-attribution — Exchange address attribution

### Corporate, financial & compliance

- osint-corporate-structure — Corporate structure / ownership chains
- osint-beneficial-ownership — Beneficial ownership registries
- osint-sanctions — Sanctions screening (OFAC/EU/UN)
- osint-pep-screening — PEP screening
- osint-adverse-media — Adverse media screening
- osint-aml-kyc — AML/KYC OSINT workflows
- osint-stock-market — Market data & securities filings deep
- osint-tenders-procurement — Public tenders & procurement
- osint-lobbying — Lobbying & political donations
- osint-charity-registry — Charity / nonprofit registries
- osint-insider-trading — Insider-trading signal detection

### Transport & logistics depth

- osint-rail — Rail tracking / train OSINT
- osint-transit — Public transit OSINT
- osint-trucking — Trucking / ELD / freight OSINT
- osint-container-tracking — Shipping container tracking
- osint-port-authority — Port authority / customs data
- osint-adsb-deep — ADS-B deep: MLAT, receivers, anomaly detection

### SIGINT-adjacent / geolocation signals

- osint-wifi-geolocation — Wi-Fi geolocation (WiGLE)
- osint-bluetooth-geolocation — BLE beacon geolocation
- osint-cell-tower-location — Cell-tower / base-station mapping
- osint-ip-geolocation — IP geolocation accuracy & limits
- osint-network-trace-geo — Traceroute / latency-based geolocation
- osint-sigint-basics — SIGINT basics for OSINT analysts
- osint-imint — IMINT methodology
- osint-osint-radio-deep — SDR-assisted OSINT

### Archives, recovery & web depth

- osint-commoncrawl — Common Crawl analysis
- osint-archive-tools — Archive tooling & APIs (CDX, Memento)
- osint-deleted-content — Recovering deleted content
- osint-cache-recovery — Search-engine cache recovery
- osint-source-code-search — Sourcegraph / grep.app code search
- osint-web-scraping — Web scraping ethics & tooling
- osint-structured-extraction — Structured data extraction pipelines
- osint-ocr-pipeline — OCR pipelines for OSINT
- osint-ner-pipeline — Named-entity recognition for OSINT
- osint-document-forgery — Document forgery / tamper detection
- osint-pdf-forensics — PDF structure forensics
- osint-office-forensics — Office/OOXML forensics

### Tradecraft, analysis & OPSEC

- osint-structured-analytic — Structured analytic techniques (ACH, key assumptions)
- osint-source-evaluation — Source reliability (Admiralty scale)
- osint-cognitive-bias — Cognitive bias in analysis
- osint-timeline-analysis — Timeline & link analysis
- osint-graph-analysis — Graph analytics for OSINT
- osint-anti-attribution — Anti-attribution tradecraft
- osint-vm-compartmentalization — VM compartmentalization
- osint-identity-rotation — Sock-puppet identity rotation
- osint-legal-process — Legal process / subpoena / MLAT
- osint-info-sharing — Information sharing & disclosure
- osint-osint-ctf-hard — Hard OSINT CTF problem patterns
- osint-geoint-ctf — GEOINT CTF methodology
- osint-socmint-ctf — SOCMINT CTF methodology
- osint-metadata-ctf — Metadata-forensics CTF
- osint-ctf-toolchain — OSINT CTF toolchain & workflow

## cloud

Total unique proposed lessons: **215**

### Provider breadth — non-big-3 clouds (entirely missing)

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

### SaaS identity & enterprise IdP (major gap)

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

### AWS — missing service surfaces

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

### Azure — missing service surfaces

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

### GCP — missing service surfaces

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

### Kubernetes — missing surfaces

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

### Container runtimes & supply chain

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

### Serverless platforms & patterns

- cloud-knative — Knative / OpenFaaS / Fission: события, SSRF и захват
- cloud-lambda-extensions — Lambda extensions / runtime API / layers: злоупотребление
- cloud-function-url — Function URL / API-триггеры: authz и SSRF
- cloud-serverless-framework — Serverless Framework / SST / SAM: конфиги и секреты
- cloud-serverless-gpu — Serverless GPU / AI-inference: захват дорогих ресурсов
- cloud-faas-egress — Serverless egress / VPC-интеграция: обход изоляции

### IaC beyond Terraform/Bicep/CFN

- cloud-pulumi — Pulumi: стеки, secrets-provider и злоупотребление
- cloud-aws-cdk — AWS CDK: синтез, bootstrap-роли и escalation
- cloud-ansible — Ansible: inventory, vault, become и захват парка
- cloud-chef-puppet — Chef / Puppet / SaltStack: серверы, креды и захват
- cloud-crossplane — Crossplane / Kubernetes-IaC: провайдеры и escalation
- cloud-terragrunt-atlantis — Terragrunt / Atlantis / Spacelift: автоматизация и захват
- cloud-terraform-cloud — Terraform Cloud / Enterprise: workspaces, run-triggers, токены
- cloud-packer — Packer / образ-билдеры: подмена артефактов

### CI/CD beyond GH/GitLab/Jenkins/ArgoCD

- cloud-cicd-teamcity — TeamCity: агенты, токены и RCE
- cloud-cicd-circleci — CircleCI: контексты, orbs и кража секретов
- cloud-cicd-buildkite-travis — Buildkite / Travis / Drone: агенты и секреты
- cloud-cicd-bamboo — Bamboo / Bitbucket Pipelines: креды и инъекции
- cloud-cicd-tekton — Tekton / Argo Workflows / Rollouts: пайплайны в кластере
- cloud-cicd-spinnaker-flux — Spinnaker / Flux: CD-плоскость и захват
- cloud-cicd-selfhosted-runners — Self-hosted runners: persistence и кража между репозиториями
- cloud-cicd-oidc-deep — OIDC-доверие CI→облако deep: условия sub/aud и подделка
- cloud-cicd-artifact-poison — Отравление артефактов и кэшей пайплайна

### Networking & egress

- cloud-vpc-peering — VPC peering / Transit / Hub-spoke: изоляция и её обход
- cloud-privatelink — PrivateLink / Private Service Connect / Private Endpoint
- cloud-vpn-hybrid — Site-to-Site VPN / Direct Connect / ExpressRoute: гибридные мосты
- cloud-dns-deep — Облачный DNS deep: subdomain takeover, zone-делегирование, DNSSEC
- cloud-load-balancer-attacks — Балансировщики: smuggling, header-инъекции, origin-bypass
- cloud-egress-control — Egress-контроль / firewall / NAT: exfil и его обход
- cloud-service-mesh-net — Service mesh как сетевой слой: mTLS-обход и перехват
- cloud-bgp-routing — BGP / маршрутизация в облаке: hijack и аномалии

### Data, analytics & messaging

- cloud-snowflake — Snowflake: роли, shares, external stages и утечка
- cloud-databricks — Databricks: workspace, tokens, кластеры и exfil
- cloud-kafka-msk — Kafka / MSK / Confluent / Event Hubs: ACL, SASL и инъекции
- cloud-airflow-dag — Airflow / Dagster / Prefect: DAG-инъекции и кража соединений
- cloud-dbt-looker — dbt / Looker / Tableau / Power BI: доступ к данным и утечка
- cloud-data-lake — Data lake / Lakehouse: каталоги, права и обход
- cloud-streaming-exfil — Стриминговая exfiltration: Kinesis/PubSub/EventHub каналы

### AI / ML / LLM in cloud

- cloud-llm-prompt-injection — Prompt injection в облачных LLM-сервисах и агентах
- cloud-ai-model-theft — Кража моделей: веса, endpoints, извлечение через API
- cloud-ai-supply-chain — AI supply chain: модели, датасеты, ноутбуки и pickle-RCE
- cloud-rag-security — RAG / vector-DB: утечка через embeddings и инъекции
- cloud-ai-agent-abuse — Автономные AI-агенты с облачными правами: злоупотребление

### Secrets management (beyond native)

- cloud-vault — HashiCorp Vault: auth-методы, policies, seal/unseal и захват
- cloud-cyberark — CyberArk / PAM: сейфы, эпитеты и обход
- cloud-sops-sealed — SOPS / sealed-secrets / git-crypt: ключи и обход
- cloud-external-secrets — External Secrets Operator: провайдеры и подмена
- cloud-secret-scanning — TruffleHog / gitleaks / git-secrets: пайплайны и обход

### Post-exploitation & attack technique depth

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

### Governance, compliance & emerging

- cloud-cspm-cnapp — CSPM/CNAPP: Prowler, ScoutSuite, Wiz, Orca — настройка и обход
- cloud-compliance-frameworks — FedRAMP / SOC2 / PCI / HIPAA / GDPR в облаке
- cloud-data-residency — Data residency / sovereignty / региональные границы
- cloud-confidential-computing — Confidential computing: enclaves, attestation и атаки
- cloud-pq-crypto — Пост-квантовая криптография в облачных KMS/сертификатах
- cloud-wasm-edge — WebAssembly в облаке/edge: sandbox и его обход
- cloud-5g-mec — 5G / MEC / edge-cloud: поверхность и интеграция
- cloud-quantum-hardware — Квантовые облачные сервисы (Braket/Azure Quantum): доступ

## hardware

Total unique proposed lessons: **156**

### Wi-Fi / 802.11 hardware (entirely missing — highest-value gap)

- hardware-wifi-basics — Wi-Fi: каналы, кадры 802.11, monitor mode и чипсеты
- hardware-wifi-deauth — Deauth / disassoc атаки и защита (PMF)
- hardware-wifi-handshake — Захват WPA/WPA2 handshake и PMKID
- hardware-wifi-cracking — Офлайн-взлом WPA/WPA2: hashcat, словари и правила
- hardware-wifi-wpa3 — WPA3 / SAE / Dragonfly: атаки и downgrade
- hardware-wifi-krack — KRACK и атаки на 802.11-шифрование
- hardware-wifi-eviltwin — Evil Twin / rogue AP / captive-portal фишинг
- hardware-wifi-enterprise — WPA-Enterprise / 802.1X / EAP: обход и кража кредов
- hardware-wifi-driver-fw — Атаки на драйвер/прошивку Wi-Fi-чипсета
- hardware-wifi-6-7 — Wi-Fi 6/6E/7: OFDMA, MLO и новые поверхности
- hardware-wifi-pmkid-deep — PMKID / client-less атаки и форензика эфира
- hardware-wifi-ap-hacking — Взлом SOHO-роутеров и прошивок AP

### Cellular, SIM & baseband

- hardware-gsm-2g — GSM/2G: A5/1, IMSI-catcher и перехват
- hardware-umts-3g — UMTS/3G: защита, downgrade и атаки
- hardware-lte-4g — LTE/4G: attach, NAS, downgrade и IMSI-катчер
- hardware-5g-nr — 5G NR: архитектура, security, gNB и атаки
- hardware-sim-esim — SIM/eSIM: приложения, OTA, ключи и клонирование
- hardware-baseband — Baseband-процессор: реверс, фаззинг и уязвимости
- hardware-osmocom — Osmocom / srsRAN: построение базовой станции для тестов
- hardware-sms-ss7 — SS7 / Diameter / SMS-перехват и утечки
- hardware-imsi-catcher-det — Детект и защита от IMSI-катчеров

### GNSS, satellite & broadcast radio

- hardware-gps-gnss — GPS/GNSS: спуфинг, jamming и spoofing-детект
- hardware-satcom — SATCOM / Iridium / Inmarsat / Starlink: перехват и атаки
- hardware-dect — DECT: перехват, клонирование трубок и баз
- hardware-tetra — TETRA: протокол, шифрование и атаки на рации
- hardware-pocsag-flex — POCSAG / FLEX-пейджинг: декодирование и инъекции
- hardware-apco25 — APCO-25 / P25: цифровая радиосвязь и атаки
- hardware-ham-digital — DMR / D-STAR / Yaesu: цифровое радио и подмена

### RF protocols & wireless IoT breadth

- hardware-zwave-deep — Z-Wave deep: S0/S2, фреймы и атаки
- hardware-zigbee-deep — Zigbee deep: стек, ключи, OTA и атаки
- hardware-thread-matter — Thread / Matter: commissioning, ключи и атаки
- hardware-6lowpan — 6LoWPAN / 802.15.4: сетевой стек и атаки
- hardware-wirelesshart — WirelessHART / ISA100: промышленное беспроводное
- hardware-enocean — EnOcean / энергонезависимые датчики
- hardware-mbus — M-Bus / wM-Bus: счётчики и перехват
- hardware-knx-dali — KNX / DALI / LonWorks: здания и освещение
- hardware-bacnet — BACnet: здания, атаки и запись точек
- hardware-hart-ip — HART-IP: полевые приборы и инъекции

### Automotive & mobility deep

- hardware-flexray — FlexRay: шина, фреймы и анализ
- hardware-lin-bus — LIN-шина: автомобильный суб-протокол и атаки
- hardware-automotive-ethernet — Automotive Ethernet (100BASE-T1/1000BASE-T1)
- hardware-doip — DoIP (ISO 13400): диагностика по Ethernet
- hardware-iso-tp — ISO-TP / транспорт CAN: сегментация и фаззинг
- hardware-keyless-relay — Keyless entry / RKE/PKE: relay, RollJam, amplification
- hardware-tpms — TPMS: датчики давления, спуфинг и слежка
- hardware-telematics-tcu — Телематика / TCU: облако, eCall и захват
- hardware-infotainment — Инфоtainment / head-unit: Android Auto, CarPlay, атаки
- hardware-autosar — AUTOSAR: стек, Secure Onboard Communication и атаки
- hardware-ev-charging — EV-зарядка / OCPP: протокол, захват и billing
- hardware-ecu-flashing — Прошивка ECU: flashing, тюнинг и подмена
- hardware-immobilizer — Иммобилайзеры: обход и клонирование ключей

### ICS / SCADA fieldbus & protocols breadth

- hardware-ethercat — EtherCAT: промышленный Ethernet и атаки
- hardware-powerlink-sercos — POWERLINK / SERCOS: детерминированные сети
- hardware-opc-ua — OPC UA: безопасность, сертификаты и обход
- hardware-opc-da — OPC Classic/DA: DCOM, legacy-поверхность
- hardware-iec-61850 — IEC 61850: подстанции, GOOSE, MMS и атаки
- hardware-iec-104 — IEC 60870-5-104: телемеханика энергетики
- hardware-dnp3-sav5 — DNP3 Secure Authentication (SAv5) и его обход
- hardware-cip-enip — CIP / EtherNet/IP deep: объекты и запись
- hardware-plc-vendors — ПЛК вендоров: Siemens S7, Allen-Bradley, Schneider, Mitsubishi
- hardware-safety-plc — Safety-PLC / Triconex / SIS: атаки на системы безопасности
- hardware-rtu-remote — RTU / удалённые терминалы и телеметрия
- hardware-scada-hmi — SCADA HMI / historian: захват и подмена данных
- hardware-smart-grid — Smart grid / AMI / DLMS-COSEM: счётчики и инфраструктура
- hardware-powerline — Powerline (HomePlug/G3/PRIME): связь по электросети
- hardware-industrial-robot — Промышленные роботы / коботы: ROS, UR, KUKA, ABB

### MCU families & architectures

- hardware-arm-cortex-m — ARM Cortex-M: реверс, отладка и защита
- hardware-arm-cortex-a — ARM Cortex-A: TrustZone, MMU и эксплойты
- hardware-riscv — RISC-V: отладка, реверс и безопасность
- hardware-mips-embedded — MIPS-embedded: роутеры, реверс и эксплойты
- hardware-xtensa-esp — Xtensa / ESP32 / ESP8266: реверс и захват
- hardware-avr-pic — AVR / PIC / 8051: микроконтроллеры и их реверс
- hardware-stm32-nrf — STM32 / nRF / Nordic: отладка, DFU и secure boot
- hardware-ti-nxp — TI / NXP (SWIM/BDM) / Renesas: семейства и отладка
- hardware-embedded-os — FreeRTOS / Zephyr / VxWorks / QNX / ThreadX: реверс
- hardware-bare-metal — Bare-metal прошивки: реверс и анализ без ОС
- hardware-embedded-linux-deep — Embedded Linux deep: kernel, modules, rootfs
- hardware-rpi-arduino — Raspberry Pi / Arduino / Pico: платформы и атаки

### Silicon & physical attacks (beyond current)

- hardware-decapping — Декапсуляция чипов: кислоты, плазма и подготовка
- hardware-microprobing — Микропробирование: чтение внутренних сигналов
- hardware-fib-edit — FIB / circuit-edit: изменение цепей и обход защит
- hardware-emfi — Electromagnetic fault injection (EMFI) и импульсы
- hardware-body-bias — Body biasing injection (BBI) и другие инъекции
- hardware-clock-glitch — Clock glitching deep: параметры и стабильность
- hardware-voltage-glitch-deep — Voltage glitching deep: ChipWhisperer-сценарии
- hardware-optical-fault-deep — Оптические атаки deep: лазер, маскирование
- hardware-temperature-attacks — Термические атаки: нагрев, охлаждение, remanence
- hardware-cold-boot — Cold boot / DRAM remanence: извлечение ключей
- hardware-memory-bus-sniff — Перехват шины памяти: SDRAM-сниффинг
- hardware-xray-pcb — X-ray / CT / микроскопия плат и чипов
- hardware-pcb-netlist — Извлечение нетлиста и реверс многослойных плат
- hardware-tamper-response — Anti-tamper: меш, детекторы, potting и обход
- hardware-counterfeit-chips — Контрафактные чипы и supply-chain
- hardware-hardware-implant — Аппаратные импланты: сборка и сокрытие

### Side-channel depth

- hardware-template-attack — Template attacks / profiled side-channel
- hardware-tvla — TVLA / leakage assessment: методология оценки
- hardware-dema-sema — DEMA / SEMA: электромагнитный анализ
- hardware-cache-timing-hw — Cache-timing и микроархитектурные утечки в железе
- hardware-sca-align — Выравнивание трасс, preprocessing и борьба с шумом
- hardware-sca-countermeasures — Контрмеры side-channel и их обход
- hardware-fault-sca-combined — Комбинация fault + side-channel в одной атаке

### Secure elements & TEE depth

- hardware-tee-optree — OP-TEE / Trusted Firmware: сборка, отладка и эксплойты
- hardware-secure-world-exploit — Эксплуатация secure world и переход границ
- hardware-atecc-se050 — ATECC / SE050 / microchip secure elements
- hardware-puf — Physical Unclonable Functions (PUF) и их атаки
- hardware-hsm — HSM (PKCS#11 / Luna / nCipher): доступ и злоупотребление
- hardware-secure-boot-bypass-deep — Обход secure boot deep: подпись, fuse, ROM

### USB, PCIe & high-speed buses

- hardware-usb4-thunderbolt — USB4 / Thunderbolt: PCIe-tunneling и DMA
- hardware-pcie-dma — PCIe / DMA-атаки, IOMMU-обход и PCILeech
- hardware-pcie-fuzzing — Фаззинг PCIe/устройств и драйверов
- hardware-i3c-spmi — I3C / SPMI / SMBus: новые управляющие шины
- hardware-ps2-serial-deep — PS/2 / legacy-шины и их поверхности
- hardware-sdio-sd — SDIO / SD-карты: протокол, атаки и клонирование

### Hardware wallets & financial hardware

- hardware-wallet-ledger — Ledger / Trezor: архитектура и seed-извлечение
- hardware-wallet-fault — Fault/side-channel атаки на аппаратные кошельки
- hardware-wallet-secure-element — Secure element в кошельках: границы и обход
- hardware-pos-atm — POS-терминалы / банкоматы: аппаратные атаки
- hardware-payment-nfc — Бесконтактные платежи: relay, MITM и ограничения

### Mobile & consumer hardware

- hardware-iphone-hardware — iPhone: checkm8, DFU, Secure Enclave, аппаратные атаки
- hardware-android-hardware — Android: EDL (Qualcomm 9008), MTK, Odin/Samsung
- hardware-baseband-mobile — Мобильный baseband: реверс и уязвимости
- hardware-icloud-bypass — iCloud / FRP-обход и аппаратные методы
- hardware-consoles — Игровые консоли: Switch (Fusée Gelée/RCM), PS4/PS5, Xbox
- hardware-modchips — Modchips и аппаратные модификации консолей
- hardware-smarttv-cameras — Smart TV / IP-камеры / DVR: аппаратный доступ
- hardware-wearables — Носимые устройства: разбор, прошивка и данные

### Physical security & access control

- hardware-osdp — OSDP / Wiegand: доступ-контроль, перехват и спуфинг
- hardware-access-controllers — Контроллеры доступа и их обход
- hardware-electronic-locks — Электронные замки, отели и их обход
- hardware-alarm-systems — Сигнализации / датчики: обход и глушение
- hardware-cctv-analog — CCTV / аналоговое видео: перехват и подмена
- hardware-garage-gates — Ворота / шлагбаумы: sub-GHz и rolling codes
- hardware-badge-clone-deep — Клонирование бейджей deep: низко- и высокочастотные

### Boot, firmware & tooling breadth

- hardware-coreboot-tianocore — coreboot / TianoCore / GRUB: загрузка и атаки
- hardware-ota-update — OTA-обновления: подпись, downgrade и подмена
- hardware-firmware-automation — FirmAE / EMBA / Firmware Analysis Toolkit
- hardware-symbolic-firmware — Symbolic execution прошивок (angr) и её границы
- hardware-router-firmware — Прошивки роутеров/NAS/OpenWrt: реверс и CVEs
- hardware-jtagulator-greatfet — JTAGulator / GreatFET / Bus Pirate: автопоиск
- hardware-chipwhisperer — ChipWhisperer: стенд, скрипты и воспроизводимость
- hardware-hackrf-proxmark — HackRF / Proxmark3 / Flipper Zero: рабочие процессы
- hardware-vna-spectrum — VNA / спектроанализатор / генератор в исследованиях
- hardware-swo-rtt — SWO / RTT / semihosting: трассировка без halt
- hardware-openocd-gdb — OpenOCD / GDB-stub / vendor-отладка

### Emerging & advanced frontier

- hardware-chiplets-cxl — Чиплеты / CXL / die-to-die: поверхности и атаки
- hardware-riscv-security — RISC-V security extensions: PMP, debug и атаки
- hardware-pq-hardware — Пост-квантовая криптография в железе
- hardware-neuromorphic — Нейроморфные и AI-ускорители: реверс и атаки
- hardware-quantum-hardware — Квантовое железо: криоэлектроника и контроль
- hardware-embedded-ai — Embedded AI / TinyML: модели, кража и adversarial
- hardware-thermal-camera — Тепловидение в hardware-исследованиях
- hardware-mems-sensors — MEMS-датчики: акустические и инерциальные атаки
- hardware-acoustic-cryptanalysis — Акустический криптоанализ и side-channel
- hardware-supply-chain-secure — Безопасность supply chain железа end-to-end
- hardware-hardware-ctf — Hardware-CTF: типовые стенды, задачи и подходы
- hardware-lab-setup — Организация лаборатории: питание, ESD, инструменты, безопасность

## misc

Total unique proposed lessons: **305**

### Квантовые вычисления и пост-квантовая криптография

- misc-quantum-crypto — Квантовые вычисления и пост-квантовая криптография в CTF
- misc-lattice-crypto — Решёточная криптография (LWE, NTRU) в задачах
- misc-qkd — Квантовое распределение ключей: протоколы и атаки
- misc-grover-shor — Grover и Shor: как ломают RSA/ECC
- misc-quantum-oracle — Квантовые оракулы и алгоритм Саймона
- misc-pqc-migration — Переход на пост-квантовые схемы (Kyber, Dilithium)
- misc-qiskit-cirq — Qiskit/Cirq: моделирование квантовых схем

### Блокчейн и Web3 (продвинутое)

- misc-evm-internals — Внутренности EVM: opcodes, gas, storage layout
- misc-solana-ctf — Solana и Anchor: PDA, account confusion, CPI
- misc-cairo-starknet — Cairo/StarkNet: felt-арифметика и уязвимости
- misc-zk-circuits — ZK-схемы (Circom, Groth16): атаки на доказательства
- misc-flash-loan — Flash loan и манипуляции оракулами
- misc-oracle-manipulation — Оракулы цен и их атаки
- misc-defi-mev-deep — Продвинутый MEV: sandwich, backrun, JIT
- misc-bitcoin-script — Bitcoin Script, SegWit и Ordinals
- misc-signature-replay — Подписи, permit и replay в Web3
- misc-rust-solana — Rust в Solana-контрактах: аудит
- misc-move-sui — Move/Sui: ресурсная модель и уязвимости
- misc-cosmos-wasm — Cosmos и CosmWasm-контракты
- misc-yul-assembly — Yul/assembly-оптимизации и их баги
- misc-upgradeable-proxy — Прокси-паттерны (UUPS, diamond) и их баги
- misc-erc-standards — Тонкости ERC-20/721/1155 и нестандарты
- misc-ctf-web3-meta — Методология Web3-CTF и разведка контрактов

### Сериализация данных и парсинг

- misc-protobuf — Protobuf: varint, схемы, обратный разбор
- misc-msgpack-cbor — MessagePack, CBOR, BSON: парсинг и атаки
- misc-asn1-der — ASN.1/DER: разбор и уязвимости
- misc-avro-thrift — Avro и Thrift: схемы и десериализация
- misc-toml-ini — TOML/INI: парсеры и трюки
- misc-csv-injection — CSV injection и формульные атаки
- misc-markdown-render — Markdown-рендер: mXSS и парсер-диффы
- misc-html-parser-diff — Диффы HTML-парсеров и mXSS
- misc-html-email — HTML-письма: парсинг и CSS-эксфильтрация
- misc-ical-vcard — iCalendar/vCard: парсинг и уязвимости
- misc-srt-subtitle — SRT/VTT/ASS: парсинг и инъекции
- misc-ndjson-lines — NDJSON/line-delimited: потоковый разбор
- misc-ebml-matroska — EBML/Matroska: структура и разбор
- misc-plexus-parser — Парсер-диффы и обход валидации

### Форматы файлов и медиа (углублённо)

- misc-font-parsing — Шрифты (TTF/OTF/WOFF): таблицы, глифы, эксплойты
- misc-exif-deep — EXIF/IPTC/XMP: метаданные и GPS
- misc-sqlite-forensics — SQLite: WAL, freelist, восстановление удалённого
- misc-nbt-anvil — Minecraft NBT/Anvil: форматы и модификации
- misc-savegame-formats — Форматы сохранений игр: разбор и редактирование
- misc-3d-model-formats — 3D-форматы (STL/OBJ/GLTF): разбор
- misc-ebook-formats — EPUB/MOBI: разбор и DRM
- misc-office-macro — OOXML-макросы и вложенные объекты
- misc-archive-nested — Вложенные архивы и zip-bombs
- misc-disk-image-misc — Образы дисков: MBR/GPT, разделы, loopback
- misc-carving-misc — Carving файлов из raw-данных
- misc-midi-misc — MIDI: события, sysex, каналы
- misc-pcap-misc — PCAP в misc: разбор нестандартных протоколов
- misc-compound-doc — Legacy OLE/Compound File: структура
- misc-postscript-misc — PostScript/PJL: разбор и инъекции
- misc-dwg-misc — CAD-форматы (DWG/DXF): разбор
- misc-mobile-format-misc — APK/IPA как контейнеры в misc-задачах

### Ядро, системы и изоляция (углублённо)

- misc-syscall-fuzzing — Фаззинг syscalls (syzkaller) в CTF
- misc-kernel-module — Разбор kernel-модулей и ioctl
- misc-ebpf-deep — eBPF: программы, карты, верификатор, побег
- misc-io-uring — io_uring: уязвимости и эксплойт
- misc-vdso-vvar — vDSO/vvar: подмена и атаки
- misc-procfs-tricks — /proc и /sys: утечки и трюки
- misc-netfilter — Netfilter/nftables: правила и обход
- misc-seccomp-bpf-deep — seccomp-BPF: фильтры и обход
- misc-namespace-deep — namespaces: user/pid/net и побеги
- misc-cgroup-v2 — cgroups v2: изоляция и побеги
- misc-landlock — Landlock LSM: песочницы
- misc-fuse-misc — FUSE: файловые системы в userland
- misc-tty-pty — TTY/pty: инъекции и побеги
- misc-signal-tricks — Сигналы: перехват, seccomp, ptrace
- misc-ptrace-debug — ptrace: отладка, инъекции, анти-отладка
- misc-selinux-apparmor — SELinux/AppArmor: профили и обход
- misc-uefi-secureboot — UEFI/Secure Boot в misc-задачах
- misc-initramfs — initramfs/initrd: распаковка и модификация
- misc-kexec-livepatch — kexec и livepatch: подмена ядра
- misc-bpf-tracing — bpftrace/perf: трассировка и атаки
- misc-numa-misc — NUMA и топология памяти
- misc-ksm-thp — KSM/THP: дедупликация памяти и атаки

### Память и аллокаторы

- misc-heap-misc — Heap-эксплуатация в misc (glibc)
- misc-glibc-versions — Различия glibc: tcache, safe-linking, hooks
- misc-musl-allocator — musl malloc: внутренности и эксплойт
- misc-windows-heap — Windows heap: LFH и эксплойты
- misc-aslr-bypass — Обход ASLR: утечки и частичные перезаписи
- misc-cfi-bypass — CFI/CET/Shadow Stack: обход
- misc-memory-forensics-misc — Анализ дампов памяти в misc
- misc-rop-misc — ROP/JOP-цепочки в misc-задачах
- misc-sigreturn-misc — SROP и signal-return-ориентированное программирование
- misc-ret2dlresolve — ret2dlresolve и динамическая линковка
- misc-fsop — FSOP: подмена FILE-структур
- misc-house-of — House of X-техники (force, spirit, einherjar)

### Сетевые протоколы и сервисы

- misc-websocket-misc — WebSocket: фреймы, маскирование, атаки
- misc-quic-misc — QUIC/HTTP3: разбор и атаки
- misc-mqtt-misc — MQTT: брокеры, топики, утечки
- misc-coap-misc — CoAP: протокол IoT и атаки
- misc-modbus-misc — Modbus/ICS-протоколы в misc
- misc-grpc-misc — gRPC: protobuf-фреймы и отражение
- misc-dns-misc — DNS в misc: туннели, rebinding, exfil
- misc-ntp-misc — NTP: amplification и подделка
- misc-ssdp-upnp — SSDP/UPnP: обнаружение и атаки
- misc-mdns-zeroconf — mDNS/ZeroConf: спуфинг
- misc-smb-protocol — SMB в misc: разбор пакетов
- misc-tls-fingerprint — JA3/JA4: фингерпринтинг и обход
- misc-raw-sockets — Raw sockets и scapy для задач
- misc-can-bus — CAN-шина: кадры и инъекции
- misc-serial-uart — UART и последовательные протоколы
- misc-ipv6-misc — IPv6 в misc: туннели, RA, ND
- misc-rdp-protocol — RDP-протокол: разбор и атаки
- misc-kerberos-misc — Kerberos-пакеты в misc-задачах
- misc-ipsec-misc — IPsec/IKE: разбор и атаки
- misc-openvpn-wireguard — VPN-протоколы: разбор handshake

### Игры, эмуляторы и хардвар

- misc-gameboy-rom — Game Boy ROM: разбор и патч
- misc-nes-rom — NES ROM: мапперы и хаки
- misc-chess-engine — Шахматные движки: UCI и взлом
- misc-emulator-dev — Разработка эмуляторов и их уязвимости
- misc-save-state — Save states: разбор и манипуляции
- misc-tas-speedrun — TAS/скоростное прохождение: инструменты
- misc-anti-cheat — Анти-читы: обход и обнаружение
- misc-game-network — Игровые сетевые протоколы и читы
- misc-retro-console — Ретро-консоли и картриджи
- misc-firmware-extract — Извлечение прошивок (binwalk, unblob)
- misc-usb-misc — USB: дескрипторы и HID-инъекции
- misc-bluetooth-misc — Bluetooth в misc-задачах
- misc-nfc-rfid-misc — NFC/RFID в misc-задачах
- misc-ir-remote — ИК-пульты и сигналы
- misc-gps-nmea — GPS/NMEA-парсинг и спуфинг
- misc-lora-misc — LoRa/LoRaWAN в CTF
- misc-zigbee-misc — Zigbee: кадры и атаки
- misc-zwave-misc — Z-Wave: разбор и атаки
- misc-jtag-swd-misc — JTAG/SWD в misc-задачах
- misc-logic-analyzer — Логические анализаторы и декодирование

### Случайность, время и гонки

- misc-prng-attacks — PRNG-атаки: MT19937, LCG, xorshift
- misc-timing-attacks — Timing-атаки и сравнение строк
- misc-race-conditions — Гонки в misc (TOCTOU)
- misc-fork-bomb — fork-bomb и исчерпание ресурсов
- misc-entropy-misc — Энтропия и /dev/urandom в задачах
- misc-clock-skew — Часовые пояса, tzdata и skew
- misc-leap-second — Високосные секунды и даты-края
- misc-y2k38 — Переполнение времени (2038) в задачах

### Криптография в misc (углублённо)

- misc-modern-cipher-misc — AES/ChaCha в misc-задачах
- misc-hash-collision — Коллизии хешей (MD5, SHA-1, chosen-prefix)
- misc-length-extension — Length-extension атаки на хеши
- misc-mac-forgery — CBC-MAC/CMAC/GMAC: подделка
- misc-padding-oracle — Padding oracle в misc
- misc-stream-nonce — Повтор nonce и XOR-утечки
- misc-rsa-misc — RSA в misc: Wiener, Coppersmith, общие модули
- misc-ecc-misc — ECC в misc: invalid curve, twist
- misc-dh-misc — Diffie-Hellman: small subgroup, invalid key
- misc-crt-fault — CRT-fault атаки на подпись
- misc-crypto-sidechannel — Крипто-побочные каналы (Kocher)
- misc-hash-cracking-misc — Взлом хешей: режимы и оптимизация
- misc-password-hashing — Алгоритмы паролей (bcrypt, argon2) в задачах
- misc-homomorphic — Гомоморфное шифрование: задачи и атаки
- misc-secret-sharing — Разделение секрета (Shamir, SSS)
- misc-mpc-misc — MPC-протоколы и их утечки
- misc-caesar-morse-bacon — Морзе, Бэкон, Полибий и классика
- misc-musical-book-cipher — Музыкальные и книжные шифры

### Регулярные выражения и парсинг языков

- misc-regex-engines — Движки регексов: PCRE/RE2/Oniguruma
- misc-regex-catastrophic — Катастрофический backtracking (ReDoS deep)
- misc-grammar-parsing — Грамматики и парсер-генераторы
- misc-antlr-parser — ANTLR/PEG: разбор кастомных языков
- misc-interpreter-write — Написать интерпретатор для задачи
- misc-compiler-ctf — Компилятор/транспайлер в CTF
- misc-vm-bytecode — Кастомные VM и байткод-задачи
- misc-turing-machine — Машина Тьюринга и автоматы
- misc-lexer-tricks — Лексеры и обход токенизации
- misc-grammar-injection — Инъекции через грамматики и DSL

### Математика и вычисления (углублённо)

- misc-fft-convolution — FFT и свёртки в задачах
- misc-linear-algebra — Линейная алгебра над GF(2)/полями
- misc-poly-gf — Полиномы над конечными полями
- misc-lattice-reduction — LLL и решёточные редукции
- misc-sat-solving — SAT-солверы и кодирование
- misc-cp-sat — CP-SAT/OR-Tools: оптимизация
- misc-markov-chains — Цепи Маркова и случайные блуждания
- misc-probability — Вероятностные задачи и Monte-Carlo
- misc-numerical-methods — Численные методы и точность
- misc-optimization — Оптимизация и линейное программирование
- misc-info-theory — Теория информации и энтропия
- misc-error-correcting — Помехоустойчивые коды (Hamming, RS)
- misc-compression-algos — Алгоритмы сжатия и их взлом
- misc-huffman-arithmetic — Хаффман/арифметическое кодирование
- misc-game-theory — Теория игр и стратегии
- misc-combinatorics — Комбинаторика и перечисление
- misc-bitmask-dp — Битмаски и DP по подмножествам
- misc-string-algorithms — Строковые алгоритмы (KMP, Z, suffix)
- misc-sqrt-decomposition — sqrt-декомпозиция и Mo
- misc-fft-ntt — NTT и модульная арифметика

### ML/AI и LLM (углублённо)

- misc-llm-rag — RAG: отравление, извлечение, обход guardrails
- misc-llm-guardrails — Guardrails и их обход
- misc-multimodal-llm — Мультимодальные LLM: атаки на vision
- misc-prompt-leak — Утечка системного промпта
- misc-llm-tool-abuse — Злоупотребление tool-use и function calling
- misc-agentic-escape — Побег агентных систем
- misc-mcp-security — MCP: безопасность серверов и тулов
- misc-model-extraction — Извлечение модели (model stealing)
- misc-adversarial-examples — Adversarial-примеры и патчи
- misc-data-poisoning — Отравление обучающих данных
- misc-backdoor-models — Бэкдоры в моделях
- misc-membership-inference — Membership inference
- misc-llm-supply-chain — Supply chain LLM (pickle, safetensors)
- misc-pickle-ml — Pickle-десериализация ML-моделей
- misc-diffusion-attacks — Диффузионные модели: атаки
- misc-voice-deepfake — Голосовые дипфейки и детекция
- misc-ai-watermark — Водяные знаки AI-контента
- misc-llm-tokenizer — Токенизаторы и их атаки
- misc-jailbreak-encoding — Кодирование для обхода фильтров (base64, ciphers)
- misc-ai-prompt-injection-misc — Прямые и косвенные prompt injection

### Песочницы и рантаймы (углублённо)

- misc-php-sandbox — PHP sandbox escape (disable_functions)
- misc-java-sandbox — Java sandbox/SecurityManager обход
- misc-go-sandbox — Go-песочницы и unsafe
- misc-rust-sandbox — Rust unsafe и песочницы
- misc-deno-bun — Deno/Bun: песочницы и права
- misc-gvisor — gVisor: внутренности и побег
- misc-firecracker — Firecracker microVM: изоляция и побег
- misc-qemu-escape — QEMU/VMM escape
- misc-kata-containers — Kata Containers: побег
- misc-crun-podman — crun/podman: побег из контейнера
- misc-lxc-incus — LXC/Incus: изоляция и побег
- misc-wasm-deep — WASM: валидатор, sandbox, эксплойты
- misc-wasmtime-wasmer — WASM-рантаймы: уязвимости
- misc-llvm-ir — LLVM IR: разбор и оптимизации
- misc-jit-spray — JIT-спрей и эксплуатация
- misc-v8-internals — V8: интерпретатор, JIT, эксплойты
- misc-spidermonkey — SpiderMonkey/JavaScriptCore internals
- misc-lua-c-api — Lua C-API и песочницы
- misc-ruby-gvl — Ruby GVL и потоки в песочницах
- misc-perl-taint — Perl taint-режим и его обход
- misc-tcl-safe — Tcl safe-interp и побег
- misc-sqlite-ext — SQLite-расширения и песочницы

### Web-уязвимости в misc

- misc-http2-smuggling — HTTP/2 в misc
- misc-cache-poison-misc — Cache poisoning в misc
- misc-ssti-misc — SSTI в misc
- misc-prototype-pollution — Prototype pollution
- misc-nosql-misc — NoSQL-инъекции в misc
- misc-graphql-misc — GraphQL в misc
- misc-deser-misc — Десериализация в misc (Java/PHP/Python)
- misc-xxe-misc — XXE в misc
- misc-ldap-misc — LDAP-инъекции
- misc-xpath-misc — XPath-инъекции
- misc-crlf-injection — CRLF/header-инъекции
- misc-open-redirect-misc — Open redirect в misc-задачах

### Кодировки, обфускация и текст

- misc-quine — Квины и саморепликация
- misc-code-golf — Code golf
- misc-unicode-exploits — Unicode-эксплойты (bidi, Trojan Source)
- misc-homoglyph — Гомоглифы и confusable
- misc-bidi-attack — Trojan Source и bidi-контрол
- misc-terminal-escape — ANSI-escape инъекции
- misc-filename-tricks — Трюки с именами файлов
- misc-env-tricks — Переменные окружения и их абуз
- misc-locale-tricks — Локали и ICU
- misc-fp-precision — Числа с плавающей точкой и их баги
- misc-integer-overflow — Переполнения целых
- misc-bit-manipulation — Бит-манипуляции
- misc-endianness — Порядок байтов
- misc-base-conversion — Системы счисления и конверсии
- misc-text-compression — Текстовые компрессоры (smaz, shrinker)
- misc-braille-semaphore — Брайль, семафор, другие алфавиты
- misc-captcha-solve — Решение CAPTCHA
- misc-ocr-deep — OCR: Tesseract, предобработка
- misc-qr-damaged — Повреждённые QR/штрихкоды
- misc-barcode-formats — Форматы штрихкодов: генерация и чтение

### Эзотерические языки (доп.)

- misc-esolang-lolcode — LOLCODE и интерпретация
- misc-esolang-brainfuck-deep — Brainfuck-оптимизация и гольф
- misc-esolang-cow — Cow, Ook! и производные
- misc-esolang-piet-deep — Piet: компиляция изображений
- misc-esolang-chef — Chef и двумерные кулинарные языки
- misc-esolang-false — FALSE и стековые эзотерики
- misc-esolang-malbolge-deep — Malbolge: генерация программ
- misc-esolang-whitespace-deep — Whitespace: инструменты
- misc-esolang-jsfuck-deep — JSFuck/jjencode/AAencode deep
- misc-esolang-befunge-deep — Befunge: 3D и funge-98
- misc-esolang-sha-256 — SHA-256 как эзотерический язык
- misc-esolang-rockstar — Rockstar и прочие шуточные
- misc-esoteric-golf — Эзотерический гольф и минимализм

### Инструменты и автоматизация

- misc-pwntools-deep — pwntools: продвинутые приёмы
- misc-scapy-deep — scapy: конструирование пакетов
- misc-cyberchef — CyberChef: рецепты и автоматизация
- misc-z3-deep — Z3: продвинутое моделирование
- misc-sage-misc — SageMath для misc-задач
- misc-scripting-bash-deep — Bash-скриптинг для задач
- misc-parallel-tools — GNU parallel и xargs
- misc-gdb-scripts — GDB-скрипты и автоматизация
- misc-radare2 — radare2/rizin для misc
- misc-binwalk-deep — binwalk/unblob: извлечение
- misc-yara-misc — YARA-правила для задач
- misc-docker-tooling — Docker для воспроизводимых задач
- misc-nix-reproducible — Nix/воспроизводимость
- misc-jupyter-ctf — Jupyter/ноутбуки для анализа

### Разное и общее

- misc-misc-methodology-deep — Углублённая методология misc-CTF
- misc-teaming — Командная работа в CTF
- misc-hint-reading — Разбор условий и скрытых подсказок
- misc-scoring-strategy — Стратегия набора очков
- misc-custom-format-rev — Реверс кастомных форматов
- misc-spec-reading — Чтение RFC/спецификаций
- misc-differential-analysis — Дифференциальный анализ
- misc-fuzzing-misc — Фаззинг для misc-задач
- misc-symbolic-exec — Символьное исполнение (angr, KLEE)
- misc-concolic — Коколическое тестирование
- misc-decompiler-misc — Декомпиляторы (Ghidra, IDA) в misc
- misc-patcher-misc — Патчинг бинарей и рантайма
- misc-anti-analysis — Анти-анализ и обход
- misc-time-based-puzzles — Задачи с таймингом
- misc-multistage — Многоэтапные цепочки задач
- misc-file-format-detection — Определение форматов по содержимому
- misc-entropy-analysis — Энтропийный анализ данных
- misc-data-recovery — Восстановление данных
- misc-flag-formats — Форматы флагов и их поиск
- misc-writeup-methodology — Как писать райтапы

## mobile

Total unique proposed lessons: **330**

### Android: компоненты и IPC (углублённо)

- mobile-android-pendingintent — PendingIntent: mutable-флаги и захват
- mobile-android-accessibility — Accessibility Service: злоупотребление
- mobile-android-device-admin — Device Admin / Device Owner API
- mobile-android-notification-listener — NotificationListenerService: перехват
- mobile-android-overlay — Overlay-атаки (SYSTEM_ALERT_WINDOW)
- mobile-android-fileprovider — FileProvider: path traversal и URI-утечки
- mobile-android-shared-uid — Shared UID и коллизии пакетов
- mobile-android-implicit-intent — Неявные интенты и перехват
- mobile-android-protected-broadcast — Protected/Sticky broadcasts
- mobile-android-sticky-broadcast — Sticky broadcast и утечки
- mobile-android-foreground-service — Foreground-сервисы и их абуз
- mobile-android-job-scheduler — JobScheduler/WorkManager-злоупотребление
- mobile-android-bound-service — Bound-сервисы и их эксплуатация
- mobile-android-aidl — AIDL-интерфейсы и их атаки
- mobile-android-messenger-ipc — Messenger/Binder-обмен и атаки
- mobile-android-asynctask — Устаревшие API и их баги
- mobile-android-contentprovider-sql — Content Provider SQL-инъекции deep
- mobile-android-contentprovider-grant — URI-permission grants и их абуз

### Android: платформа, ядро и аппаратное доверие

- mobile-android-selinux — SELinux в Android: политики и обход
- mobile-android-verified-boot — Verified Boot и dm-verity
- mobile-android-bootloader — Загрузчик: разблокировка и последствия
- mobile-android-kernel-exploit — Эксплуатация Android-ядра
- mobile-android-trustzone — TrustZone/TEE: атаки
- mobile-android-strongbox — StrongBox и Titan M
- mobile-android-tee-attacks — Атаки на TEE и Secure Element
- mobile-android-attestation — Key Attestation: проверка и обход
- mobile-android-hardware-keys — Аппаратные ключи и HSM
- mobile-android-fbe-fde — File-Based/Full-Disk Encryption: атаки
- mobile-android-metadata — Метаданные Android-артефактов
- mobile-android-lockscreen — Обход блокировки экрана
- mobile-android-factory-reset — Обход Factory Reset Protection
- mobile-android-privesc — Эскалация привилегий на устройстве
- mobile-android-persistence — Персистентность на Android
- mobile-android-system-app — Системные приложения и их привилегии
- mobile-android-privileged-perm — Privileged permissions и их абуз
- mobile-android-init-rc — init.rc и сервисы Android
- mobile-android-property-service — Системные свойства и их подмена

### Android: сборка, форматы, реверс

- mobile-android-split-apk — Split APK и base/конфиг-разделение
- mobile-android-aab — App Bundle: разбор и Play Asset Delivery
- mobile-android-odex-vdex — ODEX/VDEX/ART-форматы
- mobile-android-smali-patch — Патч smali и пересборка
- mobile-android-multidex — Multidex и загрузка классов
- mobile-android-dynamic-code — Динамическая загрузка кода (DexClassLoader)
- mobile-android-reflection — Reflection-злоупотребление
- mobile-android-native-libs — Нативные библиотеки: загрузка и инъекции
- mobile-android-ndk-debug — Нативная отладка (gdb/lldb)
- mobile-android-unicorn-emu — Unicorn-эмуляция native-кода
- mobile-android-ghidra — Ghidra для Android native
- mobile-android-angr — Angr для Android-задач
- mobile-android-jadx-deep — JADX deep: скрипты и плагины
- mobile-android-mobsf-deep — MobSF deep: автоматизация и API
- mobile-android-apktool — apktool: сборка и разбор
- mobile-android-signature-spoof — Подмена подписи и обновление
- mobile-android-janus — Janus CVE-2017-13156
- mobile-android-masterkey — Master Key CVE-2013-4787
- mobile-android-debuggable — debuggable-флаг и run-as
- mobile-android-allowbackup — allowBackup и авто-бэкап
- mobile-android-cleartext — cleartextTraffic и сетевые флаги
- mobile-android-instant-apps — Instant Apps: поверхность атаки
- mobile-android-odex-unpack — Распаковка ART-профилей и odex

### Android: хукинг и защита

- mobile-android-inline-hook — Inline-хуки (Dobby, substrate)
- mobile-android-plt-got-hook — PLT/GOT-хуки
- mobile-android-syscall-hook — Syscall-хуки и их обход
- mobile-android-art-internals — ART-интерналы: GC, компилятор
- mobile-android-jit — JIT и профилирование
- mobile-android-frida-gadget — Frida Gadget без root
- mobile-android-lsposed — LSPosed-модули: разработка
- mobile-android-xposed-deep — Xposed-модули deep
- mobile-android-detect-emulator — Детект эмулятора (deep)
- mobile-android-detect-proxy — Обход детекта прокси
- mobile-android-detect-vpn — Детект VPN и обход
- mobile-android-detect-debug — Обход детекта отладки
- mobile-android-root-hidden — Скрытие root (Shamiko, Zygisk)
- mobile-android-playintegrity-deep — Play Integrity API deep
- mobile-android-safetynet-legacy — Legacy SafetyNet и его обход
- mobile-android-attestation-bypass — Обход attestation-проверок
- mobile-android-rasp — RASP: обнаружение и обход
- mobile-android-app-shielding — App-shielding и распаковка
- mobile-android-dexguard — DexGuard-обход
- mobile-android-ollvm — OLLVM/нативная обфускация
- mobile-android-string-encrypt — Шифрование строк и его снятие
- mobile-android-whitebox — White-box-криптография в приложениях
- mobile-android-vmp — VMProtect на мобильных

### Android: сеть и API

- mobile-android-oauth — OAuth в Android: Custom Tabs, AppAuth
- mobile-android-quic — QUIC/HTTP3 в мобильных приложениях
- mobile-android-grpc — gRPC в мобильных приложениях
- mobile-android-websocket — WebSocket в мобильных приложениях
- mobile-android-ssl-pinning-native — Нативный pinning и обход
- mobile-android-cert-transparency — Certificate Transparency на мобильных
- mobile-android-pinning-deep — Продвинутый pinning bypass (multi-layer)
- mobile-android-account-manager — AccountManager: утечки и абуз
- mobile-android-sync-adapter — SyncAdapter-абуз
- mobile-android-jwt-mobile — JWT в мобильных приложениях
- mobile-android-api-graphql — GraphQL-API мобильных приложений
- mobile-android-api-versioning — Версионирование API и старые версии
- mobile-android-ratelimit-bypass — Обход rate-limit мобильного API

### Android: хранилища, ключи, приватность

- mobile-android-keystore-deep — Android Keystore deep: KeyGenParameterSpec
- mobile-android-biometric-prompt — BiometricPrompt-обход
- mobile-android-screenshots — FLAG_SECURE и его обход
- mobile-android-screen-record — MediaProjection и запись экрана
- mobile-android-clipboard-deep — Буфер обмена deep
- mobile-android-ime — Клавиатуры/IME: кейлоггинг
- mobile-android-autofill — Autofill-фреймворк: утечки
- mobile-android-random — Random/SecureRandom-ошибки
- mobile-android-keygen-errors — Ошибки генерации ключей
- mobile-android-crypto-deep — Криптография Android deep
- mobile-android-analytics — Аналитика и телеметрия: утечки
- mobile-android-crashlytics — Crash-репортинг: утечки
- mobile-android-tracking — Трекинг и его обнаружение
- mobile-android-privacy — Приватность и GDPR в приложениях

### Android: enterprise, MDM, окружение

- mobile-android-work-profile — Work Profile и разделение данных
- mobile-android-multi-user — Мультипользовательские устройства
- mobile-android-enterprise — Android Enterprise
- mobile-android-kiosk — Kiosk-режим и его обход
- mobile-android-mdm-deep — MDM deep: политики и обход
- mobile-android-zero-touch — Zero-touch enrollment
- mobile-android-device-policy — Device Policy Controller
- mobile-android-samsung-knox — Samsung Knox
- mobile-android-gms — GMS-зависимости и атаки
- mobile-android-gms-safety — GMS SafetyNet/Integrity
- mobile-android-firebase-auth — Firebase Auth: конфиги и утечки
- mobile-android-remote-config — Firebase Remote Config
- mobile-android-dynamic-feature — Dynamic Feature Modules

### Android: платформы и форм-факторы

- mobile-android-tv — Android TV: приложения и пульты
- mobile-android-foldable — Складные устройства и адаптивность
- mobile-android-large-screen — Планшеты/большие экраны
- mobile-android-xr — Android XR
- mobile-android-multimodal — Мультимодальные API (vision/voice)
- mobile-android-on-device-ai — On-device AI (Gemini Nano, ML Kit)
- mobile-android-ml-model — ML-модели в приложении: извлечение
- mobile-android-nnapi — NNAPI/GPU-делегирование
- mobile-android-tflite — TFLite-модели: разбор и атаки
- mobile-android-onnx — ONNX-модели на устройстве
- mobile-android-wsa — Windows Subsystem for Android
- mobile-android-chromeos — Android на ChromeOS
- mobile-android-waydroid — Waydroid/Anbox

### iOS: платформа, подписи, доверие

- mobile-ios-code-signing — Код-подписи и entitlements
- mobile-ios-entitlements — Entitlements deep: привилегии
- mobile-ios-provisioning — Provisioning-профили
- mobile-ios-app-attest — App Attest и DeviceCheck
- mobile-ios-sandbox — iOS-песочница и её границы
- mobile-ios-sandbox-escape — Побег из песочницы
- mobile-ios-kernel — Ядро iOS: эксплойты
- mobile-ios-sep — Secure Enclave: атаки
- mobile-ios-pac — Pointer Authentication (PAC)
- mobile-ios-arm64e — arm64e и PAC-байпас
- mobile-ios-checkm8-deep — checkm8 deep
- mobile-ios-jailbreak-deep — Jailbreak-и и их обнаружение
- mobile-ios-dopamine — Современные jailbreak (Dopamine, palera1n)
- mobile-ios-trollstore — TrollStore и CoreTrust
- mobile-ios-macdirtycow — MacDirtyCow CVE-2022-46689
- mobile-ios-integrity — Проверки целостности iOS
- mobile-ios-anti-debug — Anti-debug на iOS и обход
- mobile-ios-anti-hook — Anti-hook (substrate/frida detection)
- mobile-ios-fairplay — FairPlay-шифрование
- mobile-ios-decryption — Расшифровка App Store-приложений

### iOS: IPC, рантайм, реверс

- mobile-ios-mach-ports — Mach-порты и IPC
- mobile-ios-xpc — XPC-сервисы и их атаки
- mobile-ios-objc-runtime — Objective-C runtime deep
- mobile-ios-dyld — dyld и загрузка библиотек
- mobile-ios-method-swizzle — Method swizzling и хуки
- mobile-ios-frida-deep — Frida на iOS deep
- mobile-ios-cycript-deep — Cycript deep
- mobile-ios-lldb-deep — LLDB deep на iOS
- mobile-ios-hooking-internals — Внутренности хукинга на iOS
- mobile-ios-swiftui — SwiftUI-приложения: реверс
- mobile-ios-combine — Combine/async-await в реверсе
- mobile-ios-coresymbolication — CoreSymbolication
- mobile-ios-symbolication — Символизация крашей
- mobile-ios-crash-reports — Crash-репорты: анализ
- mobile-ios-macho-deep — Mach-O deep: сегменты и лоады
- mobile-ios-static-libs — Статические библиотеки в IPA
- mobile-ios-xcframework — XCFramework и фреймворки
- mobile-ios-fuzzing — Фаззинг iOS-приложений
- mobile-ios-coresymbolication-deep — CoreSymbolication deep
- mobile-ios-app-clip — App Clips: поверхность атаки

### iOS: данные, хранилища, приватность

- mobile-ios-pasteboard — UIPasteboard-утечки
- mobile-ios-keychain-deep — Keychain access groups deep
- mobile-ios-app-groups — App Groups и общие данные
- mobile-ios-data-protection-deep — Data Protection classes deep
- mobile-ios-crypto — CommonCrypto/CryptoKit-ошибки
- mobile-ios-autofill — AutoFill и пароли
- mobile-ios-keyboard — Кастомные клавиатуры iOS
- mobile-ios-screenshot — Скриншоты и запись на iOS
- mobile-ios-privacy-manifest — Privacy Manifest и tracking
- mobile-ios-att — App Tracking Transparency
- mobile-ios-ads — Рекламные SDK: утечки
- mobile-ios-icloud-keychain — iCloud Keychain
- mobile-ios-cloud-backup — iCloud-бэкапы: анализ

### iOS: web, интеграция, сервисы

- mobile-ios-webview — WKWebView: атаки
- mobile-ios-javascriptcore — JavaScriptCore-эксплойты
- mobile-ios-shortcuts — Shortcuts-автоматизация и абуз
- mobile-ios-app-intents — App Intents и SiriKit
- mobile-ios-widgets — Widgets и Live Activities
- mobile-ios-sign-in-apple — Sign in with Apple
- mobile-ios-passkit — PassKit и Apple Pay
- mobile-ios-wallet — Wallet и NFC-платежи
- mobile-ios-healthkit — HealthKit-данные
- mobile-ios-homekit — HomeKit-безопасность
- mobile-ios-ibeacon — iBeacon и CoreLocation
- mobile-ios-corebluetooth — CoreBluetooth: атаки
- mobile-ios-corenfc — CoreNFC
- mobile-ios-arkit — ARKit и камеры
- mobile-ios-extensions — Расширения iOS и их поверхность
- mobile-ios-share-extension — Share-расширения
- mobile-ios-visionos — visionOS-приложения

### iOS: enterprise, развёртывание, инструменты

- mobile-ios-mdm — MDM на iOS
- mobile-ios-supervised — Supervised-устройства
- mobile-ios-dep — Apple DEP
- mobile-ios-configurator — Apple Configurator
- mobile-ios-lockdown — lockdownd и pairing
- mobile-ios-afc — AFC и файловый доступ
- mobile-ios-libimobiledevice — libimobiledevice
- mobile-ios-idevice-tools — idevice-tools
- mobile-ios-usb-restrict — USB-доступ и ограничения
- mobile-ios-testflight — TestFlight-развёртывание
- mobile-ios-xcode-debug — Xcode-отладка
- mobile-ios-instruments — Instruments-профилирование
- mobile-ios-sideload — Sideloading и его риски
- mobile-ios-altstore — AltStore/SideStore
- mobile-ios-eu-sideload — EU-сайдлоадинг (DMA)
- mobile-ios-ipa-repack — Перепаковка IPA

### Кросс-платформенные фреймворки и языки

- mobile-kotlin-multiplatform — Kotlin Multiplatform: реверс
- mobile-compose — Jetpack Compose: UI и безопасность
- mobile-maui — .NET MAUI: реверс и безопасность
- mobile-unity — Unity-приложения: реверс
- mobile-unreal — Unreal-приложения: реверс
- mobile-godot — Godot-приложения: реверс
- mobile-il2cpp — IL2CPP-реверс
- mobile-mono-unity — Mono/Unity DLL: реверс
- mobile-lua-mobile — Lua в мобильных приложениях
- mobile-cocos2d — Cocos2d-приложения
- mobile-game-reverse — Реверс мобильных игр
- mobile-pwa — PWA vs native
- mobile-mini-apps — Мини-приложения (WeChat, Telegram)
- mobile-telegram-mini — Telegram Mini Apps: безопасность
- mobile-superapp — Супер-приложения: поверхность атаки
- mobile-web3-wallet — Крипто-кошельки на мобильных

### SDK, платежи, монетизация, фрод

- mobile-sdk-security — Безопасность SDK
- mobile-third-party-sdk — Сторонние SDK: риски
- mobile-analytics-sdk — Аналитические SDK
- mobile-ad-sdk — Рекламные SDK
- mobile-payment-sdk — Платёжные SDK
- mobile-in-app-purchase — IAP: обход и подделка
- mobile-subscription-fraud — Фрод подписок
- mobile-receipt-validation — Проверка чеков
- mobile-license-check — Лицензионные проверки и обход
- mobile-piracy — Пиратство и обход
- mobile-anti-piracy — Anti-piracy и anti-tamper
- mobile-banking-security — Безопасность банковских приложений
- mobile-payment-security — Платёжная безопасность
- mobile-kyc — KYC/identity-верификация и обход
- mobile-face-liveness — Liveness-детект и его обход
- mobile-identity-doc — Сканирование документов: атаки
- mobile-fraud — Мобильный фрод и его детект
- mobile-bot-detection — Bot-детект на мобильных
- mobile-device-fingerprint — Фингерпринтинг устройств
- mobile-attribution — Атрибуция (IDFA/GAID)

### Форензика и анализ (углублённо)

- mobile-android-forensics-tools — Инструменты Android-форензики
- mobile-android-timeline — Таймлайн Android-артефактов
- mobile-android-bugreport — Bugreport-анализ
- mobile-android-tombstone — Tombstone-анализ
- mobile-android-anr — ANR-анализ
- mobile-android-memory-dump — Дамп памяти процесса
- mobile-android-heap-dump — Heap-дамп Android
- mobile-live-memory — Живой анализ памяти
- mobile-volatility — Volatility для мобильных
- mobile-mvt — MVT: проверка компрометации
- mobile-autopsy-mobile — Autopsy для мобильных
- mobile-timeline-mobile — Таймлайн мобильных артефактов
- mobile-gps-artifacts — GPS/локации в артефактах
- mobile-app-usage-artifacts — Использование приложений: артефакты
- mobile-keyboard-artifacts — Артефакты клавиатур
- mobile-thumbnail-artifacts — Thumbnail-кэши
- mobile-notification-artifacts — Уведомления: артефакты
- mobile-cloud-backup-deep — Облачные бэкапы deep
- mobile-whatsapp-forensics — WhatsApp-форензика
- mobile-telegram-forensics — Telegram-форензика
- mobile-signal-forensics — Signal-форензика
- mobile-social-forensics — Соцсети: артефакты
- mobile-browser-forensics — Браузеры: артефакты
- mobile-android-perfetto — Perfetto-трассировка
- mobile-android-systrace — systrace-анализ
- mobile-logcat-deep — logcat deep: анализ
- mobile-dumpsys-deep — dumpsys deep

### Малварь, шпионаж, целевые атаки

- mobile-android-spyware — Коммерческий шпионаж (Pegasus-подобное)
- mobile-android-overlay-malware — Overlay-малварь
- mobile-android-malicious-keyboard — Вредоносные клавиатуры
- mobile-android-dropper — Дропперы и стаггеры
- mobile-android-banker-deep — Банковские трояны deep
- mobile-android-sms-stealer — Кража SMS/OTP
- mobile-android-rat — RAT на Android
- mobile-ios-spyware — iOS-шпионаж и zero-click
- mobile-zero-click — Zero-click эксплойты мобильных
- mobile-forensics-compromise — Признаки компрометации
- mobile-apt-mobile — APT против мобильных
- mobile-threat-intel — Threat intel для мобильных
- mobile-malware-family — Классификация семейств малвари

### Радио, телеком, IoT-компаньоны

- mobile-ble-reversing — Реверс BLE-протоколов
- mobile-ble-gatt-deep — GATT deep: характеристики и дескрипторы
- mobile-nfc-payment — NFC-платежи: атаки
- mobile-uwb — UWB (Ultra-Wideband)
- mobile-thread-matter — Thread/Matter в мобильных
- mobile-esim — eSIM и SIM-безопасность
- mobile-baseband — Baseband-атаки
- mobile-sim-toolkit — SIM Toolkit (STK)
- mobile-cellular-proto — Сотовые протоколы (2G/3G/4G/5G) с мобильного
- mobile-imsi-catcher — IMSI-catcher и защита
- mobile-sms-otp — SMS-OTP: перехват и обход
- mobile-sim-swap — SIM-swap-атаки
- mobile-esim-provisioning — eSIM-провижининг
- mobile-iot-companion — IoT-компаньоны: атаки
- mobile-wearable-deep — Носимые устройства deep
- mobile-auto-companion — Автомобильные компаньоны
- mobile-drone-app — Дроны и их приложения

### Тестирование, CI/CD, автоматизация

- mobile-appium — Appium-автоматизация
- mobile-espresso — Espresso-тесты
- mobile-xctest — XCTest/XCUITest
- mobile-maestro — Maestro-тестирование
- mobile-detox — Detox-тестирование
- mobile-monkey — Android Monkey-тестирование
- mobile-fuzz-native — Фаззинг нативного кода
- mobile-libfuzzer — libFuzzer на мобильных
- mobile-afl-native — AFL на мобильных
- mobile-sanitizers — ASan/UBSan на мобильных
- mobile-valgrind — Valgrind на Android
- mobile-ci-cd — CI/CD для мобильных приложений
- mobile-screenshot-testing — Визуальное тестирование
- mobile-pentest-report — Отчётность мобильного пентеста
- mobile-pentest-methodology — Методология мобильного пентеста (OWASP MASTG)

