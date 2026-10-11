# GAPS-offensive.md — Deep Curriculum Gap Audit (web / pwn / reversing)

**Scope:** the three "offensive" categories of the learning tree at `/home/Serebr1k/learning_tree`:
`content/web` (34 lessons), `content/pwn` (32), `content/reversing` (32).
**Method:** read every lesson's frontmatter (id/title/parent/difficulty) and every `##` section heading,
then diff against an expert CTF/pentest syllabus per domain. Read-only audit — **no lessons were written.**
**Verdict:** the user's skepticism is correct. ~33 lessons per category is a *foundation*, not a curriculum.
Each category is missing roughly **2x more lessons than it has**. Coverage is **32–39%**.

> This file merges the two concurrent gap-audit passes (see §5): it keeps the full existing-lesson
> inventory (required by the task) and the union of both missing-topic lists.

## Summary table

| Category  | Existing | Missing topics identified | Canonical target | Coverage | Verdict |
|-----------|---------:|--------------------------:|-----------------:|---------:|---------|
| web       | 34       | 73                        | ~107             | **32 %** | Strong spine, shallow on modern HTTP/desync + browser-edge classes |
| pwn       | 32       | 50                        | ~82              | **39 %** | Good classic coverage; modern glibc, kernel, Windows, browser are thin |
| reversing | 32       | 53                        | ~85              | **38 %** | Broad, but misses emulation/DBI depth, WASM, iOS, malware, protectors |
| **Total** | **98**   | **176**                   | **~274**         | **36 %** | Each category needs **+50 to +73** lessons to be credible |

**Bottom line:** none of these three categories is "complete" at ~32 lessons. A serious CTF player
can hit ~60–70% of *real* challenges with what exists, but the *hard* 30–40% of challenge classes
(HTTP smuggling variants + client-side desync, modern heap glibc 2.35+, kernel/Windows/browser pwn,
WASM/iOS/malware reversing, emulation & concolic) are **absent**.

---

# 1. WEB

## 1.1 Existing lessons (34)

| id | title | difficulty | parent |
|----|-------|-----------|--------|
| web-http-basics | Основы HTTP и анатомия веб-запроса | beginner | — (root) |
| web-architecture | Архитектура веб-приложений | beginner | web-http-basics |
| web-recon-fuzzing | Разведка и фаззинг | easy | web-architecture |
| web-auth-jwt-idor | Аутентификация, JWT, IDOR | medium | web-recon-fuzzing |
| web-business-logic | Бизнес-логика и race conditions | hard | web-auth-jwt-idor |
| web-waf-bypass | Обход WAF и фильтров | expert | web-business-logic |
| web-sqli | SQL-инъекции | medium | web-recon-fuzzing |
| web-xss | XSS | medium | web-sqli |
| web-command-injection | Command Injection | medium | web-sqli |
| web-file-upload | Загрузка файлов | medium | web-command-injection |
| web-ssti | SSTI | hard | web-file-upload |
| web-deserialization | Небезопасная десериализация | expert | web-ssti |
| web-lfi-path-traversal | LFI / Path Traversal | medium | web-architecture |
| web-ssrf | SSRF | hard | web-lfi-path-traversal |
| web-xxe | XXE | hard | web-ssrf |
| web-cookies-sessions | Cookies и сессии | medium | web-http-basics |
| web-same-origin-cors | SOP, CORS, postMessage | medium | web-http-basics |
| web-tls-certs | TLS и сертификаты | easy | web-http-basics |
| web-api-rest-graphql-soap | API: REST/GraphQL/SOAP | medium | web-architecture |
| web-api-security | BOLA, BFLA, mass assignment | hard | web-api-rest-graphql-soap |
| web-oauth-oidc-saml | OAuth2, OIDC, SAML | hard | web-auth-jwt-idor |
| web-csrf | CSRF | medium | web-auth-jwt-idor |
| web-clickjacking | Clickjacking | easy | web-csrf |
| web-csp-bypass | CSP и обход | hard | web-xss |
| web-prototype-pollution | Prototype pollution | hard | web-xss |
| web-open-redirect-crlf | Open Redirect / CRLF | medium | web-xss |
| web-race-conditions | Race conditions | hard | web-business-logic |
| web-request-smuggling | Request Smuggling / HTTP-2 | expert | web-waf-bypass |
| web-host-header | Host header и X-Forwarded | hard | web-waf-bypass |
| web-cache-poisoning | Cache Poisoning / Deception | expert | web-waf-bypass |
| web-subdomain-takeover | Subdomain Takeover | medium | web-recon-fuzzing |
| web-websocket | WebSocket security | medium | web-architecture |
| web-nosql-ldap-xpath | NoSQL/LDAP/XPath | medium | web-sqli |
| web-tooling | Burp, ffuf, nuclei, sqlmap | easy | web-recon-fuzzing |

## 1.2 Missing topics (73)

### A. Server-side injection — advanced (9)
| proposed id | title | parent | diff | why it matters |
|-------------|-------|--------|------|----------------|
| web-ssti-engines | SSTI по движкам: Jinja2, Twig, Freemarker, Velocity, Smarty, Handlebars, Mako, EJS, Pebble | web-ssti | expert | Per-engine sandbox escapes are the real skill; one generic SSTI lesson is shallow. |
| web-el-ognl-injection | Expression Language и OGNL-инъекции (SpEL, OGNL, MVEL) | web-ssti | hard | Spring/Struts RCE primitive; CVE-2017-5638 / CVE-2022-22963 class. |
| web-log4shell-jndi | JNDI-инъекции и Log4Shell (CVE-2021-44228) | web-ssti | expert | Single most impactful web CVE of the decade; LDAP/RMI callbacks. |
| web-orm-injection | ORM/HQL/JPQL-инъекции | web-sqli | hard | SQLi hides behind Hibernate/JPA/Prisma; distinct exploitation. |
| web-ssi-xslt-injection | SSI- и XSLT-инъекции | web-ssti | medium | Separate parsers, separate exploitation; absent entirely. |
| web-latex-csv-injection | LaTeX- и CSV/Formula-инъекции | web-command-injection | medium | PDF/export features; spreadsheet formula exfil. |
| web-http-parameter-pollution | HTTP Parameter Pollution и parameter smuggling | web-waf-bypass | medium | WAF bypass + logic bypass; used in every chained bug. |
| web-second-order-injection | Second-order и stored-инъекции | web-sqli | medium | Payload stored then executed elsewhere — scanners miss it. |
| web-nodejs-injection | Серверные инъекции в Node.js (eval, vm, child_process, template literals) | web-command-injection | hard | Node-specific sinks; growing CTF/bounty surface. |

### B. Client-side (14)
| proposed id | title | parent | diff | why it matters |
|-------------|-------|--------|------|----------------|
| web-dom-clobbering | DOM clobbering | web-xss | medium | Needed for CSP-bypass and sanitizer-bypass chains. |
| web-mxss | mXSS и обход sanitizer'ов | web-xss | hard | Defeats DOMPurify-class filters; core of modern XSS. |
| web-client-side-template-injection | CSTI и sandbox escape (AngularJS, Vue) | web-xss | hard | Client-side template injection is its own class. |
| web-dangling-markup | Dangling markup injection | web-xss | medium | Data exfil without JS; often overlooked. |
| web-css-injection | CSS-инъекции и эксфильтрация данных | web-xss | medium | Attribute/selector-based data theft. |
| web-prototype-pollution-rce | Prototype pollution → client gadgets → DOM XSS / server-side PP → RCE | web-prototype-pollution | expert | PP is only a marker when you can chain it to a sink. |
| web-csp-advanced | CSP advanced: nonce reuse, strict-dynamic, base-uri, script gadgets | web-csp-bypass | hard | Existing lesson covers basics only. |
| web-xs-leaks | XS-Leaks (cross-site leaks) | web-same-origin-cors | hard | Major modern class (cache/probe/timing side-channels). |
| web-service-worker | Service Worker и атаки на PWA | web-same-origin-cors | hard | Persistent client-side compromise. |
| web-trusted-types-bypass | Trusted Types и обходы клиентских защит | web-csp-bypass | hard | Bypassing modern browser hardening. |
| web-client-side-desync | Client-side desync (CSD) | web-request-smuggling | expert | Desync from the browser; 2022+ research area. |
| web-browser-security | Модель безопасности браузера: site isolation, CORB/ORB, COOP/COEP | web-same-origin-cors | medium | Foundation for all client-side attacks. |
| web-jsonp-xssi | JSONP и XSSI (JSON hijacking) | web-same-origin-cors | medium | Legacy but still live; leaks cross-origin data. |
| web-webstorage | Web Storage, IndexedDB и клиентские утечки | web-cookies-sessions | easy | Token/session storage mistakes. |

### C. HTTP / request manipulation (6)
| proposed id | title | parent | diff | why it matters |
|-------------|-------|--------|------|----------------|
| web-request-smuggling-advanced | Smuggling advanced: TE.TE, TE.CL, CL.0, H2.CL, H2.TE, response-queue poisoning, pause-based | web-request-smuggling | expert | The single highest-value modern web bug class; base lesson is intro-level. |
| web-http2-attacks | HTTP/2: h2c upgrade, pseudo-headers, HPACK, downgrade, request splitting, Rapid Reset | web-request-smuggling | expert | Modern targets are H2-first; classic CL.TE doesn't apply. |
| web-websocket-smuggling | WebSocket smuggling и tunnelling | web-websocket | expert | Upgrade-based desync; not covered. |
| web-http3-quic | HTTP/3 и QUIC: атаки и десинхронизация | web-request-smuggling | expert | Emerging transport; forward-looking. |
| web-http-verb-tampering | HTTP method/verb tampering и method override | web-waf-bypass | easy | Trivial access-control bypass still missed by tooling. |
| web-range-redos-dos | DoS через Range/ReDoS/amplification | web-business-logic | medium | Availability attacks are part of the syllabus. |

### D. Auth / identity (10)
| proposed id | title | parent | diff | why it matters |
|-------------|-------|--------|------|----------------|
| web-jwt-advanced | JWT advanced: jwk/jku/x5u injection, kid injection/SQLi, alg confusion | web-auth-jwt-idor | hard | The JWT lesson covers alg:none; the modern attack surface is far wider. |
| web-mfa-bypass | Обход 2FA/MFA: race, response manipulation, backup codes | web-auth-jwt-idor | hard | 2FA bypass is a staple of bug bounties. |
| web-password-reset | Password-reset poisoning, account enumeration | web-host-header | medium | Only touched inside the host-header lesson. |
| web-sso-mixup | OAuth mix-up, PKCE downgrade, device-code abuse | web-oauth-oidc-saml | expert | Beyond redirect_uri; the real SSO bug classes. |
| web-saml-deep | SAML deep: XSW, comment injection, signature stripping, replay | web-oauth-oidc-saml | expert | SAML is one lesson today; XSW alone is a lesson. |
| web-refresh-token | Refresh-token rotation и lifecycle flaws | web-auth-jwt-idor | hard | Long-lived session theft. |
| web-webauthn | WebAuthn/passkeys: атаки и ошибки реализации | web-auth-jwt-idor | expert | Passkeys are shipping everywhere now. |
| web-remember-me | Remember-me и persistent-token abuse | web-cookies-sessions | medium | Spring Security-style token forgery. |
| web-ntlm-relay-web | NTLM relay через web (Responder, WebDAV) | web-host-header | expert | Internal-network pivot from a web bug. |
| web-session-puzzling | Session puzzling и advanced fixation | web-cookies-sessions | medium | Subtle state-confusion class. |

### E. Access control / business logic (9)
| proposed id | title | parent | diff | why it matters |
|-------------|-------|--------|------|----------------|
| web-idor-uuid | IDOR на UUID/opaque id: предиктивность и enumeration | web-auth-jwt-idor | medium | UUIDs are assumed safe and are not. |
| web-graphql-deep | GraphQL deep: introspection off, batching, aliasing, depth/circular DoS, authz | web-api-rest-graphql-soap | hard | GraphQL gets one section today; it needs a lesson. |
| web-grpc | gRPC и protobuf: реверс и атаки | web-api-rest-graphql-soap | hard | Entirely absent protocol. |
| web-serverless | Serverless/FaaS: SSRF, event injection, cold-start | web-ssrf | hard | Cloud-native attack surface. |
| web-webhooks | Webhooks: SSRF, signature bypass, replay | web-api-security | medium | Common integration bug. |
| web-openapi-exposure | Утечки Swagger/OpenAPI и debug-страниц | web-recon-fuzzing | easy | Free attack-surface disclosure. |
| web-business-logic-advanced | Продвинутая логика: workflow bypass, currency rounding, limit-overrun | web-business-logic | hard | Beyond race conditions. |
| web-race-single-packet | Race conditions: single-packet attack, Turbo Intruder, limit-overrun | web-race-conditions | expert | Existing lesson is conceptual; single-packet is the modern technique. |
| web-captcha-bypass | Обход CAPTCHA и anti-automation | web-business-logic | medium | Enables brute force / enumeration. |

### F. Infrastructure / server / deserialization (16)
| proposed id | title | parent | diff | why it matters |
|-------------|-------|--------|------|----------------|
| web-dns-rebinding | DNS rebinding | web-ssrf | hard | Bypasses SSRF allowlists entirely. |
| web-ssrf-cloud-deep | SSRF в облака: AWS/GCP/Azure metadata и IAM | web-ssrf | hard | Metadata → IAM creds → full account takeover. |
| web-ssrf-protocol-smuggling | SSRF protocol smuggling: gopher/dict/redis/fastcgi/mysql | web-ssrf | expert | Turns SSRF into RCE. |
| web-zip-slip | Zip Slip и атаки на распаковку | web-file-upload | medium | Path traversal via archives. |
| web-php-wrappers | PHP-обёртки и inclusion-to-RCE | web-lfi-path-traversal | medium | php://filter, data://, expect://, log poisoning. |
| web-log-poisoning | Log poisoning → LFI → RCE | web-lfi-path-traversal | medium | Classic LFI escalation. |
| web-php-tricks | PHP internals для CTF: type juggling, magic hashes, php://filter chains, phar | web-deserialization | hard | php filter-chain RCE and phar deser are ubiquitous. |
| web-server-misconfig | Мисconfig серверов: Apache/nginx/IIS CVEs и alias traversal | web-architecture | medium | Server-software bugs (the `svc-web-server` domain). |
| web-framework-cves | Фреймворк-CVE: Spring4Shell, Struts, Tomcat, Jenkins | web-architecture | expert | N-day exploitation of common stacks. |
| web-git-env-exposure | Утечки .git/.env/backup и source disclosure | web-recon-fuzzing | easy | Highest-ROI recon finding. |
| web-java-deser-chains | Java deserialization gadget chains (ysoserial) | web-deserialization | expert | The lesson is intro; gadget chains are the craft. |
| web-php-deser-chains | PHP deserialization POP chains (phpggc) | web-deserialization | hard | Framework-specific gadget chains. |
| web-python-deser | Python pickle/PyYAML deserialization | web-deserialization | medium | Covered only as an example today. |
| web-node-deser | Node.js deserialization (node-serialize, funcster) | web-deserialization | hard | IIFE gadget → RCE. |
| web-ruby-deser | Ruby Marshal/YAML deserialization | web-deserialization | hard | Rails-class RCE. |
| web-viewstate | .NET ViewState deserialization (machineKey, __VIEWSTATE) | web-deserialization | expert | ASP.NET ViewState RCE; recurring enterprise bug. |

### G. Cross-cutting / bypass (9)
| proposed id | title | parent | diff | why it matters |
|-------------|-------|--------|------|----------------|
| web-xxe-advanced | XXE advanced: blind OOB, parameter entities, error-based, XInclude, XXE→SSRF | web-xxe | hard | Base lesson covers the simple in-band case only. |
| web-file-upload-advanced | File-upload advanced: полиглоты, .htaccess/.user.ini, SVG, nginx, phar | web-file-upload | expert | Filter-bypass depth. |
| web-cors-deep | CORS advanced: null origin, regex bypass, credentials, internal networks | web-same-origin-cors | medium | CORS misconfig is a top bounty class. |
| web-subdomain-takeover-deep | Subdomain takeover: providers, DNS/NS/MX takeover | web-subdomain-takeover | medium | Provider fingerprints + DNS-level takeover. |
| web-waf-bypass-advanced | WAF bypass advanced: encoding, Unicode, charset, chunked | web-waf-bypass | hard | Parser/charset confusion. |
| web-url-parsing | URL parsing confusion и SSRF/redirect bypass | web-waf-bypass | hard | The root cause of countless bypasses. |
| web-unicode-normalization | Unicode normalization, homoglyph, path override, null byte | web-waf-bypass | medium | Filter bypass via NFKC/case-folding; pairs with path traversal. |
| web-attack-chains | Построение цепочек атак (chain composition) | web-business-logic | expert | Turning medium bugs into critical impact. |
| web-mobile-api-bypass | Мобильные API: pinning-обход, hidden endpoints, IDOR | web-api-security | hard | Mobile clients expose undocumented API surface. |

## 1.3 Shallow coverage (exists but too thin)
- `web-oauth-oidc-saml` crams OAuth **+** OIDC **+** SAML into one lesson → split into 3 (see D).
- `web-request-smuggling` mentions HTTP/2 but is an intro → advanced + H2 + CSD needed (see C).
- `web-oauth`/`web-jwt` cover only the "top-3" bug of each family.
- `web-deserialization` names 4 languages but deep-dives only pickle → per-language chains needed (see F).
- `web-ssti` lacks per-engine payloads and sandbox escapes.
- `web-race-conditions` is conceptual — no single-packet technique.
- No lesson covers **DNS rebinding**, **JNDI/Log4Shell**, **gRPC**, **XS-Leaks**, **DOM clobbering**.

## 1.4 Top-10 highest-value missing web lessons
1. `web-request-smuggling-advanced` (expert)
2. `web-mfa-bypass` (hard)
3. `web-jwt-advanced` (hard)
4. `web-ssrf-protocol-smuggling` (expert)
5. `web-log4shell-jndi` (expert)
6. `web-dom-clobbering` (medium)
7. `web-graphql-deep` (hard)
8. `web-xs-leaks` (hard)
9. `web-ssti-engines` (expert)
10. `web-ssrf-cloud-deep` (hard)

---

# 2. PWN

## 2.1 Existing lessons (32)

| id | title | difficulty | parent |
|----|-------|-----------|--------|
| pwn-elf-basics | ELF и x86-64 | beginner | — (root) |
| pwn-methodology | Методология pwn | medium | — (root) |
| pwn-buffer-overflow | Переполнение буфера | easy | pwn-elf-basics |
| pwn-pwntools | pwntools | easy | pwn-elf-basics |
| pwn-calling-conventions | Соглашения о вызовах | easy | pwn-elf-basics |
| pwn-rop | ROP | medium | pwn-buffer-overflow |
| pwn-shellcode | Shellcode | medium | pwn-buffer-overflow |
| pwn-format-string | Format string | medium | pwn-buffer-overflow |
| pwn-fs-advanced | Format string advanced | hard | pwn-format-string |
| pwn-got-plt | GOT и PLT | medium | pwn-rop |
| pwn-ret2libc | ret2libc + one_gadget | hard | pwn-got-plt |
| pwn-mitigations | NX/ASLR/PIE/canary | hard | pwn-ret2libc |
| pwn-ret2dlresolve | ret2dlresolve | expert | pwn-mitigations |
| pwn-seccomp-srop | seccomp, SROP, ORW | expert | pwn-ret2dlresolve |
| pwn-gadget-hunting | ROPgadget/ropper/one_gadget | medium | pwn-rop |
| pwn-gdb-pwndbg | GDB + pwndbg | easy | pwn-pwntools |
| pwn-canary-bypass | Canary обход | hard | pwn-mitigations |
| pwn-pie-bypass | PIE/ASLR обход | hard | pwn-mitigations |
| pwn-ret2csu | ret2csu | hard | pwn-rop |
| pwn-stack-pivot | Stack pivot | hard | pwn-rop |
| pwn-brop | BROP | expert | pwn-rop |
| pwn-heap-basics | Heap glibc | hard | pwn-mitigations |
| pwn-heap-uaf | Use-After-Free | expert | pwn-heap-basics |
| pwn-heap-tcache | tcache poisoning | expert | pwn-heap-uaf |
| pwn-fastbin-dup | fastbin dup | expert | pwn-heap-basics |
| pwn-unsafe-unlink | Unsafe unlink | expert | pwn-heap-basics |
| pwn-house-of-force | House of Force/Spirit/Orange | expert | pwn-heap-basics |
| pwn-fsop | FSOP | expert | pwn-heap-tcache |
| pwn-glibc-mitigations | glibc 2.3x: safe-linking | expert | pwn-heap-tcache |
| pwn-arm64-basics | ARM64 pwn | medium | pwn-calling-conventions |
| pwn-windows-intro | Windows pwn | expert | pwn-rop |
| pwn-kernel-intro | Kernel pwn intro | expert | pwn-mitigations |

## 2.2 Missing topics (50)

### A. Stack / ROP / primitives (13)
| proposed id | title | parent | diff | why it matters |
|-------------|-------|--------|------|----------------|
| pwn-integer-overflow | Целочисленные переполнения и underflow | pwn-buffer-overflow | medium | Root cause of many CTF bugs. |
| pwn-off-by-one | Off-by-one и off-by-null | pwn-heap-basics | hard | Classic heap-corruption trigger. |
| pwn-ret2vdso | ret2vDSO и vsyscall | pwn-rop | hard | Gadget source without libc leak. |
| pwn-static-no-libc | Эксплуатация статических бинарей и без libc | pwn-ret2libc | expert | Common in CTF; no libc to leak. |
| pwn-musl | Эксплуатация под musl libc | pwn-static-no-libc | expert | Different allocator/ld behavior. |
| pwn-fini-init-array | .fini_array/.init_array и exit handlers | pwn-got-plt | hard | Control-flow target when GOT is protected. |
| pwn-environ-leak | Утечки через environ и argv | pwn-format-string | medium | Stack-pointer leak primitive. |
| pwn-stack-clash | Stack Clash | pwn-buffer-overflow | expert | Large-allocation guard-bypass. |
| pwn-cet-cfi | Обход CET/CFI и shadow stack | pwn-mitigations | expert | Forward-looking hardware mitigation. |
| pwn-cpp-exploitation | C++: vtable, type confusion, exceptions | pwn-heap-uaf | expert | Real-world binaries are C++. |
| pwn-fuzzing | Фаззинг: AFL++, libFuzzer, honggfuzz | pwn-methodology | hard | Bug-finding is half of pwn. |
| pwn-asan-ubsan | ASan/UBSan и их обход | pwn-methodology | medium | Debug builds in challenges. |
| pwn-libc-database | Определение версии libc (libc-database) | pwn-ret2libc | medium | Essential daily skill; only a section today. |

### B. Heap exploitation — advanced (14)
| proposed id | title | parent | diff | why it matters |
|-------------|-------|--------|------|----------------|
| pwn-largebin-attack | Large bin attack | pwn-heap-basics | expert | Modern arbitrary-write primitive. |
| pwn-unsortedbin-attack | Unsorted/small bin attack | pwn-heap-basics | expert | Classic glibc<2.29 primitive. |
| pwn-house-einherjar | House of Einherjar | pwn-heap-basics | expert | Off-by-null consolidation trick. |
| pwn-house-lore | House of Lore | pwn-heap-basics | expert | Small-bin attack. |
| pwn-house-botcake | House of Botcake | pwn-heap-tcache | expert | Double-free bypass under tcache. |
| pwn-house-modern | Современные House of: Kiwi, Emma, Apple, God | pwn-glibc-mitigations | expert | glibc 2.31–2.36 exploitation. |
| pwn-tcache-stashing | tcache stashing unlink attack | pwn-heap-tcache | expert | Core modern tcache technique. |
| pwn-mmap-exploitation | mmap/munmap и большие чанки | pwn-heap-basics | expert | Non-heap-region corruption. |
| pwn-io-stdout | House of Husk / _IO_2_1_stdout FSOP | pwn-fsop | expert | FSOP variant absent today. |
| pwn-io-str-overflow | _IO_str_overflow и vtable-цепочки | pwn-fsop | expert | glibc 2.24+ FSOP. |
| pwn-exit-handlers | Эксплуатация __run_exit_handlers/atexit | pwn-fsop | hard | Trigger path for FSOP. |
| pwn-heap-fengshui | Heap feng shui и grooming | pwn-heap-basics | medium | Making exploits reliable. |
| pwn-calloc | Эксплуатация calloc и обхода tcache | pwn-heap-tcache | hard | Bypasses tcache-only assumptions. |
| pwn-custom-allocator | Эксплуатация кастомных аллокаторов | pwn-heap-basics | expert | Real CTF "heap" tasks. |

### C. Kernel (8)
| proposed id | title | parent | diff | why it matters |
|-------------|-------|--------|------|----------------|
| pwn-kernel-rop | Kernel ROP и обход KPTI (trampoline) | pwn-kernel-intro | expert | Standard kernel exploit stage. |
| pwn-kernel-heap | Kernel heap: SLUB, kmalloc, UAF | pwn-kernel-intro | expert | The dominant kernel bug class. |
| pwn-kernel-pipe-buffer | Эксплуатация pipe_buffer | pwn-kernel-intro | expert | Classic CVE primitive (Dirty Pipe family). |
| pwn-kernel-smep-smap | Обход SMEP/SMAP/KASLR в ядре | pwn-kernel-intro | expert | Required for any kernel RCE. |
| pwn-kernel-userfaultfd | userfaultfd и FUSE для гонок | pwn-kernel-heap | expert | Race-window widening. |
| pwn-kernel-ebpf | Эксплуатация eBPF | pwn-kernel-intro | expert | Hot kernel attack surface. |
| pwn-kernel-io_uring | Эксплуатация io_uring | pwn-kernel-intro | expert | Modern kernel UAFs. |
| pwn-kernel-nftables | Netfilter/nftables UAF | pwn-kernel-intro | expert | Recurring real-world CVE class. |

### D. Architectures / OS (8)
| proposed id | title | parent | diff | why it matters |
|-------------|-------|--------|------|----------------|
| pwn-mips | MIPS pwn | pwn-arm64-basics | hard | Router/IoT CTF staple. |
| pwn-riscv | RISC-V pwn | pwn-arm64-basics | hard | Emerging ISA. |
| pwn-arm64-heap | ARM64 heap exploitation | pwn-arm64-basics | expert | ARM is not just stack. |
| pwn-windows-heap | Windows heap exploitation (LFH/Segment Heap) | pwn-windows-intro | expert | Windows pwn is one intro lesson today. |
| pwn-windows-kernel | Windows kernel pwn (pool, SMEP bypass) | pwn-windows-intro | expert | Driver/pool corruption. |
| pwn-macos | macOS pwn | pwn-windows-intro | expert | Untouched platform. |
| pwn-browser | Browser/JIT exploitation | pwn-heap-uaf | expert | Type confusion/JIT bugs; top CTF category. |
| pwn-qemu-user | Эксплуатация под qemu-user | pwn-methodology | medium | How foreign-arch challenges are run. |

### E. Methodology / misc (7)
| proposed id | title | parent | diff | why it matters |
|-------------|-------|--------|------|----------------|
| pwn-sandbox-escape | Sandbox escapes (seccomp user-notify, nsjail) | pwn-seccomp-srop | expert | Post-RCE containment bypass. |
| pwn-nday | N-day exploitation (patch diff → exploit) | pwn-methodology | expert | Real-world pwn skill. |
| pwn-rust-go-exploit | Эксплуатация Rust/Go бинарей | pwn-methodology | expert | Memory-safe langs still break. |
| pwn-symbolic-angr | Символьное исполнение в pwn (angr) | pwn-methodology | hard | Automating constraint solving. |
| pwn-shellcode-advanced | Полиморфный/self-modifying shellcode, egghunter, alphanumeric | pwn-shellcode | hard | Constrained-input shellcode. |
| pwn-heap-qemu-debug | Отладка heap в qemu/gdb-multiarch | pwn-methodology | medium | Cross-arch debugging. |
| pwn-ctf-recipe | Рецепты популярных CTF-задач (чек-лист по типам) | pwn-methodology | medium | Pattern library for competition speed. |

## 2.3 Shallow coverage (exists but too thin)
- `pwn-kernel-intro` covers only ret2usr/modprobe_path/msg_msg → the kernel domain is ~90% missing (see C).
- `pwn-house-of-force` covers 3 houses; the "House of" family is 10+ techniques.
- `pwn-heap-*` never covers **large bin**, **unsorted bin**, **tcache stashing**, **Einherjar**, **modern Houses**.
- `pwn-windows-intro` is a single intro; Windows heap/kernel/browser entirely absent.
- No **fuzzing**, **N-day**, **browser/JIT**, **macOS**, **MIPS/RISC-V**, **musl/static** coverage.

## 2.4 Top-10 highest-value missing pwn lessons
1. `pwn-largebin-attack` (expert)
2. `pwn-house-modern` (expert)
3. `pwn-kernel-rop` (expert)
4. `pwn-kernel-heap` (expert)
5. `pwn-tcache-stashing` (expert)
6. `pwn-house-einherjar` (expert)
7. `pwn-browser` (expert)
8. `pwn-windows-heap` (expert)
9. `pwn-musl` (expert)
10. `pwn-cpp-exploitation` (expert)

---

# 3. REVERSING

## 3.1 Existing lessons (32)

| id | title | difficulty | parent |
|----|-------|-----------|--------|
| reversing-intro | Введение в реверс | beginner | — (root) |
| reversing-asm | Чтение ассемблера x86-64 | easy | reversing-intro |
| reversing-analysis-methodology | Методология анализа | easy | reversing-intro |
| reversing-file-formats | Форматы ELF/PE/Mach-O | easy | reversing-asm |
| reversing-static-analysis | Статический анализ | easy | reversing-asm |
| reversing-decompiler | Работа с декомпилятором | medium | reversing-static-analysis |
| reversing-dynamic-debug | Динамический анализ | medium | reversing-decompiler |
| reversing-patching | Патчинг | medium | reversing-dynamic-debug |
| reversing-anti-debug | Анти-отладка | hard | reversing-patching |
| reversing-anti-vm | Анти-VM | hard | reversing-anti-debug |
| reversing-packing-upx | Упаковка/UPX | hard | reversing-anti-debug |
| reversing-obfuscation | Обфускация/CFG flattening | hard | reversing-packing-upx |
| reversing-vm-crackmes | VM-based crackmes | expert | reversing-obfuscation |
| reversing-deobfuscation | Деобфускация MBA/opaque | expert | reversing-obfuscation |
| reversing-symbolic-execution | Символьное исполнение (angr) | expert | reversing-vm-crackmes |
| reversing-taint-analysis | Taint-анализ / DBI | expert | reversing-symbolic-execution |
| reversing-advanced-debugging | Продвинутая отладка | hard | reversing-dynamic-debug |
| reversing-dynamic-linking | Динамическая линковка | medium | reversing-static-analysis |
| reversing-keygen | Keygen | medium | reversing-patching |
| reversing-crypto-binaries | Криптография в бинарниках | medium | reversing-decompiler |
| reversing-protocols | Реверс протоколов/форматов | medium | reversing-dynamic-debug |
| reversing-managed-dotnet-java | .NET и Java | medium | reversing-decompiler |
| reversing-python-bytecode | Python-байткод | medium | reversing-decompiler |
| reversing-rust-go | Rust и Go | hard | reversing-static-analysis |
| reversing-android-apk | Android APK | medium | reversing-managed-dotnet-java |
| reversing-architectures | ARM/MIPS/RISC-V | medium | reversing-asm |
| reversing-firmware | Прошивки | hard | reversing-static-analysis |
| reversing-game-anticheat | Игры и анти-чит | hard | reversing-packing-upx |
| reversing-ida-deep | IDA Pro deep | hard | reversing-decompiler |
| reversing-ghidra-deep | Ghidra deep | hard | reversing-decompiler |
| reversing-radare2 | radare2/rizin | medium | reversing-static-analysis |
| reversing-binary-diffing | Бинарный диффинг | hard | reversing-static-analysis |

## 3.2 Missing topics (53)

### A. Platforms / languages (9)
| proposed id | title | parent | diff | why it matters |
|-------------|-------|--------|------|----------------|
| reversing-ios | Реверс iOS (Mach-O, Frida, jailbreak) | reversing-android-apk | expert | Entire mobile platform missing. |
| reversing-android-native | Android native (JNI, .so, obfuscation) | reversing-android-apk | hard | The APK lesson is Java-level only. |
| reversing-wasm | Реверс WebAssembly | reversing-architectures | hard | Common modern CTF category. |
| reversing-dotnet-advanced | .NET advanced: ConfuserEx, de4dot, IL-патчинг | reversing-managed-dotnet-java | hard | Real obfuscated .NET. |
| reversing-java-advanced | Java advanced: ProGuard, bytecode obfuscation | reversing-managed-dotnet-java | hard | Enterprise/CTF Java. |
| reversing-swift-objc | Реверс Swift и Objective-C | reversing-architectures | hard | Apple targets. |
| reversing-go-advanced | Go advanced: runtime, pclntab, горутины | reversing-rust-go | hard | Beyond "определение языка". |
| reversing-rust-advanced | Rust advanced: monomorphization, panic | reversing-rust-go | hard | Rust is increasingly common. |
| reversing-aot-native | .NET Native/AOT | reversing-managed-dotnet-java | expert | Native-compiled managed code. |

### B. Malware / kernel / low-level (10)
| proposed id | title | parent | diff | why it matters |
|-------------|-------|--------|------|----------------|
| reversing-malware-static | Статический анализ malware | reversing-static-analysis | hard | Core DFIR/threat-intel skill. |
| reversing-malware-dynamic | Динамический анализ malware и sandbox | reversing-malware-static | hard | Behavior analysis + evasion. |
| reversing-yara-sigma | YARA/Sigma: правила обнаружения | reversing-malware-static | medium | Detection engineering. |
| reversing-kernel-drivers | Реверс драйверов ядра (Linux/Windows) | reversing-anti-vm | expert | Rootkit/anti-cheat core. |
| reversing-hypervisor | Реверс гипервизоров и VMX | reversing-kernel-drivers | expert | Ring -1 analysis. |
| reversing-uefi-bios | Реверс UEFI/BIOS | reversing-firmware | expert | Firmware below the OS. |
| reversing-embedded-rtos | Реверс embedded/RTOS (FreeRTOS, bare-metal) | reversing-firmware | hard | IoT/device RE. |
| reversing-hardware-debug | Аппаратный реверс: UART/JTAG/SPI | reversing-firmware | hard | Physical access workflows. |
| reversing-ebpf | Реверс eBPF-программ | reversing-kernel-drivers | expert | Kernel-level program analysis. |
| reversing-sdr | Реверс SDR/радио-прошивок | reversing-firmware | expert | RF/IoT security. |

### C. Techniques / automation (19)
| proposed id | title | parent | diff | why it matters |
|-------------|-------|--------|------|----------------|
| reversing-unicorn-emulation | Эмуляция: Unicorn/Qiling для деобфускации | reversing-deobfuscation | hard | Emulation is the modern deobf toolkit. |
| reversing-concolic | Concolic execution (Triton, Manticore) | reversing-symbolic-execution | expert | Hybrid static/dynamic solving. |
| reversing-angr-advanced | angr advanced: CFG, veritesting, символьные указатели | reversing-symbolic-execution | expert | The lesson covers the basic recipe only. |
| reversing-z3-advanced | Z3 advanced: моделирование и упрощение | reversing-symbolic-execution | hard | Constraint craft. |
| reversing-binary-lifting | Binary lifting (P-Code, angr IR) | reversing-symbolic-execution | expert | Custom analysis on IR. |
| reversing-self-modifying | Self-modifying code и unpacking через эмуляцию | reversing-deobfuscation | expert | Defeats static analysis. |
| reversing-anti-tamper | Anti-tamper, integrity checks и обход | reversing-anti-debug | hard | Pairs with anti-debug. |
| reversing-mba-advanced | MBA advanced и алгебраическая деобфускация | reversing-deobfuscation | expert | Deep obfuscation removal. |
| reversing-movfuscator | Instruction-level обфускация (movfuscator) | reversing-obfuscation | expert | Extreme obfuscation. |
| reversing-commercial-protectors | Коммерческие протекторы: VMProtect, Themida | reversing-vm-crackmes | expert | Real-world protected binaries. |
| reversing-devirtualization | Девиртуализация коммерческих VM | reversing-vm-crackmes | expert | The hard end of VM RE. |
| reversing-packers-custom | Кастомные/самописные пакеры и распаковка | reversing-packing-upx | expert | Beyond UPX. |
| reversing-frida-advanced | Frida advanced: Stalker, hooking, RPC | reversing-taint-analysis | hard | Universal dynamic instrumentation. |
| reversing-pin-dbi | Intel PIN и DynamoRIO advanced | reversing-taint-analysis | hard | Classic DBI platforms. |
| reversing-qbdi | QBDI и инструментация | reversing-taint-analysis | expert | Modern DBI. |
| reversing-kernel-taint | Taint-анализ в ядре и hypervisor-based | reversing-taint-analysis | expert | Whole-system taint. |
| reversing-time-travel | Time-travel debugging (rr, WinDbg TTD) | reversing-advanced-debugging | hard | Replay-based analysis. |
| reversing-hardware-trace | Аппаратная трассировка (Intel PT) | reversing-advanced-debugging | expert | Coverage-free tracing. |
| reversing-shellcode-analysis | Анализ и реверс shellcode | reversing-static-analysis | hard | Malware/exploit triage. |

### D. Formats / crypto / misc (15)
| proposed id | title | parent | diff | why it matters |
|-------------|-------|--------|------|----------------|
| reversing-protobuf-grpc | Реверс protobuf/gRPC/Thrift | reversing-protocols | medium | Very common in CTF/real apps. |
| reversing-crypto-advanced | Продвинутый реверс криптографии: white-box, custom ciphers | reversing-crypto-binaries | expert | Beyond identification. |
| reversing-keygen-advanced | Keygen advanced: асимметричные проверки и патч | reversing-keygen | hard | RSA/ECC-based licensing. |
| reversing-drm | Реверс DRM и Denuvo | reversing-game-anticheat | expert | High-value protected targets. |
| reversing-game-anticheat-advanced | Анти-чит advanced: kernel anti-cheat, hypervisor | reversing-game-anticheat | expert | Ring-0 anti-cheat RE. |
| reversing-firmware-emulation | Эмуляция прошивок (FirmAE, firmadyne) | reversing-firmware | hard | Automated firmware analysis. |
| reversing-automotive-can | Реверс автомобильных сетей (CAN/UDS) | reversing-firmware | expert | Automotive security. |
| reversing-container-images | Реверс контейнеров и cloud-бинарников | reversing-analysis-methodology | medium | Cloud-native RE. |
| reversing-decompiler-plugin | Разработка плагинов декомпилятора (Ghidra/IDA) | reversing-ghidra-deep | hard | Scaling analysis. |
| reversing-elf-instrumentation | Инструментация ELF (e9patch, frida-gadget) | reversing-patching | hard | Binary rewriting. |
| reversing-lief | Программный патчинг ELF/PE (LIEF) | reversing-patching | medium | Scriptable binary editing. |
| reversing-1day | 1-day анализ / patch-gap эксплуатация | reversing-binary-diffing | expert | Core real-world RE skill. |
| reversing-ai-assisted | AI-ассистированный реверс (LLM-ренейминг, авто-декомпиляция) | reversing-analysis-methodology | medium | Emerging workflow. |
| reversing-mobile-malware | Реверс мобильных малварей (Android/iOS) | reversing-android-native | expert | Banking-trojan analysis. |
| reversing-ransomware | Реверс ransomware и восстановление ключей | reversing-crypto-binaries | expert | High-impact DFIR. |

## 3.3 Shallow coverage (exists but too thin)
- `reversing-managed-dotnet-java` covers .NET **and** Java in one lesson → split + advanced deobfuscation.
- `reversing-rust-go` only "определение языка"; runtime-level RE absent.
- `reversing-vm-crackmes` *mentions* commercial protectors but does not teach devirtualization.
- `reversing-firmware` covers extraction/emulation lightly; UEFI, RTOS, automotive, hardware-debug absent.
- `reversing-crypto-binaries` identifies algorithms but not custom/white-box ciphers.
- No **malware analysis**, **iOS**, **WASM**, **kernel drivers**, **hypervisor**, **concolic**, **Unicorn emulation**.

## 3.4 Top-10 highest-value missing reversing lessons
1. `reversing-ios` (expert)
2. `reversing-malware-dynamic` (hard)
3. `reversing-unicorn-emulation` (hard)
4. `reversing-wasm` (hard)
5. `reversing-dotnet-advanced` (hard)
6. `reversing-commercial-protectors` (expert)
7. `reversing-android-native` (hard)
8. `reversing-kernel-drivers` (expert)
9. `reversing-concolic` (expert)
10. `reversing-protobuf-grpc` (medium)

---

# 4. Consolidated verdict

| Category | Existing | Missing | Coverage | Honest statement |
|----------|---------:|--------:|---------:|------------------|
| web | 34 | 73 | 32 % | Needs **+65 lessons** to be a credible web-pentest curriculum. |
| pwn | 32 | 50 | 39 % | Needs **+50 lessons**; kernel/browser/Windows are near-empty. |
| reversing | 32 | 53 | 38 % | Needs **+45 lessons**; malware/iOS/WASM/protectors missing. |

**Bottom line:** the existing 98 lessons are a good *introductory spine* but cover roughly a third of
each domain. The biggest structural holes are: **kernel & modern-heap pwn**, **advanced HTTP desync &
modern client-side web**, and **malware / mobile / commercial-protector reversing**. Each category
should be expanded by **+45 to +65 lessons** (≈ **+160 total**) before it can be called complete.

*Coverage % = (distinct canonical topics covered at usable depth) / (canonical topics). Counts are
the distinct canonical topics; some (e.g. all "House of *", all kernel) can be merged into fewer
lessons, so realistic authored-lesson targets are ~10–15% lower than the missing-topic counts.*

---

# 5. Concurrency note (housekeeping for the coordinator)

Two gap-audit passes ran concurrently and both wrote this file. This document is the **merged**
result (full existing-lesson inventory + union of missing-topic proposals). The earlier pass's
distinct proposals were folded in (`web-php-tricks`, `web-race-single-packet`,
`web-prototype-pollution-rce`, `web-csp-advanced`, `web-path-normalization`, `web-viewstate`,
`reversing-1day`, `reversing-lief`, `reversing-time-travel`, `reversing-hardware-trace`,
`reversing-binary-lifting`, `reversing-ebpf`, `reversing-sdr`, `reversing-packers-custom`,
`reversing-shellcode-analysis`). **Recommendation: de-duplicate the gap-audit task** — only one
writer should own `GAPS-offensive.md`.

*Generated by the curriculum-gap-audit (read-only). No content lesson files were modified.*
