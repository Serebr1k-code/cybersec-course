# Split-parent ORDER handoff (rank-web-a → rank-web-b)

`content/web/` was split **alphabetically by filename**:
* **rank-web-a** → first 90 files (`db-elasticsearch.md` … `web-playbook-file-to-rce.md`).
* **rank-web-b** → remaining 91 files (`web-playbook-injection-triage.md` … `web-zip-slip.md`).

`order` was normalized to **0-based, unique, contiguous** per parent, using the
sort key `(FINAL_star, old_order)` (prereqs/intro first, difficulty non-decreasing).
See `DIFFICULTY_RUBRIC.md` for the full rubric.

For parents whose children span the split, rank-web-a computed the **full union
ordering** and already wrote the new `order` for its own children. Apply the
values below to the listed **rank-web-b** children so each parent stays contiguous
(union = `0,1,2,…,n-1`). Only the `order:` field of these files changes.

| parent | file (rank-web-b) | old order | → new order |
|--------|-------------------|-----------|-------------|
| web-api-security | web-webhooks.md | 101 | 0 |
| web-architecture-protocols | web-websocket.md | 2 | 1 |
| web-auth-bypass | web-webauthn.md | 2 | 1 |
| web-auth-protocols | web-refresh-token.md | 2 | 1 |
| web-browser-core | web-postmessage-tabnabbing.md | 4 | 3 |
| web-csp-bypass | web-trusted-types-bypass.md | 44 | 1 |
| web-deser-expert | web-viewstate.md | 2 | 1 |
| web-deser-languages | web-python-deser.md | 1 | 0 |
| web-deser-languages | web-ruby-deser.md | 3 | 2 |
| web-file-upload | web-zip-slip.md | 91 | 0 |
| web-file-upload | web-ssti.md | 11 | 1 |
| web-http-basics | web-tls-certs.md | 18 | 2 |
| web-http-basics | web-same-origin-cors.md | 17 | 3 |
| web-injection-advanced | web-second-order-injection.md | 2 | 0 |
| web-injection-basics | web-xss.md | 1 | 0 |
| web-lfi-path-traversal | web-ssrf.md | 14 | 1 |
| web-logic-core | web-range-redos-dos.md | 2 | 1 |
| web-logic-races | web-race-conditions.md | 1 | 0 |
| web-nosql-ldap-xpath | web-xpath-injection.md | 76 | 2 |
| web-oauth-oidc-saml | web-sso-mixup.md | 64 | 1 |
| web-oauth-oidc-saml | web-saml-deep.md | 65 | 2 |
| web-playbooks-exploit | web-playbook-ssrf-to-internal.md | 3 | 2 |
| web-recon-attack-entry | web-sqli.md | 2 | 1 |
| web-recon-surface | web-tooling.md | 1 | 0 |
| web-recon-surface | web-subdomain-takeover.md | 4 | 3 |
| web-request-smuggling | web-request-smuggling-advanced.md | 51 | 1 |
| web-sqli | web-sqli-dbms.md | 3 | 1 |
| web-sqli | web-tools-sqli.md | 4 | 2 |
| web-ssrf-advanced | web-serverless.md | 3 | 1 |
| web-ssrf-advanced | web-ssrf-protocol-smuggling.md | 1 | 2 |
| web-ssti-advanced | web-ssti-engines.md | 1 | 2 |
| web-ssti-core | web-ssi-xslt-injection.md | 1 | 0 |
| web-waf-evasion-basics | web-unicode-normalization.md | 3 | 1 |
| web-waf-parsing-attacks | web-url-parsing.md | 1 | 0 |
| web-waf-parsing-attacks | web-waf-bypass-advanced.md | 3 | 2 |

**Already-consistent split parents (no change needed on either side):**
`web-request-smuggling` (mine) combined with the sibling's
`web-request-smuggling-advanced`; `web-injection-advanced`'s `web-orm-injection`
stays at 1; etc. Any parent not listed above already satisfied the union key.

After applying, re-run `CGO_ENABLED=0 go run ./tools/quizvalidate -content ./content`
(0 broken) and confirm no parent has duplicate/non-contiguous `order` values.
