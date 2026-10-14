#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rename the forensics cloud-* gB lessons to forensics-* (owning-prefix rule / de-dup)."""
import os, re

C = "content/forensics"
L = "content/labs"

RENAME = {
 "cloud-serverless": "forensics-serverless",
 "cloud-container-runtime": "forensics-container-runtime",
 "cloud-vm-hypervisor": "forensics-vm-hypervisor",
 "cloud-storage": "forensics-storage",
 "cloud-iac-state": "forensics-iac-state",
 "cloud-secrets-manager": "forensics-secrets-manager",
 "cloud-cicd": "forensics-cicd",
}

# 1) rename md + fix id line / self-prereq
for old, new in RENAME.items():
    src = os.path.join(C, old + ".md")
    dst = os.path.join(C, new + ".md")
    if not os.path.exists(src):
        print("skip md (missing):", src); continue
    with open(src, encoding="utf-8") as f:
        txt = f.read()
    txt = re.sub(r"^id: %s$" % re.escape(old), "id: " + new, txt, count=1, flags=re.M)
    # fix a self-referencing prereq
    txt = txt.replace("prerequisites: [forensics-cloud-identity, cloud-secrets-manager]",
                      "prerequisites: [forensics-cloud-identity]")
    os.rename(src, dst)
    with open(dst, "w", encoding="utf-8") as f:
        f.write(txt)
    print("md:", old, "->", new)

# 2) rename lab bundles + fix id field
for old, new in RENAME.items():
    src = os.path.join(L, old + ".json")
    dst = os.path.join(L, new + ".json")
    if not os.path.exists(src):
        print("skip lab (missing):", src); continue
    with open(src, encoding="utf-8") as f:
        txt = f.read()
    txt = txt.replace('"id": "%s"' % old, '"id": "%s"' % new, 1)
    os.rename(src, dst)
    with open(dst, "w", encoding="utf-8") as f:
        f.write(txt)
    print("lab:", old, "->", new)

# 3) fix hub body prose references (order lists)
for hub in ("forensics-cloud-runtime", "forensics-cloud-devsecops"):
    p = os.path.join(C, hub + ".md")
    with open(p, encoding="utf-8") as f:
        txt = f.read()
    for old, new in RENAME.items():
        txt = re.sub(r"`%s`" % re.escape(old), "`%s`" % new, txt)
    with open(p, "w", encoding="utf-8") as f:
        f.write(txt)
    print("hub updated:", hub)
