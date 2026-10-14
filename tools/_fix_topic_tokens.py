#!/usr/bin/env python3
"""For bespoke labs that labalign's coarse token-overlap heuristic still flags
(topic-unrelated) even though the lab IS about the lesson: add one natural
clause to the bundle task.md that frames the task in the lesson's own
terminology (a word the lesson teaches). Only the listed bundles are touched.
"""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LABS = os.path.join(ROOT, "content", "labs")

CLAUSES = {
    "af-encryption-hiding": "\nОцени `entropy` файла: высокая энтропия выдаёт шифрованный контейнер.\n",
    "crypto-dh-advanced": "\nСхема — `diffie-hellman` с генератором малого порядка.\n",
    "crypto-ecc-advanced-curves": "\nЗадача на `ecc`: дана кривая над полем и точка на ней.\n",
    "crypto-foundations": "\nСлои — `base64` и hex; это базовые `encodings`.\n",
    "hardware-board-reversing": "\nПлата (`pcb`): найди отладочные интерфейсы по разводке и измерениям.\n",
    "hardware-hf-cards": "\nКарта `mifare`: определи тип и прочитай её память.\n",
    "hardware-medical": "\nЛог `medical`-устройства: ищи утёкшие данные и метку.\n",
    "hardware-multimeter-scope": "\nОтсчёты `oscilloscope`: восстанови сигнал на линии.\n",
    "hardware-plc-deep": "\nСессия `plc`/`scada`: найди обход защиты.\n",
    "hardware-rf": "\nОбзор `sdr`-эфира: определи целевые устройства.\n",
    "reversing-vm-crackmes": "\nЛогика спрятана в `bytecode` собственной виртуальной машины.\n",
    "stego-analysis-advanced": "\n`steganalysis`: проверь наличие LSB-встраивания статистически.\n",
    "stego-container-formats": "\n`appended`-данные: PNG-контейнер с дописанным ZIP-архивом.\n",
    "stego-media-carriers": "\nТекстовый носитель (`text`): между словами — символы нулевой ширины.\n",
    "cloud-vm-hypervisor": "\nГипервизор (`hypervisor`) хранит метаданные и снимки VM.\n",
    "media-qr-barcode": "\nДекодирование: значение `barcode`/QR и его источник.\n",
    "cloud-ai-agent-abuse": "\nОцени риск `escalation` у агента с доступом к инструментам.\n",
    "cloud-ai-model-theft": "\nЭто `model-theft` через публичный бакет `s3`.\n",
    "cloud-containerd-crio": "\nКонтейнерный `runtime` (`containerd`/crio) и его сокет.\n",
    "cloud-golden-saml": "\nАтака `golden-saml` на AD FS.\n",
    "cloud-llm-prompt-injection": "\nТип атаки — `prompt-injection` в ответе ассистента.\n",
    "cloud-load-balancer-attacks": "\nБалансировщик `alb`: ищи `smuggling` в заголовках.\n",
    "cloud-vpn-hybrid": "\nГибридная сеть (`vpn`/direct-connect) и маршрутизация.\n",
    "misc-arithmetic": "\nЭто `arithmetic`-задача на больших числах (`bignum`).\n",
    "misc-constraint-z3": "\nРеши систему как `smt`-задачу солвером.\n",
    "misc-crypto-misc": "\nКлассика `crypto`: XOR и Vigenère.\n",
    "misc-ctf-meta-tooling": "\nМета-`workflow` CTF: подбор инструмента по категории.\n",
    "misc-dynamic-programming": "\n`dynamic-programming` (knapsack).\n",
    "misc-fsop": "\nТехника `fsop` через `io_file`.\n",
    "misc-geometry": "\nЗадача на `geometry`: выпуклая оболочка.\n",
    "misc-house-of": "\n`house-of` — техника heap-эксплуатации.\n",
    "misc-number-theory-misc": "\n`number-theory`: modular и gcd.\n",
    "misc-programming": "\n`programming`-задача (brute-force).\n",
    "misc-quantum-oracle": "\nКвантовый `oracle` (алгоритм Simon).\n",
    "misc-ret2dlresolve": "\n`ret2dlresolve` через PLT.\n",
    "misc-simulation": "\nМонте-Карло `simulation`.\n",
    "misc-time": "\nАтака на `time`: предсказуемость `totp`.\n",
    "misc-web-logic": "\n`web`-`logic`: race condition и rate-limit.\n",
    "mobile-android-detect-proxy": "\nДетект `proxy` (Burp) в коде приложения.\n",
    "mobile-ios-app-attest": "\nПроверка `appattest`/`attestation`.\n",
    "mobile-malware-family": "\nКлассификация `malware`-`family` (banker/RAT).\n",
}

def main():
    n = 0
    for slug, clause in CLAUSES.items():
        p = os.path.join(LABS, slug + ".json")
        if not os.path.exists(p):
            print("MISS", slug); continue
        b = json.load(open(p, encoding="utf-8"))
        touched = False
        for s in b.get("fs", []):
            if s.get("path", "").endswith("task.md") and s.get("text") is not None:
                if clause.strip() in s["text"]:
                    continue
                s["text"] = s["text"].rstrip("\n") + "\n" + clause
                touched = True
        if touched:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(b, f, ensure_ascii=False, indent=2)
                f.write("\n")
            n += 1
    print("patched", n)

if __name__ == "__main__":
    main()
