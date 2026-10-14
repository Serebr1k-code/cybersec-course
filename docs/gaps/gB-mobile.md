# content/mobile — GAP ANALYSIS (independent pass B)

Inventory: 116 md files (95 content lessons + 21 module/hub pages). Verdict: **STRONG**
(excellent Android/iOS static+dynamic analysis, Frida/objection, pinning bypass, forensics,
OAuth, deeplinks, WebView, IPC, keystore, malware, cross-platform reversing).
Below: MAXIMUM list of MISSING topics (base/standard + niche/advanced/exotic).
One bullet = one proposed lesson. `<proposed-id> — <title>`.

## Android: компоненты и IPC (углублённо)
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

## Android: платформа, ядро и аппаратное доверие
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

## Android: сборка, форматы, реверс
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

## Android: хукинг и защита
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

## Android: сеть и API
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

## Android: хранилища, ключи, приватность
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

## Android: enterprise, MDM, окружение
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

## Android: платформы и форм-факторы
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

## iOS: платформа, подписи, доверие
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

## iOS: IPC, рантайм, реверс
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

## iOS: данные, хранилища, приватность
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

## iOS: web, интеграция, сервисы
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

## iOS: enterprise, развёртывание, инструменты
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

## Кросс-платформенные фреймворки и языки
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

## SDK, платежи, монетизация, фрод
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

## Форензика и анализ (углублённо)
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

## Малварь, шпионаж, целевые атаки
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

## Радио, телеком, IoT-компаньоны
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

## Тестирование, CI/CD, автоматизация
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
