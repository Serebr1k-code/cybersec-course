# Batch 6: mobile labs — platforms, frida, pinning, wearables, iOS.
WD = '/home/student/task'


def _dir(p):
    return {'path': p, 'type': 'dir'}


def _f(p, t):
    return {'path': p, 'text': t}


def _lab(id, title, files, hints, flag, fs, tools=None, toolset=None):
    spec = {
        'id': id, 'category': 'mobile', 'title': title,
        'toolset': toolset or ['core', 'grep'],
        'workdir': WD, 'files': files,
        'check': "grep -q 'nto{' found.txt",
        'hints': hints,
        'expect': {'file': f'{WD}/found.txt', 'contains': flag},
        'fs': fs,
    }
    if tools:
        spec['tools'] = tools
    return spec


def _task(text, rest):
    return [_dir(WD), _f(f'{WD}/task.md', text)] + rest


SPECS = [
    _lab('mobile-android-auto', 'Практика: поверхность Android Auto',
         ['task.md', 'auto_config.xml', 'notes.txt'],
         ['`auto_config.xml` — конфигурация Android Auto интеграции.',
          'Ищи разрешённые категории приложений и переиспользуемые компоненты.',
          'Секрет есть в конфиге — найди `nto{` и запиши в `found.txt`.'],
         'nto{4ndr01d_4ut0_3xp0s3d}',
         _task('# Задача: Android Auto\n\nРазбери конфигурацию Android Auto и найди флаг.\n', [
             _f(f'{WD}/auto_config.xml',
                '<automotiveApp>\n  <uses name="template"/>\n'
                '  <category android:name="androidx.car.app.category.NAVIGATION"/>\n'
                '  <meta-data android:name="distractionOptimized" android:value="nto{4ndr01d_4ut0_3xp0s3d}"/>\n'
                '</automotiveApp>\n'),
             _f(f'{WD}/notes.txt', 'Категория NAVIGATION даёт больше прав, чем MEDIA.\n')])),
    _lab('mobile-android-emulator-lab', 'Практика: конфигурация AVD',
         ['task.md', 'config.ini'],
         ['`config.ini` — конфигурация Android Virtual Device.',
          'Смотри образы (`image.sysdir`) и флаги отладки.',
          'В конфиге есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{4vd_d3bugg4bl3_1m4g3}',
         _task('# Задача: AVD\n\nРазбери конфигурацию эмулятора и найди флаг.\n', [
             _f(f'{WD}/config.ini',
                'AvdId=VantaLab\nimage.sysdir.1=system-images/android-30/google_apis/x86_64/\n'
                'hw.gpu.enabled=yes\nhw.keyboard=yes\ndisk.dataPartition.size=6G\n'
                'debug.token=nto{4vd_d3bugg4bl3_1m4g3}\n')])),
    _lab('mobile-android-instrumentation', 'Практика: Frida-инструментация',
         ['task.md', 'agent.js', 'output.log'],
         ['`agent.js` — Frida-агент, `output.log` — его вывод.',
          'Агент подменяет проверку и логирует значения.',
          'В выводе есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{1nstum3nt4t10n_rpc_l34k}',
         _task('# Задача: инструментация\n\nРазбери Frida-агент и его вывод. Найди флаг и запиши в `found.txt`.\n', [
             _f(f'{WD}/agent.js',
                "rpc.exports = {\n  dump: function () {\n    var V = Java.use('com.vanta.app.Vault');\n"
                "    return V.getSecret();\n  }\n};\n"),
             _f(f'{WD}/output.log',
                '[*] agent attached\n[frida] rpc.dump() -> nto{1nstum3nt4t10n_rpc_l34k}\n')])),
    _lab('mobile-android-rooting', 'Практика: Magisk и root',
         ['task.md', 'magisk_state.txt'],
         ['`magisk_state.txt` — состояние root-окружения (Magisk).',
          'Смотри модули, DenyList и Zygisk.',
          'В выводе есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{m4g1sk_zyg1sk_m0dul3}',
         _task('# Задача: Magisk\n\nРазбери состояние root-окружения и найди флаг.\n', [
             _f(f'{WD}/magisk_state.txt',
                'Magisk version: 27.0\nZygisk: enabled\nDenyList: com.vanta.app\n'
                'Modules:\n  vanta-unlock (v1.2) - "nto{m4g1sk_zyg1sk_m0dul3}"\n')])),
    _lab('mobile-app-cloning', 'Практика: клонирование приложений',
         ['task.md', 'clone.log'],
         ['`clone.log` — лог попытки запустить клон приложения.',
          'Клон не может разделить data-dir — нужен отдельный пакет.',
          'В логе есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{cl0n3_4pp_p4r4ll3l_sp4c3}',
         _task('# Задача: клонирование\n\nРазбери лог клонирования приложения и найди флаг.\n', [
             _f(f'{WD}/clone.log',
                '[*] cloning com.vanta.app -> com.vanta.app.clone\n'
                '[*] patching package name in AndroidManifest\n'
                '[!] signature check failed on clone\n'
                '[+] clone token: nto{cl0n3_4pp_p4r4ll3l_sp4c3}\n')])),
    _lab('mobile-app2app', 'Практика: app-to-app атаки',
         ['task.md', 'app2app.txt'],
         ['`app2app.txt` — лог взаимодействия двух приложений через Intent/Custom Tabs.',
          'Ищи редирект, который можно перехватить другой схемой.',
          'В логе есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{4pp2app_r3d1r3ct_st34l}',
         _task('# Задача: app-to-app\n\nРазбери лог app-to-app взаимодействия и найди флаг.\n', [
             _f(f'{WD}/app2app.txt',
                'app A -> CustomTabsIntent(vanta://oauth)\n'
                'attacker registered vanta:// first -> intercept\n'
                'leaked code: nto{4pp2app_r3d1r3ct_st34l}\n')])),
    _lab('mobile-arm-x86-translation', 'Практика: ARM↔x86 трансляция',
         ['task.md', 'translation.log'],
         ['`translation.log` — лог трансляции нативного кода на эмуляторе.',
          'Ищи участки, где нативный код выполняется через эмуляцию (libhoudini/QEMU).',
          'В логе есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{4rm_tr4nsl4t10n_bug}',
         _task('# Задача: трансляция\n\nРазбери лог ARM↔x86 трансляции и найди флаг.\n', [
             _f(f'{WD}/translation.log',
                '[*] libhoudini loaded\n[*] translating 0x4000-0x4fff (ARMv7 -> x86)\n'
                '[!] JIT cache mismatch at 0x4120\n[+] debug: nto{4rm_tr4nsl4t10n_bug}\n')])),
    _lab('mobile-banking-trojan', 'Практика: анализ банковского трояна',
         ['task.md', 'sample_strings.txt'],
         ['`sample_strings.txt` — строки из образца Android-трояна.',
          'Ищи C2-домены, права accessibility, overlay-атаки.',
          'Среди строк есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{b4nk1ng_tr0j4n_c2}',
         _task('# Задача: троян\n\nРазбери строки образца банковского трояна и найди флаг.\n', [
             _f(f'{WD}/sample_strings.txt',
                'BIND_ACCESSIBILITY_SERVICE\nSYSTEM_ALERT_WINDOW\n'
                'https://c2.evil.example/gate.php\n'
                'c2_token=nto{b4nk1ng_tr0j4n_c2}\n'
                'target_packages=com.bank.a,com.bank.b\n')])),
    _lab('mobile-crossplatform', 'Практика: гибридные фреймворки',
         ['task.md', 'cordova_config.xml', 'www'],
         ['`cordova_config.xml` и `www/` — артефакты Cordova-приложения.',
          'Ищи allow-navigation/allow-intent и JS-мосты.',
          'Секрет есть в www — найди `nto{` и запиши в `found.txt`.'],
         'nto{c0rd0v4_wh1t3l1st_byp4ss}',
         _task('# Задача: Cordova\n\nРазбери гибридное приложение и найди флаг.\n', [
             _f(f'{WD}/cordova_config.xml',
                '<widget id="com.vanta.app">\n'
                '  <allow-navigation href="*"/>\n'
                '  <allow-intent href="http://*/*"/>\n'
                '</widget>\n'),
             _dir(f'{WD}/www'),
             _f(f'{WD}/www/config.js', "window.__SECRET__ = 'nto{c0rd0v4_wh1t3l1st_byp4ss}';\n")])),
    _lab('mobile-dart-reversing', 'Практика: реверс Flutter/Dart',
         ['task.md', 'libapp.so.strings.txt'],
         ['`libapp.so.strings.txt` — строки из нативной библиотеки Flutter.',
          'Dart-строки лежат в снапшоте; `blutter` их восстанавливает.',
          'Среди строк есть флаг — найди `nto{` и запиши в `found.txt`.'],
         'nto{flutt3r_d4rt_sn4psh0t}',
         _task('# Задача: Flutter\n\nРазбери строки Flutter-приложения и найди флаг.\n', [
             _f(f'{WD}/libapp.so.strings.txt',
                'package:flutter/src/widgets\n'
                'VantaAuth\n'
                'apiToken = nto{flutt3r_d4rt_sn4psh0t}\n'
                'dart:async\n')])),
    _lab('mobile-dynamic-frida', 'Практика: динамический анализ с Frida',
         ['task.md', 'frida_session.log'],
         ['`frida_session.log` — динамическая сессия Frida.',
          'Ищи значения, возвращённые перехваченными методами.',
          'В сессии есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{dyn4m1c_fr1d4_runt1m3}',
         _task('# Задача: Frida dynamic\n\nРазбери динамическую сессию Frida и найди флаг.\n', [
             _f(f'{WD}/frida_session.log',
                '[*] attached to com.vanta.app\n'
                'Java.perform: hooking Vault.check\n'
                'Vault.check("user") -> false\n'
                'Vault.check("nto{dyn4m1c_fr1d4_runt1m3}") -> true\n')])),
    _lab('mobile-flutter', 'Практика: реверс React Native / Flutter',
         ['task.md', 'index.android.bundle.strings.txt'],
         ['`index.android.bundle.strings.txt` — строки JS-бандла (Hermes/JS).',
          'Ищи константы и ключи в бандле.',
          'Среди строк есть флаг — найди `nto{` и запиши в `found.txt`.'],
         'nto{r34ct_n4t1v3_bundl3_l34k}',
         _task('# Задача: кросс-платформа\n\nРазбери строки бандла и найди флаг.\n', [
             _f(f'{WD}/index.android.bundle.strings.txt',
                'function getApiKey(){return "nto{r34ct_n4t1v3_bundl3_l34k}"}\n'
                'APP_VERSION=1.4.2\n')])),
    _lab('mobile-ipc-fuzzing', 'Практика: фаззинг Android IPC',
         ['task.md', 'drozer.log'],
         ['`drozer.log` — вывод drozer по компонентам приложения.',
          'Ищи `isExported` и `permission: null`.',
          'В выводе есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{1pc_fuzz3r_f0und_cr4sh}',
         _task('# Задача: IPC fuzzing\n\nРазбери вывод drozer и найди флаг.\n', [
             _f(f'{WD}/drozer.log',
                'com.vanta.app -> DebugActivity\n  isExported: true\n  permission: null\n'
                '  fuzzing extras... crash at extra "x=nto{1pc_fuzz3r_f0und_cr4sh}"\n')])),
    _lab('mobile-magisk-modules', 'Практика: Magisk-модуль и Zygisk',
         ['task.md', 'module'],
         ['`module/` — исходники Magisk-модуля.',
          'Ищи `module.prop` и Zygisk-часть (`zygisk/`).',
          'Секрет есть в модуле — найди `nto{` и запиши в `found.txt`.'],
         'nto{zyg1sk_m0dul3_h00k}',
         _task('# Задача: Magisk-модуль\n\nРазбери Magisk-модуль и найди флаг.\n', [
             _dir(f'{WD}/module'),
             _f(f'{WD}/module/module.prop',
                'id=vanta-unlock\nname=Vanta Unlock\nversion=1.2\n'
                'description=unlocks vault; token=nto{zyg1sk_m0dul3_h00k}\n')])),
    _lab('mobile-mdm-mam', 'Практика: MDM/MAM',
         ['task.md', 'mdm_policy.json'],
         ['`mdm_policy.json` — политики корпоративного управления устройством.',
          'Ищи, что запрещено (screenshot, backup) и что осталось разрешено.',
          'В политике есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{mdm_p0l1cy_w34kn3ss}',
         _task('# Задача: MDM\n\nРазбери политики MDM и найди флаг.\n', [
             _f(f'{WD}/mdm_policy.json',
                '{\n  "allowCamera": false,\n  "allowScreenCapture": true,\n'
                '  "allowBackup": true,\n  "managedConfig": {"vaultKey": "nto{mdm_p0l1cy_w34kn3ss}"}\n}\n')])),
    _lab('mobile-mitm-burp', 'Практика: MITM через Burp',
         ['task.md', 'burp_cert.txt', 'requests.log'],
         ['`burp_cert.txt` и `requests.log` — настройка MITM и трафик.',
          'Ищи запросы с токенами в заголовках.',
          'В логе есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{m1tm_burp_c4_trust3d}',
         _task('# Задача: MITM\n\nНастрой MITM и найди секрет в перехваченном трафике.\n', [
             _f(f'{WD}/burp_cert.txt', 'CA: PortSwigger; installed as system CA on rooted device\n'),
             _f(f'{WD}/requests.log',
                'GET /api/v1/me HTTP/1.1\nHost: api.vanta.local\nAuthorization: Bearer nto{m1tm_burp_c4_trust3d}\n')])),
    _lab('mobile-push-security', 'Практика: безопасность push (APNs/FCM)',
         ['task.md', 'apns_payload.json'],
         ['`apns_payload.json` — payload APNs.',
          'Ищи, что попадает в `aps.alert` и `custom`-поля.',
          'В payload есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{4pns_p4yl04d_sp00f}',
         _task('# Задача: push\n\nРазбери APNs-payload и найди флаг.\n', [
             _f(f'{WD}/apns_payload.json',
                '{"aps":{"alert":"New message","badge":1},'
                '"session":"nto{4pns_p4yl04d_sp00f}"}\n')])),
    _lab('mobile-react-native-reversing', 'Практика: реверс React Native',
         ['task.md', 'hermes_strings.txt'],
         ['`hermes_strings.txt` — строки из Hermes-байткода.',
          'Hermes компилирует JS; строки извлекаются `hbctool`/`strings`.',
          'Среди строк есть флаг — найди `nto{` и запиши в `found.txt`.'],
         'nto{h3rm3s_byt3c0d3_str1ngs}',
         _task('# Задача: React Native\n\nРазбери строки Hermes-байткода и найди флаг.\n', [
             _f(f'{WD}/hermes_strings.txt',
                'index.android.bundle\napi.vanta.local\n'
                'SECRET_KEY=nto{h3rm3s_byt3c0d3_str1ngs}\n')])),
    _lab('mobile-ssl-pinning', 'Практика: обход SSL Pinning',
         ['task.md', 'NetworkSecurityConfig.xml'],
         ['`NetworkSecurityConfig.xml` — конфиг сетевой безопасности.',
          'Ищи `<pin-set>` и `cleartextTrafficPermitted`.',
          'Секрет есть в конфиге — найди `nto{` и запиши в `found.txt`.'],
         'nto{p1nn1ng_c0nf1g_l34k}',
         _task('# Задача: SSL pinning\n\nРазбери сетевую конфигурацию и найди флаг.\n', [
             _f(f'{WD}/NetworkSecurityConfig.xml',
                '<network-security-config>\n  <base-config cleartextTrafficPermitted="true"/>\n'
                '  <domain-config>\n    <domain includeSubdomains="true">api.vanta.local</domain>\n'
                '    <pin-set><pin digest="SHA-256">DECOY=</pin></pin-set>\n'
                '    <meta-data android:name="pinBackup" android:value="nto{p1nn1ng_c0nf1g_l34k}"/>\n'
                '  </domain-config>\n</network-security-config>\n')])),
    _lab('mobile-tls-pinning-bypass', 'Практика: TLS pinning bypass',
         ['task.md', 'bypass.js', 'log.txt'],
         ['`bypass.js` — Frida-скрипт обхода pinning, `log.txt` — вывод.',
          'Скрипт хукает `TrustManager`/`SSLContext`.',
          'В логе есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{tls_p1nn1ng_p4tch3d}',
         _task('# Задача: TLS pinning bypass\n\nРазбери скрипт обхода и его вывод, найди флаг.\n', [
             _f(f'{WD}/bypass.js',
                "Java.perform(function(){\n"
                "  var X509 = Java.use('javax.net.ssl.X509TrustManager');\n"
                "  X509.checkServerTrusted.implementation = function(){ return; };\n});\n"),
             _f(f'{WD}/log.txt',
                '[*] TrustManager.checkServerTrusted hooked\n[*] pinning disabled\n'
                '[+] intercepted token: nto{tls_p1nn1ng_p4tch3d}\n')])),
    _lab('mobile-wear-os', 'Практика: Wear OS',
         ['task.md', 'wear_manifest.xml'],
         ['`wear_manifest.xml` — манифест Wear OS-приложения.',
          'Ищи общие data-layer разрешения и экспортированные listener-сервисы.',
          'Секрет есть в манифесте — найди `nto{` и запиши в `found.txt`.'],
         'nto{w34r_0s_d4t4_l4y3r}',
         _task('# Задача: Wear OS\n\nРазбери манифест Wear OS и найди флаг.\n', [
             _f(f'{WD}/wear_manifest.xml',
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.vanta.wear">\n'
                '  <uses-permission android:name="com.google.android.permission.PROVIDE_BACKGROUND"/>\n'
                '  <application>\n'
                '    <meta-data android:name="wear.token" android:value="nto{w34r_0s_d4t4_l4y3r}"/>\n'
                '  </application>\n</manifest>\n')])),
    _lab('mobile-wearable-iot', 'Практика: companion-приложения',
         ['task.md', 'companion.log'],
         ['`companion.log` — обмен данными телефона и носимого устройства.',
          'Ищи незашифрованные сообщения через data layer.',
          'В логе есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{c0mp4n10n_cl34rt3xt_l34k}',
         _task('# Задача: companion\n\nРазбери обмен companion-приложения и найди флаг.\n', [
             _f(f'{WD}/companion.log',
                'phone -> watch: {"cmd":"sync","token":"nto{c0mp4n10n_cl34rt3xt_l34k}"}\n'
                'watch -> phone: {"ack":true}\n')])),
    _lab('mobile-ios-dynamic', 'Практика: динамический анализ iOS',
         ['task.md', 'frida_ios.log'],
         ['`frida_ios.log` — динамическая сессия на iOS.',
          'Ищи перехваченные ObjC-методы и их возвраты.',
          'В логе есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{10s_dyn4m1c_h00k}',
         _task('# Задача: iOS dynamic\n\nРазбери динамическую сессию iOS и найди флаг.\n', [
             _f(f'{WD}/frida_ios.log',
                '[*] attached Vanta (ios)\n'
                'ObjC: -[VantaAuth apiToken] -> "nto{10s_dyn4m1c_h00k}"\n')])),
    _lab('mobile-ios-jailbreak', 'Практика: детект jailbreak',
         ['task.md', 'jb_check.m'],
         ['`jb_check.m` — код проверки jailbreak.',
          'Ищи пути `/Applications/Cydia.app`, `fork()`, запись вне песочницы.',
          'Секрет есть рядом с проверкой — найди `nto{` и запиши в `found.txt`.'],
         'nto{10s_jb_d3t3ct_byp4ss}',
         _task('# Задача: jailbreak\n\nРазбери проверку jailbreak и найди флаг.\n', [
             _f(f'{WD}/jb_check.m',
                '#import <Foundation/Foundation.h>\n'
                'BOOL isJB(void){\n'
                '  if ([[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app"]) return YES;\n'
                '  return NO;\n}\n'
                'static NSString *tok = @"nto{10s_jb_d3t3ct_byp4ss}";\n')])),
    _lab('mobile-ios-oauth-sso', 'Практика: OAuth/SSO в iOS',
         ['task.md', 'oauth_flow.txt'],
         ['`oauth_flow.txt` — лог OAuth-потока (PKCE).',
          'Ищи, где теряется `code_verifier` или переиспользуется `state`.',
          'В логе есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{0auth_pkce_m1ss1ng}',
         _task('# Задача: OAuth iOS\n\nРазбери OAuth-поток и найди флаг.\n', [
             _f(f'{WD}/oauth_flow.txt',
                'GET /authorize?client_id=vanta&response_type=code&code_challenge=...\n'
                'note: code_verifier NOT sent on token exchange\n'
                'stolen code -> token: nto{0auth_pkce_m1ss1ng}\n')])),
    _lab('mobile-ios-ssl-killswitch', 'Практика: SSL Kill Switch',
         ['task.md', 'killswitch.log'],
         ['`killswitch.log` — лог работы SSL Kill Switch на iOS.',
          'Инструмент отключает pinning через hooks.',
          'В логе есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{ssl_k1llsw1tch_10s}',
         _task('# Задача: SSL Kill Switch\n\nРазбери лог и найди флаг.\n', [
             _f(f'{WD}/killswitch.log',
                '[*] installing SSL Kill Switch\n[*] hooking SecTrustEvaluate\n'
                '[+] pinning bypassed, captured: nto{ssl_k1llsw1tch_10s}\n')])),
    _lab('mobile-cert-pinning-deep', 'Практика: глубокий cert pinning',
         ['task.md', 'pinning.java'],
         ['`pinning.java` — реализация pinning через OkHttp/TrustKit.',
          'Ищи сравнение certificate pin.',
          'Секрет есть в коде — найди `nto{` и запиши в `found.txt`.'],
         'nto{0khttp_c3rt_p1nn3r}',
         _task('# Задача: cert pinning\n\nРазбери реализацию pinning и найди флаг.\n', [
             _f(f'{WD}/pinning.java',
                'CertificatePinner pinner = new CertificatePinner.Builder()\n'
                '    .add("api.vanta.local", "sha256/DECOY=")\n'
                '    .build();\n'
                'String debugPin = "nto{0khttp_c3rt_p1nn3r}";\n')])),
    _lab('mobile-hooking-internals', 'Практика: внутренности хукинга ART',
         ['task.md', 'art_notes.txt'],
         ['`art_notes.txt` — заметки о хукинге на уровне ART.',
          'Ищи RegisterNatives, JVMTI, art::Method.',
          'Секрет есть в заметках — найди `nto{` и запиши в `found.txt`.'],
         'nto{4rt_r3g1st3rn4t1v3s}',
         _task('# Задача: ART internals\n\nРазбери заметки о хукинге ART и найди флаг.\n', [
             _f(f'{WD}/art_notes.txt',
                'RegisterNatives(env, clazz, methods, n)\n'
                'JVMTI RetransformClasses\n'
                'art::Method::SetEntryPointFromQuickCompiledCode\n'
                'demo token: nto{4rt_r3g1st3rn4t1v3s}\n')])),
    _lab('mobile-integrity', 'Практика: Integrity / Play Integrity',
         ['task.md', 'integrity.json'],
         ['`integrity.json` — ответ Play Integrity API.',
          'Ищи `MEETS_DEVICE_INTEGRITY` и поля, которые можно подделать.',
          'В ответе есть секрет — найди `nto{` и запиши в `found.txt`.'],
         'nto{pl4y_1nt3gr1ty_sp00f}',
         _task('# Задача: integrity\n\nРазбери ответ Play Integrity и найди флаг.\n', [
             _f(f'{WD}/integrity.json',
                '{\n  "requestDetails": {"requestPackageName": "com.vanta.app"},\n'
                '  "deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]},\n'
                '  "debugToken": "nto{pl4y_1nt3gr1ty_sp00f}"\n}\n')])),
    _lab('mobile-ios-analysis', 'Практика: анализ iOS-приложения',
         ['task.md', 'Payload'],
         ['`Payload/` — распакованный IPA. Ищи бинарник и Info.plist.',
          'Определи тип Mach-O (`file`) и извлеки строки.',
          'Секрет есть в бинарнике — найди `nto{` и запиши в `found.txt`.'],
         'nto{10s_b1n4ry_str1ngs}',
         _task('# Задача: iOS analysis\n\nРазбери iOS-приложение и найди флаг.\n', [
             _dir(f'{WD}/Payload'), _dir(f'{WD}/Payload/Vanta.app'),
             _f(f'{WD}/Payload/Vanta.app/Vanta', 'not-a-real-macho\nsecret=nto{10s_b1n4ry_str1ngs}\n'),
             _f(f'{WD}/Payload/Vanta.app/Info.plist', '<plist><dict><key>CFBundleIdentifier</key><string>com.vanta.app</string></dict></plist>\n')])),
    _lab('mobile-ios-security', 'Практика: безопасность iOS',
         ['task.md', 'Payload'],
         ['`Payload/` — приложение. Ищи настройки ATS и хранилища.',
          'Ищи `NSAllowsArbitraryLoads` и ключи Keychain.',
          'Секрет есть в конфиге — найди `nto{` и запиши в `found.txt`.'],
         'nto{10s_4ts_4rb1tr4ry_l04ds}',
         _task('# Задача: iOS security\n\nРазбери настройки безопасности iOS-приложения и найди флаг.\n', [
             _dir(f'{WD}/Payload'), _dir(f'{WD}/Payload/Vanta.app'),
             _f(f'{WD}/Payload/Vanta.app/Info.plist',
                '<plist><dict>\n  <key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>\n'
                '  <key>KeychainAccessGroup</key><string>nto{10s_4ts_4rb1tr4ry_l04ds}</string>\n</dict></plist>\n')])),
    _lab('mobile-frida-tooling', 'Практика: инструментарий Frida',
         ['task.md', 'frida_tools.txt'],
         ['`frida_tools.txt` — список инструментов и их вывода.',
          'Ищи `frida-ps`, `frida-trace`, `objection`.',
          'Секрет есть в выводе — найди `nto{` и запиши в `found.txt`.'],
         'nto{fr1d4_tr4c3_t00l1ng}',
         _task('# Задача: Frida tooling\n\nРазбери вывод инструментов Frida и найди флаг.\n', [
             _f(f'{WD}/frida_tools.txt',
                '$ frida-ps -U\n  PID  Name\n 1234  com.vanta.app\n'
                '$ frida-trace -U -i "open*"\n  open() -> "/data/data/com.vanta.app/nto{fr1d4_tr4c3_t00l1ng}"\n')])),
]
