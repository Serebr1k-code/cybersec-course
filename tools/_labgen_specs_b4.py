# Batch 4: mobile labs (iOS, native, frida, misc surfaces). Real artifacts.
import base64
import os

B4 = '/tmp/labgen/b4'
WD = '/home/student/task'


def _b64(path):
    with open(os.path.join(B4, path), 'rb') as f:
        return base64.b64encode(f.read()).decode()


_SO = _b64('libvanta.so')


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


SPECS = [
    # native .so
    _lab(
        'mobile-native-so-deep',
        'Практика: реверс нативной библиотеки',
        ['task.md', 'libvanta.so'],
        [
            'Определи тип файла: `file libvanta.so`.',
            'Печатаемые строки в бинаре ищут `strings`: `strings libvanta.so`.',
            "Среди строк есть флаг — `strings libvanta.so | grep nto > found.txt`.",
        ],
        'nto{n4t1v3_s0_r3v3rs1ng}',
        [
            _dir(WD),
            _f(f'{WD}/task.md',
               '# Задача: нативная библиотека\n\nВ приложении есть `libvanta.so` — нативный код, который проверяет лицензию.\n'
               'Разбери его и найди строку-флаг. Запиши флаг в `found.txt`.\n'),
            {'path': f'{WD}/libvanta.so', 'b64': _SO},
        ],
        toolset=['core', 'strings', 'nm', 'objdump', 'readelf'],
        tools={
            'nm': {'help': "nm [-D] <файл> — таблица символов",
                   'cases': [{'match': r"-D.*libvanta\.so", 'output':
                              "000000000000100d T check\n0000000000001000 T expected_flag\n"}],
                   'fallback': "nm: доступно `nm -D libvanta.so`\n"},
            'readelf': {'help': "readelf -h <файл> — заголовок ELF",
                        'cases': [{'match': r"-h.*libvanta\.so", 'output':
                                   "ELF Header:\n  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00\n"
                                   "  Class:                             ELF64\n  Type:                              DYN (Shared object file)\n"
                                   "  Machine:                           Advanced Micro Devices X86-64\n"}],
                        'fallback': "readelf: доступно `readelf -h libvanta.so`\n"},
            'objdump': {'help': "objdump -d <файл> — дизассемблирование",
                        'cases': [{'match': r"-d.*libvanta\.so", 'output':
                                   "\nlibvanta.so:     file format elf64-x86-64\n\nDisassembly of section .text:\n\n"
                                   "0000000000001000 <expected_flag>:\n    1000:\t55                   \tpush   %rbp\n"
                                   "    1004:\t48 8d 05 f5 0f 00 00 \tlea    0xff5(%rip),%rax        # 2000 <check+0xff3>\n"
                                   "    100c:\tc3                   \tret\n"}],
                        'fallback': "objdump: доступно `objdump -d libvanta.so`\n"},
        },
    ),
    # adb
    _lab(
        'mobile-adb-fastboot',
        'Практика: разбор вывода adb',
        ['task.md', 'adb_devices.txt', 'notes.txt'],
        [
            '`adb_devices.txt` — вывод `adb devices -l` и свойств устройства.',
            'Ищи устройства с `ro.debuggable=1` и незаблокированным загрузчиком.',
            "Среди свойств есть секрет — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{adb_d3bugg4bl3_d3v1c3}',
        [
            _dir(WD),
            _f(f'{WD}/adb_devices.txt',
               'List of devices attached\n'
               'emulator-5554  device product:sdk_gphone model:sdk_gphone64_x86_64 transport_id:1\n'
               'R58M12ABCDE    device product:beyond1 model:SM_G973F transport_id:2\n'
               '[emulator-5554]: getprop ro.debuggable => 1\n'
               '[emulator-5554]: getprop ro.secure => 0\n'
               '[emulator-5554]: getprop vanta.debug.token => nto{adb_d3bugg4bl3_d3v1c3}\n'),
            _f(f'{WD}/notes.txt', 'На эмуляторе включена отладка. Проверяй свойства через `getprop`.\n'),
        ],
    ),
    # binder
    _lab(
        'mobile-android-binder',
        'Практика: разбор Binder-транзакций',
        ['task.md', 'binder.log'],
        [
            '`binder.log` — дамп транзакций Binder (межпроцессное взаимодействие Android).',
            'Обрати внимание на интерфейсы системных сервисов и передаваемые строки.',
            "Среди транзакций есть строка с секретом — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{b1nd3r_tr4ns4ct10n_l34k}',
        [
            _dir(WD),
            _f(f'{WD}/binder.log',
               'binder: 1842:1842 transaction 1 to 0x0 (activity)\n'
               '  data: interface=android.app.IActivityManager code=START_ACTIVITY\n'
               'binder: 1842:1850 transaction 42 to 0x0 (vanta.auth)\n'
               '  data: interface=com.vanta.IAuth code=GET_TOKEN extra="nto{b1nd3r_tr4ns4ct10n_l34k}"\n'
               'binder: 1842:1851 transaction 7 to 0x0 (package)\n'
               '  data: interface=android.content.pm.IPackageManager code=GET_PACKAGE_INFO\n'),
        ],
    ),
    # iOS basics
    _lab(
        'mobile-ios-basics',
        'Практика: разбор Info.plist iOS',
        ['task.md', 'Payload'],
        [
            '`Payload/` — распакованный IPA. Конфигурация приложения — в `Info.plist`.',
            'В plist интересны URL-схемы, ключи ATS и кастомные значения.',
            "Секрет лежит в `Info.plist` — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{1pa_1nf0_pl1st_l34k}',
        [
            _dir(WD), _dir(f'{WD}/Payload'), _dir(f'{WD}/Payload/Vanta.app'),
            _f(f'{WD}/Payload/Vanta.app/Info.plist',
               '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
               '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n'
               '  <key>CFBundleIdentifier</key><string>com.vanta.app</string>\n'
               '  <key>CFBundleShortVersionString</key><string>1.4.2</string>\n'
               '  <key>VantaDebugToken</key><string>nto{1pa_1nf0_pl1st_l34k}</string>\n'
               '  <key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>\n'
               '</dict>\n</plist>\n'),
        ],
    ),
    # iOS static class-dump
    _lab(
        'mobile-ios-static',
        'Практика: class-dump iOS',
        ['task.md', 'classdump.txt'],
        [
            '`classdump.txt` — результат `class-dump` по бинарю iOS-приложения.',
            'Ищи методы с подозрительными именами (`token`, `secret`, `key`, `flag`).',
            "В одном из методов зашита строка-флаг — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{cl4ssdump_f1nds_m3th0ds}',
        [
            _dir(WD),
            _f(f'{WD}/classdump.txt',
               '@interface VantaAuth : NSObject\n'
               '- (NSString *)apiToken;\n'
               '- (BOOL)isPremium;\n'
               '- (NSString *)debugFlag;\n@end\n\n'
               '@implementation VantaAuth\n'
               '- (NSString *)debugFlag { return @"nto{cl4ssdump_f1nds_m3th0ds}"; }\n'
               '@end\n'),
        ],
    ),
    # iOS URL schemes
    _lab(
        'mobile-ios-urlscheme',
        'Практика: URL-схемы iOS',
        ['task.md', 'Payload'],
        [
            'URL-схемы приложения описаны в `Info.plist` в `CFBundleURLTypes`.',
            'Любое приложение может зарегистрировать ту же схему — перехват callback.',
            "Секрет — в параметре callback-схемы: найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{url_sch3m3_h1j4ck}',
        [
            _dir(WD), _dir(f'{WD}/Payload'), _dir(f'{WD}/Payload/Vanta.app'),
            _f(f'{WD}/Payload/Vanta.app/Info.plist',
               '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n'
               '  <key>CFBundleURLTypes</key>\n  <array>\n    <dict>\n'
               '      <key>CFBundleURLSchemes</key>\n      <array><string>vanta</string></array>\n'
               '      <key>CFBundleURLName</key><string>com.vanta.app.oauth</string>\n'
               '    </dict>\n  </array>\n'
               '  <key>VantaOAuthRedirect</key><string>vanta://oauth?code=nto{url_sch3m3_h1j4ck}</string>\n'
               '</dict>\n</plist>\n'),
        ],
    ),
    # universal links
    _lab(
        'mobile-universal-links',
        'Практика: Universal Links / AASA',
        ['task.md', 'apple-app-site-association'],
        [
            'Universal Links настраиваются файлом `apple-app-site-association` на домене.',
            'Смотри `paths` и `components` — какие пути отдаются приложению.',
            "Среди путей есть чувствительный — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{un1v3rs4l_l1nks_p4ths}',
        [
            _dir(WD),
            _f(f'{WD}/apple-app-site-association',
               '{\n  "applinks": {\n    "details": [\n      {\n'
               '        "appID": "ABCDE12345.com.vanta.app",\n'
               '        "paths": ["/account/*", "/oauth/callback?token=nto{un1v3rs4l_l1nks_p4ths}", "NOT /help/*"]\n'
               '      }\n    ]\n  }\n}\n'),
        ],
    ),
    # cycript
    _lab(
        'mobile-ios-cycript',
        'Практика: runtime-интроспекция (cycript)',
        ['task.md', 'cycript_session.log'],
        [
            '`cycript_session.log` — сессия cycript в рантайме iOS-приложения.',
            'Ищи вызовы методов, возвращающих секреты.',
            "В логе есть возвращённое значение с флагом — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{cycr1pt_runt1m3_l34k}',
        [
            _dir(WD),
            _f(f'{WD}/cycript_session.log',
               'cy# var app = [UIApplication sharedApplication]\n'
               'cy# var auth = [[NSClassFromString(@"VantaAuth") alloc] init]\n'
               'cy# [auth apiToken]\n'
               '@"nto{cycr1pt_runt1m3_l34k}"\n'
               'cy# [auth isPremium]\n'
               '@YES\n'),
        ],
    ),
    # dylib injection
    _lab(
        'mobile-ios-dylib-injection',
        'Практика: инъекция dylib',
        ['task.md', 'entitlements.plist', 'loader.log'],
        [
            'Для инъекции dylib нужен `get-task-allow` в entitlements (или re-sign).',
            'Смотри `entitlements.plist` и лог загрузки DYLD_INSERT_LIBRARIES.',
            "В логе загрузки есть путь с секретом — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{dyl1b_1nj3ct10n_w0rks}',
        [
            _dir(WD),
            _f(f'{WD}/entitlements.plist',
               '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n'
               '  <key>get-task-allow</key><true/>\n'
               '  <key>application-identifier</key><string>ABCDE12345.com.vanta.app</string>\n'
               '</dict>\n</plist>\n'),
            _f(f'{WD}/loader.log',
               'dyld: loaded /usr/lib/libSystem.B.dylib\n'
               'dyld: DYLD_INSERT_LIBRARIES=/tmp/nto{dyl1b_1nj3ct10n_w0rks}.dylib\n'
               'dyld: loaded hook.dylib, patching VantaAuth.apiToken\n'),
        ],
    ),
    # deeplink RCE chain
    _lab(
        'mobile-deeplink-rce',
        'Практика: цепочка deep link → RCE',
        ['task.md', 'decoded'],
        [
            'Deep link ведёт в экспортированный компонент, который грузит URL в WebView.',
            'Если URL-параметр попадает в `loadUrl` без проверки — это путь к RCE/утечке.',
            "Секрет — в целевом внутреннем экране: найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{d33pl1nk_t0_rc3_ch41n}',
        [
            _dir(WD), _dir(f'{WD}/decoded'), _dir(f'{WD}/decoded/smali/com/vanta/app/ui'),
            _f(f'{WD}/decoded/AndroidManifest.xml',
               '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.vanta.app">\n'
               '  <application>\n'
               '    <activity android:name=".ui.WebActivity" android:exported="true">\n'
               '      <intent-filter><action android:name="android.intent.action.VIEW"/>\n'
               '        <data android:scheme="vanta" android:host="open"/></intent-filter>\n'
               '    </activity>\n  </application>\n</manifest>\n'),
            _f(f'{WD}/decoded/smali/com/vanta/app/ui/WebActivity.smali',
               '.class public Lcom/vanta/app/ui/WebActivity;\n'
               '.method public onCreate(Landroid/os/Bundle;)V\n'
               '    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;\n'
               '    const-string v0, "url"\n'
               '    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n'
               '    const-string v1, "nto{d33pl1nk_t0_rc3_ch41n}"\n'
               '    invoke-virtual {p0, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n'
               '    return-void\n.end method\n'),
        ],
    ),
    # deeplink deep
    _lab(
        'mobile-deeplink-deep',
        'Практика: deep-link цепочка захвата аккаунта',
        ['task.md', 'decoded'],
        [
            'Deep link `vanta://reset?...` инициирует сброс пароля.',
            'Если параметр email не проверяется, токен сброса уйдёт атакующему.',
            "Секрет — токен сброса: найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{d33pl1nk_4cc0unt_t4k30v3r}',
        [
            _dir(WD), _dir(f'{WD}/decoded'), _dir(f'{WD}/decoded/smali/com/vanta/app/ui'),
            _f(f'{WD}/decoded/AndroidManifest.xml',
               '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.vanta.app">\n'
               '  <application>\n'
               '    <activity android:name=".ui.ResetActivity" android:exported="true">\n'
               '      <intent-filter><action android:name="android.intent.action.VIEW"/>\n'
               '        <data android:scheme="vanta" android:host="reset"/></intent-filter>\n'
               '    </activity>\n  </application>\n</manifest>\n'),
            _f(f'{WD}/decoded/smali/com/vanta/app/ui/ResetActivity.smali',
               '.class public Lcom/vanta/app/ui/ResetActivity;\n'
               '.method public onCreate(Landroid/os/Bundle;)V\n'
               '    const-string v0, "email"\n'
               '    const-string v1, "reset_token=nto{d33pl1nk_4cc0unt_t4k30v3r}"\n'
               '    return-void\n.end method\n'),
        ],
    ),
    # packers
    _lab(
        'mobile-android-packers',
        'Практика: распаковка DEX-пакера',
        ['task.md', 'dump.txt'],
        [
            'Упакованное APK держит настоящий DEX в памяти — его дампят (`frida-dexdump`).',
            '`dump.txt` — строки из дампнутого DEX.',
            "Среди строк есть флаг — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{d3x_dump_unp4ck3d}',
        [
            _dir(WD),
            _f(f'{WD}/dump.txt',
               'Lcom/vanta/app/StubApplication; -> attachBaseContext\n'
               'Lcom/vanta/app/real/Pay; -> process\n'
               'const-string v0, "nto{d3x_dump_unp4ck3d}"\n'
               'Lcom/packer/Native; -> load\n'),
        ],
    ),
    # frida-dexdump
    _lab(
        'mobile-frida-dexdump',
        'Практика: дамп DEX из памяти',
        ['task.md', 'dexdump.log'],
        [
            '`frida-dexdump` сканирует память процесса и выгружает DEX-файлы.',
            'Ищи, какой класс/метод держит секрет.',
            "В логе дампа есть строка с флагом — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{fr1d4_d3xdump_p4yl04d}',
        [
            _dir(WD),
            _f(f'{WD}/dexdump.log',
               '[*] Searching for DexClassLoader in memory...\n'
               '[*] Found DEX at 0x7f9a0000, size 1480\n'
               '[+] Dumped classes.dex\n'
               '    class Lcom/vanta/app/Vault;\n'
               '      field SECRET = "nto{fr1d4_d3xdump_p4yl04d}"\n'),
        ],
    ),
    # frida scripting
    _lab(
        'mobile-frida-scripting',
        'Практика: Frida-скриптинг',
        ['task.md', 'hook.js', 'frida.log'],
        [
            'Frida-скрипт хукает метод и печатает аргументы/возврат.',
            '`hook.js` — скрипт, `frida.log` — его вывод.',
            "В выводе есть возвращённый секрет — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{fr1d4_h00k_r3turn_v4lu3}',
        [
            _dir(WD),
            _f(f'{WD}/hook.js',
               "Java.perform(function () {\n"
               "  var V = Java.use('com.vanta.app.Vault');\n"
               "  V.getSecret.implementation = function () {\n"
               "    var r = this.getSecret();\n"
               "    console.log('[hook] getSecret -> ' + r);\n"
               "    return r;\n  };\n});\n"),
            _f(f'{WD}/frida.log',
               '[*] Spawned com.vanta.app\n[hook] getSecret -> nto{fr1d4_h00k_r3turn_v4lu3}\n'),
        ],
    ),
    # objection
    _lab(
        'mobile-objection',
        'Практика: Objection без скриптов',
        ['task.md', 'objection_session.log'],
        [
            'Objection даёт готовые команды: `android sslpinning disable`, `android root disable`.',
            '`objection_session.log` — лог сессии.',
            "Среди вывода есть секрет — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{0bj3ct10n_0n3_1n3r}',
        [
            _dir(WD),
            _f(f'{WD}/objection_session.log',
               'com.vanta.app on (google: 13) [usb] # android root disable\n'
               '(agent) Root detection hooks installed\n'
               'com.vanta.app on (google: 13) [usb] # android sslpinning disable\n'
               '(agent) SSL pinning disabled\n'
               'com.vanta.app on (google: 13) [usb] # env\n'
               '{"debug":true,"token":"nto{0bj3ct10n_0n3_1n3r}"}\n'),
        ],
    ),
    # MobSF report
    _lab(
        'mobile-automation',
        'Практика: разбор отчёта MobSF',
        ['task.md', 'mobsf_report.json'],
        [
            'MobSF — автоматизированный анализатор мобильных приложений.',
            '`mobsf_report.json` — его отчёт; ищи раздел `secrets`/`hardcoded`.',
            "В отчёте есть найденный секрет — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{m0bsf_f0und_th3_s3cr3t}',
        [
            _dir(WD),
            _f(f'{WD}/mobsf_report.json',
               '{\n  "app_name": "Vanta",\n  "package_name": "com.vanta.app",\n'
               '  "hardcoded_secrets": [\n    {"type": "Generic API Key", "value": "AIzaSyDECOY0000000000000000000000000000"},\n'
               '    {"type": "Flag", "value": "nto{m0bsf_f0und_th3_s3cr3t}"}\n  ],\n'
               '  "security_score": 42\n}\n'),
        ],
    ),
    # BLE
    _lab(
        'mobile-bluetooth-le',
        'Практика: разбор GATT-обмена',
        ['task.md', 'gatt_dump.txt'],
        [
            '`gatt_dump.txt` — дамп GATT-сервисов и характеристик BLE-устройства.',
            'Ищи характеристики с записью (write) — через них можно писать команды.',
            "Среди значений есть секрет — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{bl3_g4tt_ch4r4ct3r1st1c}',
        [
            _dir(WD),
            _f(f'{WD}/gatt_dump.txt',
               'Service 0000180a-0000-1000-8000-00805f9b34fb (Device Information)\n'
               '  Char 00002a29 (Manufacturer Name) read: "Vanta"\n'
               'Service 0000fff0-0000-1000-8000-00805f9b34fb (Vendor)\n'
               '  Char 0000fff1 write: "AUTH nto{bl3_g4tt_ch4r4ct3r1st1c}"\n'),
        ],
    ),
    # cloud forensics
    _lab(
        'mobile-forensics-cloud',
        'Практика: облачная мобильная форензика',
        ['task.md', 'icloud_export'],
        [
            '`icloud_export/` — выгрузка данных приложения из облачного бэкапа.',
            'Ищи файлы конфигурации и кэш токенов.',
            "Секрет в одном из файлов — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{1cl0ud_b4ckup_syncs_s3cr3ts}',
        [
            _dir(WD), _dir(f'{WD}/icloud_export'), _dir(f'{WD}/icloud_export/Documents'),
            _f(f'{WD}/icloud_export/Documents/tokens.json',
               '{"refresh_token":"1//0eDECOY","device_id":"A1B2",'
               '"vault":"nto{1cl0ud_b4ckup_syncs_s3cr3ts}"}\n'),
            _f(f'{WD}/icloud_export/Documents/notes.txt', 'sync ok\n'),
        ],
    ),
    # notifications / FCM
    _lab(
        'mobile-notifications',
        'Практика: перехват FCM-уведомлений',
        ['task.md', 'fcm_payload.json'],
        [
            'FCM-payload может содержать чувствительные данные в `data`.',
            'Если push не проверяет подпись — payload можно подделать.',
            "В payload есть секрет — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{fcm_p4yl04d_1nt3rc3pt}',
        [
            _dir(WD),
            _f(f'{WD}/fcm_payload.json',
               '{\n  "to": "fcm-token-DECOY",\n'
               '  "notification": {"title": "Vanta", "body": "New login"},\n'
               '  "data": {"action": "open_vault", "token": "nto{fcm_p4yl04d_1nt3rc3pt}"}\n}\n'),
        ],
    ),
]
