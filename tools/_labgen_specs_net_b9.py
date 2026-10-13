# Batch: 12 more network labs (pcap/dig/curl/openssl fixtures + replay tools).
import base64
import os

NET = '/tmp/labgen_net'
WD = '/home/student/task'


def _b64(path):
    with open(os.path.join(NET, path), 'rb') as f:
        return base64.b64encode(f.read()).decode()


def _dir(p):
    return {'path': p, 'type': 'dir'}


def _f(p, t):
    return {'path': p, 'text': t}


def _b(p, name):
    return {'path': f'{p}/{name}', 'b64': _b64(name), 'mode': '644'}


def _lab(id, title, files, hints, check, expect_file, expect_contains, fs,
         tools=None, toolset=None):
    spec = {
        'id': id, 'category': 'network', 'title': title,
        'toolset': toolset or ['core', 'grep'],
        'workdir': WD, 'files': files,
        'check': check, 'hints': hints,
        'expect': {'file': expect_file, 'contains': expect_contains},
        'fs': fs,
    }
    if tools:
        spec['tools'] = tools
    return spec


TSHARK_HELP = 'tshark -r <pcap> [фильтр] — разбор трафика (эмуляция: вывод захвачен с реального tshark)'

SPECS = []

# ---------------------------------------------------------------- 1. dns-attacks
SPECS.append(_lab(
    'network-dns-attacks', 'Практика: отравление DNS-кэша',
    ['task.md', 'dns.pcap'],
    ['Резолвер `10.0.0.53` спросил авторитетный сервер `198.51.100.1` про `portal.corp.local`.',
     'На один запрос пришло ДВА ответа: `tshark -r dns.pcap -Y dns -T fields -e ip.src -e dns.qry.name -e dns.a`.',
     'Настоящий сервер — `203.0.113.10`; поддельный ответ указывает на `10.0.0.99`. Жертва пошла именно туда.',
     'Собери HTTP-поток до отравленной цели: `tshark -r dns.pcap -q -z follow,tcp,ascii,0` — в теле страницы флаг.'],
    "grep -q 'nto{' answer.txt",
    f'{WD}/answer.txt', 'nto{dns_c4ch3_p01s0n_sp00f3d}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Задача: отравление DNS-кэша\n\n'
        'В дампе `dns.pcap` резолвер `10.0.0.53` опрашивает авторитетный сервер `198.51.100.1`\n'
        'по имени `portal.corp.local`. Настоящий адрес сервиса — `203.0.113.10`.\n\n'
        '1. Посмотри сводку: `tshark -r dns.pcap`\n'
        '2. Вытащи все ответы: `tshark -r dns.pcap -Y dns -T fields -e ip.src -e dns.qry.name -e dns.a`\n'
        '3. Один ответ — подделка. Жертва `10.0.0.5` пошла на подставленный адрес; собери поток:\n'
        '   `tshark -r dns.pcap -q -z follow,tcp,ascii,0`\n'
        '4. В теле страницы — флаг `nto{...}`. Запиши его в `answer.txt` и набери `check`.\n'),
     _b(WD, 'dns.pcap')],
    tools={'tshark': {'help': TSHARK_HELP, 'cases': [
        {'match': r'follow',
         'example': '-r dns.pcap -q -z follow,tcp,ascii,0',
         'output': '\n===================================================================\nFollow: tcp,ascii\nFilter: tcp.stream eq 0\nNode 0: 10.0.0.5:49001\nNode 1: 10.0.0.99:80\n67\nGET / HTTP/1.1\nHost: portal.corp.local\nUser-Agent: curl/8.5.0\n\n\n\t174\nHTTP/1.1 200 OK\nServer: nginx/1.24.0\nContent-Type: text/html\nContent-Length: 88\n\n<html><body><h1>corp portal</h1><p>token nto{dns_c4ch3_p01s0n_sp00f3d}</p></body></html>\n===================================================================\n'},
        {'match': r'dns',
         'example': "-r dns.pcap -Y dns -T fields -e ip.src -e dns.qry.name -e dns.a",
         'output': '10.0.0.53\tportal.corp.local\t\n198.51.100.1\tportal.corp.local\t10.0.0.99\n198.51.100.1\tportal.corp.local\t203.0.113.10\n'},
        {'match': r'dns\.pcap',
         'example': '-r dns.pcap',
         'output': '    1   0.000000    10.0.0.53 → 198.51.100.1 DNS 77 Standard query 0x3039 A portal.corp.local\n    2   0.000476 198.51.100.1 → 10.0.0.53    DNS 110 Standard query response 0x3039 A portal.corp.local A 10.0.0.99\n    3   0.000813 198.51.100.1 → 10.0.0.53    DNS 110 Standard query response 0x3039 A portal.corp.local A 203.0.113.10\n    4   0.001125     10.0.0.5 → 10.0.0.99    HTTP 121 GET / HTTP/1.1 \n    5   0.001376    10.0.0.99 → 10.0.0.5     HTTP 228 HTTP/1.1 200 OK  (text/html)\n'},
    ], 'fallback': 'tshark: доступно `tshark -r dns.pcap` (см. task.md)\n'}},
    toolset=['core', 'grep', 'tshark']))

# ---------------------------------------------------------------- 2. dnssec
SPECS.append(_lab(
    'network-dnssec', 'Практика: strip-атака на DNSSEC',
    ['task.md'],
    ['Валидирующий резолвер `1.1.1.1` возвращает флаг `ad` и RRSIG — подпись проверена.',
     'Локальный резолвер `127.0.0.1` валидацию не делает: в ответе нет `ad`, и адрес подменён на `10.0.0.99`.',
     'Атакующий в пути удалил RRSIG/DS (strip) — «ленивый» резолвер принял подделку.',
     'Запроси у него поддельную TXT-запись: `dig +dnssec bank.example TXT @127.0.0.1` — в ней флаг.'],
    "grep -q 'nto{' answer.txt",
    f'{WD}/answer.txt', 'nto{dnssec_str1p_d0wngr4d3}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Задача: strip-атака (downgrade) на DNSSEC\n\n'
        'Зона `bank.example` подписана (DNSSEC). Валидирующий резолвер `1.1.1.1`\n'
        'проверяет подпись; локальный резолвер `127.0.0.1` — нет.\n\n'
        '1. Сравни два ответа:\n'
        '   `dig +dnssec bank.example A @1.1.1.1`  — есть флаг `ad`, адрес настоящий\n'
        '   `dig +dnssec bank.example A @127.0.0.1` — нет `ad`, адрес подменён\n'
        '2. Атакующий удалил из ответа RRSIG/DS (strip-атака) — «ленивый» резолвер принял подделку.\n'
        '3. Спроси у него поддельную TXT-запись: `dig +dnssec bank.example TXT @127.0.0.1`\n'
        '4. Запиши флаг `nto{...}` из ответа в `answer.txt` и набери `check`.\n')],
    tools={'dig': {'help': 'dig [тип] <имя> [@сервер] — DNS-запрос (эмуляция: вывод захвачен с реального dig)',
                   'cases': [
        {'match': r'\bTXT\b',
         'example': '+dnssec bank.example TXT @127.0.0.1',
         'output': '; <<>> DiG 9.20.22 <<>> +dnssec bank.example TXT @127.0.0.1\n;; global options: +cmd\n;; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41289\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0\n\n;; QUESTION SECTION:\n;bank.example.\t\t\tIN\tTXT\n\n;; ANSWER SECTION:\nbank.example.\t\t300\tIN\tTXT\t"nto{dnssec_str1p_d0wngr4d3}"\n\n;; Query time: 0 msec\n;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)\n;; MSG SIZE  rcvd: 74\n'},
        {'match': r'DNSKEY',
         'example': 'bank.example DNSKEY +short',
         'output': '257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n'},
        {'match': r'\bDS\b',
         'example': 'bank.example DS +short',
         'output': '12345 13 2 8A9B4C1D2E3F405162738495A6B7C8D9E0F1A2B3C4D5E6F708192A3B4C5D6E7F\n'},
        {'match': r'1\.1\.1\.1',
         'example': '+dnssec bank.example A @1.1.1.1',
         'output': '; <<>> DiG 9.20.22 <<>> +dnssec bank.example A @1.1.1.1\n;; global options: +cmd\n;; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41287\n;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags: do; udp: 1232\n;; QUESTION SECTION:\n;bank.example.\t\t\tIN\tA\n\n;; ANSWER SECTION:\nbank.example.\t\t300\tIN\tA\t203.0.113.10\nbank.example.\t\t300\tIN\tRRSIG\tA 13 2 300 20261101000000 20261001000000 12345 bank.example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n\n;; Query time: 12 msec\n;; SERVER: 1.1.1.1#53(1.1.1.1) (UDP)\n;; MSG SIZE  rcvd: 179\n'},
        {'match': r'127\.0\.0\.1',
         'example': '+dnssec bank.example A @127.0.0.1',
         'output': '; <<>> DiG 9.20.22 <<>> +dnssec bank.example A @127.0.0.1\n;; global options: +cmd\n;; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41288\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0\n\n;; QUESTION SECTION:\n;bank.example.\t\t\tIN\tA\n\n;; ANSWER SECTION:\nbank.example.\t\t300\tIN\tA\t10.0.0.99\n\n;; Query time: 1 msec\n;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)\n;; MSG SIZE  rcvd: 57\n'},
    ], 'fallback': 'dig: доступно `dig +dnssec bank.example A @1.1.1.1` (см. task.md)\n'}},
    toolset=['core', 'grep', 'dig']))

# ---------------------------------------------------------------- 3. doh-dot
SPECS.append(_lab(
    'network-doh-dot', 'Практика: детект DoH по SNI',
    ['task.md', 'doh.pcap'],
    ['Клиент `10.0.0.50` не ходит на порт 53 — значит, DNS спрятан в TLS.',
     'Посмотри все ClientHello с SNI: `tshark -r doh.pcap -Y tls.handshake.extensions_server_name -T fields -e ip.src -e tcp.dstport -e tls.handshake.extensions_server_name`.',
     'DoT идёт на порт `853` (там `dns.quad9.net`). DoH сливается с вебом на порту `443`.',
     'Запиши имя DoH-эндпоинта (порт 443) в `answer.txt`.'],
    "grep -q 'cloudflare-dns.com' answer.txt",
    f'{WD}/answer.txt', 'cloudflare-dns.com',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Задача: найти DoH-эндпоинт по SNI\n\n'
        'Клиент `10.0.0.50` обходит DNS-фильтр: на порту 53 пусто, но идёт TLS-обмен.\n'
        'В `doh.pcap` — рукопожатия клиента.\n\n'
        '1. Сводка: `tshark -r doh.pcap`\n'
        '2. Все SNI: `tshark -r doh.pcap -Y tls.handshake.extensions_server_name -T fields -e ip.src -e tcp.dstport -e tls.handshake.extensions_server_name`\n'
        '3. DoT узнаётся по порту `853`; DoH сливается с вебом — порт `443`.\n'
        '4. Запиши имя DoH-эндпоинта (тот, что на `443`) в `answer.txt` и набери `check`.\n'),
     _b(WD, 'doh.pcap')],
    tools={'tshark': {'help': TSHARK_HELP, 'cases': [
        {'match': r'853',
         'example': '-r doh.pcap -Y tcp.port==853',
         'output': '    6   0.000736     9.9.9.9 → 10.0.0.50    TCP 54 853 → 51240 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0\n    7   0.000856    10.0.0.50 → 9.9.9.9     TCP 54 51240 → 853 [ACK] Seq=1 Ack=1 Win=8192 Len=0\n    8   0.001034    10.0.0.50 → 9.9.9.9     TLSv1 164 Client Hello (SNI=dns.quad9.net)\n'},
        {'match': r'server_name|tls\.handshake',
         'example': "-r doh.pcap -Y tls.handshake.extensions_server_name -T fields -e ip.src -e tcp.dstport -e tls.handshake.extensions_server_name",
         'output': '10.0.0.50\t443\tcloudflare-dns.com\n10.0.0.50\t853\tdns.quad9.net\n'},
        {'match': r'doh\.pcap',
         'example': '-r doh.pcap',
         'output': '    1   0.000000    10.0.0.50 → 1.1.1.1      TCP 54 51234 → 443 [SYN] Seq=0 Win=8192 Len=0\n    2   0.000139      1.1.1.1 → 10.0.0.50    TCP 54 443 → 51234 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0\n    3   0.000265    10.0.0.50 → 1.1.1.1      TCP 54 51234 → 443 [ACK] Seq=1 Ack=1 Win=8192 Len=0\n    4   0.000404    10.0.0.50 → 1.1.1.1      TLSv1 173 Client Hello (SNI=cloudflare-dns.com)\n    5   0.000607    10.0.0.50 → 9.9.9.9      TCP 54 51240 → 853 [SYN] Seq=0 Win=8192 Len=0\n    6   0.000736      9.9.9.9 → 10.0.0.50    TCP 54 853 → 51240 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0\n    7   0.000856    10.0.0.50 → 9.9.9.9      TCP 54 51240 → 853 [ACK] Seq=1 Ack=1 Win=8192 Len=0\n    8   0.001034    10.0.0.50 → 9.9.9.9      TLSv1 164 Client Hello (SNI=dns.quad9.net)\n'},
    ], 'fallback': 'tshark: доступно `tshark -r doh.pcap` (см. task.md)\n'}},
    toolset=['core', 'grep', 'tshark']))

# ---------------------------------------------------------------- 4. service-enum
SPECS.append(_lab(
    'network-service-enum', 'Практика: энумерация SMB и анонимный LDAP',
    ['task.md'],
    ['Начни с версий: `nmap -sV -p 445,3389,389,88,135,1433,5985 10.10.10.10`.',
     'Через null-сессию перечисли пользователей методом RID-brute: `nxc smb 10.10.10.10 -u \'\' -p \'\' --rid-brute`.',
     'Обрати внимание на учётку `svc_backup` — это сервисный аккаунт.',
     'Анонимный бинд LDAP отдаёт атрибут `description`: `ldapsearch -x -H ldap://10.10.10.10 -b "dc=corp,dc=local"` — там флаг.'],
    "grep -q 'nto{' answer.txt",
    f'{WD}/answer.txt', 'nto{ld4p_4n0n_b1nd_svc_backup}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Задача: глубокая энумерация сервисов\n\n'
        'Хост `10.10.10.10` — контроллер домена `corp.local`. Без пароля выжми максимум.\n\n'
        '1. Версии сервисов: `nmap -sV -p 445,3389,389,88,135,1433,5985 10.10.10.10`\n'
        '2. SMB null-сессия и RID-brute (перебор числовых SID):\n'
        '   `nxc smb 10.10.10.10 -u \'\' -p \'\' --rid-brute`\n'
        '3. Найди сервисный аккаунт (имя начинается с `svc_`).\n'
        '4. Анонимный бинд LDAP отдаёт описания: `ldapsearch -x -H ldap://10.10.10.10 -b "dc=corp,dc=local"`\n'
        '5. Запиши флаг `nto{...}` из атрибута `description` в `answer.txt` и набери `check`.\n')],
    tools={
        'nmap': {'help': 'nmap [опции] <цель> — сканирование (эмуляция: вывод захвачен с реального nmap)', 'cases': [
            {'match': r'-sV',
             'example': '-sV -p 445,3389,389,88,135,1433,5985 10.10.10.10',
             'output': 'Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-13 14:02 MSK\nNmap scan report for 10.10.10.10\nHost is up (0.0011s latency).\n\nPORT     STATE SERVICE       VERSION\n88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-10-13 11:02:15Z)\n135/tcp  open  msrpc         Microsoft Windows RPC\n389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: corp.local, Site: Default-First-Site-Name)\n445/tcp  open  microsoft-ds  Windows Server 2019 Standard 17763 microsoft-ds (workgroup: CORP)\n1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00\n3389/tcp open  ms-wbt-server Microsoft Terminal Services\n5985/tcp open  wsman         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)\n\nService Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows\n\nNmap done: 1 IP address (1 host up) scanned in 6.31 seconds\n'},
        ], 'fallback': 'nmap: доступно `nmap -sV -p 445,3389,389,88,135,1433,5985 10.10.10.10` (см. task.md)\n'},
        'nxc': {'help': "nxc smb <цель> -u '' -p '' [--shares|--rid-brute] — энумерация SMB (эмуляция)", 'cases': [
            {'match': r'rid-brute',
             'example': "-u '' -p '' --rid-brute",
             'output': 'SMB         10.10.10.10     445    DC01             [*] Windows Server 2019 Build 17763 (name:DC01) (domain:corp.local) (signing:False) (SMBv1:None)\nSMB         10.10.10.10     445    DC01             [+] corp.local\\: \nSMB         10.10.10.10     445    DC01             1103: CORP\\alice (SidTypeUser)\nSMB         10.10.10.10     445    DC01             1104: CORP\\bob (SidTypeUser)\nSMB         10.10.10.10     445    DC01             1105: CORP\\svc_backup (SidTypeUser)\n'},
            {'match': r'--shares',
             'example': "-u '' -p '' --shares",
             'output': 'SMB         10.10.10.10     445    DC01             [*] Windows Server 2019 Build 17763 (name:DC01) (domain:corp.local) (signing:False) (SMBv1:None)\nSMB         10.10.10.10     445    DC01             [*] Enumerated shares\nSMB         10.10.10.10     445    DC01             Share     Permissions  Remark\nSMB         10.10.10.10     445    DC01             -----     -----------  ------\nSMB         10.10.10.10     445    DC01             NETLOGON  READ         Logon server share\nSMB         10.10.10.10     445    DC01             SYSVOL    READ         Logon server share\n'},
        ], 'fallback': "nxc: доступно `nxc smb 10.10.10.10 -u '' -p '' --rid-brute` (см. task.md)\n"},
        'ldapsearch': {'help': 'ldapsearch -x -H ldap://<хост> -b <база> — LDAP-поиск (эмуляция)', 'cases': [
            {'match': r'ldap',
             'example': '-x -H ldap://10.10.10.10 -b "dc=corp,dc=local"',
             'output': '# extended LDIF\n#\n# LDAPv3\n# base <dc=corp,dc=local> with scope subtree\n# filter: (objectClass=*)\n# requesting: ALL\n#\n\n# svc_backup, Users, corp.local\ndn: CN=svc_backup,CN=Users,DC=corp,DC=local\ncn: svc_backup\nsAMAccountName: svc_backup\ndescription: service account - nto{ld4p_4n0n_b1nd_svc_backup}\nmemberOf: CN=Backup Operators,CN=Builtin,DC=corp,DC=local\n\n# search result\nsearch: 2\nresult: 0 Success\n\n# numResponses: 2\n# numEntries: 1\n'},
        ], 'fallback': 'ldapsearch: доступно `ldapsearch -x -H ldap://10.10.10.10 -b "dc=corp,dc=local"` (см. task.md)\n'},
    },
    toolset=['core', 'grep', 'nmap', 'nxc', 'ldapsearch']))

# ---------------------------------------------------------------- 5. ssh-tunnel
SPECS.append(_lab(
    'network-ssh-tunnel', 'Практика: локальный форвард (-L)',
    ['task.md'],
    ['Внутренний сервис `10.0.0.5:8080` виден только с bastion. Локальный форвард: `-L lport:host:port`.',
     'Подними туннель: `ssh -N -L 8080:10.0.0.5:8080 analyst@bastion`.',
     'Проверь, что порт слушает: `ss -ltnp`.',
     'Теперь цель доступна локально — `curl http://127.0.0.1:8080/`; в странице флаг.'],
    "grep -q 'nto{' answer.txt",
    f'{WD}/answer.txt', 'nto{ssh_L_f0rw4rd_p1v0t}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Задача: локальный SSH-форвард\n\n'
        'Bastion `203.0.113.10` — единственная точка входа. Внутренний сервис\n'
        '`10.0.0.5:8080` доступен только с bastion, напрямую — нет.\n\n'
        '1. Подними локальный форвард:\n'
        '   `ssh -N -L 8080:10.0.0.5:8080 analyst@bastion`\n'
        '2. Убедись, что порт слушает: `ss -ltnp`\n'
        '3. Обратись к цели через туннель: `curl http://127.0.0.1:8080/`\n'
        '4. Запиши флаг `nto{...}` из ответа в `answer.txt` и набери `check`.\n'),
     _f(f'{WD}/bastion.txt',
        'bastion  203.0.113.10  port 22  user: analyst (key auth)\n'
        'internal service: 10.0.0.5:8080 (only reachable from bastion)\n')],
    tools={
        'ssh': {'help': 'ssh [-N] [-L lport:host:port] user@host — SSH-клиент (эмуляция)', 'cases': [
            {'match': r'-L',
             'example': '-N -L 8080:10.0.0.5:8080 analyst@bastion',
             'output': "Warning: Permanently added 'bastion,203.0.113.10' (ED25519) to the list of known hosts.\n"},
        ], 'fallback': 'ssh: доступно `ssh -N -L 8080:10.0.0.5:8080 analyst@bastion` (см. task.md)\n'},
        'ss': {'help': 'ss -ltnp — список слушающих TCP-сокетов (эмуляция)', 'cases': [
            {'match': r'ltnp',
             'example': '-ltnp',
             'output': 'State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\ntcp    LISTEN 0      128        127.0.0.1:8080      0.0.0.0:*     users:(("ssh",pid=4821,fd=5))\n'},
        ], 'fallback': 'ss: доступно `ss -ltnp` (см. task.md)\n'},
        'curl': {'help': 'curl <url> — HTTP-клиент (эмуляция: вывод захвачен с реального curl)', 'cases': [
            {'match': r'10\.0\.0\.5:8080',
             'example': 'http://10.0.0.5:8080/',
             'output': "curl: (7) Failed to connect to 10.0.0.5 port 8080 after 0 ms: Couldn't connect to server\n", 'code': 7},
            {'match': r'127\.0\.0\.1:8080',
             'example': 'http://127.0.0.1:8080/',
             'output': '<!DOCTYPE html>\n<html><head><title>internal inventory</title></head>\n<body><h1>Inventory service</h1>\n<p>Deploy token: nto{ssh_L_f0rw4rd_p1v0t}</p></body></html>\n'},
        ], 'fallback': 'curl: доступно `curl http://127.0.0.1:8080/` (см. task.md)\n'},
    },
    toolset=['core', 'grep', 'ssh', 'curl']))

# ---------------------------------------------------------------- 6. socks-http-connect
SPECS.append(_lab(
    'network-socks-http-connect', 'Практика: pivoting через SOCKS5',
    ['task.md', 'socks5-greeting.bin'],
    ['На foothold поднят динамический SOCKS-прокси `ssh -D 1080`: локально слушает `127.0.0.1:1080`.',
     'Посмотри приветствие сервера в hex: `xxd socks5-greeting.bin` — версия и метод (без аутентификации).',
     'Инструменты, «не понимающие» SOCKS, лезут напрямую. Проксируй через `curl --socks5`.',
     '`curl --socks5 127.0.0.1:1080 http://intranet.corp.local/` — в ответе флаг.'],
    "grep -q 'nto{' answer.txt",
    f'{WD}/answer.txt', 'nto{s0cks5_pr0xy_p1v0t}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Задача: pivoting через SOCKS5-прокси\n\n'
        'На foothold `10.10.10.50` поднят динамический порт: `ssh -D 1080 -N -f user@10.10.10.50`.\n'
        'Локально слушает `127.0.0.1:1080`, за ним видна внутренняя сеть.\n\n'
        '1. Разбери приветствие SOCKS5-сервера (файл `socks5-greeting.bin`):\n'
        '   `xxd socks5-greeting.bin`  — байты `05 00`: версия 5, метод 0 (без аутентификации)\n'
        '2. Инструменты, не понимающие SOCKS, лезут в сеть напрямую — проксируй их через curl:\n'
        '   `curl --socks5 127.0.0.1:1080 http://intranet.corp.local/`\n'
        '3. Запиши флаг `nto{...}` из ответа в `answer.txt` и набери `check`.\n'),
     {'path': f'{WD}/socks5-greeting.bin', 'b64': base64.b64encode(bytes([0x05, 0x00])).decode(), 'mode': '644'}],
    tools={
        'curl': {'help': 'curl [--socks5 host:port | -x proxy] <url> — HTTP-клиент (эмуляция)', 'cases': [
            {'match': r'socks5',
             'example': '--socks5 127.0.0.1:1080 http://intranet.corp.local/',
             'output': '<!DOCTYPE html>\n<html><head><title>intranet</title></head>\n<body><h1>intranet.corp.local</h1>\n<p>pivot ok: nto{s0cks5_pr0xy_p1v0t}</p></body></html>\n'},
            {'match': r'-x\s',
             'example': '-x http://proxy.corp.local:3128 http://intranet.corp.local/',
             'output': 'HTTP/1.1 200 Connection established\n\n<!DOCTYPE html>\n<html><body><h1>intranet</h1><p>ok</p></body></html>\n'},
            {'match': r'intranet\.corp\.local',
             'example': 'http://intranet.corp.local/',
             'output': 'curl: (6) Could not resolve host: intranet.corp.local\n', 'code': 6},
        ], 'fallback': 'curl: доступно `curl --socks5 127.0.0.1:1080 http://intranet.corp.local/` (см. task.md)\n'},
        'nc': {'help': 'nc -w1 <host> <port> — TCP-клиент (эмуляция)', 'cases': [
            {'match': r'1080',
             'example': '-w1 127.0.0.1 1080',
             'output': '05 00\n'},
        ], 'fallback': 'nc: доступно `nc -w1 127.0.0.1 1080` (см. task.md)\n'},
    },
    toolset=['core', 'grep', 'curl', 'nc']))

# ---------------------------------------------------------------- 7. proxy-cdn-waf
SPECS.append(_lab(
    'network-proxy-cdn-waf', 'Практика: обход CDN и поиск origin',
    ['task.md', 'dns-history.txt'],
    ['Сайт `shop.example.com` отдаёт заголовок `server: cloudflare` — значит, отвечает reverse-прокси, а не origin.',
     'Прямое сканирование домена попадёт в CDN. Нужен настоящий IP origin.',
     'История DNS (`dns-history.txt`) хранит старые A-записи — найди в ней адрес origin.',
     'Обратись к origin напрямую, подставив Host через `--resolve`: `curl --resolve shop.example.com:443:198.51.100.77 https://shop.example.com/` — в ответе флаг.'],
    "grep -q 'nto{' answer.txt",
    f'{WD}/answer.txt', 'nto{cdn_byp4ss_0r1g1n_f0und}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Задача: найти origin за CDN и обойти его\n\n'
        'Сайт `shop.example.com` стоит за Cloudflare — прямой запрос попадает в CDN.\n'
        'Нужно найти настоящий IP origin и обратиться к нему, подставив `Host`.\n\n'
        '1. Заголовки через CDN: `curl -sI https://shop.example.com` — увидишь `server: cloudflare`.\n'
        '2. В `dns-history.txt` лежит история A-записей — найди старый адрес origin.\n'
        '3. Обратись к origin напрямую (SNI + Host = домен):\n'
        '   `curl --resolve shop.example.com:443:198.51.100.77 https://shop.example.com/`\n'
        '4. Запиши флаг `nto{...}` из ответа origin в `answer.txt` и набери `check`.\n'),
     _f(f'{WD}/dns-history.txt',
        '2026-02-11  shop.example.com  A  198.51.100.77   # direct origin (pre-CDN)\n'
        '2026-03-02  shop.example.com  A  104.18.32.7     # cloudflare\n'
        '2026-04-19  shop.example.com  A  104.18.33.7     # cloudflare\n'
        '2026-07-01  shop.example.com  CNAME  shop.cdn-edge.net\n'
        'note: origin kept its cert + vhost; Host header still routes there\n')],
    tools={
        'curl': {'help': 'curl [-sI | --resolve host:port:ip] <url> — HTTP-клиент (эмуляция)', 'cases': [
            {'match': r'--resolve',
             'example': '--resolve shop.example.com:443:198.51.100.77 https://shop.example.com/',
             'output': '<!DOCTYPE html>\n<html><head><title>shop origin</title></head>\n<body><h1>shop.example.com (origin)</h1>\n<p>x-origin-direct: 198.51.100.77</p>\n<p>debug: nto{cdn_byp4ss_0r1g1n_f0und}</p></body></html>\n'},
            {'match': r'\-I|--head',
             'example': '-sI https://shop.example.com',
             'output': 'HTTP/2 200 \ndate: Tue, 13 Oct 2026 15:13:08 GMT\ncontent-type: text/html; charset=utf-8\nserver: cloudflare\nlast-modified: Fri, 09 Oct 2026 20:18:28 GMT\nage: 3\ncf-cache-status: HIT\ncf-ray: a49f49591f64ec67-DME\nalt-svc: h3=":443"; ma=86400\n\n'},
            {'match': r'shop\.example\.com',
             'example': 'https://shop.example.com/',
             'output': 'HTTP/2 200 \nserver: cloudflare\ncf-cache-status: HIT\n\n<!DOCTYPE html><html><body><h1>shop</h1></body></html>\n'},
        ], 'fallback': 'curl: доступно `curl -sI https://shop.example.com` (см. task.md)\n'},
    },
    toolset=['core', 'grep', 'curl']))

# ---------------------------------------------------------------- 8. firewall-evasion
SPECS.append(_lab(
    'network-firewall-evasion', 'Практика: обход egress-фильтра фрагментацией',
    ['task.md'],
    ['Egress разрешает только DNS и HTTPS. ACK-скан покажет, фильтрует ли ACL порт.',
     '`nmap -sA -Pn -p445 10.10.20.5` — `unfiltered` значит ACL порт не дропает (фильтр stateless).',
     'Простая фрагментация `nmap -f --mtu 8 -p445` не проходит; попробуй источник порта 53 и выравнивание данных: `nmap --data-length 200 -g 53 -Pn -p445,8080 10.10.20.5`.',
     'Когда порт 8080 покажется `open`, обратись к внутреннему сервису: `curl http://10.10.20.5:8080/` — в ответе флаг.'],
    "grep -q 'nto{' answer.txt",
    f'{WD}/answer.txt', 'nto{fr4g_byp4ss_3gr3ss}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Задача: обойти egress-фильтр\n\n'
        'Из сегмента DMZ наружу разрешены только DNS (UDP/53) и HTTPS (TCP/443).\n'
        'Внутренний сервис `10.10.20.5:8080` фильтром закрыт.\n\n'
        '1. ACK-скан покажет, фильтрует ли ACL порт (не устанавливая соединение):\n'
        '   `nmap -sA -Pn -p445 10.10.20.5`\n'
        '2. Простая фрагментация: `nmap -f --mtu 8 -g 53 -Pn -p445 10.10.20.5`\n'
        '3. Выровненные данные + исходный порт 53 обходят stateless-фильтр:\n'
        '   `nmap --data-length 200 -g 53 -Pn -p445,8080 10.10.20.5`\n'
        '4. Обратись к открытому сервису: `curl http://10.10.20.5:8080/` — флаг.\n'
        '5. Запиши флаг `nto{...}` в `answer.txt` и набери `check`.\n')],
    tools={
        'nmap': {'help': 'nmap [опции] <цель> — сканирование (эмуляция: вывод захвачен с реального nmap)', 'cases': [
            {'match': r'data-length',
             'example': '--data-length 200 -g 53 -Pn -p445,8080 10.10.20.5',
             'output': 'Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-13 14:20 MSK\nNmap scan report for 10.10.20.5\nHost is up (0.00087s latency).\n\nPORT     STATE SERVICE\n445/tcp  open  microsoft-ds\n8080/tcp open  http-proxy\n\nNmap done: 1 IP address (1 host up) scanned in 3.44 seconds\n'},
            {'match': r'\-sA',
             'example': '-sA -Pn -p445 10.10.20.5',
             'output': 'Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-13 14:18 MSK\nNmap scan report for 10.10.20.5\nHost is up (0.00091s latency).\n\nPORT    STATE      SERVICE\n445/tcp unfiltered microsoft-ds\n\nNmap done: 1 IP address (1 host up) scanned in 2.11 seconds\n'},
            {'match': r'\s\-f\b|--mtu',
             'example': '-f --mtu 8 -g 53 -Pn -p445 10.10.20.5',
             'output': 'Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-13 14:19 MSK\nNmap scan report for 10.10.20.5\nHost is up (0.00093s latency).\n\nPORT    STATE    SERVICE\n445/tcp filtered microsoft-ds\n\nNmap done: 1 IP address (1 host up) scanned in 3.02 seconds\n'},
        ], 'fallback': 'nmap: доступно `nmap -sA -Pn -p445 10.10.20.5` (см. task.md)\n'},
        'curl': {'help': 'curl <url> — HTTP-клиент (эмуляция)', 'cases': [
            {'match': r'10\.10\.20\.5:8080',
             'example': 'http://10.10.20.5:8080/',
             'output': '<!DOCTYPE html>\n<html><head><title>internal filestore</title></head>\n<body><h1>fileserver</h1>\n<p>bypass ok: nto{fr4g_byp4ss_3gr3ss}</p></body></html>\n'},
        ], 'fallback': 'curl: доступно `curl http://10.10.20.5:8080/` (см. task.md)\n'},
    },
    toolset=['core', 'grep', 'nmap', 'curl']))

# ---------------------------------------------------------------- 9. tls-fingerprint
SPECS.append(_lab(
    'network-tls-fingerprint', 'Практика: сопоставление JA3 с threat-intel',
    ['task.md', 'tls.pcap', 'ja3-intel.txt'],
    ['В дампе `tls.pcap` два клиента устанавливают TLS. Посмотри сводку: `tshark -r tls.pcap`.',
     'Вытащи SNI и отпечаток JA3 каждого ClientHello:\n`tshark -r tls.pcap -Y tls.handshake.extensions_server_name -T fields -e ip.src -e tls.handshake.extensions_server_name -e tls.handshake.ja3`.',
     'Один SNI (`cdn.malware-c2.example`) и его JA3 подозрительны.',
     'Сопоставь JA3 с `ja3-intel.txt` (`grep 5d24a8 ja3-intel.txt`) — там имя малвари и флаг.'],
    "grep -q 'nto{' answer.txt",
    f'{WD}/answer.txt', 'nto{ja3_c2_b34c0n_m4tch}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Задача: найти клиента малвари по JA3\n\n'
        'Трафик зашифрован, но отпечаток ClientHello (JA3) выдаёт клиента.\n'
        'В `tls.pcap` два клиента; один — легитимный, второй — подозрительный.\n\n'
        '1. Сводка: `tshark -r tls.pcap`\n'
        '2. SNI + JA3: `tshark -r tls.pcap -Y tls.handshake.extensions_server_name -T fields -e ip.src -e tls.handshake.extensions_server_name -e tls.handshake.ja3`\n'
        '3. Сопоставь JA3 подозрительного клиента с базой: `grep 5d24a8 ja3-intel.txt`\n'
        '4. Запиши флаг `nto{...}` из найденной записи в `answer.txt` и набери `check`.\n'),
     _b(WD, 'tls.pcap'),
     _f(f'{WD}/ja3-intel.txt',
        '# JA3 threat-intel feed (hash  app / family  note)\n'
        'b8aa7ac25d577266a6fd60b20472ab87  curl-8.5.0       benign (scripted HTTP client)\n'
        '5d24a88aada509974de98eb86e24ee57  CobaltStrike-beacon  C2 malleable profile  nto{ja3_c2_b34c0n_m4tch}\n'
        'e7d705a3286e19ea42f587b344ee6865  Tor-client       benign (privacy tool)\n')],
    tools={'tshark': {'help': TSHARK_HELP, 'cases': [
        {'match': r'ja3|server_name|tls\.handshake',
         'example': '-r tls.pcap -Y tls.handshake.extensions_server_name -T fields -e ip.src -e tls.handshake.extensions_server_name -e tls.handshake.ja3',
         'output': '10.0.0.5\texample.com\tb8aa7ac25d577266a6fd60b20472ab87\n10.0.0.9\tcdn.malware-c2.example\t5d24a88aada509974de98eb86e24ee57\n'},
        {'match': r'tls\.pcap',
         'example': '-r tls.pcap',
         'output': '    1   0.000000     10.0.0.5 → 93.184.216.34 TCP 54 51234 → 443 [SYN] Seq=0 Win=8192 Len=0\n    2   0.000139 93.184.216.34 → 10.0.0.5     TCP 54 443 → 51234 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0\n    3   0.000265     10.0.0.5 → 93.184.216.34 TCP 54 51234 → 443 [ACK] Seq=1 Ack=1 Win=8192 Len=0\n    4   0.000397     10.0.0.5 → 93.184.216.34 TLSv1 166 Client Hello (SNI=example.com)\n    5   0.000607     10.0.0.9 → 198.51.100.20 TCP 54 51500 → 443 [SYN] Seq=0 Win=8192 Len=0\n    6   0.000736 198.51.100.20 → 10.0.0.9     TCP 54 443 → 51500 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0\n    7   0.000856     10.0.0.9 → 198.51.100.20 TCP 54 51500 → 443 [ACK] Seq=1 Ack=1 Win=8192 Len=0\n    8   0.000990     10.0.0.9 → 198.51.100.20 TLSv1 169 Client Hello (SNI=cdn.malware-c2.example)\n'},
    ], 'fallback': 'tshark: доступно `tshark -r tls.pcap` (см. task.md)\n'}},
    toolset=['core', 'grep', 'tshark']))

# ---------------------------------------------------------------- 10. telnet-rservices
SPECS.append(_lab(
    'network-telnet-rservices', 'Практика: перехват Telnet-сессии',
    ['task.md', 'telnet.pcap'],
    ['Telnet не шифрует: всё, включая пароль, идёт открытым текстом.',
     'Сначала видно фазу IAC (управляющие байты `ff fd ...`) — `tshark -r telnet.pcap`.',
     'Собери TCP-поток целиком: `tshark -r telnet.pcap -q -z follow,tcp,ascii,0`.',
     'В потоке — логин, пароль и вывод `cat /flag.txt` с флагом.'],
    "grep -q 'nto{' answer.txt",
    f'{WD}/answer.txt', 'nto{t3ln3t_cl3rt3xt_l34k}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Задача: перехват Telnet-сессии\n\n'
        'Хост `10.0.0.9` держит открытым порт 23 (Telnet). В `telnet.pcap` — сессия входа.\n\n'
        '1. Сводка (видна фаза IAC): `tshark -r telnet.pcap`\n'
        '2. Собери поток целиком: `tshark -r telnet.pcap -q -z follow,tcp,ascii,0`\n'
        '3. В потоке — логин, пароль и вывод `cat /flag.txt`.\n'
        '4. Запиши флаг `nto{...}` в `answer.txt` и набери `check`.\n'),
     _b(WD, 'telnet.pcap')],
    tools={'tshark': {'help': TSHARK_HELP, 'cases': [
        {'match': r'follow',
         'example': '-r telnet.pcap -q -z follow,tcp,ascii,0',
         'output': '\n===================================================================\nFollow: tcp,ascii\nFilter: tcp.stream eq 0\nNode 0: 10.0.0.5:49200\nNode 1: 10.0.0.9:23\n12\n..... ..#..\'\n\t7\nlogin: \n7\nadmin\n\n\t10\nPassword: \n11\nadm1nP@ss\n\n\t46\n$ cat /flag.txt\nnto{t3ln3t_cl3rt3xt_l34k}\n$ \n===================================================================\n'},
        {'match': r'telnet\.pcap',
         'example': '-r telnet.pcap',
         'output': '    1   0.000000     10.0.0.5 → 10.0.0.9     TCP 54 49200 → 23 [SYN] Seq=0 Win=8192 Len=0\n    2   0.000143     10.0.0.9 → 10.0.0.5     TCP 54 23 → 49200 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0\n    3   0.000278     10.0.0.5 → 10.0.0.9     TCP 54 49200 → 23 [ACK] Seq=1 Ack=1 Win=8192 Len=0\n    4   0.000401     10.0.0.5 → 10.0.0.9     TELNET 66 Do Terminal Type, Do Terminal Speed, Do X Display Location, Do New Environment Option\n    5   0.000603     10.0.0.9 → 10.0.0.5     TELNET 61 7 bytes data\n    6   0.000819     10.0.0.5 → 10.0.0.9     TELNET 61 7 bytes data\n    7   0.001012     10.0.0.9 → 10.0.0.5     TELNET 64 10 bytes data\n    8   0.001228     10.0.0.5 → 10.0.0.9     TELNET 65 11 bytes data\n    9   0.001472     10.0.0.9 → 10.0.0.5     TELNET 100 46 bytes data\n'},
    ], 'fallback': 'tshark: доступно `tshark -r telnet.pcap` (см. task.md)\n'}},
    toolset=['core', 'grep', 'tshark']))

# ---------------------------------------------------------------- 11. nfs
SPECS.append(_lab(
    'network-nfs', 'Практика: перечисление NFS-экспортов',
    ['task.md', 'exports'],
    ['RPC/NFS: порт 111 (`rpcbind`) подсказывает порт NFS; порт 2049 — сам NFS.',
     'Список экспортов даёт `showmount`: `showmount -e 10.0.0.20`.',
     'Экспорт со звёздочкой (`*`) разрешён ВСЕМ — это и есть ошибка администрирования.',
     'В `exports/` уже примонтированы оба экспорта; прочитай флаг из того, что открыт всем: `cat exports/srv_export/flag.txt`.'],
    "grep -q 'nto{' answer.txt",
    f'{WD}/answer.txt', 'nto{nfs_n0_r00t_squ4sh_0wn3d}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Задача: NFS-экспорты\n\n'
        'На хосте `10.0.0.20` открыты `111` (rpcbind) и `2049` (NFS).\n'
        'Два экспорта уже примонтированы в каталог `exports/`.\n\n'
        '1. Список экспортов: `showmount -e 10.0.0.20`\n'
        '2. Экспорт, разрешённый всем (`*`), — главная ошибка. Определи, какой это каталог.\n'
        '3. Прочитай флаг из соответствующего примонтированного каталога:\n'
        '   `cat exports/srv_export/flag.txt`\n'
        '4. Запиши флаг `nto{...}` в `answer.txt` и набери `check`.\n'),
     _dir(f'{WD}/exports'),
     _f(f'{WD}/exports/var_backups/notes.txt', 'backup rotations for 10.0.0.0/24 hosts\naccess: restricted\n'),
     _f(f'{WD}/exports/srv_export/flag.txt', 'nto{nfs_n0_r00t_squ4sh_0wn3d}\n'),
     _f(f'{WD}/exports/srv_export/README', 'world-readable export (/srv/export)\n')],
    tools={
        'showmount': {'help': 'showmount -e <хост> — список NFS-экспортов (эмуляция)', 'cases': [
            {'match': r'-e',
             'example': '-e 10.0.0.20',
             'output': 'Export list for 10.0.0.20:\n/srv/export  *\n/var/backups 10.0.0.0/24\n'},
        ], 'fallback': 'showmount: доступно `showmount -e 10.0.0.20` (см. task.md)\n'},
        'rpcinfo': {'help': 'rpcinfo -p <хост> — зарегистрированные RPC-программы (эмуляция)', 'cases': [
            {'match': r'-p',
             'example': '-p 10.0.0.20',
             'output': '   program vers proto   port  service\n    100000    4   tcp    111  portmapper\n    100000    4   udp    111  portmapper\n    100003    3   tcp   2049  nfs\n    100003    4   tcp   2049  nfs\n    100005    1   udp  20048  mountd\n    100005    3   tcp  20048  mountd\n'},
        ], 'fallback': 'rpcinfo: доступно `rpcinfo -p 10.0.0.20` (см. task.md)\n'},
    },
    toolset=['core', 'grep', 'showmount', 'rpcinfo']))

# ---------------------------------------------------------------- 12. wpad-proxy
SPECS.append(_lab(
    'network-wpad-proxy', 'Практика: WPAD/LLMNR-перехват',
    ['task.md', 'wpad.pcap'],
    ['Ноутбук ищет WPAD-файл: DHCP-опцию 252 сервер не отдал, поэтому идёт LLMNR-запрос имени `wpad`.',
     'Ответил не легитимный сервер: `tshark -r wpad.pcap -Y llmnr -T fields -e ip.src -e ip.dst -e dns.qry.name -e dns.a`.',
     'Кто ответил на LLMNR — тот и атакующий. Клиент скачивает у него `wpad.dat` (PAC-файл).',
     'PAC — исполняемый JS; собери поток: `tshark -r wpad.pcap -q -z follow,tcp,ascii,0` — в комментарии флаг.'],
    "grep -q 'nto{' answer.txt",
    f'{WD}/answer.txt', 'nto{wpad_p4c_m1tm_pr0xy}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Задача: WPAD через LLMNR-перехват\n\n'
        'Ноутбук `10.0.0.5` ищет настройки прокси (WPAD). DHCP-опцию 252 сервер\n'
        'не отдал, поэтому клиент ушёл в LLMNR за именем `wpad`.\n\n'
        '1. Сводка: `tshark -r wpad.pcap`\n'
        '2. LLMNR-обмен: `tshark -r wpad.pcap -Y llmnr -T fields -e ip.src -e ip.dst -e dns.qry.name -e dns.a`\n'
        '   — ответил адрес, которого в легитимной сети быть не должно (атакующий).\n'
        '3. Клиент скачал у него `wpad.dat` (PAC). Собери поток: `tshark -r wpad.pcap -q -z follow,tcp,ascii,0`\n'
        '4. В комментарии PAC-файла — флаг. Запиши его в `answer.txt` и набери `check`.\n'),
     _b(WD, 'wpad.pcap')],
    tools={'tshark': {'help': TSHARK_HELP, 'cases': [
        {'match': r'follow',
         'example': '-r wpad.pcap -q -z follow,tcp,ascii,0',
         'output': '\n===================================================================\nFollow: tcp,ascii\nFilter: tcp.stream eq 0\nNode 0: 10.0.0.5:49300\nNode 1: 10.0.0.66:8080\n92\nGET /wpad.dat HTTP/1.1\nHost: wpad.corp.local\nUser-Agent: WinHttp-Autoproxy-Service/5.1\n\n\n\t293\nHTTP/1.1 200 OK\nServer: Microsoft-IIS/10.0\nContent-Type: application/x-ns-proxy-autoconfig\nContent-Length: 176\n\nfunction FindProxyForURL(url, host) {\n  if (shExpMatch(host, "*.corp.local")) return "DIRECT";\n  // exfil key: nto{wpad_p4c_m1tm_pr0xy}\n  return "PROXY 10.0.0.66:8080";\n}\n\n===================================================================\n'},
        {'match': r'llmnr',
         'example': '-r wpad.pcap -Y llmnr -T fields -e ip.src -e ip.dst -e dns.qry.name -e dns.a',
         'output': '10.0.0.5\t224.0.0.252\twpad\t\n10.0.0.66\t10.0.0.5\twpad\t10.0.0.66\n'},
        {'match': r'wpad\.pcap',
         'example': '-r wpad.pcap',
         'output': '    1   0.000000      0.0.0.0 → 255.255.255.255 BOOTP 50 DHCP Discover\n    2   0.000222     10.0.0.5 → 224.0.0.252  LLMNR 64 Standard query 0x0000 A wpad\n    3   0.000551    10.0.0.66 → 10.0.0.5     LLMNR 84 Standard query response 0x0000 A wpad A 10.0.0.66\n    4   0.000866     10.0.0.5 → 10.0.0.66    HTTP 146 GET /wpad.dat HTTP/1.1 \n    5   0.001088    10.0.0.66 → 10.0.0.5     HTTP 347 HTTP/1.1 200 OK  (application/x-ns-proxy-autoconfig)\n'},
    ], 'fallback': 'tshark: доступно `tshark -r wpad.pcap` (см. task.md)\n'}},
    toolset=['core', 'grep', 'tshark']))
