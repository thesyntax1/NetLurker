package dev.netlurker.android.core

/**
 * Port knowledge tables, ported verbatim from the desktop build (src/netmon.cpp).
 *
 * They are kept as plain tables rather than a remote feed on purpose: the verdicts must
 * be reproducible offline, and a rule set that changes without the user knowing is not
 * evidence.
 */
object Ports {

    /** Well-known service names — used for the "service" column and to spot unknown ports. */
    val knownServices: Map<Int, String> = linkedMapOf(
        7 to "ECHO", 19 to "CHARGEN", 20 to "FTP-DATA", 21 to "FTP", 22 to "SSH", 23 to "TELNET",
        25 to "SMTP", 37 to "TIME", 42 to "WINS", 43 to "WHOIS", 49 to "TACACS", 53 to "DNS",
        67 to "DHCP", 68 to "DHCP", 69 to "TFTP", 70 to "GOPHER", 79 to "FINGER", 80 to "HTTP",
        81 to "HTTP-ALT", 88 to "KERBEROS", 102 to "MS-EXCHANGE", 110 to "POP3", 111 to "RPCBIND",
        113 to "IDENT", 119 to "NNTP", 123 to "NTP", 135 to "MS-RPC", 137 to "NETBIOS-NS",
        138 to "NETBIOS-DGM", 139 to "NETBIOS-SSN", 143 to "IMAP", 161 to "SNMP", 162 to "SNMP-TRAP",
        177 to "XDMCP", 179 to "BGP", 194 to "IRC", 389 to "LDAP", 427 to "SLP", 443 to "HTTPS",
        445 to "SMB", 464 to "KERBEROS", 465 to "SMTPS", 500 to "IKE/IPSEC", 502 to "MODBUS",
        514 to "SYSLOG", 515 to "LPD", 520 to "RIP", 523 to "IBM-DB2", 548 to "AFP", 554 to "RTSP",
        587 to "SMTP-SUB", 593 to "RPC-HTTP", 623 to "IPMI", 631 to "IPP", 636 to "LDAPS",
        664 to "IPMI", 853 to "DNS-over-TLS", 873 to "RSYNC", 902 to "VMWARE", 989 to "FTPS",
        990 to "FTPS", 993 to "IMAPS", 995 to "POP3S", 1080 to "SOCKS", 1194 to "OpenVPN",
        1234 to "VLC/STREAM", 1241 to "NESSUS", 1352 to "LOTUS", 1433 to "MSSQL", 1434 to "MSSQL-M",
        1521 to "ORACLE", 1701 to "L2TP", 1723 to "PPTP", 1755 to "MMS", 1812 to "RADIUS",
        1883 to "MQTT", 1900 to "SSDP/UPnP", 2049 to "NFS", 2082 to "CPANEL", 2083 to "CPANEL-SSL",
        2086 to "WHM", 2181 to "ZOOKEEPER", 2375 to "DOCKER", 2376 to "DOCKER-TLS", 2379 to "ETCD",
        2483 to "ORACLE", 2967 to "SYMANTEC-AV", 3000 to "DEV-HTTP", 3074 to "XBOX-LIVE",
        3128 to "SQUID-PROXY", 3268 to "GLOBAL-CATALOG", 3283 to "APPLE-ARD", 3306 to "MYSQL",
        3389 to "RDP", 3478 to "STUN/TURN", 3479 to "PSN", 3690 to "SVN", 4000 to "ICQ/DEV",
        4070 to "SPOTIFY", 4500 to "IPSEC-NAT", 4505 to "SALTSTACK", 4506 to "SALTSTACK",
        5000 to "UPnP/DEV", 5001 to "IPERF", 5004 to "RTP", 5060 to "SIP", 5061 to "SIP-TLS",
        5222 to "XMPP", 5223 to "APPLE-PUSH", 5228 to "GOOGLE-PLAY", 5349 to "TURNS",
        5353 to "mDNS", 5355 to "LLMNR", 5432 to "POSTGRESQL", 5601 to "KIBANA", 5672 to "AMQP",
        5683 to "CoAP", 5900 to "VNC", 5938 to "TeamViewer", 5985 to "WinRM", 5986 to "WinRM-SSL",
        6000 to "X11", 6379 to "REDIS", 6443 to "KUBERNETES", 6881 to "BITTORRENT",
        6882 to "BITTORRENT", 6969 to "BT-TRACKER", 7070 to "REALSERVER", 7680 to "WIN-UPDATE-P2P",
        8000 to "HTTP-ALT", 8006 to "PROXMOX", 8008 to "HTTP-ALT", 8080 to "HTTP-PROXY",
        8081 to "HTTP-ALT", 8086 to "INFLUXDB", 8123 to "HOME-ASSISTANT", 8443 to "HTTPS-ALT",
        8883 to "MQTTS", 8888 to "HTTP-ALT", 9000 to "HTTP-ALT", 9090 to "PROMETHEUS",
        9100 to "JETDIRECT", 9200 to "ELASTICSEARCH", 9418 to "GIT", 10000 to "WEBMIN",
        11211 to "MEMCACHED", 15672 to "RABBITMQ", 19132 to "MINECRAFT-BE", 25565 to "MINECRAFT",
        27015 to "STEAM/SRCDS", 27017 to "MONGODB", 27036 to "STEAM-P2P", 32400 to "PLEX",
        33434 to "TRACEROUTE", 47001 to "WinRM-HTTP", 49152 to "DYNAMIC-RPC", 50000 to "SAP",
        51820 to "WIREGUARD", 62078 to "iPHONE-SYNC"
    )

    /** port to (score, reason). Reasons are translation keys resolved by [Reasons]. */
    val suspicious: Map<Int, Pair<Int, String>> = linkedMapOf(
        23 to (40 to "Telnet - unencrypted remote access"),
        25 to (20 to "Direct SMTP - possible spam/bot indicator"),
        69 to (30 to "TFTP - unauthenticated file transfer (loader malware)"),
        135 to (25 to "MS-RPC exposed to the internet - lateral movement risk"),
        139 to (30 to "NetBIOS exposed to the internet"),
        445 to (45 to "SMB exposed to the internet - EternalBlue/ransomware vector"),
        1080 to (30 to "SOCKS proxy tunnel"),
        1337 to (70 to "1337 - classic backdoor port"),
        1604 to (45 to "1604 - DarkComet RAT"),
        2222 to (15 to "Alternate SSH"),
        3128 to (20 to "Egress through an open proxy"),
        3333 to (45 to "3333 - crypto mining pool"),
        3389 to (35 to "RDP exposed to the internet - brute-force target"),
        4444 to (75 to "4444 - Metasploit/Meterpreter default port"),
        4445 to (65 to "4445 - frequently a reverse shell"),
        4782 to (65 to "4782 - Quasar RAT"),
        5554 to (60 to "5554 - Sasser worm"),
        5555 to (40 to "5555 - ADB / mining / RAT"),
        5900 to (30 to "VNC - possibly unencrypted remote desktop"),
        6666 to (60 to "6666 - IRC botnet command channel"),
        6667 to (60 to "6667 - IRC (botnet C2)"),
        6668 to (60 to "6668 - IRC botnet C2"),
        6669 to (60 to "6669 - IRC botnet C2"),
        7777 to (45 to "7777 - mining pool / RAT"),
        8333 to (25 to "8333 - Bitcoin node"),
        9001 to (45 to "9001 - Tor OR port"),
        9030 to (40 to "9030 - Tor directory port"),
        9050 to (45 to "9050 - Tor SOCKS proxy"),
        9051 to (45 to "9051 - Tor control port"),
        12345 to (70 to "12345 - NetBus trojan"),
        12346 to (70 to "12346 - NetBus trojan"),
        14444 to (45 to "14444 - Monero mining pool"),
        20034 to (70 to "20034 - NetBus Pro"),
        27374 to (70 to "27374 - SubSeven trojan"),
        31337 to (80 to "31337 - Back Orifice / 'elite' backdoor"),
        45700 to (45 to "45700 - Monero mining pool"),
        54321 to (55 to "54321 - BackOrifice2000 / School Bus")
    )

    /** Ports that are only alarming when they face the internet. */
    private val internetFacingOnly = setOf(445, 3389, 135, 139, 5900)

    fun serviceName(port: Int): String? = knownServices[port]

    fun threatNote(port: Int): String? = suspicious[port]?.second

    /** Desktop rule: some entries only count when the socket is internet facing. */
    fun isInternetFacingOnly(port: Int): Boolean = internetFacingOnly.contains(port)
}
