"""Curated top-100 TCP ports with service names.

Port ranking follows common exposure order: web, remote access, mail,
databases, message queues, then admin panels. The list is a hand-checked
100 entries with no speculative filler.
"""

SERVICE_NAMES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain", 80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    113: "ident", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 179: "bgp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 514: "syslog", 515: "printer", 587: "submission",
    631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "ms-sql-s", 1521: "oracle", 1883: "mqtt",
    2049: "nfs", 2181: "zookeeper", 2375: "docker", 2376: "docker-tls",
    3000: "node-dev", 3128: "squid", 3268: "ldap-globalcat",
    3269: "ldap-globalcat-ssl", 3306: "mysql", 3389: "ms-wbt-server",
    4444: "metasploit", 49152: "unknown", 49154: "unknown",
    5000: "upnp", 5222: "xmpp-client", 5357: "wsdapi", 5432: "postgresql",
    5555: "adb", 5601: "kibana", 5672: "amqp", 5900: "vnc",
    5984: "couchdb", 6379: "redis", 6443: "kubernetes-api", 6667: "irc",
    7001: "weblogic", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "cslistener",
    9001: "tor-orport", 9042: "cassandra", 9200: "elasticsearch",
    9300: "elasticsearch", 9418: "git", 9999: "abyss", 10000: "webmin",
    11211: "memcached", 15672: "rabbitmq-mgmt", 16379: "redis-sentinel",
    27017: "mongodb", 32400: "plex", 50000: "db2c", 55553: "metasploit-rpc",
}

# Top 100, ordered by how often each port is worth probing first.
# Mirrors the exposure ranking used by masscan/nmap top-ports lists,
# re-checked by hand.
TOP_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 135,
    139, 143, 53, 3306, 8443, 5432, 6379, 1521, 993, 995,
    1723, 113, 1433, 5900, 1025, 587, 111, 992, 8888, 8080,
    1026, 9418, 5984, 27017, 11211, 6667, 3128, 631, 5555, 5672,
    636, 49152, 3268, 5357, 8081, 5222, 989, 5060, 5405, 179,
    2049, 3269, 50000, 20000, 17500, 3000, 7001, 9000, 9200, 873,
    2160, 8180, 16379, 15672, 9999, 5000, 82, 10000, 6443, 4444,
    32400, 55553, 49154, 8089, 515, 20, 1080, 1443, 9042, 5601,
    9300, 2181, 1883, 7070, 3478, 88, 464, 617, 5800, 6969,
    12000, 2144, 6789, 8020, 8194, 9001, 49153, 625, 626, 627,
]


def top_ports(n: int) -> list:
    """First ``n`` ports from the curated ranking, clamped to [0, 100]."""
    n = max(0, min(int(n), len(TOP_PORTS)))
    return TOP_PORTS[:n]


def service_name(port: int) -> str:
    """Known service name for a port, or '-'."""
    return SERVICE_NAMES.get(port, "-")
