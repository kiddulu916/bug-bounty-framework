"""
Plugin Configuration

This module provides centralized configuration and shared resources for all plugins.
Plugins should never create their own lists or configurations - they should use this module instead.

## Usage

```python
from bbf.plugins.config import (
    get_wordlist,
    get_ports,
    get_services,
    get_technologies,
    get_vulnerabilities,
    get_headers,
    get_user_agents
)
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional

logger = logging.getLogger(__name__)

# Base paths
BASE_DIR = Path(__file__).parent.parent
WORDLISTS_DIR = BASE_DIR / "wordlists"
CONFIG_DIR = BASE_DIR / "config"

# Ensure directories exist
WORDLISTS_DIR.mkdir(exist_ok=True)
CONFIG_DIR.mkdir(exist_ok=True)

# Wordlist paths
SUBDOMAIN_WORDLIST = WORDLISTS_DIR / "SecLists/Discovery/DNS/subdomains-top1million-110000.txt"
DIRECTORY_WORDLIST = WORDLISTS_DIR / "SecLists/Discovery/Web-Content/raft-large-directories.txt"
PASSWORD_WORDLIST = WORDLISTS_DIR / "SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
USERNAME_WORDLIST = WORDLISTS_DIR / "SecLists/Usernames/top-usernames-shortlist.txt"
EXTENSION_WORDLIST = WORDLISTS_DIR / "SecLists/Discovery/Web-Content/raft-small-extensions-lowercase.txt"

# Configuration files
PORTS_CONFIG = CONFIG_DIR / "ports.json"
SERVICES_CONFIG = CONFIG_DIR / "services.json"
TECHNOLOGIES_CONFIG = CONFIG_DIR / "technologies.json"
VULNERABILITIES_CONFIG = CONFIG_DIR / "vulnerabilities.json"
HEADERS_CONFIG = CONFIG_DIR / "headers.json"
USER_AGENTS_CONFIG = CONFIG_DIR / "user_agents.json"

# Cache for loaded configurations
_config_cache: Dict[str, any] = {}

def _load_json_config(config_path: Path) -> dict:
    """Load and cache JSON configuration file."""
    if config_path.name in _config_cache:
        return _config_cache[config_path.name]
    
    try:
        if not config_path.exists():
            logger.warning(f"Configuration file not found: {config_path}")
            return {}
        
        with open(config_path) as f:
            config = json.load(f)
            _config_cache[config_path.name] = config
            return config
    except Exception as e:
        logger.error(f"Error loading configuration {config_path}: {str(e)}")
        return {}

def get_wordlist(wordlist_type: str) -> List[str]:
    """
    Get a wordlist by type.
    
    Args:
        wordlist_type: One of 'subdomain', 'directory', 'password', 'username'
    
    Returns:
        List of words from the wordlist
    """
    wordlist_map = {
        'subdomain': SUBDOMAIN_WORDLIST,
        'directory': DIRECTORY_WORDLIST,
        'password': PASSWORD_WORDLIST,
        'username': USERNAME_WORDLIST,
        'extensions': EXTENSION_WORDLIST
    }
    
    if wordlist_type not in wordlist_map:
        raise ValueError(f"Unknown wordlist type: {wordlist_type}")
    
    wordlist_path = wordlist_map[wordlist_type]
    try:
        if not wordlist_path.exists():
            logger.warning(f"Wordlist not found: {wordlist_path}")
            return []
        
        with open(wordlist_path) as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Error loading wordlist {wordlist_path}: {str(e)}")
        return []

def get_ports() -> Dict[str, List[int]]:
    """
    Get port configurations.
    
    Returns:
        Dictionary mapping port categories to lists of port numbers
        Example: {'web': [80, 443], 'database': [3306, 5432]}
    """
    return _load_json_config(PORTS_CONFIG)

def get_services() -> Dict[int, Dict[str, str]]:
    """
    Get service configurations.
    
    Returns:
        Dictionary mapping port numbers to service information
        Example: {80: {'name': 'http', 'description': 'HTTP'}}
    """
    return _load_json_config(SERVICES_CONFIG)

def get_technologies() -> Dict[str, Dict[str, any]]:
    """
    Get technology detection patterns.
    
    Returns:
        Dictionary mapping technology names to detection patterns
        Example: {'nginx': {'headers': ['Server: nginx'], 'html': ['<meta name="generator" content="nginx">']}}
    """
    return _load_json_config(TECHNOLOGIES_CONFIG)

def get_vulnerabilities() -> Dict[str, Dict[str, any]]:
    """
    Get vulnerability detection patterns.
    
    Returns:
        Dictionary mapping vulnerability types to detection patterns
        Example: {'sql_injection': {'patterns': ['SQL syntax'], 'severity': 'high'}}
    """
    return _load_json_config(VULNERABILITIES_CONFIG)

def get_headers() -> Dict[str, List[str]]:
    """
    Get HTTP header configurations.
    
    Returns:
        Dictionary mapping header categories to lists of headers
        Example: {'security': ['X-Frame-Options', 'Content-Security-Policy']}
    """
    return _load_json_config(HEADERS_CONFIG)

def get_user_agents() -> List[str]:
    """
    Get list of user agent strings.
    
    Returns:
        List of user agent strings for HTTP requests
    """
    return _load_json_config(USER_AGENTS_CONFIG).get('user_agents', [])

# Default configurations if files don't exist
DEFAULT_PORTS = {
    # Web Services
    'web': [
        80, 443, 8080, 8443,  # Standard HTTP/HTTPS
        8000, 8008, 8888,     # Alternative HTTP
        3000, 3001,           # Node.js, React
        5000, 5001,           # Flask, Django
        7000, 7001,           # Development servers
        9000, 9001            # Alternative web ports
    ],
    
    # Database Services
    'database': [
        1433, 1434,           # Microsoft SQL Server
        3306,                 # MySQL
        5432,                 # PostgreSQL
        27017, 27018,        # MongoDB
        6379,                 # Redis
        9200, 9300,          # Elasticsearch
        11211,                # Memcached
        5000,                 # CouchDB
        5984,                 # CouchDB HTTP
        8086,                 # InfluxDB
        9042,                 # Cassandra
        2181,                 # ZooKeeper
        9092                  # Kafka
    ],
    
    # Mail Services
    'mail': [
        25,                   # SMTP
        110,                  # POP3
        143,                  # IMAP
        465,                  # SMTPS
        587,                  # Submission
        993,                  # IMAPS
        995,                  # POP3S
        2525,                 # Alternative SMTP
        4190                  # Sieve
    ],
    
    # DNS Services
    'dns': [
        53,                   # DNS
        853,                  # DNS over TLS
        5353,                 # mDNS
        5355                  # LLMNR
    ],
    
    # File Transfer
    'ftp': [
        20, 21,              # FTP
        22,                   # SFTP
        69,                   # TFTP
        115,                  # SFTP
        989, 990,            # FTPS
        2049                  # NFS
    ],
    
    # Remote Access
    'remote': [
        22,                   # SSH
        23,                   # Telnet
        3389,                # RDP
        5900, 5901,          # VNC
        5631,                # pcAnywhere
        5000,                # VNC
        5800, 5801,          # VNC over HTTP
        8888                  # Alternative RDP
    ],
    
    # VPN Services
    'vpn': [
        1194,                # OpenVPN
        1723,                # PPTP
        500,                 # ISAKMP
        4500,                # NAT-T
        1701,                # L2TP
        1812, 1813,         # RADIUS
        500, 4500           # IKE
    ],
    
    # Management & Monitoring
    'management': [
        161, 162,            # SNMP
        514,                 # Syslog
        123,                 # NTP
        161, 162,            # SNMP
        199,                 # SNMP-TRAP
        5666,                # Nagios
        9090,                # Prometheus
        9100,                # Node Exporter
        3000,                # Grafana
        8080, 8081,          # Management Consoles
        8443                 # Secure Management
    ],
    
    # Cloud & Container
    'cloud': [
        2375, 2376,          # Docker
        2377, 2378,          # Docker Swarm
        4243,                # Docker Registry
        5000,                # Docker Registry
        6443,                # Kubernetes API
        10250,               # Kubelet
        10251,               # Kube-scheduler
        10252,               # Kube-controller
        10255,               # Kubelet Read-only
        10256                # Kube-proxy
    ],
    
    # Security & Authentication
    'security': [
        389, 636,            # LDAP/LDAPS
        1812, 1813,         # RADIUS
        2082, 2083,         # cPanel
        2086, 2087,         # WHM
        2222,                # DirectAdmin
        10000,               # Webmin
        8443                 # Plesk
    ],
    
    # Common Services (Most frequently used)
    'common': [
        21, 22, 23,          # FTP, SSH, Telnet
        25, 53,              # SMTP, DNS
        80, 443,             # HTTP, HTTPS
        110, 143,            # POP3, IMAP
        161, 162,            # SNMP
        389, 636,            # LDAP/LDAPS
        445,                 # SMB
        465, 587,            # SMTPS, Submission
        993, 995,            # IMAPS, POP3S
        1433, 1434,          # MSSQL
        1521,                # Oracle
        1723,                # PPTP
        2049,                # NFS
        3306,                # MySQL
        3389,                # RDP
        5432,                # PostgreSQL
        5900,                # VNC
        6379,                # Redis
        8080, 8443,          # Alternative HTTP/HTTPS
        27017                # MongoDB
    ]
}

DEFAULT_SERVICES = {
    # Web Services
    80: {'name': 'http', 'description': 'HTTP', 'category': 'web'},
    443: {'name': 'https', 'description': 'HTTPS', 'category': 'web'},
    8080: {'name': 'http-alt', 'description': 'Alternative HTTP', 'category': 'web'},
    8443: {'name': 'https-alt', 'description': 'Alternative HTTPS', 'category': 'web'},
    8000: {'name': 'http-alt', 'description': 'Alternative HTTP', 'category': 'web'},
    8008: {'name': 'http-alt', 'description': 'Alternative HTTP', 'category': 'web'},
    8888: {'name': 'http-alt', 'description': 'Alternative HTTP', 'category': 'web'},
    3000: {'name': 'http-alt', 'description': 'Node.js/React', 'category': 'web'},
    5000: {'name': 'http-alt', 'description': 'Flask/Django', 'category': 'web'},
    
    # Database Services
    1433: {'name': 'mssql', 'description': 'Microsoft SQL Server', 'category': 'database'},
    1434: {'name': 'mssql-udp', 'description': 'Microsoft SQL Server UDP', 'category': 'database'},
    3306: {'name': 'mysql', 'description': 'MySQL', 'category': 'database'},
    5432: {'name': 'postgresql', 'description': 'PostgreSQL', 'category': 'database'},
    27017: {'name': 'mongodb', 'description': 'MongoDB', 'category': 'database'},
    6379: {'name': 'redis', 'description': 'Redis', 'category': 'database'},
    9200: {'name': 'elasticsearch', 'description': 'Elasticsearch HTTP', 'category': 'database'},
    9300: {'name': 'elasticsearch', 'description': 'Elasticsearch Transport', 'category': 'database'},
    11211: {'name': 'memcached', 'description': 'Memcached', 'category': 'database'},
    5000: {'name': 'couchdb', 'description': 'CouchDB', 'category': 'database'},
    5984: {'name': 'couchdb-http', 'description': 'CouchDB HTTP', 'category': 'database'},
    8086: {'name': 'influxdb', 'description': 'InfluxDB', 'category': 'database'},
    9042: {'name': 'cassandra', 'description': 'Cassandra', 'category': 'database'},
    2181: {'name': 'zookeeper', 'description': 'ZooKeeper', 'category': 'database'},
    9092: {'name': 'kafka', 'description': 'Kafka', 'category': 'database'},
    
    # Mail Services
    25: {'name': 'smtp', 'description': 'SMTP', 'category': 'mail'},
    110: {'name': 'pop3', 'description': 'POP3', 'category': 'mail'},
    143: {'name': 'imap', 'description': 'IMAP', 'category': 'mail'},
    465: {'name': 'smtps', 'description': 'SMTPS', 'category': 'mail'},
    587: {'name': 'submission', 'description': 'SMTP Submission', 'category': 'mail'},
    993: {'name': 'imaps', 'description': 'IMAPS', 'category': 'mail'},
    995: {'name': 'pop3s', 'description': 'POP3S', 'category': 'mail'},
    2525: {'name': 'smtp-alt', 'description': 'Alternative SMTP', 'category': 'mail'},
    4190: {'name': 'sieve', 'description': 'Sieve', 'category': 'mail'},
    
    # DNS Services
    53: {'name': 'dns', 'description': 'DNS', 'category': 'dns'},
    853: {'name': 'dns-over-tls', 'description': 'DNS over TLS', 'category': 'dns'},
    5353: {'name': 'mdns', 'description': 'Multicast DNS', 'category': 'dns'},
    5355: {'name': 'llmnr', 'description': 'Link-Local Multicast Name Resolution', 'category': 'dns'},
    
    # File Transfer
    20: {'name': 'ftp-data', 'description': 'FTP Data', 'category': 'ftp'},
    21: {'name': 'ftp', 'description': 'FTP Control', 'category': 'ftp'},
    22: {'name': 'ssh', 'description': 'SSH/SFTP', 'category': 'ftp'},
    69: {'name': 'tftp', 'description': 'TFTP', 'category': 'ftp'},
    115: {'name': 'sftp', 'description': 'SFTP', 'category': 'ftp'},
    989: {'name': 'ftps-data', 'description': 'FTPS Data', 'category': 'ftp'},
    990: {'name': 'ftps', 'description': 'FTPS Control', 'category': 'ftp'},
    2049: {'name': 'nfs', 'description': 'Network File System', 'category': 'ftp'},
    
    # Remote Access
    23: {'name': 'telnet', 'description': 'Telnet', 'category': 'remote'},
    3389: {'name': 'rdp', 'description': 'Remote Desktop Protocol', 'category': 'remote'},
    5900: {'name': 'vnc', 'description': 'VNC', 'category': 'remote'},
    5901: {'name': 'vnc-1', 'description': 'VNC Display 1', 'category': 'remote'},
    5631: {'name': 'pcanywhere', 'description': 'pcAnywhere', 'category': 'remote'},
    5800: {'name': 'vnc-http', 'description': 'VNC over HTTP', 'category': 'remote'},
    5801: {'name': 'vnc-http-1', 'description': 'VNC over HTTP Display 1', 'category': 'remote'},
    8888: {'name': 'rdp-alt', 'description': 'Alternative RDP', 'category': 'remote'},
    
    # VPN Services
    1194: {'name': 'openvpn', 'description': 'OpenVPN', 'category': 'vpn'},
    1723: {'name': 'pptp', 'description': 'PPTP', 'category': 'vpn'},
    500: {'name': 'isakmp', 'description': 'ISAKMP', 'category': 'vpn'},
    4500: {'name': 'ipsec-nat-t', 'description': 'IPsec NAT-Traversal', 'category': 'vpn'},
    1701: {'name': 'l2tp', 'description': 'L2TP', 'category': 'vpn'},
    1812: {'name': 'radius', 'description': 'RADIUS Authentication', 'category': 'vpn'},
    1813: {'name': 'radius-acct', 'description': 'RADIUS Accounting', 'category': 'vpn'},
    
    # Management & Monitoring
    161: {'name': 'snmp', 'description': 'SNMP', 'category': 'management'},
    162: {'name': 'snmptrap', 'description': 'SNMP Trap', 'category': 'management'},
    514: {'name': 'syslog', 'description': 'Syslog', 'category': 'management'},
    123: {'name': 'ntp', 'description': 'Network Time Protocol', 'category': 'management'},
    199: {'name': 'snmptrap', 'description': 'SNMP Trap', 'category': 'management'},
    5666: {'name': 'nagios', 'description': 'Nagios', 'category': 'management'},
    9090: {'name': 'prometheus', 'description': 'Prometheus', 'category': 'management'},
    9100: {'name': 'node-exporter', 'description': 'Node Exporter', 'category': 'management'},
    3000: {'name': 'grafana', 'description': 'Grafana', 'category': 'management'},
    
    # Cloud & Container
    2375: {'name': 'docker', 'description': 'Docker', 'category': 'cloud'},
    2376: {'name': 'docker-tls', 'description': 'Docker TLS', 'category': 'cloud'},
    2377: {'name': 'docker-swarm', 'description': 'Docker Swarm', 'category': 'cloud'},
    2378: {'name': 'docker-swarm-tls', 'description': 'Docker Swarm TLS', 'category': 'cloud'},
    4243: {'name': 'docker-registry', 'description': 'Docker Registry', 'category': 'cloud'},
    5000: {'name': 'docker-registry', 'description': 'Docker Registry', 'category': 'cloud'},
    6443: {'name': 'kubernetes', 'description': 'Kubernetes API', 'category': 'cloud'},
    10250: {'name': 'kubelet', 'description': 'Kubelet', 'category': 'cloud'},
    10251: {'name': 'kube-scheduler', 'description': 'Kube-scheduler', 'category': 'cloud'},
    10252: {'name': 'kube-controller', 'description': 'Kube-controller', 'category': 'cloud'},
    10255: {'name': 'kubelet-readonly', 'description': 'Kubelet Read-only', 'category': 'cloud'},
    10256: {'name': 'kube-proxy', 'description': 'Kube-proxy', 'category': 'cloud'},
    
    # Security & Authentication
    389: {'name': 'ldap', 'description': 'LDAP', 'category': 'security'},
    636: {'name': 'ldaps', 'description': 'LDAPS', 'category': 'security'},
    2082: {'name': 'cpanel', 'description': 'cPanel', 'category': 'security'},
    2083: {'name': 'cpanel-ssl', 'description': 'cPanel SSL', 'category': 'security'},
    2086: {'name': 'whm', 'description': 'Web Host Manager', 'category': 'security'},
    2087: {'name': 'whm-ssl', 'description': 'Web Host Manager SSL', 'category': 'security'},
    2222: {'name': 'directadmin', 'description': 'DirectAdmin', 'category': 'security'},
    10000: {'name': 'webmin', 'description': 'Webmin', 'category': 'security'},
    8443: {'name': 'plesk', 'description': 'Plesk', 'category': 'security'}
}

# Create default configuration files if they don't exist
def _create_default_configs():
    """Create default configuration files if they don't exist."""
    if not PORTS_CONFIG.exists():
        with open(PORTS_CONFIG, 'w') as f:
            json.dump(DEFAULT_PORTS, f, indent=2)
    
    if not SERVICES_CONFIG.exists():
        with open(SERVICES_CONFIG, 'w') as f:
            json.dump(DEFAULT_SERVICES, f, indent=2)
    
    if not USER_AGENTS_CONFIG.exists():
        default_user_agents = {
            'user_agents': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            ]
        }
        with open(USER_AGENTS_CONFIG, 'w') as f:
            json.dump(default_user_agents, f, indent=2)

# Create default configurations on module import
_create_default_configs() 