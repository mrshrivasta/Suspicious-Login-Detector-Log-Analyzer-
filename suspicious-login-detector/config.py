import os
from pathlib import Path
from typing import List, Dict, Any

class Config:
    # File paths
    LOG_DIR = Path("sample_logs")
    OUTPUT_DIR = Path("output")
    GEO_DB_PATH = "GeoLite2-City.mmdb"  # Download from MaxMind
    
    # Log patterns
    APACHE_LOG_PATTERN = (
        r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d{3}) '
        r'(?P<size>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    )
    
    NGINX_LOG_PATTERN = (
        r'^(?P<ip>\S+) - \S+ \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d{3}) '
        r'(?P<size>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    )
    
    # Detection thresholds
    THRESHOLDS = {
        'failed_logins_per_ip': 5,
        'failed_logins_per_minute': 10,
        'requests_per_minute': 100,
        'unique_ips_per_minute': 50,
        'suspicious_user_agents': 3,
        'non_standard_ports': True
    }
    
    # Suspicious paths (login endpoints)
    LOGIN_PATHS = [
        '/login', '/admin/login', '/wp-login.php', '/phpmyadmin',
        '/auth', '/signin', '/logon', '/wp-admin', '/administrator'
    ]
    
    # Suspicious user agents
    SUSPICIOUS_UA_PATTERNS = [
        'scanner', 'nikto', 'sqlmap', 'nessus', 'nmap',
        'curl', 'wget', 'python-requests', 'gobuster', 'dirb'
    ]
    
    @classmethod
    def setup_dirs(cls):
        """Create necessary directories"""
        cls.OUTPUT_DIR.mkdir(exist_ok=True)