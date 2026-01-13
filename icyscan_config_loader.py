#!/usr/bin/env python3
"""
IcyScan Configuration Loader
Loads and validates configuration from icyscan_config.yaml
"""

import os
import yaml
from typing import Dict, Any, List


class IcyScanConfig:
    """Configuration manager for IcyScan"""
    
    DEFAULT_CONFIG_PATHS = [
        "./icyscan_config.yaml",
        "~/.config/icyscan/config.yaml",
        "/etc/icyscan/config.yaml"
    ]
    
    def __init__(self, config_path: str = None):
        """Initialize configuration"""
        self.config_path = config_path or self._find_config()
        self.config = self._load_config()
    
    def _find_config(self) -> str:
        """Find configuration file in default locations"""
        for path in self.DEFAULT_CONFIG_PATHS:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                return expanded_path
        
        # Return default path if not found (will create default config)
        return self.DEFAULT_CONFIG_PATHS[0]
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        if not os.path.exists(self.config_path):
            print(f"[!] Config file not found: {self.config_path}")
            print(f"[*] Using default configuration")
            return self._default_config()
        
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            print(f"[+] Loaded configuration from: {self.config_path}")
            return config
        except Exception as e:
            print(f"[!] Error loading config: {e}")
            print(f"[*] Using default configuration")
            return self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration if file not found"""
        return {
            "global": {
                "threads": 5,
                "timeout": 600,
                "output_base": "Scans"
            },
            "nmap": {
                "quick_scan": {"enabled": True},
                "service_scan": {"enabled": True},
                "full_scan": {"enabled": True, "background": True}
            },
            "subdomains": {
                "ffuf": {"enabled": True},
                "gobuster": {"enabled": True}
            },
            "ftp": {"enabled": True},
            "smb": {"enabled": True},
            "ldap": {"enabled": True},
            "nikto": {"enabled": True},
            "feroxbuster": {"enabled": True},
            "exploits": {"enabled": True}
        }
    
    # ============================================================
    # GETTER METHODS
    # ============================================================
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-notation key"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            
            if value is None:
                return default
        
        return value
    
    def get_threads(self) -> int:
        """Get number of threads"""
        return self.get("global.threads", 5)
    
    def get_timeout(self) -> int:
        """Get default timeout"""
        return self.get("global.timeout", 600)
    
    def is_enabled(self, tool: str) -> bool:
        """Check if a tool is enabled"""
        return self.get(f"{tool}.enabled", True)
    
    # ============================================================
    # NMAP CONFIGURATION
    # ============================================================
    
    def get_nmap_quick_flags(self) -> str:
        """Get Nmap quick scan flags"""
        return self.get("nmap.quick_scan.flags", "-T4 -F")
    
    def get_nmap_service_flags(self) -> str:
        """Get Nmap service scan flags"""
        return self.get("nmap.service_scan.flags", "-sV -sC -T4")
    
    def get_nmap_full_flags(self) -> str:
        """Get Nmap full scan flags"""
        return self.get("nmap.full_scan.flags", "-sV -sC -T4 -p-")
    
    def nmap_full_background(self) -> bool:
        """Check if full scan should run in background"""
        return self.get("nmap.full_scan.background", True)
    
    # ============================================================
    # SUBDOMAIN ENUMERATION
    # ============================================================
    
    def get_subdomain_wordlists(self) -> List[str]:
        """Get subdomain wordlists"""
        return self.get("subdomains.ffuf.wordlists", [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/wordlists/dirb/common.txt"
        ])
    
    def get_ffuf_threads(self) -> int:
        """Get ffuf thread count"""
        return self.get("subdomains.ffuf.threads", 50)
    
    def get_ffuf_match_codes(self) -> List[int]:
        """Get ffuf match codes"""
        return self.get("subdomains.ffuf.match_codes", [200, 204, 301, 302, 307, 401, 403])
    
    # ============================================================
    # FTP CONFIGURATION
    # ============================================================
    
    def get_ftp_anonymous_usernames(self) -> List[str]:
        """Get FTP anonymous usernames to try"""
        return self.get("ftp.anonymous.usernames", ["anonymous", "ftp"])
    
    def get_ftp_anonymous_passwords(self) -> List[str]:
        """Get FTP anonymous passwords to try"""
        return self.get("ftp.anonymous.passwords", ["anonymous@", "ftp@", ""])
    
    def get_ftp_max_downloads(self) -> int:
        """Get maximum FTP file downloads"""
        return self.get("ftp.download.max_files", 50)
    
    def get_ftp_max_file_size(self) -> int:
        """Get maximum FTP file size"""
        return self.get("ftp.download.max_file_size", 10485760)
    
    def get_ftp_interesting_extensions(self) -> List[str]:
        """Get FTP interesting file extensions"""
        return self.get("ftp.download.interesting_extensions", [
            ".txt", ".pdf", ".conf", ".config", ".ini", ".xml", ".json",
            ".sh", ".bat", ".ps1", ".py", ".php", ".asp", ".sql", ".db",
            ".bak", ".log", ".key", ".pem"
        ])
    
    # ============================================================
    # SMB/NETEXEC CONFIGURATION
    # ============================================================
    
    def smb_null_session_enabled(self) -> bool:
        """Check if SMB null session enumeration is enabled"""
        return self.get("smb.null_session.enabled", True)
    
    def smb_enumerate_shares(self) -> bool:
        """Check if SMB share enumeration is enabled"""
        return self.get("smb.null_session.enumerate_shares", True)
    
    def smb_enumerate_users(self) -> bool:
        """Check if SMB user enumeration is enabled"""
        return self.get("smb.null_session.enumerate_users", True)
    
    def get_smb_credentials(self) -> List[Dict[str, str]]:
        """Get SMB credentials to try"""
        return self.get("smb.authenticated.credentials", [])
    
    # ============================================================
    # NIKTO CONFIGURATION
    # ============================================================
    
    def get_nikto_timeout(self) -> int:
        """Get Nikto timeout"""
        return self.get("nikto.timeout", 300)
    
    def get_nikto_max_time(self) -> str:
        """Get Nikto max time per target"""
        return self.get("nikto.max_time", "5m")
    
    def get_nikto_max_subdomains(self) -> int:
        """Get maximum subdomains to scan with Nikto"""
        return self.get("nikto.max_subdomains", 10)
    
    def get_web_ports(self) -> List[int]:
        """Get web ports to scan"""
        return self.get("nikto.web_ports", [80, 443, 8080, 8443, 8000, 8888, 3000, 5000])
    
    # ============================================================
    # FEROXBUSTER CONFIGURATION
    # ============================================================
    
    def get_feroxbuster_wordlists(self) -> List[str]:
        """Get feroxbuster wordlists"""
        return self.get("feroxbuster.wordlists", [
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            "/usr/share/wordlists/dirb/common.txt"
        ])
    
    def get_feroxbuster_threads(self) -> int:
        """Get feroxbuster thread count"""
        return self.get("feroxbuster.threads", 50)
    
    def get_feroxbuster_depth(self) -> int:
        """Get feroxbuster depth"""
        return self.get("feroxbuster.depth", 2)
    
    def get_feroxbuster_extensions(self) -> List[str]:
        """Get feroxbuster file extensions"""
        return self.get("feroxbuster.extensions", [])
    
    def get_feroxbuster_interesting_keywords(self) -> List[str]:
        """Get keywords for interesting path detection"""
        return self.get("feroxbuster.interesting_keywords", [
            "admin", "login", "dashboard", "config", "backup", "upload",
            "api", "secret", "private", ".git", ".env", "password"
        ])
    
    # ============================================================
    # CREDENTIALS
    # ============================================================
    
    def get_common_usernames(self) -> List[str]:
        """Get common usernames to try"""
        return self.get("credentials.common_usernames", [
            "admin", "administrator", "root", "user", "test", "guest"
        ])
    
    def get_common_passwords(self) -> List[str]:
        """Get common passwords to try"""
        return self.get("credentials.common_passwords", [
            "", "admin", "password", "Password123!", "123456", "root"
        ])
    
    def get_specific_credentials(self) -> List[Dict[str, str]]:
        """Get specific service credentials"""
        return self.get("credentials.specific", [])


# Example usage
if __name__ == "__main__":
    config = IcyScanConfig()
    
    print("\n=== Configuration Test ===")
    print(f"Threads: {config.get_threads()}")
    print(f"Nmap quick flags: {config.get_nmap_quick_flags()}")
    print(f"FTP max downloads: {config.get_ftp_max_downloads()}")
    print(f"Nikto enabled: {config.is_enabled('nikto')}")
    print(f"Web ports: {config.get_web_ports()}")
