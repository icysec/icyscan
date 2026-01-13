#!/usr/bin/env python3
"""
IcyScan - Advanced Network Enumeration Framework
Version: 1.0
Release: January 2026

A modular framework for automated reconnaissance and enumeration
"""

__version__ = "1.0"
__author__ = "Custom Enumeration Tool"
__release_date__ = "January 2026"

import subprocess
import argparse
import json
import sys
import os
import time
import random
from datetime import datetime
from typing import List, Dict, Optional
import xml.etree.ElementTree as ET
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Try to import tqdm for progress bars, fallback gracefully if not available
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    print("[!] tqdm not installed - progress bars disabled. Install with: pip install tqdm")
    time.sleep(2)


class Colors:
    """ANSI color codes for terminal output"""
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


# Multiple ASCII art banners (randomly selected at startup)
BANNERS = [
    # Banner 1 - Original
    f"""{Colors.CYAN}{Colors.BOLD}
 ██▓ ▄████▄ ▓██   ██▓  ██████  ▄████▄   ▄▄▄       ███▄    █ 
▓██▒▒██▀ ▀█  ▒██  ██▒▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █ 
▒██▒▒▓█    ▄  ▒██ ██░░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒
░██░▒▓▓▄ ▄██▒ ░ ▐██▓░  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒
░██░▒ ▓███▀ ░ ░ ██▒▓░▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░
░▓  ░ ░▒ ▒  ░  ██▒▒▒ ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ 
 ▒ ░  ░  ▒   ▓██ ░▒░ ░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░
 ▒ ░░        ▒ ▒ ░░  ░  ░  ░  ░          ░   ▒      ░   ░ ░ 
 ░  ░ ░      ░ ░           ░  ░ ░            ░  ░         ░ 
    ░        ░ ░              ░                              
{Colors.END}""",

    # Banner 2 - 3D
    rf"""{Colors.CYAN}{Colors.BOLD}
                                                                              ,--. 
   ,---,  ,----..                .--.--.     ,----..     ,---,              ,--.'| 
,`--.' | /   /   \        ,---, /  /    '.  /   /   \   '  .' \         ,--,:  : | 
|   :  :|   :     :      /_ ./||  :  /`. / |   :     : /  ;    '.    ,`--.'`|  ' : 
:   |  '.   |  ;. /,---, |  ' :;  |  |--`  .   |  ;. /:  :       \   |   :  :  | | 
|   :  |.   ; /--`/___/ \.  : ||  :  ;_    .   ; /--` :  |   /\   \  :   |   \ | : 
'   '  ;;   | ;    .  \  \ ,' ' \  \    `. ;   | ;    |  :  ' ;.   : |   : '  '; | 
|   |  ||   : |     \  ;  `  ,'  `----.   \|   : |    |  |  ;/  \   \'   ' ;.    ; 
'   :  ;.   | '___   \  \    '   __ \  \  |.   | '___ '  :  | \  \ ,'|   | | \   | 
|   |  ''   ; : .'|   '  \   |  /  /`--'  /'   ; : .'||  |  '  '--'  '   : |  ; .' 
'   :  |'   | '/  :    \  ;  ; '--'.     / '   | '/  :|  :  :        |   | '`--'   
;   |.' |   :    /      :  \  \  `--'---'  |   :    / |  | ,'        '   : |       
'---'    \   \ .'        \  ' ;             \   \ .'  `--''          ;   |.'       
          `---`           `--`               `---`                   '---'         
{Colors.END}""",

    # Banner 3 - Snowflake
    f"""{Colors.CYAN}{Colors.BOLD}
        ▄█     ▄████████ ▄██   ▄      ▄████████  ▄████████    ▄████████ ███▄▄▄▄   
       ███    ███    ███ ███   ██▄   ███    ███ ███    ███   ███    ███ ███▀▀▀██▄ 
       ███▌   ███    █▀  ███▄▄▄███   ███    █▀  ███    █▀    ███    ███ ███   ███ 
       ███▌   ███        ▀▀▀▀▀▀███   ███        ███          ███    ███ ███   ███ 
       ███▌   ███        ▄██   ███ ▀███████████ ███        ▀███████████ ███   ███ 
       ███    ███    █▄  ███   ███          ███ ███    █▄    ███    ███ ███   ███ 
       ███    ███    ███ ███   ███    ▄█    ███ ███    ███   ███    ███ ███   ███ 
       █▀     ██████████  ▀█████▀   ▄████████▀  ████████▀    ███    █▀   ▀█   █▀  
{Colors.END}""",

    # Banner 4 - Def Leppard
    f"""{Colors.CYAN}{Colors.BOLD}
                                                                       
                                                                       
            .,                   .      .,               L.            
  t        ,Wt                  ;W     ,Wt               EW:        ,ft
  Ej      i#D. f.     ;WE.     f#E    i#D.            .. E##;       t#E
  E#,    f#f   E#,   i#G     .E#f    f#f             ;W, E###t      t#E
  E#t  .D#i    E#t  f#f     iWW;   .D#i             j##, E#fE#f     t#E
  E#t :KW,     E#t G#i     L##Lffi:KW,             G###, E#t D#G    t#E
  E#t t#f      E#jEW,     tLLG##L t#f            :E####, E#t  f#E.  t#E
  E#t  ;#G     E##E.        ,W#i   ;#G          ;W#DG##, E#t   t#K: t#E
  E#t   :KE.   E#G         j#E.     :KE.       j###DW##, E#t    ;#W,t#E
  E#t    .DW:  E#t       .D#j        .DW:     G##i,,G##, E#t     :K#D#E
  E#t      L#, E#t      ,WK,           L#,  :K#K:   L##, E#t      .E##E
  E#t       jt EE.      EG.             jt ;##D.    L##, ..         G#E
  ,;.          t        ,                  ,,,      .,,              fE
                                                                      ,
{Colors.END}""",

    # Banner 5 - Simple Block
    f"""{Colors.CYAN}{Colors.BOLD}
    ██╗ ██████╗██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ██║██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██║██║      ╚████╔╝ ███████╗██║     ███████║██╔██╗ ██║
    ██║██║       ╚██╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║
    ██║╚██████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
    ╚═╝ ╚═════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    ════════════════════════════════════════════════════════
              Network Enumeration Framework v1.0
{Colors.END}""",

    # Banner 6 - x992
    f"""{Colors.CYAN}{Colors.BOLD}
  d8,                                                    
 `8P                                                     
                                                         
  88b d8888b?88   d8P  .d888b, d8888b d888b8b    88bd88b 
  88Pd8P' `Pd88   88   ?8b,   d8P' `Pd8P' ?88    88P' ?8b
 d88 88b    ?8(  d88     `?8b 88b    88b  ,88b  d88   88P
d88' `?888P'`?88P'?8b `?888P' `?888P'`?88P'`88bd88'   88b
                   )88                                   
                  ,d8P                                   
               `?888P'                                   
{Colors.END}""",
]


class IcyScan:
    """Main IcyScan enumeration framework"""
    
    def __init__(self, target: str, output_dir: str = "IcyScan", threads: int = 5):
        self.target = target
        self.output_dir = output_dir
        self.threads = threads
        
        # Thread lock for safe display updates
        self.display_lock = threading.Lock()
        self.results_lock = threading.Lock()
        
        # Progress tracking
        self.progress_bars = {}  # Store active progress bars
        
        # Results storage
        self.results = {
            "target": target,
            "ports": [],
            "services": [],
            "loot": [],
            "vulnerabilities": [],
            "exploits": [],
            "domains": [],
            "subdomains": []
        }
        
        # Create proper directory structure:
        # output_dir/TARGET/
        # ├── Loot/           (credentials, passwords, interesting findings)
        # ├── Exploits/       (exploit files, POCs)
        # └── Logs/           (all scan outputs: nmap, nikto, feroxbuster, etc.)
        self.base_dir = f"{output_dir}/{target}"
        self.loot_dir = f"{self.base_dir}/Loot"
        self.exploits_dir = f"{self.base_dir}/Exploits"
        self.scans_dir = f"{self.base_dir}/Logs"
        
        # Create all directories
        os.makedirs(self.loot_dir, exist_ok=True)
        os.makedirs(self.exploits_dir, exist_ok=True)
        os.makedirs(self.scans_dir, exist_ok=True)
        
        # For backwards compatibility, keep scan_dir pointing to Logs/
        self.scan_dir = self.scans_dir
        
        self.display_banner()
    
    def add_port(self, port_info: Dict):
        """Thread-safe method to add port"""
        with self.results_lock:
            if not any(p['port'] == port_info['port'] for p in self.results['ports']):
                self.results["ports"].append(port_info)
                return True
        return False
    
    def add_service(self, service_info: Dict):
        """Thread-safe method to add service"""
        with self.results_lock:
            if not any(s['port'] == service_info['port'] for s in self.results['services']):
                self.results["services"].append(service_info)
                return True
        return False
    
    def add_loot(self, loot_item: str):
        """Thread-safe method to add loot"""
        with self.results_lock:
            if loot_item not in self.results["loot"]:
                self.results["loot"].append(loot_item)
                return True
        return False
    
    def add_domain(self, domain: str):
        """Thread-safe method to add domain"""
        with self.results_lock:
            if domain not in self.results["domains"]:
                self.results["domains"].append(domain)
                return True
        return False
    
    def add_subdomain(self, subdomain: str):
        """Thread-safe method to add subdomain"""
        with self.results_lock:
            if subdomain not in self.results["subdomains"]:
                self.results["subdomains"].append(subdomain)
                return True
        return False
    
    def is_external_domain(self, domain: str) -> bool:
        """Check if domain is external/third-party (CDN, services, etc.)"""
        # Common CDN and third-party service domains
        external_patterns = [
            # CDNs
            'cloudflare.com', 'cloudfront.net', 'akamaized.net', 'fastly.net',
            'cdn77.com', 'jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',
            
            # Google services
            'googleapis.com', 'googleusercontent.com', 'gstatic.com', 'google.com',
            'youtube.com', 'ytimg.com', 'googlevideo.com',
            
            # JavaScript libraries
            'jquery.com', 'jqueryui.com', 'angularjs.org', 'reactjs.org',
            
            # Social media
            'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
            'pinterest.com', 'reddit.com', 'tiktok.com',
            
            # Analytics
            'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
            'analytics.google.com', 'hotjar.com', 'mixpanel.com',
            
            # Advertising
            'googlesyndication.com', 'adservice.google.com', 'adsense.com',
            
            # Fonts
            'fonts.googleapis.com', 'fonts.gstatic.com', 'typekit.net',
            
            # Other common services
            'amazonaws.com', 'azure.com', 'digitalocean.com', 'heroku.com',
            'github.io', 'wordpress.com', 'wix.com', 'shopify.com',
            'stripe.com', 'paypal.com', 'braintree.com'
        ]
        
        domain_lower = domain.lower()
        
        # Check if domain ends with any external pattern
        for pattern in external_patterns:
            if domain_lower.endswith(pattern):
                return True
        
        # Check if it's a different root domain than target
        # Extract main domain from target
        target_parts = self.target.split('.')
        domain_parts = domain_lower.split('.')
        
        # If domain has different TLD or different main domain, it's external
        if len(domain_parts) >= 2 and len(target_parts) >= 2:
            # Compare last two parts (domain.tld)
            target_root = '.'.join(target_parts[-2:])
            domain_root = '.'.join(domain_parts[-2:])
            
            # Check if target is IP address
            try:
                import ipaddress
                ipaddress.ip_address(self.target)
                # Target is IP, so any domain is external
                return True
            except:
                # Target is domain, compare roots
                if target_root != domain_root:
                    return True
        
        return False
    
    def filter_external_subdomains(self):
        """Remove external/third-party domains from subdomains list"""
        original_count = len(self.results["subdomains"])
        
        # Filter out external domains
        filtered = []
        removed = []
        
        for subdomain in self.results["subdomains"]:
            if self.is_external_domain(subdomain):
                removed.append(subdomain)
                self.log(f"Filtered out external domain: {subdomain}", "INFO")
            else:
                filtered.append(subdomain)
        
        self.results["subdomains"] = filtered
        
        if removed:
            self.log(f"Filtered out {len(removed)} external/third-party domains", "SUCCESS")
            self.log(f"Keeping {len(filtered)} target-related subdomains", "SUCCESS")
            
            # Save filtered domains to a file for reference
            if removed:
                removed_list = "FILTERED EXTERNAL DOMAINS\n"
                removed_list += "="*80 + "\n\n"
                removed_list += "These domains were found but filtered out as external/third-party:\n\n"
                for domain in sorted(removed):
                    removed_list += f"  - {domain}\n"
                
                self.save_results("filtered_external_domains.txt", removed_list)
    
    def create_progress_bar(self, task_name: str, total: int, desc: str = None):
        """Create a progress bar for a task"""
        if not TQDM_AVAILABLE:
            return None
        
        if desc is None:
            desc = task_name
        
        pbar = tqdm(
            total=total,
            desc=f"{Colors.CYAN}{desc}{Colors.END}",
            bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]',
            ncols=80,
            leave=False,
            position=0
        )
        self.progress_bars[task_name] = pbar
        return pbar
    
    def update_progress_bar(self, task_name: str, increment: int = 1):
        """Update progress bar for a task"""
        if task_name in self.progress_bars:
            self.progress_bars[task_name].update(increment)
    
    def close_progress_bar(self, task_name: str):
        """Close and remove a progress bar"""
        if task_name in self.progress_bars:
            self.progress_bars[task_name].close()
            del self.progress_bars[task_name]
            # Print newline to fix display issues
            print()
    
    def display_banner(self):
        """Display IcyScan ASCII banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
 ██▓ ▄████▄ ▓██   ██▓  ██████  ▄████▄   ▄▄▄       ███▄    █ 
▓██▒▒██▀ ▀█  ▒██  ██▒▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █ 
▒██▒▒▓█    ▄  ▒██ ██░░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒
░██░▒▓▓▄ ▄██▒ ░ ▐██▓░  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒
░██░▒ ▓███▀ ░ ░ ██▒▓░▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░
░▓  ░ ░▒ ▒  ░  ██▒▒▒ ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ 
 ▒ ░  ░  ▒   ▓██ ░▒░ ░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░
 ▒ ░░        ▒ ▒ ░░  ░  ░  ░  ░          ░   ▒      ░   ░ ░ 
 ░  ░ ░      ░ ░           ░  ░ ░            ░  ░         ░ 
    ░        ░ ░              ░                              
{Colors.END}
{Colors.BOLD}═══════════════════════════════════════════════════════════════════════════════
                        IcyScan - Network Enumeration Framework
                                    Version {__version__}
                              Target: {Colors.GREEN}{self.target}{Colors.END}
                              Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
═══════════════════════════════════════════════════════════════════════════════{Colors.END}
"""
        print(banner)
        self.display_status()
    
    def display_status(self):
        """Display current scan status with findings (thread-safe)"""
        with self.display_lock:
            # Clear screen
            os.system('clear' if os.name != 'nt' else 'cls')
            
            # Display banner
            print(self.get_banner_only())
            
            # Status display with clean dividers
            print(f"{Colors.BOLD}{'═' * 80}{Colors.END}")
            print(f"{Colors.CYAN}TARGET:{Colors.END}      {self.target}")
            print(f"{Colors.CYAN}BASE DIR:{Colors.END}    {self.base_dir}")
            print(f"{Colors.CYAN}THREADS:{Colors.END}     {self.threads} concurrent tasks")
            print(f"{Colors.BOLD}{'═' * 80}{Colors.END}\n")
        
        # PORTS Section
        print(f"{Colors.BOLD}[ PORTS ]{Colors.END}")
        print(f"{Colors.BOLD}{'─' * 80}{Colors.END}")
        if self.results["ports"]:
            for port in self.results["ports"][:15]:
                port_str = f"{port['port']}/{port['protocol']}"
                service_str = port.get('service', 'unknown')
                if port['state'] == 'open':
                    print(f"  {Colors.GREEN}●{Colors.END} {port_str:<12} {service_str}")
                else:
                    print(f"  {Colors.RED}●{Colors.END} {port_str:<12} {service_str}")
            if len(self.results["ports"]) > 15:
                print(f"  {Colors.YELLOW}... {len(self.results['ports']) - 15} more{Colors.END}")
        else:
            print(f"  {Colors.YELLOW}No ports discovered yet{Colors.END}")
        print()
        
        # SERVICES Section
        print(f"{Colors.BOLD}[ SERVICES ]{Colors.END}")
        print(f"{Colors.BOLD}{'─' * 80}{Colors.END}")
        if self.results["services"]:
            for svc in self.results["services"][:8]:
                port_str = f"Port {svc['port']}"
                svc_str = f"{svc.get('product', '')} {svc.get('version', '')}".strip()
                print(f"  {Colors.CYAN}●{Colors.END} {port_str:<12} {svc_str}")
            if len(self.results["services"]) > 8:
                print(f"  {Colors.YELLOW}... {len(self.results['services']) - 8} more{Colors.END}")
        else:
            print(f"  {Colors.YELLOW}No services enumerated yet{Colors.END}")
        print()
        
        # DOMAINS Section
        print(f"{Colors.BOLD}[ DOMAINS ]{Colors.END}")
        print(f"{Colors.BOLD}{'─' * 80}{Colors.END}")
        if self.results["domains"]:
            for domain in self.results["domains"][:5]:
                print(f"  {Colors.GREEN}●{Colors.END} {domain}")
            if len(self.results["domains"]) > 5:
                print(f"  {Colors.YELLOW}... {len(self.results['domains']) - 5} more{Colors.END}")
        else:
            print(f"  {Colors.YELLOW}No domains discovered yet{Colors.END}")
        print()
        
        # SUBDOMAINS Section
        print(f"{Colors.BOLD}[ SUBDOMAINS ]{Colors.END}")
        print(f"{Colors.BOLD}{'─' * 80}{Colors.END}")
        if self.results["subdomains"]:
            for subdomain in self.results["subdomains"][:8]:
                print(f"  {Colors.GREEN}●{Colors.END} {subdomain}")
            if len(self.results["subdomains"]) > 8:
                print(f"  {Colors.YELLOW}... {len(self.results['subdomains']) - 8} more{Colors.END}")
        else:
            print(f"  {Colors.YELLOW}No subdomains found yet{Colors.END}")
        print()
        
        # EXPLOITS Section
        print(f"{Colors.BOLD}[ EXPLOITS ]{Colors.END}")
        print(f"{Colors.BOLD}{'─' * 80}{Colors.END}")
        if self.results["exploits"]:
            print(f"  {Colors.RED}Found {len(self.results['exploits'])} potential exploits!{Colors.END}")
            for exploit in self.results["exploits"][:5]:
                title = exploit.get('title', 'Unknown')[:70]
                print(f"  {Colors.RED}●{Colors.END} {title}")
            if len(self.results["exploits"]) > 5:
                print(f"  {Colors.YELLOW}... {len(self.results['exploits']) - 5} more{Colors.END}")
        else:
            print(f"  {Colors.YELLOW}No exploits found yet{Colors.END}")
        print()
        
        # LOOT Section
        print(f"{Colors.BOLD}[ LOOT ]{Colors.END}")
        print(f"{Colors.BOLD}{'─' * 80}{Colors.END}")
        if self.results["loot"]:
            for item in self.results["loot"][:10]:
                item_text = item[:70] if len(item) > 70 else item
                print(f"  {Colors.GREEN}●{Colors.END} {item_text}")
            if len(self.results["loot"]) > 10:
                print(f"  {Colors.YELLOW}... {len(self.results['loot']) - 10} more{Colors.END}")
        else:
            print(f"  {Colors.YELLOW}No loot collected yet{Colors.END}")
        
        print(f"\n{Colors.BOLD}{'═' * 80}{Colors.END}\n")
        
        # Force flush to ensure display updates immediately
        sys.stdout.flush()
    
    def get_banner_only(self):
        """Get just the banner without status"""
        # Select random banner
        banner = random.choice(BANNERS)
        return f"""
{banner}
{Colors.BOLD}═══════════════════════════════════════════════════════════════════════════════
                        Custom Enumeration Framework
                              Target: {Colors.GREEN}{self.target}{Colors.END}
═══════════════════════════════════════════════════════════════════════════════{Colors.END}
"""
    
    def log(self, message: str, level: str = "INFO"):
        """Log message and save to file"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        color = Colors.CYAN
        if level == "SUCCESS":
            color = Colors.GREEN
        elif level == "WARNING":
            color = Colors.YELLOW
        elif level == "ERROR":
            color = Colors.RED
        
        log_msg = f"[{timestamp}] [{level}] {message}"
        colored_msg = f"{color}[{timestamp}]{Colors.END} [{level}] {message}"
        
        # Print to console
        print(colored_msg)
        
        # Save to log file
        self.save_log(log_msg)
    
    def save_results(self, filename: str, content: str):
        """Save scan results to file"""
        filepath = f"{self.scan_dir}/{filename}"
        with open(filepath, "w") as f:
            f.write(content)
        return filepath
    
    def save_log(self, message: str):
        """Save to log file"""
        log_file = f"{self.scan_dir}/scan.log"
        with open(log_file, "a") as f:
            f.write(message + "\n")
    
    
    def run_command(self, command: List[str], description: str, timeout: int = 600) -> Dict:
        """Execute a command and return results"""
        self.log(f"Running: {description}", "INFO")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                "command": " ".join(command),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "success": result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out: {description}", "ERROR")
            return {"success": False, "error": "timeout"}
        except FileNotFoundError:
            self.log(f"Tool not found: {command[0]}", "ERROR")
            return {"success": False, "error": "tool_not_found"}
        except Exception as e:
            self.log(f"Error running command: {e}", "ERROR")
            return {"success": False, "error": str(e)}
    
    # ==================== NMAP SCANNING ====================
    
    def nmap_quick_scan(self):
        """Quick Nmap scan of well-known ports"""
        self.log("Starting quick Nmap scan (well-known ports)...", "INFO")
        
        # Create progress bar (100 ports to scan)
        pbar = self.create_progress_bar("nmap_quick", 100, "Quick Scan (Top 100 Ports)")
        
        xml_file = f"{self.scan_dir}/nmap_quick.xml"
        
        # Start Nmap process
        command = [
            "nmap",
            "-T4",
            "-F",  # Fast scan (top 100 ports)
            "-oX", xml_file,
            "-oN", f"{self.scan_dir}/nmap_quick.txt",
            "--stats-every", "2s",  # Update every 2 seconds
            self.target
        ]
        
        # Run command with progress updates
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # Monitor progress
        last_percent = 0
        for line in process.stdout:
            # Look for percentage in nmap output
            if "% done" in line.lower():
                match = re.search(r'(\d+\.?\d*)%', line)
                if match:
                    percent = float(match.group(1))
                    if pbar and percent > last_percent:
                        increment = int(percent - last_percent)
                        self.update_progress_bar("nmap_quick", increment)
                        last_percent = percent
        
        process.wait()
        
        # Complete the progress bar
        if pbar:
            self.update_progress_bar("nmap_quick", 100 - int(last_percent))
            self.close_progress_bar("nmap_quick")
        
        if process.returncode == 0:
            self.log("Quick scan completed!", "SUCCESS")
            
            # Parse final results
            if os.path.exists(xml_file):
                self.parse_nmap_xml(xml_file)
                self.display_status()
        else:
            self.log("Quick scan failed", "ERROR")
    
    def nmap_service_scan(self):
        """Targeted Nmap service/script scan on discovered open ports"""
        if not self.results["ports"]:
            self.log("No open ports found for service scan", "WARNING")
            return
        
        self.log("Starting targeted service scan on discovered ports...", "INFO")
        
        # Build port list
        port_list = ",".join([str(p["port"]) for p in self.results["ports"]])
        self.log(f"Scanning ports: {port_list}", "INFO")
        
        # Create progress bar
        pbar = self.create_progress_bar("nmap_service", 100, "Service/Script Scan")
        
        xml_file = f"{self.scans_dir}/nmap_service.xml"
        
        command = [
            "nmap",
            "-sV",  # Service version detection
            "-sC",  # Default scripts
            "-T4",
            "-p", port_list,
            "-oX", xml_file,
            "-oN", f"{self.scans_dir}/nmap_service.txt",
            "--stats-every", "10s",
            self.target
        ]
        
        # Run with progress monitoring
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        last_percent = 0
        for line in process.stdout:
            if "% done" in line.lower():
                match = re.search(r'(\d+\.?\d*)%', line)
                if match:
                    percent = float(match.group(1))
                    if pbar and percent > last_percent:
                        increment = int(percent - last_percent)
                        self.update_progress_bar("nmap_service", increment)
                        last_percent = percent
        
        process.wait()
        
        # Complete the progress bar
        if pbar:
            self.update_progress_bar("nmap_service", 100 - int(last_percent))
            self.close_progress_bar("nmap_service")
        
        if process.returncode == 0:
            self.log("Service scan completed!", "SUCCESS")
            
            # Parse results
            if os.path.exists(xml_file):
                self.parse_nmap_xml(xml_file, full_scan=True)
                self.display_status()
        else:
            self.log("Service scan failed", "ERROR")
    
    def nmap_full_scan(self):
        """Extended Nmap scan with service detection"""
        self.log("Starting extended Nmap scan (all ports + service detection)...", "INFO")
        
        command = [
            "nmap",
            "-sV",  # Service version detection
            "-sC",  # Default scripts
            "-T4",
            "-p-",  # All ports
            "-oX", f"{self.scan_dir}/nmap_full.xml",
            "-oN", f"{self.scan_dir}/nmap_full.txt",
            self.target
        ]
        
        result = self.run_command(command, "Full port scan with service detection")
        
        if result.get("success"):
            self.log("Full scan completed!", "SUCCESS")
            
            # Parse results
            xml_file = f"{self.scan_dir}/nmap_full.xml"
            if os.path.exists(xml_file):
                self.parse_nmap_xml(xml_file, full_scan=True)
                self.display_status()
        else:
            self.log("Full scan failed", "ERROR")
    
    def nmap_full_scan_background(self):
        """Start full Nmap scan in background thread"""
        self.log("Starting full Nmap scan in BACKGROUND...", "INFO")
        self.log("Will continue with other tasks while scan runs", "INFO")
        
        def run_full_scan():
            xml_file = f"{self.scan_dir}/nmap_full.xml"
            
            # Create progress bar for full scan (65535 ports)
            pbar = self.create_progress_bar("nmap_full", 100, "Full Scan (All 65,535 Ports)")
            
            command = [
                "nmap",
                "-sV",  # Service version detection
                "-sC",  # Default scripts
                "-T4",
                "-p-",  # All ports
                "-oX", xml_file,
                "-oN", f"{self.scan_dir}/nmap_full.txt",
                "--stats-every", "30s",  # Update every 30 seconds
                self.target
            ]
            
            self.log("Background full scan started (monitoring progress)...", "INFO")
            
            # Run with progress monitoring
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            last_percent = 0
            for line in process.stdout:
                # Look for percentage in nmap output
                if "% done" in line.lower():
                    match = re.search(r'(\d+\.?\d*)%', line)
                    if match:
                        percent = float(match.group(1))
                        if pbar and percent > last_percent:
                            increment = int(percent - last_percent)
                            self.update_progress_bar("nmap_full", increment)
                            last_percent = percent
            
            process.wait()
            
            # Complete the progress bar
            if pbar:
                self.update_progress_bar("nmap_full", 100 - int(last_percent))
                self.close_progress_bar("nmap_full")
            
            if process.returncode == 0:
                self.log("Background full scan completed!", "SUCCESS")
                
                # Parse results
                if os.path.exists(xml_file):
                    self.parse_nmap_xml(xml_file, full_scan=True)
                    self.display_status()
            else:
                self.log("Background full scan failed", "ERROR")
        
        # Start in background thread
        self.full_scan_thread = threading.Thread(target=run_full_scan, daemon=False)
        self.full_scan_thread.start()
        self.log("Full scan thread started - continuing with other tasks...", "SUCCESS")
    
    def wait_for_full_scan(self):
        """Wait for background full scan to complete"""
        if hasattr(self, 'full_scan_thread') and self.full_scan_thread.is_alive():
            self.log("=" * 60, "INFO")
            self.log("Waiting for background full Nmap scan to complete...", "INFO")
            self.log("(This scan is checking all 65,535 ports + service detection)", "INFO")
            self.log("=" * 60, "INFO")
            self.full_scan_thread.join()
            self.log("Full Nmap scan finished and parsed!", "SUCCESS")
        else:
            self.log("Full scan already complete", "INFO")
    
    def parse_nmap_xml(self, xml_file: str, full_scan: bool = False):
        """Parse Nmap XML output and update results"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('host'):
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            port_num = int(port.get('portid'))
                            protocol = port.get('protocol')
                            
                            port_info = {
                                "port": port_num,
                                "protocol": protocol,
                                "state": "open"
                            }
                            
                            # Get service info
                            service = port.find('service')
                            if service is not None:
                                port_info["service"] = service.get('name', 'unknown')
                                port_info["product"] = service.get('product', '')
                                port_info["version"] = service.get('version', '')
                                
                                # Add to services for enumeration
                                if full_scan and port_info["product"]:
                                    service_info = {
                                        "port": port_num,
                                        "service": port_info["service"],
                                        "product": port_info["product"],
                                        "version": port_info["version"],
                                        "search_string": f"{port_info['product']} {port_info['version']}".strip()
                                    }
                                    
                                    # Thread-safe add
                                    self.add_service(service_info)
                            
                            # Thread-safe add to ports list
                            if self.add_port(port_info):
                                self.log(f"Found open port: {port_num}/{protocol} - {port_info.get('service', 'unknown')}", "SUCCESS")
                                # Update display immediately when port is found
                                self.display_status()
            
        except Exception as e:
            self.log(f"Error parsing Nmap XML: {e}", "ERROR")
    
    # ==================== DOMAIN DETECTION & MANAGEMENT ====================
    
    def check_web_redirects(self):
        """Check web services for domain redirects"""
        self.log("Checking for domain redirects on web services...", "INFO")
        
        web_ports = [80, 443, 8080, 8443, 8000, 3000, 5000]
        
        for port_info in self.results["ports"]:
            port = port_info["port"]
            if port in web_ports or "http" in port_info.get("service", "").lower():
                self.log(f"Checking port {port} for redirects...", "INFO")
                
                # Try both http and https
                protocols = ["http"]
                if port in [443, 8443]:
                    protocols = ["https", "http"]  # Try https first for SSL ports
                
                for protocol in protocols:
                    url = f"{protocol}://{self.target}:{port}"
                    
                    # Use curl to check for redirects (more reliable)
                    curl_cmd = [
                        "curl",
                        "-s",  # Silent
                        "-I",  # Headers only
                        "-L",  # Follow redirects
                        "--max-time", "5",
                        "--max-redirs", "5",
                        "-k",  # Insecure (ignore SSL errors)
                        url
                    ]
                    
                    try:
                        result = subprocess.run(
                            curl_cmd,
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        
                        if result.returncode == 0 or result.stdout:
                            output = result.stdout
                            
                            # Look for Location headers (redirects)
                            location_matches = re.findall(r'[Ll]ocation:\s*(\S+)', output)
                            
                            for location in location_matches:
                                self.log(f"Found redirect: {location}", "INFO")
                                
                                # Extract domain from Location header
                                domain_match = re.search(r'://([^:/]+)', location)
                                if domain_match:
                                    domain = domain_match.group(1)
                                    
                                    # Check if it's not just an IP and not external
                                    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                                        # Check if domain is external/CDN
                                        if not self.is_external_domain(domain):
                                            self.log(f"Found domain: {domain}", "SUCCESS")
                                            
                                            if domain not in self.results["domains"]:
                                                self.results["domains"].append(domain)
                                                self.add_to_hosts(domain, self.target)
                                                self.display_status()
                                                
                                                # Trigger subdomain enumeration
                                                self.enumerate_subdomains(domain)
                                        else:
                                            self.log(f"Skipping external domain: {domain} (CDN/third-party)", "INFO")
                            
                            # Also check Host headers in response for virtual hosting
                            # Sometimes the server name appears in headers
                            host_matches = re.findall(r'[Ss]erver:\s*([^\r\n]+)', output)
                            for server_info in host_matches:
                                # Look for domain names in server info
                                domain_in_server = re.findall(r'\b([a-z0-9][-a-z0-9]*\.[-a-z0-9.]+[a-z])\b', server_info.lower())
                                for domain in domain_in_server:
                                    if domain not in self.results["domains"] and '.' in domain:
                                        self.log(f"Found potential domain in server header: {domain}", "INFO")
                        
                    except subprocess.TimeoutExpired:
                        self.log(f"Timeout checking {url}", "WARNING")
                    except Exception as e:
                        self.log(f"Error checking {url}: {e}", "WARNING")
                    
                    # Also try a simple GET request to see HTML content
                    curl_html_cmd = [
                        "curl",
                        "-s",
                        "--max-time", "5",
                        "-k",
                        url
                    ]
                    
                    try:
                        result = subprocess.run(
                            curl_html_cmd,
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        
                        if result.returncode == 0 and result.stdout:
                            html = result.stdout
                            
                            # Look for domain names in HTML content (meta tags, links, etc.)
                            # Common patterns: href="http://domain.htb" or action="http://domain.htb"
                            html_domains = re.findall(r'https?://([a-z0-9][-a-z0-9]*\.[-a-z0-9.]+[a-z])(?:[:/]|")', html.lower())
                            
                            for domain in set(html_domains):
                                # Use proper external domain filtering
                                if not self.is_external_domain(domain):
                                    if domain not in self.results["domains"]:
                                        self.log(f"Found domain in HTML: {domain}", "SUCCESS")
                                        self.results["domains"].append(domain)
                                        self.add_to_hosts(domain, self.target)
                                        self.display_status()
                                        
                                        # Trigger subdomain enumeration
                                        self.enumerate_subdomains(domain)
                                else:
                                    self.log(f"Skipping external domain in HTML: {domain}", "INFO")
                    
                    except Exception as e:
                        self.log(f"Error fetching HTML from {url}: {e}", "WARNING")
        
        # Filter external domains from all discovered subdomains at the end
        if self.results["subdomains"]:
            self.log("Filtering external/third-party domains from all subdomains...", "INFO")
            self.filter_external_subdomains()
    
    def add_to_hosts(self, domain: str, ip: str):
        """Add domain to /etc/hosts file"""
        self.log(f"Adding {domain} to /etc/hosts...", "INFO")
        
        # Check if entry already exists
        try:
            with open('/etc/hosts', 'r') as f:
                hosts_content = f.read()
                if domain in hosts_content:
                    self.log(f"{domain} already in /etc/hosts", "INFO")
                    return
        except PermissionError:
            pass  # Will handle with sudo below
        
        # Prepare the hosts entry
        hosts_entry = f"{ip}    {domain}\n"
        
        # Try to add without sudo first
        try:
            with open('/etc/hosts', 'a') as f:
                f.write(hosts_entry)
            self.log(f"Added {domain} to /etc/hosts", "SUCCESS")
            self.add_loot(f"Added {domain} -> {ip} to /etc/hosts")
            return
        except PermissionError:
            self.log("Need sudo privileges to modify /etc/hosts", "WARNING")
            
            # Try with sudo
            try:
                # Create temporary file with the entry
                temp_file = f"/tmp/icyscan_hosts_{os.getpid()}"
                with open(temp_file, 'w') as f:
                    f.write(hosts_entry)
                
                # Use sudo to append to /etc/hosts
                sudo_cmd = f"sudo bash -c 'cat {temp_file} >> /etc/hosts'"
                self.log(f"Running: {sudo_cmd}", "INFO")
                
                result = subprocess.run(
                    sudo_cmd,
                    shell=True,
                    capture_output=True,
                    text=True
                )
                
                # Clean up temp file
                os.remove(temp_file)
                
                if result.returncode == 0:
                    self.log(f"Successfully added {domain} to /etc/hosts with sudo", "SUCCESS")
                    self.add_loot(f"Added {domain} -> {ip} to /etc/hosts")
                else:
                    self.log(f"Failed to add to /etc/hosts: {result.stderr}", "ERROR")
                    self.log(f"Manual command: echo '{ip}    {domain}' | sudo tee -a /etc/hosts", "INFO")
                    
            except Exception as e:
                self.log(f"Error adding to /etc/hosts: {e}", "ERROR")
                self.log(f"Please manually add: {ip}    {domain}", "WARNING")
    
    def enumerate_subdomains(self, domain: str):
        """Enumerate subdomains using ffuf and gobuster"""
        self.log(f"Starting subdomain enumeration for {domain}...", "INFO")
        
        # Choose wordlist
        wordlists = [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
        ]
        
        wordlist = None
        for wl in wordlists:
            if os.path.exists(wl):
                wordlist = wl
                self.log(f"Found wordlist: {wordlist}", "INFO")
                break
        
        if not wordlist:
            self.log("No suitable wordlist found for subdomain enumeration", "WARNING")
            self.log("Tried: " + ", ".join(wordlists), "WARNING")
            return
        
        # Clean domain name for filename (remove dots)
        domain_clean = domain.replace('.', '_')
        
        # Method 1: ffuf DNS fuzzing
        self.log("Running ffuf subdomain enumeration...", "INFO")
        ffuf_output = f"{self.scan_dir}/subdomains_ffuf_{domain_clean}.json"
        ffuf_txt = f"{self.scan_dir}/subdomains_ffuf_{domain_clean}.txt"
        
        ffuf_cmd = [
            "ffuf",
            "-u", f"http://FUZZ.{domain}",
            "-w", wordlist,
            "-t", "50",
            "-mc", "200,204,301,302,307,401,403",
            "-timeout", "3",
            "-v",
            "-o", ffuf_output,
            "-of", "json"
        ]
        
        self.log(f"ffuf command: {' '.join(ffuf_cmd)}", "INFO")
        result = self.run_command(ffuf_cmd, "ffuf subdomain fuzzing")
        
        if result.get("success"):
            self.log(f"ffuf completed successfully", "SUCCESS")
            
            if os.path.exists(ffuf_output):
                self.log(f"ffuf output file created: {ffuf_output}", "SUCCESS")
                try:
                    with open(ffuf_output, 'r') as f:
                        ffuf_data = json.load(f)
                        if "results" in ffuf_data and ffuf_data["results"]:
                            self.log(f"ffuf found {len(ffuf_data['results'])} results", "SUCCESS")
                            for item in ffuf_data["results"]:
                                subdomain = f"{item['input']['FUZZ']}.{domain}"
                                if subdomain not in self.results["subdomains"]:
                                    self.results["subdomains"].append(subdomain)
                                    self.log(f"Found subdomain: {subdomain}", "SUCCESS")
                                    
                                    # Add to /etc/hosts
                                    self.add_to_hosts(subdomain, self.target)
                        else:
                            self.log("ffuf found no results", "INFO")
                except Exception as e:
                    self.log(f"Error parsing ffuf output: {e}", "WARNING")
            else:
                self.log(f"ffuf output file not created: {ffuf_output}", "WARNING")
        else:
            self.log(f"ffuf failed or not installed", "WARNING")
            if "error" in result:
                self.log(f"Error: {result['error']}", "WARNING")
        
        # Method 2: gobuster vhost
        self.log("Running gobuster vhost enumeration...", "INFO")
        gobuster_output = f"{self.scan_dir}/subdomains_gobuster_{domain_clean}.txt"
        
        # Find a web port to use
        web_port = 80
        for port_info in self.results["ports"]:
            if port_info["port"] in [80, 443, 8080]:
                web_port = port_info["port"]
                break
        
        protocol = "https" if web_port in [443, 8443] else "http"
        
        gobuster_cmd = [
            "gobuster", "vhost",
            "-u", f"{protocol}://{domain}:{web_port}",
            "-w", wordlist,
            "-t", "50",
            "--append-domain",
            "-o", gobuster_output,
            "-k"  # Skip SSL verification
        ]
        
        self.log(f"gobuster command: {' '.join(gobuster_cmd)}", "INFO")
        result = self.run_command(gobuster_cmd, "gobuster vhost fuzzing")
        
        if result.get("success"):
            self.log(f"gobuster completed successfully", "SUCCESS")
            
            if os.path.exists(gobuster_output):
                self.log(f"gobuster output file created: {gobuster_output}", "SUCCESS")
                try:
                    with open(gobuster_output, 'r') as f:
                        lines = f.readlines()
                        found_count = 0
                        for line in lines:
                            # Parse gobuster vhost output
                            # Format: Found: subdomain.domain.com Status: 200
                            match = re.search(r'Found:\s+(\S+)', line)
                            if match:
                                subdomain = match.group(1)
                                if subdomain not in self.results["subdomains"]:
                                    self.results["subdomains"].append(subdomain)
                                    self.log(f"Found vhost: {subdomain}", "SUCCESS")
                                    found_count += 1
                                    
                                    # Add to /etc/hosts
                                    self.add_to_hosts(subdomain, self.target)
                        
                        if found_count == 0:
                            self.log("gobuster found no subdomains", "INFO")
                        else:
                            self.log(f"gobuster found {found_count} subdomains", "SUCCESS")
                            
                except Exception as e:
                    self.log(f"Error parsing gobuster output: {e}", "WARNING")
            else:
                self.log(f"gobuster output file not created: {gobuster_output}", "WARNING")
        else:
            self.log(f"gobuster failed or not installed", "WARNING")
            if "error" in result:
                self.log(f"Error: {result['error']}", "WARNING")
        
        # Update display
        self.display_status()
        
        # Save subdomain list if any found
        if self.results["subdomains"]:
            subdomain_list = "\n".join(sorted(self.results["subdomains"]))
            subdomain_file = f"{self.scan_dir}/subdomains_{domain_clean}.txt"
            self.save_results(f"subdomains_{domain_clean}.txt", subdomain_list)
            self.log(f"Saved {len(self.results['subdomains'])} subdomains to {subdomain_file}", "SUCCESS")
        else:
            self.log(f"No subdomains found for {domain}", "INFO")
    
    # ==================== NFS ENUMERATION ====================
    
    def enumerate_nfs(self):
        """Enumerate NFS with NXC first, then native tools for mounting"""
        self.log("=" * 60, "INFO")
        self.log("NFS ENUMERATION", "INFO")
        self.log("=" * 60, "INFO")
        
        # Check if NFS ports are open
        nfs_ports = [p for p in self.results["ports"] if p["port"] in [111, 2049]]
        
        if not nfs_ports:
            self.log("No NFS ports found", "WARNING")
            return
        
        self.log(f"Found NFS ports: {[p['port'] for p in nfs_ports]}", "INFO")
        
        # First, try NXC for NFS enumeration
        nxc_cmd = self.get_nxc_command()
        if nxc_cmd:
            self.log("Testing NFS with NXC...", "INFO")
            nxc_nfs_cmd = [nxc_cmd, "nfs", self.target]
            nxc_result = self.run_command(nxc_nfs_cmd, "NXC NFS enumeration", timeout=30)
            
            if nxc_result.get("success"):
                self.save_results("nxc_nfs_enum.txt", nxc_result["stdout"])
                self.log("✓ NXC NFS enumeration complete", "SUCCESS")
                
                # Parse NXC output for shares/exports
                if "export" in nxc_result["stdout"].lower() or "/" in nxc_result["stdout"]:
                    self.log("NXC detected NFS exports", "SUCCESS")
        else:
            self.log("NXC not available, using native showmount", "WARNING")
        
        # Use native showmount for detailed export listing
        self.log(f"Discovering NFS exports with showmount...", "INFO")
        
        showmount_cmd = ["showmount", "-e", self.target]
        result = self.run_command(showmount_cmd, "showmount export list", timeout=30)
        
        if not result.get("success"):
            self.log("showmount failed - trying rpcinfo...", "WARNING")
            
            rpcinfo_cmd = ["rpcinfo", "-p", self.target]
            rpc_result = self.run_command(rpcinfo_cmd, "rpcinfo check", timeout=30)
            
            if rpc_result.get("success"):
                self.save_results("nfs_rpcinfo.txt", rpc_result["stdout"])
                
                if "nfs" in rpc_result["stdout"].lower():
                    self.log("NFS service detected via rpcinfo", "SUCCESS")
                    self.add_loot(f"NFS service running on {self.target}")
            
            return
        
        # Save showmount output
        self.save_results("nfs_showmount.txt", result["stdout"])
        
        # Parse showmount output
        exports = []
        lines = result["stdout"].split('\n')
        
        for line in lines[1:]:  # Skip header
            line = line.strip()
            if not line:
                continue
            
            parts = line.split()
            if parts:
                export_path = parts[0]
                access_info = " ".join(parts[1:]) if len(parts) > 1 else "unknown"
                
                exports.append({
                    "path": export_path,
                    "access": access_info
                })
                
                self.log(f"✓ Found NFS export: {export_path} (Access: {access_info})", "SUCCESS")
        
        if not exports:
            self.log("No NFS exports found", "WARNING")
            return
        
        self.log(f"Found {len(exports)} NFS export(s)", "SUCCESS")
        self.add_loot(f"NFS: Found {len(exports)} export(s) on {self.target}")
        
        # Mount exports
        nfs_mount_base = f"{self.loot_dir}/NFS_Mounts"
        os.makedirs(nfs_mount_base, exist_ok=True)
        
        pbar = self.create_progress_bar("nfs_mount", len(exports), "Mounting NFS Shares")
        
        mounted_shares = []
        
        for export in exports:
            export_path = export["path"]
            safe_name = export_path.replace('/', '_').strip('_') or "root"
            mount_point = f"{nfs_mount_base}/{safe_name}"
            os.makedirs(mount_point, exist_ok=True)
            
            self.log(f"Mounting {export_path} to {mount_point}...", "INFO")
            
            # Try NFSv3
            mount_cmd = [
                "mount", "-t", "nfs", "-o", "nolock,vers=3",
                f"{self.target}:{export_path}", mount_point
            ]
            
            mount_result = self.run_command(mount_cmd, f"mount NFS {export_path}", timeout=30)
            
            if mount_result.get("success") or mount_result.get("returncode") == 0:
                self.log(f"✓ Mounted {export_path}!", "SUCCESS")
                self.add_loot(f"NFS: Mounted {export_path} at {mount_point}")
                
                mounted_shares.append({
                    "export": export_path,
                    "mount_point": mount_point,
                    "access": export["access"]
                })
                
                # List contents
                try:
                    contents = os.listdir(mount_point)
                    if contents:
                        self.log(f"Contents: {len(contents)} items", "INFO")
                        
                        # Save listing
                        listing = f"NFS Export: {export_path}\n"
                        listing += f"Mount Point: {mount_point}\n"
                        listing += f"Access: {export['access']}\n"
                        listing += "="*80 + "\n\n"
                        
                        for item in contents[:100]:
                            item_path = os.path.join(mount_point, item)
                            try:
                                if os.path.isdir(item_path):
                                    listing += f"[DIR]  {item}\n"
                                else:
                                    size = os.path.getsize(item_path)
                                    listing += f"[FILE] {item} ({size} bytes)\n"
                            except:
                                listing += f"       {item}\n"
                        
                        self.save_results(f"nfs_listing_{safe_name}.txt", listing)
                        self.add_loot(f"NFS: {len(contents)} items in {export_path}")
                        
                        # Find interesting files
                        interesting = [i for i in contents[:50] if any(ext in i.lower() 
                                     for ext in ['.txt', '.conf', '.key', '.pem', '.sh', '.xml'])]
                        
                        if interesting:
                            self.log(f"✓ Found {len(interesting)} interesting files", "SUCCESS")
                            self.add_loot(f"NFS Interesting: {', '.join(interesting[:5])}")
                
                except Exception as e:
                    self.log(f"Error reading {export_path}: {e}", "WARNING")
            else:
                # Try NFSv4
                self.log(f"Retrying with NFSv4...", "INFO")
                mount_cmd_v4 = [
                    "mount", "-t", "nfs4", "-o", "nolock",
                    f"{self.target}:{export_path}", mount_point
                ]
                
                mount_result_v4 = self.run_command(mount_cmd_v4, f"mount NFSv4 {export_path}", timeout=30)
                
                if mount_result_v4.get("success") or mount_result_v4.get("returncode") == 0:
                    self.log(f"✓ Mounted with NFSv4!", "SUCCESS")
                    self.add_loot(f"NFS: Mounted {export_path} (NFSv4) at {mount_point}")
                    
                    mounted_shares.append({
                        "export": export_path,
                        "mount_point": mount_point,
                        "access": export["access"],
                        "version": "NFSv4"
                    })
                else:
                    self.log(f"Mount failed for {export_path}", "ERROR")
                    try:
                        os.rmdir(mount_point)
                    except:
                        pass
            
            self.update_progress_bar("nfs_mount", 1)
        
        self.close_progress_bar("nfs_mount")
        
        # Generate summary
        if mounted_shares:
            summary = "NFS MOUNT SUMMARY\n" + "="*80 + "\n\n"
            summary += f"Target: {self.target}\n"
            summary += f"Mounted Shares: {len(mounted_shares)}/{len(exports)}\n\n"
            
            for share in mounted_shares:
                summary += f"Export: {share['export']}\n"
                summary += f"Mount Point: {share['mount_point']}\n"
                summary += f"Access: {share['access']}\n"
                if 'version' in share:
                    summary += f"Version: {share['version']}\n"
                summary += "-"*80 + "\n"
            
            summary += "\nTo unmount all shares:\n"
            for share in mounted_shares:
                summary += f"  sudo umount {share['mount_point']}\n"
            
            self.save_results("nfs_mount_summary.txt", summary)
            
            self.log("=" * 60, "SUCCESS")
            self.log(f"Successfully mounted {len(mounted_shares)} NFS share(s)!", "SUCCESS")
            self.log(f"Mount points: {nfs_mount_base}", "SUCCESS")
            self.log("=" * 60, "SUCCESS")
            
            self.log("IMPORTANT: Remember to unmount NFS shares:", "WARNING")
            for share in mounted_shares:
                self.log(f"  sudo umount {share['mount_point']}", "WARNING")
        
        self.display_status()
        """Enumerate NFS shares and attempt to mount them"""
        self.log("=" * 60, "INFO")
        self.log("NFS ENUMERATION STARTED", "INFO")
        self.log("=" * 60, "INFO")
        
        # Check if NFS ports are open
        nfs_ports = [p for p in self.results["ports"] if p["port"] in [111, 2049]]
        
        if not nfs_ports:
            self.log("No NFS ports found, skipping NFS enumeration", "WARNING")
            return
        
        self.log(f"Found NFS ports: {[p['port'] for p in nfs_ports]}", "INFO")
        
        # Create NFS mount directory in Loot
        nfs_mount_base = f"{self.loot_dir}/NFS_Mounts"
        os.makedirs(nfs_mount_base, exist_ok=True)
        
        # 1. Use showmount to list exports
        self.log(f"Discovering NFS exports on {self.target}...", "INFO")
        
        showmount_cmd = ["showmount", "-e", self.target]
        result = self.run_command(showmount_cmd, "showmount export list", timeout=30)
        
        if not result.get("success"):
            self.log("showmount failed - NFS may not be configured or accessible", "WARNING")
            
            # Try rpcinfo as backup
            self.log("Trying rpcinfo to check NFS services...", "INFO")
            rpcinfo_cmd = ["rpcinfo", "-p", self.target]
            rpc_result = self.run_command(rpcinfo_cmd, "rpcinfo check", timeout=30)
            
            if rpc_result.get("success"):
                self.save_results(f"{self.scans_dir}/nfs_rpcinfo.txt", rpc_result["stdout"])
                
                if "nfs" in rpc_result["stdout"].lower():
                    self.log("NFS service detected via rpcinfo", "SUCCESS")
                    self.add_loot(f"NFS service running on {self.target}")
                else:
                    self.log("No NFS service detected via rpcinfo", "INFO")
            
            return
        
        # Save showmount output
        self.save_results(f"{self.scans_dir}/nfs_showmount.txt", result["stdout"])
        
        # Parse showmount output
        exports = []
        lines = result["stdout"].split('\n')
        
        for line in lines[1:]:  # Skip header line
            line = line.strip()
            if not line:
                continue
            
            # Parse line: "/export/path hostname(options)" or "/export/path *"
            parts = line.split()
            if parts:
                export_path = parts[0]
                
                # Get access info
                access_info = "unknown"
                if len(parts) > 1:
                    access_info = " ".join(parts[1:])
                
                exports.append({
                    "path": export_path,
                    "access": access_info
                })
                
                self.log(f"Found NFS export: {export_path} (Access: {access_info})", "SUCCESS")
        
        if not exports:
            self.log("No NFS exports found", "WARNING")
            return
        
        self.log(f"Found {len(exports)} NFS export(s)", "SUCCESS")
        self.add_loot(f"NFS: Found {len(exports)} export(s) on {self.target}")
        
        # Create progress bar for mounting
        pbar = self.create_progress_bar("nfs_mount", len(exports), "Mounting NFS Shares")
        
        # 2. Attempt to mount each export
        mounted_shares = []
        
        for export in exports:
            export_path = export["path"]
            
            # Create safe mount point name
            safe_name = export_path.replace('/', '_').strip('_')
            if not safe_name:
                safe_name = "root"
            
            mount_point = f"{nfs_mount_base}/{safe_name}"
            os.makedirs(mount_point, exist_ok=True)
            
            self.log(f"Attempting to mount {export_path} to {mount_point}...", "INFO")
            
            # Try to mount
            mount_cmd = [
                "mount",
                "-t", "nfs",
                "-o", "nolock,vers=3",  # Use NFSv3 with nolock
                f"{self.target}:{export_path}",
                mount_point
            ]
            
            mount_result = self.run_command(mount_cmd, f"mount NFS {export_path}", timeout=30)
            
            if mount_result.get("success") or mount_result.get("returncode") == 0:
                self.log(f"Successfully mounted {export_path}!", "SUCCESS")
                self.add_loot(f"NFS: Mounted {export_path} at {mount_point}")
                
                mounted_shares.append({
                    "export": export_path,
                    "mount_point": mount_point,
                    "access": export["access"]
                })
                
                # List contents
                try:
                    contents = os.listdir(mount_point)
                    if contents:
                        self.log(f"Contents of {export_path}: {len(contents)} items", "INFO")
                        
                        # Save file listing
                        listing = f"NFS Export: {export_path}\n"
                        listing += f"Mount Point: {mount_point}\n"
                        listing += f"Access: {export['access']}\n"
                        listing += "="*80 + "\n\n"
                        listing += "Contents:\n"
                        
                        for item in contents[:100]:  # First 100 items
                            item_path = os.path.join(mount_point, item)
                            try:
                                if os.path.isdir(item_path):
                                    listing += f"[DIR]  {item}\n"
                                else:
                                    size = os.path.getsize(item_path)
                                    listing += f"[FILE] {item} ({size} bytes)\n"
                            except:
                                listing += f"       {item}\n"
                        
                        if len(contents) > 100:
                            listing += f"\n... and {len(contents) - 100} more items\n"
                        
                        self.save_results(f"{self.loot_dir}/nfs_listing_{safe_name}.txt", listing)
                        self.add_loot(f"NFS: {len(contents)} items in {export_path}")
                        
                        # Look for interesting files
                        interesting_files = []
                        for item in contents[:50]:  # Check first 50
                            if any(ext in item.lower() for ext in ['.txt', '.conf', '.key', '.pem', '.sh', '.xml', '.ini', '.password', '.secret', '.backup', '.bak']):
                                interesting_files.append(item)
                        
                        if interesting_files:
                            self.log(f"Found {len(interesting_files)} interesting files in {export_path}", "SUCCESS")
                            self.add_loot(f"NFS: Found interesting files in {export_path}: {', '.join(interesting_files[:5])}")
                    else:
                        self.log(f"{export_path} is empty or inaccessible", "INFO")
                        
                except PermissionError:
                    self.log(f"Permission denied reading {export_path}", "WARNING")
                    self.add_loot(f"NFS: {export_path} mounted but access denied")
                except Exception as e:
                    self.log(f"Error reading {export_path}: {e}", "WARNING")
            else:
                self.log(f"Failed to mount {export_path}", "WARNING")
                
                # Try NFSv4
                self.log(f"Retrying with NFSv4...", "INFO")
                mount_cmd_v4 = [
                    "mount",
                    "-t", "nfs4",
                    "-o", "nolock",
                    f"{self.target}:{export_path}",
                    mount_point
                ]
                
                mount_result_v4 = self.run_command(mount_cmd_v4, f"mount NFSv4 {export_path}", timeout=30)
                
                if mount_result_v4.get("success") or mount_result_v4.get("returncode") == 0:
                    self.log(f"Successfully mounted {export_path} with NFSv4!", "SUCCESS")
                    self.add_loot(f"NFS: Mounted {export_path} (NFSv4) at {mount_point}")
                    
                    mounted_shares.append({
                        "export": export_path,
                        "mount_point": mount_point,
                        "access": export["access"],
                        "version": "NFSv4"
                    })
                else:
                    self.log(f"Mount failed for {export_path} (both NFSv3 and NFSv4)", "ERROR")
                    # Clean up empty mount point
                    try:
                        os.rmdir(mount_point)
                    except:
                        pass
            
            # Update progress
            self.update_progress_bar("nfs_mount", 1)
        
        # Close progress bar
        self.close_progress_bar("nfs_mount")
        
        # Generate summary
        if mounted_shares:
            summary = f"NFS MOUNT SUMMARY\n"
            summary += "="*80 + "\n\n"
            summary += f"Target: {self.target}\n"
            summary += f"Mounted Shares: {len(mounted_shares)}/{len(exports)}\n\n"
            
            for share in mounted_shares:
                summary += f"Export: {share['export']}\n"
                summary += f"Mount Point: {share['mount_point']}\n"
                summary += f"Access: {share['access']}\n"
                if 'version' in share:
                    summary += f"Version: {share['version']}\n"
                summary += "-"*80 + "\n"
            
            summary += "\n"
            summary += "To unmount all shares:\n"
            for share in mounted_shares:
                summary += f"  sudo umount {share['mount_point']}\n"
            
            self.save_results(f"{self.loot_dir}/nfs_mount_summary.txt", summary)
            
            self.log("=" * 60, "SUCCESS")
            self.log(f"Successfully mounted {len(mounted_shares)} NFS share(s)!", "SUCCESS")
            self.log(f"Mount points: {nfs_mount_base}", "SUCCESS")
            self.log("=" * 60, "SUCCESS")
            
            # Important warning about cleanup
            self.log("IMPORTANT: Remember to unmount NFS shares after scanning:", "WARNING")
            for share in mounted_shares:
                self.log(f"  sudo umount {share['mount_point']}", "WARNING")
        else:
            self.log("No NFS shares could be mounted", "WARNING")
        
        self.display_status()
    
    # ==================== WEB FUZZING ====================
    
    def enumerate_feroxbuster(self):
        """Run feroxbuster for directory and file enumeration"""
        self.log("=" * 60, "INFO")
        self.log("FEROXBUSTER WEB FUZZING STARTED", "INFO")
        self.log("=" * 60, "INFO")
        
        # Find all web ports
        web_ports = [p for p in self.results["ports"] if p["port"] in [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]]
        
        if not web_ports:
            self.log("No web ports found, skipping feroxbuster", "WARNING")
            return
        
        # Choose wordlist
        wordlists = [
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"
        ]
        
        wordlist = None
        for wl in wordlists:
            if os.path.exists(wl):
                wordlist = wl
                break
        
        if not wordlist:
            self.log("No suitable wordlist found for feroxbuster", "WARNING")
            return
        
        self.log(f"Using wordlist: {wordlist}", "INFO")
        
        # Collect all targets to fuzz
        targets_to_fuzz = []
        
        # Add main target
        for port_info in web_ports:
            port = port_info["port"]
            protocol = "https" if port in [443, 8443] else "http"
            targets_to_fuzz.append((f"{protocol}://{self.target}:{port}", f"target_port{port}"))
        
        # Add discovered domains
        for domain in self.results["domains"]:
            for port_info in web_ports:
                port = port_info["port"]
                protocol = "https" if port in [443, 8443] else "http"
                domain_clean = domain.replace('.', '_')
                targets_to_fuzz.append((f"{protocol}://{domain}:{port}", f"{domain_clean}_port{port}"))
        
        # Add all subdomains (feroxbuster is fast, we can scan all)
        for subdomain in self.results["subdomains"]:
            for port_info in web_ports:
                port = port_info["port"]
                protocol = "https" if port in [443, 8443] else "http"
                sub_clean = subdomain.replace('.', '_')
                targets_to_fuzz.append((f"{protocol}://{subdomain}:{port}", f"{sub_clean}_port{port}"))
        
        self.log(f"Total targets to fuzz: {len(targets_to_fuzz)}", "INFO")
        
        # Create progress bar
        pbar = self.create_progress_bar("feroxbuster", len(targets_to_fuzz), "Feroxbuster Fuzzing")
        
        for url, filename in targets_to_fuzz:
            self.log(f"Fuzzing {url} with feroxbuster...", "INFO")
            
            output_file = f"{self.scans_dir}/feroxbuster_{filename}.txt"
            
            command = [
                "feroxbuster",
                "-u", url,
                "-w", wordlist,
                "-t", "50",  # 50 threads
                "-d", "2",   # Depth 2
                "--auto-bail",  # Stop on too many errors
                "--random-agent",
                "-o", output_file,
                "-q",  # Quiet mode
                "--no-state"  # Don't save state
            ]
            
            # Add insecure flag for HTTPS
            if url.startswith("https"):
                command.append("-k")
            
            result = self.run_command(command, f"Feroxbuster on {url}", timeout=600)
            
            if result.get("success"):
                self.log(f"Feroxbuster completed for {url}", "SUCCESS")
                
                # Parse feroxbuster output
                if os.path.exists(output_file):
                    self.parse_feroxbuster_output(output_file, url)
            else:
                self.log(f"Feroxbuster failed for {url}", "WARNING")
            
            # Update progress
            self.update_progress_bar("feroxbuster", 1)
        
        # Close progress bar
        self.close_progress_bar("feroxbuster")
        
        self.log("Feroxbuster enumeration complete!", "SUCCESS")
        self.display_status()
    
    def parse_feroxbuster_output(self, output_file: str, url: str):
        """Parse feroxbuster output for interesting findings"""
        try:
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Count findings by status code
            status_200 = len(re.findall(r'200\s+', content))
            status_301 = len(re.findall(r'301\s+', content))
            status_302 = len(re.findall(r'302\s+', content))
            status_403 = len(re.findall(r'403\s+', content))
            
            total_found = status_200 + status_301 + status_302 + status_403
            
            if total_found > 0:
                self.add_loot(f"Feroxbuster: Found {total_found} paths on {url} (200:{status_200}, 301:{status_301}, 302:{status_302}, 403:{status_403})")
                self.log(f"Found {total_found} paths on {url}", "SUCCESS")
            
            # Look for interesting paths
            interesting_keywords = [
                'admin', 'login', 'dashboard', 'config', 'backup',
                'upload', 'api', 'secret', 'private', 'internal',
                '.git', '.env', 'password', 'credentials', 'key'
            ]
            
            interesting_paths = []
            for line in content.split('\n'):
                if any(keyword in line.lower() for keyword in interesting_keywords):
                    # Extract the path
                    match = re.search(r'(https?://[^\s]+)', line)
                    if match:
                        interesting_paths.append(match.group(1))
            
            if interesting_paths:
                # Save to loot directory
                loot_file = f"{self.loot_dir}/feroxbuster_interesting_{url.replace('://', '_').replace(':', '_').replace('/', '_')}.txt"
                with open(loot_file, 'w') as f:
                    f.write(f"Interesting paths found on {url}:\n\n")
                    for path in interesting_paths[:50]:
                        f.write(f"{path}\n")
                
                self.add_loot(f"Feroxbuster: Found {len(interesting_paths)} interesting paths on {url}")
                self.log(f"Found {len(interesting_paths)} interesting paths on {url}", "SUCCESS")
            
        except Exception as e:
            self.log(f"Error parsing feroxbuster output: {e}", "WARNING")
    
    # ==================== WEB ENUMERATION ====================
    
    def enumerate_nikto(self):
        """Run Nikto web vulnerability scanner on all web services"""
        self.log("=" * 60, "INFO")
        self.log("NIKTO WEB ENUMERATION STARTED", "INFO")
        self.log("=" * 60, "INFO")
        
        # Find all web ports
        web_ports = [p for p in self.results["ports"] if p["port"] in [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]]
        
        if not web_ports:
            self.log("No web ports found, skipping Nikto", "WARNING")
            return
        
        self.log(f"Found {len(web_ports)} web services to scan", "INFO")
        
        # Collect all targets to scan
        targets_to_scan = []
        
        # Add main target
        for port_info in web_ports:
            port = port_info["port"]
            protocol = "https" if port in [443, 8443] else "http"
            targets_to_scan.append((f"{protocol}://{self.target}:{port}", f"target_port{port}"))
        
        # Add discovered domains
        for domain in self.results["domains"]:
            for port_info in web_ports:
                port = port_info["port"]
                protocol = "https" if port in [443, 8443] else "http"
                domain_clean = domain.replace('.', '_')
                targets_to_scan.append((f"{protocol}://{domain}:{port}", f"{domain_clean}_port{port}"))
        
        # Add subdomains (limit to first 10 to avoid excessive scanning)
        for subdomain in self.results["subdomains"][:10]:
            for port_info in web_ports:
                port = port_info["port"]
                protocol = "https" if port in [443, 8443] else "http"
                sub_clean = subdomain.replace('.', '_')
                targets_to_scan.append((f"{protocol}://{subdomain}:{port}", f"{sub_clean}_port{port}"))
        
        self.log(f"Total targets to scan: {len(targets_to_scan)}", "INFO")
        
        # Create progress bar
        pbar = self.create_progress_bar("nikto", len(targets_to_scan), "Nikto Web Scanning")
        
        for url, filename in targets_to_scan:
            self.log(f"Scanning {url} with Nikto...", "INFO")
            
            output_file = f"{self.scan_dir}/nikto_{filename}.txt"
            
            command = [
                "nikto",
                "-h", url,
                "-maxtime", "5m",  # 5 minute timeout per target
                "-output", output_file,
                "-Format", "txt",
                "-nointeractive"
            ]
            
            result = self.run_command(command, f"Nikto scan on {url}", timeout=360)
            
            if result.get("success"):
                self.log(f"Nikto scan completed for {url}", "SUCCESS")
                
                # Parse nikto output for interesting findings
                if os.path.exists(output_file):
                    self.parse_nikto_output(output_file, url, self.loot_dir)
            else:
                self.log(f"Nikto scan failed for {url}", "WARNING")
            
            # Update progress
            self.update_progress_bar("nikto", 1)
        
        # Close progress bar
        self.close_progress_bar("nikto")
        
        self.log("Nikto enumeration complete!", "SUCCESS")
        self.display_status()
    
    def parse_nikto_output(self, output_file: str, url: str, loot_dir: str):
        """Parse Nikto output for credentials, files, and vulnerabilities"""
        try:
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Look for interesting findings
            
            # 1. Credentials/Authentication issues
            if "default credentials" in content.lower() or "default password" in content.lower():
                self.add_loot(f"Nikto: Possible default credentials on {url}")
                self.log(f"Found potential default credentials on {url}", "SUCCESS")
            
            if "basic auth" in content.lower() or "authentication" in content.lower():
                self.add_loot(f"Nikto: Authentication mechanism found on {url}")
            
            # 2. Interesting directories/files
            interesting_paths = re.findall(r'\+\s+(/[^\s:]+)', content)
            if interesting_paths:
                # Save to loot directory
                paths_file = f"{loot_dir}/nikto_paths_{url.replace('://', '_').replace(':', '_').replace('/', '_')}.txt"
                with open(paths_file, 'w') as f:
                    f.write(f"Interesting paths found on {url}:\n\n")
                    for path in set(interesting_paths[:50]):  # First 50 unique paths
                        f.write(f"{path}\n")
                
                self.add_loot(f"Nikto: Found {len(set(interesting_paths))} interesting paths on {url}")
                self.log(f"Found {len(set(interesting_paths))} interesting paths on {url}", "SUCCESS")
            
            # 3. Vulnerabilities
            vuln_keywords = [
                "vulnerability", "vulnerable", "exploit", "CVE-",
                "outdated", "old version", "security"
            ]
            
            vuln_lines = []
            for line in content.split('\n'):
                if any(keyword in line.lower() for keyword in vuln_keywords):
                    vuln_lines.append(line.strip())
            
            if vuln_lines:
                vuln_file = f"{loot_dir}/nikto_vulns_{url.replace('://', '_').replace(':', '_').replace('/', '_')}.txt"
                with open(vuln_file, 'w') as f:
                    f.write(f"Potential vulnerabilities found on {url}:\n\n")
                    for line in vuln_lines[:20]:  # First 20 findings
                        f.write(f"{line}\n")
                
                self.add_loot(f"Nikto: Found {len(vuln_lines)} potential vulnerabilities on {url}")
                self.log(f"Found {len(vuln_lines)} potential vulnerabilities on {url}", "SUCCESS")
            
            # 4. Server information
            server_match = re.search(r'Server:\s*([^\n]+)', content)
            if server_match:
                server = server_match.group(1).strip()
                self.add_loot(f"Web Server: {server} on {url}")
            
            # 5. Configuration issues
            if "directory indexing" in content.lower() or "directory listing" in content.lower():
                self.add_loot(f"Nikto: Directory listing enabled on {url}")
            
            if "x-frame-options" in content.lower() or "clickjacking" in content.lower():
                self.add_loot(f"Nikto: Clickjacking vulnerability possible on {url}")
            
        except Exception as e:
            self.log(f"Error parsing Nikto output: {e}", "WARNING")
    
    # ==================== NXC (NETEXEC) MULTI-PROTOCOL ENUMERATION ====================
    
    def get_nxc_command(self):
        """Determine which NetExec command is available (nxc or netexec)"""
        check_nxc = subprocess.run(["which", "nxc"], capture_output=True)
        if check_nxc.returncode == 0:
            return "nxc"
        
        check_netexec = subprocess.run(["which", "netexec"], capture_output=True)
        if check_netexec.returncode == 0:
            return "netexec"
        
        return None
    
    def enumerate_nxc_protocol(self, protocol: str, port: int):
        """Generic NXC enumeration for any supported protocol"""
        self.log("=" * 60, "INFO")
        self.log(f"{protocol.upper()} ENUMERATION (NXC)", "INFO")
        self.log("=" * 60, "INFO")
        
        nxc_cmd = self.get_nxc_command()
        if not nxc_cmd:
            self.log("NetExec (nxc) not found. Install with: pipx install netexec", "ERROR")
            return
        
        # Use discovered domain if available, otherwise use IP
        target = self.results["domains"][0] if self.results["domains"] else self.target
        
        # Protocol-specific enumeration
        if protocol == "smb":
            self._enumerate_smb_nxc(nxc_cmd, target)
        elif protocol == "ldap":
            self._enumerate_ldap_nxc(nxc_cmd, target)
        elif protocol == "ftp":
            self._enumerate_ftp_nxc(nxc_cmd, target)
        elif protocol == "ssh":
            self._enumerate_ssh_nxc(nxc_cmd, target)
        elif protocol == "winrm":
            self._enumerate_winrm_nxc(nxc_cmd, target)
        elif protocol == "rdp":
            self._enumerate_rdp_nxc(nxc_cmd, target)
        elif protocol == "mssql":
            self._enumerate_mssql_nxc(nxc_cmd, target)
        elif protocol == "wmi":
            self._enumerate_wmi_nxc(nxc_cmd, target)
        elif protocol == "vnc":
            self._enumerate_vnc_nxc(nxc_cmd, target)
    
    def _enumerate_smb_nxc(self, nxc_cmd: str, target: str):
        """SMB enumeration with NXC"""
        self.log(f"Target: {target}", "INFO")
        
        # Test for null session
        self.log("Testing for SMB null session...", "INFO")
        null_cmd = [nxc_cmd, "smb", target, "-u", "", "-p", ""]
        null_result = self.run_command(null_cmd, "NXC SMB null session test")
        
        null_session = False
        if null_result.get("success"):
            self.save_results("nxc_smb_null_session.txt", null_result["stdout"])
            
            output_lower = null_result["stdout"].lower()
            if any(indicator in output_lower for indicator in ["[+]", "pwn3d", "smb", "445"]):
                null_session = True
                self.log("✓ NULL SESSION AVAILABLE!", "SUCCESS")
                self.add_loot("SMB Null Session Available")
                
                with self.results_lock:
                    self.results["vulnerabilities"].append({
                        "name": "SMB Null Session",
                        "severity": "MEDIUM",
                        "description": "Anonymous SMB access is possible"
                    })
        
        # Enumerate shares
        self.log("Enumerating SMB shares...", "INFO")
        shares_cmd = [nxc_cmd, "smb", target, "-u", "", "-p", "", "--shares"]
        shares_result = self.run_command(shares_cmd, "NXC SMB share enumeration")
        
        if shares_result.get("success"):
            self.save_results("nxc_smb_shares.txt", shares_result["stdout"])
            self._parse_smb_shares(shares_result["stdout"])
        
        # Enumerate users
        self.log("Enumerating SMB users...", "INFO")
        users_cmd = [nxc_cmd, "smb", target, "-u", "", "-p", "", "--users"]
        users_result = self.run_command(users_cmd, "NXC SMB user enumeration")
        
        if users_result.get("success"):
            self.save_results("nxc_smb_users.txt", users_result["stdout"])
            self._parse_smb_users(users_result["stdout"])
        
        # Enumerate groups
        self.log("Enumerating SMB groups...", "INFO")
        groups_cmd = [nxc_cmd, "smb", target, "-u", "", "-p", "", "--groups"]
        groups_result = self.run_command(groups_cmd, "NXC SMB group enumeration")
        
        if groups_result.get("success"):
            self.save_results("nxc_smb_groups.txt", groups_result["stdout"])
        
        # Password policy
        self.log("Retrieving password policy...", "INFO")
        passpol_cmd = [nxc_cmd, "smb", target, "-u", "", "-p", "", "--pass-pol"]
        passpol_result = self.run_command(passpol_cmd, "NXC SMB password policy")
        
        if passpol_result.get("success"):
            self.save_results("nxc_smb_password_policy.txt", passpol_result["stdout"])
            self._parse_password_policy(passpol_result["stdout"])
        
        # RID Cycling
        if null_session:
            self.log("Running RID cycling...", "INFO")
            rid_cmd = [nxc_cmd, "smb", target, "-u", "", "-p", "", "--rid-brute", "5000"]
            rid_result = self.run_command(rid_cmd, "NXC SMB RID cycling", timeout=300)
            
            if rid_result.get("success"):
                self.save_results("nxc_smb_rid_brute.txt", rid_result["stdout"])
        
        # Check SMB signing
        self.log("Checking SMB signing...", "INFO")
        signing_cmd = [nxc_cmd, "smb", target]
        signing_result = self.run_command(signing_cmd, "NXC SMB info")
        
        if signing_result.get("success"):
            self.save_results("nxc_smb_info.txt", signing_result["stdout"])
            
            output_lower = signing_result["stdout"].lower()
            if "signing:false" in output_lower or "signing:disabled" in output_lower:
                self.log("✓ SMB signing DISABLED - relay attacks possible!", "SUCCESS")
                self.add_loot("SMB Signing: DISABLED (relay attacks possible)")
                
                with self.results_lock:
                    self.results["vulnerabilities"].append({
                        "name": "SMB Signing Disabled",
                        "severity": "HIGH",
                        "description": "SMB relay attacks are possible"
                    })
        
        self.display_status()
    
    def _enumerate_ldap_nxc(self, nxc_cmd: str, target: str):
        """LDAP enumeration with NXC"""
        if not self.results["domains"]:
            self.log("No domain discovered, LDAP enumeration requires a domain", "WARNING")
            return
        
        target = self.results["domains"][0]
        self.log(f"Target domain: {target}", "INFO")
        
        # Test anonymous bind
        self.log("Testing for anonymous LDAP bind...", "INFO")
        anon_cmd = [nxc_cmd, "ldap", target, "-u", "", "-p", ""]
        anon_result = self.run_command(anon_cmd, "NXC LDAP anonymous bind test")
        
        if anon_result.get("success"):
            self.save_results("nxc_ldap_anonymous.txt", anon_result["stdout"])
            
            if "[+]" in anon_result["stdout"]:
                self.log("✓ Anonymous LDAP bind available!", "SUCCESS")
                self.add_loot("LDAP Anonymous Bind Available")
                
                # Enumerate users
                users_cmd = [nxc_cmd, "ldap", target, "-u", "", "-p", "", "--users"]
                users_result = self.run_command(users_cmd, "NXC LDAP user enumeration")
                
                if users_result.get("success"):
                    self.save_results("nxc_ldap_users.txt", users_result["stdout"])
                
                # Enumerate groups
                groups_cmd = [nxc_cmd, "ldap", target, "-u", "", "-p", "", "--groups"]
                groups_result = self.run_command(groups_cmd, "NXC LDAP group enumeration")
                
                if groups_result.get("success"):
                    self.save_results("nxc_ldap_groups.txt", groups_result["stdout"])
        
        self.display_status()
    
    def _enumerate_ftp_nxc(self, nxc_cmd: str, target: str):
        """FTP enumeration with NXC, then download files with ftplib"""
        self.log(f"Target: {target}", "INFO")
        
        # Test with common FTP credentials using NXC
        self.log("Testing FTP credentials with NXC...", "INFO")
        
        creds = [
            ("anonymous", "anonymous@"),
            ("anonymous", ""),
            ("ftp", "ftp"),
            ("", "")
        ]
        
        ftp_access = False
        working_creds = None
        
        for username, password in creds:
            test_cmd = [nxc_cmd, "ftp", target, "-u", username, "-p", password]
            result = self.run_command(test_cmd, f"NXC FTP test {username}", timeout=30)
            
            if result.get("success"):
                self.save_results(f"nxc_ftp_{username}.txt", result["stdout"])
                
                if "[+]" in result["stdout"] or "230" in result["stdout"]:
                    ftp_access = True
                    working_creds = (username, password)
                    self.log(f"✓ FTP login successful: {username}:{password if password else '(blank)'}", "SUCCESS")
                    self.add_loot(f"FTP Credentials: {username}:{password if password else '(blank)'}")
                    break
        
        if not ftp_access:
            self.log("No FTP access obtained", "WARNING")
            return
        
        # Now download files using ftplib
        self.log("Downloading files with ftplib...", "INFO")
        
        try:
            import ftplib
            
            username, password = working_creds
            
            try:
                ftp = ftplib.FTP(timeout=10)
                ftp.connect(target, 21)
                ftp.login(username, password)
                
                self.log("✓ FTP connection successful!", "SUCCESS")
                
                with self.results_lock:
                    self.results["vulnerabilities"].append({
                        "name": "FTP Weak/Anonymous Access",
                        "severity": "MEDIUM",
                        "description": f"FTP access available with {username} account"
                    })
                
                # Create loot directory
                ftp_loot_dir = f"{self.loot_dir}/FTP"
                os.makedirs(ftp_loot_dir, exist_ok=True)
                
                # Get banner
                welcome = ftp.getwelcome()
                if welcome:
                    self.log(f"FTP Banner: {welcome}", "INFO")
                    self.save_results("ftp_banner.txt", welcome)
                
                # List files recursively
                self.log("Enumerating FTP directory structure...", "INFO")
                all_files = []
                all_dirs = []
                
                def parse_ftp_list(ftp_obj, current_path="/", depth=0, max_depth=5):
                    if depth > max_depth:
                        return
                    
                    try:
                        items = []
                        ftp_obj.retrlines('LIST', items.append)
                        
                        for item in items:
                            parts = item.split(None, 8)
                            if len(parts) < 9:
                                continue
                            
                            permissions = parts[0]
                            name = parts[8]
                            
                            if name in ['.', '..']:
                                continue
                            
                            full_path = f"{current_path}/{name}".replace('//', '/')
                            
                            if permissions.startswith('d'):
                                all_dirs.append(full_path)
                                try:
                                    ftp_obj.cwd(full_path)
                                    parse_ftp_list(ftp_obj, full_path, depth + 1, max_depth)
                                    ftp_obj.cwd('/')
                                except:
                                    pass
                            else:
                                file_size = parts[4] if len(parts) > 4 else "unknown"
                                all_files.append({
                                    "path": full_path,
                                    "size": file_size,
                                    "permissions": permissions
                                })
                    except Exception as e:
                        self.log(f"Error listing {current_path}: {e}", "WARNING")
                
                parse_ftp_list(ftp, "/", 0, max_depth=3)
                
                # Save file listing
                file_list = f"FTP FILE LISTING (User: {username})\n" + "="*80 + "\n\n"
                file_list += f"Total Files: {len(all_files)}\n"
                file_list += f"Total Directories: {len(all_dirs)}\n\n"
                
                file_list += "DIRECTORIES:\n" + "-"*80 + "\n"
                for dir_path in sorted(all_dirs):
                    file_list += f"{dir_path}\n"
                
                file_list += "\nFILES:\n" + "-"*80 + "\n"
                for file_info in sorted(all_files, key=lambda x: x['path']):
                    file_list += f"{file_info['path']:<60} {file_info['size']:>15} bytes\n"
                
                self.save_results("ftp_file_listing.txt", file_list)
                self.log(f"Found {len(all_files)} files and {len(all_dirs)} directories", "SUCCESS")
                
                # Download interesting files
                interesting_extensions = [
                    '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
                    '.conf', '.config', '.ini', '.xml', '.json',
                    '.sh', '.bat', '.ps1', '.py', '.php', '.asp',
                    '.sql', '.db', '.bak', '.log', '.key', '.pem'
                ]
                
                files_to_download = []
                for file_info in all_files:
                    file_ext = os.path.splitext(file_info['path'])[1].lower()
                    if file_ext in interesting_extensions or len(all_files) <= 20:
                        files_to_download.append(file_info)
                        if len(files_to_download) >= 50:
                            break
                
                if files_to_download:
                    self.log(f"Downloading {len(files_to_download)} interesting files...", "INFO")
                    pbar = self.create_progress_bar("ftp_download", len(files_to_download), "Downloading FTP Files")
                    
                    downloaded_count = 0
                    for file_info in files_to_download:
                        file_path = file_info['path']
                        
                        try:
                            size = int(file_info['size'])
                            if size > 10 * 1024 * 1024:  # 10MB max
                                self.update_progress_bar("ftp_download", 1)
                                continue
                        except:
                            pass
                        
                        local_path = f"{ftp_loot_dir}{file_path}"
                        os.makedirs(os.path.dirname(local_path), exist_ok=True)
                        
                        try:
                            with open(local_path, 'wb') as f:
                                ftp.retrbinary(f'RETR {file_path}', f.write)
                            
                            downloaded_count += 1
                            self.add_loot(f"Downloaded FTP: {file_path}")
                            self.update_progress_bar("ftp_download", 1)
                        except Exception as e:
                            self.update_progress_bar("ftp_download", 1)
                    
                    self.close_progress_bar("ftp_download")
                    self.log(f"Downloaded {downloaded_count} files to {ftp_loot_dir}", "SUCCESS")
                
                ftp.quit()
                
            except ftplib.error_perm as e:
                self.log(f"FTP permission error: {e}", "WARNING")
            except Exception as e:
                self.log(f"FTP error: {e}", "ERROR")
        
        except ImportError:
            self.log("ftplib not available", "ERROR")
    
    def _enumerate_ssh_nxc(self, nxc_cmd: str, target: str):
        """SSH enumeration with NXC"""
        self.log(f"Target: {target}", "INFO")
        
        # Basic SSH info gathering
        self.log("Gathering SSH service information...", "INFO")
        ssh_cmd = [nxc_cmd, "ssh", target]
        ssh_result = self.run_command(ssh_cmd, "NXC SSH info")
        
        if ssh_result.get("success"):
            self.save_results("nxc_ssh_info.txt", ssh_result["stdout"])
            
            # Extract SSH version
            version_match = re.search(r'SSH-[\d\.]+-([^\s]+)', ssh_result["stdout"])
            if version_match:
                ssh_version = version_match.group(1)
                self.log(f"✓ SSH Version: {ssh_version}", "INFO")
                self.add_loot(f"SSH Version: {ssh_version}")
    
    def _enumerate_winrm_nxc(self, nxc_cmd: str, target: str):
        """WinRM enumeration with NXC"""
        self.log(f"Target: {target}", "INFO")
        
        # Test WinRM availability
        self.log("Testing WinRM availability...", "INFO")
        winrm_cmd = [nxc_cmd, "winrm", target]
        winrm_result = self.run_command(winrm_cmd, "NXC WinRM test")
        
        if winrm_result.get("success"):
            self.save_results("nxc_winrm_info.txt", winrm_result["stdout"])
            
            if "winrm" in winrm_result["stdout"].lower():
                self.log("✓ WinRM service detected", "SUCCESS")
                self.add_loot("WinRM Service Available")
    
    def _enumerate_rdp_nxc(self, nxc_cmd: str, target: str):
        """RDP enumeration with NXC"""
        self.log(f"Target: {target}", "INFO")
        
        # Test RDP and check for vulnerabilities
        self.log("Testing RDP service...", "INFO")
        rdp_cmd = [nxc_cmd, "rdp", target]
        rdp_result = self.run_command(rdp_cmd, "NXC RDP test")
        
        if rdp_result.get("success"):
            self.save_results("nxc_rdp_info.txt", rdp_result["stdout"])
            
            # Check for BlueKeep vulnerability
            bluekeep_cmd = [nxc_cmd, "rdp", target, "-M", "bluekeep"]
            bluekeep_result = self.run_command(bluekeep_cmd, "NXC RDP BlueKeep check")
            
            if bluekeep_result.get("success"):
                self.save_results("nxc_rdp_bluekeep.txt", bluekeep_result["stdout"])
                
                if "vulnerable" in bluekeep_result["stdout"].lower():
                    self.log("✓ VULNERABLE to BlueKeep (CVE-2019-0708)!", "SUCCESS")
                    self.add_loot("RDP: Vulnerable to BlueKeep (CVE-2019-0708)")
                    
                    with self.results_lock:
                        self.results["vulnerabilities"].append({
                            "name": "BlueKeep RDP Vulnerability",
                            "severity": "CRITICAL",
                            "description": "CVE-2019-0708 - Remote code execution vulnerability"
                        })
    
    def _enumerate_mssql_nxc(self, nxc_cmd: str, target: str):
        """MSSQL enumeration with NXC"""
        self.log(f"Target: {target}", "INFO")
        
        # Test MSSQL
        self.log("Testing MSSQL service...", "INFO")
        mssql_cmd = [nxc_cmd, "mssql", target]
        mssql_result = self.run_command(mssql_cmd, "NXC MSSQL test")
        
        if mssql_result.get("success"):
            self.save_results("nxc_mssql_info.txt", mssql_result["stdout"])
            
            # Try to enumerate with common credentials
            self.log("Testing MSSQL with common credentials...", "INFO")
            creds = [("sa", ""), ("sa", "sa"), ("", "")]
            
            for username, password in creds:
                cred_cmd = [nxc_cmd, "mssql", target, "-u", username, "-p", password]
                cred_result = self.run_command(cred_cmd, f"NXC MSSQL test {username}")
                
                if cred_result.get("success") and "[+]" in cred_result["stdout"]:
                    self.log(f"✓ MSSQL login successful: {username}:{password}", "SUCCESS")
                    self.add_loot(f"MSSQL Credentials: {username}:{password}")
                    break
    
    def _enumerate_wmi_nxc(self, nxc_cmd: str, target: str):
        """WMI enumeration with NXC"""
        self.log(f"Target: {target}", "INFO")
        
        # Test WMI
        self.log("Testing WMI service...", "INFO")
        wmi_cmd = [nxc_cmd, "wmi", target]
        wmi_result = self.run_command(wmi_cmd, "NXC WMI test")
        
        if wmi_result.get("success"):
            self.save_results("nxc_wmi_info.txt", wmi_result["stdout"])
            self.log("✓ WMI service accessible", "SUCCESS")
    
    def _enumerate_vnc_nxc(self, nxc_cmd: str, target: str):
        """VNC enumeration with NXC"""
        self.log(f"Target: {target}", "INFO")
        
        # Test VNC
        self.log("Testing VNC service...", "INFO")
        vnc_cmd = [nxc_cmd, "vnc", target]
        vnc_result = self.run_command(vnc_cmd, "NXC VNC test")
        
        if vnc_result.get("success"):
            self.save_results("nxc_vnc_info.txt", vnc_result["stdout"])
            
            # Check for no authentication
            if "no authentication" in vnc_result["stdout"].lower() or "none" in vnc_result["stdout"].lower():
                self.log("✓ VNC with NO AUTHENTICATION!", "SUCCESS")
                self.add_loot("VNC: No Authentication Required")
                
                with self.results_lock:
                    self.results["vulnerabilities"].append({
                        "name": "VNC No Authentication",
                        "severity": "HIGH",
                        "description": "VNC server requires no authentication"
                    })
    
    def _parse_smb_shares(self, output: str):
        """Parse SMB share enumeration output"""
        lines = output.split('\n')
        shares_found = []
        
        for line in lines:
            if 'READ' in line or 'WRITE' in line or 'NO ACCESS' in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part in ['READ', 'WRITE', 'READ,WRITE', 'NO', 'ACCESS']:
                        if i > 0:
                            share_name = parts[i-1].strip('[]')
                            permissions = 'NO ACCESS' if part == 'NO' else part
                            shares_found.append((share_name, permissions))
                            break
        
        if shares_found:
            self.log(f"✓ Found {len(shares_found)} shares:", "SUCCESS")
            for share_name, permissions in shares_found:
                self.log(f"  • {share_name}: {permissions}", "INFO")
                self.add_loot(f"SMB Share: {share_name} ({permissions})")
    
    def _parse_smb_users(self, output: str):
        """Parse SMB user enumeration output"""
        user_patterns = [
            r'[\w\-\.]+\\([\w\-\.]+)',
            r'\[\*\]\s+([\w\-\.]+)',
        ]
        
        users_found = set()
        for pattern in user_patterns:
            matches = re.findall(pattern, output)
            users_found.update(matches)
        
        system_accounts = ['guest', 'administrator', 'krbtgt', 'smb', 'nobody', 'root']
        filtered_users = [u for u in users_found 
                        if u.lower() not in system_accounts and len(u) > 2]
        
        if filtered_users:
            self.log(f"✓ Found {len(filtered_users)} users:", "SUCCESS")
            for user in sorted(list(filtered_users))[:15]:
                self.log(f"  • {user}", "INFO")
                self.add_loot(f"SMB User: {user}")
    
    def _parse_password_policy(self, output: str):
        """Parse password policy output"""
        policy_patterns = {
            "Min Password Length": r"Minimum password length:\s*(\d+)",
            "Password History": r"Password history length:\s*(\d+)",
            "Max Password Age": r"Maximum password age:\s*([\d\s\w]+)",
            "Password Complexity": r"Password[_ ]complexity:\s*(\w+)",
            "Lockout Threshold": r"(?:Account lockout threshold|Lockout threshold):\s*(\d+)",
            "Lockout Duration": r"(?:Account lockout duration|Lockout duration):\s*([\d\s\w]+)",
        }
        
        policy_found = False
        policy_info = []
        for field, pattern in policy_patterns.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                policy_found = True
                value = match.group(1)
                self.log(f"  • {field}: {value}", "INFO")
                policy_info.append(f"{field}: {value}")
        
        if policy_found:
            self.log("✓ Password policy retrieved", "SUCCESS")
            self.add_loot(f"Password Policy: {', '.join(policy_info[:3])}")
    
    # Keep old function names for backwards compatibility
    def enumerate_smb_netexec(self):
        """SMB enumeration using NXC - wrapper for backwards compatibility"""
        self.enumerate_nxc_protocol("smb", 445)
    
    def enumerate_ldap_netexec(self):
        """LDAP enumeration using NXC - wrapper for backwards compatibility"""
        self.enumerate_nxc_protocol("ldap", 389)
    
    # ==================== FTP ENUMERATION ====================
    
    def search_exploits(self):
        """Search for exploits using searchsploit"""
        if not self.results["services"]:
            self.log("No services to search exploits for", "WARNING")
            return
        
        self.log(f"Searching for exploits for {len(self.results['services'])} services...", "INFO")
        
        all_exploits = []
        
        for service in self.results["services"]:
            search_string = service.get("search_string", "")
            if not search_string:
                continue
            
            self.log(f"Searching exploits for: {search_string}", "INFO")
            
            # Run searchsploit
            command = ["searchsploit", "-j", search_string]
            result = self.run_command(command, f"Searchsploit: {search_string}")
            
            if result.get("success"):
                try:
                    data = json.loads(result["stdout"])
                    if "RESULTS_EXPLOIT" in data and data["RESULTS_EXPLOIT"]:
                        exploits = data["RESULTS_EXPLOIT"]
                        
                        for exploit in exploits:
                            exploit_info = {
                                "service": search_string,
                                "port": service["port"],
                                "title": exploit.get("Title", ""),
                                "path": exploit.get("Path", ""),
                                "date": exploit.get("Date", ""),
                                "type": exploit.get("Type", "")
                            }
                            all_exploits.append(exploit_info)
                        
                        self.log(f"Found {len(exploits)} exploits for {search_string}", "SUCCESS")
                except json.JSONDecodeError:
                    self.log(f"Failed to parse searchsploit output for {search_string}", "WARNING")
        
        # Save exploits
        if all_exploits:
            self.results["exploits"] = all_exploits
            
            # Save to JSON
            exploit_json = json.dumps(all_exploits, indent=2)
            self.save_results("exploits.json", exploit_json)
            
            # Save readable format
            exploit_txt = "EXPLOIT SEARCH RESULTS\n"
            exploit_txt += "="*80 + "\n\n"
            
            current_service = None
            for exploit in all_exploits:
                if exploit["service"] != current_service:
                    current_service = exploit["service"]
                    exploit_txt += f"\n{'='*80}\n"
                    exploit_txt += f"Service: {current_service} (Port {exploit['port']})\n"
                    exploit_txt += f"{'='*80}\n"
                
                exploit_txt += f"\nTitle: {exploit['title']}\n"
                exploit_txt += f"Path:  {exploit['path']}\n"
                exploit_txt += f"Date:  {exploit['date']}\n"
                exploit_txt += f"Type:  {exploit['type']}\n"
            
            self.save_results("exploits.txt", exploit_txt)
            
            self.log(f"Total exploits found: {len(all_exploits)}", "SUCCESS")
            self.display_status()
    
    # ==================== MAIN SCAN FLOW ====================
    
    def run_scan(self):
        """Main scanning workflow"""
        try:
            # Phase 1: Quick scan (discover open ports)
            self.log("=" * 60, "INFO")
            self.log("PHASE 1: QUICK PORT SCAN", "INFO")
            self.log("=" * 60, "INFO")
            self.nmap_quick_scan()
            
            # Phase 2: Targeted service/script scan on discovered ports
            if self.results["ports"]:
                self.log("=" * 60, "INFO")
                self.log("PHASE 2: SERVICE/SCRIPT SCAN ON DISCOVERED PORTS", "INFO")
                self.log("=" * 60, "INFO")
                self.nmap_service_scan()
            
            # Start full scan in background (will continue while we do other work)
            self.log("=" * 60, "INFO")
            self.log("STARTING BACKGROUND FULL SCAN (ALL PORTS)", "INFO")
            self.log("=" * 60, "INFO")
            self.nmap_full_scan_background()
            
            # Phase 3: Domain detection & subdomain enumeration (WHILE full scan runs)
            if self.results["ports"]:
                self.log("=" * 60, "INFO")
                self.log("PHASE 3: DOMAIN DETECTION & SUBDOMAIN ENUMERATION", "INFO")
                self.log("(Full Nmap scan running in background)", "INFO")
                self.log("=" * 60, "INFO")
                self.check_web_redirects()
                
                if self.results["domains"]:
                    self.log("Domain discovery complete. Subdomains added to /etc/hosts", "SUCCESS")
            
            # Wait for full scan to complete before service enumeration
            self.wait_for_full_scan()
            
            # Phase 4: Service Enumeration (PARALLEL EXECUTION with NXC + Native Tools)
            # Map ports to protocols for NXC enumeration
            protocol_port_map = {
                "smb": [139, 445],
                "ldap": [389, 636, 3268, 3269],
                "ftp": [21],
                "ssh": [22],
                "winrm": [5985, 5986],
                "rdp": [3389],
                "mssql": [1433],
                "wmi": [135],
                "vnc": [5900, 5901, 5902, 5903]
            }
            
            # Also enumerate NFS with native tools
            nfs_services = [p for p in self.results["ports"] if p["port"] in [111, 2049]]
            
            self.log("Checking for services to enumerate...", "INFO")
            
            enumeration_tasks = []
            
            # Detect NXC-enumerable services
            for protocol, ports in protocol_port_map.items():
                found_ports = [p for p in self.results["ports"] if p["port"] in ports]
                if found_ports:
                    self.log(f"{protocol.upper()} ports found: {[p['port'] for p in found_ports]}", "INFO")
                    # Use lambda to capture protocol value
                    enumeration_tasks.append((
                        protocol.upper(), 
                        lambda p=protocol: self.enumerate_nxc_protocol(p, 0)
                    ))
                    self.log(f"Added {protocol.upper()} enumeration (NXC) to task queue", "INFO")
            
            # Add NFS enumeration (native tool)
            if nfs_services:
                self.log(f"NFS ports found: {[p['port'] for p in nfs_services]}", "INFO")
                enumeration_tasks.append(("NFS", self.enumerate_nfs))
                self.log("Added NFS enumeration to task queue", "INFO")
            
            # Note: FTP is handled by both NXC and native - we'll use native for file downloading
            # but NXC already tested anonymous access
            
            if enumeration_tasks:
                self.log("=" * 60, "INFO")
                self.log(f"PHASE 4: SERVICE ENUMERATION (PARALLEL - {len(enumeration_tasks)} TASKS)", "INFO")
                self.log("=" * 60, "INFO")
                
                # Create progress bar for service enumeration
                pbar = self.create_progress_bar("service_enum", len(enumeration_tasks), "Service Enumeration")
                
                # Execute enumeration tasks in parallel
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {executor.submit(task_func): task_name 
                              for task_name, task_func in enumeration_tasks}
                    
                    for future in as_completed(futures):
                        task_name = futures[future]
                        try:
                            future.result()
                            self.log(f"Completed: {task_name}", "SUCCESS")
                        except Exception as e:
                            self.log(f"Error in {task_name}: {e}", "ERROR")
                        
                        self.update_progress_bar("service_enum", 1)
                
                self.close_progress_bar("service_enum")
            
            # Phase 5: Web Enumeration
            web_ports = [p for p in self.results["ports"] if p["port"] in [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]]
            if web_ports:
                self.log("=" * 60, "INFO")
                self.log("PHASE 5: WEB ENUMERATION", "INFO")
                self.log("=" * 60, "INFO")
                
                # Run Nikto
                self.enumerate_nikto()
                
                # Run Feroxbuster
                self.enumerate_feroxbuster()
            
            # Phase 6: Exploit Search
            self.log("=" * 60, "INFO")
            self.log("PHASE 6: EXPLOIT SEARCH", "INFO")
            self.log("=" * 60, "INFO")
            self.search_exploits()
            
            # Final summary
            self.log("=" * 60, "SUCCESS")
            self.log("SCAN COMPLETE!", "SUCCESS")
            self.log("=" * 60, "SUCCESS")
            self.log(f"Results saved to: {self.base_dir}", "INFO")
            self.log(f"Total ports found: {len(self.results['ports'])}", "INFO")
            self.log(f"Total services found: {len(self.results['services'])}", "INFO")
            self.log(f"Total loot items: {len(self.results['loot'])}", "INFO")
            self.log(f"Total exploits found: {len(self.results['exploits'])}", "INFO")
            
            # Display final status
            self.display_status()
            
        except KeyboardInterrupt:
            self.log("\n\nScan interrupted by user", "WARNING")
            self.log(f"Partial results saved to: {self.base_dir}", "INFO")
            sys.exit(1)
        except Exception as e:
            self.log(f"Fatal error: {e}", "ERROR")
            import traceback
            traceback.print_exc()
            sys.exit(1)


# ==================== MAIN ENTRY POINT ====================

def main():
    parser = argparse.ArgumentParser(
        description="IcyScan - Custom Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 10.10.10.10
  %(prog)s -t example.com -o results
  %(prog)s -t 10.10.10.10 --threads 8
  
The tool will:
  1. Run quick Nmap scan (well-known ports)
  2. Detect domains from web redirects
  3. Enumerate subdomains in parallel (ffuf + gobuster)
  4. Add all domains/subdomains to /etc/hosts
  5. Run full Nmap scan (all ports + service detection) in BACKGROUND
  6. Enumerate services in parallel (SMB, LDAP, FTP)
  7. Run web enumeration (Nikto) on all web services
  8. Search for exploits using searchsploit
  9. Display live results and save to Scans/ directory
  
Multi-threading:
  - Default: 5 threads (balanced)
  - Recommended for 16GB RAM: 8-10 threads
  - Maximum: 15 threads
  
Progress bars require tqdm: pip install tqdm --break-system-packages
  
This order ensures web enumeration tools have access to all 
discovered domains, and Nikto scans all web services with proper
domain names in /etc/hosts.
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-o", "--output", default="IcyScan", help="Output directory (default: IcyScan)")
    parser.add_argument("--threads", type=int, default=5, 
                       help="Number of concurrent threads (default: 5, recommended: 8-10 for 16GB RAM)")
    
    args = parser.parse_args()
    
    # Validate thread count
    if args.threads > 15:
        print(f"{Colors.YELLOW}[!] Warning: {args.threads} threads may be excessive. Recommended max: 15{Colors.END}")
        response = input("Continue? (y/n): ")
        if response.lower() != 'y':
            sys.exit(0)
    
    # Initialize and run IcyScan
    scanner = IcyScan(args.target, args.output, args.threads)
    scanner.run_scan()


if __name__ == "__main__":
    main()
