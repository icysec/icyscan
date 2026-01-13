#!/usr/bin/env python3
"""
IcyScan - Interactive CLI
Version: 1.1
Release: January 2026

Interactive command-line interface for network enumeration
"""

__version__ = "1.1"

import cmd2
from cmd2 import Cmd, with_argparser
import argparse
import sys
import os
import random
from typing import Dict, Any, List, Optional

# Import the main IcyScan class
try:
    from icyscan import IcyScan, Colors
except ImportError:
    print("Error: Could not import icyscan.py")
    print("Make sure icyscan.py is in the same directory")
    sys.exit(1)


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
    f"""{Colors.CYAN}{Colors.BOLD}
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
              Network Enumeration Framework v1.1
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


class IcyScanInteractiveCLI(cmd2.Cmd):
    """Interactive CLI for IcyScan"""
    
    # Set nano as default editor
    editor = 'nano'
    
    # Select random banner at startup
    selected_banner = random.choice(BANNERS)
    
    # Banner
    intro = f"""{selected_banner}
{Colors.BOLD}IcyScan v{__version__} - Interactive Enumeration Framework{Colors.END}

{Colors.YELLOW}First time? Start here:{Colors.END}
  {Colors.GREEN}set target <IP|hostname>{Colors.END}  - {Colors.BOLD}(REQUIRED){Colors.END} Set your target
  {Colors.CYAN}scan quick{Colors.END}                 - Run quick port scan
  {Colors.CYAN}show loot{Colors.END}                  - Show findings

Type {Colors.CYAN}help{Colors.END} for all commands or {Colors.CYAN}tutorial{Colors.END} for a complete guide.
"""
    
    prompt = f"{Colors.CYAN}icyscan>{Colors.END} "
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Set nano as default editor (instead of vim)
        self.editor = 'nano'
        
        # Session state
        self.session = {
            'target': None,
            'threads': 5,
            'output_dir': 'Scans',
            'scanner': None,
            'scan_complete': False
        }
        
        # Command history file
        self.history_file = os.path.expanduser('~/.icyscan_history')
        
        # Categories for help
        self.categories = {
            'Configuration': ['set', 'show', 'options'],
            'Scanning': ['scan'],
            'Enumeration': ['enum'],
            'Results': ['show'],
            'Utilities': ['clear', 'tutorial', 'exit', 'quit']
        }
    
    def _check_target_set(self):
        """Check if target is set, show error if not"""
        if not self.session['target']:
            self.perror("Target not set. Use: set target <IP|hostname>")
            self.poutput(f"{Colors.YELLOW}Example:{Colors.END} set target 10.10.10.10")
            return False
        return True
    
    # ==================== CONFIGURATION COMMANDS ====================
    
    set_parser = argparse.ArgumentParser()
    set_parser.add_argument('variable', choices=['target', 'threads', 'output'],
                           help='Variable to set')
    set_parser.add_argument('value', help='Value to set')
    
    @with_argparser(set_parser)
    def do_set(self, args):
        """Set configuration variables
        
        Usage:
            set target <IP|hostname>    - Set target host
            set threads <number>        - Set number of threads (1-15)
            set output <directory>      - Set output directory
            
        Examples:
            set target 10.10.10.10
            set threads 10
            set output MyResults
        """
        if args.variable == 'target':
            self.session['target'] = args.value
            self.poutput(f"{Colors.GREEN}[+]{Colors.END} Target set to: {Colors.BOLD}{args.value}{Colors.END}")
            
            # Reset scanner if target changes
            if self.session['scanner']:
                self.session['scanner'] = None
                self.session['scan_complete'] = False
                self.poutput(f"{Colors.YELLOW}[!]{Colors.END} Previous scan data cleared")
        
        elif args.variable == 'threads':
            try:
                threads = int(args.value)
                if threads < 1 or threads > 15:
                    self.perror("Threads must be between 1 and 15")
                    return
                self.session['threads'] = threads
                self.poutput(f"{Colors.GREEN}[+]{Colors.END} Threads set to: {threads}")
            except ValueError:
                self.perror("Threads must be a number")
        
        elif args.variable == 'output':
            self.session['output_dir'] = args.value
            self.poutput(f"{Colors.GREEN}[+]{Colors.END} Output directory set to: {args.value}")
    
    def do_options(self, args):
        """Show current configuration options"""
        self.poutput(f"\n{Colors.BOLD}Current Configuration:{Colors.END}")
        self.poutput(f"{'='*60}")
        
        # Highlight if target is not set
        if self.session['target']:
            self.poutput(f"Target:      {Colors.GREEN}{self.session['target']}{Colors.END}")
        else:
            self.poutput(f"Target:      {Colors.RED}Not set (REQUIRED){Colors.END}")
            self.poutput(f"{Colors.YELLOW}             Use: set target <IP|hostname>{Colors.END}")
        
        self.poutput(f"Threads:     {self.session['threads']}")
        self.poutput(f"Output Dir:  {self.session['output_dir']}")
        
        if self.session['scanner']:
            self.poutput(f"Status:      {Colors.GREEN}Scanner initialized{Colors.END}")
            self.poutput(f"Scan Status: {'Complete' if self.session['scan_complete'] else 'In progress / Not started'}")
        else:
            if self.session['target']:
                self.poutput(f"Status:      {Colors.YELLOW}Scanner not initialized{Colors.END}")
            else:
                self.poutput(f"Status:      {Colors.RED}Waiting for target{Colors.END}")
        self.poutput(f"{'='*60}\n")
    
    show_parser = argparse.ArgumentParser()
    show_parser.add_argument('item', 
                            choices=['options', 'ports', 'services', 'domains', 'loot', 'exploits', 'vulns'],
                            help='Item to show')
    
    @with_argparser(show_parser)
    def do_show(self, args):
        """Show various information
        
        Usage:
            show options    - Show current configuration
            show ports      - Show discovered ports
            show services   - Show identified services
            show domains    - Show discovered domains
            show loot       - Show collected loot
            show exploits   - Show available exploits
            show vulns      - Show vulnerabilities
            
        Examples:
            show ports
            show loot
        """
        if args.item == 'options':
            self.do_options('')
            return
        
        if not self.session['scanner']:
            self.perror("No scan data available. Run a scan first.")
            return
        
        scanner = self.session['scanner']
        
        if args.item == 'ports':
            self._show_ports(scanner)
        elif args.item == 'services':
            self._show_services(scanner)
        elif args.item == 'domains':
            self._show_domains(scanner)
        elif args.item == 'loot':
            self._show_loot(scanner)
        elif args.item == 'exploits':
            self._show_exploits(scanner)
        elif args.item == 'vulns':
            self._show_vulnerabilities(scanner)
    
    # ==================== SCANNING COMMANDS ====================
    
    scan_parser = argparse.ArgumentParser()
    scan_parser.add_argument('type', 
                            choices=['quick', 'full', 'service', 'web', 'all'],
                            help='Type of scan')
    
    @with_argparser(scan_parser)
    def do_scan(self, args):
        """Run various types of scans
        
        Usage:
            scan quick      - Quick port scan (top 100 ports)
            scan full       - Full port scan (all 65,535 ports)
            scan service    - Service detection on discovered ports
            scan web        - Web enumeration only
            scan all        - Complete enumeration (everything)
            
        Examples:
            scan quick
            scan all
        """
        if not self._check_target_set():
            return
        
        # Initialize scanner if needed
        if not self.session['scanner']:
            self.poutput(f"{Colors.CYAN}[*]{Colors.END} Initializing scanner...")
            try:
                self.session['scanner'] = IcyScan(
                    self.session['target'],
                    self.session['output_dir'],
                    self.session['threads']
                )
            except Exception as e:
                self.perror(f"Failed to initialize scanner: {e}")
                return
        
        scanner = self.session['scanner']
        
        try:
            if args.type == 'quick':
                self.poutput(f"{Colors.CYAN}[*]{Colors.END} Running quick port scan...")
                scanner.nmap_quick_scan()
                self._show_ports(scanner)
            
            elif args.type == 'full':
                self.poutput(f"{Colors.CYAN}[*]{Colors.END} Running full port scan...")
                scanner.nmap_full_scan_background()
                scanner.wait_for_full_scan()
                self._show_ports(scanner)
            
            elif args.type == 'service':
                if not scanner.results['ports']:
                    self.perror("No ports discovered. Run 'scan quick' first.")
                    return
                self.poutput(f"{Colors.CYAN}[*]{Colors.END} Running service detection...")
                scanner.nmap_service_scan()
                self._show_services(scanner)
            
            elif args.type == 'web':
                web_ports = [p for p in scanner.results['ports'] if p['port'] in [80, 443, 8080, 8443]]
                if not web_ports:
                    self.perror("No web ports found. Run 'scan quick' first.")
                    return
                self.poutput(f"{Colors.CYAN}[*]{Colors.END} Running web enumeration...")
                scanner.enumerate_nikto()
                scanner.enumerate_feroxbuster()
                self.poutput(f"{Colors.GREEN}[+]{Colors.END} Web enumeration complete")
            
            elif args.type == 'all':
                self.poutput(f"{Colors.CYAN}[*]{Colors.END} Running complete enumeration...")
                self.poutput(f"{Colors.YELLOW}[!]{Colors.END} This may take 20-30 minutes...")
                scanner.run_scan()
                self.session['scan_complete'] = True
                self.poutput(f"{Colors.GREEN}[+]{Colors.END} Complete scan finished!")
                self.do_show(argparse.Namespace(item='loot'))
        
        except KeyboardInterrupt:
            self.poutput(f"\n{Colors.YELLOW}[!]{Colors.END} Scan interrupted by user")
        except Exception as e:
            self.perror(f"Scan error: {e}")
    
    
    # ==================== ENUMERATION COMMANDS ====================
    
    enum_parser = argparse.ArgumentParser()
    enum_parser.add_argument('service', 
                            choices=['smb', 'ldap', 'ftp', 'ssh', 'nfs', 'rdp', 'winrm', 'mssql', 'web', 'all'],
                            help='Service to enumerate')
    
    @with_argparser(enum_parser)
    def do_enum(self, args):
        """Enumerate specific services
        
        Usage:
            enum smb        - Enumerate SMB (NetExec)
            enum ldap       - Enumerate LDAP (NetExec)
            enum ftp        - Enumerate FTP
            enum ssh        - Enumerate SSH
            enum nfs        - Enumerate NFS
            enum rdp        - Enumerate RDP
            enum winrm      - Enumerate WinRM
            enum mssql      - Enumerate MSSQL
            enum web        - Enumerate web services
            enum all        - Enumerate all services
            
        Examples:
            enum smb
            enum all
        """
        if not self._check_target_set():
            return
        
        if not self.session['scanner']:
            self.perror("Scanner not initialized. Run 'scan quick' first.")
            return
        
        scanner = self.session['scanner']
        
        if not scanner.results['ports']:
            self.perror("No ports discovered. Run 'scan quick' first.")
            return
        
        try:
            if args.service == 'smb':
                self.poutput(f"{Colors.CYAN}[*]{Colors.END} Enumerating SMB...")
                scanner.enumerate_nxc_protocol('smb', 445)
            
            elif args.service == 'ldap':
                self.poutput(f"{Colors.CYAN}[*]{Colors.END} Enumerating LDAP...")
                scanner.enumerate_nxc_protocol('ldap', 389)
            
            elif args.service == 'ftp':
                self.poutput(f"{Colors.CYAN}[*]{Colors.END} Enumerating FTP...")
                scanner.enumerate_nxc_protocol('ftp', 21)
            
            elif args.service == 'ssh':
                self.poutput(f"{Colors.CYAN}[*]{Colors.END} Enumerating SSH...")
                scanner.enumerate_nxc_protocol('ssh', 22)
            
            elif args.service == 'nfs':
                self.poutput(f"{Colors.CYAN}[*]{Colors.END} Enumerating NFS...")
                scanner.enumerate_nfs()
            
            elif args.service == 'rdp':
                self.poutput(f"{Colors.CYAN}[*]{Colors.END} Enumerating RDP...")
                scanner.enumerate_nxc_protocol('rdp', 3389)
            
            elif args.service == 'winrm':
                self.poutput(f"{Colors.CYAN}[*]{Colors.END} Enumerating WinRM...")
                scanner.enumerate_nxc_protocol('winrm', 5985)
            
            elif args.service == 'mssql':
                self.poutput(f"{Colors.CYAN}[*]{Colors.END} Enumerating MSSQL...")
                scanner.enumerate_nxc_protocol('mssql', 1433)
            
            elif args.service == 'web':
                self.poutput(f"{Colors.CYAN}[*]{Colors.END} Enumerating web services...")
                scanner.enumerate_nikto()
                scanner.enumerate_feroxbuster()
            
            elif args.service == 'all':
                self.poutput(f"{Colors.CYAN}[*]{Colors.END} Enumerating all services...")
                self.poutput(f"{Colors.YELLOW}[!]{Colors.END} This may take several minutes...")
                
                # Enumerate based on open ports
                port_map = {
                    'smb': [139, 445],
                    'ldap': [389, 636],
                    'ftp': [21],
                    'ssh': [22],
                    'rdp': [3389],
                    'winrm': [5985, 5986],
                    'mssql': [1433],
                    'nfs': [111, 2049]
                }
                
                for service, ports in port_map.items():
                    if any(p['port'] in ports for p in scanner.results['ports']):
                        self.poutput(f"{Colors.CYAN}[*]{Colors.END} Enumerating {service.upper()}...")
                        if service == 'nfs':
                            scanner.enumerate_nfs()
                        else:
                            scanner.enumerate_nxc_protocol(service, ports[0])
                
                # Web enumeration
                web_ports = [p for p in scanner.results['ports'] if p['port'] in [80, 443, 8080, 8443]]
                if web_ports:
                    self.poutput(f"{Colors.CYAN}[*]{Colors.END} Enumerating web services...")
                    scanner.enumerate_nikto()
                    scanner.enumerate_feroxbuster()
            
            self.poutput(f"{Colors.GREEN}[+]{Colors.END} Enumeration complete")
            self._show_loot(scanner)
        
        except Exception as e:
            self.perror(f"Enumeration error: {e}")
    
    
    # ==================== RESULTS COMMANDS ====================
    
    # ==================== UTILITY COMMANDS ====================
    
    def do_tutorial(self, args):
        """Show a quick start tutorial"""
        tutorial = f"""
{Colors.BOLD}IcyScan Quick Start Tutorial{Colors.END}
{Colors.CYAN}{'='*60}{Colors.END}

{Colors.BOLD}1. Set your target:{Colors.END}
   {Colors.GREEN}set target 10.10.10.10{Colors.END}
   {Colors.GREEN}set threads 10{Colors.END}

{Colors.BOLD}2. Run a quick scan:{Colors.END}
   {Colors.GREEN}scan quick{Colors.END}

{Colors.BOLD}3. View discovered ports:{Colors.END}
   {Colors.GREEN}show ports{Colors.END}

{Colors.BOLD}4. Enumerate specific services:{Colors.END}
   {Colors.GREEN}enum smb{Colors.END}
   {Colors.GREEN}enum ldap{Colors.END}
   {Colors.GREEN}enum web{Colors.END}

{Colors.BOLD}5. Or enumerate everything:{Colors.END}
   {Colors.GREEN}enum all{Colors.END}

{Colors.BOLD}6. View your findings:{Colors.END}
   {Colors.GREEN}show loot{Colors.END}
   {Colors.GREEN}show exploits{Colors.END}
   {Colors.GREEN}show vulns{Colors.END}

{Colors.BOLD}Complete Workflow Example:{Colors.END}
   {Colors.GREEN}set target 10.10.10.10{Colors.END}
   {Colors.GREEN}scan quick{Colors.END}
   {Colors.GREEN}enum all{Colors.END}
   {Colors.GREEN}show loot{Colors.END}

{Colors.BOLD}For a full automated scan:{Colors.END}
   {Colors.GREEN}set target 10.10.10.10{Colors.END}
   {Colors.GREEN}scan all{Colors.END}

{Colors.CYAN}{'='*60}{Colors.END}
Type {Colors.CYAN}help <command>{Colors.END} for detailed help on any command.
"""
        self.poutput(tutorial)
    
    def do_clear(self, args):
        """Clear the screen"""
        os.system('clear' if os.name != 'nt' else 'cls')
    
    def do_banner(self, args):
        """Display a random IcyScan banner"""
        banner = random.choice(BANNERS)
        self.poutput(banner)
        self.poutput(f"{Colors.BOLD}IcyScan v{__version__} - Interactive Enumeration Framework{Colors.END}\n")
    
    def do_exit(self, args):
        """Exit IcyScan"""
        self.poutput(f"\n{Colors.CYAN}[*]{Colors.END} Exiting IcyScan. Happy hacking! 🧊")
        return True
    
    def do_quit(self, args):
        """Exit IcyScan"""
        return self.do_exit(args)
    
    # ==================== DISPLAY HELPER METHODS ====================
    
    def _show_ports(self, scanner):
        """Display discovered ports in a table"""
        if not scanner.results['ports']:
            self.poutput(f"{Colors.YELLOW}[!]{Colors.END} No ports discovered yet")
            return
        
        self.poutput(f"\n{Colors.BOLD}Discovered Ports:{Colors.END}")
        self.poutput(f"{Colors.CYAN}{'='*60}{Colors.END}")
        self.poutput(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<20}")
        self.poutput(f"{'-'*60}")
        
        for port in scanner.results['ports']:
            port_num = port.get('port', 'N/A')
            state = port.get('state', 'open')
            service = port.get('service', 'unknown')
            self.poutput(f"{port_num:<10} {state:<10} {service:<20}")
        
        self.poutput(f"{Colors.CYAN}{'='*60}{Colors.END}\n")
    
    def _show_services(self, scanner):
        """Display identified services"""
        if not scanner.results['services']:
            self.poutput(f"{Colors.YELLOW}[!]{Colors.END} No services identified yet")
            return
        
        self.poutput(f"\n{Colors.BOLD}Identified Services:{Colors.END}")
        self.poutput(f"{Colors.CYAN}{'='*60}{Colors.END}")
        
        for service in scanner.results['services']:
            port = service.get('port', 'N/A')
            name = service.get('service', 'unknown')
            version = service.get('version', '')
            self.poutput(f"Port {port:<6} {name} {version}")
        
        self.poutput(f"{Colors.CYAN}{'='*60}{Colors.END}\n")
    
    def _show_domains(self, scanner):
        """Display discovered domains"""
        domains = scanner.results.get('domains', [])
        subdomains = scanner.results.get('subdomains', [])
        
        if not domains and not subdomains:
            self.poutput(f"{Colors.YELLOW}[!]{Colors.END} No domains discovered yet")
            return
        
        self.poutput(f"\n{Colors.BOLD}Discovered Domains:{Colors.END}")
        self.poutput(f"{Colors.CYAN}{'='*60}{Colors.END}")
        
        if domains:
            self.poutput(f"\n{Colors.BOLD}Domains:{Colors.END}")
            for domain in domains:
                self.poutput(f"  • {domain}")
        
        if subdomains:
            self.poutput(f"\n{Colors.BOLD}Subdomains:{Colors.END}")
            for subdomain in subdomains:
                self.poutput(f"  • {subdomain}")
        
        self.poutput(f"\n{Colors.CYAN}{'='*60}{Colors.END}\n")
    
    def _show_loot(self, scanner):
        """Display collected loot"""
        if not scanner.results['loot']:
            self.poutput(f"{Colors.YELLOW}[!]{Colors.END} No loot collected yet")
            return
        
        self.poutput(f"\n{Colors.BOLD}Collected Loot:{Colors.END}")
        self.poutput(f"{Colors.GREEN}{'='*60}{Colors.END}")
        
        for item in scanner.results['loot']:
            self.poutput(f"{Colors.GREEN}[+]{Colors.END} {item}")
        
        self.poutput(f"{Colors.GREEN}{'='*60}{Colors.END}")
        self.poutput(f"\nTotal items: {len(scanner.results['loot'])}\n")
    
    def _show_exploits(self, scanner):
        """Display available exploits"""
        if not scanner.results['exploits']:
            self.poutput(f"{Colors.YELLOW}[!]{Colors.END} No exploits found yet. Run 'scan all' or search manually.")
            return
        
        self.poutput(f"\n{Colors.BOLD}Available Exploits:{Colors.END}")
        self.poutput(f"{Colors.RED}{'='*60}{Colors.END}")
        
        for exploit in scanner.results['exploits']:
            service = exploit.get('service', 'unknown')
            port = exploit.get('port', 'N/A')
            title = exploit.get('title', 'No title')
            self.poutput(f"\n{Colors.BOLD}Service:{Colors.END} {service} (Port {port})")
            self.poutput(f"{Colors.BOLD}Exploit:{Colors.END} {title}")
        
        self.poutput(f"\n{Colors.RED}{'='*60}{Colors.END}")
        self.poutput(f"\nTotal exploits: {len(scanner.results['exploits'])}\n")
    
    def _show_vulnerabilities(self, scanner):
        """Display identified vulnerabilities"""
        if not scanner.results.get('vulnerabilities'):
            self.poutput(f"{Colors.YELLOW}[!]{Colors.END} No vulnerabilities identified yet")
            return
        
        self.poutput(f"\n{Colors.BOLD}Identified Vulnerabilities:{Colors.END}")
        self.poutput(f"{Colors.RED}{'='*60}{Colors.END}")
        
        for vuln in scanner.results['vulnerabilities']:
            name = vuln.get('name', 'Unknown')
            severity = vuln.get('severity', 'UNKNOWN')
            desc = vuln.get('description', 'No description')
            
            # Color code severity
            severity_color = Colors.RED if severity == 'HIGH' or severity == 'CRITICAL' else Colors.YELLOW
            
            self.poutput(f"\n{Colors.BOLD}Name:{Colors.END} {name}")
            self.poutput(f"{Colors.BOLD}Severity:{Colors.END} {severity_color}{severity}{Colors.END}")
            self.poutput(f"{Colors.BOLD}Description:{Colors.END} {desc}")
        
        self.poutput(f"\n{Colors.RED}{'='*60}{Colors.END}")
        self.poutput(f"\nTotal vulnerabilities: {len(scanner.results['vulnerabilities'])}\n")


def main():
    """Main entry point for interactive CLI"""
    import sys
    
    # Check if running with sudo
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}[!] Warning: Not running as root. Some features (NFS mounting, /etc/hosts) may not work.{Colors.END}")
        print(f"{Colors.YELLOW}[!] Recommended: sudo python3 icyscan_interactive.py{Colors.END}\n")
    
    # Start interactive CLI
    cli = IcyScanInteractiveCLI()
    
    # If arguments provided, run in non-interactive mode
    if len(sys.argv) > 1:
        # Process command line args (compatibility with old CLI)
        parser = argparse.ArgumentParser()
        parser.add_argument('-t', '--target', help='Target IP or hostname')
        parser.add_argument('--threads', type=int, default=5, help='Number of threads')
        parser.add_argument('-o', '--output', default='Scans', help='Output directory')
        args = parser.parse_args()
        
        if args.target:
            cli.onecmd(f"set target {args.target}")
            cli.onecmd(f"set threads {args.threads}")
            cli.onecmd(f"set output {args.output}")
            cli.onecmd("scan all")
            return
    
    # Run interactive mode
    try:
        cli.cmdloop()
    except KeyboardInterrupt:
        print(f"\n{Colors.CYAN}[*]{Colors.END} Exiting IcyScan. Happy hacking! 🧊")
        sys.exit(0)


if __name__ == '__main__':
    main()
