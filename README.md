# 🧊 IcyScan - Advanced Network Enumeration Framework

**Version:** 1.1  
**Release:** January 2026  
**Purpose:** Automated reconnaissance and enumeration for penetration testing

IcyScan is a network enumeration framework I built to automate the tedious parts of reconnaissance. It's designed to be fast, thorough, and easy to configure for different scenarios (CTF, pentesting, bug bounty, etc.).

**New in v1.1:** Interactive CLI mode for modular, customizable enumeration!

---

## 🎯 Two Ways to Use IcyScan

### **1. Original CLI Mode (v1.0)** - Automated Full Scans
Perfect for quick, complete enumeration in one command.

```bash
sudo ./icyscan.py -t 10.10.10.10 --threads 10
```

### **2. Interactive Mode (v1.1)** - Modular Testing
Perfect for manual pentesting with granular control.

```bash
sudo python3 icyscan_interactive.py

icyscan> set target 10.10.10.10
icyscan> scan quick
icyscan> enum smb
icyscan> show loot
```

Choose the mode that fits your workflow!

---

## 🚀 Quick Start

### **Installation**

```bash
# 1. Install Python dependencies
pip install tqdm pyyaml cmd2 --break-system-packages

# 2. Install required tools (if not already installed)
sudo apt update
sudo apt install -y nmap nikto feroxbuster ffuf gobuster showmount nfs-common curl

# 3. Install NetExec (nxc) for SMB/LDAP enumeration
pipx install netexec
# Or if pipx not available:
pip install netexec --break-system-packages

# 4. Make executable
chmod +x icyscan.py icyscan_interactive.py

# 5. Run with sudo (required for NFS mounting and /etc/hosts)
sudo ./icyscan.py -t 10.10.10.10
# OR
sudo python3 icyscan_interactive.py
```

### **Basic Usage - Original CLI Mode**

```bash
# Scan single target with defaults (5 threads)
sudo ./icyscan.py -t 10.10.10.10

# Scan with more threads (recommended for 16GB RAM)
sudo ./icyscan.py -t 10.10.10.10 --threads 10

# Scan domain
sudo ./icyscan.py -t example.htb --threads 8

# Custom output directory
sudo ./icyscan.py -t 10.10.10.10 -o MyResults
```

### **Basic Usage - Interactive Mode**

```bash
# Launch interactive console
sudo python3 icyscan_interactive.py

# Inside the console:
icyscan> set target 10.10.10.10     # Set your target
icyscan> set threads 10              # Adjust threads
icyscan> scan quick                  # Quick port scan
icyscan> show ports                  # View results
icyscan> enum smb                    # Enumerate SMB
icyscan> enum all                    # Enumerate all services
icyscan> show loot                   # View findings
icyscan> exit                        # Exit when done
```

---

## 🎮 Interactive Mode (v1.1)

### **Why Use Interactive Mode?**

Interactive mode gives you **modular control** over the enumeration process - perfect for manual pentesting where you want to explore targets step-by-step.

**Benefits:**
- ✅ Run only the scans you need
- ✅ Test specific services without full enumeration
- ✅ Results stay in memory (no re-scanning)
- ✅ Interactive command interface
- ✅ Command history with arrow keys
- ✅ Random ASCII art banners at startup

### **Interactive Commands**

**Configuration:**
```bash
set target <IP|hostname>    # Set target
set threads <number>        # Set thread count (1-15)
set output <directory>      # Set output directory
options                     # Show current config
```

**Scanning:**
```bash
scan quick      # Quick port scan (top 100 ports)
scan full       # Full port scan (all 65,535 ports)
scan service    # Service detection on discovered ports
scan web        # Web enumeration only
scan all        # Complete enumeration (everything)
```

**Enumeration:**
```bash
enum smb        # Enumerate SMB with NetExec
enum ldap       # Enumerate LDAP with NetExec
enum ftp        # Enumerate FTP
enum ssh        # Enumerate SSH
enum nfs        # Enumerate NFS
enum rdp        # Enumerate RDP
enum winrm      # Enumerate WinRM
enum mssql      # Enumerate MSSQL
enum web        # Run Nikto + Feroxbuster
enum all        # Enumerate all discovered services
```

**Results:**
```bash
show options    # Show configuration
show ports      # Show discovered ports
show services   # Show identified services
show domains    # Show discovered domains
show loot       # Show collected loot
show exploits   # Show available exploits
show vulns      # Show vulnerabilities
```

**Utilities:**
```bash
help                # List all commands
help <command>      # Get help on specific command
tutorial            # Show quick start guide
banner              # Display random ASCII art
clear               # Clear screen
exit                # Exit (or 'quit')
```

### **Interactive Workflow Example**

```bash
$ sudo python3 icyscan_interactive.py

  d8,                                                    
 `8P                                                     
                                                         
  88b d8888b?88   d8P  .d888b, d8888b d888b8b    88bd88b 
  88Pd8P' `Pd88   88   ?8b,   d8P' `Pd8P' ?88    88P' ?8b
 d88 88b    ?8(  d88     `?8b 88b    88b  ,88b  d88   88P
d88' `?888P'`?88P'?8b `?888P' `?888P'`?88P'`88bd88'   88b
                   )88                                   
                  ,d8P                                   
               `?888P' 

IcyScan v1.1 - Interactive Enumeration Framework

# Set target and scan
icyscan> set target 10.10.10.10
[+] Target set to: 10.10.10.10

icyscan> scan quick
[*] Running quick port scan...
[████████████████████] 100%
[+] Found 5 open ports: 21, 22, 80, 445, 3389

# View results
icyscan> show ports
PORT    STATE   SERVICE
21      open    ftp
22      open    ssh
80      open    http
445     open    microsoft-ds
3389    open    ms-wbt-server

# Enumerate specific service
icyscan> enum smb
[*] Enumerating SMB...
[+] NULL SESSION AVAILABLE!
[+] Found 3 shares: IPC$, ADMIN$, backup
[+] Found 8 users

# Check findings
icyscan> show loot
[+] SMB Null Session Available
[+] SMB Share: backup (READ,WRITE)
[+] SMB User: john.doe
[+] SMB User: jane.smith

# Continue enumeration
icyscan> enum web
[*] Running Nikto on http://10.10.10.10...
[*] Running Feroxbuster...

icyscan> show exploits
[+] MS17-010 - EternalBlue (SMB)
[+] CVE-2019-0708 - BlueKeep (RDP)

icyscan> exit
```

### **When to Use Each Mode**

| Scenario | Mode | Why |
|----------|------|-----|
| Quick full enumeration | **Original CLI** | One command, everything automated |
| Manual pentesting | **Interactive** | Modular control, explore as you go |
| CTF box (unknown target) | **Interactive** | Scan quick → investigate → enumerate |
| Bug bounty (specific target) | **Original CLI** | Fast, thorough, automated |
| Learning/practicing | **Interactive** | See each step, understand flow |
| Scripting/automation | **Original CLI** | Easy to script, single command |
| Testing specific services | **Interactive** | Run only what you need |

---

## 📊 What IcyScan Does (Original CLI Mode)

### **Automated Workflow**

```
Phase 1: Quick Port Scan (top 100 ports)              [2 min]
Phase 2: Service/Script Scan (discovered ports)       [3 min]
         ↓ (Background: Full scan starts)
Phase 3: Domain & Subdomain Enumeration               [4 min]
         ↓ (Wait for full scan to complete)
Phase 4: Service Enumeration (SMB/LDAP/FTP/NFS)      [3 min, parallel]
Phase 5: Web Enumeration (Nikto + Feroxbuster)       [15 min]
Phase 6: Exploit Search (searchsploit)                [1 min]

Total Time: ~20-30 minutes (with parallelization)
```

### **Key Features**

**Core Capabilities:**
✅ **Multi-threaded** - Run multiple tasks simultaneously  
✅ **Background scanning** - Full Nmap runs while other tasks execute  
✅ **Progress bars** - Real-time progress for all operations  
✅ **Smart filtering** - Auto-excludes CDNs and external domains  
✅ **Auto-mounting** - Discovers and mounts NFS shares  
✅ **Organized output** - Clean directory structure  
✅ **Configurable** - YAML config file for all settings  
✅ **Live updates** - Real-time display of findings  

**Interactive Mode (v1.1):**
✅ **Modular testing** - Run only specific scans/enumeration  
✅ **Command history** - Arrow keys to navigate previous commands  
✅ **State persistence** - Results stay in memory between commands  
✅ **Random banners** - 6 different ASCII art banners  
✅ **Action-based commands** - Clear, intuitive command structure  
✅ **Built-in help** - Tutorial and command help system  
✅ **Tab completion** - cmd2 library for enhanced UX  

---

## 📁 Output Structure

```
10.10.10.10/
├── Loot/                       # High-value findings
│   ├── FTP/                   # Downloaded FTP files
│   ├── NFS_Mounts/            # Mounted NFS shares
│   │   ├── home/             (mounted /home export)
│   │   └── backup/           (mounted /backup export)
│   ├── nfs_mount_summary.txt # Unmount commands
│   ├── nikto_vulns_*.txt     # Web vulnerabilities
│   └── feroxbuster_*.txt     # Interesting paths
│
├── Exploits/                   # Exploit files (future)
│
└── Scans/                      # All scan outputs
    ├── nmap_quick.txt/xml
    ├── nmap_service.txt/xml
    ├── nmap_full.txt/xml
    ├── nikto_*.txt
    ├── feroxbuster_*.txt
    ├── netexec_*.txt
    ├── nfs_showmount.txt
    └── subdomains_*.txt
```

---

## 🎯 Key Features

### **1. Parallel Execution**

Services enumerate simultaneously instead of sequentially:

```
Service Enumeration |████████████████████| 4/4 [03:15<00:00]

• SMB   → Thread 1 ✓
• LDAP  → Thread 2 ✓
• FTP   → Thread 3 ✓
• NFS   → Thread 4 ✓
```

**Time saved:** 9 minutes (12 min → 3 min)

---

### **2. External Domain Filtering**

Automatically excludes third-party services:

**Filtered:**
- ❌ code.jquery.com
- ❌ fonts.googleapis.com
- ❌ cdn.cloudflare.com

**Kept:**
- ✅ admin.target.htb
- ✅ api.target.htb
- ✅ dev.target.htb

Saves time by not scanning jQuery or Google Analytics!

---

### **3. NFS Auto-Mounting**

```
[SUCCESS] Found NFS export: /home
[SUCCESS] Successfully mounted /home!
[INFO] Contents: 127 items
[SUCCESS] Found interesting files: id_rsa, .bash_history, passwords.txt
```

Mounted at: `Loot/NFS_Mounts/home/`

**Remember to unmount:**
```bash
sudo umount Loot/NFS_Mounts/home/
```

---

### **4. Background Full Scan**

Full port scan runs in background while other work continues:

```
Full Scan (All 65,535 Ports) |████░░░░░░░░░░░░░░| 25/100 (running)
```

**Time saved:** 5-10 minutes

---

### **5. Progress Bars**

Real-time feedback on all long operations:

```
Quick Scan (Top 100 Ports)        |████████████████████| 100/100
Service/Script Scan               |████████████████████| 100/100
Full Scan (All 65,535 Ports)      |████░░░░░░░░░░░░░░░| 45/100
Mounting NFS Shares               |████████████████████| 3/3
Downloading FTP Files             |████████████████████| 42/42
Nikto Web Scanning                |████████████████████| 8/8
Feroxbuster Fuzzing              |████████████████████| 12/12
```

---

## ⚙️ Configuration

### **Quick Setup**

```bash
# 1. Copy config file
cp icyscan_config.yaml /path/to/icyscan/

# 2. Edit settings
nano icyscan_config.yaml

# 3. Run (auto-loads config)
./icyscan.py -t target.htb
```

### **Common Configurations**

#### **Aggressive CTF/HTB**
```yaml
global:
  threads: 10

nmap:
  full_scan:
    flags: "-T5 --min-rate 5000"

feroxbuster:
  threads: 100
  depth: 3
```

#### **Stealthy Pentest**
```yaml
global:
  threads: 3

nmap:
  quick_scan:
    flags: "-T2 -sS"
```

#### **Custom Credentials**
```yaml
credentials:
  specific:
    - service: "smb"
      username: "Administrator"
      password: "Password123!"
```

#### **Custom Wordlists**
```yaml
subdomains:
  ffuf:
    wordlists:
      - "/home/user/my-subdomains.txt"

feroxbuster:
  wordlists:
    - "/home/user/my-directories.txt"
```

See `CONFIG_GUIDE.md` for full documentation.

---

## 🛠️ Tools Used

### **Port Scanning**
- **Nmap** - Three-stage approach (quick/service/full)

### **Web Enumeration**
- **Nikto** - Vulnerability scanner
- **Feroxbuster** - Directory/file fuzzer

### **Service Enumeration**
- **NetExec** - SMB/LDAP enumeration
- **FTP** - Anonymous login + file download
- **NFS** - Export discovery + auto-mounting

### **Subdomain Discovery**
- **ffuf** - DNS fuzzing
- **gobuster** - Vhost enumeration

---

## 📝 Live Display

Real-time status showing all findings:

```
════════════════════════════════════════════════════════════════
TARGET:      10.10.10.10
BASE DIR:    Scans/10.10.10.10
THREADS:     10 concurrent tasks
════════════════════════════════════════════════════════════════

[ PORTS ]
────────────────────────────────────────────────────────────────
  ● 21/tcp        ftp
  ● 22/tcp        ssh
  ● 80/tcp        http
  ● 445/tcp       microsoft-ds
  ● 2049/tcp      nfs

[ SERVICES ]
────────────────────────────────────────────────────────────────
  ● Port 21      ProFTPD 1.3.5
  ● Port 80      Apache httpd 2.4.41

[ DOMAINS ]
────────────────────────────────────────────────────────────────
  ● example.htb

[ SUBDOMAINS ]
────────────────────────────────────────────────────────────────
  ● admin.example.htb
  ● api.example.htb

[ LOOT ]
────────────────────────────────────────────────────────────────
  ● FTP Anonymous Access Available
  ● Downloaded: /backup/passwords.txt
  ● SMB Null Session Available
  ● NFS: Mounted /home at Loot/NFS_Mounts/home
  ● Nikto: Found 8 vulnerabilities
  ● Feroxbuster: Found 45 paths
```

---

## 📦 Files Included

### **Core Files**
- `icyscan.py` - Original CLI mode (automated full scans)
- `icyscan_interactive.py` - Interactive CLI mode (modular testing)
- `icyscan_config.yaml` - Configuration template
- `icyscan_config_loader.py` - Config parser
- `README.md` - This file

### **Which Files Do You Need?**

**Minimal Setup (Original CLI Only):**
```
icyscan.py
icyscan_config.yaml
icyscan_config_loader.py
```

**Full Setup (Both Modes):**
```
icyscan.py
icyscan_interactive.py
icyscan_config.yaml
icyscan_config_loader.py
```

**Note:** Interactive mode requires the `cmd2` library:
```bash
pip install cmd2 --break-system-packages
```

---

## 🐛 Troubleshooting

### **Progress bars not showing?**
```bash
pip install tqdm --break-system-packages
```

### **Config not loading?**
```bash
# Must be in same directory as icyscan.py
ls -la icyscan_config.yaml
```

### **Tool not found?**
```bash
# Check installation
which nikto feroxbuster netexec

# Install missing tools
sudo apt install nikto feroxbuster
pipx install netexec
```

### **NFS won't mount?**
```bash
# Run with sudo
sudo ./icyscan.py -t target

# Install NFS client
sudo apt install nfs-common
```

### **Interactive mode issues?**
```bash
# cmd2 module not found
pip install cmd2 --break-system-packages

# Can't import icyscan
# Make sure icyscan.py is in the same directory as icyscan_interactive.py
ls -la icyscan.py icyscan_interactive.py

# Banner not displaying correctly
# Make sure terminal supports UTF-8
export LANG=en_US.UTF-8
```

### **Commands not working in interactive mode?**
- Use full command syntax: `scan quick` not `quick`
- Use full command syntax: `show loot` not `loot`
- Type `help` to see all available commands
- Type `tutorial` for a quick start guide

---

## 💡 Best Practices

### **Before Scanning**
✅ Ensure you have permission  
✅ Run with sudo for full functionality  
✅ Configure custom credentials if available  
✅ Use appropriate thread count  

### **During Scanning**
✅ Monitor live display  
✅ Let full scan run in background  
✅ Check Loot/ directory regularly  

### **After Scanning**
✅ Unmount NFS shares:
   ```bash
   sudo umount Loot/NFS_Mounts/*
   ```
✅ Review Loot/ for credentials  
✅ Check filtered_external_domains.txt  

---

## 📊 Performance

**Hardware: 16GB RAM, 8 cores**

| Task | Sequential | IcyScan | Saved |
|------|------------|---------|-------|
| Full Scan | 10 min | Background | 10 min |
| Service Enum | 12 min | 3 min | 9 min |
| Web Enum | 20 min | 15 min | 5 min |
| **Total** | **44 min** | **20 min** | **24 min** |

**55% faster** with parallelization!

---

## 🎓 Tips

### **Speed Up**
```bash
# More threads
--threads 12

# Faster Nmap
nmap:
  full_scan:
    flags: "-T5 --min-rate 5000"
```

### **Stealth**
```yaml
nmap:
  quick_scan:
    flags: "-T2 -sS"
```

### **Focus Web Only**
```yaml
nmap:
  full_scan:
    enabled: false
smb:
  enabled: false
```

---

## 🔐 Security Notes

⚠️ **Legal:** Only scan systems you have permission to test  
⚠️ **Data:** Loot/ may contain sensitive information  
⚠️ **NFS:** Always unmount shares when done  

---

---

## 🚀 Example Workflow

```bash
# 1. Setup
cd /opt/tools/icyscan
pip install tqdm pyyaml --break-system-packages

# 2. Configure
cp icyscan_config.yaml.example icyscan_config.yaml
nano icyscan_config.yaml

# 3. Scan
sudo ./icyscan.py -t 10.10.10.10 --threads 10

# 4. Monitor progress
watch -n 5 ls -lh Scans/10.10.10.10/Loot/

# 5. Review
cd Scans/10.10.10.10/
cat SUMMARY.txt
ls -R Loot/

# 6. Cleanup
sudo umount Loot/NFS_Mounts/*
```

---

## 📈 Changelog

**v1.0** - January 2026 (Initial Public Release)
- Multi-threaded parallel execution with configurable worker threads
- Background full port scanning (65,535 ports)
- Three-stage Nmap approach (quick → service → full)
- NetExec (NXC) integration for 10+ protocols
  - SMB, LDAP, FTP, SSH, WinRM, RDP, MSSQL, WMI, VNC, NFS
- NFS auto-mounting with file enumeration
- External domain filtering (CDNs, third-party services)
- Progress bars for all long-running operations
- YAML configuration system with examples
- Organized output structure (Loot/Exploits/Scans)
- Web enumeration (Nikto + Feroxbuster)
- Subdomain discovery (ffuf + gobuster)
- Automatic /etc/hosts management
- Exploit search integration (searchsploit)
- Live status display with real-time updates
- Smart credential testing across protocols
- Vulnerability detection (BlueKeep, SMB signing, VNC no-auth)

---

---

## 🚀 Future Development

**Completed in v1.1:**
- ✅ Interactive CLI mode
- ✅ Modular command structure
- ✅ Random ASCII art banners
- ✅ Command history and tab completion

IcyScan v1.1 is functional and works well for my needs, but there are always more features to add. Here's what I'm considering for future versions:

### **Web Application Security Testing**

**Automated Vulnerability Detection:**
- **XSS Testing**
  - Reflected, Stored, and DOM-based XSS
  - Context-aware payload generation
  - Form and parameter injection
  
- **SQL Injection**
  - Error-based, Union-based, Blind SQLi
  - Database fingerprinting
  - Automated data extraction

- **Other Web Vulnerabilities**
  - Command Injection
  - Path Traversal / LFI / RFI
  - XXE (XML External Entity)
  - SSRF (Server-Side Request Forgery)
  - Open Redirect detection

**Tool Integration:**
- SQLMap for advanced exploitation
- XSStrike for XSS detection
- Custom payload libraries

### **Active Directory Automation**

**Comprehensive AD Testing:**
- **BloodHound Integration**
  - Automated data collection
  - Attack path analysis
  - Shortest path to Domain Admin

- **Impacket Suite**
  - secretsdump.py - Credential extraction
  - GetNPUsers.py - ASREPRoast
  - GetUserSPNs.py - Kerberoasting
  - psexec/wmiexec - Remote execution
  - ntlmrelayx - SMB relay attacks

- **Advanced NXC Features**
  - Pass-the-hash automation
  - LAPS password extraction
  - GPP password extraction
  - Domain trust enumeration

**Attack Chain Automation:**
- ASREPRoast → Crack → Spray
- Kerberoast → Crack → Escalate
- BloodHound → Find Path → Execute

### **Intelligent Exploitation**

**Automated Exploit Execution:**
- Metasploit integration
- Automatic module selection
- CVE database integration
- Safe exploitation with rollback

**Common Exploits:**
- EternalBlue (MS17-010)
- BlueKeep (CVE-2019-0708)
- ProxyLogon / ProxyShell
- Zerologon (CVE-2020-1472)
- PrintNightmare

### **Credential Attacks**

- Password spraying with lockout detection
- Hashcat/John the Ripper integration
- Breach database lookups
- Credential stuffing

### **Advanced Reporting**

- Professional PDF reports
- CVSS vulnerability scoring
- Attack path visualization
- Timeline of discoveries
- Risk prioritization

### **Other Ideas**

- **Network Pivoting:** SSH tunnels, SOCKS proxies, multi-hop traversal
- **Cloud Security:** AWS/Azure/GCP enumeration
- **Container Security:** Docker/Kubernetes testing
- **Wireless:** WiFi and Bluetooth attacks
- **OSINT Integration:** Email enumeration, breach lookups, social media recon
- **AI/ML:** Smart attack path recommendations, pattern recognition

---

## 📚 Documentation

**Included Files:**
- `README.md` - This file (complete usage guide)
- `icyscan_config.yaml` - Configuration template

---

## 🎉 Happy Scanning!

IcyScan makes enumeration faster, cleaner, and more efficient. Customize it to your needs and let it handle the tedious work!

**Remember: Always scan responsibly! 🔐**
