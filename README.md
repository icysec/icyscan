# 🧊 IcyScan - Advanced Network Enumeration Framework

**Version:** 1.0  
**Release:** January 2026  
**Purpose:** Automated reconnaissance and enumeration for penetration testing

IcyScan is a network enumeration framework I built to automate the tedious parts of reconnaissance. It's designed to be fast, thorough, and easy to configure for different scenarios (CTF, pentesting, bug bounty, etc.).

---

## 🚀 Quick Start

### **Installation**

```bash
# 1. Install Python dependencies
pip install tqdm pyyaml --break-system-packages

# 2. Install required tools (if not already installed)
sudo apt update
sudo apt install -y nmap nikto feroxbuster ffuf gobuster showmount nfs-common curl

# 3. Install NetExec (nxc) for SMB/LDAP enumeration
pipx install netexec
# Or if pipx not available:
pip install netexec --break-system-packages

# 4. Make executable
chmod +x icyscan.py

# 5. Run with sudo (required for NFS mounting and /etc/hosts)
sudo ./icyscan.py -t 10.10.10.10
```

### **Basic Usage**

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

---

## 📊 What IcyScan Does

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

✅ **Multi-threaded** - Run multiple tasks simultaneously  
✅ **Background scanning** - Full Nmap runs while other tasks execute  
✅ **Progress bars** - Real-time progress for all operations  
✅ **Smart filtering** - Auto-excludes CDNs and external domains  
✅ **Auto-mounting** - Discovers and mounts NFS shares  
✅ **Organized output** - Clean directory structure  
✅ **Configurable** - YAML config file for all settings  
✅ **Live updates** - Real-time display of findings  

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

IcyScan v1.0 is functional and works well for my needs, but there are always more features to add. Here's what I'm considering for future versions:

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
- `CONFIG_GUIDE.md` - Configuration examples and best practices
- `icyscan_config.yaml` - Configuration template

**Configuration:**
See `CONFIG_GUIDE.md` for detailed examples on customizing IcyScan for different scenarios (CTF, pentesting, bug bounty, etc.)

---

## 🎉 Happy Scanning!

**Remember: Always scan responsibly! 🔐**
