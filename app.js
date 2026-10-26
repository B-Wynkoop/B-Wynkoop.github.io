// PROJECTS
const projects = [
  {
    id: 'malware',
    category: 'analysis',
    label: 'MALWARE ANALYSIS · CASE REPORT',
    title: '🦠 Malware Analysis',
    desc: 'A static and dynamic investigation of a packed .NET sample. From obfuscation and Defender policy changes to persistence artifacts.',
    name: '🦠 Malware Analysis',
    tags: 'PEStudio · Procmon · Regshot',
    repo: 'Malware_Analysis',
    takeaway:
      '"Developing practical malware analysis, threat investigation, and technical reporting skills while maintaining a repeatable and isolated analysis workflow',
  },
  {
    id: 'refresh',
    category: 'automation',
    label: 'AUTOMATION · BASH',
    title: '🐧 RefreshX',
    desc: 'A Bash utility that brings Debian-based package updates and cleanup into one workflow.',
    repo: 'Linux-CleanUpdate',
    terminal: ['$ ./update.sh', 'apt → snap → flatpak', 'Update. Upgrade. Clean.'],
    takeaway:
      'The script sequences APT, Snap, and Flatpak updates, followed by package cleanup. It requires sudo and the relevant package managers. Its checksum check is not fail-closed: subsequent commands can still run if verification fails. Review the source before use.',
  },
  {
    id: 'lynis',
    category: 'automation',
    label: 'AUTOMATION · SYSTEM AUDITING',
    title: '🔎 LynisLens',
    desc: 'A small reporting wrapper that pulls Lynis warnings and suggestions into a focused text file.',
    repo: 'Lynis-Reporter',
    terminal: ['$ ./lynis.sh', 'Run audit → extract findings', 'warnings / suggestions'],
    takeaway:
      'This wrapper runs Lynis, extracts warning and suggestion lines from its report, and opens lynis-review.txt. Lynis and sudo access are required. It organizes findings and suggestions, it does not remediate them but gives hardening suggestions.',
  },
  {
    id: 'network',
    category: 'infrastructure',
    label: 'NETWORK ENGINEERING · PACKET TRACER',
    title: '🛜 Network Architecture',
    name: 'Small business network architecture',
    desc: 'Built a functional network on a single Cisco 2911 router, three 2960 switches to segment different departments , and three IP networks. Built and tested in Packet Tracer.',
    takeaway:
      'The project connects end-user devices, printers, and a server across three subnets. Router interfaces enable inter-subnet communication; ICMP and simulation tools verify connectivity.',
  },
  {
    id: 'windows',
    category: 'infrastructure',
    label: 'SYSTEM HARDENING · RISK MATRIX',
    title: '🔐 Windows',
    desc: 'A documented Windows configuration project. Explore the original two-page report.',
  },
  {
    id: 'ubuntu',
    category: 'infrastructure',
    label: 'SYSTEM HARDENING · RISK MATRIX',
    title: '🔐 Ubuntu',
    desc: 'A documented Ubuntu configuration project. Explore the original two-page report.',
  },
  {
    id: 'macos',
    category: 'infrastructure',
    label: 'SYSTEM HARDENING · RISK MATRIX',
    title: '🔐 MacOS',
    desc: 'A documented macOS configuration project. Explore the original two-page report.',
  },
  {
    id: 'kali',
    category: 'infrastructure',
    label: 'SYSTEM HARDENING · RISK MATRIX',
    title: '🔐 Kali Linux',
    desc: 'A documented Kali Linux configuration project. Explore the original two-page report.',
  },
];

// REPORTS & SOURCES
const reports = {
  'malware': [
    {
      'image': 'assets/malware-1.webp',
      'text':
        '[SUMMARY]\nThis report provides a technical analysis of executable sample 95c21c7542ced5450ff32d9d077f454c763443cacd821d45bd14c30b87d9e8f3.exe. Static and dynamic analysis identified a packed and obfuscated 64-bit .NET executable that modified Windows Defender settings, used hidden PowerShell with execution policy bypass, created persistence artifacts, and dropped a secondary payload. Windows Defender classified the dropped payload as Trojan:MSIL/NegaStealer.AB!MTB during local testing. Post analysis validation against MalwareBazaar identifies the submitted sample as RemcosRAT, with multiple linked sandboxes also reporting Remcos related behavior.\n\n[THREAT SEVERITY] HIGH\nThe sample demonstrates high-risk behavior including .NET packing/obfuscation, attempts to modify Defender policy, hidden PowerShell execution, and persistence through registry and scheduled-task artifacts.\n\n[STATIC ANALYSIS & METADATA]\nStatic property inspection of the binary confirms that the executable is compiled as a 64-bit Portable Executable (PE32+) targeted for the Microsoft .NET Framework (v4.7.2). File Property Value / Detail File Name 95c21c7542ced5450ff32d9d077f454c763443cacd821d45bd14c30b87d9e8f3.exe SHA-256 Hash 95C21C7542CED5450FF32D9D077F454C763443CACD821D45BD14C30B87D9E8F3 File Size 1.37 MB (1,444,864 bytes) Compiler / Language VB.NET / Microsoft Intermediate Language (MSIL) Original Filename Zlvc.exe Embedded Product Name VirtualMachine26 Embedded Company Name HyperCore Labs (embedded metadata) Compile Stamp Thu Aug 27 03:46:08 2026 UTC PDB Debug Path C:\\Users\\Administrator\\Desktop\\Client\\Temp\\NOCvnnitRK\\src\\obj\\Debug\\Zlvc.pdb\n\n[Entropy & Packing Indicators]\nDetect It Easy and PeStudio showed unusually high entropy in key areas of the Portable Executable (PE). The .text section measured 7.944 entropy and represented most of the file, while an embedded resource measured 7.995 entropy (approximately 1.32 MB). High entropy is consistent with compression, packing, or obfuscation and can make static inspection more difficult. External sandbox validation later identified SmartAssembly .NET packing for this sample, supporting the local packing/obfuscation assessment.\n',
    },
    {
      'image': 'assets/malware-2.webp',
      'text':
        '[DYNAMIC BEHAVIOR & HOST MODIFICATIONS]\nUpon dynamic execution within an isolated Windows analysis virtual machine, Process Monitor captured specific host tampering actions designed to weaken security configurations and degrade operating system defenses.\n\n[ZoneMap Configuration Changes]\nProcess Monitor captured changes to Windows Internet Settings ZoneMap values. Specifically, the sample modified the following values under the registry path HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\:\u2022 ProxyBypass: 1 (Maps proxy-bypass sites into the Local Intranet zone)\u2022 IntranetName: 1 (Includes local intranet sites not otherwise assigned)\u2022 UNCAsIntranet: 1 (Maps UNC network paths into the Local Intranet zone)\u2022 AutoDetect: 0 (Disables automatic intranet detection) These values change how Windows classifies local and intranet resources. Proxy-bypass sites and UNC paths may be treated as Local Intranet content under this configuration. The analysis confirmed the registry changes but did not demonstrate proxy bypass traffic, unauthorized script execution, or lateral movement.\n\n[Antivirus Defense Evasion]\nProcess Monitor and Defender alerts show an attempt to modify Microsoft Defender policy. The sample accessed and attempted to write the following value: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware The attempted change is consistent with defense evasion. Defender detected the modification during the analysis; the local run did not establish that real time protection was successfully disabled or that C2 occurred.\n\n[PERSISTENCE MECHANISMS]\nRegshot comparison data showed two persistence-related artifacts created after execution: The artifacts are documented as observed; intended trigger behavior was not independently validated. Type Target Registry/Task Path Details / Command Line Registry Run Key HKU\\S-1-5-21-...\\Software\\Microsoft\\\\Windows\\CurrentVersion\\Run\\XoI Launches PowerShell with -ExecutionPolicy Bypass and a hidden window. Scheduled Task \\SoftLanding (GUID: {00B2430C-BAA4-45FD-9FBA-A23DC18FCBA7}) Creates a scheduled task artifact named SoftLanding; trigger behavior was not independently validated.\n\n[Obfuscated Run-Key PowerShell Command Analysis]\nThe registry Run value Xoi invokes PowerShell with flags that suppress profiles, bypass execution policy, and hide the window: powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ... The command also contains Base64-encoded strings. Decoding the observed strings revealed: Encoded String Decoded Value Technical Action U3RhcnQtU2xlZXA= Start-Sleep Introduces an execution delay that may reduce behavior observed in short analysis windows. QzpcVXNlcnNcV2luZG93c1VzZXJc QXBwRGF0YVxSb2FtaW5nXFhvbC 5leG== (Partially obfuscated string) C:\\Users\\WindowsUser\\AppData\\Roaming\\XoI.exe References the dropped executable for later execution. HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiVirus\n',
    },
    {
      'image': 'assets/malware-3.webp',
      'text':
        "[DROPPED PAYLOADS & ENDPOINT DETECTION ALERTS]\nDuring dynamic execution, the sample created or referenced a dropped executable under the user Roaming profile. Windows Defender generated the following alerts during the analysis. Security Alert Classification Action Taken / Context VirTool:Win32/DefenderTamperingRestore Severe (Active/Quarantined) Triggered by the attempted modification of the DisableAntiSpyware value in Microsoft Defender policies. VirTool:PowerShell/Magnib.A Severe (Active/Quarantined) Triggered by the obfuscated Run-key PowerShell command; Defender/AMSI detected the script content. Trojan:MSIL/NegaStealer.AB!MTB Severe (Quarantined) Local Defender classification for the dropped executable payload \u2018XoI.exe\u2019 under 'C:\\Users\\WindowsUser\\AppData\\Roaming\\'.\n[Incident Response]\n- Host Isolation: Immediately isolate affected endpoints to prevent further network communication. - Process Remediation: Terminate the malicious sample process, the dropped payload, and any associated suspicious PowerShell processes after preserving evidence. - File Cleanup: Quarantine/remove C:\\Users\\WindowsUser\\AppData\\Roaming\\Xol.exe after evidence collection. - Registry/Task Restoration: Remove XoI and SoftLanding artifacts and restore modified Defender/ZoneMap settings from known-good values. - EDR/AV Sweep: Scan for Remcos, NegaStealer detections, and the observed behavioral indicators.\n[Post Analysis]\nPost analysis comparison with MalwareBazaar was performed after the local investigation. MalwareBazaar lists the submitted sample as RemcosRAT; the SHA-256 and file size match this sample. Linked Joe Sandbox, Hatching Triage, CERT.PL MWDB, Threatray, and VMRay results also identify Remcos. Triage reports SmartAssembly packing, PowerShell execution, Run-key persistence, and Defender policy changes. It also extracts Remcos C2 configuration, including www.dmgl-international.xyz:2404 and backup domains. These external results corroborate several local behaviors but are not treated as locally observed network activity. The windows analysis VM was intentionally Internet-isolated, so no external C2 communications were confirmed locally.\n",
    },
  ],
  'network': [
    {
      'image': 'assets/network-1.webp',
      'text':
        'Project Summary\nI built a small business network in Cisco Packet Tracer using a Cisco 2911 router and \nthree Cisco 2960 switches. I configured three separate IP networks, connected PCs, laptops, printers, \nand a server, and configured the router interfaces to allow communication between the different \nsubnets. I then tested the network using ICMP traffic and Packet Tracer\u2019s\n simulation tools to verify connectivity and troubleshoot the network.\n\nProject Outcome\nThis project gave me hands on experience building a small business network from the \nground up in Cisco Packet Tracer. I worked with multiple network segments, switches, a \ncentral router, end-user devices, printers, and a dedicated server network.\nWorking through the project helped me better understand how IP addressing, routing, \nswitching, and network segmentation come together in a real network environment. I \nalso gained experience configuring Cisco devices, troubleshooting connectivity issues, \nand testing communication between different parts of the network.\n',
    },
  ],
  'windows': [
    {
      'image': 'assets/windows-1.webp',
      'text':
        'System Hardening | VirtualBox\n________________________________________________\n{ Windows 11 Home }\n[6] Data:\n- BitLocker Full Disk Encryption | 80 GB Virtual | V\n- Offline Disk Encryption | 2-TB HDD | V\n- Windows USB Recovery Drive | V\n- Encrypted File Backups | V\n- Weekly Drive Optimization | V\n- BitWarden Account Encryption | V\n[6] Application:\n- Daily Security & App Updates | V\n- Protection From Non-Trusted Apps | V\n- Removed Windows Bloatware | V\n[6] Host:\n- Windows Backups (Disk Encrypted) | V\n- Offline External Encrypted Backups | V\n- Disabled Root Log-In | V\n- Secure Boot | V\n- BitDefender Antivirus | V\n- BIOS Password | Bare Metal | V\n[6] Network:\n- Windows Defender Firewall | (Disabled Incoming | Enabled Outgoing) | V\n- Port 22 Disabled (SSH) | V\n- Port 3389 Disabled (RDP) | V\n- BitDefender VPN | V\n- DNS > HTTPS (DOH) (CloudFlare 1.0.0.1 \u2013 Google 8.8.8.8) | V\n[4] Web:\n- Firefox (No Saved Passwords (Always Ask Before Any Download)) | V\nExtensions:\n- Ublock Origin  | V\n- Ghostery | V\n- Privacy Badger | V\n- Chrome Mask  | V\n- MalwareBytes | V\n____________________________________________________________\n',
    },
    {
      'image': 'assets/windows-2.webp',
      'text':
        'Overview:\nThis Windows 11 Home system is set-up in Virtual-Box with virtual hardware and network configurations. \nBit-Locker Encryption is used for its 80GB of virtual storage to ensure data is safe, even at rest. DNS > \nHTTPS is enabled with Cloudflare as the primary DNS,  this improves the system security by encrypting \nDNS searches by sending them through HTTPS (443) blockinf ISP DNS snooping. Both RDP (3389) and \nSSH (22) has been disabled to prevent brute-force entry attempts to the system. Anti-malware software has \nbeen set up with BitDefender real-time protection and prevention. Overall this system now provides full data \nencryption, privacy improvements, and offline recovery and data security for the user.\nDefense In Depth:\n____________________________________________________________\nData:\n- BitLocker Full Disk Encryption | 80 GB Virtual | \u201cSecures live and resting data on the device\u201d\n- Offline Disk Encryption | 2-TB HDD | \u201cFor encrypted offline system backups\u201d\n- Recovery Drive | \u201cUSB windows recovery drive for backup system recovery\u201d\n- Encrypted File Backups | \u201cWindows data backups [Folders, Apps, Settings, Credentials]\u201d\n- Monthly Drive Optimization | \u201cDe-fragment drives to re-organize fragmented data and improve system \nperformance\u201d\n________________________________________________________________________________\nApplication:\n- Daily Security & App Updates | \u201cEnsures any new vulnerabilities in applications or systems are patched\u201d\n- Protection From Non-Trusted Apps | \u201cKeep non-trusted application permissions limited, only allowed if I \nallow it\u201d\n- Removed Windows Bloatware | \u201cRemoved all unnecessary applications pre-installed with windows for \nimproved performance\u201d\n________________________________________________________________________________\nHost:\n- Windows Backups (Disk Encrypted) | \u201cConsistent backups for easy roll-backs\u201d\n- Offline External Backups | \u201cResting encrypted backups on external HDD\u201d \n- Disabled Root Log-In (UAC) | \u201cReduces attack surface of brute-force attacks to privileged\u201d accounts\u201d\n- Secure Boot | \u201cEnsures the system boots from trusted sources only\u201d\n- Bit-Defender Anti-Malware | \u201cReal-Time malware protection and prevention\u201d\n- BIOS Password | Bare Metal | \u201cKeeps unauthorized users from accessing boot-loader options\u201d\n________________________________________________________________________________\nNetwork:\n- Windows Defender Firewall | (Disabled Incoming) | \u201cStops other devices from attempting access to the \nsystem unless allowed\u201d\n- Port 22 Disabled (SSH) | \u201cDisabled when not in use to prevent brute-force attacks and possible lateral \nmovement\u201d\n- Port 3389 Disabled (RDP) | \u201cDisabled when not in use to prevent brute-force attacks\u201d\n- Bit-Defender VPN | \u201cEncrypts internet traffic and IP address\u201d\n- DNS > HTTPS (DOH) (Cloud-Flare 1.0.0.1 \u2013 Google 8.8.8.8) | \u201cReduce DNS snooping and spoofing by \nencrypting DNS queries\u201d\n________________________________________________________________________________\n| Created By https://B-Wynkoop.github.io For System Hardening |\n| GitHub | https://github.com/B-Wynkoop |\n| LinkedIn | https://www.linkedin.com/in/d-brady-wynkoop-0ba0a3379/ |\n',
    },
  ],
  'macos': [
    {
      'image': 'assets/macos-1.webp',
      'text':
        'System Hardening | Bare Metal\n________________________________________________\n{ MacOS \u2013 Silicon }\n[6] Data:\n- FileVault Disk Encryption | 256 GB | V\n- TimeMachine Encrypted Backups | V\n- External Disk Encryption | 2-TB HDD | V\n- \u201cPasswords\u201d Credential Encryption | V\n[6] Application:\n- Auto Security & App Updates | V\n- Removed Unused Applications | V\n- Browser Hardening | [4] Web: | V\n- Disable Guest Account | V\n[6] Host:\n- Full System Backups (Encrypted) | V\n- System Integrity Protection | V\n- Secure Boot | V\n- Malware Scanner & Remover | XProtect (Remediator) | V\n- Block Unsigned Applications | GateKeeper | V\n- Lockdown mode | On/Off | VX\n[6] Network:\n- NordVPN | V\n- Rotating Private Wi-Fi Address | V\n- Stealth Mode | V\n- Encrypted DNS (DoH) | V\n- MacOS Firewall | (Deny Incoming | Allow Outgoing) | V\n- Incoming Allowed for Built-In and Signed Apps | V\n- Port 22 Disabled (SSH) | V\n- Port 3389 Disabled (RDP) | V\n[4] Web:\n- Firefox (No Saved Passwords (Always Ask Before Any Download)) | V\nExtensions:\n- Ublock Origin  | V\n- Ghostery | V\n- Privacy Badger | V\n- Chrome Mask  | V\n- MalwareBytes | V\n____________________________________________________________\n',
    },
    {
      'image': 'assets/macos-2.webp',
      'text':
        'Overview:\nThis Apple MacOS system is set up for everyday use with strict security measures in place. Full disk \nencryption with AES and multi-factor authentication procedures set for account and setting changes. This \nsystem is tailored to transition into security and pen-testing with virtualization. Application permissions and \nsignatures are currently verified by built in and pre-signed applications. Full browser hardening, encrypted \nDNS, rotating wi-fi address, VPN and more all help stay secure while connected to your home or other \nnetwork.\nDefense In Depth:\n____________________________________________________________\nData:\n- FileVault Disk Encryption | 256 GB | \u201cXTS-AES-128 encrypted drive for at rest security\u201d\n- TimeMachine Encrypted Backups | \u201cEnsures roll back plans are in place in case of system breaks\u201d\n- External Disk Encryption | 2-TB HDD | \u201cData integrity and security with encryption stored offline\u201d\n- \u201cPasswords\u201d Credential Encryption | \u201cLogin credentials, notes, keys and more all encrypted\u201d \n________________________________________________________________________________\nApplication:\n- Auto Security & App Updates | \u201cAuto system and security updates to remove prior known vulnerabilities\u201d\n- Removed Unused Applications | \u201cRemoved unused apps to lower the systems attack surface\u201d\n- Browser Hardening | [4] Web: | \u201cSecurity configurations for browsers to ensure sensitive data stays secure\u201d\n- Disbaled Guest Account | \u201cDeleting guest accounts help reduce breach points\u201d\n________________________________________________________________________________\nHost:\n- Full System Backups (Encrypted) | \u201cTime machine backups sent to an encrypted HDD then stored at rest \noffline\u201d\n- System Integrity Protection | \u201cChecks system files for file manipulation to enforce system integrity\u201d\n- Secure Boot | \u201cApple Silicon sets this automatically, default denies boot loading any OS unsigned by \nApple\u201d\n- Malware Scanner & Remover | XProtect (Re-mediator) | \u201cBuilt in to Mac, XProtect scans for malware on \nthe device, if found XProtect re-mediator then removes the malware\u201d\n- Blocked Unsigned Applications | GateKeeper | \u201cKeeps untrusted apps from accessing sensitive or system \nfiles\u201d\n- Lockdown mode | On/Off | \u201cIn case of a cyber attack, lockdown removes your connections from nearly \neverything removing access for the malicious actor\u201d\n________________________________________________________________________________\nNetwork:\n- NordVPN | \u201cHides IP address and prevents ISP DNS snooping\u201d\n- Rotating Private Wi-Fi Address | \u201cReduces tracking of the system locally and on other networks\u201d\n- Stealth Mode | \u201cDisables response to network pings\u201d\n- Encrypted DNS (DoH) | \u201cCloudflare encrypted DNS > HTTPS\u201d\n- MacOS Firewall | (Deny Incoming | Allow Outgoing) | \u201cReduce incoming data from unknown or untrusted \nsources\u201d\n- Only Allowed Built-In and Signed Software | \u201cRestricts unauthorized users from accessing privileged \npermissions\u201d\n- Port 22 Disabled (SSH) | \u201cDisables secure shell access to this machine\u201d\n- Port 3389 Disabled (RDP) | \u201cDisabled remote desktop access to the system\u201d\n________________________________________________________________________________\n| Created By https://B-Wynkoop.github.io For System Hardening |\n| GitHub | https://github.com/B-Wynkoop |\n| LinkedIn | https://www.linkedin.com/in/d-brady-wynkoop-0ba0a3379/ |\n',
    },
  ],
  'ubuntu': [
    {
      'image': 'assets/ubuntu-1.webp',
      'text':
        'System Hardening | Bare Metal\n________________________________________________________________________________\n{ Ubuntu 24.04 }\n[6] Data:\n- Internal Disk Encryption | (2) 1-TB SSD | V\n- External Disk Encryption | 2-TB HDD | V\n- External USB Encryption | 256-GB | V\n- Encrypted File Backups (Monthly) | V\n[6] Application:\n- Daily System & App Updates | V\n- App Armour | V\n- FireJail | V\n[6] Host:\n- TimeShift (Recovery Snapshots Stored with Encryption) | V\n- Disabled Root Log-In | V\n- Brute Force Prevention | Fail2Ban | V\n- BIOS Password | V\n- Suricata IDS & IPS | V\n[6] Network:\n- NordVPN | V\n- DNS > HTTPS (DOH) | V\n- ClamAV | V\n- RkHunter | V\n- Lynis | V\n- Firewall | UFW (Disabled Incoming) | V\n- Port 22 Disabled (SSH) | V\n- Port 3389 Disabled (RDP) | V\n[4] Web:\n- FireJail | V\n- Virtual Machines (VirtualBox) | V\n- Firefox (No Saved Passwords (Always Ask Before Any Download)) | V\nExtensions:\n- Ublock Origin  | V\n- Ghostery | V\n- Privacy Badger |  V\n- Chrome Mask  | V\n- MalwareBytes | V\n[4] Accounts:\n- Bitwarden (Encrypted and Updated all Passwords) | V\n- Multi-Factor Authentication | V\n \n________________________________________________________________________________\n',
    },
    {
      'image': 'assets/ubuntu-2.webp',
      'text':
        'Overview:\nThis system is configured for everyday personal desktop use. Encryptions added at every layer as well as \ntwo-factor and multi-factor authentication methods implemented. A BIOS password is implemented and root \nlogin disabled to ensure unauthorized access to bootloaders or privileged permissions. Browser hardening \nwas also implemented with tracking, ad, malware, and secure DNS queries. Daily system, snap, and flatpak \nupdates to ensure up to date security patches. With NordVPN the systems IP address and network traffic is \nencrypted enforcing strict security policies. Malware detection and removal tools, root and bootkit scanners, \nand system audits for hardening all set up for peace of mind when using this system.\nDefense In Depth:\n____________________________________________________________\nData:\n- Internal Disk Encryption | (2) 1-TB SSD | \u201cData secured at rest\u201d\n- External Disk Encryption | 2-TB HDD | \u201cOffline data backups secured at rest\u201d\n- External USB Encryption | 256-GB | \u201cEncrypted USB for extra storage\u201d\n- Encrypted File Backups (Monthly) | \u201cBackups to external HDD stored offline\u201d\n________________________________________________________________________________\nApplication:\n- Daily System & App Updates | \u201cPatches known vulnerabilities in systems and applications\u201d\n- App Armour | \u201cKeeps app privileges to a minimum\u201d\n- FireJail | \u201cSandboxes any application the user desires\u201d\n________________________________________________________________________________\nHost:\n- TimeShift (Encrypted Recovery Snapshots Daily) | \u201cSnapshots taken (2) hourly, (2) daily, and (2) monthly\u201d \n- Disabled Root Log-In | \u201cLower the risk of root access to the system\u201d\n- Brute Force Prevention | Fail2Ban | \u201cMonitors log files for multiple login attempts, then blocks the IP\u201d\n- BIOS Password | \u201cPrevents boot loader and BIOS tampering\u201d\n- Suricata IDS & IPS | \u201cMonitors network traffic for suspicious behavior and blocks it\u201d\n________________________________________________________________________________\nNetwork:\n- NordVPN | \u201cHides IP and encrypts internet traffic\u201d\n- DNS > HTTPS | \u201cUsing Cloudflare DNS over HTTPS to encrypt DNS queries\u201d\n- ClamAV | \u201cMalware detection and removal tool\u201d\n- RkHunter | \u201cRootkit and Bootkit detection\u201d\n- Lynis | \u201cFor system hardening audits\u201d\n- Firewall | UFW (Disabled Incoming) | \u201cBlocks port scanning as well as an extra layer of remote access\u201d\n- Port 22 Disabled (SSH) | \u201cDisables secure shell access to the system\u201d\n- Port 3389 Disabled (RDP) | \u201cDisabled remote desktop access to the system\u201d\n________________________________________________________________________________\n| Created By https://B-Wynkoop.github.io For System Hardening |\n| GitHub | https://github.com/B-Wynkoop |\n| LinkedIn | https://www.linkedin.com/in/d-brady-wynkoop-0ba0a3379/ |\n',
    },
  ],
  'kali': [
    {
      'image': 'assets/kali-1.webp',
      'text':
        'System Hardening | VirtualBox\n________________________________________________\n{ Kali Linux }\n[6] Data:\n- LUKS Disk Encryption | 60 GB Virtual | V\n- External Disk Encryption | 2-TB HDD | V\n- Timeshift Backups | V\n- Clonezilla Full System Backups | V\n- BitWarden Account Encryption | V\n[6] Application:\n- Daily Security & App Updates | V\n- FireJail (Sandbox) | V\n[6] Host:\n- Full System Backups (Encrypted) | V\n- Disabled Root Log-In | V\n- Secure Boot | X\n- Antivirus | X\n- BIOS Password | Bare Metal | V\n- File History of 7 days \u2013 Trash & Temporary Files Delete after 7 days | V\n[6] Network:\n- NordVPN | V\n- UFW | (Deny Incoming | Allow Outgoing) | V\n- Restricted Ports < 1024 for Privileged Users | V\n- Port 22 Disabled (SSH) | V\n- Port 3389 Disabled (RDP) | V\nKali Tweaks:\n- Package Mirror Cloudflare CDN | V\n- HTTPS Protocol | V\n- Disabled Samba Client | V\n[4] Web:\n- FireJail (Sandboxing)\n- Firefox (No Saved Passwords (Always Ask Before Any Download)) | V\nOn/Off Extensions:\n- Ublock Origin  | V\n- Ghostery | V\n- Privacy Badger | V\n- Chrome Mask  | V\n- MalwareBytes | On/Off | VX\n____________________________________________________________\n| Created By https://B-Wynkoop.github.io For System Hardening |\n| GitHub | https://github.com/B-Wynkoop |\n| LinkedIn | https://www.linkedin.com/in/d-brady-wynkoop-0ba0a3379/ |\n',
    },
    {
      'image': 'assets/kali-2.webp',
      'text':
        'Overview:\nThis system is set-up in Virtual-Box with virtual hardware and network configurations. This Kali-Linux \nconfiguration is intended to run a variety of penetration testing tools securely.  Full disk encryption with \nLUKS as well as system backups and scheduled snapshots. FireJail is set up on this machine so that \napplications can be sandboxed for further permission managing. All system package updates use Cloudflare \nserver instead of community for fast and reliable package updates. Antivirus and secure boot are disabled to \nallow Kali\u2019s penetration tools to run effectively and efficiently. This systems security is configured for \npenetration testing as intended with Kali-Linux, additional security has been added to the users system as an \nextra layer of defense when working with malicious data.\nDefense In Depth:\n____________________________________________________________\nData:\n- LUKS Disk Encryption | 60 GB Virtual | \u201c60GB of LUKS encrypted virtual memory\u201d\n- External Disk Encryption | 2-TB HDD | \u201cExternal encrypted 2TB HDD, stays offline\u201d\n- Encrypted Timeshift Backups | \u201c(2) Timeshift snapshots hourly, (2) Daily, and (1) monthly all saved to its \nown partition in the virtual drive\u201d  \n- Clonezilla Full System Backups | \u201cA live boot USB allowing a full system backup offline\u201d \n- BitWarden Account Encryption | \u201cEncrypted password, key, and note manager for accounts\u201d\n________________________________________________________________________________\nApplication:\n- Daily Security & App Updates | \u201cTerminal full upgrades for apt managed packages (kali tools, etc)\u201d\n- FireJail (Sandbox) | \u201cKeeps applications sandboxed to help control system access\u201d\n________________________________________________________________________________\nHost:\n- Full System Backups (Encrypted) | \u201cWithout the passphrase all backed up data is unreadable\u201d\n- Disabled Root Log-In | \u201cKeeps unauthorized users from accessing a higher privileged account\u201d\n- Secure Boot | \u201cSecure boot is deactivated to prevent problems with booting as Kali\u2019s kernel at default is \nmissing those signed keys\u201d\n- Antivirus | \u201cAny anti-malware or virus software is not installed on this machine as this system is \nintentionally used for pen-testing, any malware or virus prevention can remove some abilities to run kali \ntools\u201d\n- BIOS Password | Bare Metal | \u201cPrevents manipulation with the boot-loader and BIOS settings\u201d\n- File History of 7 days \u2013 Trash & Temporary Files Delete after 7 days | \u201cFile history and trash that could \nhave sensitive information get removed after 7 days, cleans any temp files as well\u201d \n________________________________________________________________________________\nNetwork:\n- NordVPN | \u201cHides IP and encrypts your traffic,  also prevents ISP DNS snooping\u201d\n- UFW | (Deny Incoming | Allow Outgoing) | \u201cUncomplicated Firewall used for simple !incoming =outgoing \nand port rules\u201d\n- Restrict Ports < 1024 for Privileged Users | \u201cRestricts any port < 1024 for access only by root\u201d\n- Port 22 Disabled (SSH) | \u201cDisabled secure shell access to the system through port 22\u201d\n- Port 3389 Disabled (RDP) | \u201cDisabled remote desktop access through port 3389\u201d\nKali Tweaks:\n- Package Mirror Cloudflare CDN | \u201cUses Cloudflare networks to update packages for reliable and secure \ndownloads\u201d\n- HTTPS Protocol | \u201cDefaults to using the secure version of hypertext transfer protocol\u201d\n- Disabled Samba Client | \u201cDisabled the system from accessing windows file sharing until needed\u201d\n________________________________________________________________________________\n',
    },
  ],
};

// PROJECT SOURCES
const projectSources = {
  'refresh':
    "#!/usr/bin/env bash\n##!/bin/bash\n\n############## Bash Script For Updating Debian Linux ###############\n####################################################################\n# bin/bash - Runs Only If Located In Specified Path\t\t           #\n# usr/bin/env bash - Any Bash In User Path (Respects Custom Paths) #\n# && Allows Run Text To Only Display Printf If The Command Runs    #\n# sha256sum update.sh > update.sh.sha256\t\t\t               #\n####################################################################\n\n# Checking Integrity of File Before Updating\nsha256sum -c update.sh.sha256 &&\nprintf '\\e[36mHash Verified\\e[0m\\n'\n\n# Updates Package List & Prints Run Text In Green\nsudo apt update &&\nprintf '\\e[32m^^Updates^^\\e[0m\\n'\n\n# Installs Available Package Updates From The List & Prints Run Text In Green\nsudo apt upgrade -y &&\nprintf '\\e[32m^^Upgrades^^\\e[0m\\n'\n\n# Updates Available Snap Packages & Prints Run Text In Green\nsudo snap refresh &&\nprintf '\\e[32m^^Snap-Updates^^\\e[0m\\n'\n\n# Updates Available System & User FlatPak Packages & Prints Run Text In Green\nsudo flatpak update --system -y && flatpak update --user -y &&\nprintf '\\e[32m^^Flatpak-Updates^^\\e[0m\\n'\n\n# Removes Unused Packages and Configurations & Prints Run Text In Green\nsudo apt autoremove --purge &&\nprintf '\\e[32m^^Auto-Remove^^\\e[0m\\n'\n\n# Cleans Old System Packages & Prints Run Text In Green\nsudo apt autoclean &&\nprintf '\\e[32m^^Auto-Clean^^\\e[0m\\n'\n\n# Purple Message of Script Completion\nprintf '\\e[35m[-------------------------------Script Complete--------------------------------]\\e[0m\\n'\n\n##################################\n# Printf > Echo\t\t\t         #\n# Printf = Versatile & Control   #\n# Echo = Bash & Control\t\t     #\n#        #########################\n#Bwynkoop#\n##########\n",
  'lynis':
    '#!/usr/bin/env bash\n##!/bin/bash\n\n###### Simple LYNIS Script For System Hardening Documentation ######\n####################################################################\n# bin/bash - Runs Only If Located In Specified Path                #\n# usr/bin/env bash - Any Bash In User Path (Respects Custom Paths) #\n####################################################################\n\n# Runs Lynis Audit Tool With Sudo Privileges \nsudo lynis audit system &&\n\n# Grabs Warnings & Suggestions from Lynis and sends it to lynis-review.txt \nsudo grep -E "warning|suggestion" /var/log/lynis-report.dat > lynis-review.txt &&\n\n# Opens the Generated Report In a text editor\nopen lynis-review.txt \n\n#########\n# Brady #\n#########\n\n# * CREDITS TO LYNIS AUDITING TOOL *\n',
};

let current = null,
  page = 0,
  tab = 'overview',
  lastFocus = null;

const dialog = document.querySelector('dialog'),
  body = document.querySelector('#dialog-body');

const escapeHTML = (s) =>
  s.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );

document.querySelector('#projects').innerHTML = projects
  .map(
    (p, i) =>
      `<button class="project" data-id="${p.id}" data-category="${p.category}" aria-label="${p.name || p.title}: ${p.terminal ? 'explore project' : 'read report'}"><div class="preview"><span class="preview-index">${String(i + 1).padStart(2, '0')} / ${p.category.toUpperCase()}</span>${p.terminal ? `<div class="terminal"><div class="terminal-head">● ● ● &nbsp; ${p.id === 'refresh' ? 'REFRESHX' : 'LYNISLENS'} / BASH</div><div class="cmd">${p.terminal[0]}</div><div>${p.terminal[1]}</div><div class="dim">${p.terminal[2]}</div></div>` : `<img class="paper behind" src="assets/${p.id}-1.webp" alt="" loading="lazy"><img class="paper" src="assets/${p.id}-1.webp" alt="" loading="lazy">`}<span class="preview-type">${p.terminal ? 'SOURCE & PROJECT PREVIEW' : 'INTERACTIVE REPORT ↗'}</span></div><div class="project-info"><div class="eyebrow">${p.label}</div><h3>${p.title}</h3><p>${p.desc}</p><div class="project-arrow">${p.terminal ? 'Explore project' : 'Open the report'} <span>↗</span></div></div></button>`,
  )
  .join('');

document.querySelectorAll('[data-filter]').forEach((b) =>
  b.addEventListener('click', () => {
    document.querySelectorAll('[data-filter]').forEach((a) => {
      a.classList.toggle('active', a === b);
      a.setAttribute('aria-pressed', a === b);
    });

    document
      .querySelectorAll('.project')
      .forEach(
        (p) =>
          (p.hidden =
            b.dataset.filter !== 'all' && p.dataset.category !== b.dataset.filter),
      );
  }),
);

document.querySelectorAll('[data-id]').forEach((b) =>
  b.addEventListener('click', async () => {
    lastFocus = b;
    current = projects.find((p) => p.id === b.dataset.id);
    page = 0;
    tab = 'overview';

    document.querySelector('#dialog-category').textContent = current.label;
    dialog.showModal();
    document.body.classList.add('modal-open');
    body.innerHTML = '<p style="padding:30px">Loading project…</p>';

    try {
      render();
    } catch (e) {
      body.innerHTML =
        '<p style="padding:30px">The preview could not load. Please refresh and try again.</p>';
    }
  }),
);

function close() {
  dialog.close();
}

document.querySelector('.close').addEventListener('click', close);

dialog.addEventListener('close', () => {
  document.body.classList.remove('modal-open');
  lastFocus?.focus();
});

dialog.addEventListener('click', (e) => {
  if (e.target === dialog) {
    const r = dialog.getBoundingClientRect();

    if (
      e.clientX < r.left ||
      e.clientX > r.right ||
      e.clientY < r.top ||
      e.clientY > r.bottom
    )
      close();
  }
});

const mobile = () => matchMedia('(max-width:600px)').matches;
const step = () => (mobile() ? 1 : 2);

function render(direction = '') {
  const p = current;

  body.innerHTML = `<div class="detail-heading"><div><h2 id="dialog-title">${p.name || p.title}</h2><p>${p.desc}</p></div><div class="detail-actions">${p.terminal ? `<a href="https://github.com/B-Wynkoop/${p.repo}" target="_blank" rel="noopener">View repository ↗</a>` : `<a href="reports/${p.id}.pdf" download>Download PDF ↓</a><a href="reports/${p.id}.pdf" target="_blank" rel="noopener">Open PDF ↗</a>`}</div></div>`;

  if (p.terminal) {
    renderCode();
    return;
  }

  const pages = reports[p.id];

  if (page >= pages.length) page = pages.length - 1;

  let shown = pages.slice(page, page + step());

  body.insertAdjacentHTML(
    'beforeend',
    `<div class="reader"><div class="spread ${direction}" aria-label="Report pages">${shown.map((v, i) => `<div class="page"><img src="${v.image}" alt="Report page ${page + i + 1}. Full page text available below."></div>`).join('')}${!mobile() && shown.length === 1 ? '<div class="page empty"><small>D. BRADY WYNKOOP</small>End of Report</div>' : ''}</div><div class="reader-controls"><button id="prev" aria-label="Previous pages" ${page === 0 ? 'disabled' : ''}>← Previous</button><span aria-live="polite">${shown.length > 1 ? `Pages ${page + 1}–${page + shown.length}` : `Page ${page + 1}`} of ${pages.length}</span><button id="next" aria-label="Next pages" ${page + step() >= pages.length ? 'disabled' : ''}>Next →</button><label>Go to <select id="page-select" aria-label="Go to report page">${pages.map((_, i) => `<option value="${i}" ${i === page ? 'selected' : ''}>${i + 1}</option>`).join('')}</select></label></div><p class="reader-help">${mobile() ? 'SWIPE TO TURN PAGES' : 'USE ← → ARROW KEYS TO TURN PAGES'} · ESC TO CLOSE</p></div><details class="readable-text"><summary>Read Accessible Page Text +</summary><pre>${shown.map((v, i) => `PAGE ${page + i + 1}\n\n${escapeHTML(v.text)}`).join('\n\n')}</pre></details>${p.takeaway ? `<div class="code-details"><h3>Project Context</h3><p>${p.takeaway}</p>${p.repo ? `<a class="project-arrow" href="https://github.com/B-Wynkoop/${p.repo}" target="_blank" rel="noopener">Explore the Evidence Repository ↗</a>` : ''}</div>` : ''}`,
  );

  document.querySelector('#prev').onclick = () => turn(-1);
  document.querySelector('#next').onclick = () => turn(1);

  document.querySelector('#page-select').onchange = (e) => {
    page = Number(e.target.value);
    render('turn-next');
  };

  let startX = 0,
    startY = 0;

  const spread = document.querySelector('.spread');

  spread.addEventListener(
    'touchstart',
    (e) => {
      startX = e.changedTouches[0].clientX;
      startY = e.changedTouches[0].clientY;
    },
    { passive: true },
  );

  spread.addEventListener(
    'touchend',
    (e) => {
      let dx = e.changedTouches[0].clientX - startX,
        dy = e.changedTouches[0].clientY - startY;

      if (Math.abs(dx) > 60 && Math.abs(dx) > Math.abs(dy) * 1.5) turn(dx < 0 ? 1 : -1);
    },
    { passive: true },
  );
}

function turn(dir) {
  if (!current || current.terminal) return;

  const next = page + dir * step();

  if (next < 0 || next >= reports[current.id].length) return;

  page = next;
  render(dir > 0 ? 'turn-next' : 'turn-prev');

  document.querySelector(dir > 0 ? '#next' : '#prev')?.focus({ preventScroll: true });
}

async function renderCode() {
  const p = current;

  body.insertAdjacentHTML(
    'beforeend',
    `<div class="code-details"><div class="code-tabs" role="group" aria-label="Project content"><button data-tab="overview" class="${tab === 'overview' ? 'active' : ''}">Overview</button><button data-tab="source" class="${tab === 'source' ? 'active' : ''}">Actual source</button></div><div id="code-content"></div></div>`,
  );

  document.querySelectorAll('[data-tab]').forEach(
    (b) =>
      (b.onclick = () => {
        tab = b.dataset.tab;
        render();
      }),
  );

  const target = document.querySelector('#code-content');

  if (tab === 'overview') {
    target.innerHTML = `<h3>The purpose</h3><p>${p.desc}</p><h3>How it works</h3><p>${p.takeaway}</p><p>This preview presents the repository’s source. Commands are not executed in your browser.</p>`;
  } else {
    target.textContent = 'Loading source…';

    try {
      const text = projectSources[p.id];

      if (typeof text !== 'string') throw Error();

      if (current === p && tab === 'source')
        target.innerHTML = `<p>Original repository source · ${p.id === 'refresh' ? 'update.sh' : 'lynis.sh'}</p><pre><code>${escapeHTML(text)}</code></pre>`;
    } catch {
      target.textContent = 'Source could not load. Use the repository link above.';
    }
  }
}

dialog.addEventListener('keydown', (e) => {
  if (['SELECT', 'INPUT', 'TEXTAREA'].includes(e.target.tagName)) return;

  if (e.key === 'ArrowRight') {
    e.preventDefault();
    turn(1);
  }

  if (e.key === 'ArrowLeft') {
    e.preventDefault();
    turn(-1);
  }
});

let wasMobile = mobile();

window.addEventListener('resize', () => {
  if (wasMobile !== mobile()) {
    wasMobile = mobile();

    if (dialog.open && !current.terminal) render();
  }
});

document.querySelector('#year').textContent = new Date().getFullYear();

window.addEventListener(
  'scroll',
  () => {
    const total = document.documentElement.scrollHeight - innerHeight;

    document.querySelector('#progress').style.width =
      `${total > 0 ? (scrollY / total) * 100 : 0}%`;
  },
  { passive: true },
);

const observer = new IntersectionObserver(
  (entries) =>
    entries.forEach((e) => {
      if (e.isIntersecting)
        document
          .querySelectorAll('nav a')
          .forEach((a) => a.classList.toggle('current', a.hash === `#${e.target.id}`));
    }),
  { rootMargin: '-15% 0px -65% 0px' },
);

document.querySelectorAll('#work,#about,#expertise').forEach((s) => observer.observe(s));