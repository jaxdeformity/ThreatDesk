"""Build the synthetic enterprise technology inventory used by the
Vulns tab.

The organisation is fictional ("Meridian Global Holdings", a diversified
Fortune-50-scale group: retail banking, insurance, logistics, healthcare
services). Counts, owners, versions and environments are invented. The
products and versions are real, so they line up with public
vulnerability data.

Each row: category, subcategory, vendor, product, version, environment,
count, owner, criticality, internet_facing, match.

``match`` lists the names CISA's KEV catalog uses for this product.
KEV naming is inconsistent (NetScaler alone appears under five product
names), so every entry carries its own match phrases. A phrase matches
when it reads inside "vendor product" of a KEV entry, or when its first
word is the KEV vendor and the rest starts the KEV product name.

Run:  python samples/build_inventory.py
Writes: samples/meridian-global.json
"""

from __future__ import annotations

import json
from pathlib import Path

C, H, M, L = "crown_jewel", "high", "medium", "low"

ROWS: list[tuple] = [
    # ── Network: perimeter, WAN, data centre fabric ─────────────────────
    ("Network", "Perimeter firewall", "Palo Alto Networks", "PA-7080 / PA-5450 (PAN-OS)", "11.1.4-h7", "Data centres (6), regional hubs (22)", 64, "Network Security Engineering", C, True, ["Palo Alto Networks PAN-OS"]),
    ("Network", "Perimeter firewall", "Palo Alto Networks", "Expedition (migration tool)", "1.2.96", "Network tooling VLAN", 2, "Network Security Engineering", M, False, ["Palo Alto Networks Expedition"]),
    ("Network", "Branch firewall", "Fortinet", "FortiGate 100F/200F (FortiOS)", "7.2.10", "Branches and retail stores (4,100)", 4180, "Branch Network Operations", H, True, ["Fortinet FortiOS", "Fortinet Multiple Products"]),
    ("Network", "Web proxy", "Fortinet", "FortiProxy", "7.4.6", "Regional egress", 18, "Branch Network Operations", H, True, ["Fortinet FortiProxy"]),
    ("Network", "Web application firewall", "Fortinet", "FortiWeb", "7.4.5", "Insurance customer portals", 12, "Application Security", H, True, ["Fortinet FortiWeb"]),
    ("Network", "Endpoint VPN management", "Fortinet", "FortiClient EMS", "7.2.4", "Branch IT management", 3, "Branch Network Operations", M, False, ["Fortinet FortiClient EMS", "Fortinet FortiClientEMS"]),
    ("Network", "Sandbox", "Fortinet", "FortiSandbox", "4.4.6", "Mail and web inspection", 4, "Security Operations", M, False, ["Fortinet FortiSandbox"]),
    ("Network", "Mail gateway", "Fortinet", "FortiMail", "7.4.3", "Logistics subsidiary mail", 6, "Messaging Engineering", M, True, ["Fortinet FortiMail"]),
    ("Network", "Data centre firewall", "Cisco", "Secure Firewall 4100 (ASA / FTD)", "ASA 9.18.4 / FTD 7.4.2", "Legacy acquisitions, PCI segment", 46, "Network Security Engineering", C, True, ["Cisco Adaptive Security Appliance", "Cisco Firepower Threat Defense", "Cisco Secure Firewall Adaptive Security Appliance", "Cisco Secure Firewall ASA", "Cisco ASA"]),
    ("Network", "Firewall management", "Cisco", "Secure Firewall Management Center (FMC)", "7.4.2", "Security management VLAN", 4, "Network Security Engineering", H, False, ["Cisco Secure Firewall Management Center"]),
    ("Network", "Campus and WAN routing", "Cisco", "Catalyst 9300/9500, ISR 4000 (IOS XE)", "17.9.5", "Campuses (140), WAN edge", 9200, "Enterprise Networking", H, False, ["Cisco IOS XE", "Cisco IOS and IOS XE", "Cisco IOS Software", "Cisco IOS software", "Cisco IOS, XR, and XE"]),
    ("Network", "Service provider core", "Cisco", "ASR 9000 (IOS XR)", "7.9.2", "Backbone, 8 PoPs", 32, "Enterprise Networking", C, False, ["Cisco IOS XR"]),
    ("Network", "SD-WAN", "Cisco", "Catalyst SD-WAN Manager / Controller", "20.12.3", "Global SD-WAN overlay", 9, "Enterprise Networking", C, True, ["Cisco Catalyst SD-WAN", "Cisco SD-WAN"]),
    ("Network", "Network access control", "Cisco", "Identity Services Engine (ISE)", "3.3 patch 2", "Campus 802.1X", 14, "Network Security Engineering", H, False, ["Cisco Identity Services Engine"]),
    ("Network", "Remote access VPN client", "Cisco", "Secure Client (AnyConnect)", "5.1.4", "Managed laptops", 142000, "End User Computing", M, False, ["Cisco AnyConnect"]),
    ("Network", "Data centre switching", "Arista", "7050X3 / 7280R3 (EOS)", "4.31.2F", "Data centres (6)", 1450, "Data Centre Networking", H, False, ["Arista Extensible Operating System", "Arista EOS"]),
    ("Network", "SD-WAN (acquired logistics unit)", "Arista", "VeloCloud Orchestrator", "5.2.1", "Logistics depots", 1, "Logistics IT", M, True, ["Arista VeloCloud", "VMware SD-WAN"]),
    ("Network", "Core routing (insurance)", "Juniper", "MX480 / SRX4600 (Junos OS)", "22.4R3", "Insurance data centres", 38, "Enterprise Networking", H, True, ["Juniper Junos OS", "Juniper Junos"]),
    ("Network", "Application delivery", "F5", "BIG-IP i10800 (LTM, APM, ASM)", "17.1.1.3", "Data centres, DMZ", 56, "Application Delivery", C, True, ["F5 BIG-IP"]),
    ("Network", "Application delivery", "Citrix", "NetScaler ADC / Gateway MPX 15000", "14.1-29.72", "Virtual desktop gateway, DMZ", 24, "End User Computing", C, True, ["Citrix NetScaler", "Citrix Application Delivery Controller", "Citrix ADC", "Citrix SD-WAN and NetScaler"]),
    ("Network", "Load balancer (healthcare)", "Progress", "Kemp LoadMaster", "7.2.59", "Clinic scheduling DMZ", 6, "Healthcare IT", M, True, ["Progress LoadMaster"]),
    ("Network", "SSL VPN (insurance)", "Ivanti", "Connect Secure", "22.7R2.4", "Insurance remote access", 8, "Insurance IT Infrastructure", C, True, ["Ivanti Connect Secure", "Ivanti Pulse Connect Secure", "Pulse Secure Pulse Connect Secure"]),
    ("Network", "Network access (insurance)", "Ivanti", "Policy Secure", "22.7R1", "Insurance campus NAC", 4, "Insurance IT Infrastructure", M, False, ["Ivanti Policy Secure"]),
    ("Network", "Retail store firewall", "SonicWall", "TZ670 (SonicOS)", "7.0.1-5145", "Pharmacy retail stores (acquired)", 620, "Retail IT", M, True, ["SonicWall SonicOS"]),
    ("Network", "Remote access (acquired)", "SonicWall", "SMA 1000", "12.4.3", "Pharmacy remote access", 2, "Retail IT", H, True, ["SonicWall SMA1000", "SonicWall SMA 1000"]),
    ("Network", "Warehouse Wi-Fi", "Ubiquiti", "UniFi OS (Dream Machine Pro)", "4.1.13", "Small logistics depots", 85, "Logistics IT", L, False, ["Ubiquiti UniFi"]),
    ("Network", "Wireless", "Hewlett Packard Enterprise (HPE)", "Aruba 7240XM controllers (ArubaOS)", "8.12.0.1", "Campuses", 120, "Enterprise Networking", M, False, ["Aruba ArubaOS", "HPE Aruba"]),
    ("Network", "DNS", "ISC", "BIND", "9.18.28", "External authoritative DNS", 16, "DNS and DHCP Services", C, True, ["ISC BIND"]),
    ("Network", "DDI", "Infoblox", "NIOS", "9.0.3", "Internal DNS, DHCP, IPAM", 48, "DNS and DHCP Services", C, False, ["Infoblox NIOS"]),
    ("Network", "Storage networking", "Broadcom", "Brocade G720 (Fabric OS)", "9.2.0b", "SAN fabrics", 96, "Storage Engineering", H, False, ["Broadcom Brocade Fabric OS", "Brocade Fabric OS"]),
    ("Network", "Cellular gateways", "Sierra Wireless", "AirLink RV55 (ALEOS)", "4.17.0", "Delivery fleet telematics", 3800, "Fleet Technology", M, True, ["Sierra Wireless AirLink"]),

    # ── Identity and access ─────────────────────────────────────────────
    ("Identity", "Directory", "Microsoft", "Active Directory Domain Services", "Windows Server 2022 DCs", "11 forests, 64 domain controllers", 64, "Identity Engineering", C, False, ["Microsoft Active Directory"]),
    ("Identity", "Federation", "Microsoft", "Active Directory Federation Services (AD FS)", "Windows Server 2019", "Legacy SAML apps", 8, "Identity Engineering", C, True, ["Microsoft Active Directory Federation Services"]),
    ("Identity", "Cloud identity", "Microsoft", "Entra ID (P2)", "SaaS", "Workforce identity, 210k users", 210000, "Identity Engineering", C, True, ["Microsoft Entra", "Microsoft Azure Active Directory"]),
    ("Identity", "Workforce SSO", "Okta", "Workforce Identity Cloud", "SaaS", "Acquired business units", 38000, "Identity Engineering", H, True, ["Okta"]),
    ("Identity", "Privileged access", "CyberArk", "Privileged Access Manager (PVWA, CPM, PSM)", "14.0", "Tier-0 vaults", 22, "Privileged Access", C, False, ["CyberArk"]),
    ("Identity", "Privileged remote access", "BeyondTrust", "Privileged Remote Access (PRA) / Remote Support (RS)", "24.2.2", "Vendor access, help desk", 6, "Privileged Access", C, True, ["BeyondTrust Remote Support", "BeyondTrust Privileged Remote Access"]),
    ("Identity", "Certificate services", "Microsoft", "Active Directory Certificate Services", "Windows Server 2019", "Internal PKI", 12, "Identity Engineering", C, False, ["Microsoft Active Directory Certificate Services"]),
    ("Identity", "MFA (legacy)", "RSA", "SecurID Authentication Manager", "8.7 SP1", "Mainframe and OT access", 4, "Identity Engineering", H, False, ["RSA SecurID"]),

    # ── End-user computing ───────────────────────────────────────────────
    ("Endpoints", "Desktop OS", "Microsoft", "Windows 11 Enterprise", "23H2 / 24H2", "Corporate laptops and desktops", 168000, "End User Computing", H, False, ["Microsoft Windows", "Microsoft Win32k", "Microsoft Windows Kernel", "Microsoft DirectX", "Microsoft Graphics Device Interface", "Microsoft MSHTML", "Microsoft SMBv1", "Microsoft Enhanced Cryptographic Provider", "Microsoft XML Core Services", "Microsoft Defender"]),
    ("Endpoints", "Desktop OS (legacy)", "Microsoft", "Windows 10 Enterprise LTSC", "21H2", "Branch kiosks, lab instruments", 21400, "End User Computing", M, False, ["Microsoft Windows"]),
    ("Endpoints", "Desktop OS", "Apple", "macOS", "Sonoma 14.7 / Sequoia 15.2", "Design, engineering, executives", 18600, "End User Computing", M, False, ["Apple macOS", "Apple OS X", "Apple iOS and macOS", "Apple iOS, iPadOS, and macOS", "Apple Multiple Products"]),
    ("Endpoints", "Mobile", "Apple", "iOS / iPadOS", "17.7 / 18.2", "Corporate phones, clinician iPads", 96000, "Mobility", M, True, ["Apple iOS", "Apple iPadOS", "Apple iOS and iPadOS", "Apple Multiple Products"]),
    ("Endpoints", "Mobile", "Samsung", "Galaxy S23/S24, XCover6 Pro (Android 14)", "One UI 6.1", "Field logistics, store associates", 54000, "Mobility", M, True, ["Samsung Mobile Devices", "Android Framework", "Android Kernel", "Android Runtime", "Android Android Kernel", "Qualcomm Multiple Chipsets", "Qualcomm Chipsets", "Arm Mali"]),
    ("Endpoints", "Mobile", "Google", "Pixel 8 (Android 15)", "AP4A", "Security team test devices", 140, "Mobility", L, True, ["Google Pixel", "Android Pixel"]),
    ("Endpoints", "Browser", "Google", "Chrome Enterprise", "131", "All managed endpoints", 190000, "End User Computing", H, True, ["Google Chromium", "Google Chrome", "Google Skia", "Google Dawn"]),
    ("Endpoints", "Browser", "Microsoft", "Edge", "131", "All managed Windows endpoints", 189000, "End User Computing", H, True, ["Microsoft Edge"]),
    ("Endpoints", "Browser (legacy mode)", "Microsoft", "Internet Explorer 11 mode", "IE mode in Edge", "Claims and mainframe web front ends", 40000, "End User Computing", M, False, ["Microsoft Internet Explorer"]),
    ("Endpoints", "Browser", "Mozilla", "Firefox ESR", "128.5", "Developers, research", 9200, "End User Computing", L, True, ["Mozilla Firefox", "Mozilla Multiple Products"]),
    ("Endpoints", "Productivity", "Microsoft", "Microsoft 365 Apps for enterprise", "2408 (Semi-Annual Enterprise)", "All knowledge workers", 182000, "End User Computing", H, False, ["Microsoft Office", "Microsoft Word", "Microsoft Excel", "Microsoft PowerPoint", "Microsoft Outlook", "Microsoft Visual Basic for Applications"]),
    ("Endpoints", "PDF", "Adobe", "Acrobat Reader DC / Acrobat Pro", "24.005", "All endpoints", 176000, "End User Computing", M, False, ["Adobe Acrobat", "Adobe Reader"]),
    ("Endpoints", "Archive", "RARLAB", "WinRAR", "7.01", "Finance, engineering (exception list)", 3100, "End User Computing", L, False, ["RARLAB WinRAR"]),
    ("Endpoints", "Editor", "Notepad++", "Notepad++", "8.6.9", "Developer workstations", 14000, "End User Computing", L, False, ["Notepad++"]),
    ("Endpoints", "Thin clients", "IGEL", "IGEL OS", "12.4.2", "Call centres, hospital wards", 26000, "End User Computing", M, False, ["IGEL OS"]),
    ("Endpoints", "Disk tools", "Daemon", "Daemon Tools Lite", "12.1", "Training labs (unapproved, being removed)", 40, "End User Computing", L, False, ["Daemon Tools"]),
    ("Endpoints", "Vendor tools", "ASUS", "Live Update", "3.6.8", "Engineering workstations (ASUS ProArt)", 260, "End User Computing", L, False, ["ASUS Live Update"]),
    ("Endpoints", "Messaging (BYOD)", "Meta Platforms", "WhatsApp", "2.24", "Unmanaged personal devices with work profile", 30000, "Mobility", L, True, ["Meta Platforms WhatsApp", "WhatsApp"]),

    # ── Endpoint management and security ───────────────────────────────
    ("Endpoint management", "Configuration management", "Microsoft", "Configuration Manager (MECM)", "2403", "Global, 4 primary sites", 31, "Client Engineering", C, False, ["Microsoft Configuration Manager"]),
    ("Endpoint management", "UEM", "Microsoft", "Intune", "SaaS", "Windows, iOS, Android", 300000, "Client Engineering", H, True, ["Microsoft Intune"]),
    ("Endpoint management", "MDM (insurance)", "Ivanti", "Endpoint Manager Mobile (EPMM / MobileIron Core)", "12.1.0.1", "Insurance mobile fleet", 4, "Insurance IT Infrastructure", C, True, ["Ivanti Endpoint Manager Mobile", "Ivanti EPMM", "MobileIron Core"]),
    ("Endpoint management", "Endpoint manager (insurance)", "Ivanti", "Endpoint Manager (EPM)", "2024 SU1", "Insurance desktops", 3, "Insurance IT Infrastructure", H, False, ["Ivanti Endpoint Manager (EPM)", "Ivanti Endpoint Manager"]),
    ("Endpoint management", "Cloud services appliance", "Ivanti", "Cloud Services Appliance (CSA)", "5.0.2", "Insurance remote endpoints", 2, "Insurance IT Infrastructure", H, True, ["Ivanti Cloud Services Appliance"]),
    ("Endpoint management", "Mobile gateway", "Ivanti", "Sentry", "9.20", "Insurance mobile mail", 4, "Insurance IT Infrastructure", M, True, ["Ivanti Sentry"]),
    ("Endpoint management", "UEM (logistics)", "Omnissa", "Workspace ONE UEM", "2406", "Rugged scanners, drivers' tablets", 61000, "Fleet Technology", H, True, ["Omnissa Workspace One", "VMware Workspace ONE"]),
    ("Endpoint management", "Systems management (pharmacy)", "Quest", "KACE Systems Management Appliance", "14.0", "Pharmacy stores", 2, "Retail IT", M, True, ["Quest KACE"]),
    ("Endpoint management", "Asset agent (Japan)", "Motex", "LANSCOPE Endpoint Manager", "9.4", "Japan subsidiary", 2400, "APAC IT", L, False, ["Motex LANSCOPE"]),
    ("Endpoint management", "Asset agent (Japan)", "SKYSEA", "Client View", "19.2", "Japan subsidiary plants", 900, "APAC IT", L, False, ["SKYSEA Client View"]),
    ("Security tooling", "EDR", "CrowdStrike", "Falcon sensor", "7.18", "All Windows, macOS, Linux", 240000, "Security Operations", C, False, ["CrowdStrike Falcon"]),
    ("Security tooling", "EDR (legacy)", "Trend Micro", "Apex One", "2019 (SaaS agent)", "Healthcare clinics (migration in progress)", 7800, "Healthcare IT", M, False, ["Trend Micro Apex One"]),
    ("Security tooling", "Antivirus", "Microsoft", "Defender for Endpoint", "Platform 4.18.24090", "All Windows endpoints and servers", 220000, "Security Operations", H, False, ["Microsoft Defender", "Microsoft Malware Protection Engine"]),
    ("Security tooling", "SIEM", "Splunk", "Enterprise / Enterprise Security", "9.2.3 / ES 7.3", "Security data platform", 210, "Security Operations", C, False, ["Splunk Enterprise"]),
    ("Security tooling", "Host monitoring", "Wazuh", "Wazuh Server", "4.8.1", "Retail Linux POS servers", 6, "Retail IT", M, False, ["Wazuh"]),
    ("Security tooling", "Container scanning", "Aquasecurity", "Trivy", "0.56.2", "CI pipelines", 1, "Platform Engineering", M, False, ["Aquasecurity Trivy", "Aqua Security Trivy"]),
    ("Security tooling", "Red team", "Fortra", "Cobalt Strike", "4.10", "Internal red team (licensed)", 3, "Offensive Security", M, False, ["Fortra Cobalt Strike", "HelpSystems Cobalt Strike"]),
    ("Security tooling", "Email security", "Cisco", "Secure Email Gateway (ESA)", "15.5.1", "Corporate mail hygiene", 16, "Messaging Engineering", C, True, ["Cisco Secure Email", "Cisco Email Security"]),
    ("Security tooling", "Email security (pharmacy)", "Barracuda Networks", "Email Security Gateway", "9.2", "Pharmacy subsidiary", 2, "Retail IT", M, True, ["Barracuda Networks Barracuda Email Security Gateway", "Barracuda Networks Multiple Products", "Barracuda Email Security"]),
    ("Security tooling", "Firewall (Europe)", "Check Point", "Quantum Security Gateway", "R81.20", "European subsidiaries", 40, "EMEA IT", H, True, ["Check Point Security Gateway", "Check Point Multiple Products", "Check Point Quantum"]),
    ("Security tooling", "Firewall management (Europe)", "Check Point", "SmartConsole", "R81.20", "EMEA security admins", 30, "EMEA IT", M, False, ["Check Point SmartConsole"]),

    # ── Server operating systems ────────────────────────────────────────
    ("Server OS", "Windows Server", "Microsoft", "Windows Server 2022 Datacenter", "21H2 (20348)", "Data centres, Azure", 21800, "Server Engineering", H, False, ["Microsoft Windows", "Microsoft Win32k", "Microsoft Windows Kernel", "Microsoft Internet Key Exchange (IKE)"]),
    ("Server OS", "Windows Server", "Microsoft", "Windows Server 2019 / 2016", "1809 / 1607", "Data centres, legacy apps", 9600, "Server Engineering", H, False, ["Microsoft Windows"]),
    ("Server OS", "Windows Server (unsupported)", "Microsoft", "Windows Server 2012 R2 (ESU)", "6.3", "Mainframe gateways, lab systems", 410, "Server Engineering", H, False, ["Microsoft Windows"]),
    ("Server OS", "Linux", "Red Hat", "Enterprise Linux 9 / 8", "9.4 / 8.10", "Data centres, AWS, Azure", 28400, "Linux Engineering", H, False, ["Linux Kernel", "Red Hat Enterprise Linux", "Red Hat Polkit", "Red Hat Libuser", "Red Hat Automatic Bug Reporting Tool", "Sudo Sudo", "GNU Bash", "GNU Bourne-Again Shell", "GNU InetUtils", "OpenBSD OpenSSH", "Microsoft Open Management Infrastructure"]),
    ("Server OS", "Linux", "Canonical", "Ubuntu Server LTS", "22.04 / 24.04", "Kubernetes nodes, ML clusters", 14600, "Linux Engineering", H, False, ["Linux Kernel", "Canonical Ubuntu"]),
    ("Server OS", "Linux", "SUSE", "Linux Enterprise Server for SAP", "15 SP5", "SAP HANA hosts", 380, "SAP Basis", C, False, ["Linux Kernel", "SUSE"]),
    ("Server OS", "Unix", "IBM", "AIX", "7.3 TL2", "Core banking (Power10)", 120, "Core Banking Infrastructure", C, False, ["IBM AIX"]),
    ("Server OS", "Mainframe", "IBM", "z/OS", "3.1", "Card processing, policy admin (z16)", 4, "Mainframe Systems", C, False, ["IBM z/OS"]),
    ("Server OS", "Appliance OS", "Unraid", "Unraid", "6.12", "Media lab (shadow IT, being removed)", 1, "Marketing", L, False, ["Unraid"]),

    # ── Server and data-centre hardware ─────────────────────────────────
    ("Hardware", "Compute", "Dell", "PowerEdge R760 / R660", "BIOS 2.3.5, iDRAC9 7.10", "Data centres", 14200, "Data Centre Engineering", H, False, ["Dell iDRAC", "Dell PowerEdge"]),
    ("Hardware", "Compute", "Hewlett Packard Enterprise (HPE)", "ProLiant DL380 Gen11", "iLO 6 1.62", "Data centres", 6800, "Data Centre Engineering", H, False, ["Hewlett Packard Enterprise (HPE) iLO", "HPE iLO"]),
    ("Hardware", "Infrastructure management", "Hewlett Packard Enterprise (HPE)", "OneView", "9.0", "HPE fleet management", 3, "Data Centre Engineering", H, False, ["Hewlett Packard Enterprise (HPE) OneView", "HPE OneView"]),
    ("Hardware", "Compute", "Cisco", "UCS X-Series / Intersight", "5.2(2)", "VDI and private cloud", 1900, "Data Centre Engineering", H, False, ["Cisco UCS", "Cisco Intersight"]),
    ("Hardware", "Hyperconverged (legacy)", "Cisco", "HyperFlex HX", "5.0(2e)", "Retail edge clusters", 140, "Retail IT", M, False, ["Cisco HyperFlex"]),
    ("Hardware", "BMC firmware", "AMI", "MegaRAC SPx (OEM BMC)", "13.x", "White-box GPU servers, storage nodes", 2600, "Data Centre Engineering", H, False, ["AMI MegaRAC"]),
    ("Hardware", "GPU servers", "Supermicro", "SYS-821GE-TNHR (8x H100)", "BMC 1.03.18", "AI training cluster", 512, "AI Platform", C, False, ["Supermicro"]),
    ("Hardware", "Motherboards / firmware", "GIGABYTE", "Server and workstation boards (UEFI)", "F14", "Engineering render farm", 380, "Data Centre Engineering", L, False, ["GIGABYTE Multiple Products"]),
    ("Hardware", "Storage", "Dell", "PowerMax 8500 / PowerStore 5200T", "PowerMaxOS 10.1", "Tier-1 block storage", 42, "Storage Engineering", C, False, ["Dell PowerMax", "Dell PowerStore"]),
    ("Hardware", "Storage", "NetApp", "AFF A900 (ONTAP)", "9.14.1P6", "File services, VMware datastores", 64, "Storage Engineering", C, False, ["NetApp ONTAP"]),
    ("Hardware", "Storage", "Pure Storage", "FlashArray//XL (Purity)", "6.6.10", "Database tier", 28, "Storage Engineering", C, False, ["Pure Storage"]),
    ("Hardware", "NAS (branch)", "QNAP", "TS-873A (QTS)", "5.1.8", "Regional offices", 210, "Branch Network Operations", M, True, ["QNAP Network Attached Storage", "QNAP Photo Station", "QNAP QTS"]),
    ("Hardware", "NAS (lab)", "Zyxel", "NAS542", "5.21", "Logistics depot CCTV storage", 30, "Facilities", L, False, ["Zyxel Multiple Network-Attached Storage"]),
    ("Hardware", "Network appliances (depots)", "Zyxel", "USG FLEX 200 / ATP500", "5.38", "Small depots (acquired)", 140, "Logistics IT", M, True, ["Zyxel Multiple Firewalls", "Zyxel USG", "Zyxel ATP"]),
    ("Hardware", "Mobile chipsets", "Qualcomm", "Snapdragon 8 Gen 2/3", "Vendor BSP", "Corporate Android phones", 54000, "Mobility", M, False, ["Qualcomm Multiple Chipsets", "Qualcomm Chipsets"]),
    ("Hardware", "Mobile GPU", "Arm", "Mali GPU (Exynos devices)", "r47p0", "XCover rugged phones", 18000, "Mobility", L, False, ["Arm Mali"]),
    ("Hardware", "Serial device servers", "Lantronix", "EDS5000", "2.1.0.0R3", "Distribution centre PLC links", 220, "OT Engineering", M, False, ["Lantronix EDS5000"]),

    # ── Virtualisation and private cloud ────────────────────────────────
    ("Virtualisation", "Hypervisor", "Broadcom", "VMware ESXi", "8.0 U3b / 7.0 U3q", "Data centres (2,100 hosts)", 2100, "Private Cloud Engineering", C, False, ["VMware ESXi", "Broadcom VMware ESX", "VMware ESXi, Workstation", "VMware ESXi and Workstation", "VMware Multiple Products"]),
    ("Virtualisation", "Management", "Broadcom", "VMware vCenter Server", "8.0 U3d", "14 vCenters", 14, "Private Cloud Engineering", C, False, ["VMware vCenter", "Broadcom VMware vCenter"]),
    ("Virtualisation", "Operations", "Broadcom", "VMware Aria Operations / Automation", "8.18", "Private cloud operations", 6, "Private Cloud Engineering", H, False, ["VMware Aria Operations", "Broadcom VMware Aria Operations", "VMware vRealize", "VMware Aria"]),
    ("Virtualisation", "Guest tools", "Broadcom", "VMware Tools", "12.4.5", "All VMware guests", 41000, "Private Cloud Engineering", M, False, ["Broadcom VMware Aria Operations and VMware Tools", "VMware Tools"]),
    ("Virtualisation", "Desktop hypervisor", "Broadcom", "VMware Workstation Pro", "17.6", "Developer workstations", 2300, "End User Computing", L, False, ["VMware Workstation"]),
    ("Virtualisation", "Hypervisor", "Microsoft", "Hyper-V / Azure Stack HCI", "23H2", "Branch and clinic edge clusters", 860, "Server Engineering", H, False, ["Microsoft Hyper-V", "Microsoft Windows"]),
    ("Virtualisation", "Hypervisor", "Nutanix", "AHV / Prism Central", "6.8.1 / pc.2024.2", "Insurance VDI", 240, "Insurance IT Infrastructure", H, False, ["Nutanix"]),
    ("Virtualisation", "Virtual desktops", "Citrix", "Virtual Apps and Desktops (CVAD)", "2402 LTSR CU1", "Call centres, offshore partners", 46000, "End User Computing", C, True, ["Citrix Virtual Apps", "Citrix Workspace", "Citrix Session Recording"]),
    ("Virtualisation", "Disaster recovery", "Dell", "RecoverPoint for Virtual Machines", "6.0 SP1", "DR replication", 8, "Storage Engineering", H, False, ["Dell RecoverPoint"]),

    # ── Public cloud (multi-cloud) ──────────────────────────────────────
    ("Cloud", "AWS", "Amazon Web Services", "EC2, EKS, RDS, S3, Lambda", "Org with 1,840 accounts", "us-east-1, us-west-2, eu-west-1, ap-southeast-2", 1840, "Cloud Platform (AWS)", C, True, ["Amazon Web Services", "AWS"]),
    ("Cloud", "Azure", "Microsoft", "Azure (AKS, App Service, SQL MI, Functions)", "1,120 subscriptions", "East US 2, West Europe, UK South", 1120, "Cloud Platform (Azure)", C, True, ["Microsoft Azure"]),
    ("Cloud", "Google Cloud", "Google", "Google Cloud (GKE, BigQuery, Vertex AI)", "420 projects", "us-central1, europe-west4", 420, "Data and AI Platform", H, True, ["Google Cloud"]),
    ("Cloud", "Oracle Cloud", "Oracle", "OCI (Exadata Cloud, Fusion Apps)", "ERP tenancy", "Ashburn, Frankfurt", 1, "Finance Systems", C, True, ["Oracle Cloud Infrastructure"]),
    ("Cloud", "Kubernetes", "Red Hat", "OpenShift Container Platform", "4.15.30", "On-prem and ROSA", 46, "Platform Engineering", C, False, ["Red Hat OpenShift"]),
    ("Cloud", "Kubernetes", "CNCF", "Kubernetes (EKS / AKS / GKE)", "1.29 / 1.30", "Managed clusters", 310, "Platform Engineering", C, True, ["Kubernetes"]),
    ("Cloud", "Infrastructure as code", "HashiCorp", "Terraform Enterprise", "v202409-2", "Cloud landing zones", 3, "Platform Engineering", H, False, ["HashiCorp Terraform"]),
    ("Cloud", "Secrets", "HashiCorp", "Vault Enterprise", "1.17.6", "Application secrets", 12, "Platform Engineering", C, False, ["HashiCorp Vault"]),
    ("Cloud", "Object storage (on-prem)", "MinIO", "MinIO", "RELEASE.2024-08-17", "ML feature store", 24, "AI Platform", M, False, ["MinIO"]),
    ("Cloud", "Configuration management", "SaltStack", "Salt", "3006.9", "Linux fleet configuration", 4, "Linux Engineering", H, False, ["SaltStack Salt", "VMware Salt"]),
    ("Cloud", "Configuration management", "Red Hat", "Ansible Automation Platform", "2.4", "Network and server automation", 9, "Automation Engineering", H, False, ["Red Hat Ansible"]),

    # ── Collaboration and messaging ─────────────────────────────────────
    ("Collaboration", "Email (on-prem hybrid)", "Microsoft", "Exchange Server Subscription Edition", "SE RTM", "Hybrid relay, journaling, 3 sites", 18, "Messaging Engineering", C, True, ["Microsoft Exchange Server", "Microsoft Exchange"]),
    ("Collaboration", "Email (cloud)", "Microsoft", "Exchange Online", "SaaS", "All mailboxes", 210000, "Messaging Engineering", C, True, ["Microsoft Exchange Online"]),
    ("Collaboration", "Intranet", "Microsoft", "SharePoint Server Subscription Edition", "24H2", "Legal, compliance, intranet", 22, "Collaboration Platforms", C, True, ["Microsoft SharePoint"]),
    ("Collaboration", "Email (acquired)", "Synacor", "Zimbra Collaboration Suite", "10.0.9", "Freight subsidiary (migration Q3)", 4, "Logistics IT", M, True, ["Synacor Zimbra", "Zimbra Collaboration Suite"]),
    ("Collaboration", "Webmail (acquired)", "Roundcube", "Webmail", "1.6.7", "Freight subsidiary", 2, "Logistics IT", M, True, ["Roundcube Webmail", "Roundcube Roundcube Webmail"]),
    ("Collaboration", "Mail server (Europe)", "Exim", "Exim", "4.97", "EMEA outbound relays", 6, "EMEA IT", M, True, ["Exim"]),
    ("Collaboration", "Wiki", "Atlassian", "Confluence Data Center", "8.5.14", "Engineering knowledge base", 6, "Developer Platforms", H, True, ["Atlassian Confluence"]),
    ("Collaboration", "Issue tracking", "Atlassian", "Jira Software Data Center", "9.12.12", "Engineering and change", 8, "Developer Platforms", C, True, ["Atlassian Jira", "Atlassian Multiple Products"]),
    ("Collaboration", "Wiki (R&D)", "XWiki", "XWiki Platform", "15.10.11", "Pharma research wiki", 1, "Research IT", L, False, ["XWiki Platform"]),
    ("Collaboration", "Documents", "ONLYOFFICE", "Docs", "8.1.3", "Research collaboration (Linux)", 2, "Research IT", L, False, ["ONLYOFFICE Docs"]),
    ("Collaboration", "Documents", "Collabora", "Collabora Online (CODE)", "24.04", "Nextcloud integration, research", 2, "Research IT", L, False, ["Collabora Online"]),
    ("Collaboration", "File sync (research)", "ownCloud", "ownCloud Server", "10.15", "Research partners", 1, "Research IT", L, True, ["ownCloud"]),
    ("Collaboration", "Video", "Zoom", "Workplace", "6.2", "All employees", 200000, "Collaboration Platforms", M, True, ["Zoom"]),
    ("Collaboration", "Telephony", "Cisco", "Unified Communications Manager / BroadWorks", "15 SU2", "Contact centres", 18, "Unified Communications", C, False, ["Cisco Unified Communications Manager", "Cisco BroadWorks"]),
    ("Collaboration", "Telephony (healthcare)", "Mitel", "MiCollab / MiVoice Connect", "9.8 SP1", "Clinics", 12, "Healthcare IT", M, True, ["Mitel MiCollab", "Mitel MiVoice"]),
    ("Collaboration", "Telephony (stores)", "Sangoma", "FreePBX / Switchvox", "16.0.40", "Pharmacy stores", 80, "Retail IT", L, True, ["Sangoma FreePBX", "Sangoma Switchvox"]),
    ("Collaboration", "Telephony (lab)", "SignalWire", "FreeSWITCH", "1.10.11", "IVR development", 3, "Contact Centre Engineering", L, False, ["SignalWire FreeSwitch"]),
    ("Collaboration", "Video conferencing (Russia JV, frozen)", "TrueConf", "Server", "5.2", "Dormant joint-venture office", 1, "EMEA IT", L, True, ["TrueConf"]),

    # ── Business applications ───────────────────────────────────────────
    ("Business applications", "ERP", "SAP", "S/4HANA 2023 and ECC 6.0 EHP8 (NetWeaver)", "S/4 2023 FPS01, NW 7.50", "Finance, supply chain, HR", 140, "SAP Basis", C, True, ["SAP NetWeaver", "SAP S/4HANA", "SAP Multiple Products"]),
    ("Business applications", "ERP (insurance)", "Oracle", "E-Business Suite", "12.2.12", "Insurance general ledger", 12, "Finance Systems", C, False, ["Oracle E-Business Suite"]),
    ("Business applications", "HR (legacy)", "Oracle", "PeopleSoft HCM (PeopleTools)", "9.2 / 8.61", "Canadian payroll", 6, "HR Technology", H, False, ["Oracle PeopleSoft"]),
    ("Business applications", "PLM", "Oracle", "Agile Product Lifecycle Management", "9.3.6", "Medical device engineering", 4, "Engineering Systems", H, False, ["Oracle Agile Product Lifecycle Management"]),
    ("Business applications", "PLM", "PTC", "Windchill", "12.1.2", "Manufacturing subsidiary", 6, "Engineering Systems", H, False, ["PTC Windchill"]),
    ("Business applications", "Manufacturing execution", "Dassault Systèmes", "DELMIA Apriso", "2024", "Medical devices plants", 4, "Manufacturing IT", H, False, ["Dassault Systèmes DELMIA Apriso", "Dassault DELMIA"]),
    ("Business applications", "ITSM", "ServiceNow", "Now Platform", "Washington DC Patch 7", "IT, HR, security operations", 1, "Enterprise Service Management", C, True, ["ServiceNow"]),
    ("Business applications", "CRM", "Salesforce", "Sales and Service Cloud", "SaaS", "Insurance agents, commercial banking", 52000, "CRM Platforms", H, True, ["Salesforce"]),
    ("Business applications", "Analytics", "Qlik", "Qlik Sense Enterprise", "May 2024 Patch 6", "Supply chain analytics", 6, "Data and AI Platform", M, True, ["Qlik Sense"]),
    ("Business applications", "Reporting", "TIBCO", "JasperReports Server", "8.2", "Claims reporting", 3, "Insurance Applications", M, False, ["TIBCO JasperReports"]),
    ("Business applications", "Analytics (legacy)", "Hitachi Vantara", "Pentaho Business Analytics Server", "9.3", "Logistics BI", 2, "Logistics IT", L, False, ["Hitachi Vantara Pentaho"]),
    ("Business applications", "BI", "Metabase", "Metabase", "0.50.21", "Product analytics", 2, "Digital Products", L, True, ["Metabase"]),
    ("Business applications", "Print management", "PaperCut", "PaperCut MF", "23.0.9", "All offices", 36, "End User Computing", M, False, ["PaperCut NG/MF", "PaperCut"]),
    ("Business applications", "Signage", "Samsung", "MagicINFO 9 Server", "21.1050", "Retail and lobby signage", 4, "Facilities", L, True, ["Samsung MagicINFO"]),
    ("Business applications", "Time and attendance", "ZKTeco", "BioTime", "9.0.1", "Warehouses (biometric clocks)", 3, "Logistics IT", M, False, ["ZKTeco BioTime"]),
    ("Business applications", "Help desk (logistics)", "SolarWinds", "Web Help Desk", "12.8.3", "Logistics IT help desk", 1, "Logistics IT", M, True, ["SolarWinds Web Help Desk"]),
    ("Business applications", "Help desk (pharmacy)", "SysAid", "SysAid On-Prem", "23.3.38", "Pharmacy IT", 1, "Retail IT", M, True, ["SysAid"]),
    ("Business applications", "Customer support", "Zammad GmbH", "Zammad", "6.3", "EMEA customer support", 1, "EMEA IT", L, True, ["Zammad"]),
    ("Business applications", "Order management (3PL)", "Advantive", "VeraCore", "2024.1", "E-commerce fulfilment", 1, "Logistics IT", H, True, ["Advantive VeraCore"]),

    # ── Databases and data platforms ────────────────────────────────────
    ("Databases", "Relational", "Oracle", "Database Enterprise Edition / Exadata X9M", "19.24 / 23ai", "Core banking, policy admin", 860, "Database Engineering", C, False, ["Oracle Database"]),
    ("Databases", "Relational", "Microsoft", "SQL Server Enterprise", "2019 CU28 / 2022 CU15", "Line-of-business apps", 6400, "Database Engineering", C, False, ["Microsoft SQL Server"]),
    ("Databases", "In-memory", "SAP", "HANA", "2.0 SPS07", "S/4HANA", 120, "SAP Basis", C, False, ["SAP HANA"]),
    ("Databases", "Relational", "PostgreSQL", "PostgreSQL", "15.8 / 16.4", "Digital platforms", 3100, "Database Engineering", H, False, ["PostgreSQL"]),
    ("Databases", "Document", "MongoDB", "MongoDB Enterprise Server", "7.0.14", "Mobile app back ends", 420, "Database Engineering", H, False, ["MongoDB"]),
    ("Databases", "Search", "Elastic", "Elasticsearch / Kibana", "8.15.2", "Observability, fraud search", 640, "Observability Engineering", H, False, ["Elastic Elasticsearch", "Elastic Kibana"]),
    ("Databases", "Search", "Apache", "Solr", "9.6.1", "Product catalogue search", 40, "Digital Products", M, True, ["Apache Solr"]),
    ("Databases", "Cache", "Redis", "Redis Enterprise", "7.4", "Session stores", 380, "Database Engineering", H, False, ["Redis"]),
    ("Databases", "Streaming", "Confluent", "Confluent Platform (Apache Kafka)", "7.7", "Event streaming", 220, "Data Platform Engineering", C, False, ["Apache Kafka"]),
    ("Databases", "Messaging", "Apache", "ActiveMQ Classic", "5.18.4", "Claims integration bus", 18, "Integration Engineering", H, False, ["Apache ActiveMQ"]),
    ("Databases", "Messaging", "IBM", "MQ", "9.3.0.20", "Payments messaging", 90, "Integration Engineering", C, False, ["IBM MQ"]),
    ("Databases", "Data warehouse", "Snowflake", "Snowflake", "SaaS", "Enterprise data warehouse", 1, "Data Platform Engineering", C, True, ["Snowflake"]),
    ("Databases", "Lakehouse", "Databricks", "Databricks on AWS and Azure", "Runtime 15.4 LTS", "Analytics and ML", 1, "Data and AI Platform", C, True, ["Databricks"]),
    ("Databases", "Data risk", "IBM", "Data Risk Manager", "2.0.6", "Database security analytics", 1, "Data Protection", M, False, ["IBM Data Risk Manager"]),

    # ── Middleware and application servers ─────────────────────────────
    ("Middleware", "Java EE", "Oracle", "WebLogic Server", "14.1.1.0 / 12.2.1.4", "Policy admin, claims", 340, "Middleware Engineering", C, True, ["Oracle WebLogic", "Oracle Fusion Middleware", "Oracle HTTP Server"]),
    ("Middleware", "Java EE", "Red Hat", "JBoss EAP", "7.4.18", "Banking channels", 520, "Middleware Engineering", H, False, ["Red Hat JBoss"]),
    ("Middleware", "Java EE", "IBM", "WebSphere Application Server", "9.0.5.20", "Mainframe integration", 160, "Middleware Engineering", H, False, ["IBM WebSphere"]),
    ("Middleware", "Servlet container", "Apache", "Tomcat", "9.0.96 / 10.1.31", "Internal web apps", 4200, "Middleware Engineering", H, True, ["Apache Tomcat"]),
    ("Middleware", "Web server", "Apache", "HTTP Server", "2.4.62", "Reverse proxies, static content", 2600, "Middleware Engineering", H, True, ["Apache HTTP Server"]),
    ("Middleware", "Web server", "F5", "NGINX Plus", "R32", "API ingress", 880, "Application Delivery", H, True, ["F5 NGINX", "NGINX"]),
    ("Middleware", "Web server", "Microsoft", "IIS", "10.0", "Windows web apps", 5200, "Server Engineering", H, True, ["Microsoft Internet Information Services", "Microsoft IIS"]),
    ("Middleware", "Runtime", "Microsoft", ".NET Framework / .NET", "4.8.1 / 8.0.10", "Windows apps", 26000, "Application Platforms", H, False, ["Microsoft .NET Framework", "Microsoft .NET"]),
    ("Middleware", "Runtime", "Oracle", "Java SE (JDK / JRE)", "8u431 / 17.0.13 / 21.0.5", "Servers and endpoints", 61000, "Application Platforms", H, False, ["Oracle Java SE", "Oracle Java Runtime Environment"]),
    ("Middleware", "Runtime", "Erlang", "Erlang/OTP", "26.2.5", "RabbitMQ clusters", 60, "Integration Engineering", M, False, ["Erlang Erlang/OTP"]),
    ("Middleware", "Runtime", "PHP Group", "PHP", "8.2.24", "Marketing sites, legacy portals", 140, "Digital Products", M, True, ["PHP Group PHP"]),
    ("Middleware", "API gateway", "WSO2", "API Manager", "4.2.0", "Partner APIs (insurance)", 8, "Integration Engineering", H, True, ["WSO2 Multiple Products", "WSO2 API Manager"]),
    ("Middleware", "Integration", "MuleSoft", "Anypoint Runtime", "4.6", "System APIs", 220, "Integration Engineering", H, False, ["MuleSoft"]),
    ("Middleware", "Web UI library", "Telerik", "UI for ASP.NET AJAX", "2019.3.1023", "Legacy agent portal", 6, "Insurance Applications", H, True, ["Telerik User Interface (UI) for ASP.NET AJAX", "Telerik UI"]),
    ("Middleware", "Web UI library", "Ajax.NET Professional", "Ajax.NET Professional", "21.12.22.1", "Legacy claims intake", 2, "Insurance Applications", M, True, ["Ajax.NET Professional"]),

    # ── Web, CMS and digital ────────────────────────────────────────────
    ("Web and CMS", "CMS", "Sitecore", "Experience Platform (XP)", "10.3.2", "Corporate and brand websites", 24, "Digital Experience", H, True, ["Sitecore CMS", "Sitecore Multiple Products", "Sitecore Experience Platform"]),
    ("Web and CMS", "CMS / forms", "Adobe", "Experience Manager (AEM) and AEM Forms", "6.5.21", "Insurance quote forms", 30, "Digital Experience", C, True, ["Adobe Experience Manager"]),
    ("Web and CMS", "E-commerce", "Adobe", "Commerce (Magento)", "2.4.7-p2", "Pharmacy online store", 12, "Digital Commerce", C, True, ["Adobe Commerce", "Adobe Magento", "Mirasvit"]),
    ("Web and CMS", "CMS", "Kentico", "Xperience", "13.0.160", "Regional marketing sites", 6, "Digital Experience", M, True, ["Kentico Xperience", "Kentico Kentico Xperience"]),
    ("Web and CMS", "CMS", "WordPress", "WordPress Core", "6.6.2", "Campaign microsites", 70, "Marketing Technology", M, True, ["WordPress Core", "WordPress WordPress Core"]),
    ("Web and CMS", "CMS", "Drupal", "Drupal Core", "10.3.6", "Foundation and careers sites", 8, "Marketing Technology", M, True, ["Drupal Core"]),
    ("Web and CMS", "CMS (acquired)", "Craft CMS", "Craft CMS", "4.12.5", "Logistics brand site", 1, "Marketing Technology", L, True, ["Craft CMS"]),
    ("Web and CMS", "CMS (acquired)", "DotNetNuke (DNN)", "DNN Platform", "9.13.4", "Legacy intranet (Mexico)", 1, "LATAM IT", L, False, ["DotNetNuke"]),
    ("Web and CMS", "Forum", "vBulletin", "vBulletin", "6.0.6", "Customer community (read-only archive)", 1, "Digital Products", L, True, ["vBulletin"]),
    ("Web and CMS", "Hosting panel", "WebPros", "cPanel & WHM", "118", "Marketing agency hosting (third party)", 3, "Marketing Technology", L, True, ["WebPros cPanel", "cPanel", "LiteSpeed cPanel"]),
    ("Web and CMS", "Hosting panel", "CyberPersons", "CyberPanel", "2.3.6", "Agency-managed microsites", 1, "Marketing Technology", L, True, ["CyberPersons CyberPanel", "CWP Control Web Panel"]),
    ("Web and CMS", "CMS", "Joomla", "Joomla! with JCE editor and SP Page Builder", "5.1.4", "Franchise partner sites", 40, "Marketing Technology", L, True, ["Widget Factory Joomla Content Editor", "JoomShaper SP Page Builder", "Joomlack Page Builder", "Balbooa Forms", "iCagenda"]),
    ("Web and CMS", "Headless CMS", "Strapi", "Strapi", "4.25.8", "Mobile app content", 3, "Digital Products", M, True, ["Strapi"]),
    ("Web and CMS", "Geospatial", "OSGeo", "GeoServer", "2.25.3", "Fleet routing maps", 4, "Fleet Technology", M, True, ["OSGeo GeoServer"]),

    # ── Developer platforms (CI/CD and the Artifactory supply chain) ───
    ("Developer platforms", "Artifact repository", "JFrog", "Artifactory Enterprise+ / Xray", "7.90.13", "Global artifact cache (Maven, npm, PyPI, Docker)", 12, "Developer Platforms", C, True, ["JFrog Artifactory"]),
    ("Developer platforms", "Source control", "GitLab", "GitLab Enterprise Edition (self-managed)", "17.3.4", "Primary SCM, 28k repos", 6, "Developer Platforms", C, True, ["GitLab Community and Enterprise", "GitLab GitLab"]),
    ("Developer platforms", "Source control", "GitHub", "GitHub Enterprise Cloud + Actions", "SaaS", "Open-source and data science", 1, "Developer Platforms", H, True, ["GitHub", "tj-actions changed-files", "reviewdog action-setup"]),
    ("Developer platforms", "Source control (acquired)", "Gitea", "Gitea", "1.22.2", "Logistics engineering team", 1, "Logistics IT", M, False, ["Gitea", "Gogs"]),
    ("Developer platforms", "CI", "Jenkins", "Jenkins LTS", "2.462.3", "Legacy CI, 140 controllers", 140, "Developer Platforms", H, False, ["Jenkins"]),
    ("Developer platforms", "CI", "JetBrains", "TeamCity", "2024.07.2", "Mobile and game studio builds", 4, "Developer Platforms", H, True, ["JetBrains TeamCity"]),
    ("Developer platforms", "Code quality", "SonarSource", "SonarQube Enterprise", "10.6", "Static analysis", 3, "Application Security", M, False, ["SonarQube"]),
    ("Developer platforms", "Version control client", "Git", "Git for Windows / Git", "2.46.2", "All developer workstations", 31000, "Developer Platforms", M, False, ["Git Git"]),
    ("Developer platforms", "IDE extension", "Nx", "Nx Console", "18.x", "Front-end monorepos", 4200, "Developer Platforms", L, False, ["Nx Nx Console"]),
    ("Developer platforms", "Workflow automation", "Kestra", "Kestra OSS", "0.19", "Data engineering pipelines", 2, "Data Platform Engineering", M, False, ["Kestra"]),
    ("Developer platforms", "Workflow automation", "n8n", "n8n", "1.62", "Ops automation (security team)", 2, "Security Automation", M, True, ["n8n"]),
    ("Developer platforms", "API toolchain", "React Native Community", "CLI", "14.1", "Mobile app builds", 900, "Mobile Engineering", L, False, ["React Native Community CLI"]),

    # Packages pulled through Artifactory into production builds
    ("Software packages", "Java logging", "Apache", "Log4j2", "2.17.2 / 2.24.1", "Pinned in 6,800 Maven builds", 6800, "Application Security", C, False, ["Apache Log4j2", "Apache Log4j"]),
    ("Software packages", "Java framework", "Apache", "Struts", "2.5.33 / 6.4.0", "Legacy insurance portals", 38, "Insurance Applications", H, True, ["Apache Struts"]),
    ("Software packages", "Java framework", "VMware", "Spring Framework / Spring Boot", "5.3.39 / 6.1.13", "Most Java services", 4100, "Application Platforms", H, True, ["Spring Framework", "VMware Spring", "Spring Cloud"]),
    ("Software packages", "Java ERP framework", "Apache", "OFBiz", "18.12.16", "Spare-parts catalogue", 2, "Logistics IT", M, True, ["Apache OFBiz"]),
    ("Software packages", "Python web", "Kludex", "Starlette", "0.38.6", "Internal FastAPI services", 640, "Application Platforms", M, False, ["Kludex Starlette", "Starlette"]),
    ("Software packages", "Ruby web", "Rails", "Ruby on Rails", "7.1.4", "Booking and scheduling apps", 40, "Digital Products", M, True, ["Rails Ruby on Rails", "Ruby on Rails"]),
    ("Software packages", "PHP web", "Laravel", "Livewire", "3.5.6", "Partner portals", 14, "Digital Products", M, True, ["Laravel Livewire"]),
    ("Software packages", "PHP framework", "Yiiframework", "Yii", "2.0.51", "Legacy logistics tools", 4, "Logistics IT", L, False, ["Yiiframework Yii"]),
    ("Software packages", "PHP library", "PHP", "PHPMailer", "6.9.1", "Marketing forms", 30, "Marketing Technology", L, True, ["PHP PHPMailer", "PHPMailer"]),
    ("Software packages", "PHP library", "PEAR", "Archive_Tar", "1.4.14", "Legacy PHP apps", 12, "Digital Products", L, False, ["PEAR Archive_Tar"]),
    ("Software packages", "JavaScript", "Meta", "React / React Server Components", "18.3 / 19.0", "Web front ends", 2600, "Digital Products", H, True, ["Meta React", "React Server Components"]),
    ("Software packages", "JavaScript build", "Vite", "Vite", "5.4.8", "Front-end builds", 1900, "Digital Products", M, False, ["Vite Vitejs", "Vitejs"]),
    ("Software packages", "JavaScript", "TanStack", "TanStack Query / Router", "5.59", "Web front ends", 1100, "Digital Products", L, False, ["TanStack"]),
    ("Software packages", "JavaScript lint", "Prettier", "eslint-config-prettier", "9.1.0", "All JS repos", 3400, "Developer Platforms", L, False, ["Prettier eslint-config-prettier"]),
    ("Software packages", "Image processing", "ImageMagick", "ImageMagick", "7.1.1-38", "Document imaging pipeline", 60, "Insurance Applications", M, False, ["ImageMagick"]),
    ("Software packages", "Font rendering", "FreeType", "FreeType", "2.13.3", "Bundled in Linux base images", 18000, "Linux Engineering", L, False, ["FreeType"]),
    ("Software packages", "Compression", "Google", "Brotli", "1.1.0", "Bundled in CDN edge images", 900, "Application Delivery", L, False, ["Google Brotli"]),
    ("Software packages", "Crypto", "OpenSSL", "OpenSSL", "3.0.15 / 3.3.2", "Linux base images", 42000, "Linux Engineering", H, False, ["OpenSSL"]),
    ("Software packages", "Crypto", "OpenBSD", "OpenSSH", "9.6p1 / 9.8p1", "All Linux and Unix servers", 43000, "Linux Engineering", H, False, ["OpenBSD OpenSSH"]),
    ("Software packages", "Notebook", "Marimo", "Marimo", "0.9.4", "Data science notebooks", 300, "Data and AI Platform", L, False, ["Marimo"]),
    ("Software packages", "Database admin", "Adminer", "Adminer", "4.8.1", "Legacy dev tooling (prohibited)", 3, "Digital Products", L, True, ["Adminer"]),

    # ── AI and ML platform ──────────────────────────────────────────────
    ("AI platform", "LLM gateway", "BerriAI", "LiteLLM Proxy", "1.52.0", "Internal LLM routing", 6, "AI Platform", H, False, ["BerriAI LiteLLM"]),
    ("AI platform", "Agent builder", "Langflow", "Langflow", "1.0.18", "Business-unit AI pilots", 4, "AI Platform", H, True, ["Langflow", "IBM Langflow"]),
    ("AI platform", "ML lifecycle", "MLflow", "MLflow", "2.16.2", "Model registry", 3, "AI Platform", H, False, ["MLflow"]),
    ("AI platform", "Distributed compute", "Ray-Project", "Ray", "2.37.0", "Training and batch inference", 14, "AI Platform", H, False, ["Ray-Project Ray", "Anyscale Ray"]),
    ("AI platform", "GPU cluster manager", "GPUStack", "GPUStack", "0.3.2", "On-prem inference pilot", 1, "AI Platform", M, False, ["GPUStack"]),
    ("AI platform", "Data visualisation", "Grafana Labs", "Grafana Enterprise", "11.2.2", "Platform and AI dashboards", 18, "Observability Engineering", M, False, ["Grafana Labs Grafana", "Grafana"]),

    # ── Monitoring and IT operations ───────────────────────────────────
    ("IT operations", "Network monitoring", "SolarWinds", "Orion Platform / Network Performance Monitor", "2024.2.1", "Global network monitoring", 18, "Network Operations Centre", C, False, ["SolarWinds Orion", "SolarWinds Network Performance Monitor"]),
    ("IT operations", "File transfer", "SolarWinds", "Serv-U MFT", "15.4.2", "Retail supplier file drops", 2, "Retail IT", H, True, ["SolarWinds Serv-U"]),
    ("IT operations", "Monitoring (acquired)", "Nagios", "Nagios XI", "2024R1.2", "Logistics data centre", 2, "Logistics IT", M, False, ["Nagios Nagios XI"]),
    ("IT operations", "Monitoring", "Zabbix", "Zabbix", "7.0.4", "OT network monitoring", 4, "OT Engineering", M, False, ["Zabbix Frontend", "Zabbix"]),
    ("IT operations", "Monitoring", "Paessler", "PRTG Network Monitor", "24.3.100", "EMEA offices", 3, "EMEA IT", L, False, ["Paessler PRTG"]),
    ("IT operations", "Monitoring", "Progress", "WhatsUp Gold", "2024.0.1", "Pharmacy stores", 1, "Retail IT", M, False, ["Progress WhatsUp Gold"]),
    ("IT operations", "Remote monitoring (MSP)", "N-able", "N-central", "2024.5", "Managed-service partner for clinics", 1, "Healthcare IT", H, True, ["N-able N-central", "N-able N-Central"]),
    ("IT operations", "Remote monitoring (MSP)", "Kaseya", "VSA", "9.5.20", "Dental clinic group (acquired)", 1, "Healthcare IT", H, True, ["Kaseya Virtual System/Server Administrator", "Kaseya VSA"]),
    ("IT operations", "Remote support", "ConnectWise", "ScreenConnect", "24.2.3", "Field engineering vendor access", 2, "IT Service Desk", C, True, ["ConnectWise ScreenConnect"]),
    ("IT operations", "Remote support", "SimpleHelp", "SimpleHelp", "5.5.7", "Clinic IT contractor", 1, "Healthcare IT", H, True, ["SimpleHelp"]),
    ("IT operations", "Software licensing", "Cisco", "Smart Licensing Utility", "2.3.0", "Network licensing", 2, "Enterprise Networking", L, False, ["Cisco Smart Licensing Utility"]),
    ("IT operations", "Software distribution", "Siemens", "Software Center", "3.2", "Plant engineering workstations", 4, "Manufacturing IT", L, False, ["Siemens Software Center"]),

    # ── Managed file transfer ──────────────────────────────────────────
    ("File transfer", "MFT", "Progress", "MOVEit Transfer", "2024.0.4", "Partner and payroll file exchange", 4, "Integration Engineering", C, True, ["Progress MOVEit"]),
    ("File transfer", "MFT", "Fortra", "GoAnywhere MFT", "7.6.1", "Bank statement exchange", 3, "Integration Engineering", C, True, ["Fortra GoAnywhere"]),
    ("File transfer", "MFT", "Cleo", "Harmony / VLTrader", "5.8.0.21", "Logistics EDI", 4, "Logistics IT", C, True, ["Cleo Multiple Products", "Cleo Harmony"]),
    ("File transfer", "SFTP", "CrushFTP", "CrushFTP", "11.2.1", "Marketing agency exchange", 1, "Marketing Technology", M, True, ["CrushFTP"]),
    ("File transfer", "SFTP", "Wing FTP Server", "Wing FTP Server", "7.4.3", "Plant data uploads", 1, "Manufacturing IT", M, True, ["Wing FTP Server"]),
    ("File transfer", "File sharing", "Citrix", "ShareFile Storage Zones Controller", "5.12.1", "Legal document exchange", 2, "Legal Technology", H, True, ["Citrix ShareFile"]),
    ("File transfer", "File sharing", "Gladinet", "CentreStack", "16.10", "Clinic file sync (acquired)", 1, "Healthcare IT", M, True, ["Gladinet CentreStack", "Gladinet Triofox"]),
    ("File transfer", "SFTP", "ProFTPD", "ProFTPD", "1.3.8b", "Legacy Unix batch", 6, "Core Banking Infrastructure", M, False, ["ProFTPD"]),
    ("File transfer", "File transfer (Japan)", "Soliton Systems K.K", "FileZen", "5.0.10", "Japan subsidiary", 1, "APAC IT", L, True, ["Soliton Systems K.K FileZen"]),

    # ── Backup and recovery ────────────────────────────────────────────
    ("Backup", "Backup", "Veeam", "Backup & Replication", "12.2.0.334", "VMware and Hyper-V estates", 48, "Backup and Recovery", C, False, ["Veeam Backup"]),
    ("Backup", "Backup", "Commvault", "Commvault Platform / Command Center", "11.36", "Databases and file servers", 22, "Backup and Recovery", C, True, ["Commvault Command Center", "Commvault Web Server"]),
    ("Backup", "Backup (legacy)", "Veritas", "Backup Exec", "22.2", "Small clinics", 30, "Healthcare IT", M, False, ["Veritas Backup Exec"]),
    ("Backup", "Backup (endpoints)", "Acronis", "Cyber Protect", "16", "Executive laptops", 1, "End User Computing", L, False, ["Acronis Backup", "Acronis Cyber Protect"]),
    ("Backup", "Backup (lab)", "NAKIVO", "Backup & Replication", "10.11", "Research lab", 1, "Research IT", L, False, ["NAKIVO Backup"]),
    ("Backup", "Backup (cloud)", "Ahsay", "AhsayCBS", "9.5", "Managed backup for franchisees", 1, "Retail IT", L, True, ["Ahsay AhsayCBS"]),

    # ── OT, physical security and building systems ─────────────────────
    ("OT and IoT", "PLCs", "Rockwell", "ControlLogix 5580 / FactoryTalk", "v34", "Distribution centres, device plants", 1400, "OT Engineering", C, False, ["Rockwell Multiple Products", "Rockwell Automation"]),
    ("OT and IoT", "PLCs", "Siemens", "SIMATIC S7-1500", "V3.1", "Device manufacturing plants", 600, "OT Engineering", C, False, ["Siemens SIMATIC"]),
    ("OT and IoT", "SCADA (lab)", "OpenPLC", "ScadaBR", "1.2", "OT training lab", 1, "OT Engineering", L, False, ["OpenPLC ScadaBR"]),
    ("OT and IoT", "Building automation", "KNX Association", "KNX IP routers", "Spec 2.1", "Headquarters building systems", 140, "Facilities", M, False, ["KNX Association KNX"]),
    ("OT and IoT", "CCTV", "Hikvision", "DS-2CD IP cameras / NVRs", "V5.7.x", "Warehouses (being replaced)", 6200, "Corporate Security", M, False, ["Hikvision Multiple Products", "Hikvision"]),
    ("OT and IoT", "CCTV", "Dahua", "IP cameras", "V2.840", "Acquired depots", 900, "Corporate Security", L, False, ["Dahua IP Camera"]),
    ("OT and IoT", "CCTV", "GeoVision", "GV-IP cameras", "V1.10", "Pharmacy stores", 1800, "Corporate Security", L, False, ["GeoVision Multiple Devices"]),
    ("OT and IoT", "Conference cameras", "PTZOptics", "PT30X-NDI", "6.3.40", "Boardrooms", 120, "Collaboration Platforms", L, False, ["PTZOptics PT30X"]),
    ("OT and IoT", "Weather stations", "Smartbedded", "Meteobridge", "6.1", "Logistics hubs", 22, "Fleet Technology", L, True, ["Smartbedded Meteobridge"]),
    ("OT and IoT", "Access control", "ZKTeco", "BioTime readers", "2.0", "Warehouses", 1400, "Corporate Security", M, False, ["ZKTeco"]),
    ("OT and IoT", "Edge routers (stores)", "MikroTik", "RouterOS", "7.16", "Franchise stores", 300, "Retail IT", L, True, ["MikroTik RouterOS"]),
    ("OT and IoT", "Edge routers (stores)", "DrayTek", "Vigor 2927", "4.4.5.3", "Franchise stores (EMEA)", 210, "EMEA IT", L, True, ["DrayTek"]),
    ("OT and IoT", "Edge routers (home office)", "TP-Link", "Archer / Deco (provided to executives)", "Latest", "Executive home offices", 400, "Executive Support", L, True, ["TP-Link"]),
    ("OT and IoT", "Edge routers (home office)", "ASUS", "RT-AX88U Pro", "3.0.0.6.102", "Executive home offices", 160, "Executive Support", L, True, ["ASUS Routers", "ASUS RT-AX"]),
    ("OT and IoT", "Streaming (lobby)", "Plex", "Plex Media Server", "1.41", "Lobby displays (unapproved)", 3, "Facilities", L, False, ["Plex Media Server"]),
]

# Fix level of the deployed version: KEV entries added on or before this
# date are treated as fixed by the version in production. Estimated from
# each version's release date. Products not listed use DEFAULT_PATCHED.
DEFAULT_PATCHED = "2026-08-31"
PATCHED_THROUGH = {
    # Lagging or unsupported estates: these carry real exposure.
    "Windows Server 2012 R2": "2025-01-14",
    "Windows 10 Enterprise LTSC": "2025-10-14",
    "Internet Explorer 11 mode": "2025-06-30",
    "TZ670 (SonicOS)": "2025-03-31",
    "SMA 1000": "2025-06-30",
    "Zimbra Collaboration Suite": "2025-06-30",
    "Webmail": "2025-09-30",
    "Connect Secure": "2026-06-30",
    "NetScaler ADC / Gateway MPX 15000": "2026-07-31",
    "Struts": "2024-12-31",
    "UI for ASP.NET AJAX": "2020-01-01",
    "Ajax.NET Professional": "2022-01-01",
    "VSA": "2021-07-02",
    "DS-2CD IP cameras / NVRs": "2023-06-30",
    "IP cameras": "2023-01-01",
    "GV-IP cameras": "2024-01-01",
    "RouterOS": "2025-02-01",
    "Vigor 2927": "2024-10-01",
    "Archer / Deco (provided to executives)": "2025-12-31",
    "Plex Media Server": "2023-01-01",
    "Adminer": "2021-05-01",
    "vBulletin": "2024-01-01",
    "Exim": "2025-01-01",
    "TS-873A (QTS)": "2025-11-30",
    "NAS542": "2024-06-30",
    "USG FLEX 200 / ATP500": "2025-09-30",
    "Endpoint Manager Mobile (EPMM / MobileIron Core)": "2026-05-31",
    "Galaxy S23/S24, XCover6 Pro (Android 14)": "2026-03-31",
    "Java SE (JDK / JRE)": "2026-07-15",
    "WebLogic Server": "2026-04-30",
    "S/4HANA 2023 and ECC 6.0 EHP8 (NetWeaver)": "2026-06-30",
    "E-Business Suite": "2026-07-15",
    "VMware ESXi": "2026-06-30",
    "Expedition (migration tool)": "2024-06-30",
    "ScadaBR": "2024-01-01",
    "Daemon Tools Lite": "2024-01-01",
    "Unraid": "2025-01-01",
    "Pentaho Business Analytics Server": "2025-03-31",
    "Web Help Desk": "2026-03-31",
    "Serv-U MFT": "2026-05-31",
    "Harmony / VLTrader": "2026-07-31",
    "Langflow": "2026-06-30",
    "LiteLLM Proxy": "2026-06-30",
}

FIELDS = ["category", "subcategory", "vendor", "product", "version", "environment", "count", "owner",
          "criticality", "internet_facing", "match"]


def build() -> dict:
    assets = []
    for i, row in enumerate(ROWS, 1):
        rec = dict(zip(FIELDS, row))
        rec["id"] = f"INV-{i:04d}"
        rec["patched_through"] = PATCHED_THROUGH.get(rec["product"], DEFAULT_PATCHED)
        assets.append(rec)
    return {
        "organisation": {
            "name": "Meridian Global Holdings (fictional)",
            "description": "Synthetic Fortune-50-scale group: retail banking, insurance, logistics, pharmacy retail, "
                           "healthcare services and medical-device manufacturing. 210,000 employees, 6 data centres, "
                           "AWS + Azure + Google Cloud + OCI.",
            "synthetic": True,
            "generated_by": "samples/build_inventory.py",
        },
        "assets": assets,
    }


if __name__ == "__main__":
    out = Path(__file__).with_name("meridian-global.json")
    data = build()
    out.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(data['assets'])} products)")
