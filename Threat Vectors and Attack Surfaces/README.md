# Threat Vectors and Attack Surfaces Lab

## Enterprise Security Homelab Project

---

## Lab Overview

This hands-on lab focused on identifying and mitigating common threat vectors and attack surfaces in an enterprise Windows environment. The lab demonstrated practical security hardening techniques including port management, credential security, and vulnerability assessment.

**Lab Environment:** Windows Server 2022 Domain, Windows 11 Workstation, Kali Linux  

---

## Learning Objectives

- ✅ Discover and remediate unnecessary open service ports
- ✅ Identify and disable default credential accounts
- ✅ Recognize vulnerable applications through version analysis
- ✅ Simulate real-world exploitation techniques
- ✅ Analyze attack indicators using Windows Event Viewer

---

## Lab Architecture

<img width="378" height="468" alt="image" src="https://github.com/user-attachments/assets/1b6ace69-b2c3-425f-8d54-468d06658ad0" />

---

## Exercise 1: Open Service Ports Assessment

### Objective
Identify and close unnecessary network service ports that create potential attack vectors.

### Tools Used
- **Nmap** - Network scanning and port discovery
- **Windows Defender Firewall** - Port blocking and access control

### Methodology

#### 1. Port Discovery
Connected to the Kali Linux attack system and performed network reconnaissance:

```bash
# Initial port scan
nmap -Pn 192.168.0.2

# Aggressive scan for detailed information
nmap -Pn -A -p 80,443,3306 192.168.0.2
```

**Findings:**

<img width="722" height="402" alt="image" src="https://github.com/user-attachments/assets/bd7a6127-7695-4920-98ce-fb743067ab15" />

- Port 80 (HTTP): Apache httpd 2.4.56 running
- Port 443 (HTTPS): Apache httpd 2.4.56 with SSL
- Port 3306 (MySQL): MariaDB database service

**Risk Assessment:** These services were running on a domain member server (ACIDM01) with no legitimate business requirement for web hosting or database services, representing unnecessary attack surface.

#### 2. Port Remediation
Created Windows Firewall inbound rules to block unnecessary ports:

**Configuration Steps:**
1. Accessed Windows Defender Firewall with Advanced Security
   <img width="717" height="260" alt="image" src="https://github.com/user-attachments/assets/2428073e-e703-4333-b5f8-b675388849ee" />

2. Created new inbound rule blocking TCP ports 80, 443, 3306
   <img width="715" height="582" alt="image" src="https://github.com/user-attachments/assets/761edef0-2ecb-4667-9779-9e7db1f57bb8" />

3. Applied rule across all network profiles (Domain, Private, Public)
   <img width="677" height="250" alt="image" src="https://github.com/user-attachments/assets/f9193848-e3fc-43aa-b719-9538c1579de8" />

**Verification:**
```bash
# Confirmed ports were successfully closed
nmap -Pn 192.168.0.2
# Result: Ports 80, 443, and 3306 no longer appeared in scan results
```

### Key Takeaways
- Regular port audits identify unnecessary services that expand attack surface
- Defense-in-depth requires both service management and firewall controls
- The `-Pn` flag bypasses host discovery, useful for systems that don't respond to ping

---

## Exercise 2: Default Credentials Mitigation

### Objective
Identify and disable built-in Guest accounts that use default or no credentials.

### Tools Used
- **Active Directory Users and Computers** - Account management
- **Windows Server authentication system**

### Methodology

#### 1. Guest Account Discovery
Attempted login to domain controller using default Guest account:

```
Username: Guest
Password: (blank)
Result: Successful login with no authentication required
```

**Risk Assessment:** The enabled Guest account provided unauthorized network access with zero authentication barriers. According to CIRT.net's Default Password Database, default credentials are one of the most exploited attack vectors, with 2,117+ documented default passwords across 531+ vendors.

#### 2. Account Remediation

**Steps Taken:**
1. Logged into ACIDC01 as domain administrator
2. Opened Active Directory Users and Computers console
<img width="720" height="177" alt="image" src="https://github.com/user-attachments/assets/e2b1c402-abb8-486d-aa27-d17a110f8b37" />

3. Located Guest account in Users container
4. Right-clicked account → Selected "Disable Account"
<img width="725" height="566" alt="image" src="https://github.com/user-attachments/assets/c6d0ebaa-a0eb-4574-af50-70d91dac93c9" />

**Verification:**
- Attempted Guest login again after remediation
- Result: Access denied, account disabled successfully
<img width="668" height="484" alt="image" src="https://github.com/user-attachments/assets/ee680a7c-7443-4af3-abeb-68b016f78454" />


### Security Best Practices Implemented
- ✅ Disabled unnecessary default accounts
- ✅ Followed principle of least privilege
- ✅ Documented account status changes for audit trail

### Key Takeaways
- Default accounts should be disabled unless specifically required by policy
- When Guest access is necessary, implement:
  - Strong password policies
  - Session timeout controls
  - Enhanced monitoring and logging
  - Network segmentation

---

## Exercise 3: Vulnerable Application Assessment

### Objective
Identify installed vulnerable software and demonstrate exploitation techniques to understand attack indicators.

### Tools Used
- **Adobe Reader 8.1.1** - Target vulnerable application
- **NIST National Vulnerability Database (NVD)** - Vulnerability research
- **Metasploit Framework** - Exploitation toolkit
- **Windows Event Viewer** - Attack indicator analysis

### Methodology

#### Phase 1: Vulnerability Discovery

**Application Identification:**
- Discovered Adobe Reader 8.1.1 installed on ACIWIN11 workstation
- Violated organizational policy prohibiting user-installed applications

**Vulnerability Research:**

https://nvd.nist.gov/vuln/detail/cve-2007-5659 
<img width="657" height="317" alt="image" src="https://github.com/user-attachments/assets/c8e46992-62bc-464f-a577-b10e9821e2cc" />

**Risk Assessment:** Critical severity vulnerability with known public exploit code available.

#### Phase 2: Simulated Attack

**Exploitation Workflow:**

1. **Exploit Generation** (Attacker perspective - Kali Linux):
```bash
# Launch Metasploit Framework
msfconsole

# Search for Adobe Reader exploits
search adobe 8.1.1
```
<img width="723" height="161" alt="image" src="https://github.com/user-attachments/assets/eee2a3f7-1dc3-454e-9d2d-4e17d8504a66" />

```
# Use the collectemailinfo exploit
use exploit/windows/fileformat/adobe_collectemailinfo

# View exploit options
show options
```
<img width="721" height="412" alt="image" src="https://github.com/user-attachments/assets/6eb3fefb-addc-4e4f-a8fc-b29de02abde9" />

```
# Generate malicious PDF
exploit
```
<img width="723" height="133" alt="image" src="https://github.com/user-attachments/assets/536089c1-6a29-44ef-9e5e-b8f817ed0b1c" />


2. **Payload Delivery:**
```bash
# Uploaded malicious PDF to shared folder on ACIWIN11
# Simulated phishing/social engineering delivery method
```

3. **Payload Execution:**
- User opened malicious PDF file with Adobe Reader 8.1.1
- Exploit attempted to execute but failed due to OS incompatibility
- Attack indicators still generated in system logs

#### Phase 3: Indicator Analysis

**Event Viewer Analysis:**

Examined Windows Application logs and identified attack indicators:

```
Log: Application
Event Level: Error
Source: Application Error
Faulting Application: AcroRd32.exe (Adobe Reader)
Timestamp: [Corresponding to PDF opening]
```

**Indicators of Compromise (IoCs):**
- ✅ Application crash events in Event Viewer
- ✅ Multiple AcroRd32.exe errors within short timeframe
- ✅ Unusual PDF file accessed from unexpected location
- ✅ Process termination without user action

<img width="532" height="426" alt="image" src="https://github.com/user-attachments/assets/415add9b-e47a-4f2c-a554-0dba552138d9" />

### Attack Chain Analysis

```
1. Reconnaissance → Attacker identified vulnerable Adobe Reader version
2. Weaponization → Created malicious PDF using Metasploit
3. Delivery → Social engineering/file share delivery to target
4. Exploitation → User opened malicious PDF
5. Installation → (Failed due to OS incompatibility)
6. Command & Control → (Not reached)
7. Actions on Objectives → (Not reached)
```

### Key Takeaways

**From a Defender's Perspective:**
- Even failed attacks leave forensic evidence
- Application whitelisting would have prevented unauthorized Adobe installation
- Vulnerability management requires continuous software inventory
- User security awareness is critical (opening unknown PDFs)

**Remediation Actions Required:**
1. Remove Adobe Reader 8.1.1 immediately
2. Investigate who installed the unauthorized software
3. Implement application control policies (AppLocker/WDAC)
4. Conduct user security awareness training
5. Deploy vulnerability scanning for software inventory
6. Establish patch management procedures

---

## Skills Demonstrated

### Technical Skills
- Network reconnaissance using Nmap
- Windows Firewall configuration and management
- Active Directory account administration
- Vulnerability research and CVE analysis
- Metasploit Framework operation
- Windows Event Viewer log analysis
- Attack chain mapping and incident response

### Security Concepts
- Attack surface reduction
- Defense-in-depth strategy
- Principle of least privilege
- Vulnerability lifecycle management
- Indicators of Compromise (IoC) identification
- Security monitoring and detection

### Tools & Technologies
- Nmap (port scanning)
- Windows Defender Firewall
- Active Directory Users and Computers
- Metasploit Framework
- Windows Event Viewer
- Kali Linux
- Windows Server 2022
- SMB file sharing protocol

---

## Lessons Learned

### What Worked Well
✅ Systematic approach to identifying security weaknesses  
✅ Combination of offensive and defensive perspectives  
✅ Documentation of findings for audit and compliance purposes  
✅ Use of industry-standard tools and frameworks  

### Areas for Improvement
⚠️ Could implement automated vulnerability scanning  
⚠️ Should establish baseline security configurations  
⚠️ Need recurring security audits on a schedule  
⚠️ Consider implementing Security Information and Event Management (SIEM)  

### Real-World Applications
- This lab mirrors actual security assessment procedures
- Techniques used are standard in penetration testing engagements
- Remediation methods follow industry best practices (CIS Controls, NIST CSF)
- Skills directly transferable to SOC analyst and security engineer roles

---

## References & Resources

### Tools Used
- [Nmap - Network Mapper](https://nmap.org/)
- [Metasploit Framework](https://www.metasploit.com/)
- [Kali Linux](https://www.kali.org/)

### Vulnerability Databases
- [NIST National Vulnerability Database](https://nvd.nist.gov/)
- [CIRT.net Default Password Database](https://cirt.net/passwords)
- [CVE-2007-5659 Details](https://nvd.nist.gov/vuln/detail/cve-2007-5659)

### Best Practices & Frameworks
- NIST Cybersecurity Framework
- CIS Critical Security Controls
- MITRE ATT&CK Framework
- OWASP Security Guidelines

---

## Lab Environment Details

**Virtual Machines Used:**
- ACIDC01: Windows Server 2022 (Domain Controller)
- ACIDM01: Windows Server 2022 (Member Server)
- ACIWIN11: Windows 11 Professional (Workstation)
- ACIKALI: Kali Purple 2023.1 (Attack System)

---

*This lab is part of my ongoing cybersecurity homelab project focused on developing practical skills. For more labs and projects, visit my [website](https://thesunnynguyen.github.io/).*
