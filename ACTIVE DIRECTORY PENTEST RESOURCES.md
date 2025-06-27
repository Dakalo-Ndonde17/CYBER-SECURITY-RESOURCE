
![AD-Pentesting-Resources(1920)](https://github.com/user-attachments/assets/24eb0cb3-e076-4f49-895a-45c23bdab04f)




List of tools and resources for pentesting Microsoft Active Directory
===========

<br>

Create Vulnerable AD Lab
====
  - [Medium Tutorial by Logan Hugli](https://medium.com/@lhugli/constructing-a-vulnerable-active-directory-hacking-lab-environment-6e7cc7fd55c6)
  - [Medium article by Justin Duru](https://medium.com/@jduru213/cybersecurity-homelab-building-an-on-premise-domain-environment-with-splunk-windows-and-active-840ba325f3ee)
  - [Vulnerable-AD Script](https://github.com/safebuffer/vulnerable-AD/tree/master)
  - [BadBlood Script](https://github.com/davidprowe/BadBlood)
  - [DetectionLab](https://www.detectionlab.network/introduction/)
  - [Game of Active Directory - GOAD](https://github.com/Orange-Cyberdefense/GOAD)
  - [Ludus](https://ludus.cloud)

<br>

AD Pentesting Cheat Sheets
====
  - [Orange Cyberdefense AD Mindmap](https://orange-cyberdefense.github.io/ocd-mindmaps/)
  - [AD Pentesting Cheat-Sheets](https://swisskyrepo.github.io/InternalAllTheThings/)
    - This one contains an AMAZING amount of info on AD for Pentesters and Red Teams
  - [S1ckB0y1337 Active Directory Exploitation Cheat-Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)
  - [HackTheBox AD Pentesting Cheat-Sheet](https://www.hackthebox.com/blog/active-directory-penetration-testing-cheatsheet-and-guide)
  - [HackTricks AD Methodology](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
  - [The Hacker Recipes](https://www.thehacker.recipes/)
  - [ired.team AD and Kerberos Cheat Sheets](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse)

<br>

AD Security Write-Ups and Research Articles
====
  - [Writeup for CVE-2025-21299 and CVE-2025-29280](https://www.netspi.com/blog/technical-blog/adversary-simulation/cve-2025-21299-cve-2025-29809-unguarding-microsoft-credential-guard/)
    + Insufficient validation of the Kerberos krbtgt service name within the TGT can lead to a bypass of credential guard, and therefore extraction of a primary TGT from the host that should otherwise be prevented.
  - [Common Tool Errors - Kerberos](https://blog.zsec.uk/common-tool-errors-kerberos/)
    + So you are performing your favourite kerberos attacks, such as pass the ticket, Public Key Cryptography for Initial Authentication (PKINIT), Shadow Credentials or Active Directory Certificate Services (AD CS) vulnerabilities but you run into a kerberos error and despite troubleshooting you're still none-the-wiser on what todo?
  - [BadSuccessor: Abusing dMSA to Priv Esc in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
    + Akamai researcher Yuval Gordon discovered a privilege escalation vulnerability in Windows Server 2025 that allows attackers to compromise any user in Active Directory (AD). The attack exploits the delegated Managed Service Account (dMSA) feature that was introduced in Windows Server 2025, works with the default configuration, and is trivial to implement.
  - [BadSuccessor Deep Dive: Full AD Compromise](https://www.youtube.com/watch?v=IWP-8IMzQU8)
    + Step-by-step walkthroughs of the BadSuccessor attack
    + Also some detection guidance

<br>

AD Security Tools
====
+ [BloodHound CE](https://github.com/SpecterOps/BloodHound)
  - BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory or Azure environment
  - Attackers can use BloodHound to quickly identify highly complex attack paths that would otherwise be impossible to find
  - Defenders can use BloodHound to identify and eliminate those same attack paths
  - Both red and blue teams can use BloodHound to better understand privileged relationships in an Active Directory or Azure environment

<br>
      
+ [GoodHound](https://github.com/idnahacks/GoodHound?tab=readme-ov-file)
  - GoodHound operationalises Bloodhound by determining the busiest paths to high value targets and creating actionable output to prioritise remediation of attack paths

<br>

+ [GPO-Hound](https://github.com/cogiceo/GPOHound)
  - A tool for dumping and analysing Group Policy Objects (GPOs) extracted from the SYSVOL share
 
<br>

+ [ADalanche](https://github.com/lkarlslund/Adalanche)
  - Adalanche instantly reveals what permissions users and groups have in an Active Directory
  - It is useful for visualizing and exploring
    + Who can take over accounts, machines or the entire domain
    + Find and show misconfigurations
   
<br>
     
+ [Hardening Kitty](https://github.com/scipag/HardeningKitty)
  - Intended use is for Windows system hardening
  - Can be used to <u>**test for weak configurations**</u>

<br>
 
+ [Delinea Weak Password Finder](https://delinea.com/resources/weak-password-finder-tool-active-directory)
  - Free tool to quickly <u>**discover weak passwords in AD**</u>

<br>

+ [Rubeus](https://github.com/GhostPack/Rubeus)
  - A C# toolset for raw Kerberos interaction and abuses

<br>

+ [Seatbelt](https://github.com/GhostPack/Seatbelt)
  - A C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives

<br>

+ [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
  - This set of tools allows enterprise security administrators to download, analyze, test, edit and store Microsoft-recommended security configuration baselines for Windows and other Microsoft products, while comparing them against other security configurations

<br>
 
+ [Semperis Forest Druid](https://www.semperis.com/forest-druid/)
  - Focuses on attack paths leading into the Tier 0 perimeter in hybrid identity environments—saving time by prioritizing your most critical assets

<br>

+ [Semperis Purple Knight](https://www.semperis.com/purple-knight/)
  - A free AD, Entra ID, and Okta security assessment tool—to help you discover indicators of exposure (IoEs) and indicators of compromise (IoCs) in your hybrid AD environment

<br>
 
+ [Group3r](https://github.com/Group3r/Group3r)
  - A tool for pentesters and red teamers to rapidly <u>**enumerate relevant settings in AD Group Policy**</u>, and to identify exploitable misconfigurations
 
<br>

+ [LockSmith](https://github.com/TrimarcJake/Locksmith)
  - A tool built to find and fix common misconfigurations in <u>**Active Directory Certificate Services**</u>

<br>

+ [BlueTuxedo](https://github.com/TrimarcJake/BlueTuxedo)
  - A tool built to find and fix common misconfigurations in <u>**Active Directory-Integrated DNS**</u>
    + Also a little bit of DHCP
   
<br>

+ [Empire](https://github.com/BC-SECURITY/Empire)
  - A post-exploitation and adversary emulation <u>**C2 framework**</u> that is used to aid Red Teams and Penetration Testers

<br>

+ [Starkiller](https://github.com/BC-SECURITY/Starkiller)
  - Frontend for Empire
 
<br>

+ [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
  - A collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment
 
<br>

+ [SharpSploit](https://github.com/cobbr/SharpSploit)
  - A .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers
 
<br>

+ [Ping Castle](https://www.pingcastle.com/)
  - An Active Directory health and security audit tool
  - Specifically designed to assess the security posture of an AD environment and provides a report with detailed findings
 
<br>

+ [ADRecon](https://github.com/sense-of-security/ADRecon)
  - Extracts and combines various artefacts out of an AD environment

 <br>
 
+ [GPOZaurr](https://github.com/EvotecIT/GPOZaurr)
  - Group Policy Eater is a PowerShell module that aims to gather information about Group Policies
  - Also allows fixing issues that you may find in them
  - Provides 360 degrees of information about Group Policies and their settings

<br>

+ [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
  - SharpSuccessor is a .NET Proof of Concept(PoC) of BadSuccessor attack from Akamai
 
<br>

+ [BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
  - Checks for prerequisites and attack abuse of BadSuccessor exploit

Blue and Purple Team Resources
=========

<br>

+ [PowerPUG](https://github.com/Trimarc/PowerPUG)
  - A tiny tool built to help Active Directory (AD) admins, operators, and defenders smoothly transition their most sensitive users (Domain Admins, etc.) into the AD Protected Users group (PUG) with minimal complications.
 
<br>

+ [PlumHound](https://github.com/PlumHound/PlumHound)
  - Released as Proof of Concept for Blue and Purple teams to more effectively use BloodHoundAD in continual security life-cycles by utilizing the BloodHoundAD pathfinding engine to identify Active Directory security vulnerabilities resulting from business operations, procedures, policies and legacy service operations
 
<br>

+ [The Respotter Honepot](https://github.com/lawndoc/Respotter)
  - This application detects active instances of Responder by taking advantage of the fact that Responder will respond to any DNS query
 
<br>

+ [Atomic Purple Team](https://github.com/DefensiveOrigins/AtomicPurpleTeam)
  - A business/organizational concept designed to assist organizations in building, deploying, maintaining, and justying Attack-Detect-Defend Infosec Exercises

<br>

+ [Active Directory Firewall](https://github.com/MichaelGrafnetter/active-directory-firewall)
  - This project aims to provide production-ready and well-tested guidelines on configuring the Windows Firewall for Active Directory-related server roles.
