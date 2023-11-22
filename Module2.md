**Tricks**<br>
during enumration process focus on never use any script that can make any noise.<br>
or use any kind make a your enumration is unique like 4672(S): Special privileges assigned to new logon.<br>
or make spilke ☣️ Like the picture in the below <br>
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/46d17bd2-9ee7-467e-8473-217c829d3fa9)

> U can list the session and logged on users on the machines if you enumrate windows server less than 2019 if u a membership of domain admin group, but u will leave event 4624 and 4634 on all machines.<br>
> when u use paramter like check access on this case the request not send for all machines, it's just send to the high level machines like servers to check.<br>

***Privilege Escalation***
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

***Services Issues using PowerUp***<br>
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


***Feature Abuse***
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

***Domain Enumeration - BloodHound***
> BloodHound have two part the collector 'sharphond .ps1' that running to check the all of AD and give u file u open it in the second part called GUI.<br>
> The SharpHound toolset is specifically designed to collect data within an Active Directory <br>
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

***Lateral Movement - PowerShell Remoting***
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
