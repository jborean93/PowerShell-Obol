# Changelog for Obol

## v0.1.0 - TBD

+ Initial version of the `Obol` module

Cmdlets present with this initial release.

### KDC

+ [Start-ObolKdc](docs/en-US/Obol/Start-ObolKdc.md): Starts an Obol Kerberos KDC.
+ [Get-ObolKdc](docs/en-US/Obol/Get-ObolKdc.md): Gets the Obol KDCs running in the current runspace.
+ [Stop-ObolKdc](docs/en-US/Obol/Stop-ObolKdc.md): Stops an Obol KDC.

### Principals

+ [New-ObolPrincipal](docs/en-US/Obol/New-ObolPrincipal.md): Creates a principal in the realm of an Obol KDC.
+ [Get-ObolPrincipal](docs/en-US/Obol/Get-ObolPrincipal.md): Gets the principals of Obol KDCs.
+ [Set-ObolPrincipal](docs/en-US/Obol/Set-ObolPrincipal.md): Changes principals of an Obol KDC.
+ [Remove-ObolPrincipal](docs/en-US/Obol/Remove-ObolPrincipal.md): Removes principals from an Obol KDC.
+ [New-ObolPrincipalSetting](docs/en-US/Obol/New-ObolPrincipalSetting.md): Creates the settings for a principal to create with `Start-ObolKdc -Principal` or `New-ObolPrincipal -Setting`.

### Keytabs

+ [Export-ObolKeytab](docs/en-US/Obol/Export-ObolKeytab.md): Exports the keys of principals of an Obol KDC to a keytab file.
+ [Import-ObolKeytab](docs/en-US/Obol/Import-ObolKeytab.md): Imports the entries of keytab files.
+ [ConvertTo-ObolKeytab](docs/en-US/Obol/ConvertTo-ObolKeytab.md): Converts the keys of principals or keytab entries to the bytes of a keytab.
+ [ConvertFrom-ObolKeytab](docs/en-US/Obol/ConvertFrom-ObolKeytab.md): Converts the bytes of a keytab to keytab entries.
+ [New-ObolKeytabEntry](docs/en-US/Obol/New-ObolKeytabEntry.md): Creates keytab entries from a password or key.
+ [ConvertTo-ObolSalt](docs/en-US/Obol/ConvertTo-ObolSalt.md): Converts a principal or account name to the salt its keys are derived from a password with.

### MIT/Heimdal Krb5

+ [ConvertTo-ObolKrb5Config](docs/en-US/Obol/ConvertTo-ObolKrb5Config.md): Creates a krb5.conf for Obol KDCs as a string.
+ [Export-ObolKrb5Config](docs/en-US/Obol/Export-ObolKrb5Config.md): Writes a krb5.conf for Obol KDCs to a file.
+ [Enter-ObolKrb5Environment](docs/en-US/Obol/Enter-ObolKrb5Environment.md): Points the krb5 environment variables of the current process at Obol KDCs.
+ [Exit-ObolKrb5Environment](docs/en-US/Obol/Exit-ObolKrb5Environment.md): Restores the krb5 environment variables changed by Enter-ObolKrb5Environment.
+ [Use-ObolKrb5Environment](docs/en-US/Obol/Use-ObolKrb5Environment.md): Runs a scriptblock with an Obol KDC and the krb5 environment variables pointing at it.

### Windows SSPI

+ [Add-ObolSspiKdc](docs/en-US/Obol/Add-ObolSspiKdc.md): Points the Windows Kerberos SSP at a KDC for a realm, `-Scope Thread` (per-thread, no admin) or `-Scope Machine` (machine-wide binding cache, admin). Windows only.
+ [Get-ObolSspiKdc](docs/en-US/Obol/Get-ObolSspiKdc.md): Lists the SSPI KDC entries, `-Scope Thread` (this thread's pins) or `-Scope Machine` (the binding cache). Windows only.
+ [Clear-ObolSspiKdc](docs/en-US/Obol/Clear-ObolSspiKdc.md): Removes the SSPI KDC entries, `-Scope Process` (all pins in the process) or `-Scope Machine` (purge the binding cache). Windows only.
+ [Enter-ObolSspiEnvironment](docs/en-US/Obol/Enter-ObolSspiEnvironment.md): Registers Obol KDCs with Windows Kerberos for the current thread or the whole machine. Windows only.
+ [Exit-ObolSspiEnvironment](docs/en-US/Obol/Exit-ObolSspiEnvironment.md): Removes the KDCs registered by Enter-ObolSspiEnvironment. Windows only.
+ [Use-ObolSspiEnvironment](docs/en-US/Obol/Use-ObolSspiEnvironment.md): Runs a scriptblock with an Obol KDC registered with Windows Kerberos. Windows only.
