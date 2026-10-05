---
document type: module
Help Version: 1.0.0.0
HelpInfoUri: ''
Locale: en-US
Module Guid: 3eda8e6b-0288-4e08-b580-25e71aa51a0e
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Obol Module
---

# Obol Module

## Description

PowerShell module that runs a Kerberos KDC endpoint based on Kerberos.NET.

## Obol Cmdlets

### [Add-ObolSspiKdc](Add-ObolSspiKdc.md)

Points the Windows Kerberos SSP at a KDC for a realm, for the current thread or the whole machine.

### [Clear-ObolSspiKdc](Clear-ObolSspiKdc.md)

Removes the KDCs Obol pointed the Windows Kerberos SSP at, for the whole process or the whole machine.

### [ConvertFrom-ObolKeytab](ConvertFrom-ObolKeytab.md)

Converts the bytes of a keytab to keytab entries.

### [ConvertTo-ObolKeytab](ConvertTo-ObolKeytab.md)

Converts the keys of principals or keytab entries to the bytes of a keytab.

### [ConvertTo-ObolKrb5Config](ConvertTo-ObolKrb5Config.md)

Creates a krb5.conf for Obol KDCs as a string.

### [ConvertTo-ObolSalt](ConvertTo-ObolSalt.md)

Converts a principal or account name to the salt its keys are derived from a password with.

### [Enter-ObolKrb5Environment](Enter-ObolKrb5Environment.md)

Points the krb5 environment variables of the current process at Obol KDCs.

### [Enter-ObolSspiEnvironment](Enter-ObolSspiEnvironment.md)

Registers Obol KDCs with Windows Kerberos so SSPI authentication uses them.

### [Exit-ObolKrb5Environment](Exit-ObolKrb5Environment.md)

Restores the krb5 environment variables changed by Enter-ObolKrb5Environment.

### [Exit-ObolSspiEnvironment](Exit-ObolSspiEnvironment.md)

Removes the KDCs registered with Windows Kerberos by Enter-ObolSspiEnvironment.

### [Export-ObolKeytab](Export-ObolKeytab.md)

Exports the keys of principals of an Obol KDC to a keytab file.

### [Export-ObolKrb5Config](Export-ObolKrb5Config.md)

Writes a krb5.conf for Obol KDCs to a file.

### [Get-ObolKdc](Get-ObolKdc.md)

Gets the Obol KDCs running in the current runspace.

### [Get-ObolPrincipal](Get-ObolPrincipal.md)

Gets the principals of Obol KDCs.

### [Get-ObolSspiKdc](Get-ObolSspiKdc.md)

Lists the KDCs Obol has pointed the Windows Kerberos SSP at, for the current thread or the whole machine.

### [Import-ObolKeytab](Import-ObolKeytab.md)

Imports the entries of keytab files.

### [New-ObolKeytabEntry](New-ObolKeytabEntry.md)

Creates keytab entries from a password or key.

### [New-ObolPrincipal](New-ObolPrincipal.md)

Creates a principal in the realm of an Obol KDC.

### [New-ObolPrincipalSetting](New-ObolPrincipalSetting.md)

Creates the settings for a principal to create with `Start-ObolKdc -Principal` or `New-ObolPrincipal -Setting`.

### [Remove-ObolPrincipal](Remove-ObolPrincipal.md)

Removes principals from an Obol KDC.

### [Set-ObolPrincipal](Set-ObolPrincipal.md)

Changes principals of an Obol KDC.

### [Start-ObolKdc](Start-ObolKdc.md)

Starts an Obol Kerberos KDC.

### [Stop-ObolKdc](Stop-ObolKdc.md)

Stops an Obol KDC.

### [Trace-ObolKdc](Trace-ObolKdc.md)

Outputs the requests Obol KDCs answer, as they happen or the ones made while a scriptblock runs.

### [Use-ObolKrb5Environment](Use-ObolKrb5Environment.md)

Runs a scriptblock with an Obol KDC and the krb5 environment variables pointing at it.

### [Use-ObolSspiEnvironment](Use-ObolSspiEnvironment.md)

Runs a scriptblock with an Obol KDC registered with Windows Kerberos.
