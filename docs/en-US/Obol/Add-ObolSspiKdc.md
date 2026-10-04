---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/Add-ObolSspiKdc.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Add-ObolSspiKdc
---

# Add-ObolSspiKdc

## SYNOPSIS

Points the Windows Kerberos SSP at a KDC for a realm, for the current thread or the whole machine.

## SYNTAX

### __AllParameterSets

```
Add-ObolSspiKdc [-Realm] <string> [-KdcAddress] <string> [-Scope <ObolSspiKdcScope>]
 [-DcFlags <ObolSspiDcFlags>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Tells the Windows Kerberos SSP (the `kerberos.dll` inside LSASS) to use `-KdcAddress` as the KDC for `-Realm`.
This is similar to the `[realms]` section in `krb5.conf` used in other Kerberos providers like MIT krb5 or Heimdal.

`-Scope` selects where the entry lives:

- `Thread` (the default) pins the KDC for the **current OS thread** only, using the undocumented `KerbPinKdc` message. No administrator rights are needed.
- `Machine` adds an entry to the **machine-wide binding cache** (the `klist.exe add_bind` equivalent), shared by every process and logon session

The `Thread` scoped entry is consuled before the machine wide binding cache and other KDC locator mechanisms.
It only steers Kerberos by callers to SSPI on the same thread that added the KDC.
Anything that might run on another thread or process, `Start-Job`, `Start-ThreadJob`, `ForEach-Object -Parallel`, .NET `async`/`await` will not see these KDC entries.

To clear a KDC entry use [Clear-ObolSspiKdc](./Clear-ObolSspiKdc.md) with the relevant `-Scope`.

Obol stores the realm and address verbatim for both scopes: it sends the LSA message directly rather than running `klist.exe`, so there is no DNS or DC-locator lookup and an unresolvable realm is still accepted.
The SSP always uses port 88, so `-KdcAddress` must be a bare host or IP with no port.

This cmdlet is only supported on Windows and errors on other platforms.
See [about_ObolSspi](./about_ObolSspi.md) for the more details around SSPI and KDC lookups.

## EXAMPLES

### Example 1: Pin a KDC for the current thread

```powershell
PS C:\> Add-ObolSspiKdc -Realm EXAMPLE.TEST -KdcAddress 127.0.0.1
```

Pins `EXAMPLE.TEST` to `127.0.0.1:88` for the current thread, no admin needed.

### Example 2: Add a machine-wide binding

```powershell
PS C:\> Add-ObolSspiKdc -Realm EXAMPLE.TEST -KdcAddress dc01.example.test -Scope Machine
```

Adds a machine-wide binding (run from an elevated session).
This also affects SMB and other kernel-brokered authentication.

### Example 3: Pin and see the result

```powershell
PS C:\> Add-ObolSspiKdc -Realm EXAMPLE.TEST -KdcAddress 127.0.0.1 -PassThru

Scope  Realm        KdcAddress KdcName
-----  -----        ---------- -------
Thread EXAMPLE.TEST 127.0.0.1
```

Pins the realm and returns the `ObolSspiKdc` describing it.

## PARAMETERS

### -Confirm

Prompts you for confirmation before running the cmdlet.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: ''
SupportsWildcards: false
Aliases:
- cf
ParameterSets:
- Name: (All)
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -DcFlags

The Domain Controller flags to set for this entry.
These flags are meant to represent what `DsGetDcName` would normally report, as Obol does not look them up it is up to the caller to define and ensure are correct.
The known values are `None`, `Pdc`, `Gc`, `Ldap`, `DirectoryService`, `Kdc`, `TimeServer`, `Closest`, `Writable`, `GoodTimeServer`, `NonDomainNamingContext`, `SelectSecretDomain`, `FullSecretDomain`, `WebService`, `DirectoryService8`, `DirectoryService9`, `DirectoryService10`, `KeyList`, `DirectoryService13`, `DirectoryService12`, `DnsController`, `DnsDomain`, `DnsForest`.

```yaml
Type: Obol.ObolSspiDcFlags
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -KdcAddress

The host name or IP address of the KDC, such as `dc01.example.test`, `127.0.0.1` or `fe80::1`.
A port cannot be included, the SSP always uses port 88, so a value with a port such as `dc01:1088` or `[::1]:88` is rejected.
The address is stored as given, Obol does no DNS or DC-locator lookup.

```yaml
Type: System.String
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 1
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -PassThru

Returns the `ObolSspiKdc` object that was added.
By default this cmdlet produces no output.
For `-Scope Machine` the entry is re-read from the cache so the returned object includes the SSP-populated fields.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Realm

The Kerberos realm to register the KDC with, conventionally upper case such as `EXAMPLE.TEST`.
It is matched case insensitively against outgoing requests and stored as given.

```yaml
Type: System.String
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 0
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Scope

Where the entry applies.
`Thread` (the default) pins the KDC for the current OS thread, with no administrator rights.
`Machine` adds it to the machine-wide binding cache, which needs administrator rights and affects every process.

```yaml
Type: Obol.ObolSspiKdcScope
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -WhatIf

Runs the command in a mode that only reports what would happen without performing the actions.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: ''
SupportsWildcards: false
Aliases:
- wi
ParameterSets:
- Name: (All)
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutBuffer, -OutVariable, -PipelineVariable,
-ProgressAction, -Verbose, -WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### Obol.ObolSspiKdc

The entry that was added, only when `-PassThru` is specified, see `Get-ObolSspiKdc` for the properties.

## NOTES

This cmdlet is only supported on Windows, it uses the Windows Kerberos SSP and errors on other platforms.

`-Scope Machine` needs administrator rights. `-Scope Thread` does not, but only applies to the OS thread it was created on, see `about_ObolSspi` for the thread and authentication caveats.

## RELATED LINKS

- [Get-ObolSspiKdc](./Get-ObolSspiKdc.md)
- [Clear-ObolSspiKdc](./Clear-ObolSspiKdc.md)
- [about_ObolSspi](./about_ObolSspi.md)
- [about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md)
