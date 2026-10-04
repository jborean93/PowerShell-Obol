---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/Enter-ObolSspiEnvironment.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Enter-ObolSspiEnvironment
---

# Enter-ObolSspiEnvironment

## SYNOPSIS

Registers Obol KDCs with Windows Kerberos so SSPI authentication uses them.

## SYNTAX

### __AllParameterSets

```
Enter-ObolSspiEnvironment [-Kdc] <ObolKdc[]> [-Scope <ObolSspiKdcScope>] [-NoPrompt] [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Windows' own Kerberos, used by SSPI and anything built on it such as `HttpClient` with default credentials, `NegotiateStream`, `System.DirectoryServices` and SMB, ignores `krb5.conf` and the krb5 environment variables `Enter-ObolKrb5Environment` sets.
This registers each KDC's realm with Windows Kerberos instead, so it sends the requests for that realm to the KDC, until `Exit-ObolSspiEnvironment` removes it.

`-Scope` sets which authentication uses the KDCs:

+ `Thread` (the default): only Kerberos authentication done on the current thread. No administrator rights are needed.
+ `Machine`: all Kerberos authentication on the machine, including other processes and SMB. This needs administrator rights.

A PowerShell console and a script run every command on the same thread, so with `Thread` the commands after this one use the KDCs.
Authentication done on another thread does not, such as in a job, another runspace, `ForEach-Object -Parallel` or an async continuation, or kernel/LSASS driven authentication like SMB and CredSSP, use `Machine` for those.

Only one SSPI environment can be entered in the process at a time, it can be used together with a krb5 environment from `Enter-ObolKrb5Environment`.
It is exited when the runspace that entered it closes.

The `prompt` function of the runspace is changed to start with the first realm, such as `[EXAMPLE.TEST]`, or `[EXAMPLE.TEST +1]` when there are KDCs for other realms too.
The label is shown in magenta unless `$PSStyle.OutputRendering` is `PlainText`, so it can be told apart from the cyan realm of a krb5 environment when both are entered.
`Exit-ObolSspiEnvironment` removes the label and restores the original prompt, use `-NoPrompt` to leave the prompt unchanged.

This cmdlet is only supported on Windows and errors on other platforms.

## EXAMPLES

### Example 1: Use a KDC for the current thread

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST -Port 88 -Principal @{ 'HTTP/web.example.test' = $null }
$kdc | Enter-ObolSspiEnvironment

# SSPI Kerberos for EXAMPLE.TEST on this thread now uses $kdc.

Exit-ObolSspiEnvironment
$kdc | Stop-ObolKdc
```

Starts a KDC on port 88, registers it for the current thread, then removes the registration and stops the KDC.

### Example 2: Use SSPI

```powershell
$password = ConvertTo-SecureString -AsPlainText -Force 'Password123!'
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST -Port 88 -Principal @{
    user = $password
    'HTTP/web.example.test' = $null
}
$kdc | Enter-ObolSspiEnvironment

$client = [System.Net.Security.NegotiateAuthentication]::new(
    [System.Net.Security.NegotiateAuthenticationClientOptions]@{
        Package = 'Kerberos'
        Credential = [System.Net.NetworkCredential]::new('user@EXAMPLE.TEST', 'Password123!')
        TargetName = 'HTTP/web.example.test'
    })
$status = [System.Net.Security.NegotiateAuthenticationStatusCode]::GenericFailure
$token = $client.GetOutgoingBlob([byte[]]@(), [ref]$status)
$client.Dispose()

Exit-ObolSspiEnvironment
$kdc | Stop-ObolKdc
```

Gets a Kerberos service ticket for `HTTP/web.example.test` from the KDC through the Windows Kerberos SSP, with .NET's `NegotiateAuthentication`.
`$status` is `Completed` and `$token` is the Kerberos token to send to the service.
The commands run on the thread that entered the environment, a background job or `ForEach-Object -Parallel` would not find the KDC.

### Example 3: Use a KDC for the whole machine

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST -Port 88
Enter-ObolSspiEnvironment $kdc -Scope Machine
```

Registers the KDC for every process on the machine, such as for SMB, from an elevated session.
Windows stops using it after about 10 minutes, see the notes.

### Example 4: Several KDCs on port 88

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST -Port 88
$other = Start-ObolKdc -Realm OTHER.TEST -Address 127.0.0.2 -Port 88
$kdc, $other | Enter-ObolSspiEnvironment
```

Windows Kerberos only uses port 88, so each KDC listens on its own loopback address.

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

### -Kdc

The KDCs to register, as output by `Start-ObolKdc` or `Get-ObolKdc`.
Each must be running and listen on port 88, the only port Windows Kerberos uses, a KDC that does not is written as an error and the others are still registered.
A KDC listening on all addresses, such as `0.0.0.0`, is registered with the loopback address.

```yaml
Type: Obol.ObolKdc[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 0
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -NoPrompt

Leave the prompt unchanged.
Without it the realm is added to the start of the prompt while the environment is entered.

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

### -Scope

Which authentication uses the KDCs.

+ `Thread`: Kerberos authentication done on the current thread, like `Add-ObolSspiKdc -Scope Thread`. No administrator rights are needed. It fails if the thread already has a KDC from `Add-ObolSspiKdc`, as `Exit-ObolSspiEnvironment` would remove it.
+ `Machine`: all Kerberos authentication on the machine, like `Add-ObolSspiKdc -Scope Machine`. This needs administrator rights.

The default is `Thread`.

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

### Obol.ObolKdc[]

The KDCs to register.

## OUTPUTS

## NOTES

Windows cannot remove the registration of a single realm, so `Exit-ObolSspiEnvironment` removes every one in the same scope, see that cmdlet.

With `Machine`, Windows only keeps a KDC entered up to the minutes represented by `FarKdcTimeout`, 10 minutes by default.
After this time the machine binding will be invalid and no seen by KDC using the machine bind method.
See [Expiry in about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md#expiry) to change it.

A registration only matters when Windows has to contact a KDC, a ticket it already has is used as is, see [WHEN A KDC IS CONTACTED in about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md#when-a-kdc-is-contacted).

## RELATED LINKS

- [Exit-ObolSspiEnvironment](./Exit-ObolSspiEnvironment.md)
- [Use-ObolSspiEnvironment](./Use-ObolSspiEnvironment.md)
- [Add-ObolSspiKdc](./Add-ObolSspiKdc.md)
- [Start-ObolKdc](./Start-ObolKdc.md)
- [about_ObolSspi](./about_ObolSspi.md)
