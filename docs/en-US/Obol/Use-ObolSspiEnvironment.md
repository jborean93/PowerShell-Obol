---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/Use-ObolSspiEnvironment.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Use-ObolSspiEnvironment
---

# Use-ObolSspiEnvironment

## SYNOPSIS

Runs a scriptblock with an Obol KDC registered with Windows Kerberos.

## SYNTAX

### Start (Default)

```
Use-ObolSspiEnvironment [-Realm] <string> [-ScriptBlock] <scriptblock> [-Scope <ObolSspiKdcScope>]
 [-Address <ipaddress>] [-Transport <ObolKdcTransport>] [-MaxUdpReplySize <int>]
 [-CaseInsensitivePrincipal] [-DomainSid <string>] [-Principal <IDictionary>] [-NoNewScope]
 [<CommonParameters>]
```

### Kdc

```
Use-ObolSspiEnvironment [-ScriptBlock] <scriptblock> -Kdc <ObolKdc[]> [-Scope <ObolSspiKdcScope>]
 [-NoNewScope] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Starts a KDC, or uses existing ones, registers them with Windows Kerberos, runs the scriptblock and then always removes the registration and stops the KDC it started, even when the scriptblock fails.
It combines `Start-ObolKdc`, `Enter-ObolSspiEnvironment`, `Exit-ObolSspiEnvironment` and `Stop-ObolKdc` for a script that only needs the KDC while one block of code runs.
Pester tests that set up a KDC in `BeforeAll` and remove it in `AfterAll` cannot use a scriptblock that spans both blocks, they use those cmdlets directly.

With `-Realm` a new KDC is started with the KDC parameters of `Start-ObolKdc` and stopped once the scriptblock finishes.
With `-Kdc` the given KDCs are used and left running.
Each KDC is passed to the scriptblock as a separate argument, such as `param ($kdc)` or `$args[0]`.

Windows' own Kerberos, used by SSPI and anything built on it such as `HttpClient` with default credentials, `NegotiateStream`, `System.DirectoryServices` and SMB, ignores `krb5.conf` and the krb5 environment variables.
This registers each KDC's realm with Windows Kerberos instead, so it sends the requests for that realm to the KDC, the same as `Enter-ObolSspiEnvironment`.
`-Scope` sets which authentication uses the KDCs:

+ `Thread` (the default): only Kerberos authentication done on the thread the scriptblock runs on. No administrator rights are needed.
+ `Machine`: all Kerberos authentication on the machine, including other processes and SMB, through the KDC binding cache. This needs administrator rights.
+ `MitRealm`: all Kerberos authentication on the machine, the realm is added like `ksetup.exe /addkdc` so Windows treats it as an MIT realm. This needs administrator rights.
+ `DcLocator`: all Kerberos authentication on the machine, Windows finds the KDC like a domain controller of an Active Directory domain through a DNS server and LDAP ping responder Obol runs on UDP ports 53 and 389 of the KDC address. This needs administrator rights.

See `Enter-ObolSspiEnvironment` for how the machine wide scopes differ.

Programs that use MIT krb5 or Heimdal, such as `kinit` or a Python or Java client, use `Use-ObolKrb5Environment` instead.
This cmdlet is only supported on Windows and errors on other platforms.

The scriptblock is run like the call operator `& { ... }` runs it, or like the dot-source operator `. { ... }` with `-NoNewScope`:

+ Output is written to the pipeline as it is received.
+ A terminating error in the scriptblock, such as `throw`, is thrown by this cmdlet once the registration is removed and the KDC stopped.
+ Errors, warnings and the other streams are written through this cmdlet, so `-ErrorVariable`, `-WarningVariable`, `-InformationVariable` and redirection such as `3>&1` or `2>$null` apply to them.
+ Commands in the scriptblock follow the preference variables of the caller, such as `$ErrorActionPreference`, like they would in `& { ... }`.
  The `-ErrorAction`, `-WarningAction`, `-InformationAction`, `-Verbose` and `-Debug` common parameters of this cmdlet only apply to its own errors and messages, such as a KDC that fails to start, not to the commands in the scriptblock.
  Set the preference variable inside the scriptblock to change how its commands handle errors, or before calling this cmdlet to change it for the caller too.

Windows Kerberos has some limitations:

+ It always contacts a KDC on port 88.
  A KDC started with `-Realm` always listens on port 88, if it is already in use set `-Address` to another `127.0.0.x` address, as Windows allows the same port on different loopback addresses.
  A KDC from `-Kdc` on any other port is an error and the scriptblock is not run.
+ It cannot remove the registration of a single realm, so when the scriptblock finishes every registration in the same scope is removed, see `Exit-ObolSspiEnvironment`.
  With `Thread` this fails if the thread already has a KDC from `Add-ObolSspiKdc`, as it would be removed.
+ With `Thread`, authentication that is not done on the scriptblock's thread does not use the KDC, such as in a job, another runspace or an async continuation, or SMB and CredSSP which Windows does on its own threads.
+ With `Machine`, Windows stops using the KDC about 10 minutes after the scriptblock starts, the `FarKdcTimeout` setting, as it only keeps a KDC added by hand for that long.
+ With `MitRealm` and `DcLocator`, it fails without starting a KDC if the realm's registry key or an NRPT rule for the realm already exists, existing configuration is never changed.

Only one SSPI environment can be entered in the process at a time, so this fails without starting a KDC if `Enter-ObolSspiEnvironment` or another `Use-ObolSspiEnvironment` has one entered.
It can be used inside `Use-ObolKrb5Environment`, or the other way around, to configure both environment types.
See [about_ObolSspi](./about_ObolSspi.md) for how this works in Windows Kerberos.

## EXAMPLES

### Example 1: Run with a KDC for the current thread

```powershell
Use-ObolSspiEnvironment -Realm EXAMPLE.TEST -Principal @{ 'HTTP/web.example.test' = $null } {
    param ($kdc)

    # SSPI Kerberos for EXAMPLE.TEST on this thread uses $kdc.
}
```

Starts a KDC for `EXAMPLE.TEST` on port 88, registers it for the scriptblock's thread, then removes the registration and stops the KDC.

### Example 2: Use SSPI

```powershell
$password = ConvertTo-SecureString -AsPlainText -Force 'Password123!'
Use-ObolSspiEnvironment -Realm EXAMPLE.TEST -Principal @{ user = $password; 'HTTP/web.example.test' = $null } {
    $client = [System.Net.Security.NegotiateAuthentication]::new(
        [System.Net.Security.NegotiateAuthenticationClientOptions]@{
            Package = 'Kerberos'
            Credential = [System.Net.NetworkCredential]::new('user@EXAMPLE.TEST', 'Password123!')
            TargetName = 'HTTP/web.example.test'
        })
    try {
        $status = [System.Net.Security.NegotiateAuthenticationStatusCode]::GenericFailure
        $token = $client.GetOutgoingBlob([byte[]]@(), [ref]$status)
        $status
    }
    finally {
        $client.Dispose()
    }
}
```

Gets a Kerberos service ticket for `HTTP/web.example.test` from the KDC through the Windows Kerberos SSP, with .NET's `NegotiateAuthentication`.
`$status` is `Completed` and `$token` is the Kerberos token to send to the service.
The scriptblock runs on the thread the KDC is registered for, so the SSP finds the KDC without any other configuration.

### Example 3: Run with a KDC for the whole machine

```powershell
Use-ObolSspiEnvironment -Realm EXAMPLE.TEST -Scope Machine {
    # Other processes and SMB use the KDC for EXAMPLE.TEST here.
}
```

Registers the KDC for every process on the machine, so SMB, which Windows runs on its own threads, uses it too.
This needs an elevated session.

### Example 4: Run with the KDC found like a domain controller

```powershell
Use-ObolSspiEnvironment -Realm EXAMPLE.TEST -Scope DcLocator {
    nltest.exe /dsgetdc:EXAMPLE.TEST /kdc
}
```

Windows finds the KDC through the DNS records and LDAP ping an Active Directory domain controller answers, `nltest.exe` shows `kdc1.example.test` as the domain controller.
This needs an elevated session.

### Example 5: Configure Windows Kerberos and the krb5 environment

```powershell
Use-ObolKrb5Environment -Realm EXAMPLE.TEST -Port 88 {
    param ($kdc)

    Use-ObolSspiEnvironment -Kdc $kdc {
        # Both SSPI and MIT krb5 clients use $kdc here.
    }
}
```

Starts one KDC on port 88 and points both the krb5 environment and Windows Kerberos at it.

### Example 5: Stop on errors in the scriptblock

```powershell
Use-ObolSspiEnvironment -Realm EXAMPLE.TEST {
    $ErrorActionPreference = 'Stop'

    Get-Item ./missing.txt
    'not reached'
}
```

The commands in the scriptblock follow `$ErrorActionPreference`, so the error from `Get-Item` stops the scriptblock.
`Use-ObolSspiEnvironment -ErrorAction Stop` would not stop it, as the common parameter only applies to the errors of `Use-ObolSspiEnvironment` itself and not the scriptblock it runs.

## PARAMETERS

### -Address

The IP address to listen on, defaults to the IPv4 loopback address `127.0.0.1`.
The value can be any IPv4 or IPv6 address string, such as `192.168.1.10`, or an `[IPAddress]` object.
Host names like `localhost` are not supported, use the address the name resolves to.

Common values, which tab completion offers, are:

- `127.0.0.1`: IPv4 loopback, only reachable from this host
- `::1`: IPv6 loopback, only reachable from this host
- `0.0.0.0`: All IPv4 addresses
- `::`: All IPv6 and IPv4 addresses

Whether the IPv6 values work depends on how the platform is configured.
Common cases are Linux containers, where IPv6 is often disabled so `::1` is not available, and Linux hosts with IPv6 disabled at boot, where neither `::1` nor `::` can be used.
In cases where IPv6 is disabled, use `127.0.0.1` or `0.0.0.0` instead.
Any address other than a loopback address makes the KDC reachable from other hosts that can reach that bound address.
The cmdlet does not add or change any firewall rules, the host firewall must allow the port for other hosts to connect.
On Windows, listening on a non-loopback address may show a Windows Defender Firewall prompt for the PowerShell process.
Used with `-Realm` only.

```yaml
Type: System.Net.IPAddress
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Start
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -CaseInsensitivePrincipal

Matches principal names case insensitively, like AD, instead of case sensitively like MIT.
With this set `user` and `USER` are the same principal, so creating both fails.
The realm is always matched case sensitively.
Used with `-Realm` only.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Start
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -DomainSid

The domain SID the SIDs of the principals are based on, in the AD form `S-1-5-21-<a>-<b>-<c>` where each value is a 32-bit unsigned integer.
Defaults to a random domain SID so the principals of different KDCs have different SIDs.

Set a domain SID to give principals the same SIDs each time the KDC is started, or to match the SIDs of an existing domain.
The PAC of a ticket has the domain SID, the SID of the principal and the Domain Users group of the domain (RID 513).
Used with `-Realm` only.

```yaml
Type: System.String
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Start
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

Existing KDCs to use, as output by `Start-ObolKdc` or `Get-ObolKdc`, instead of starting a new one.
The KDCs are not stopped after the scriptblock runs.
A KDC that is not running or does not listen on port 88 is a terminating error and the scriptblock is not run.

```yaml
Type: Obol.ObolKdc[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Kdc
  Position: Named
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -MaxUdpReplySize

The largest reply in bytes sent over UDP, defaults to 4096 like the MIT KDC `max_dgram_reply_size` setting.
A larger reply is replaced with a `KRB_ERR_RESPONSE_TOO_BIG` error, which tells the client to retry over TCP.
The error is sent even if it is larger than this limit.
The value must be between 1 and 65507, the largest UDP payload over IPv4.
It has no effect when the KDC does not listen over UDP.
Used with `-Realm` only.

```yaml
Type: System.Int32
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Start
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -NoNewScope

Runs the scriptblock in the current scope, like the dot-source operator, so variables and functions it defines are kept after it finishes.
Without it the scriptblock runs in a new child scope like the call operator.
A scriptblock created elsewhere, such as in a module, also runs in the current scope.

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

### -Principal

Principals to create when the KDC starts, a dictionary of principal names and the value representing how to create each one:

- `$null`: No extra options, random keys, such as for a service
- A `SecureString`: The password to derive the keys from
- An `ObolPrincipalSetting` from `New-ObolPrincipalSetting` for any other settings, such as `-Flag`, `-EncryptionType`, `-Alias` or `-Rid`

Use an ordered dictionary (`[ordered]@{}`) to create the principals in a set order, which sets the order of their RIDs.
The principals are created before the KDC answers any request, a request sent while they are created waits until they exist.
If any principal cannot be created the KDC is stopped and the command fails.
Used with `-Realm` only.

```yaml
Type: System.Collections.IDictionary
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Start
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

The Kerberos realm the KDC serves, for example `EXAMPLE.TEST`.
The realm is case sensitive, as defined by RFC 4120, and is used exactly as given.
Requests for any other realm, including `example.test` for `EXAMPLE.TEST`, fail with a wrong realm error.
Realms are conventionally upper case.
The realm cannot contain `/`, `@`, `\` or control characters, an MIT KDC cannot serve such a realm and every principal name in it would need escaping.
A new KDC for this realm is started for the scriptblock and stopped after.

```yaml
Type: System.String
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Start
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

Which authentication uses the KDCs while the scriptblock runs.

+ `Thread`: Kerberos authentication done on the thread the scriptblock runs on, like `Add-ObolSspiKdc -Scope Thread`. No administrator rights are needed.
+ `Machine`: all Kerberos authentication on the machine, like `Add-ObolSspiKdc -Scope Machine`. This needs administrator rights, without them it fails before the KDC is started.
+ `MitRealm`: all Kerberos authentication on the machine, the realm and its KDCs are added to the registry like `ksetup.exe /addkdc`. This needs administrator rights, without them it fails before the KDC is started.
+ `DcLocator`: all Kerberos authentication on the machine, an NRPT rule sends the realm's DNS queries to a DNS server and LDAP ping responder Obol runs. The realm must be a DNS name. This needs administrator rights, without them it fails before the KDC is started.

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

### -ScriptBlock

The scriptblock to run while the KDC is registered.

```yaml
Type: System.Management.Automation.ScriptBlock
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Start
  Position: 1
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
- Name: Kdc
  Position: 0
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Transport

The transports to listen on, `Tcp`, `Udp` or both with `-Transport Tcp, Udp`.
Defaults to both, using the same port number for each.
Use a single transport to test how a client behaves when the other one is unavailable, or when only one of the ports is free.
Used with `-Realm` only.

```yaml
Type: Obol.ObolKdcTransport
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Start
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

Existing KDCs to use with `-Kdc`.

## OUTPUTS

## NOTES

`$MyInvocation` in the scriptblock has the script and line that called `Use-ObolSspiEnvironment`, like `& { ... }` on that line would. Its `InvocationName` is the path of the calling script rather than `&` or `.`, and only the first line of a call that spans several lines is known.

The KDC started with `-Realm` is listed by `Get-ObolKdc` while the scriptblock runs.

## RELATED LINKS

- [Start-ObolKdc](./Start-ObolKdc.md)
- [Enter-ObolSspiEnvironment](./Enter-ObolSspiEnvironment.md)
- [Exit-ObolSspiEnvironment](./Exit-ObolSspiEnvironment.md)
- [Use-ObolKrb5Environment](./Use-ObolKrb5Environment.md)
- [about_ObolSspi](./about_ObolSspi.md)
- [about_Operators](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_operators)
