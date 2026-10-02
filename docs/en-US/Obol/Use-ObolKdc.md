---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/Use-ObolKdc.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Use-ObolKdc
---

# Use-ObolKdc

## SYNOPSIS

Runs a scriptblock with an Obol KDC and the krb5 environment variables pointing at it.

## SYNTAX

### Start (Default)

```
Use-ObolKdc [-Realm] <string> [-ScriptBlock] <scriptblock> [-Address <ipaddress>] [-Port <int>]
 [-Transport <ObolKdcTransport>] [-MaxUdpReplySize <int>] [-CaseInsensitivePrincipal]
 [-DomainSid <string>] [-Principal <IDictionary>] [-Provider <ObolKrb5Provider>]
 [-ServicePrincipal <string[]>] [-ClientPrincipal <string[]>] [-SetNativeEnvironment] [-NoNewScope]
 [<CommonParameters>]
```

### Kdc

```
Use-ObolKdc [-ScriptBlock] <scriptblock> -Kdc <ObolKdc[]> [-Provider <ObolKrb5Provider>]
 [-ServicePrincipal <string[]>] [-ClientPrincipal <string[]>] [-SetNativeEnvironment] [-NoNewScope]
 [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Starts a KDC, or uses existing ones, enters the krb5 environment for them, runs the scriptblock and then always exits the environment and stops the KDC it started, even when the scriptblock fails.
It combines `Start-ObolKdc`, `Enter-ObolKrb5Environment`, `Exit-ObolKrb5Environment` and `Stop-ObolKdc` for a script that only needs the KDC while one block of code runs.
Pester tests that set up a KDC in `BeforeAll` and remove it in `AfterAll` use those cmdlets instead, as a scriptblock cannot span both blocks.

With `-Realm` a new KDC is started with the KDC parameters of `Start-ObolKdc` and stopped once the scriptblock finishes.
With `-Kdc` the given KDCs are used and left running.
Each KDC is passed to the scriptblock as a separate argument, such as `param ($kdc)` or `$args[0]`.

The environment variables are set like `Enter-ObolKrb5Environment` sets them, see that cmdlet for what they are and how they reach child processes and native libraries.
The keytab environment variables are set from principal names, as a new KDC has no principal objects before it starts.
It fails if a krb5 environment is already entered in the process, the scriptblock is not run and no KDC is started.

The scriptblock is run like the call operator `& { ... }` runs it, or like the dot-source operator `. { ... }` with `-NoNewScope`:

+ Output is written to the pipeline as it is received.
+ A terminating error in the scriptblock, such as `throw`, is thrown by this cmdlet once the environment is exited and the KDC stopped.
+ Errors, warnings and the other streams are written through this cmdlet, so `-ErrorVariable`, `-WarningVariable`, `-InformationVariable` and redirection such as `3>&1` or `2>$null` apply to them.
+ Commands in the scriptblock follow the preference variables of the caller, such as `$ErrorActionPreference`, like they would in `& { ... }`.
  The `-ErrorAction`, `-WarningAction`, `-InformationAction`, `-Verbose` and `-Debug` common parameters of this cmdlet only apply to its own errors and messages, such as a KDC that fails to start, not to the commands in the scriptblock.
  Set the preference variable inside the scriptblock to change how its commands handle errors, or before calling this cmdlet to change it for the caller too.

On Windows only the krb5 environment variables are set, which affect programs using MIT krb5 or Heimdal and not Windows SSPI authentication.

## EXAMPLES

### Example 1: Get a ticket with kinit

```powershell
$password = ConvertTo-SecureString -AsPlainText -Force 'Password123!'
Use-ObolKdc -Realm EXAMPLE.TEST -Principal @{ user = $password; 'HTTP/web.example.test' = $null } {
    'Password123!' | kinit user
    kvno HTTP/web.example.test
}
```

Starts a KDC for `EXAMPLE.TEST` with two principals, gets a ticket for `user` and a service ticket with the MIT krb5 tools, then stops the KDC and restores the environment variables.

### Example 2: Test a client and service with keytabs

```powershell
$params = @{
    Realm = 'EXAMPLE.TEST'
    Principal = @{ user = $null; 'HTTP/web.example.test' = $null }
    ClientPrincipal = 'user'
    ServicePrincipal = 'HTTP/web.example.test'
}
Use-ObolKdc @params {
    param ($kdc)

    kinit -k -i user
    ./test-service.sh
}
```

Writes a client keytab for `user` and a service keytab for `HTTP/web.example.test`, so `kinit` gets a ticket without a password and a service started by the script reads its keys from `KRB5_KTNAME`.

### Example 3: Use existing KDCs

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST -Principal @{ user = $null }
$other = Start-ObolKdc -Realm OTHER.TEST -Principal @{ user = $null }

$kdc, $other | Use-ObolKdc -ClientPrincipal user, user@OTHER.TEST {
    param ($first, $second)

    kinit -k -i user@OTHER.TEST
}
```

Uses two running KDCs, the first realm is the default realm and a principal name without a realm is found in it.
The KDCs keep running after the scriptblock finishes.

### Example 4: Set variables in the current scope

```powershell
Use-ObolKdc -Realm EXAMPLE.TEST -NoNewScope {
    $ccache = $env:KRB5CCNAME
}
$ccache
```

Runs the scriptblock in the current scope, so variables it sets are kept after it finishes.
The credential cache file itself is removed with the environment.

### Example 5: Stop on errors in the scriptblock

```powershell
Use-ObolKdc -Realm EXAMPLE.TEST {
    $ErrorActionPreference = 'Stop'

    Get-Item ./missing.txt
    'not reached'
}
```

The commands in the scriptblock follow `$ErrorActionPreference`, so the error from `Get-Item` stops the scriptblock.
Setting it in the scriptblock only changes it for the scriptblock, which runs in its own scope, with `-NoNewScope` it stays set after the scriptblock finishes.
`Use-ObolKdc -ErrorAction Stop` would not stop it, as the common parameter only applies to the errors of `Use-ObolKdc` itself and not the scriptblock it runs.

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

### -ClientPrincipal

Names of principals to write to a client keytab that `KRB5_CLIENT_KTNAME` points to.
A name without a realm, such as `user`, is found in the realm of the first KDC, a name with a realm, such as `user@OTHER.TEST`, in the first KDC for that realm.
A name that is not found is a terminating error and the scriptblock is not run.

Only MIT krb5 reads `KRB5_CLIENT_KTNAME`.
Heimdal, the Kerberos implementation on macOS, ignores it, use `-ServicePrincipal` for the client instead so `kinit -k <client>` finds its keys in the keytab `KRB5_KTNAME` points to.

```yaml
Type: System.String[]
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
The realm of the first KDC is the default realm.
The KDCs are not stopped after the scriptblock runs.
A KDC that is not running is a terminating error and the scriptblock is not run.

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

### -Port

The port to listen on, the same port number is used for TCP and UDP.
The default of `0` uses a random port that is free for every transport in `-Transport`.
The port chosen is available from the `Port` property of the output object, or the `Endpoint` property for the address and port together.
The command fails if the port is already in use for any of those transports.

The standard Kerberos KDC port is `88`.
Windows always contacts to a KDC on port `88`, it ignores the port in a `_kerberos` `SRV` record and in a realm mapping like `ksetup /addkdc`, so use `-Port 88` for a KDC that Windows hosts connect to directly.
Only a KDC proxy (MS-KKDCP) lets Windows reach a KDC through another port by having the proxy forward the traffic to an alternative port.
MIT and Heimdal clients can use any port set in `krb5.conf` or an `SRV` record.
On Linux and macOS binding a port below 1024 may need root or a capability like `CAP_NET_BIND_SERVICE`, Windows does not need administrator rights for it.
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

### -Provider

The Kerberos implementation the krb5.conf is written for, see `Export-ObolKrb5Config` for how they differ.

+ `Default`: `Heimdal` on macOS and `Mit` on other platforms.
+ `Mit`: MIT krb5.
+ `Heimdal`: Heimdal, including the macOS GSS framework.

`Default` is used when the parameter is not set.

```yaml
Type: Obol.ObolKrb5Provider
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

### -ScriptBlock

The scriptblock to run while the KDC and environment exist.
Each KDC is passed to it as a separate argument, in the order they were given, or the started KDC with `-Realm`.

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

### -ServicePrincipal

Names of principals to write to a keytab that `KRB5_KTNAME` points to.
A name without a realm, such as `HTTP/web.example.test`, is found in the realm of the first KDC, a name with a realm in the first KDC for that realm.
A name that is not found is a terminating error and the scriptblock is not run.

```yaml
Type: System.String[]
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

### -SetNativeEnvironment

Also set the environment variables in the C library's environment on Linux and macOS, so native libraries in the current process, such as the GSSAPI library .NET uses for Kerberos authentication, use the KDC.
See `Enter-ObolKrb5Environment -SetNativeEnvironment` for the risks, the C library functions that change the environment are not thread safe.
It has no effect on Windows.

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

### System.Object

The output of the scriptblock.

## NOTES

`$MyInvocation` in the scriptblock has the script and line that called `Use-ObolKdc`, like `& { ... }` on that line would. Its `InvocationName` is the path of the calling script rather than `&` or `.`, and only the first line of a call that spans several lines is known.

The KDC started with `-Realm` is listed by `Get-ObolKdc` while the scriptblock runs.

## RELATED LINKS

- [Start-ObolKdc](./Start-ObolKdc.md)
- [Enter-ObolKrb5Environment](./Enter-ObolKrb5Environment.md)
- [Exit-ObolKrb5Environment](./Exit-ObolKrb5Environment.md)
- [about_Operators](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_operators)

