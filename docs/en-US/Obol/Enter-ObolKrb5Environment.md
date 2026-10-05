---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/PowerShell-Obol/blob/main/docs/en-US/Obol/Enter-ObolKrb5Environment.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Enter-ObolKrb5Environment
---

# Enter-ObolKrb5Environment

## SYNOPSIS

Points the krb5 environment variables of the current process at Obol KDCs.

## SYNTAX

### __AllParameterSets

```
Enter-ObolKrb5Environment [-Kdc] <ObolKdc[]> [-Provider <ObolKrb5Provider>]
 [-ServicePrincipal <ObolPrincipal[]>] [-ClientPrincipal <ObolPrincipal[]>] [-SetNativeEnvironment]
 [-NoPrompt] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Sets the environment variables MIT krb5 and Heimdal read so Kerberos clients and services started from the current process use Obol KDCs.
It writes the files the environment variables point to in a new directory under the temporary folder, readable only by the current user on Linux and macOS:

+ `KRB5_CONFIG`: a `krb5.conf` for the KDCs, the same content as `ConvertTo-ObolKrb5Config` outputs.
  It replaces the system configuration, the realm of the first KDC is the default realm.
+ `KRB5CCNAME`: a `FILE:` credential cache in the directory, so tickets from `kinit` do not mix with the user's own tickets.
  The file is created by the first client that stores a ticket.
+ `KRB5_KTNAME`: a keytab of the keys of `-ServicePrincipal`, only set when it is used.
  Services and `kinit -k` without a keytab path use it.
+ `KRB5_CLIENT_KTNAME`: a keytab of the keys of `-ClientPrincipal`, only set when it is used.
  MIT krb5 uses it to get initial tickets without a password, such as `kinit -k -i`.
  Heimdal, including macOS, does not read it, pass the client to `-ServicePrincipal` instead and use `kinit -k` without a keytab path.

The environment variables are set for the whole process, not just the current runspace, and child processes such as `kinit` or `curl` inherit them.
Only one environment can be entered in a process at a time, run `Exit-ObolKrb5Environment` to restore the previous values and remove the files.
To use something else, such as different KDCs in separate child processes, write the files with `Export-ObolKrb5Config` and `Export-ObolKeytab` and set the environment variables yourself.

The environment is not tied to the KDCs, stopping a KDC does not exit it.
Only the runspace that entered it can exit it, and it is exited when that runspace closes.

The `prompt` function of the runspace is changed to start with the default realm, such as `[EXAMPLE.TEST]`, or `[EXAMPLE.TEST +1]` when there are KDCs for other realms too.
The realm is shown in cyan unless `$PSStyle.OutputRendering` is `PlainText`, which is also the case when the `NO_COLOR` environment variable is set.
`Exit-ObolKrb5Environment` restores the original prompt, use `-NoPrompt` to leave the prompt unchanged.

On Linux and macOS .NET keeps its own copy of the environment variables and does not modify the underlying process environment set.
Child processes see the change but native libraries loaded in the current process do not, including the GSSAPI library .NET uses for Negotiate and Kerberos authentication in `HttpClient`, `NegotiateStream` and `NegotiateAuthentication`.
Use `-SetNativeEnvironment` to also change the native process environment block that those libraries read.

On Windows the environment variables only affect programs that use MIT krb5 or Heimdal, such as MIT Kerberos for Windows.
They do not change which KDC Windows itself uses for SSPI authentication.

A KDC that is not running or whose realm cannot be written in a krb5.conf writes an error and is left out, nothing is changed if no KDC can be used.

## EXAMPLES

### Example 1: Get tickets with kinit

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST -Principal @{
    user = ConvertTo-SecureString -AsPlainText -Force 'Password123!'
    'HTTP/web.example.test' = $null
}
Enter-ObolKrb5Environment -Kdc $kdc
'Password123!' | kinit user
kvno HTTP/web.example.test
Exit-ObolKrb5Environment
```

Points `kinit` and `kvno` at the KDC, the tickets are stored in a credential cache that is removed on exit.

### Example 2: Run a client and service with keytabs

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST -Principal @{ user = $null; 'HTTP/web.example.test' = $null }
$params = @{
    Kdc = $kdc
    ClientPrincipal = $kdc | Get-ObolPrincipal user
    ServicePrincipal = $kdc | Get-ObolPrincipal HTTP/web.example.test
}
Enter-ObolKrb5Environment @params
try {
    kinit -k -i user
    ./my-service-test
}
finally {
    Exit-ObolKrb5Environment
}
```

Writes a client keytab for `user` and a service keytab for `HTTP/web.example.test`, then gets a ticket without a password using MIT krb5.
A service started from the process reads its keys from `KRB5_KTNAME`.

### Example 3: Use Kerberos authentication from .NET in the current process

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST -Principal @{ user = $null; 'HTTP/web.example.test' = $null }
Enter-ObolKrb5Environment -Kdc $kdc -ClientPrincipal ($kdc | Get-ObolPrincipal user) -SetNativeEnvironment
kinit -k -i user

$auth = [System.Net.Security.NegotiateAuthentication]::new(
    [System.Net.Security.NegotiateAuthenticationClientOptions]@{
        Package = 'Kerberos'
        TargetName = 'HTTP/web.example.test'
    })
$status = [System.Net.Security.NegotiateAuthenticationStatusCode]::GenericFailure
$token = $auth.GetOutgoingBlob([byte[]]@(), [ref]$status)
```

Sets the native environment variables too, so the GSSAPI library .NET loads on Linux and macOS reads the krb5.conf and credential cache of the environment.

## PARAMETERS

### -ClientPrincipal

Principals to write to a client keytab that `KRB5_CLIENT_KTNAME` points to, as output by `Get-ObolPrincipal` or `New-ObolPrincipal`.
The keytab has an entry for each key of the principals and their aliases.
`KRB5_CLIENT_KTNAME` is not set when this is not used.

Only MIT krb5 reads `KRB5_CLIENT_KTNAME`.
Heimdal, the Kerberos implementation on macOS, ignores it, add the client to `-ServicePrincipal` instead so `kinit -k <client>` finds its keys in the keytab `KRB5_KTNAME` points to.

```yaml
Type: Obol.ObolPrincipal[]
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

The KDCs to point the environment at, as output by `Start-ObolKdc` or `Get-ObolKdc`.
The realm of the first KDC is the default realm.
KDCs from the pipeline are combined into a single krb5.conf.

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

### -ServicePrincipal

Principals to write to a keytab that `KRB5_KTNAME` points to, as output by `Get-ObolPrincipal` or `New-ObolPrincipal`.
The keytab has an entry for each key of the principals and their aliases.
`KRB5_KTNAME` is not set when this is not used.

```yaml
Type: Obol.ObolPrincipal[]
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

Also set the environment variables in the C library's environment on Linux and macOS, so native libraries in the current process, such as the GSSAPI library .NET uses for Kerberos authentication, use the KDCs.
Without it only .NET and child processes see the environment variables.

This changes the environment for every native library in the process, any Kerberos authentication made by the process uses the KDCs until the environment is exited.
The C library functions that change the environment are not thread safe, a native thread outside of PowerShell reading an environment variable at the same time can crash the process.
Avoid using it while other threads may be using native libraries.

It has no effect on Windows, where .NET changes the process environment directly.

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

The KDCs to point the environment at.

## OUTPUTS

## NOTES

The krb5.conf only reflects the KDCs when it is written, exit and enter the environment again after starting a KDC on a new port.
The keytabs are copies of the keys when it is entered, changes to the principals are not written to them.

The environment variables replace any existing value, so MIT krb5 and Heimdal ignore the system krb5.conf and the user's default credential cache while the environment is entered.

## RELATED LINKS

- [Exit-ObolKrb5Environment](./Exit-ObolKrb5Environment.md)
- [Export-ObolKrb5Config](./Export-ObolKrb5Config.md)
- [Export-ObolKeytab](./Export-ObolKeytab.md)
- [Start-ObolKdc](./Start-ObolKdc.md)
- [MIT krb5 environment variables](https://web.mit.edu/kerberos/krb5-latest/doc/user/user_config/kerberos.html#environment-variables)
