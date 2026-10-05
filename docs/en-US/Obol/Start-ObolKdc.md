---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/Start-ObolKdc.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Start-ObolKdc
---

# Start-ObolKdc

## SYNOPSIS

Starts an Obol Kerberos KDC.

## SYNTAX

### __AllParameterSets

```
Start-ObolKdc [-Realm] <string> [-Address <ipaddress>] [-Port <int>] [-Transport <ObolKdcTransport>]
 [-MaxUdpReplySize <int>] [-CaseInsensitivePrincipal] [-DomainSid <string>]
 [-Principal <IDictionary>] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Starts a Kerberos Key Distribution Center (KDC) for the realm specified.
The KDC runs on background threads in the current PowerShell process and listens for Kerberos requests over TCP and UDP, or just one of them with `-Transport`, until it is stopped with `Stop-ObolKdc`, disposed, or the runspace that started it is closed.

By default the KDC listens on a random port, free for every transport used, on the IPv4 loopback address.
Use the `Port` property of the output object to find the port chosen.
Multiple KDCs can run at the same time, each on its own port.

The KDC creates the `krbtgt/<realm>` principal with random keys for every supported encryption type, in the order `Aes256Sha1, Aes128Sha1, Aes256Sha384, Aes128Sha256`.
TGTs are encrypted with the first key, `Aes256Sha1`, see [ENCRYPTION TYPES in about_Obol](./about_Obol.md#encryption-types) to change this.
Use `-Principal` or `New-ObolPrincipal` to add users and services.

Starting a KDC does not change any system or process configuration, including firewall rules, the client must be configured separately to use it.

## EXAMPLES

### Example 1: Start a KDC on a random port

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST
$kdc.Port
```

Starts a KDC for the realm `EXAMPLE.TEST` on a random port on `127.0.0.1` and outputs the port it is listening on.

### Example 2: Start a KDC on a specific address and port

```powershell
Start-ObolKdc -Realm EXAMPLE.TEST -Address :: -Port 8088
```

Starts a KDC that listens on TCP and UDP port 8088 for all IPv6 and IPv4 addresses.

### Example 3: Start a KDC on the standard Kerberos port

```powershell
Start-ObolKdc -Realm EXAMPLE.TEST -Address 0.0.0.0 -Port 88
```

Starts a KDC on TCP and UDP port 88 for all IPv4 addresses, the port Windows clients always use to contact a KDC.

### Example 4: Start a KDC with principals

```powershell
$password = Read-Host -AsSecureString -Prompt Password
Start-ObolKdc -Realm EXAMPLE.TEST -Principal ([ordered]@{
    user = $password
    'HTTP/web.example.test' = $null
    roast = New-ObolPrincipalSetting -Password $password -Flag DontRequirePreAuth
})
```

Starts a KDC with the user `user`, the service `HTTP/web.example.test` with random keys and the user `roast` that does not require pre-authentication.
The principals are created before the KDC answers any request.

### Example 5: Add principals after starting the KDC

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST
$password = Read-Host -AsSecureString -Prompt Password
$kdc | New-ObolPrincipal user -Password $password
$kdc | New-ObolPrincipal HTTP/web.example.test
$kdc | New-ObolPrincipal roast -Password $password -Flag DontRequirePreAuth
```

Creates the same principals as the previous example with `New-ObolPrincipal` after the KDC has started.
Principals can be added, changed and removed while the KDC is running, a client that sends a request before a principal is created gets a principal unknown error.

### Example 6: Start a TCP only KDC

```powershell
Start-ObolKdc -Realm EXAMPLE.TEST -Transport Tcp
```

Starts a KDC that only listens over TCP, for example to test that a client falls back to TCP when UDP fails.

### Example 7: Force UDP replies to be too big

```powershell
Start-ObolKdc -Realm EXAMPLE.TEST -MaxUdpReplySize 100
```

Starts a KDC that replies with `KRB_ERR_RESPONSE_TOO_BIG` to any UDP request whose reply is more than 100 bytes, to test that a client retries the request over TCP.

### Example 8: Start a KDC with a set domain SID

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST -DomainSid S-1-5-21-1111111111-2222222222-3333333333 -Principal @{
    'HTTP/web.example.test' = $null
}
($kdc | Get-ObolPrincipal HTTP/web.example.test).Sid
```

```Output
S-1-5-21-1111111111-2222222222-3333333333-1000
```

Starts a KDC whose principals have the same SIDs each time it is started with this domain SID.

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

```yaml
Type: System.Net.IPAddress
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

### -CaseInsensitivePrincipal

Matches principal names case insensitively, like AD, instead of case sensitively like MIT.
With this set `user` and `USER` are the same principal, so creating both fails.
The realm is always matched case sensitively.

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

### -DomainSid

The domain SID the SIDs of the principals are based on, in the AD form `S-1-5-21-<a>-<b>-<c>` where each value is a 32-bit unsigned integer.
Defaults to a random domain SID so the principals of different KDCs have different SIDs.

Set a domain SID to give principals the same SIDs each time the KDC is started, or to match the SIDs of an existing domain.
The PAC of a ticket has the domain SID, the SID of the principal and the Domain Users group of the domain (RID 513).

```yaml
Type: System.String
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

### -MaxUdpReplySize

The largest reply in bytes sent over UDP, defaults to 4096 like the MIT KDC `max_dgram_reply_size` setting.
A larger reply is replaced with a `KRB_ERR_RESPONSE_TOO_BIG` error, which tells the client to retry over TCP.
The error is sent even if it is larger than this limit.
The value must be between 1 and 65507, the largest UDP payload over IPv4.
It has no effect when the KDC does not listen over UDP.

```yaml
Type: System.Int32
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

```yaml
Type: System.Int32
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

```yaml
Type: System.Collections.IDictionary
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

### -Transport

The transports to listen on, `Tcp`, `Udp` or both with `-Transport Tcp, Udp`.
Defaults to both, using the same port number for each.
Use a single transport to test how a client behaves when the other one is unavailable, or when only one of the ports is free.

```yaml
Type: Obol.ObolKdcTransport
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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutBuffer, -OutVariable, -PipelineVariable,
-ProgressAction, -Verbose, -WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### Obol.ObolKdc

The KDC that was started.
It has the properties:

- `Realm`: The realm the KDC serves
- `Endpoint`: The IP address and port the KDC is listening on
- `Port`: The port the KDC is listening on
- `Transport`: The transports the KDC is listening on, `Tcp`, `Udp` or `Tcp, Udp`
- `MaxUdpReplySize`: The largest UDP reply sent before replying with `KRB_ERR_RESPONSE_TOO_BIG`
- `StartTime`: The local time the KDC was started
- `State`: Whether the KDC is `Running`, `Stopped` or `Faulted`
- `Error`: The exception that stopped the KDC when it is `Faulted`
- `CaseInsensitivePrincipal`: Whether principal names are matched case insensitively
- `DomainSid`: The domain SID the principal SIDs in the PAC are based on

A KDC is `Faulted` when its listener fails unexpectedly, it stops listening and stays listed by `Get-ObolKdc` until it is stopped with `Stop-ObolKdc`.
An invalid request never stops the KDC.

Calling `Dispose()` on the object stops the KDC like `Stop-ObolKdc`.

The object raises the .NET event `RequestProcessed` with an `ObolKdcEvent` for each request the KDC answers, see [Trace-ObolKdc](./Trace-ObolKdc.md) and [TRACING REQUESTS in about_Obol](./about_Obol.md#tracing-requests).

## NOTES

The KDC is tied to the runspace that started it and is stopped when that runspace is closed.
`Get-ObolKdc` only lists the KDCs started in the current runspace.

## RELATED LINKS

- [Get-ObolKdc](./Get-ObolKdc.md)
- [New-ObolPrincipal](./New-ObolPrincipal.md)
- [Stop-ObolKdc](./Stop-ObolKdc.md)
- [Trace-ObolKdc](./Trace-ObolKdc.md)
- [about_Obol](./about_Obol.md)
