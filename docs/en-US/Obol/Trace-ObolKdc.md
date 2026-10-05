---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/Trace-ObolKdc.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Trace-ObolKdc
---

# Trace-ObolKdc

## SYNOPSIS

Outputs the requests Obol KDCs answer, as they happen or the ones made while a scriptblock runs.

## SYNTAX

### Stream (Default)

```
Trace-ObolKdc -Kdc <ObolKdc[]> [<CommonParameters>]
```

### ScriptBlock

```
Trace-ObolKdc [-ScriptBlock] <scriptblock> -Kdc <ObolKdc[]> [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Outputs an `ObolKdcEvent` for each request a KDC answers, with the facts of the exchange, the client and service names and the error code, and the request and reply decoded into objects with the parts the KDC decrypted, such as the ticket issued and its PAC.
See [OUTPUTS](#outputs) and [about_ObolKdcEvent](./about_ObolKdcEvent.md) for the properties.

Without `-ScriptBlock` the events are written as they happen until the pipeline is stopped with Ctrl+C or a downstream command such as `Select-Object -First`, or until every traced KDC has been stopped.
Use this to watch a KDC while testing from another process or terminal.

With `-ScriptBlock` the scriptblock runs and the events of the requests made while it ran are written once it finishes, like `Measure-Command` the output of the scriptblock itself is discarded.
Use this in a test to get the requests a client made and assert on them.
The scriptblock runs in the caller's scope, like it was dot-sourced, so a variable it sets is available after the call, and each traced KDC is passed to it as an argument.
If the scriptblock fails the events are still written before its error so a failed test shows what the KDC saw.

Use `Get-ObolKdc | Trace-ObolKdc` to trace every KDC running in the current runspace.

The events come from the `RequestProcessed` .NET event of the `ObolKdc` object, which can also be used directly with `Register-ObjectEvent` to handle requests in the background, see [TRACING REQUESTS in about_Obol](./about_Obol.md#tracing-requests).

## EXAMPLES

### Example 1: Trace the requests a client makes

```powershell
$password = ConvertTo-SecureString -AsPlainText -Force 'Password123!'
$kdc = Start-ObolKdc EXAMPLE.TEST -Principal @{ user = $password; 'HTTP/web.example.test' = $null }
Enter-ObolKrb5Environment -Kdc $kdc

$events = Trace-ObolKdc -Kdc $kdc {
    'Password123!' | kinit user
    kvno HTTP/web.example.test
}
$events
```

```Output
Time                 Client              Message
----                 ------              -------
4/10/2026 3:12:01 pm Udp 127.0.0.1:40213 AS-REQ user@EXAMPLE.TEST -> krbtgt/EXAMPLE.TEST@EXAMPLE.TEST: PreAuthRequired
4/10/2026 3:12:01 pm Udp 127.0.0.1:40213 AS-REQ user@EXAMPLE.TEST -> krbtgt/EXAMPLE.TEST@EXAMPLE.TEST: AS-REP, Aes256Sha1 ticket and session key, PreAuthenticated, Initial, Renewable
4/10/2026 3:12:01 pm Udp 127.0.0.1:53377 TGS-REQ user@EXAMPLE.TEST -> HTTP/web.example.test@EXAMPLE.TEST: TGS-REP, Aes256Sha1 ticket and session key, PreAuthenticated, Renewable
```

Gets a TGT and a service ticket with the MIT tools and outputs the three requests the KDC answered.
The first AS-REQ is rejected with `PreAuthRequired` as `kinit` asks without pre-authentication first, the second has the encrypted timestamp and gets the TGT, and `kvno` uses the TGT to get the service ticket.

### Example 2: Assert on the requests in a test

```powershell
$events = Use-ObolKrb5Environment EXAMPLE.TEST -Principal @{ user = $null } -ClientPrincipal user {
    param ($kdc)

    Trace-ObolKdc -Kdc $kdc { kinit -k -i user }
}

$tgt = $events | Where-Object ErrorCode -eq None
$tgt.ClientName | Should-Be user@EXAMPLE.TEST
$tgt.Request.Body.EncryptionType | Should-NotContainCollection 23
$tgt.Reply.Ticket.DecryptedPart.Flag.HasFlag([Obol.Kerberos.TicketFlag]::Forwardable) | Should-BeTrue
```

Runs `kinit` with the client keytab `Use-ObolKrb5Environment` writes for `user` and traces the KDC it started, the events are the output of the scriptblock.
The assertions check the client authenticated as the expected principal, did not offer RC4 (23) and got a forwardable TGT.

### Example 3: Watch the KDCs until Ctrl+C

```powershell
Get-ObolKdc | Trace-ObolKdc
```

Outputs each request any KDC in the runspace answers, as it happens, until Ctrl+C.
Run the clients from another terminal or process.

### Example 4: Wait for the first failed request

```powershell
$kdc = Start-ObolKdc EXAMPLE.TEST -Port 88 -Principal @{ user = $null }

$failed = Trace-ObolKdc -Kdc $kdc | Where-Object ErrorCode -ne None | Select-Object -First 1
$failed.Reply.ErrorText
```

```Output
The client has no key for any of the requested encryption types
```

Blocks until a request from a client, run from another terminal or process, is rejected, then shows why the KDC rejected it.
`Select-Object -First` stops the trace once it has the event.

### Example 5: Inspect the ticket issued

```powershell
$principals = @{ user = $null; 'HTTP/web.example.test' = $null }
$events = Use-ObolKrb5Environment EXAMPLE.TEST -Principal $principals -ClientPrincipal user {
    param ($kdc)

    kinit -k -i user
    Trace-ObolKdc -Kdc $kdc { kvno HTTP/web.example.test }
}
$events.Reply.Ticket.DecryptedPart
$events.Reply.Ticket.DecryptedPart.Pac.LogonInfo | Format-List UserName, DomainName, UserSid, GroupId
```

```Output
Flag              : PreAuthenticated, Renewable
Key               : etype Aes256Sha1, 32 bytes
ClientName        : user@EXAMPLE.TEST
TransitedType     : 0
Transited         : {}
AuthTime          : 4/10/2026 3:12:01 pm
StartTime         : 4/10/2026 3:12:01 pm
EndTime           : 5/10/2026 1:12:01 am
RenewTill         : 11/10/2026 3:12:01 pm
Address           : {}
AuthorizationData : {IfRelevant [Win2kPac PAC for EXAMPLE\user, 4 buffers]}
Pac               : PAC for EXAMPLE\user, 4 buffers

UserName   : user
DomainName : EXAMPLE
UserSid    : S-1-5-21-2230978638-1182446536-3657225335-1001
GroupId    : {513 (Mandatory, EnabledByDefault, Enabled)}
```

Gets a TGT before the trace so only the service ticket request is traced, then shows the decrypted ticket the KDC issued and the PAC inside it, which the client cannot see as the ticket is encrypted with the service's key.
The TGT the client presented is under `$events.Request.ApRequest.Ticket.DecryptedPart` in the same way.

### Example 6: Save the messages and keys of a trace

```powershell
$events = Use-ObolKrb5Environment EXAMPLE.TEST -Principal @{ user = $null } -ClientPrincipal user {
    param ($kdc)

    Trace-ObolKdc -Kdc $kdc { kinit -k -i user }
}

$dir = New-Item ./trace -ItemType Directory -Force
$i = 0
foreach ($event in $events) {
    [System.IO.File]::WriteAllBytes("$dir/$i-request.bin", $event.Request.Bytes)
    [System.IO.File]::WriteAllBytes("$dir/$i-reply.bin", $event.Reply.Bytes)
    $i++
}
$keys = $events.Key | Sort-Object FullName, Kvno, EncryptionType -Unique
Export-ObolKeytab -Entry $keys -Path $dir/trace.keytab
```

Writes the raw request and reply of each exchange and a keytab with the long-term keys they used, so the exchange can be decoded and decrypted with other tools later, even after the principal's keys have changed.

### Example 7: Capture a trace of clients outside PowerShell

```powershell
$kdc = Start-ObolKdc EXAMPLE.TEST -Port 88 -Principal @{ user = $null; 'HTTP/web.example.test' = $null }
Trace-ObolKdc -Kdc $kdc -OutVariable events  # Press Ctrl+C when done
```

```Output
Time                 Client              Message
----                 ------              -------
4/10/2026 3:12:01 pm Udp 127.0.0.1:40213 AS-REQ user@EXAMPLE.TEST -> krbtgt/EXAMPLE.TEST@EXAMPLE.TEST: PreAuthRequired
4/10/2026 3:12:01 pm Udp 127.0.0.1:40213 AS-REQ user@EXAMPLE.TEST -> krbtgt/EXAMPLE.TEST@EXAMPLE.TEST: AS-REP, Aes256Sha1 ticket and session key, PreAuthenticated, Initial, Renewable
```

```powershell
$events.Count
$events[1].Reply.Ticket.DecryptedPart.Pac.LogonInfo
```

Shows each request as it happens while the clients run from another terminal or host, then Ctrl+C ends the trace.
Stopping the pipeline leaves the events written so far in the `-OutVariable` variable, so `$events` holds the trace for inspection afterwards.
An assignment such as `$events = Trace-ObolKdc ...` does not, the assignment never completes when the pipeline is stopped.

### Example 8: Trace some of the KDCs

```powershell
$kdc = Start-ObolKdc EXAMPLE.TEST -Principal @{ user = $null }
$other = Start-ObolKdc OTHER.TEST -Principal @{ user = $null }
$unused = Start-ObolKdc UNUSED.TEST

$events = $kdc, $other | Use-ObolKrb5Environment -ClientPrincipal user, user@OTHER.TEST {
    param ($first, $second)

    $first, $second | Trace-ObolKdc {
        kinit -k -i user@EXAMPLE.TEST
        kinit -k -i user@OTHER.TEST
    }
}
$events.Realm
```

```Output
EXAMPLE.TEST
EXAMPLE.TEST
OTHER.TEST
OTHER.TEST
```

Traces the two KDCs piped to `Trace-ObolKdc` and not the third one running in the runspace, each `kinit` is two requests as the first is answered with `PreAuthRequired`.
The `Realm` and `Kdc` properties say which KDC answered each request.

## PARAMETERS

### -Kdc

The KDCs to trace, pipe `Get-ObolKdc` to trace every KDC running in the current runspace.
A KDC that has been stopped cannot be traced.

```yaml
Type: Obol.ObolKdc[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: Named
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -ScriptBlock

The scriptblock to run.
The events of the requests made while it runs are output once it finishes, the output of the scriptblock itself is discarded.
It runs in the caller's scope like it was dot-sourced, and each traced KDC is passed as an argument so `param ($kdc)` or `$args` can be used.
If the scriptblock fails the events are output before its error.

```yaml
Type: System.Management.Automation.ScriptBlock
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: ScriptBlock
  Position: 0
  IsRequired: true
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

The KDCs to trace.

## OUTPUTS

### Obol.ObolKdcEvent

One event for each request a traced KDC answered, in the order they were processed.
A request always gets exactly one reply, a request that cannot be decoded gets a `KRB-ERROR`, so each event holds both.

- `Message`: A one line summary of the event, the default output shows it with `Time` and the transport and address of the client
- `Kdc`, `Realm`: The KDC that answered the request and its realm
- `Time`, `Duration`: The local time the request was received and how long the KDC took to process it
- `Transport`, `ClientAddress`: `Tcp` or `Udp`, and the IP address and port the client sent the request from
- `ClientName`, `ServiceName`: The client and service principals with their realm as the client sent them, the client of a TGS-REQ comes from the TGT
- `ErrorCode`: `None` if a ticket was issued, otherwise the error code of the `KRB-ERROR` sent such as `PreAuthRequired` or `ClientPrincipalUnknown`, see `[Obol.Kerberos.ErrorCode]` for the names and the RFC 4120 error codes they stand for
- `Exception`: The unexpected exception the KDC answered with a `Generic` error, such as a request that is not valid DER, otherwise `$null`
- `Key`: The long-term keys used for the request as keytab entries, see below
- `Request`: The request decoded, an `Obol.Kerberos.KdcRequest` or `TgsRequest`, or a plain `Obol.Kerberos.Message` with the bytes if it could not be decoded
- `Reply`: The reply decoded, an `Obol.Kerberos.KdcReply` with the ticket or an `Obol.Kerberos.ErrorReply`

`Request` and `Reply` hold the messages as the RFC 4120 structures, with the `Bytes` as sent and the parts the KDC decrypted or built, such as the TGT presented in a TGS-REQ, the ticket issued and the PAC, decrypted.
See [about_ObolKdcEvent](./about_ObolKdcEvent.md) for the structure.

The structure of the event and the message objects is for viewing and diagnostics, it is not a public API to build a workflow or test suite on.
Properties may be added, renamed, moved or removed in any release when a better representation is found, changes are documented in the CHANGELOG.
`ClientName`, `ServiceName`, `ErrorCode`, `Message` and `Key` are the properties to assert on.

`Message` reads `<request type> <client> -> <service>: <outcome>`.
The outcome is the reply type with the encryption types of the ticket and its session key, the ticket flags and `no PAC` if the ticket has none, or the error code with its text if any, for example `AS-REQ user@EXAMPLE.TEST -> krbtgt/EXAMPLE.TEST@EXAMPLE.TEST: AS-REP, Aes256Sha1 ticket and session key, PreAuthenticated, Initial` and `TGS-REQ -> HTTP/web.example.test@EXAMPLE.TEST: BadIntegrity: Failed to decrypt the ticket or authenticator`.
`ToString()` returns the same text.

`Key` holds the keys that decrypt every encrypted part of the request and reply: the client's key an AS-REP is encrypted with, the krbtgt key of the TGT in a TGS-REQ and the service key the ticket is encrypted with.
The other keys of an exchange, the TGT session key and the authenticator subkey, are inside the parts these decrypt.
The keys are kept with the event so the messages can be decrypted even after the principal's keys were changed with `Set-ObolPrincipal`, and can be written to a keytab with `Export-ObolKeytab -Entry` or `ConvertTo-ObolKeytab -Entry`.
They are the secrets of the test realm, treat the events as such.

## NOTES

The events are raised by the KDC before each reply is sent, so when a client call in the scriptblock returns the events of its requests have been captured.
A failed send, such as to a client that gave up waiting, is not recorded.

A reply too big for UDP is recorded with the `ResponseTooBig` error code and a TCP request too long to read with `FieldTooLong` and an empty `Request`.
A client retrying over TCP shows as a second event.

## RELATED LINKS

- [Start-ObolKdc](./Start-ObolKdc.md)
- [Get-ObolKdc](./Get-ObolKdc.md)
- [Export-ObolKeytab](./Export-ObolKeytab.md)
- [about_ObolKdcEvent](./about_ObolKdcEvent.md)
- [about_Obol](./about_Obol.md)
- [about_ObolWireshark](./about_ObolWireshark.md)
