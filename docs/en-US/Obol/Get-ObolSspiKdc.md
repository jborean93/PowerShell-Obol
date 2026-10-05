---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/PowerShell-Obol/blob/main/docs/en-US/Obol/Get-ObolSspiKdc.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Get-ObolSspiKdc
---

# Get-ObolSspiKdc

## SYNOPSIS

Lists the KDCs Obol has pointed the Windows Kerberos SSP at, for the current thread or the whole machine.

## SYNTAX

### __AllParameterSets

```
Get-ObolSspiKdc [-Scope <ObolSspiKdcScope>] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Returns the realm to KDC entries Obol has set for the Windows Kerberos SSP.

`-Scope Thread` (the default) returns the pins the **calling thread** made with `Add-ObolSspiKdc`.
The SSP has no mechanism to read pins from LSASS, so this is Obol's own per-thread record, not the live state, and a pin only applies to the thread it was made on.

`-Scope Machine` will retrieve the machine-wide binding cache (the `klist.exe query_bind` equivalent), including entries the SSP populated itself.
This needs administrator rights and will error if run by a non-admin process.

Both return `ObolSspiKdc` objects; the `Scope` property says which kind each is, and the scope-specific properties are populated accordingly.

This cmdlet is only supported on Windows and errors on other platforms.

## EXAMPLES

### Example 1: List the current thread's pins

```powershell
PS C:\> Get-ObolSspiKdc

Scope  Realm        KdcAddress KdcName
-----  -----        ---------- -------
Thread EXAMPLE.TEST 127.0.0.1
```

Lists the pins the calling thread made.

### Example 2: Read the machine binding cache

```powershell
PS C:\> Get-ObolSspiKdc -Scope Machine

Scope   Realm        KdcAddress        KdcName
-----   -----        ----------        -------
Machine EXAMPLE.TEST dc01.example.test
```

Reads the machine-wide binding cache (run from an elevated session).

## PARAMETERS

### -Scope

Which entries to return.
`Thread` (the default) returns the calling thread's pins (no admin).
`Machine` returns a live read of the machine-wide binding cache (needs admin).

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutBuffer, -OutVariable, -PipelineVariable,
-ProgressAction, -Verbose, -WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### Obol.ObolSspiKdc

One object per entry, each a realm the Windows Kerberos SSP sends to a specific KDC instead of looking one up.
`Scope` says which kind of entry it is, which also decides the properties that are set, the others are `$null`.

All entries have the properties:

- `Scope`: `Thread` for a per-thread pin, `Machine` for a binding cache entry
- `Realm`: The realm the entry applies to
- `KdcAddress`: The host name or IP address of the KDC, the SSP always contacts it on port 88
- `DcFlags`: The DC flags `DsGetDcName` returned for an SSP-resolved KDC, or the `-DcFlags` you supplied for a hand-added one (`None` by default)
- `DiscoveryTime`: The local time the entry was made, when Obol made the pin or when the binding was added to the cache

A `Thread` entry is Obol's own record of a pin made with `Add-ObolSspiKdc` on the calling thread, as Windows has no way to read the pins back.
It only has the properties above.

A `Machine` entry is read from the binding cache in LSASS, so it includes the entries the SSP added itself.
It also has the properties below, which with `DiscoveryTime` come from the members of [KERB_BINDING_CACHE_ENTRY_DATA](https://learn.microsoft.com/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_binding_cache_entry_data):

- `KdcName`: The KDC name the SSP resolved for the realm, often empty for an entry added by hand
- `AddressType`: How `KdcAddress` is read, `Inet` (`DS_INET_ADDRESS`) for an IP address or DNS host name and `NetBios` (`DS_NETBIOS_ADDRESS`) for a NetBIOS name
- `BindingFlags`: The `Flags` member, the `DsGetDcName` request flags for locating the KDC of the realm, such as `KdcRequired` (`DS_KDC_REQUIRED`). For an entry added by `Add-ObolSspiKdc` the SSP sets them from `-DcFlags`, for example `Kdc, Writable` gives `WritableRequired, TryNextClosestSite` and `None` gives `None`
- `CacheFlags`: Flags about the entry itself rather than the KDC, the only documented one is `NoDcFlags` (`KERB_NO_DC_FLAGS`), meaning no DC flags were found for the KDC. Like `KdcName` it is expected to be set for an entry the SSP found through the DC locator, an entry added by `Add-ObolSspiKdc` has `None`

The SSP stores `DiscoveryTime` as the `GetTickCount64` value, milliseconds since boot, when the entry was cached and it is converted to a local time when read.
It is the time the SSP ages the entry out from, see [Expiry in about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md#expiry).

## NOTES

This cmdlet is only supported on Windows, it uses the Windows Kerberos SSP and errors on other platforms.

`-Scope Machine` needs administrator rights, even to read the cache.

## RELATED LINKS

- [Add-ObolSspiKdc](./Add-ObolSspiKdc.md)
- [Clear-ObolSspiKdc](./Clear-ObolSspiKdc.md)
- [about_ObolSspi](./about_ObolSspi.md)
