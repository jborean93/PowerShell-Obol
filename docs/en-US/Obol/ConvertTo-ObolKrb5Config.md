---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/ConvertTo-ObolKrb5Config.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: ConvertTo-ObolKrb5Config
---

# ConvertTo-ObolKrb5Config

## SYNOPSIS

Creates a krb5.conf for Obol KDCs as a string.

## SYNTAX

### __AllParameterSets

```
ConvertTo-ObolKrb5Config [-Kdc] <ObolKdc[]> [-Provider <ObolKrb5Provider>] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Creates the content of a Kerberos configuration file (`krb5.conf`) that points clients at the realms of Obol KDCs.
The content is output as a single string with LF line endings, use `Export-ObolKrb5Config` to write it to a file.

The configuration has the realm of each KDC in `[realms]` with the address and port of the KDC, so clients do not need DNS records or port 88 to find it.
KDCs listening on all addresses (`0.0.0.0` or `::`) are written with the IPv4 or IPv6 loopback address.
Several KDCs for the same realm are listed together under that realm.

The `[libdefaults]` section sets the realm of the first KDC as `default_realm` and turns off DNS lookups of KDCs and realms and host name canonicalization (`dns_lookup_kdc`, `dns_lookup_realm`, `dns_canonicalize_hostname` and `rdns`), as test host names are usually not in DNS.
The `[domain_realm]` section maps the realm name in lowercase, and hosts under it, to the realm, such as `web.example.test` to `EXAMPLE.TEST`, so a client finds the realm of a host based service.

The content depends on the Kerberos implementation given by `-Provider`, as MIT krb5 and Heimdal choose the transport of a KDC differently.
There is no single configuration for both when a KDC listens on only one transport, a configuration for KDCs listening on both TCP and UDP works with either.

+ `Mit`: also sets `rdns = false`.
  When a KDC was started without UDP (`-Transport Tcp`) it sets `udp_preference_limit = 1`, so every request is sent over TCP first and over UDP if TCP fails, which reaches KDCs with either transport.
+ `Heimdal`: a KDC with a single transport gets a `tcp/` or `udp/` prefix on its `kdc` entry, as Heimdal does not try the other transport when one fails.
  MIT reads the prefix as part of the host name, so a configuration for Heimdal does not work with MIT when it has a KDC with a single transport.

A KDC that is not running or whose realm cannot be written in a krb5.conf, because it contains whitespace or one of `= [ ] { } # ; "`, writes an error and is left out.

The configuration only describes the KDCs, use environment variables such as `KRB5_CONFIG` to point clients at it.

## EXAMPLES

### Example 1: Show the configuration of a KDC

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST
$kdc | ConvertTo-ObolKrb5Config
```

```Output
[libdefaults]
    default_realm = EXAMPLE.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    dns_canonicalize_hostname = false
    rdns = false

[realms]
    EXAMPLE.TEST = {
        kdc = 127.0.0.1:50443
    }

[domain_realm]
    .example.test = EXAMPLE.TEST
    example.test = EXAMPLE.TEST
```

Outputs the configuration for the KDC.

### Example 2: Combine several realms

```powershell
$kdc1 = Start-ObolKdc -Realm EXAMPLE.TEST
$kdc2 = Start-ObolKdc -Realm OTHER.TEST
$config = ConvertTo-ObolKrb5Config $kdc1, $kdc2
```

Creates one configuration for both realms with `EXAMPLE.TEST` as the default realm.

### Example 3: Create a configuration for Heimdal

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST -Transport Tcp
$kdc | ConvertTo-ObolKrb5Config -Provider Heimdal
```

Creates a configuration for Heimdal clients, the `kdc` entry is `tcp/127.0.0.1:<port>` so they only use TCP.

## PARAMETERS

### -Kdc

The KDCs to add to the configuration, as output by `Start-ObolKdc` or `Get-ObolKdc`.
The realm of the first KDC is the default realm.
KDCs from the pipeline are combined into a single configuration.

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

### -Provider

The Kerberos implementation that reads the configuration:

+ `Default`: the usual implementation of the current platform, `Heimdal` on macOS and `Mit` on Linux, Windows and other platforms.
+ `Mit`: MIT krb5, used by most Linux distributions, by .NET on Linux through GSSAPI and by MIT Kerberos for Windows.
+ `Heimdal`: Heimdal, including the macOS GSS framework used by `kinit` and .NET on macOS.

`Default` is used when the parameter is not set.
The configurations only differ for KDCs started with a single transport and MIT including some extra canonicalisation options.

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutBuffer, -OutVariable, -PipelineVariable,
-ProgressAction, -Verbose, -WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### Obol.ObolKdc[]

The KDCs to add to the configuration.

## OUTPUTS

### System.String

The content of the krb5.conf.

## NOTES

The configuration only reflects the KDCs when it is created, create it again after starting a KDC on a new port.
The output does not include any keys or passwords.

## RELATED LINKS

- [Export-ObolKrb5Config](./Export-ObolKrb5Config.md)
- [Start-ObolKdc](./Start-ObolKdc.md)
- [Export-ObolKeytab](./Export-ObolKeytab.md)
- [MIT krb5.conf](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html)
- [Heimdal krb5.conf](https://github.com/heimdal/heimdal/blob/master/lib/krb5/krb5.conf.5)
