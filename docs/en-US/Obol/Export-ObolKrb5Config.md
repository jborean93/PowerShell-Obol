---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/PowerShell-Obol/blob/main/docs/en-US/Obol/Export-ObolKrb5Config.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Export-ObolKrb5Config
---

# Export-ObolKrb5Config

## SYNOPSIS

Writes a krb5.conf for Obol KDCs to a file.

## SYNTAX

### __AllParameterSets

```
Export-ObolKrb5Config [-Path] <string> -Kdc <ObolKdc[]> [-Force] [-Provider <ObolKrb5Provider>]
 [-WhatIf] [-Confirm] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Writes a Kerberos configuration file (`krb5.conf`) that points clients at the realms of Obol KDCs.
The file has the same content as the output of `ConvertTo-ObolKrb5Config`, encoded as UTF-8 without a BOM and with LF line endings.
The file is written once all KDCs have been read from the pipeline, nothing is written if no KDC can be used.

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

The configuration only describes the KDCs, use environment variables such as `KRB5_CONFIG` to point clients at it, or use `Enter-ObolKrb5Environment` to write the file and set the variables in one step.

## EXAMPLES

### Example 1: Use a KDC with MIT or Heimdal clients

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST -Principal @{
    user = ConvertTo-SecureString -AsPlainText -Force 'Password123!'
    'HTTP/web.example.test' = $null
}
$kdc | Export-ObolKrb5Config ./krb5.conf
$env:KRB5_CONFIG = (Resolve-Path ./krb5.conf).Path
$env:KRB5CCNAME = "FILE:$(Join-Path $PWD ccache)"
'Password123!' | kinit user
kvno HTTP/web.example.test
```

Writes the configuration for the KDC and uses it with `kinit` and `kvno` in the current process and its child processes.

### Example 2: Replace an existing file

```powershell
Get-ObolKdc | Export-ObolKrb5Config ./krb5.conf -Force
```

Writes the configuration for every KDC running in the session, replacing the file if it exists.

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

### -Force

Replaces the file if it exists, without this the cmdlet fails when the file exists.

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

### -Kdc

The KDCs to add to the configuration, as output by `Start-ObolKdc` or `Get-ObolKdc`.
The realm of the first KDC is the default realm.
KDCs from the pipeline are combined into a single file.

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

### -Path

The path of the krb5.conf file to write.
A relative path is resolved from the current location and the path must be on the file system.

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

The KDCs to add to the configuration.

## OUTPUTS

## NOTES

The file only reflects the KDCs when it is written, write it again after starting a KDC on a new port.
The file does not include any keys or passwords.

## RELATED LINKS

- [ConvertTo-ObolKrb5Config](./ConvertTo-ObolKrb5Config.md)
- [Enter-ObolKrb5Environment](./Enter-ObolKrb5Environment.md)
- [Start-ObolKdc](./Start-ObolKdc.md)
- [Export-ObolKeytab](./Export-ObolKeytab.md)
- [MIT krb5.conf](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html)
- [Heimdal krb5.conf](https://github.com/heimdal/heimdal/blob/master/lib/krb5/krb5.conf.5)
