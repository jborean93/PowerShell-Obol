---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/ConvertTo-ObolKeytab.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: ConvertTo-ObolKeytab
---

# ConvertTo-ObolKeytab

## SYNOPSIS

Converts the keys of principals or keytab entries to the bytes of a keytab.

## SYNTAX

### Principal (Default)

```
ConvertTo-ObolKeytab [-Principal] <ObolPrincipal[]> [<CommonParameters>]
```

### Name

```
ConvertTo-ObolKeytab [-Name] <string[]> -Kdc <ObolKdc> [<CommonParameters>]
```

### Entry

```
ConvertTo-ObolKeytab -Entry <ObolKeytabEntry[]> [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Creates a keytab in memory and outputs it as a single byte array, for keys that should not be written to disk.
It takes the same input as `Export-ObolKeytab`, principals of an Obol KDC by object or by name, or keytab entries from `Import-ObolKeytab` or `New-ObolKeytabEntry`, and the bytes are the same as the file `Export-ObolKeytab` writes.

Use `ConvertFrom-ObolKeytab` to read the bytes back as keytab entries.
Use the bytes with an API that takes a keytab in memory, such as the Kerberos.NET `KeyTable` class or a Windows SSPI Kerberos credential with the `SEC_WINNT_AUTH_DATA_TYPE_KEYTAB` packed credential type.

The keytab is output once all input has been read from the pipeline.
Nothing is output if no principal or entry was given.

## EXAMPLES

### Example 1: Get the keytab of a service as bytes

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST
$service = $kdc | New-ObolPrincipal HTTP/web.example.test
$keytab = ConvertTo-ObolKeytab $service
```

Creates the keytab of the service principal in memory.

### Example 2: Get the keytab of some keys only

```powershell
$keytab = $kdc |
    Get-ObolPrincipal HTTP/web.example.test |
    New-ObolKeytabEntry |
    Where-Object EncryptionType -eq Aes256Sha1 |
    ConvertTo-ObolKeytab
```

Creates a keytab with only the AES256 keys of the principal.

### Example 3: Encode a keytab for an environment variable

```powershell
$env:SERVICE_KEYTAB = [Convert]::ToBase64String((ConvertTo-ObolKeytab $service))
```

Passes the keytab to a child process as base64 text, such as a test service that reads its keytab from the environment.

## PARAMETERS

### -Entry

Keytab entries to add, as output by `Import-ObolKeytab` or `New-ObolKeytabEntry`.
The entries are added as they are, with their name type, timestamp and kvno, including keys of encryption types Obol does not support and repeated entries.

```yaml
Type: Obol.ObolKeytabEntry[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Entry
  Position: Named
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Kdc

The KDC to find the principals named by `-Name` in, as output by `Start-ObolKdc` or `Get-ObolKdc`.

```yaml
Type: Obol.ObolKdc
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Name
  Position: Named
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Name

The names or aliases of the principals to add from the KDC given by `-Kdc`, such as `user` or `HTTP/web.example.test`.
The KDC realm can be added after `@`.
Names are matched like the KDC matches them in requests and wildcards are not supported, use `Get-ObolPrincipal` to add principals matching a pattern.
A name that matches no principal writes an error, the other principals are still added.

```yaml
Type: System.String[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Name
  Position: 0
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Principal

The principals to add, as output by `New-ObolPrincipal` or `Get-ObolPrincipal`.
Each principal gets an entry for each of its current keys under its name and each of its aliases, a principal given more than once is only added once.

```yaml
Type: Obol.ObolPrincipal[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Principal
  Position: 0
  IsRequired: true
  ValueFromPipeline: true
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

### Obol.ObolPrincipal[]

The principals to add.

### Obol.ObolKdc

The KDC to find the principals named by `-Name` in.

### Obol.ObolKeytabEntry[]

The keytab entries to add.

## OUTPUTS

### System.Byte[]

The keytab, a single array of the MIT keytab format (version `0x0502`).

## NOTES

The bytes hold the keys of the principals in plain text, anyone who can read them can act as those principals.
Clear the array with `[Array]::Clear($keytab)` once it is no longer needed.

## RELATED LINKS

- [ConvertFrom-ObolKeytab](./ConvertFrom-ObolKeytab.md)
- [Export-ObolKeytab](./Export-ObolKeytab.md)
- [Import-ObolKeytab](./Import-ObolKeytab.md)
- [New-ObolKeytabEntry](./New-ObolKeytabEntry.md)
- [MIT keytab file format](https://web.mit.edu/kerberos/krb5-latest/doc/formats/keytab_file_format.html)
