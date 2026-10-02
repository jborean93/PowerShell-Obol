---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/ConvertFrom-ObolKeytab.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: ConvertFrom-ObolKeytab
---

# ConvertFrom-ObolKeytab

## SYNOPSIS

Converts the bytes of a keytab to keytab entries.

## SYNTAX

### __AllParameterSets

```
ConvertFrom-ObolKeytab [-InputObject] <byte[]> [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Reads a keytab held in memory, such as the output of `ConvertTo-ObolKeytab` or a keytab decoded from base64, and outputs an `ObolKeytabEntry` for each key, like `Import-ObolKeytab` does for a file.
The entries can be passed to the `-Key` parameter of `New-ObolPrincipal` and `Set-ObolPrincipal`, to `Export-ObolKeytab -Entry`, or inspected in tests.

All input is joined and read as a single keytab once it has all been received.
A byte array in a variable is sent through the pipeline one byte at a time, joining the input lets `$keytab | ConvertFrom-ObolKeytab` work like `ConvertFrom-ObolKeytab $keytab`.
Call the cmdlet once for each keytab to read several keytabs.

The data must be a keytab of version `0x0502`, data that is not a valid keytab writes an error and outputs nothing.

## EXAMPLES

### Example 1: Read the keytab of a principal without a file

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST
$service = $kdc | New-ObolPrincipal HTTP/web.example.test
ConvertTo-ObolKeytab $service | ConvertFrom-ObolKeytab
```

```Output
FullName                           Kvno EncryptionType Timestamp
--------                           ---- -------------- ---------
HTTP/web.example.test@EXAMPLE.TEST 1    Aes256Sha1     2/10/2026 1:00:00 am
HTTP/web.example.test@EXAMPLE.TEST 1    Aes128Sha1     2/10/2026 1:00:00 am
```

Lists the keytab entries of the service principal without writing the keytab to disk.

### Example 2: Create a principal from a base64 keytab

```powershell
$keytab = [Convert]::FromBase64String($env:SERVICE_KEYTAB)
$kdc | New-ObolPrincipal HTTP/web.example.test -Key (ConvertFrom-ObolKeytab $keytab)
```

Gives a principal the keys of a keytab passed as base64 text in an environment variable.

## PARAMETERS

### -InputObject

The bytes of the keytab, such as the output of `ConvertTo-ObolKeytab`.
Input from the pipeline is joined into a single keytab.

```yaml
Type: System.Byte[]
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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutBuffer, -OutVariable, -PipelineVariable,
-ProgressAction, -Verbose, -WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.Byte[]

The bytes of the keytab, joined into a single keytab.

## OUTPUTS

### Obol.ObolKeytabEntry

A key from the keytab.

## NOTES

The `Key` property of each entry holds the key value, anyone who can read it can act as the principal.
Entries for encryption types Obol does not support, such as RC4 (23), are output with the type as a number.

## RELATED LINKS

- [ConvertTo-ObolKeytab](./ConvertTo-ObolKeytab.md)
- [Import-ObolKeytab](./Import-ObolKeytab.md)
- [Export-ObolKeytab](./Export-ObolKeytab.md)
- [MIT keytab file format](https://web.mit.edu/kerberos/krb5-latest/doc/formats/keytab_file_format.html)
