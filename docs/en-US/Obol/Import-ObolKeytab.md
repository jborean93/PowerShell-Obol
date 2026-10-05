---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/Import-ObolKeytab.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Import-ObolKeytab
---

# Import-ObolKeytab

## SYNOPSIS

Imports the entries of keytab files.

## SYNTAX

### Path (Default)

```
Import-ObolKeytab [-Path] <string[]> [<CommonParameters>]
```

### LiteralPath

```
Import-ObolKeytab -LiteralPath <string[]> [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Reads the keys in MIT keytab files (version `0x0502`), the format written by `Export-ObolKeytab`, MIT `ktutil` and `kadmin`, Heimdal, `ktpass` and `msktutil`.
Each key is output as an `ObolKeytabEntry` with the principal name, kvno, encryption type, timestamp and key value.

The entries can be passed to the `-Key` parameter of `New-ObolPrincipal` and `Set-ObolPrincipal` to give a principal the keys of the keytab, or inspected in tests, such as to check the keys a program wrote.

The `Timestamp` of an entry is shown in local time, converted from the UTC epoch seconds in the raw keytab, and `NameType` is a `PrincipalNameType`, usually `Principal` (`KRB5_NT_PRINCIPAL`).
Entries for encryption types Obol does not support, such as RC4 (23), are output with the type as a number, and so is a name type without a name.
Deleted entries are skipped and data after the 32-bit kvno of an entry, such as Heimdal extensions, is ignored.
A file that is not a valid keytab writes an error and the other files are still read.
Use `ConvertFrom-ObolKeytab` to read a keytab held in memory as bytes.
Version `0x0501` keytabs, which use the byte order of the host that wrote them, are not supported.

## EXAMPLES

### Example 1: List the entries of a keytab

```powershell
Import-ObolKeytab ./http.keytab
```

```Output
FullName                           Kvno EncryptionType Timestamp
--------                           ---- -------------- ---------
HTTP/web.example.test@EXAMPLE.TEST 2    Aes256Sha1     2/10/2026 1:00:00 am
HTTP/web.example.test@EXAMPLE.TEST 2    Aes128Sha1     2/10/2026 1:00:00 am
HTTP/web.example.test@EXAMPLE.TEST 2    23             2/10/2026 1:00:00 am
```

Lists the keys in `http.keytab`, the last one is an RC4 key Obol does not support.

### Example 2: Create a principal with the keys of a keytab

```powershell
$kdc | New-ObolPrincipal HTTP/web.example.test -Key (Import-ObolKeytab ./http.keytab)
```

Creates a principal with the keys of its entries in the keytab.

### Example 3: Check a keytab written by a program

```powershell
$entries = Import-ObolKeytab ./app.keytab
$entries | Where-Object EncryptionType -eq Aes256Sha1 | Select-Object FullName, Kvno
```

Lists the principals and kvnos of the AES256 keys in `app.keytab`.

## PARAMETERS

### -LiteralPath

The paths of the keytab files to read, used exactly as given without expanding wildcards.
Files from `Get-ChildItem` bind to this parameter through their `PSPath` property.

```yaml
Type: System.String[]
DefaultValue: ''
SupportsWildcards: false
Aliases:
- PSPath
ParameterSets:
- Name: LiteralPath
  Position: Named
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: true
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Path

The paths of the keytab files to read, wildcards are expanded.
A relative path is resolved from the current location and the path must be on the file system.

```yaml
Type: System.String[]
DefaultValue: ''
SupportsWildcards: true
Aliases: []
ParameterSets:
- Name: Path
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

### System.String[]

The paths of the keytab files to read.

## OUTPUTS

### Obol.ObolKeytabEntry

A key from a keytab.

## NOTES

The `Key` property holds the key value, anyone who can read it can act as the principal.
A keytab has no salt, use `ConvertTo-ObolSalt` to work out the salt of keys derived from a password.

## RELATED LINKS

- [ConvertFrom-ObolKeytab](./ConvertFrom-ObolKeytab.md)
- [Export-ObolKeytab](./Export-ObolKeytab.md)
- [New-ObolPrincipal](./New-ObolPrincipal.md)
- [Set-ObolPrincipal](./Set-ObolPrincipal.md)
- [MIT keytab file format](https://web.mit.edu/kerberos/krb5-latest/doc/formats/keytab_file_format.html)
- [about_Obol](./about_Obol.md)
