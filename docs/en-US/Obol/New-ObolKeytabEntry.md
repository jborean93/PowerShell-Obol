---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/New-ObolKeytabEntry.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: New-ObolKeytabEntry
---

# New-ObolKeytabEntry

## SYNOPSIS

Creates keytab entries from a password or key.

## SYNTAX

### Password (Default)

```
New-ObolKeytabEntry [-Name] <string> -Password <securestring> [-Realm <string>] [-Salt <string>]
 [-EncryptionType <EncryptionType[]>] [-Kvno <int>] [<CommonParameters>]
```

### Key

```
New-ObolKeytabEntry [-Name] <string> -Key <byte[]> -EncryptionType <EncryptionType[]>
 [-Realm <string>] [-Kvno <int>] [<CommonParameters>]
```

### Principal

```
New-ObolKeytabEntry -Principal <ObolPrincipal[]> [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Creates keytab entries for any principal, without a KDC, like MIT `ktutil addent` or Windows `ktpass`, or from the keys of a principal of an Obol KDC.
Pass the entries to `Export-ObolKeytab -Entry` to write a keytab, or to `New-ObolPrincipal -Key` to give a principal the same keys.

With `-Password` an entry is created for each encryption type, by default `Aes256Sha1` and `Aes128Sha1`, with the keys derived from the password and salt (RFC 3962 and RFC 8009 with the default iteration count).
The salt defaults to the RFC 4120 salt of the principal, the realm followed by each name component, use `ConvertTo-ObolSalt` for the salt of an AD account.
The keys only match the keys of an existing account if the salt and kvno are the ones the account has.

With `-Key` a single entry is created with the key as it is, the key must be the size of the encryption type.

With `-Principal` the entries of principals of an Obol KDC are created, an entry for each of their current keys under their name and each of their aliases, the same entries `Export-ObolKeytab -Principal` writes.
Filter them with `Where-Object` before passing them to `Export-ObolKeytab` or `ConvertTo-ObolKeytab` to write only some of the keys or names.

The entries have the name type `KRB5_NT_PRINCIPAL` (1) and the current time as their timestamp.

## EXAMPLES

### Example 1: Create a keytab for a user

```powershell
$password = Read-Host -AsSecureString -Prompt Password
New-ObolKeytabEntry user@EXAMPLE.TEST -Password $password | Export-ObolKeytab ./user.keytab
```

Writes the AES256 and AES128 keys of `user@EXAMPLE.TEST` for the password to `user.keytab`, which works with any KDC that has the same password for the user with the default salt and kvno 1.

### Example 2: Create a keytab for an AD service account

```powershell
$salt = ConvertTo-ObolSalt svc_web -Realm CORP.EXAMPLE -SaltType ADUser
$params = @{
    Password = $password
    Salt = $salt
    Kvno = 3
}
@(
    New-ObolKeytabEntry HTTP/web.corp.example@CORP.EXAMPLE @params
    New-ObolKeytabEntry HTTP/web@CORP.EXAMPLE @params
) | Export-ObolKeytab ./http.keytab
```

Writes the keys of the AD account `svc_web` under two of its service principal names.
The kvno must be the `msDS-KeyVersionNumber` of the account.

### Example 3: Export only some keys of a principal

```powershell
$kdc |
    Get-ObolPrincipal HTTP/web.example.test |
    New-ObolKeytabEntry |
    Where-Object { $_.EncryptionType -eq 'Aes256Sha1' -and $_.Name -eq 'HTTP/web.example.test' } |
    Export-ObolKeytab ./http.keytab
```

Writes only the AES256 key of the principal under its own name, leaving out its other keys and aliases.

### Example 4: Create an entry from a key

```powershell
$key = [Convert]::FromHexString('ab8c3a5300b091e044f72526e1669fa999e4cb152042325df4f4864ffdf38e5c')
New-ObolKeytabEntry host/web -Realm EXAMPLE.TEST -Key $key -EncryptionType Aes256Sha1 -Kvno 2
```

Creates an entry with a known AES256 key.

## PARAMETERS

### -EncryptionType

The encryption types of the entries.
With `-Password` an entry is created for each type in the order given, `Aes256Sha1, Aes128Sha1` if not set.
With `-Key` it must be a single type that matches the size of the key.
The supported values are `Aes128Sha1`, `Aes256Sha1`, `Aes128Sha256` and `Aes256Sha384`.

```yaml
Type: Obol.Kerberos.EncryptionType[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Password
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
- Name: Key
  Position: Named
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Key

The key of the entry, 16 bytes for `Aes128Sha1` and `Aes128Sha256` or 32 bytes for `Aes256Sha1` and `Aes256Sha384`.
The value is copied, changing the array afterwards does not change the entry.

```yaml
Type: System.Byte[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Key
  Position: Named
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Kvno

The key version number of the entries, defaults to 1.
A service only accepts tickets whose kvno matches its keytab, use the kvno the account has in the KDC.

```yaml
Type: System.Int32
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Password
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
- Name: Key
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Name

The principal name of the entries, such as `user@EXAMPLE.TEST` or `HTTP/web.example.test`.
The realm is taken from after `@` or from `-Realm`.
A `\` escapes the next character like in other principal names.

```yaml
Type: System.String
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Password
  Position: 0
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
- Name: Key
  Position: 0
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Password

The password to derive the keys from, it must not be empty.

```yaml
Type: System.Security.SecureString
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Password
  Position: Named
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Principal

The principals to create the entries of, as output by `New-ObolPrincipal` or `Get-ObolPrincipal`.
Each principal gets an entry for each of its current keys under its name and each of its aliases, with its current kvno.

```yaml
Type: Obol.ObolPrincipal[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Principal
  Position: Named
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Realm

The realm of the principal for a name without `@REALM`, it must match the realm of a name that has one.

```yaml
Type: System.String
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Password
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
- Name: Key
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Salt

The salt to derive the keys with, the RFC 4120 salt of the principal if not set.
Use `ConvertTo-ObolSalt -SaltType ADUser` or `ADComputer` for the salt of an AD account, which is the same for all its service principal names.
The salt must match the one the KDC principal's keys were derived with, see [KEYS AND SALTS in about_Obol](./about_Obol.md#keys-and-salts).

```yaml
Type: System.String
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Password
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

### Obol.ObolPrincipal[]

The principals to create the entries of.

## OUTPUTS

### Obol.ObolKeytabEntry

A keytab entry for each encryption type.

## NOTES

The `Key` property holds the key value, anyone who can read it can act as the principal.
Keys derived with a non-default iteration count (`s2kparams`) are not supported.

## RELATED LINKS

- [Export-ObolKeytab](./Export-ObolKeytab.md)
- [Import-ObolKeytab](./Import-ObolKeytab.md)
- [ConvertTo-ObolSalt](./ConvertTo-ObolSalt.md)
- [New-ObolPrincipal](./New-ObolPrincipal.md)
- [about_Obol](./about_Obol.md)
