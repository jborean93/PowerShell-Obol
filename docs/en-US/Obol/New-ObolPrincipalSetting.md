---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/New-ObolPrincipalSetting.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: New-ObolPrincipalSetting
---

# New-ObolPrincipalSetting

## SYNOPSIS

Creates the settings for a principal to create with `Start-ObolKdc -Principal` or `New-ObolPrincipal -Setting`.

## SYNTAX

### __AllParameterSets

```
New-ObolPrincipalSetting [-Password <securestring>] [-Flag <ObolPrincipalFlag>]
 [-EncryptionType <ObolEncryptionType[]>] [-Alias <string[]>] [-Rid <int>] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Creates an `ObolPrincipalSetting` object with the settings of a principal, the same values as the parameters of `New-ObolPrincipal`.
The object is used as a value of `Start-ObolKdc -Principal` or with `New-ObolPrincipal -Setting` so the same settings can be used to create principals in several places.

The settings are not checked until the principal is created, such as an alias in a different realm or a RID that is already used.
A setting not set uses the default of `New-ObolPrincipal`.

## EXAMPLES

### Example 1: Start a KDC with principals from settings

```powershell
PS C:\> $password = Read-Host -AsSecureString -Prompt Password
PS C:\> $user = New-ObolPrincipalSetting -Password $password
PS C:\> $service = New-ObolPrincipalSetting -Alias HTTP/web -EncryptionType Aes256Sha1
PS C:\> Start-ObolKdc -Realm EXAMPLE.TEST -Principal ([ordered]@{
    user = $user
    'HTTP/web.example.test' = $service
})
```

Starts a KDC with the user `user` and the service `HTTP/web.example.test` that also has the name `HTTP/web` and only an AES256 key.

### Example 2: Create principals with the same settings

```powershell
PS C:\> $setting = New-ObolPrincipalSetting -EncryptionType Aes256Sha384, Aes128Sha256
PS C:\> 'HTTP/web1.example.test', 'HTTP/web2.example.test' | ForEach-Object {
    $kdc | New-ObolPrincipal $_ -Setting $setting
}
```

Creates two service principals that only have AES SHA-2 keys.

## PARAMETERS

### -Alias

Other names the KDC finds the principal by, see `New-ObolPrincipal -Alias`.

```yaml
Type: System.String[]
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

### -EncryptionType

The encryption types to create keys for, in order of preference, defaults to `Aes256Sha1, Aes128Sha1`.
See [ENCRYPTION TYPES in about_Obol](./about_Obol.md#encryption-types) for each type and how the order is used.

```yaml
Type: Obol.ObolEncryptionType[]
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
AcceptedValues:
- Aes128Sha1
- Aes256Sha1
- Aes128Sha256
- Aes256Sha384
HelpMessage: ''
```

### -Flag

Options to turn on for the principal, defaults to `None`.
See [PRINCIPAL FLAGS in about_Obol](./about_Obol.md#principal-flags) for the values and what each one does.

```yaml
Type: Obol.ObolPrincipalFlag
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
AcceptedValues:
- None
- DoesNotRequirePreAuth
- NotDelegated
- TrustedForDelegation
HelpMessage: ''
```

### -Password

The password to derive the principal's keys from, it must not be empty.
Without a password the principal gets random keys.

```yaml
Type: System.Security.SecureString
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

### -Rid

The relative identifier (RID) of the principal, see `New-ObolPrincipal -Rid`.
Without a RID the principal gets the next RID from 1000 that is not used.

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutBuffer, -OutVariable, -PipelineVariable,
-ProgressAction, -Verbose, -WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### Obol.ObolPrincipalSetting

The settings of a principal with the properties `Password`, `Flag`, `EncryptionType`, `Alias` and `Rid`.
The properties can be changed after the object is created.

## NOTES

The object does not create a principal by itself, the principal is created by `Start-ObolKdc -Principal` or `New-ObolPrincipal -Setting`.

## RELATED LINKS

- [New-ObolPrincipal](./New-ObolPrincipal.md)
- [Start-ObolKdc](./Start-ObolKdc.md)
