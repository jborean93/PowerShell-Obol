---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/Set-ObolPrincipal.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Set-ObolPrincipal
---

# Set-ObolPrincipal

## SYNOPSIS

Changes principals of an Obol KDC.

## SYNTAX

### Principal (Default)

```
Set-ObolPrincipal [-Principal] <ObolPrincipal[]> [-Password <securestring>] [-NewRandomKey]
 [-EncryptionType <ObolEncryptionType[]>] [-Flag <ObolPrincipalFlag>] [-Alias <string[]>]
 [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### Name

```
Set-ObolPrincipal [-Name] <string[]> -Kdc <ObolKdc> [-Password <securestring>] [-NewRandomKey]
 [-EncryptionType <ObolEncryptionType[]>] [-Flag <ObolPrincipalFlag>] [-Alias <string[]>]
 [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Changes the keys, encryption types, flags or aliases of principals created by `New-ObolPrincipal` or the KDC.
Only the values of the parameters that are set change.
The change applies to the next request the KDC processes, tickets already issued are not affected.

The principals are given as objects from `New-ObolPrincipal` or `Get-ObolPrincipal`, or by name or alias with `-Kdc` and `-Name`.

`-Password` or `-NewRandomKey`, which cannot be used together, replaces the principal's keys and increases its key version number (`Kvno`) by one.
Like a password change in AD or MIT, tickets for a service that were encrypted with its old keys can no longer be decrypted with the new keys.
New keys for the `krbtgt` principal make every TGT already issued by the KDC unusable.

The `krbtgt` principal cannot have aliases.

## EXAMPLES

### Example 1: Change a password

```powershell
PS C:\> $password = Read-Host -AsSecureString -Prompt Password
PS C:\> $kdc | Set-ObolPrincipal user -Password $password
```

Sets a new password for `user`, its keys are derived from the new password with the next key version number.

### Example 2: Create new keys for a service

```powershell
PS C:\> $service | Set-ObolPrincipal -NewRandomKey -PassThru
```

Creates new random keys for the service and outputs the principal with its new `Kvno`.

### Example 3: Limit a service to AES128

```powershell
PS C:\> Set-ObolPrincipal $service -EncryptionType Aes128Sha1
```

Removes every key but the AES128 key, tickets for the service and their session keys use AES128 from then on.

### Example 4: Allow a user to get a ticket without pre-authentication

```powershell
PS C:\> Set-ObolPrincipal $user -Flag DoesNotRequirePreAuth
```

The KDC issues a ticket to the user without pre-authentication until the flags are set back to `None`.

## PARAMETERS

### -Alias

Replaces the aliases of the principal, use an empty array to remove every alias.
Each alias follows the same rules as the `-Name` of `New-ObolPrincipal` and must not be the name or alias of another principal.

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

### -EncryptionType

The encryption types the principal has keys for, in order of preference, see [ENCRYPTION TYPES in about_Obol](./about_Obol.md#encryption-types) for each type and how the order is used.

Without `-Password` or `-NewRandomKey` only types the principal already has keys for can be used, as the password is not stored to derive keys for other types.
The kept keys do not change and the key version number stays the same.
With `-Password` or `-NewRandomKey` the new keys are created for these types.

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

The options of the principal, see [PRINCIPAL FLAGS in about_Obol](./about_Obol.md#principal-flags) for the values and what each one does.
The flags replace the existing flags, use `None` to turn every option off.
To change one flag combine it with the current flags, such as `-Flag ($principal.Flag -bor 'DoesNotRequirePreAuth')`.

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

The names or aliases of the principals to change in the KDC given by `-Kdc`, such as `user` or `HTTP/web.example.test`.
The KDC realm can be added after `@`.
Names are matched like the KDC matches them in requests, case sensitively unless the KDC was started with `-CaseInsensitivePrincipal`, and wildcards are not supported.
A name that matches no principal writes an error.

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

### -NewRandomKey

Replaces the principal's keys with new random keys and increases the key version number.

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

### -PassThru

Outputs the principal after it is changed.

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

### -Password

A new password to derive the principal's keys from, it must not be empty.
The key version number increases.

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

### -Principal

The principals to change, as output by `New-ObolPrincipal` or `Get-ObolPrincipal`.

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

### Obol.ObolPrincipal[]

The principals to change.

### Obol.ObolKdc

The KDC to find the principals named by `-Name` in.

## OUTPUTS

### Obol.ObolPrincipal

The changed principal when `-PassThru` is set.

## NOTES

The principal objects already output reflect the change, there is no need to get them again.

## RELATED LINKS

- [New-ObolPrincipal](./New-ObolPrincipal.md)
- [Get-ObolPrincipal](./Get-ObolPrincipal.md)
- [Remove-ObolPrincipal](./Remove-ObolPrincipal.md)
