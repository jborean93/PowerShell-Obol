---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/New-ObolPrincipal.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: New-ObolPrincipal
---

# New-ObolPrincipal

## SYNOPSIS

Creates a principal in the realm of an Obol KDC.

## SYNTAX

### Setting

```
New-ObolPrincipal [-Name] <string> -Kdc <ObolKdc> -Setting <ObolPrincipalSetting> [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

### Random (Default)

```
New-ObolPrincipal [-Name] <string> -Kdc <ObolKdc> [-Flag <ObolPrincipalFlag>]
 [-EncryptionType <ObolEncryptionType[]>] [-Alias <string[]>] [-Rid <int>] [-Kvno <int>] [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

### Password

```
New-ObolPrincipal [-Name] <string> -Kdc <ObolKdc> -Password <securestring>
 [-Flag <ObolPrincipalFlag>] [-EncryptionType <ObolEncryptionType[]>] [-Alias <string[]>]
 [-Rid <int>] [-Kvno <int>] [-Salt <string>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### Key

```
New-ObolPrincipal [-Name] <string> -Kdc <ObolKdc> -Key <ObolKeytabEntry[]>
 [-Flag <ObolPrincipalFlag>] [-Alias <string[]>] [-Rid <int>] [-Kvno <int>] [-Salt <string>]
 [-WhatIf] [-Confirm] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Creates a user or service principal in the realm of a KDC started by `Start-ObolKdc`.
The KDC can issue tickets for and to the principal straight away.

Obol has a single principal type like an MIT KDC, any principal can authenticate as a client and receive service tickets.
Use `-Password` for a principal that authenticates with a password, such as a user.
Without `-Password` the principal gets random keys, which suits a service principal.

By default each principal gets AES256 and AES128 keys (`aes256-cts-hmac-sha1-96` and `aes128-cts-hmac-sha1-96`) like AD and MIT, use `-EncryptionType` for other types.
The keys have key version number 1 unless `-Kvno` is set and RC4 is not supported.
Keys from a password use the default salt from RFC 4120, the realm followed by each name component, such as `EXAMPLE.TESTuser`, unless `-Salt` is set.

Use `-Key` to give the principal the keys of an existing keytab instead, the principal gets the kvno and encryption types of those keys.

A principal can have aliases, other names the KDC finds it by, like the service principal names of an AD account.
A ticket for an alias has the alias as its service name and is encrypted with the principal's key.

Pre-authentication with an encrypted timestamp is required unless `-Flag DoesNotRequirePreAuth` is set.

Tickets include a PAC with a SID for the principal and the Domain Users group (RID 513) as its primary group.
The SIDs are based on the `DomainSid` of the KDC and each principal gets the next RID, starting at 1000, unless `-Rid` is set.

## EXAMPLES

### Example 1: Create a user with a password

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST
$password = Read-Host -AsSecureString -Prompt Password
New-ObolPrincipal -Kdc $kdc -Name user -Password $password
```

Creates the principal `user@EXAMPLE.TEST` that authenticates with the password entered.

### Example 2: Create a service principal

```powershell
$kdc | New-ObolPrincipal HTTP/web.example.test
```

Creates the principal `HTTP/web.example.test@EXAMPLE.TEST` with random keys.

### Example 3: Create a user that does not require pre-authentication

```powershell
New-ObolPrincipal -Kdc $kdc -Name roast -Password $password -Flag DoesNotRequirePreAuth
```

Creates a user the KDC issues a ticket to without pre-authentication, for example to test the detection of AS-REP roasting.

### Example 4: Create a service with several names

```powershell
$kdc | New-ObolPrincipal HTTP/web.example.test -Alias HTTP/web, HTTP/www.example.test
```

Creates a service principal the KDC also issues tickets for under the names `HTTP/web` and `HTTP/www.example.test`.

### Example 5: Create a service with the keys of an existing keytab

```powershell
$kdc | New-ObolPrincipal HTTP/web.example.test -Key (Import-ObolKeytab ./http.keytab)
```

Creates a service principal with the keys and kvno of its entries in `http.keytab`, so a service using that keytab can decrypt the tickets the KDC issues for it.

### Example 6: Create a principal with the keys of an AD account

```powershell
$kdc = Start-ObolKdc -Realm CORP.EXAMPLE
$salt = ConvertTo-ObolSalt svc_web -Realm CORP.EXAMPLE -SaltType ADUser
$kdc | New-ObolPrincipal HTTP/web.corp.example -Password $password -Salt $salt
```

Creates a service principal with the keys the AD account `svc_web` has for the same password, so a keytab made for the account with `ktpass` works with tickets from the KDC.

### Example 7: Create a service with AES SHA-2 keys only

```powershell
$kdc | New-ObolPrincipal HTTP/web.example.test -EncryptionType Aes256Sha384, Aes128Sha256
```

Creates a service principal with only RFC 8009 keys, the service tickets and their session keys use these types.

### Example 6: Create a principal with a specific RID

```powershell
$kdc | New-ObolPrincipal Administrator -Password $password -Rid 500
```

Creates the principal `Administrator@EXAMPLE.TEST` with the SID of the built-in Administrator account, the `DomainSid` of the KDC followed by `500`.

### Example 7: Create a principal from settings

```powershell
$setting = New-ObolPrincipalSetting -Password $password -Flag DoesNotRequirePreAuth
$kdc | New-ObolPrincipal roast -Setting $setting
```

Creates the principal `roast@EXAMPLE.TEST` with the settings from `New-ObolPrincipalSetting`, the same settings can be used for other principals or with `Start-ObolKdc -Principal`.

## PARAMETERS

### -Alias

Other names the KDC finds the principal by, such as further service principal names.
Each alias follows the same rules as `-Name` and must not be the name or alias of another principal.

An alias also works as a client name, like the account name and UPN of an AD account are other names for it.
For example `HTTP/web.example.test` with the alias `web` and a password can authenticate as `web@EXAMPLE.TEST`.
Keys derived from a password always use the salt of the principal's name, the KDC sends it to the client in PA-ETYPE-INFO2.

```yaml
Type: System.String[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Random
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
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

The encryption types to create keys for, in order of preference, defaults to `Aes256Sha1, Aes128Sha1`.
The values are `Aes128Sha1`, `Aes256Sha1`, `Aes128Sha256` and `Aes256Sha384`, see [ENCRYPTION TYPES in about_Obol](./about_Obol.md#encryption-types) for each type and how the order is used.

```yaml
Type: Obol.ObolEncryptionType[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Random
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
- Name: Password
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
The values are `None`, `DoesNotRequirePreAuth`, `NotDelegated`, `TrustedForDelegation` and `NoAuthDataRequired`, see [PRINCIPAL FLAGS in about_Obol](./about_Obol.md#principal-flags) for what each one does.

```yaml
Type: Obol.ObolPrincipalFlag
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Random
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
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
AcceptedValues:
- None
- DoesNotRequirePreAuth
- NotDelegated
- TrustedForDelegation
- NoAuthDataRequired
HelpMessage: ''
```

### -Kdc

The KDC to create the principal in, as output by `Start-ObolKdc` or `Get-ObolKdc`.
The principal is created in every KDC passed through the pipeline.

```yaml
Type: Obol.ObolKdc
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

### -Key

Keytab entries to take the principal's keys and kvno from instead of a password, as output by `Import-ObolKeytab` or `ConvertFrom-ObolKeytab`.
Only the entries for the principal name or one of its aliases are used, entries that cannot be used write a warning.
See [KEYS FROM A KEYTAB in about_Obol](./about_Obol.md#keys-from-a-keytab) for how the keys are chosen.
Cannot be used with `-Password` or `-EncryptionType`, filter the entries with `Where-Object` to choose the encryption types.

```yaml
Type: Obol.ObolKeytabEntry[]
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

The key version number of the principal, 1 if not set.
Set it to the kvno an account has in another KDC, such as the `msDS-KeyVersionNumber` of an AD account, so a keytab made there for the same keys works with tickets from the KDC.

With `-Key` the keys are taken from the entries with this kvno, the newest kvno of the entries if not set, see [KEYS FROM A KEYTAB in about_Obol](./about_Obol.md#keys-from-a-keytab).

```yaml
Type: System.Int32
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Random
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
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

The principal name, such as `user` or `HTTP/web.example.test`.
Name components are separated by `/` and the KDC realm can be added after `@`, such as `user@EXAMPLE.TEST`.
A realm that does not match the KDC realm is an error.

Like MIT, a `\` escapes the next character so a component can contain `/`, `@` or `\`, such as `HTTP\/web` for the single component `HTTP/web`.
The escapes `\n`, `\t`, `\b` and `\0` are a newline, tab, backspace and null character.
The `Name` of the principal shows these characters escaped the same way.
Names are case sensitive unless the KDC was started with `-CaseInsensitivePrincipal`.
The `krbtgt/<realm>` principal is created by the KDC and cannot be created again.

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

### -Password

The password to derive the principal's keys from, it must not be empty.
The password is not stored, only the keys derived from it.
Without a password the principal gets random keys.

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

### -Rid

The relative identifier (RID) of the principal, its SID is the `DomainSid` of the KDC followed by the RID.
Without a RID the principal gets the next RID from 1000 that is not used, RIDs are not reused after a principal is removed.

Use it to match the SID of an existing account, such as `500` for the built-in Administrator account of a domain.
The RID must not be used by another principal, the `krbtgt/<realm>` principal has the RID `502`.

```yaml
Type: System.Int32
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Random
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
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

The salt the keys were derived with, sent to clients that log in with the password, the RFC 4120 salt of the principal if not set.
It only needs to be set to match keys derived somewhere else, such as an AD account, see [KEYS AND SALTS in about_Obol](./about_Obol.md#keys-and-salts) and `ConvertTo-ObolSalt`.
Can only be used with `-Password` or `-Key`.

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

### -Setting

The settings of the principal from `New-ObolPrincipalSetting`, or a hashtable of its properties, instead of the individual parameters.
Use it to create several principals with the same settings.

```yaml
Type: Obol.ObolPrincipalSetting
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Setting
  Position: Named
  IsRequired: true
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

### Obol.ObolKdc

The KDC to create the principal in.

## OUTPUTS

### Obol.ObolPrincipal

The principal that was created.
It has the properties:

- `Name`: The principal name without the realm, with `/`, `@` and `\` in a component escaped with `\`
- `Realm`: The realm of the principal
- `FullName`: The principal name with the realm, such as `user@EXAMPLE.TEST`
- `Alias`: Other names the KDC finds the principal by
- `Kvno`: The key version number, it increases each time `Set-ObolPrincipal` sets new keys
- `EncryptionType`: The encryption types the principal has keys for, in order of preference
- `Flag`: The options turned on for the principal, such as `DoesNotRequirePreAuth`
- `Sid`: The SID of the principal used in the PAC

The object reflects changes made later with `Set-ObolPrincipal`.

## NOTES

A client can send the principal name as a single component with a realm suffix, such as the enterprise name `user@example.test` sent by Windows.
The KDC strips a suffix that matches its realm, ignoring case, and looks up the rest of the name.

## RELATED LINKS

- [Get-ObolPrincipal](./Get-ObolPrincipal.md)
- [New-ObolPrincipalSetting](./New-ObolPrincipalSetting.md)
- [Set-ObolPrincipal](./Set-ObolPrincipal.md)
- [Remove-ObolPrincipal](./Remove-ObolPrincipal.md)
- [Start-ObolKdc](./Start-ObolKdc.md)
- [about_Obol](./about_Obol.md)
