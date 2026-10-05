---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/PowerShell-Obol/blob/main/docs/en-US/Obol/ConvertTo-ObolSalt.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: ConvertTo-ObolSalt
---

# ConvertTo-ObolSalt

## SYNOPSIS

Converts a principal or account name to the salt its keys are derived from a password with.

## SYNTAX

### __AllParameterSets

```
ConvertTo-ObolSalt [-Name] <string> [-Realm <string>] [-SaltType <ObolSaltType>]
 [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Gets the salt a Kerberos implementation combines with a password to derive the AES keys of a principal (RFC 3962).
The keys of the same password are only the same with the same salt, so the salt is needed to get the keys an account has in another KDC.
Use this with the salt to the `-Salt` parameter of `New-ObolPrincipal`, `Set-ObolPrincipal` or `New-ObolKeytabEntry`.

`-SaltType` decides how the name and realm are combined:

+ `Default`: the RFC 4120 salt used by MIT, Heimdal and Obol, the realm followed by each name component without separators, such as `EXAMPLE.TESTHTTPweb.example.test` for `HTTP/web.example.test@EXAMPLE.TEST`.
  The name is a principal name and can include its realm after `@`.
+ `ADUser`: the salt of an AD user or service account (MS-KILE 3.1.1.2), the realm in uppercase followed by the case sensitive `sAMAccountName`, such as `CORP.EXAMPLEsvc_web`.
  The salt is the same for every service principal name of the account.
+ `ADComputer`: the salt of an AD computer account, the realm in uppercase, `host`, the computer name in lowercase without the trailing `$`, `.` and the realm in lowercase, such as `CORP.EXAMPLEhostweb.corp.example`.

For the AD types the name is the account name, not a principal name, and the domain is always given with `-Realm`.
A user principal name is rejected as its user part is not always the `sAMAccountName` the salt is made from.

Names can come from the pipeline as strings, or as objects with `Name` and `Realm` properties such as the output of `Get-ObolPrincipal` and `Import-ObolKeytab`.
The salt is a string, the keys are derived from its UTF-8 bytes.

## EXAMPLES

### Example 1: Get the salt of an AD service account

```powershell
ConvertTo-ObolSalt svc_web -Realm corp.example -SaltType ADUser
```

```Output
CORP.EXAMPLEsvc_web
```

Gets the salt of the AD account `svc_web`.

### Example 2: Create a principal with the keys of an AD computer

```powershell
$kdc = Start-ObolKdc -Realm CORP.EXAMPLE
$salt = ConvertTo-ObolSalt 'WEB$' -Realm CORP.EXAMPLE -SaltType ADComputer
$kdc | New-ObolPrincipal host/web.corp.example -Alias 'WEB$' -Password $password -Salt $salt
```

Creates a principal with the keys the computer account `WEB$` has for the same password.

### Example 3: Get the default salts of several principals

```powershell
'user@EXAMPLE.TEST', 'HTTP/web.example.test@EXAMPLE.TEST' | ConvertTo-ObolSalt
```

```Output
EXAMPLE.TESTuser
EXAMPLE.TESTHTTPweb.example.test
```

Gets the salt MIT, Heimdal and Obol use for each principal by default.

### Example 4: Get the default salts of the entries in a keytab

```powershell
Import-ObolKeytab ./http.keytab | ConvertTo-ObolSalt
```

Gets the default salt of the principal of each entry, the salt a KDC with default salts sends to a client that authenticates with the password.

## PARAMETERS

### -Name

The name to get the salt of.
For `-SaltType Default` it is a principal name such as `user@EXAMPLE.TEST` or `HTTP/web.example.test`, the realm is taken from after `@` or from `-Realm` and a `\` escapes the next character like in other principal names.
For `ADUser` it is the `sAMAccountName`, such as `svc_web`, and for `ADComputer` the computer name with or without the trailing `$`, such as `WEB$`.

```yaml
Type: System.String
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 0
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: true
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Realm

The realm of the principal, or the DNS name of the domain of an AD account, such as `EXAMPLE.TEST`.
For `-SaltType Default` it is used as given and only needed if the name has no realm, it must match the realm of a name that has one.
For the AD types it is required and its case does not matter.
It binds from the `Realm` property of pipeline objects, each object uses its own realm.

```yaml
Type: System.String
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: true
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -SaltType

How the salt is built from the name and realm, `Default`, `ADUser` or `ADComputer`, see the description. Defaults to `Default`.

```yaml
Type: Obol.ObolSaltType
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

### System.String

The names to get the salt of, objects with a `Name` and optional `Realm` property also bind.

## OUTPUTS

### System.String

The salt of each name.

## NOTES

The salt of a principal piped from `Get-ObolPrincipal` is worked out from its name, a principal created with `-Salt` has that salt in its `Salt` property instead.
Kerberos implementations can be configured to use other salts, such as the MIT `norealm`, `onlyrealm` or `special` salt types.
Use the salt the KDC sends in its `PA-ETYPE-INFO2` reply for such a principal, for example from the `KRB5_TRACE` output of MIT `kinit`.

## RELATED LINKS

- [New-ObolPrincipal](./New-ObolPrincipal.md)
- [Set-ObolPrincipal](./Set-ObolPrincipal.md)
- [New-ObolKeytabEntry](./New-ObolKeytabEntry.md)
- [MS-KILE 3.1.1.2 Cryptographic Material](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/7a7b081d-c0c6-46f4-acbf-a439664270b8)
- [RFC 3962](https://www.rfc-editor.org/rfc/rfc3962)
- [about_Obol](./about_Obol.md)
