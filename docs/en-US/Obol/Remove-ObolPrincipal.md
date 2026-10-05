---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/PowerShell-Obol/blob/main/docs/en-US/Obol/Remove-ObolPrincipal.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Remove-ObolPrincipal
---

# Remove-ObolPrincipal

## SYNOPSIS

Removes principals from an Obol KDC.

## SYNTAX

### Principal (Default)

```
Remove-ObolPrincipal [-Principal] <ObolPrincipal[]> [-WhatIf] [-Confirm] [<CommonParameters>]
```

### Name

```
Remove-ObolPrincipal [-Name] <string[]> -Kdc <ObolKdc> [-WhatIf] [-Confirm] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Removes principals from the realm of their KDC.
The principals are given as objects from `New-ObolPrincipal` or `Get-ObolPrincipal`, or by name or alias with `-Kdc` and `-Name`.
The KDC no longer finds the principal by its name or aliases, so it cannot get new tickets and no new tickets are issued for it.
Tickets already issued are not affected, but a TGT of a removed principal cannot be used to get service tickets.

The name and aliases can be used for a new principal afterwards.
The `krbtgt` principal cannot be removed.

## EXAMPLES

### Example 1: Remove a principal

```powershell
$kdc | Remove-ObolPrincipal user
```

Removes the principal `user` of the KDC.

### Example 2: Remove principals from Get-ObolPrincipal

```powershell
$kdc | Get-ObolPrincipal HTTP/* | Remove-ObolPrincipal
```

Removes every principal of the KDC whose name or alias starts with `HTTP/`.

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

The names or aliases of the principals to remove from the KDC given by `-Kdc`, such as `user` or `HTTP/web.example.test`.
The KDC realm can be added after `@`.
Names are matched like the KDC matches them in requests and wildcards are not supported, use `Get-ObolPrincipal` to remove principals matching a pattern.
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

### -Principal

The principals to remove, as output by `New-ObolPrincipal` or `Get-ObolPrincipal`.

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

The principals to remove.

### Obol.ObolKdc

The KDC to find the principals named by `-Name` in.

## OUTPUTS

## NOTES

Changing a removed principal with `Set-ObolPrincipal` fails.

## RELATED LINKS

- [New-ObolPrincipal](./New-ObolPrincipal.md)
- [Get-ObolPrincipal](./Get-ObolPrincipal.md)
- [Set-ObolPrincipal](./Set-ObolPrincipal.md)
