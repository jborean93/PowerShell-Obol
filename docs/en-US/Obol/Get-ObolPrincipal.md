---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/Get-ObolPrincipal.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Get-ObolPrincipal
---

# Get-ObolPrincipal

## SYNOPSIS

Gets the principals of Obol KDCs.

## SYNTAX

### __AllParameterSets

```
Get-ObolPrincipal [[-Name] <string[]>] -Kdc <ObolKdc[]> [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Gets the principals in the realm of KDCs started by `Start-ObolKdc`.
Pipe `Get-ObolKdc` to get the principals of every KDC in the current runspace.
The principals are returned in the order they were created, starting with the `krbtgt/<realm>` principal the KDC creates.

## EXAMPLES

### Example 1: Get the principals of a KDC

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST
$kdc | Get-ObolPrincipal
```

Gets the principals of the KDC, including the `krbtgt/EXAMPLE.TEST` principal the KDC creates.

### Example 2: Get the service principals of a KDC

```powershell
$kdc | Get-ObolPrincipal HTTP/*
```

Gets the principals of the KDC whose name starts with `HTTP/`.

### Example 3: Get every principal

```powershell
Get-ObolKdc | Get-ObolPrincipal
```

Gets the principals of every KDC in the current runspace.

## PARAMETERS

### -Kdc

The KDCs to get the principals of, as output by `Start-ObolKdc` or `Get-ObolKdc`.

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

### -Name

Only output the principals with one of these names.
The pattern is matched against both the name and the name with the realm, such as `user` and `user@EXAMPLE.TEST`.
Names with escaped characters are matched in their escaped form, such as `HTTP\/web`.
Wildcards are supported and the match is case insensitive even if the KDC matches principal names case sensitively.

```yaml
Type: System.String[]
DefaultValue: ''
SupportsWildcards: true
Aliases: []
ParameterSets:
- Name: (All)
  Position: 0
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

The KDCs to get the principals of.

## OUTPUTS

### Obol.ObolPrincipal

The principals, see `New-ObolPrincipal` for the properties.

## NOTES

A name that matches no principal does not write an error.

## RELATED LINKS

- [New-ObolPrincipal](./New-ObolPrincipal.md)
- [Get-ObolKdc](./Get-ObolKdc.md)
