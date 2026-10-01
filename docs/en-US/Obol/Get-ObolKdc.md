---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/Get-ObolKdc.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Get-ObolKdc
---

# Get-ObolKdc

## SYNOPSIS

Gets the Obol KDCs running in the current runspace.

## SYNTAX

### __AllParameterSets

```
Get-ObolKdc [[-Realm] <string[]>] [-Port <int[]>] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Gets the KDCs started by `Start-ObolKdc` in the current runspace that are still running or have faulted, in the order they were started.
A faulted KDC stays listed until it is stopped with `Stop-ObolKdc` so the failure can be seen.
Use the `Realm` and `Port` parameters to filter the KDCs returned.

## EXAMPLES

### Example 1: Get all running KDCs

```powershell
PS C:\> Get-ObolKdc
```

Gets every KDC running in the current runspace.

### Example 2: Get the KDCs for a realm

```powershell
PS C:\> Get-ObolKdc -Realm *.TEST
```

Gets the KDCs whose realm ends with `.TEST`.

### Example 3: Stop all KDCs

```powershell
PS C:\> Get-ObolKdc | Stop-ObolKdc
```

Stops every KDC running in the current runspace.

## PARAMETERS

### -Port

Only output the KDCs listening on one of these ports.

```yaml
Type: System.Int32[]
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

### -Realm

Only output the KDCs for these realms.
Wildcards are supported and the match is case insensitive.

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

## OUTPUTS

### Obol.ObolKdc

The running KDCs, see `Start-ObolKdc` for the properties.

## NOTES

KDCs started in other runspaces are not returned.

## RELATED LINKS

- [Start-ObolKdc](./Start-ObolKdc.md)
- [Stop-ObolKdc](./Stop-ObolKdc.md)
