---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/PowerShell-Obol/blob/main/docs/en-US/Obol/Stop-ObolKdc.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Stop-ObolKdc
---

# Stop-ObolKdc

## SYNOPSIS

Stops an Obol KDC.

## SYNTAX

### __AllParameterSets

```
Stop-ObolKdc [-Kdc] <ObolKdc[]> [-WhatIf] [-Confirm] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Stops a KDC started by `Start-ObolKdc`.
The KDC stops listening on TCP and UDP, any open TCP connections are closed and it is removed from the KDCs returned by `Get-ObolKdc`.
Stopping a KDC that is already stopped does nothing.
Stopping a faulted KDC removes it from `Get-ObolKdc` and leaves its state as `Faulted`.

Calling `Dispose()` on the KDC object does the same thing.

## EXAMPLES

### Example 1: Stop a KDC

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST
Stop-ObolKdc -Kdc $kdc
```

Starts and then stops a KDC.

### Example 2: Stop all KDCs

```powershell
Get-ObolKdc | Stop-ObolKdc
```

Stops every KDC running in the current runspace.

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

The KDC to stop, as output by `Start-ObolKdc` or `Get-ObolKdc`.

```yaml
Type: Obol.ObolKdc[]
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

### Obol.ObolKdc[]

The KDCs to stop.

## OUTPUTS

## NOTES

KDCs are also stopped when the runspace that started them is closed.

## RELATED LINKS

- [Get-ObolKdc](./Get-ObolKdc.md)
- [Start-ObolKdc](./Start-ObolKdc.md)
