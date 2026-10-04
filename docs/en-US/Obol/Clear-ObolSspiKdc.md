---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/Clear-ObolSspiKdc.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Clear-ObolSspiKdc
---

# Clear-ObolSspiKdc

## SYNOPSIS

Removes the KDCs Obol pointed the Windows Kerberos SSP at, for the whole process or the whole machine.

## SYNTAX

### __AllParameterSets

```
Clear-ObolSspiKdc [-Scope <ObolSspiKdcScope>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Removes the realm to KDC entries set with `Add-ObolSspiKdc`.

`-Scope Process` (the default) sends the undocumented `KerbUnpinAllKdcs` message, removing the thread pins for all threads in the current process.
Pinning is per thread, but unpinning is not: there is no per-realm or per-thread unpin, so this clears **all** pins in the whole process at once, those made on any thread and any made outside Obol.
No administrator rights are needed to clear a process KDC pin.

`-Scope Machine` purges the whole machine-wide binding cache (the `klist.exe purge_bind` equivalent).
This needs administrator rights and will error if run by a non-admin process.

This cmdlet is only supported on Windows and errors on other platforms.

## EXAMPLES

### Example 1: Remove the process's pins

```powershell
PS C:\> Clear-ObolSspiKdc
```

Removes every KDC pin in the current process.

### Example 2: Purge the machine binding cache

```powershell
PS C:\> Clear-ObolSspiKdc -Scope Machine
```

Flushes the whole machine-wide binding cache (run from an elevated session).

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

### -Scope

What to clear.
`Process` (the default) removes all pins in the current process (no admin).
`Machine` purges the machine-wide binding cache (needs admin).

```yaml
Type: Obol.ObolSspiKdcScope
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

## OUTPUTS

## NOTES

This cmdlet is only supported on Windows, it uses the Windows Kerberos SSP and errors on other platforms.

`-Scope Machine` needs administrator rights. Both scopes are all-or-nothing, there is no per-realm removal.

## RELATED LINKS

- [Add-ObolSspiKdc](./Add-ObolSspiKdc.md)
- [Get-ObolSspiKdc](./Get-ObolSspiKdc.md)
- [about_ObolSspi](./about_ObolSspi.md)
