---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/Exit-ObolSspiEnvironment.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Exit-ObolSspiEnvironment
---

# Exit-ObolSspiEnvironment

## SYNOPSIS

Removes the KDCs registered with Windows Kerberos by Enter-ObolSspiEnvironment.

## SYNTAX

### __AllParameterSets

```
Exit-ObolSspiEnvironment [-WhatIf] [-Confirm] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Removes the KDCs `Enter-ObolSspiEnvironment` registered with Windows Kerberos, so it goes back to finding KDCs the usual way.
Nothing happens if no SSPI environment is entered.

It also removes the realm the environment added to the prompt.

Windows cannot remove the registration of a single realm, so every registration in the same scope is removed:

+ `Thread`: every KDC registered for any thread in the PowerShell process, including other runspaces and ones made with `Add-ObolSspiKdc`.
+ `Machine`: every KDC registered for the machine, including the ones Windows found itself, which it finds again the next time they are needed.
+ `MitRealm`: the realm and host mapping registry keys the environment created, and every KDC registered for the machine like `Machine`.
+ `DcLocator`: the NRPT rules the environment created, its DNS and LDAP ping listeners, and every KDC registered for the machine like `Machine`.
  The DNS client cache is flushed so the realm names stop resolving straight away.

Only the runspace that entered the environment can exit it, and it is exited when that runspace closes.
This cmdlet is only supported on Windows and errors on other platforms.

## EXAMPLES

### Example 1: Exit the SSPI environment

```powershell
Exit-ObolSspiEnvironment
```

Removes the KDCs registered by `Enter-ObolSspiEnvironment`.

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

Exiting does not stop the KDCs, use `Stop-ObolKdc` for that.

Exiting does not remove the tickets Windows got from the KDCs or clear the caches outside the Kerberos SSP, such as Netlogon's domain controller cache.
See [CLEARING CACHED STATE in about_ObolSspi](./about_ObolSspi.md#clearing-cached-state) for how to clear them between tests.

## RELATED LINKS

- [Enter-ObolSspiEnvironment](./Enter-ObolSspiEnvironment.md)
- [Use-ObolSspiEnvironment](./Use-ObolSspiEnvironment.md)
- [Clear-ObolSspiKdc](./Clear-ObolSspiKdc.md)
- [about_ObolSspi](./about_ObolSspi.md)
