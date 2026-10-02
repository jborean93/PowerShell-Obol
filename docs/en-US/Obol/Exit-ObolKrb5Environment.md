---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/Exit-ObolKrb5Environment.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Exit-ObolKrb5Environment
---

# Exit-ObolKrb5Environment

## SYNOPSIS

Restores the krb5 environment variables changed by Enter-ObolKrb5Environment.

## SYNTAX

### __AllParameterSets

```
Exit-ObolKrb5Environment [-WhatIf] [-Confirm] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Restores the environment variables `Enter-ObolKrb5Environment` set, and removes the directory with its krb5.conf, credential cache and keytabs.
Only the environment variables it set are changed, `KRB5_CONFIG` and `KRB5CCNAME`, plus `KRB5_KTNAME` and `KRB5_CLIENT_KTNAME` if it was given `-ServicePrincipal` or `-ClientPrincipal`, any other environment variable is left alone.

Each of those environment variables gets back the value it had before entering.
If one of them did not exist before entering, it is removed.
If one of them was changed after entering, it is left with its new value.
Native environment variables set by `-SetNativeEnvironment` are restored the same way.

The prompt function changed by `Enter-ObolKrb5Environment` is restored, unless the prompt was replaced after entering, such as by a profile or prompt theme, in which case it is left as is.

Only the runspace that entered the environment can exit it, calling this from another runspace fails and changes nothing.
Closing the runspace that entered it also exits it.
Nothing is done if no environment is entered, so it can be called in cleanup code without checking.

If the directory cannot be removed the environment variables are still restored and an error is written.

## EXAMPLES

### Example 1: Exit the environment in a Pester test

```powershell
BeforeAll {
    $kdc = Start-ObolKdc -Realm EXAMPLE.TEST
    Enter-ObolKrb5Environment -Kdc $kdc
}

AfterAll {
    Exit-ObolKrb5Environment
    Stop-ObolKdc -Kdc $kdc
}
```

Enters the environment before the tests run and restores the environment variables after.

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

Tickets in the credential cache of the environment are removed with it.

Unlike `Enter-PSSession`, typing `exit` does not leave the environment, it closes PowerShell, which also exits the environment as its runspace closes.

## RELATED LINKS

- [Enter-ObolKrb5Environment](./Enter-ObolKrb5Environment.md)
