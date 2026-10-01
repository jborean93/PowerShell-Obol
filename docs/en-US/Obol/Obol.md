---
document type: module
Help Version: 1.0.0.0
HelpInfoUri: ''
Locale: en-US
Module Guid: 3eda8e6b-0288-4e08-b580-25e71aa51a0e
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Obol Module
---

# Obol Module

## Description

PowerShell module that runs a Kerberos KDC endpoint based on Kerberos.NET.

## Obol Cmdlets

### [Get-ObolKdc](Get-ObolKdc.md)

Gets the Obol KDCs running in the current runspace.

### [Get-ObolPrincipal](Get-ObolPrincipal.md)

Gets the principals of Obol KDCs.

### [New-ObolPrincipal](New-ObolPrincipal.md)

Creates a principal in the realm of an Obol KDC.

### [New-ObolPrincipalSetting](New-ObolPrincipalSetting.md)

Creates the settings for a principal to create with `Start-ObolKdc -Principal` or `New-ObolPrincipal -Setting`.

### [Remove-ObolPrincipal](Remove-ObolPrincipal.md)

Removes principals from an Obol KDC.

### [Set-ObolPrincipal](Set-ObolPrincipal.md)

Changes principals of an Obol KDC.

### [Start-ObolKdc](Start-ObolKdc.md)

Starts an Obol Kerberos KDC.

### [Stop-ObolKdc](Stop-ObolKdc.md)

Stops an Obol KDC.
