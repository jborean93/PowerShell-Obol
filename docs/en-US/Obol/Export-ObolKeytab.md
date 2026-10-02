---
document type: cmdlet
external help file: Obol.dll-Help.xml
HelpUri: https://www.github.com/jborean93/Obol/blob/main/docs/en-US/Obol/Export-ObolKeytab.md
Locale: en-US
Module Name: Obol
ms.date: ''
PlatyPS schema version: 2024-05-01
title: Export-ObolKeytab
---

# Export-ObolKeytab

## SYNOPSIS

Exports the keys of principals of an Obol KDC to a keytab file.

## SYNTAX

### Principal (Default)

```
Export-ObolKeytab [-Path] <string> -Principal <ObolPrincipal[]> [-Append] [-Force] [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

### Name

```
Export-ObolKeytab [-Path] <string> [-Name] <string[]> -Kdc <ObolKdc> [-Append] [-Force] [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

### Entry

```
Export-ObolKeytab [-Path] <string> -Entry <ObolKeytabEntry[]> [-Append] [-Force] [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Writes the long-term keys of principals to a keytab file so services and clients can use them without a password, such as an acceptor reading the keytab through `KRB5_KTNAME` or `kinit -k`.
The principals are given as objects from `New-ObolPrincipal` or `Get-ObolPrincipal`, or by name or alias with `-Kdc` and `-Name`.
Principals from several KDCs can be written to the same keytab.
With `-Entry` the cmdlet writes keytab entries from `Import-ObolKeytab` or `New-ObolKeytabEntry` instead, which need no KDC.

The file uses the MIT keytab format (version `0x0502`) read by MIT krb5, Heimdal, Java, Kerberos.NET and Windows `ktpass` compatible tools.
Each principal gets an entry for every key it has, under its name and under each of its aliases, with the current key version number.
A ticket for an alias is encrypted with the same key, the alias entries let acceptors that look keys up by the ticket's service name find it.

The keys are the ones the KDC uses now, keys replaced by `Set-ObolPrincipal` are not kept so only the current key version is written.
Export the keytab again after changing the keys of a principal.

The file is written once all principals have been read from the pipeline.
Nothing is written if no principal or entry was given.
Use `ConvertTo-ObolKeytab` to get the keytab as bytes without writing a file.

On Linux and macOS a new file is created readable and writable only by the current user, an existing file keeps its permissions.
On Windows a new file inherits the permissions of its folder, write it to a folder only the current user can read, such as a folder in the user profile, not a shared location like `C:\Temp`.

## EXAMPLES

### Example 1: Export the keys of a service

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST
$kdc | New-ObolPrincipal HTTP/web.example.test -Alias HTTP/web
$kdc | Export-ObolKeytab ./http.keytab HTTP/web.example.test
```

Creates a service principal with random keys and writes them to `http.keytab` under the names `HTTP/web.example.test@EXAMPLE.TEST` and `HTTP/web@EXAMPLE.TEST`.

### Example 2: Export principals from Get-ObolPrincipal

```powershell
$kdc | Get-ObolPrincipal HTTP/* | Export-ObolKeytab ./services.keytab -Force
```

Writes the keys of every principal whose name or alias starts with `HTTP/` to `services.keytab`, replacing the file if it exists.

### Example 3: Get a ticket with a keytab

```powershell
$kdc | New-ObolPrincipal user
$kdc | Export-ObolKeytab ./user.keytab user
$kdc | Export-ObolKrb5Config ./krb5.conf
$env:KRB5_CONFIG = (Resolve-Path ./krb5.conf).Path
kinit -k -t ./user.keytab user@EXAMPLE.TEST
```

Creates a principal with random keys, so it has no password, and uses its keytab to get a TGT with MIT or Heimdal `kinit`.

### Example 4: Create a keytab for an AD account

```powershell
$salt = ConvertTo-ObolSalt svc_web -Realm CORP.EXAMPLE -SaltType ADUser
New-ObolKeytabEntry HTTP/web.corp.example@CORP.EXAMPLE -Password $password -Salt $salt -Kvno 3 |
    Export-ObolKeytab ./http.keytab
```

Writes the keys the AD account `svc_web` has for the password under its service principal name, like `ktpass`, without a KDC.

### Example 5: Remove the RC4 keys from a keytab

```powershell
Import-ObolKeytab ./old.keytab | Where-Object EncryptionType -ne 23 | Export-ObolKeytab ./new.keytab
```

Copies every entry of `old.keytab` except the RC4 keys to `new.keytab`.

### Example 6: Export only some keys of a principal

```powershell
$kdc |
    Get-ObolPrincipal HTTP/web.example.test |
    New-ObolKeytabEntry |
    Where-Object { $_.EncryptionType -eq 'Aes256Sha1' -and $_.Name -eq 'HTTP/web.example.test' } |
    Export-ObolKeytab ./http.keytab
```

Writes only the AES256 key of `HTTP/web.example.test` under its own name, leaving out its other keys and aliases, for example to test a service whose keytab lacks the key a ticket is encrypted with.

### Example 7: Add a principal to an existing keytab

```powershell
$kdc | Export-ObolKeytab ./services.keytab HTTP/other.example.test -Append
```

Adds the entries for `HTTP/other.example.test` to the end of `services.keytab`.

## PARAMETERS

### -Append

Adds the entries to the end of an existing keytab instead of creating a new file.
The file is created if it does not exist, an existing file must be a keytab of version `0x0502`.
Entries already in the file are kept, readers use the entry with the highest key version number for a principal and encryption type.
Cannot be used with `-Force`.

```yaml
Type: System.Management.Automation.SwitchParameter
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

### -Entry

Keytab entries to write, as output by `Import-ObolKeytab` or `New-ObolKeytabEntry`.
The entries are written as they are, with their name type, timestamp and kvno, including keys of encryption types Obol does not support and repeated entries.
Use it to create a keytab for an account that is not in an Obol KDC, or to filter or combine existing keytabs.

```yaml
Type: Obol.ObolKeytabEntry[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Entry
  Position: Named
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Force

Replaces the file if it exists, without this the cmdlet fails when the file exists.
Cannot be used with `-Append`.

```yaml
Type: System.Management.Automation.SwitchParameter
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

The names or aliases of the principals to export from the KDC given by `-Kdc`, such as `user` or `HTTP/web.example.test`.
The KDC realm can be added after `@`.
Names are matched like the KDC matches them in requests and wildcards are not supported, use `Get-ObolPrincipal` to export principals matching a pattern.
A name that matches no principal writes an error, the other principals are still exported.

```yaml
Type: System.String[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Name
  Position: 1
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Path

The path of the keytab file to write.
A relative path is resolved from the current location and the path must be on the file system.

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

### -Principal

The principals to export, as output by `New-ObolPrincipal` or `Get-ObolPrincipal`.
A principal given more than once is only written once.

```yaml
Type: Obol.ObolPrincipal[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Principal
  Position: Named
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

The principals to export.

### Obol.ObolKdc

The KDC to find the principals named by `-Name` in.

### Obol.ObolKeytabEntry[]

The keytab entries to write.

## OUTPUTS

## NOTES

A keytab holds the keys of the principals in plain text, anyone who can read it can act as those principals.

The entries use the name type `KRB5_NT_PRINCIPAL` (1) like MIT `kadmin ktadd` and the time the cmdlet ran as their timestamp.
Use `klist -k -t -e` to list the entries of a keytab with MIT or Heimdal.

## RELATED LINKS

- [ConvertTo-ObolKeytab](./ConvertTo-ObolKeytab.md)
- [New-ObolPrincipal](./New-ObolPrincipal.md)
- [Get-ObolPrincipal](./Get-ObolPrincipal.md)
- [Set-ObolPrincipal](./Set-ObolPrincipal.md)
- [Export-ObolKrb5Config](./Export-ObolKrb5Config.md)
- [MIT keytab file format](https://web.mit.edu/kerberos/krb5-latest/doc/formats/keytab_file_format.html)
