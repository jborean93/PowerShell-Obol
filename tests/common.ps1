using namespace System.IO

$ErrorActionPreference = 'Stop'

Function New-TestKeytab {
    <#
    .SYNOPSIS
    Writes a keytab with the given entries.

    .PARAMETER Entry
    Hashtables with Name (components joined by '/'), Realm, Kvno, EncryptionType (the number) and optionally Key
    (bytes, defaults to zeros of the size of the encryption type).
    #>
    param ([string]$Path, [hashtable[]]$Entry)

    $data = [System.Collections.Generic.List[byte]]::new()
    $data.AddRange([byte[]](0x05, 0x02))

    Function Add-Number([System.Collections.Generic.List[byte]]$Buffer, [uint64]$Value, [int]$Length) {
        foreach ($i in ($Length - 1)..0) {
            $Buffer.Add([byte](($Value -shr (8 * $i)) -band 0xFF))
        }
    }

    Function Add-String([System.Collections.Generic.List[byte]]$Buffer, [string]$Value) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        Add-Number $Buffer $bytes.Length 2
        $Buffer.AddRange($bytes)
    }

    foreach ($e in $Entry) {
        # An if expression unrolls the array, cast it back to bytes.
        [byte[]]$key = if ($e.ContainsKey('Key')) { $e.Key } else {
            [byte[]]::new($(if ($e.EncryptionType -in 17, 19) { 16 } else { 32 }))
        }
        $components = $e.Name -split '/'

        $body = [System.Collections.Generic.List[byte]]::new()
        Add-Number $body $components.Count 2
        Add-String $body $e.Realm
        foreach ($c in $components) { Add-String $body $c }
        Add-Number $body 1 4  # KRB5_NT_PRINCIPAL
        Add-Number $body 0 4  # timestamp
        $body.Add([byte]($e.Kvno -band 0xFF))
        Add-Number $body $e.EncryptionType 2
        Add-Number $body $key.Length 2
        $body.AddRange($key)
        Add-Number $body $e.Kvno 4

        Add-Number $data $body.Count 4
        $data.AddRange($body)
    }

    [System.IO.File]::WriteAllBytes($Path, $data.ToArray())
}

Function Read-TestKeytab {
    <#
    .SYNOPSIS
    Parses an MIT keytab, version 0x0502, into one object per entry.

    .DESCRIPTION
    A parser separate from the module's own reader, used to check the bytes the cmdlets write. It fails the test if
    an entry's length does not match its contents.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param (
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Path')]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName = 'Data')]
        [byte[]]$Data
    )

    # Not $data, variable names ignore case so that is the -Data parameter.
    [byte[]]$bytes = if ($Path) { [File]::ReadAllBytes($Path) } else { $Data }

    # Spans cannot be used in PowerShell, read the big endian numbers byte by byte.
    Function Read-Number {
        param ([int]$Offset, [int]$Length)

        [uint64]$value = 0
        foreach ($i in 0..($Length - 1)) {
            $value = ($value -shl 8) -bor $bytes[$Offset + $i]
        }
        $value
    }

    Read-Number 0 2 | Should-Be 0x0502
    $offset = 2

    Function Read-String {
        $length = (Read-Number ($offset) 2)
        $value = [System.Text.Encoding]::UTF8.GetString($bytes, $offset + 2, $length)
        $offset = $offset + 2 + $length
        $value
    }

    while ($offset -lt $bytes.Length) {
        $length = (Read-Number ($offset) 4)
        $end = $offset + 4 + $length
        $offset += 4
        $count = (Read-Number ($offset) 2)
        $offset += 2
        $realm = . Read-String
        $components = foreach ($i in 1..$count) { . Read-String }
        $nameType = (Read-Number ($offset) 4)
        $timestamp = (Read-Number ($offset + 4) 4)
        $kvno8 = $bytes[$offset + 8]
        $etype = (Read-Number ($offset + 9) 2)
        $keyLength = (Read-Number ($offset + 11) 2)
        $key = [Convert]::ToHexStringLower($bytes, $offset + 13, $keyLength)
        $offset += 13 + $keyLength
        $kvno = (Read-Number ($offset) 4)
        $offset += 4
        $offset | Should-Be $end

        [PSCustomObject]@{
            Name = "$($components -join '/')@$realm"
            Components = @($components)
            NameType = $nameType
            Timestamp = [DateTimeOffset]::FromUnixTimeSeconds($timestamp)
            Kvno8 = $kvno8
            Kvno = $kvno
            EncryptionType = [Obol.ObolEncryptionType]$etype
            Key = $key
        }
    }
}

Function Invoke-KerberosTool {
    <#
    .SYNOPSIS
    Runs a Kerberos command line tool, such as kinit, and fails the test with its output if it does not succeed.

    .OUTPUTS
    The output of the tool as one string.
    #>
    param ([scriptblock]$Command)

    $out = (& $Command 2>&1) -join "`n"
    $LASTEXITCODE | Should-Be 0 -Because $out
    $out
}


Function Get-NativeEnvironmentVariable {
    <#
    .SYNOPSIS
    Gets a variable from the C library's environment on Linux and macOS, which .NET does not change there.
    #>
    param ([string]$Name)

    if (-not ('ObolTests.Libc' -as [type])) {
        $lib = if ($IsMacOS) { 'libc' } else { 'libc.so.6' }
        Add-Type -Namespace ObolTests -Name Libc -MemberDefinition @"
[DllImport("$lib", EntryPoint = "getenv")]
private static extern IntPtr GetEnvPtr(string name);

public static string GetEnv(string name) => Marshal.PtrToStringUTF8(GetEnvPtr(name));
"@
    }
    [ObolTests.Libc]::GetEnv($Name)
}

Function Invoke-AsLogonUser {
    <#
    .SYNOPSIS
    Logs a user on (network logon), impersonates them on the current thread, runs the scriptblock, then reverts.

    .DESCRIPTION
    Windows only. Used to test code paths that depend on the caller's effective token, such as the SeTcbPrivilege
    routes of the SSPI binding cache cmdlets. The scriptblock runs synchronously on the current thread so any cmdlet
    in it runs under the impersonation. A network logon (type 3) is used, it carries the account's granted
    privileges, an interactive logon token does not.

    .OUTPUTS
    The output of the scriptblock.
    #>
    param (
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )

    if (-not ('ObolTests.LogonHelper' -as [type])) {
        Add-Type -Namespace ObolTests -Name LogonHelper -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
private static extern bool LogonUserW(string user, string domain, string password, int type, int provider, out IntPtr token);

[DllImport("advapi32.dll", SetLastError = true)]
private static extern bool ImpersonateLoggedOnUser(IntPtr token);

[DllImport("advapi32.dll", SetLastError = true)]
private static extern bool RevertToSelf();

[DllImport("kernel32.dll", SetLastError = true)]
private static extern bool CloseHandle(IntPtr handle);

public static IntPtr Logon(string user, string password) {
    // LOGON32_LOGON_NETWORK (3), LOGON32_PROVIDER_DEFAULT (0).
    if (!LogonUserW(user, ".", password, 3, 0, out IntPtr token))
        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "LogonUser failed");
    return token;
}

public static void Impersonate(IntPtr token) {
    if (!ImpersonateLoggedOnUser(token))
        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "ImpersonateLoggedOnUser failed");
}

public static void Revert() {
    if (!RevertToSelf())
        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "RevertToSelf failed");
}

public static void Close(IntPtr handle) { CloseHandle(handle); }
'@
    }

    $token = [ObolTests.LogonHelper]::Logon($Username, $Password)
    try {
        [ObolTests.LogonHelper]::Impersonate($token)
        try { & $ScriptBlock }
        finally { [ObolTests.LogonHelper]::Revert() }
    }
    finally {
        [ObolTests.LogonHelper]::Close($token)
    }
}

Function New-ObolPowerShell {
    <#
    .SYNOPSIS
    Creates a PowerShell instance with its own runspace in this process that has the Obol module imported.

    .DESCRIPTION
    Without -ThreadOptions the instance owns its runspace and disposing it closes the runspace.

    With -ThreadOptions the runspace is created with those options, used to test behaviour tied to the OS thread:
    ReuseThread keeps every Invoke on the one thread, UseNewThread runs each Invoke on a fresh thread. The options
    can only be set before the runspace opens, so the instance does not own it, dispose $ps.Runspace as well.
    #>
    param ([System.Management.Automation.Runspaces.PSThreadOptions]$ThreadOptions)

    if ($PSBoundParameters.ContainsKey('ThreadOptions')) {
        $runspace = [runspacefactory]::CreateRunspace()
        $runspace.ThreadOptions = $ThreadOptions
        $runspace.Open()
        $ps = [PowerShell]::Create($runspace)
    }
    else {
        $ps = [PowerShell]::Create()
    }

    $null = $ps.AddCommand('Import-Module').AddArgument(
        [Path]::Combine((Get-Module Obol).ModuleBase, 'Obol.psd1')).Invoke()
    $ps.Commands.Clear()
    $ps
}
