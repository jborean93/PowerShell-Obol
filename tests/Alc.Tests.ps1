using module ../output/Obol
using namespace System.IO
using namespace System.Management.Automation
using namespace System.Runtime.Loader

BeforeAll { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

Describe "Module loading" {
    BeforeAll {
        $moduleBase = (Get-Module Obol).ModuleBase
        $binPath = [Path]::Combine($moduleBase, 'bin', 'net10.0')

        # Copies the built module to a new folder so a child process can change or import it without touching the
        # module this process loaded. Only one copy of the module can be loaded in a process.
        Function Copy-TestModule {
            param ([string]$Name)

            $destination = [Path]::Combine($TestDrive, $Name, 'Obol')
            $null = New-Item $destination -ItemType Directory -Force
            Copy-Item -Path ([Path]::Combine($moduleBase, '*')) -Destination $destination -Recurse
            $destination
        }

        # Runs a script in a new pwsh process and returns its output parsed from JSON.
        Function Invoke-ChildPwsh {
            param ([string]$Script)

            $out = & ([Environment]::ProcessPath) -NoProfile -NonInteractive -Command $Script 2>&1
            $LASTEXITCODE | Should-Be 0 -Because ($out -join "`n")
            ($out -join "`n") | ConvertFrom-Json
        }
    }

    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
    }

    It "Loads the module assembly in the Obol load context" {
        [AssemblyLoadContext]::GetLoadContext([Obol.ObolKdc].Assembly).Name | Should-Be Obol
    }

    It "Loads the loader in the default load context" {
        $loader = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GetName().Name -eq 'Obol.Loader' }

        $loader | Should-NotBeNull
        [AssemblyLoadContext]::GetLoadContext($loader) | Should-BeSame ([AssemblyLoadContext]::Default)
    }

    It "Loads Kerberos.NET in the module load context" {
        $null = Start-ObolKdc EXAMPLE.TEST

        $kerberosAsm = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GetName().Name -eq 'Kerberos.NET' }

        $kerberosAsm | Should-NotBeNull
        [AssemblyLoadContext]::GetLoadContext($kerberosAsm).Name | Should-Be Obol
    }

    It "Uses the System.Management.Automation of PowerShell" {
        # The module references it without bundling it, so the load context falls back to PowerShell's copy.
        $actual = [Obol.Commands.StartObolKdc].BaseType.Assembly

        $actual | Should-BeSame ([PSObject].Assembly)
        [AssemblyLoadContext]::GetLoadContext($actual) | Should-BeSame ([AssemblyLoadContext]::Default)
    }

    It "Does not make dependency types resolvable by name" {
        $null = Start-ObolKdc EXAMPLE.TEST

        'Kerberos.NET.Crypto.KerberosKey' -as [type] | Should-BeNull
    }

    It "Only loads dependencies listed in Obol.deps.json" {
        # A file next to the module that is not a runtime asset in Obol.deps.json must not be loaded. The build puts
        # PowerShell's System.Management.Automation.dll there for the coverage instrumenter, this one is not a valid
        # assembly so loading it from the module folder would fail.
        $copy = Copy-TestModule decoy
        [File]::WriteAllText([Path]::Combine($copy, 'bin', 'net10.0', 'System.Management.Automation.dll'), 'not an assembly')

        $actual = Invoke-ChildPwsh @"
`$ErrorActionPreference = 'Stop'
Import-Module '$copy'
`$kdc = Start-ObolKdc EXAMPLE.TEST
`$sma = [Obol.Commands.StartObolKdc].BaseType.Assembly
[PSCustomObject]@{
    State = `$kdc.State.ToString()
    SmaIsPwsh = [object]::ReferenceEquals(`$sma, [System.Management.Automation.PSObject].Assembly)
    SmaLocation = `$sma.Location
} | ConvertTo-Json
"@

        $actual.State | Should-Be Running
        $actual.SmaIsPwsh | Should-BeTrue
        $actual.SmaLocation | Should-NotBeLikeString "$copy*"
    }

    It "Refuses to import a copy from another path in the same process" {
        $first = Copy-TestModule first
        $second = Copy-TestModule second

        $actual = Invoke-ChildPwsh @"
Import-Module '$first'
try {
    Import-Module '$second' -ErrorAction Stop
    `$errorId = `$null
}
catch {
    `$errorId = `$_.FullyQualifiedErrorId
}
[PSCustomObject]@{
    ErrorId = `$errorId
    Loaded = (Get-Module Obol).ModuleBase
} | ConvertTo-Json
"@

        $actual.ErrorId | Should-BeLikeString 'ModuleAlreadyLoadedFromDifferentPath*'
        $actual.Loaded | Should-BeLikeString "$first*"
    }
}
