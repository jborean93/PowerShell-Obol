using module ../output/Obol
using namespace System.IO

BeforeAll {
    . ([Path]::Combine($PSScriptRoot, 'common.ps1'))

    $variableNames = 'KRB5_CONFIG', 'KRB5CCNAME', 'KRB5_KTNAME', 'KRB5_CLIENT_KTNAME'
}

Describe "Enter-ObolKrb5Environment" {
    BeforeEach {
        $previous = @{}
        foreach ($name in $variableNames) {
            $previous[$name] = [Environment]::GetEnvironmentVariable($name)
            Remove-Item "Env:\$name" -ErrorAction Ignore
        }

        $kdc = Start-ObolKdc EXAMPLE.TEST -Principal @{ user = $null; 'HTTP/web.example.test' = $null }
    }

    AfterEach {
        Exit-ObolKrb5Environment
        Get-ObolKdc | Stop-ObolKdc
        foreach ($name in $variableNames) {
            # PowerShell passes $null to a .NET string parameter as '', which would leave an empty variable.
            if ($null -eq $previous[$name]) {
                Remove-Item "Env:\$name" -ErrorAction Ignore
            }
            else {
                Set-Item "Env:\$name" $previous[$name]
            }
        }
    }

    It "Sets KRB5_CONFIG and KRB5CCNAME for a KDC" {
        $actual = Enter-ObolKrb5Environment $kdc

        $actual | Should-BeNull
        $dir = [Path]::GetDirectoryName($env:KRB5_CONFIG)
        $env:KRB5_CONFIG | Should-Be ([Path]::Combine($dir, 'krb5.conf'))
        $env:KRB5CCNAME | Should-Be "FILE:$([Path]::Combine($dir, 'ccache'))"
        [File]::ReadAllText($env:KRB5_CONFIG) | Should-Be (ConvertTo-ObolKrb5Config $kdc)
        Test-Path ([Path]::Combine($dir, 'ccache')) | Should-BeFalse
        [Environment]::GetEnvironmentVariable('KRB5_KTNAME') | Should-BeNull
        [Environment]::GetEnvironmentVariable('KRB5_CLIENT_KTNAME') | Should-BeNull
    }

    It "Creates the directory readable only by the current user" -Skip:$IsWindows {
        Enter-ObolKrb5Environment $kdc -ServicePrincipal ($kdc | Get-ObolPrincipal user)

        $dir = [Path]::GetDirectoryName($env:KRB5_CONFIG)
        [File]::GetUnixFileMode($dir) | Should-Be ([UnixFileMode]'UserRead, UserWrite, UserExecute')
        [File]::GetUnixFileMode(($env:KRB5_KTNAME -replace '^FILE:')) |
            Should-Be ([UnixFileMode]'UserRead, UserWrite')
    }

    It "Uses KDCs from the pipeline" {
        $other = Start-ObolKdc OTHER.TEST

        $kdc, $other | Enter-ObolKrb5Environment

        [File]::ReadAllText($env:KRB5_CONFIG) | Should-Be (ConvertTo-ObolKrb5Config $kdc, $other)
    }

    It "Writes the krb5.conf for -Provider <Provider>" -TestCases @(
        @{ Provider = 'Mit' }
        @{ Provider = 'Heimdal' }
    ) {
        param ($Provider)

        $kdc = Start-ObolKdc TCP.TEST -Transport Tcp

        Enter-ObolKrb5Environment $kdc -Provider $Provider

        [File]::ReadAllText($env:KRB5_CONFIG) | Should-Be (ConvertTo-ObolKrb5Config $kdc -Provider $Provider)
    }

    It "Sets KRB5_KTNAME to a keytab of -ServicePrincipal" {
        $principal = $kdc | Get-ObolPrincipal HTTP/web.example.test

        Enter-ObolKrb5Environment $kdc -ServicePrincipal $principal

        $env:KRB5_KTNAME | Should-BeLikeString 'FILE:*'
        $entries = Read-TestKeytab ($env:KRB5_KTNAME -replace '^FILE:')
        $entries.Count | Should-Be @(New-ObolKeytabEntry -Principal $principal).Count
        $entries.Name | Select-Object -Unique | Should-Be 'HTTP/web.example.test@EXAMPLE.TEST'
        [Environment]::GetEnvironmentVariable('KRB5_CLIENT_KTNAME') | Should-BeNull
    }

    It "Sets KRB5_CLIENT_KTNAME to a keytab of -ClientPrincipal" {
        $principal = $kdc | Get-ObolPrincipal user

        Enter-ObolKrb5Environment $kdc -ClientPrincipal $principal

        $entries = Read-TestKeytab ($env:KRB5_CLIENT_KTNAME -replace '^FILE:')
        $entries.Count | Should-Be @(New-ObolKeytabEntry -Principal $principal).Count
        $entries.Name | Select-Object -Unique | Should-Be 'user@EXAMPLE.TEST'
        [Environment]::GetEnvironmentVariable('KRB5_KTNAME') | Should-BeNull
    }

    It "Fails if an environment is already entered" {
        Enter-ObolKrb5Environment $kdc
        $config = $env:KRB5_CONFIG

        { Enter-ObolKrb5Environment $kdc } |
            Should-Throw -FullyQualifiedErrorId 'Krb5EnvironmentAlreadyEntered,Obol.Commands.EnterObolKrb5Environment'

        $env:KRB5_CONFIG | Should-Be $config
    }

    It "Fails if an environment is entered in another runspace" {
        $ps = New-ObolPowerShell
        try {
            $null = $ps.AddCommand('Enter-ObolKrb5Environment').AddParameter('Kdc', $kdc)
            $null = $ps.Invoke()

            { Enter-ObolKrb5Environment $kdc } | Should-Throw -FullyQualifiedErrorId (
                'Krb5EnvironmentAlreadyEntered,Obol.Commands.EnterObolKrb5Environment')
        }
        finally {
            $ps.Dispose()
        }
    }

    It "Exits when the runspace that entered it closes" {
        $ps = New-ObolPowerShell
        $null = $ps.AddCommand('Enter-ObolKrb5Environment').AddParameter('Kdc', $kdc)
        $null = $ps.Invoke()
        $dir = [Path]::GetDirectoryName($env:KRB5_CONFIG)

        $ps.Runspace.Dispose()
        $ps.Dispose()

        [Environment]::GetEnvironmentVariable('KRB5_CONFIG') | Should-BeNull
        Test-Path $dir | Should-BeFalse
        Enter-ObolKrb5Environment $kdc
        [Environment]::GetEnvironmentVariable('KRB5_CONFIG') | Should-NotBeNull
    }

    It "Writes an error for a stopped KDC" {
        $other = Start-ObolKdc OTHER.TEST
        Stop-ObolKdc $other

        $kdc, $other | Enter-ObolKrb5Environment -ErrorVariable err -ErrorAction SilentlyContinue

        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'KdcNotRunning,Obol.Commands.EnterObolKrb5Environment'
        [File]::ReadAllText($env:KRB5_CONFIG) | Should-Be (ConvertTo-ObolKrb5Config $kdc)
    }

    It "Changes nothing if every KDC failed" {
        Stop-ObolKdc $kdc

        $kdc | Enter-ObolKrb5Environment -ErrorAction SilentlyContinue

        [Environment]::GetEnvironmentVariable('KRB5_CONFIG') | Should-BeNull
    }

    It "Changes nothing with -WhatIf" {
        Enter-ObolKrb5Environment $kdc -WhatIf

        [Environment]::GetEnvironmentVariable('KRB5_CONFIG') | Should-BeNull
        [Environment]::GetEnvironmentVariable('KRB5CCNAME') | Should-BeNull
    }

    It "Fails for an undefined provider" {
        $provider = [Enum]::ToObject([Obol.ObolKrb5Provider], 99)

        { Enter-ObolKrb5Environment $kdc -Provider $provider } |
            Should-Throw -FullyQualifiedErrorId 'InvalidProvider,Obol.Commands.EnterObolKrb5Environment'

        [Environment]::GetEnvironmentVariable('KRB5_CONFIG') | Should-BeNull
    }

    Context "Prompt" {
        BeforeEach {
            $rendering = $PSStyle.OutputRendering
            $PSStyle.OutputRendering = 'PlainText'
            $prompt = prompt
        }

        AfterEach {
            $PSStyle.OutputRendering = $rendering
        }

        It "Adds the realm to the prompt" {
            Enter-ObolKrb5Environment $kdc

            prompt | Should-Be "[EXAMPLE.TEST] $prompt"
        }

        It "Adds the number of other realms to the prompt" {
            $other = Start-ObolKdc OTHER.TEST
            $same = Start-ObolKdc EXAMPLE.TEST

            $kdc, $same, $other | Enter-ObolKrb5Environment

            prompt | Should-Be "[EXAMPLE.TEST +1] $prompt"
        }

        It "Colors the realm when output rendering allows it" {
            $PSStyle.OutputRendering = 'Ansi'

            Enter-ObolKrb5Environment $kdc

            prompt | Should-Be "$($PSStyle.Foreground.Cyan)[EXAMPLE.TEST]$($PSStyle.Reset) $prompt"
        }

        It "Leaves the prompt alone with -NoPrompt" {
            $function = ${function:global:prompt}

            Enter-ObolKrb5Environment $kdc -NoPrompt

            [object]::ReferenceEquals(${function:global:prompt}, $function) | Should-BeTrue
        }
    }

    Context "Native environment" -Skip:$IsWindows {
        It "Leaves the native environment alone by default" {
            Enter-ObolKrb5Environment $kdc

            Get-NativeEnvironmentVariable KRB5_CONFIG | Should-NotBe $env:KRB5_CONFIG
        }

        It "Sets the native environment with -SetNativeEnvironment" {
            Enter-ObolKrb5Environment $kdc -SetNativeEnvironment

            Get-NativeEnvironmentVariable KRB5_CONFIG | Should-Be $env:KRB5_CONFIG
            Get-NativeEnvironmentVariable KRB5CCNAME | Should-Be $env:KRB5CCNAME
        }
    }
}
