using module ../output/Obol
using namespace System.IO

BeforeAll {
    . ([Path]::Combine($PSScriptRoot, 'common.ps1'))

    $variableNames = 'KRB5_CONFIG', 'KRB5CCNAME', 'KRB5_KTNAME', 'KRB5_CLIENT_KTNAME'
}

Describe "Exit-ObolKrb5Environment" {
    BeforeEach {
        $previous = @{}
        foreach ($name in $variableNames) {
            $previous[$name] = [Environment]::GetEnvironmentVariable($name)
            Remove-Item "Env:\$name" -ErrorAction Ignore
        }

        $kdc = Start-ObolKdc EXAMPLE.TEST -Principal @{ user = $null }
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

    It "Restores the variables and removes the files" {
        $env:KRB5_CONFIG = '/before/krb5.conf'
        $env:KRB5_KTNAME = 'FILE:/before/keytab'
        $principal = $kdc | Get-ObolPrincipal user
        Enter-ObolKrb5Environment $kdc -ServicePrincipal $principal -ClientPrincipal $principal
        $dir = [Path]::GetDirectoryName($env:KRB5_CONFIG)

        $actual = Exit-ObolKrb5Environment

        $actual | Should-BeNull
        $env:KRB5_CONFIG | Should-Be '/before/krb5.conf'
        $env:KRB5_KTNAME | Should-Be 'FILE:/before/keytab'
        [Environment]::GetEnvironmentVariable('KRB5CCNAME') | Should-BeNull
        [Environment]::GetEnvironmentVariable('KRB5_CLIENT_KTNAME') | Should-BeNull
        Test-Path $dir | Should-BeFalse
    }

    It "Removes a ccache written in the environment" {
        Enter-ObolKrb5Environment $kdc
        $ccache = $env:KRB5CCNAME -replace '^FILE:'
        Set-Content $ccache test

        Exit-ObolKrb5Environment

        Test-Path $ccache | Should-BeFalse
    }

    It "Exits if the directory was already removed" {
        Enter-ObolKrb5Environment $kdc
        Remove-Item ([Path]::GetDirectoryName($env:KRB5_CONFIG)) -Recurse -Force

        Exit-ObolKrb5Environment

        [Environment]::GetEnvironmentVariable('KRB5_CONFIG') | Should-BeNull
    }

    It "Restores the variables if the directory cannot be removed" -Skip:$IsWindows {
        Enter-ObolKrb5Environment $kdc
        $dir = [Path]::GetDirectoryName($env:KRB5_CONFIG)
        [File]::SetUnixFileMode($dir, 'UserRead, UserExecute')
        try {
            Exit-ObolKrb5Environment -ErrorVariable err -ErrorAction SilentlyContinue

            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId |
                Should-Be 'Krb5EnvironmentRemoveFailed,Obol.Commands.ExitObolKrb5Environment'
            $err[0].TargetObject | Should-Be $dir
            [Environment]::GetEnvironmentVariable('KRB5_CONFIG') | Should-BeNull
        }
        finally {
            [File]::SetUnixFileMode($dir, 'UserRead, UserWrite, UserExecute')
            Remove-Item $dir -Recurse -Force
        }
    }

    It "Restores the variables if a file in the directory is open" -Skip:(-not $IsWindows) {
        Enter-ObolKrb5Environment $kdc
        $dir = [Path]::GetDirectoryName($env:KRB5_CONFIG)
        # Windows cannot delete a file opened without FileShare.Delete.
        $fs = [File]::Open($env:KRB5_CONFIG, 'Open', 'Read', 'Read')
        try {
            Exit-ObolKrb5Environment -ErrorVariable err -ErrorAction SilentlyContinue

            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId |
                Should-Be 'Krb5EnvironmentRemoveFailed,Obol.Commands.ExitObolKrb5Environment'
            $err[0].TargetObject | Should-Be $dir
            [Environment]::GetEnvironmentVariable('KRB5_CONFIG') | Should-BeNull
        }
        finally {
            $fs.Dispose()
            Remove-Item $dir -Recurse -Force
        }
    }

    It "Restores the variables if the directory cannot be removed when the runspace closes" -Skip:$IsWindows {
        $ps = New-ObolPowerShell
        $null = $ps.AddCommand('Enter-ObolKrb5Environment').AddParameter('Kdc', $kdc).Invoke()
        $dir = [Path]::GetDirectoryName($env:KRB5_CONFIG)
        [File]::SetUnixFileMode($dir, 'UserRead, UserExecute')
        try {
            $ps.Dispose()

            [Environment]::GetEnvironmentVariable('KRB5_CONFIG') | Should-BeNull
            Test-Path $dir | Should-BeTrue
        }
        finally {
            [File]::SetUnixFileMode($dir, 'UserRead, UserWrite, UserExecute')
            Remove-Item $dir -Recurse -Force
        }
    }

    It "Leaves a variable changed after entering" {
        Enter-ObolKrb5Environment $kdc
        $env:KRB5CCNAME = 'FILE:/changed'

        Exit-ObolKrb5Environment

        $env:KRB5CCNAME | Should-Be 'FILE:/changed'
        [Environment]::GetEnvironmentVariable('KRB5_CONFIG') | Should-BeNull
    }

    It "Does nothing if no environment is entered" {
        $env:KRB5_CONFIG = '/before/krb5.conf'

        Exit-ObolKrb5Environment

        $env:KRB5_CONFIG | Should-Be '/before/krb5.conf'
    }

    It "Changes nothing with -WhatIf" {
        Enter-ObolKrb5Environment $kdc
        $config = $env:KRB5_CONFIG

        Exit-ObolKrb5Environment -WhatIf

        $env:KRB5_CONFIG | Should-Be $config
        Test-Path $config | Should-BeTrue
    }

    It "Allows entering again" {
        Enter-ObolKrb5Environment $kdc
        $first = $env:KRB5_CONFIG
        Exit-ObolKrb5Environment

        Enter-ObolKrb5Environment $kdc

        $env:KRB5_CONFIG | Should-NotBe $first
        Test-Path $env:KRB5_CONFIG | Should-BeTrue
    }

    It "Fails for an environment entered in another runspace" {
        $ps = New-ObolPowerShell
        try {
            $null = $ps.AddCommand('Enter-ObolKrb5Environment').AddParameter('Kdc', $kdc).Invoke()
            $config = $env:KRB5_CONFIG

            { Exit-ObolKrb5Environment } |
                Should-Throw -FullyQualifiedErrorId 'Krb5EnvironmentNotOwned,Obol.Commands.ExitObolKrb5Environment'

            $env:KRB5_CONFIG | Should-Be $config
        }
        finally {
            $ps.Dispose()
        }
        [Environment]::GetEnvironmentVariable('KRB5_CONFIG') | Should-BeNull
    }

    It "Restores the prompt" {
        $prompt = ${function:global:prompt}
        Enter-ObolKrb5Environment $kdc

        Exit-ObolKrb5Environment

        [object]::ReferenceEquals(${function:global:prompt}, $prompt) | Should-BeTrue
    }

    It "Leaves a prompt changed after entering" {
        $prompt = ${function:global:prompt}
        try {
            Enter-ObolKrb5Environment $kdc
            ${function:global:prompt} = { 'changed> ' }

            Exit-ObolKrb5Environment

            prompt | Should-Be 'changed> '
        }
        finally {
            ${function:global:prompt} = $prompt
        }
    }

    It "Stays entered after the KDC is stopped" {
        Enter-ObolKrb5Environment $kdc
        $config = $env:KRB5_CONFIG

        Stop-ObolKdc $kdc

        $env:KRB5_CONFIG | Should-Be $config
        Exit-ObolKrb5Environment
        [Environment]::GetEnvironmentVariable('KRB5_CONFIG') | Should-BeNull
    }

    Context "Native environment" -Skip:$IsWindows {
        It "Restores the native environment" {
            $before = Get-NativeEnvironmentVariable KRB5_CONFIG
            Enter-ObolKrb5Environment $kdc -SetNativeEnvironment

            Exit-ObolKrb5Environment

            Get-NativeEnvironmentVariable KRB5_CONFIG | Should-Be $before
        }
    }
}
