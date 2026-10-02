using module ../output/Obol
using namespace System.IO

BeforeAll { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

Describe "Export-ObolKrb5Config" {
    BeforeEach {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $path = [Path]::Combine($TestDrive, 'krb5.conf')
    }

    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
        Remove-Item $path -Force -ErrorAction Ignore
    }

    It "Writes the krb5.conf of a KDC" {
        $actual = Export-ObolKrb5Config $path -Kdc $kdc

        $actual | Should-BeNull
        [File]::ReadAllText($path) | Should-Be (ConvertTo-ObolKrb5Config $kdc)
    }

    It "Writes UTF-8 without a BOM and with LF line endings" {
        $kdc | Export-ObolKrb5Config $path

        $bytes = [File]::ReadAllBytes($path)
        $bytes[0] | Should-Be ([byte][char]'[')
        $bytes | Should-NotContainCollection ([byte]13)
    }

    It "Writes KDCs from the pipeline" {
        $other = Start-ObolKdc OTHER.TEST

        $kdc, $other | Export-ObolKrb5Config $path

        [File]::ReadAllText($path) | Should-Be (ConvertTo-ObolKrb5Config $kdc, $other)
    }

    It "Fails if the file exists" {
        Set-Content $path existing

        { $kdc | Export-ObolKrb5Config $path } |
            Should-Throw -FullyQualifiedErrorId 'FileAlreadyExists,Obol.Commands.ExportObolKrb5Config'

        Get-Content $path | Should-Be existing
    }

    It "Overwrites the file with -Force" {
        Set-Content $path ('x' * 4096)

        $kdc | Export-ObolKrb5Config $path -Force

        [File]::ReadAllText($path) | Should-Be (ConvertTo-ObolKrb5Config $kdc)
    }

    It "Fails for a path that is not on the file system" {
        { $kdc | Export-ObolKrb5Config Env:\test } |
            Should-Throw -FullyQualifiedErrorId 'PathNotFileSystem,Obol.Commands.ExportObolKrb5Config'
    }

    It "Fails for a directory that does not exist" {
        $missing = [Path]::Combine($TestDrive, 'missing', 'krb5.conf')

        { $kdc | Export-ObolKrb5Config $missing } |
            Should-Throw -FullyQualifiedErrorId 'FileOpenFailed,Obol.Commands.ExportObolKrb5Config'
    }

    It "Fails for a directory that does not exist with -Force" {
        $missing = [Path]::Combine($TestDrive, 'missing', 'krb5.conf')

        { $kdc | Export-ObolKrb5Config $missing -Force } |
            Should-Throw -FullyQualifiedErrorId 'FileOpenFailed,Obol.Commands.ExportObolKrb5Config'
    }

    It "Does not create a file when no KDC can be written" {
        $kdc | Stop-ObolKdc

        $kdc | Export-ObolKrb5Config $path -ErrorAction SilentlyContinue -ErrorVariable err

        $err[0].FullyQualifiedErrorId | Should-Be 'KdcNotRunning,Obol.Commands.ExportObolKrb5Config'
        Test-Path $path | Should-BeFalse
    }

    It "Writes the krb5.conf for a provider" {
        $kdc | Export-ObolKrb5Config $path -Provider Heimdal

        [File]::ReadAllText($path) | Should-Be (ConvertTo-ObolKrb5Config $kdc -Provider Heimdal)
    }

    It "Fails for an undefined provider" {
        $provider = [Enum]::ToObject([Obol.ObolKrb5Provider], 99)

        { $kdc | Export-ObolKrb5Config $path -Provider $provider } |
            Should-Throw -FullyQualifiedErrorId 'InvalidProvider,Obol.Commands.ExportObolKrb5Config'

        Test-Path $path | Should-BeFalse
    }

    It "Does not write the file with -WhatIf" {
        $kdc | Export-ObolKrb5Config $path -WhatIf

        Test-Path $path | Should-BeFalse
    }
}
