using module ../output/Obol
using namespace System.IO

BeforeAll { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

Describe "Export-ObolKeytab" {
    BeforeAll {
        $pass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
    }

    BeforeEach {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $user = New-ObolPrincipal -Kdc $kdc user -Password $pass
        $service = New-ObolPrincipal -Kdc $kdc HTTP/web.example.test -Alias HTTP/web
        $path = [Path]::Combine($TestDrive, 'test.keytab')
    }

    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
        Remove-Item $path -Force -ErrorAction Ignore
    }

    It "Exports the keys of a principal" {
        $before = [DateTimeOffset]::FromUnixTimeSeconds([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())

        $actual = Export-ObolKeytab $path -Principal $user

        $actual | Should-BeNull
        $entries = Read-TestKeytab $path
        $entries.Count | Should-Be 2
        $entries.Name | Should-BeCollection user@EXAMPLE.TEST, user@EXAMPLE.TEST
        $entries.NameType | Should-BeCollection 1, 1
        $entries.Kvno | Should-BeCollection 1, 1
        $entries.Kvno8 | Should-BeCollection 1, 1
        $entries.EncryptionType | Should-BeCollection Aes256Sha1, Aes128Sha1
        $entries[0].Timestamp | Should-BeGreaterThanOrEqual $before
        $entries[0].Timestamp | Should-BeLessThanOrEqual ([DateTimeOffset]::UtcNow)

        # The keys MIT ktutil derives for user@EXAMPLE.TEST with this password.
        $entries.Key | Should-BeCollection @(
            'cc7517320a9c6cd13de0ea137e9fe17e5724178754077af2a8c9ca80dd582a90'
            '25bd781ec92083ac830b18f2dced9315'
        )
    }

    It "Creates the file readable only by the owner" -Skip:$IsWindows {
        Export-ObolKeytab $path -Principal $user

        (Get-Item $path).UnixFileMode | Should-Be ([UnixFileMode]'UserRead, UserWrite')
    }

    It "Exports entries for the name and each alias" {
        Export-ObolKeytab $path -Principal $service

        $entries = Read-TestKeytab $path
        $entries.Name | Should-BeCollection @(
            'HTTP/web.example.test@EXAMPLE.TEST'
            'HTTP/web.example.test@EXAMPLE.TEST'
            'HTTP/web@EXAMPLE.TEST'
            'HTTP/web@EXAMPLE.TEST'
        )
        $entries[2].Key | Should-Be $entries[0].Key
        $entries[3].Key | Should-Be $entries[1].Key
    }

    It "Exports principals from the pipeline once each" {
        @($user; $kdc | Get-ObolPrincipal user, HTTP/*) | Export-ObolKeytab $path

        $entries = Read-TestKeytab $path
        $entries.Name | Select-Object -Unique | Should-BeCollection @(
            'user@EXAMPLE.TEST'
            'HTTP/web.example.test@EXAMPLE.TEST'
            'HTTP/web@EXAMPLE.TEST'
        )
        $entries.Count | Should-Be 6
    }

    It "Exports principals by name with the KDC from the pipeline" {
        $kdc | Export-ObolKeytab $path user, HTTP/web

        (Read-TestKeytab $path).Name | Select-Object -Unique | Should-BeCollection @(
            'user@EXAMPLE.TEST'
            'HTTP/web.example.test@EXAMPLE.TEST'
            'HTTP/web@EXAMPLE.TEST'
        )
    }

    It "Exports principals of several KDCs" {
        $other = Start-ObolKdc OTHER.TEST -Principal @{ user = $null }

        $kdc, $other | Get-ObolPrincipal user | Export-ObolKeytab $path

        (Read-TestKeytab $path).Name | Select-Object -Unique | Should-BeCollection user@EXAMPLE.TEST, user@OTHER.TEST
    }

    It "Exports the current kvno and encryption types" {
        $service | Set-ObolPrincipal -NewRandomKey -EncryptionType Aes128Sha256
        foreach ($i in 1..299) {
            $service | Set-ObolPrincipal -NewRandomKey
        }

        Export-ObolKeytab $path -Principal $service

        $entries = Read-TestKeytab $path
        $entries.Count | Should-Be 2
        $entries.EncryptionType | Should-BeCollection Aes128Sha256, Aes128Sha256
        $entries.Kvno | Should-BeCollection 301, 301
        $entries.Kvno8 | Should-BeCollection 45, 45
    }

    It "Exports the krbtgt keys" {
        $kdc | Export-ObolKeytab $path krbtgt/EXAMPLE.TEST

        $entries = Read-TestKeytab $path
        $entries.Name | Select-Object -Unique | Should-Be krbtgt/EXAMPLE.TEST@EXAMPLE.TEST
        $entries.EncryptionType | Should-BeCollection Aes256Sha1, Aes128Sha1, Aes256Sha384, Aes128Sha256
    }

    It "Writes escaped name components as a single component" {
        $kdc | New-ObolPrincipal 'HTTP/a\/b\@c'

        $kdc | Export-ObolKeytab $path 'HTTP/a\/b\@c'

        (Read-TestKeytab $path)[0].Components | Should-BeCollection HTTP, 'a/b@c'
    }

    It "Fails if the file exists" {
        Set-Content $path existing

        { Export-ObolKeytab $path -Principal $user } |
            Should-Throw -FullyQualifiedErrorId 'FileAlreadyExists,Obol.Commands.ExportObolKeytab'

        Get-Content $path | Should-Be existing
    }

    It "Overwrites the file with -Force" {
        Export-ObolKeytab $path -Principal $service

        Export-ObolKeytab $path -Principal $user -Force

        (Read-TestKeytab $path).Name | Select-Object -Unique | Should-Be user@EXAMPLE.TEST
    }

    It "Appends to an existing keytab with -Append" {
        Export-ObolKeytab $path -Principal $user
        $service | Set-ObolPrincipal -NewRandomKey

        Export-ObolKeytab $path -Principal $service -Append

        $entries = Read-TestKeytab $path
        $entries.Count | Should-Be 6
        $entries[0].Name | Should-Be user@EXAMPLE.TEST
        $entries[2].Name | Should-Be HTTP/web.example.test@EXAMPLE.TEST
        $entries[2].Kvno | Should-Be 2
    }

    It "Creates the file with -Append" {
        Export-ObolKeytab $path -Principal $user -Append

        (Read-TestKeytab $path).Count | Should-Be 2
    }

    It "Appends to an empty file" {
        Set-Content $path -Value $null -NoNewline

        Export-ObolKeytab $path -Principal $user -Append

        (Read-TestKeytab $path).Count | Should-Be 2
    }

    It "Fails to append to a file that is not a keytab" {
        Set-Content $path 'not a keytab' -NoNewline

        { Export-ObolKeytab $path -Principal $user -Append } |
            Should-Throw -FullyQualifiedErrorId 'InvalidKeytab,Obol.Commands.ExportObolKeytab'

        Get-Content $path | Should-Be 'not a keytab'
    }

    It "Fails with -Append and -Force" {
        { Export-ObolKeytab $path -Principal $user -Append -Force } |
            Should-Throw -FullyQualifiedErrorId 'AppendWithForce,Obol.Commands.ExportObolKeytab'
    }

    It "Writes an error for a name that does not exist and exports the others" {
        $kdc | Export-ObolKeytab $path missing, user -ErrorAction SilentlyContinue -ErrorVariable err

        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'PrincipalNotFound,Obol.Commands.ExportObolKeytab'
        (Read-TestKeytab $path).Name | Select-Object -Unique | Should-Be user@EXAMPLE.TEST
    }

    It "Does not create a file when no principal is found" {
        $kdc | Export-ObolKeytab $path missing -ErrorAction SilentlyContinue

        Test-Path $path | Should-BeFalse
    }

    It "Resolves a relative path from the current location" {
        Push-Location $TestDrive
        try {
            Export-ObolKeytab test.keytab -Principal $user
        }
        finally {
            Pop-Location
        }

        (Read-TestKeytab $path).Count | Should-Be 2
    }

    It "Fails for a path that is not on the file system" {
        { Export-ObolKeytab Env:\test -Principal $user } |
            Should-Throw -FullyQualifiedErrorId 'PathNotFileSystem,Obol.Commands.ExportObolKeytab'
    }

    It "Does not write the file with -WhatIf" {
        Export-ObolKeytab $path -Principal $user -WhatIf

        Test-Path $path | Should-BeFalse
    }

    It "Exports keytab entries" {
        $password = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
        $entries = New-ObolKeytabEntry HTTP/web@CORP.EXAMPLE -Password $password -Kvno 4

        $entries | Export-ObolKeytab $path

        $actual = Read-TestKeytab $path
        $actual.Name | Should-BeCollection HTTP/web@CORP.EXAMPLE, HTTP/web@CORP.EXAMPLE
        $actual.Kvno | Should-BeCollection 4, 4
        $actual.Key | Should-BeCollection ($entries | ForEach-Object { [Convert]::ToHexStringLower($_.Key) })
        $actual[0].Timestamp | Should-Be ([DateTimeOffset]::FromUnixTimeSeconds(
            [DateTimeOffset]::new($entries[0].Timestamp).ToUnixTimeSeconds()))
    }

    It "Copies a keytab through Import-ObolKeytab unchanged" {
        Export-ObolKeytab $path -Principal $user, $service
        $copy = [Path]::Combine($TestDrive, 'copy.keytab')

        Import-ObolKeytab $path | Export-ObolKeytab $copy

        [Convert]::ToHexString([File]::ReadAllBytes($copy)) |
            Should-Be ([Convert]::ToHexString([File]::ReadAllBytes($path)))
        Remove-Item $copy
    }

    It "Filters the entries of a keytab" {
        Export-ObolKeytab $path -Principal $user, $service
        $filtered = [Path]::Combine($TestDrive, 'filtered.keytab')

        Import-ObolKeytab $path | Where-Object { $_.Name -eq 'HTTP/web' -and $_.EncryptionType -eq 'Aes256Sha1' } |
            Export-ObolKeytab $filtered

        $actual = Read-TestKeytab $filtered
        $actual.Name | Should-Be HTTP/web@EXAMPLE.TEST
        $actual.EncryptionType | Should-Be Aes256Sha1
        Remove-Item $filtered
    }

    It "Appends entries to a keytab" {
        Export-ObolKeytab $path -Principal $user
        $entry = New-ObolKeytabEntry other@EXAMPLE.TEST -Key ([byte[]]::new(16)) -EncryptionType Aes128Sha1

        $entry | Export-ObolKeytab $path -Append

        (Read-TestKeytab $path).Name | Should-BeCollection user@EXAMPLE.TEST, user@EXAMPLE.TEST, other@EXAMPLE.TEST
    }
}
