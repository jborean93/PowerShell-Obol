using module ../output/Obol
using namespace System.IO

BeforeAll { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

Describe "Import-ObolKeytab" {
    BeforeAll {
        $password = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
    }

    BeforeEach {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $path = [Path]::Combine($TestDrive, 'test.keytab')
    }

    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
        Remove-Item ([Path]::Combine($TestDrive, '*')) -Recurse -Force -ErrorAction Ignore
    }

    It "Reads the entries of a keytab" {
        $before = [DateTime]::Now.AddSeconds(-1)
        $null = $kdc | New-ObolPrincipal user -Password $password
        $kdc | Export-ObolKeytab $path user

        $actual = Import-ObolKeytab $path

        $actual.Count | Should-Be 2
        $actual[0] | Should-HaveType ([Obol.ObolKeytabEntry])
        $actual.FullName | Should-BeCollection user@EXAMPLE.TEST, user@EXAMPLE.TEST
        $actual[0].Name | Should-Be user
        $actual[0].Realm | Should-Be EXAMPLE.TEST
        $actual[0].NameType | Should-Be ([Obol.ObolPrincipalNameType]::Principal)
        $actual.Kvno | Should-BeCollection 1, 1
        $actual.EncryptionType | Should-BeCollection Aes256Sha1, Aes128Sha1
        $actual[0].Timestamp.Kind | Should-Be Local
        $actual[0].Timestamp | Should-BeGreaterThanOrEqual $before
        [Convert]::ToHexStringLower($actual[0].Key) |
            Should-Be 'cc7517320a9c6cd13de0ea137e9fe17e5724178754077af2a8c9ca80dd582a90'
        [string]$actual[0] | Should-Be 'user@EXAMPLE.TEST Aes256Sha1 kvno 1'
    }

    It "Reads entries with unsupported encryption types" {
        New-TestKeytab $path @(
            @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 3; EncryptionType = 23; Key = [byte[]]::new(16) }
        )

        $actual = Import-ObolKeytab $path

        [int]$actual.EncryptionType | Should-Be 23
        $actual.Kvno | Should-Be 3
    }

    It "Reads an empty keytab" {
        [File]::WriteAllBytes($path, [byte[]](5, 2))

        Import-ObolKeytab $path | Should-BeNull
    }

    It "Reads keytabs matching a wildcard" {
        New-TestKeytab ([Path]::Combine($TestDrive, 'a.keytab')) @(
            @{ Name = 'a'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 18 }
        )
        New-TestKeytab ([Path]::Combine($TestDrive, 'b.keytab')) @(
            @{ Name = 'b'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 18 }
        )

        $actual = Import-ObolKeytab ([Path]::Combine($TestDrive, '*.keytab'))

        $actual.Name | Sort-Object | Should-BeCollection a, b
    }

    It "Reads keytabs from Get-ChildItem" {
        New-TestKeytab $path @(@{ Name = 'a'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 18 })

        $actual = Get-ChildItem $path | Import-ObolKeytab

        $actual.Name | Should-Be a
    }

    It "Reads a literal path with wildcard characters" {
        $literal = [Path]::Combine($TestDrive, 'a[1].keytab')
        New-TestKeytab $literal @(@{ Name = 'a'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 18 })

        $actual = Import-ObolKeytab -LiteralPath $literal

        $actual.Name | Should-Be a
    }

    It "Writes an error for a path that does not exist" {
        $missing = [Path]::Combine($TestDrive, 'missing.keytab')

        Import-ObolKeytab $missing, $missing -ErrorAction SilentlyContinue -ErrorVariable err

        $err.Count | Should-Be 2
        $err[0].FullyQualifiedErrorId | Should-Be 'PathNotFound,Obol.Commands.ImportObolKeytab'
    }

    It "Writes an error for a literal path that does not exist" {
        Import-ObolKeytab -LiteralPath ([Path]::Combine($TestDrive, 'missing.keytab')) -ErrorAction SilentlyContinue -ErrorVariable err

        $err[0].FullyQualifiedErrorId | Should-Be 'PathNotFound,Obol.Commands.ImportObolKeytab'
    }

    It "Writes an error for a file that is not a keytab and reads the others" {
        Set-Content $path 'not a keytab' -NoNewline
        $other = [Path]::Combine($TestDrive, 'other.keytab')
        New-TestKeytab $other @(@{ Name = 'a'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 18 })

        $actual = Import-ObolKeytab $path, $other -ErrorAction SilentlyContinue -ErrorVariable err

        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidKeytab,Obol.Commands.ImportObolKeytab'
        [string]$err[0] | Should-BeLikeString "*is not a valid keytab: *version is 0x6E6F*"
        $actual.Name | Should-Be a
    }

    It "Writes an error for a path that cannot be read" {
        # A directory cannot be read as a file on any platform.
        $directory = [Path]::Combine($TestDrive, 'folder.keytab')
        $null = New-Item $directory -ItemType Directory

        Import-ObolKeytab -LiteralPath $directory -ErrorAction SilentlyContinue -ErrorVariable err

        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'KeytabReadFailed,Obol.Commands.ImportObolKeytab'
        [string]$err[0] | Should-BeLikeString "Failed to read '*folder.keytab': *"
    }

    It "Writes an error for a path that is not on the file system" {
        Import-ObolKeytab Env:\PATH -ErrorAction SilentlyContinue -ErrorVariable err

        $err[0].FullyQualifiedErrorId | Should-Be 'PathNotFileSystem,Obol.Commands.ImportObolKeytab'
    }
}
