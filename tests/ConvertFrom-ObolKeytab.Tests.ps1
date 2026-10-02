using module ../output/Obol
using namespace System.IO

BeforeAll { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

Describe "ConvertFrom-ObolKeytab" {
    BeforeAll {
        # The hex of a keytab entry for host/<Component>@R with a 16 byte key 000102..0F, laid out by hand from the
        # MIT keytab file format. Kvno32 is the hex of the 32-bit kvno, empty to leave it out.
        Function New-EntryHex {
            param (
                [string]$Component = 'a',
                [int]$NameType = 1,
                [int]$Kvno8 = 1,
                [int]$EncryptionType = 17,
                [string]$Kvno32 = '00000001',
                [string]$Trailer = ''
            )

            $componentBytes = [Text.Encoding]::UTF8.GetBytes($Component)
            $body = '0002' + '000152' + '0004686F7374' +
                ('{0:X4}' -f $componentBytes.Length) + [Convert]::ToHexString($componentBytes) +
                ('{0:X8}' -f $NameType) + '01020304' + ('{0:X2}' -f $Kvno8) + ('{0:X4}' -f $EncryptionType) +
                '0010' + '000102030405060708090A0B0C0D0E0F' + $Kvno32 + $Trailer
            ('{0:X8}' -f ($body.Length / 2)) + $body
        }
    }

    BeforeEach {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $password = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
        $user = $kdc | New-ObolPrincipal user -Password $password
        $service = $kdc | New-ObolPrincipal HTTP/web -Alias HTTP/web.example.test
        $path = [Path]::Combine($TestDrive, 'test.keytab')
    }

    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
        Remove-Item $path -Force -ErrorAction Ignore
    }

    It "Reads the entries of keytab bytes" {
        $actual = ConvertFrom-ObolKeytab (ConvertTo-ObolKeytab $user)

        $actual.Count | Should-Be 2
        $actual[0] | Should-HaveType ([Obol.ObolKeytabEntry])
        $actual.FullName | Should-BeCollection user@EXAMPLE.TEST, user@EXAMPLE.TEST
        $actual.EncryptionType | Should-BeCollection Aes256Sha1, Aes128Sha1
        [Convert]::ToHexStringLower($actual[0].Key) |
            Should-Be 'cc7517320a9c6cd13de0ea137e9fe17e5724178754077af2a8c9ca80dd582a90'
    }

    It "Reads the bytes from ConvertTo-ObolKeytab in the pipeline" {
        $actual = ConvertTo-ObolKeytab $user, $service | ConvertFrom-ObolKeytab

        $actual.Count | Should-Be 6
    }

    It "Reads the bytes of a variable unrolled by the pipeline" {
        $keytab = ConvertTo-ObolKeytab $service

        $actual = $keytab | ConvertFrom-ObolKeytab

        $actual.FullName | Should-BeCollection @(
            'HTTP/web@EXAMPLE.TEST'
            'HTTP/web@EXAMPLE.TEST'
            'HTTP/web.example.test@EXAMPLE.TEST'
            'HTTP/web.example.test@EXAMPLE.TEST'
        )
    }

    It "Reads the same entries as Import-ObolKeytab" {
        New-TestKeytab $path @(
            @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 300; EncryptionType = 18 }
            @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 300; EncryptionType = 23; Key = [byte[]]::new(16) }
        )
        $expected = Import-ObolKeytab $path

        $actual = ConvertFrom-ObolKeytab ([File]::ReadAllBytes($path))

        ($actual | ForEach-Object { "$_ $($_.Timestamp) $([Convert]::ToHexString($_.Key))" }) |
            Should-BeCollection ($expected | ForEach-Object { "$_ $($_.Timestamp) $([Convert]::ToHexString($_.Key))" })
        [int]$actual[1].EncryptionType | Should-Be 23
    }

    It "Reads a keytab from base64" {
        $base64 = [Convert]::ToBase64String((ConvertTo-ObolKeytab $user))

        $actual = ConvertFrom-ObolKeytab ([Convert]::FromBase64String($base64))

        $actual.FullName | Select-Object -Unique | Should-Be user@EXAMPLE.TEST
    }

    It "Outputs nothing for a keytab without entries" {
        ConvertFrom-ObolKeytab ([byte[]](5, 2)) | Should-BeNull
    }

    It "Writes an error for data that is not a keytab" {
        $actual = ConvertFrom-ObolKeytab ([Text.Encoding]::UTF8.GetBytes('not a keytab')) -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidKeytab,Obol.Commands.ConvertFromObolKeytab'
        [string]$err[0] | Should-BeLikeString 'The data is not a valid keytab: *version is 0x6E6F*'
    }

    It "Writes an error for a truncated keytab" {
        $keytab = ConvertTo-ObolKeytab $user

        ConvertFrom-ObolKeytab $keytab[0..($keytab.Length - 10)] -ErrorAction SilentlyContinue -ErrorVariable err

        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidKeytab,Obol.Commands.ConvertFromObolKeytab'
    }

    It "Reads the MIT keytab format" {
        $actual = ConvertFrom-ObolKeytab ([Convert]::FromHexString('0502' + (New-EntryHex)))

        $actual.Name | Should-Be host/a
        $actual.Realm | Should-Be R
        $actual.NameType | Should-Be ([Obol.ObolPrincipalNameType]::Principal)
        $actual.Timestamp | Should-Be ([DateTime]::UnixEpoch.AddSeconds(0x01020304).ToLocalTime())
        $actual.Timestamp.Kind | Should-Be Local
        $actual.Kvno | Should-Be 1
        $actual.EncryptionType | Should-Be Aes128Sha1
        [Convert]::ToHexString($actual.Key) | Should-Be '000102030405060708090A0B0C0D0E0F'
    }

    It "Reads <Case>" -TestCases @(
        @{ Case = 'the 8-bit kvno without a 32-bit kvno'; Entry = @{ Kvno8 = 7; Kvno32 = '' }; Property = 'Kvno'; Expected = 7 }
        @{ Case = 'the 8-bit kvno when the 32-bit kvno is 0'; Entry = @{ Kvno8 = 7; Kvno32 = '00000000' }; Property = 'Kvno'; Expected = 7 }
        @{ Case = 'the 32-bit kvno over the 8-bit kvno'; Entry = @{ Kvno8 = 7; Kvno32 = '00000107' }; Property = 'Kvno'; Expected = 263 }
        @{ Case = 'an entry with data after the kvno'; Entry = @{ Trailer = 'FFFFFFFF01' }; Property = 'Kvno'; Expected = 1 }
        @{ Case = 'a name type other than KRB5_NT_PRINCIPAL'; Entry = @{ NameType = 2 }; Property = 'NameType'; Expected = [Obol.ObolPrincipalNameType]::ServiceInstance }
        @{ Case = 'a negative MS-KILE name type'; Entry = @{ NameType = -128 }; Property = 'NameType'; Expected = [Obol.ObolPrincipalNameType]::MsPrincipal }
        @{ Case = "a component with '/'"; Entry = @{ Component = 'a/b' }; Property = 'Name'; Expected = 'host/a\/b' }
        @{ Case = 'an unsupported encryption type'; Entry = @{ EncryptionType = 23 }; Property = 'EncryptionType'; Expected = 23 }
    ) {
        param ($Entry, $Property, $Expected)

        $actual = ConvertFrom-ObolKeytab ([Convert]::FromHexString('0502' + (New-EntryHex @Entry)))

        $actual.$Property | Should-Be $Expected
    }

    It "Skips deleted entries" {
        # A negative length marks a deleted entry, its bytes are skipped.
        $hole = 'FFFFFFF6' + ('00' * 10)

        $actual = ConvertFrom-ObolKeytab ([Convert]::FromHexString('0502' + $hole + (New-EntryHex) + $hole))

        $actual.Name | Should-Be host/a
    }

    It "Fails for version 0x0501" {
        ConvertFrom-ObolKeytab ([Convert]::FromHexString('0501' + (New-EntryHex))) -ErrorAction SilentlyContinue -ErrorVariable err

        [string]$err[0] | Should-BeLikeString '*version is 0x0501*'
    }

    It "Keeps a name type of <NameType> through ConvertTo-ObolKeytab" -TestCases @(
        @{ NameType = 99; Hex = '00000063' }
        @{ NameType = -128; Hex = 'FFFFFF80' }
    ) {
        param ($NameType, $Hex)

        $data = [Convert]::FromHexString('0502' + (New-EntryHex -NameType $NameType))

        $entry = ConvertFrom-ObolKeytab $data

        [int]$entry.NameType | Should-Be $NameType
        $actual = ConvertTo-ObolKeytab -Entry $entry
        [Convert]::ToHexString($actual) | Should-Be ([Convert]::ToHexString($data))
        [Convert]::ToHexString($actual, 2 + 4 + 2 + 3 + 6 + 3, 4) | Should-Be $Hex
    }
}

