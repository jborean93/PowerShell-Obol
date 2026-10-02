using module ../output/Obol
using namespace System.IO

BeforeAll { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

Describe "ConvertTo-ObolKeytab" {
    BeforeEach {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $password = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
        $user = $kdc | New-ObolPrincipal user -Password $password
        $service = $kdc | New-ObolPrincipal HTTP/web -Alias HTTP/web.example.test
    }

    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
    }

    It "Outputs the keytab of a principal as bytes" {
        $actual = ConvertTo-ObolKeytab $user

        $actual.GetType() | Should-Be ([byte[]])
        $actual[0] | Should-Be 5
        $actual[1] | Should-Be 2
        $entries = ConvertFrom-ObolKeytab $actual
        $entries.FullName | Should-BeCollection user@EXAMPLE.TEST, user@EXAMPLE.TEST
        [Convert]::ToHexStringLower($entries[0].Key) |
            Should-Be 'cc7517320a9c6cd13de0ea137e9fe17e5724178754077af2a8c9ca80dd582a90'
    }

    It "Outputs the same entries Export-ObolKeytab writes" {
        $path = [Path]::Combine($TestDrive, 'export.keytab')
        Export-ObolKeytab $path -Principal $user, $service

        $actual = ConvertTo-ObolKeytab $user, $service

        $expected = Import-ObolKeytab $path
        Remove-Item $path
        (ConvertFrom-ObolKeytab $actual | ForEach-Object { "$($_.FullName) $($_.Kvno) $([Convert]::ToHexString($_.Key))" }) |
            Should-BeCollection ($expected | ForEach-Object { "$($_.FullName) $($_.Kvno) $([Convert]::ToHexString($_.Key))" })
    }

    It "Combines principals from the pipeline into one keytab" {
        $actual = $user, $service, $user | ConvertTo-ObolKeytab

        $actual.Count | Should-BeGreaterThan 1
        (ConvertFrom-ObolKeytab $actual).FullName | Select-Object -Unique | Should-BeCollection @(
            'user@EXAMPLE.TEST'
            'HTTP/web@EXAMPLE.TEST'
            'HTTP/web.example.test@EXAMPLE.TEST'
        )
    }

    It "Outputs the keytab of principals by name" {
        $actual = $kdc | ConvertTo-ObolKeytab user

        (ConvertFrom-ObolKeytab $actual).FullName | Select-Object -Unique | Should-Be user@EXAMPLE.TEST
    }

    It "Outputs keytab entries unchanged" {
        $path = [Path]::Combine($TestDrive, 'entries.keytab')
        Export-ObolKeytab $path -Principal $service
        $expected = [File]::ReadAllBytes($path)

        $actual = Import-ObolKeytab $path | ConvertTo-ObolKeytab

        Remove-Item $path
        [Convert]::ToHexString($actual) | Should-Be ([Convert]::ToHexString($expected))
    }

    It "Writes an error for a name that does not exist and outputs nothing without other principals" {
        $actual = $kdc | ConvertTo-ObolKeytab missing -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err[0].FullyQualifiedErrorId | Should-Be 'PrincipalNotFound,Obol.Commands.ConvertToObolKeytab'
    }

    It "Writes the MIT keytab format" {
        # Laid out by hand from the MIT keytab file format, only the timestamp is the time the cmdlet ran.
        $actual = ConvertTo-ObolKeytab $user

        $timestamps = (Read-TestKeytab -Data $actual).Timestamp | ForEach-Object { '{0:X8}' -f $_.ToUnixTimeSeconds() }
        $name = '0001' + '000C' + [Convert]::ToHexString([Text.Encoding]::ASCII.GetBytes('EXAMPLE.TEST')) +
            '0004' + [Convert]::ToHexString([Text.Encoding]::ASCII.GetBytes('user'))
        $expected = '0502' +
            '00000047' + $name + '00000001' + $timestamps[0] + '01' + '0012' + '0020' +
            'CC7517320A9C6CD13DE0EA137E9FE17E5724178754077AF2A8C9CA80DD582A90' + '00000001' +
            '00000037' + $name + '00000001' + $timestamps[1] + '01' + '0011' + '0010' +
            '25BD781EC92083AC830B18F2DCED9315' + '00000001'
        [Convert]::ToHexString($actual) | Should-Be $expected
        $timestamps[0] | Should-Be $timestamps[1]
        [DateTimeOffset]::FromUnixTimeSeconds([Convert]::ToInt64($timestamps[0], 16)) |
            Should-BeGreaterThan ([DateTimeOffset]::UtcNow.AddMinutes(-1))
    }

    It "Writes a kvno over 255, escaped names and aliases" {
        $principal = $kdc | New-ObolPrincipal 'HTTP/a\/b' -Alias HTTP/c -Kvno 300 -EncryptionType Aes128Sha1

        $actual = Read-TestKeytab -Data (ConvertTo-ObolKeytab $principal)

        $actual.Count | Should-Be 2
        $actual[0].Components | Should-BeCollection HTTP, 'a/b'
        $actual[1].Components | Should-BeCollection HTTP, c
        $actual.Kvno8 | Should-BeCollection 44, 44
        $actual.Kvno | Should-BeCollection 300, 300
        $actual.NameType | Should-BeCollection 1, 1
    }

    It "Writes entries made outside the module unchanged" {
        $path = [Path]::Combine($TestDrive, 'outside.keytab')
        New-TestKeytab $path @(
            @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 300; EncryptionType = 18 }
            @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 300; EncryptionType = 23; Key = [byte[]]::new(16) }
        )
        $expected = [File]::ReadAllBytes($path)

        $actual = Import-ObolKeytab $path | ConvertTo-ObolKeytab

        Remove-Item $path
        [Convert]::ToHexString($actual) | Should-Be ([Convert]::ToHexString($expected))
    }
}

