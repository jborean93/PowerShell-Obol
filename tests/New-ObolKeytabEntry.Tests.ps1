using module ../output/Obol
using namespace System.IO

BeforeAll { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

Describe "New-ObolKeytabEntry" {
    BeforeAll {
        $password = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
    }

    It "Creates entries from a password with the default salt" {
        $before = [DateTime]::Now.AddSeconds(-1)

        $actual = New-ObolKeytabEntry user@EXAMPLE.TEST -Password $password

        $actual.Count | Should-Be 2
        $actual[0] | Should-HaveType ([Obol.ObolKeytabEntry])
        $actual.FullName | Should-BeCollection user@EXAMPLE.TEST, user@EXAMPLE.TEST
        $actual.Kvno | Should-BeCollection 1, 1
        $actual.NameType | Should-BeCollection Principal, Principal
        $actual.EncryptionType | Should-BeCollection Aes256Sha1, Aes128Sha1
        $actual[0].Timestamp.Kind | Should-Be Local
        $actual[0].Timestamp | Should-BeGreaterThanOrEqual $before
        # The keys MIT ktutil derives for user@EXAMPLE.TEST with this password.
        ($actual | ForEach-Object { [Convert]::ToHexStringLower($_.Key) }) | Should-BeCollection @(
            'cc7517320a9c6cd13de0ea137e9fe17e5724178754077af2a8c9ca80dd582a90'
            '25bd781ec92083ac830b18f2dced9315'
        )
    }

    It "Creates entries with a salt, kvno and encryption types" {
        $salt = ConvertTo-ObolSalt svc_web -Realm CORP.EXAMPLE -SaltType ADUser

        $actual = New-ObolKeytabEntry HTTP/web.corp.example -Realm CORP.EXAMPLE -Password $password -Salt $salt -Kvno 5 -EncryptionType Aes256Sha1

        $actual.FullName | Should-Be HTTP/web.corp.example@CORP.EXAMPLE
        $actual.Kvno | Should-Be 5
        [Convert]::ToHexStringLower($actual.Key) |
            Should-Be 'ab8c3a5300b091e044f72526e1669fa999e4cb152042325df4f4864ffdf38e5c'
    }

    It "Gives the same keys as a KDC principal with the same password" {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        try {
            $null = $kdc | New-ObolPrincipal HTTP/web -Password $password -EncryptionType Aes256Sha384, Aes128Sha256
            $path = [Path]::Combine($TestDrive, 'kdc.keytab')
            $kdc | Export-ObolKeytab $path HTTP/web

            $actual = New-ObolKeytabEntry HTTP/web@EXAMPLE.TEST -Password $password -EncryptionType Aes256Sha384, Aes128Sha256

            ($actual | ForEach-Object { [Convert]::ToHexString($_.Key) }) |
                Should-BeCollection (Import-ObolKeytab $path | ForEach-Object { [Convert]::ToHexString($_.Key) })
        }
        finally {
            $kdc | Stop-ObolKdc
        }
    }

    It "Creates an entry from a key" {
        $key = [byte[]](1..32)

        $actual = New-ObolKeytabEntry host/web@EXAMPLE.TEST -Key $key -EncryptionType Aes256Sha1 -Kvno 300

        $actual.Kvno | Should-Be 300
        $actual.EncryptionType | Should-Be Aes256Sha1
        [Convert]::ToHexString($actual.Key) | Should-Be ([Convert]::ToHexString($key))
        $key[0] = 99
        $actual.Key[0] | Should-Be 1
    }

    It "Fails for <Case>" -TestCases @(
        @{ Case = 'a name without a realm'; Params = @{ Name = 'user'; Password = 'x' }; ErrorId = 'RealmRequired' }
        @{ Case = 'a different realm'; Params = @{ Name = 'user@A.TEST'; Realm = 'B.TEST'; Password = 'x' }; ErrorId = 'PrincipalRealmMismatch' }
        @{ Case = 'an invalid name'; Params = @{ Name = 'a//b@A.TEST'; Password = 'x' }; ErrorId = 'InvalidPrincipalName' }
        @{ Case = 'an empty password'; Params = @{ Name = 'user@A.TEST'; Password = '' }; ErrorId = 'EmptyPassword' }
        @{ Case = 'duplicate encryption types'; Params = @{ Name = 'user@A.TEST'; Password = 'x'; EncryptionType = 'Aes128Sha1', 'Aes128Sha1' }; ErrorId = 'InvalidEncryptionType' }
        @{ Case = 'a key with two encryption types'; Params = @{ Name = 'user@A.TEST'; Key = [byte[]]::new(16); EncryptionType = 'Aes128Sha1', 'Aes256Sha1' }; ErrorId = 'InvalidEncryptionType' }
        @{ Case = 'a key of the wrong size'; Params = @{ Name = 'user@A.TEST'; Key = [byte[]]::new(16); EncryptionType = 'Aes256Sha1' }; ErrorId = 'InvalidKeyLength' }
    ) {
        param ($Params, $ErrorId)

        if ($Params.ContainsKey('Password')) {
            $Params.Password = if ($Params.Password) {
                ConvertTo-SecureString $Params.Password -AsPlainText -Force
            }
            else {
                [SecureString]::new()
            }
        }

        { New-ObolKeytabEntry @Params } |
            Should-Throw -FullyQualifiedErrorId "$ErrorId,Obol.Commands.NewObolKeytabEntry"
    }

    It "Fails for an undefined encryption type" {
        $etype = [Enum]::ToObject([Obol.ObolEncryptionType], 23)

        { New-ObolKeytabEntry user@A.TEST -Key ([byte[]]::new(16)) -EncryptionType $etype } |
            Should-Throw -FullyQualifiedErrorId 'InvalidEncryptionType,Obol.Commands.NewObolKeytabEntry'
    }

    It "Creates the entries of a principal" {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        try {
            $principal = $kdc | New-ObolPrincipal HTTP/web -Password $password -Alias HTTP/web.example.test -Kvno 4
            $path = [Path]::Combine($TestDrive, 'principal.keytab')
            Export-ObolKeytab $path -Principal $principal

            $actual = $principal | New-ObolKeytabEntry

            $actual.Count | Should-Be 4
            $actual.FullName | Should-BeCollection @(
                'HTTP/web@EXAMPLE.TEST'
                'HTTP/web@EXAMPLE.TEST'
                'HTTP/web.example.test@EXAMPLE.TEST'
                'HTTP/web.example.test@EXAMPLE.TEST'
            )
            $actual.Kvno | Select-Object -Unique | Should-Be 4
            ($actual | ForEach-Object { [Convert]::ToHexString($_.Key) }) |
                Should-BeCollection (Import-ObolKeytab $path | ForEach-Object { [Convert]::ToHexString($_.Key) })
        }
        finally {
            Get-ObolKdc | Stop-ObolKdc
        }
    }

    It "Filters the entries of a principal before exporting them" {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        try {
            $null = $kdc | New-ObolPrincipal HTTP/web -Alias HTTP/web.example.test
            $path = [Path]::Combine($TestDrive, 'filtered.keytab')

            $kdc | Get-ObolPrincipal HTTP/web |
                New-ObolKeytabEntry |
                Where-Object { $_.EncryptionType -eq 'Aes256Sha1' -and $_.Name -eq 'HTTP/web' } |
                Export-ObolKeytab $path

            $actual = Import-ObolKeytab $path
            $actual.FullName | Should-Be HTTP/web@EXAMPLE.TEST
            $actual.EncryptionType | Should-Be Aes256Sha1
        }
        finally {
            Get-ObolKdc | Stop-ObolKdc
        }
    }

    It "Does not take a name with a principal" {
        $parameters = (Get-Command New-ObolKeytabEntry).ParameterSets |
            Where-Object Name -eq Principal |
            ForEach-Object { $_.Parameters.Name }

        $parameters | Should-NotContainCollection Name
        $parameters | Should-NotContainCollection Kvno
        $parameters | Should-NotContainCollection Realm
    }
}
