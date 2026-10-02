using module ../output/Obol
using namespace System.IO

BeforeAll { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

Describe "New-ObolPrincipalSetting" {
    It "Creates a setting with the defaults" {
        $actual = New-ObolPrincipalSetting

        $actual | Should-HaveType ([Obol.ObolPrincipalSetting])
        $actual.Password | Should-BeNull
        $actual.Flag | Should-Be ([Obol.ObolPrincipalFlag]::None)
        $actual.EncryptionType | Should-BeNull
        $actual.Alias | Should-BeNull
        $actual.Rid | Should-BeNull
        $actual.Key | Should-BeNull
        $actual.Kvno | Should-BeNull
        $actual.Salt | Should-BeNull
    }

    It "Creates a setting with keys from a keytab" {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        try {
            $path = [Path]::Combine($TestDrive, 'setting.keytab')
            $kdc | New-ObolPrincipal HTTP/web | Set-ObolPrincipal -NewRandomKey
            $kdc | Export-ObolKeytab $path HTTP/web -Force
            $entries = Import-ObolKeytab $path

            $actual = New-ObolPrincipalSetting -Key $entries -Kvno 2 -Salt CUSTOM

            $actual.Key | Should-BeCollection $entries
            $actual.Kvno | Should-Be 2
            $actual.Salt | Should-Be CUSTOM

            $other = Start-ObolKdc EXAMPLE.TEST -Principal @{ 'HTTP/web' = $actual }
            $principal = $other | Get-ObolPrincipal HTTP/web
            $principal.Kvno | Should-Be 2
            $principal.Salt | Should-Be CUSTOM
        }
        finally {
            Get-ObolKdc | Stop-ObolKdc
        }
    }

    It "Creates a principal with the kvno of a setting" {
        try {
            $setting = New-ObolPrincipalSetting -Kvno 12

            $kdc = Start-ObolKdc EXAMPLE.TEST -Principal @{ 'HTTP/web' = $setting }

            ($kdc | Get-ObolPrincipal HTTP/web).Kvno | Should-Be 12
        }
        finally {
            Get-ObolKdc | Stop-ObolKdc
        }
    }

    It "Does not bind <Case>" -TestCases @(
        @{ Case = 'Key with Password'; Params = @{ Password = (ConvertTo-SecureString a -AsPlainText -Force) } }
        @{ Case = 'Key with EncryptionType'; Params = @{ EncryptionType = 'Aes256Sha1' } }
    ) {
        param ($Params)

        $entry = New-ObolKeytabEntry HTTP/web@EXAMPLE.TEST -Key ([byte[]]::new(32)) -EncryptionType Aes256Sha1

        { New-ObolPrincipalSetting -Key $entry @Params } |
            Should-Throw -FullyQualifiedErrorId 'AmbiguousParameterSet,Obol.Commands.NewObolPrincipalSetting'
    }

    It "Does not bind Salt without Password or Key" {
        { New-ObolPrincipalSetting -Salt abc } |
            Should-Throw -FullyQualifiedErrorId 'AmbiguousParameterSet,Obol.Commands.NewObolPrincipalSetting'
    }

    It "Fails with a negative kvno" {
        { New-ObolPrincipalSetting -Kvno -1 } |
            Should-Throw -FullyQualifiedErrorId 'ParameterArgumentValidationError,Obol.Commands.NewObolPrincipalSetting'
    }

    It "Creates a setting with every value" {
        $password = ConvertTo-SecureString -String 'Password123!' -AsPlainText -Force

        $actual = New-ObolPrincipalSetting -Password $password -Flag DoesNotRequirePreAuth -EncryptionType Aes256Sha384, Aes128Sha256 -Alias a, b -Rid 500

        $actual.Password | Should-BeSame $password
        $actual.Flag | Should-Be ([Obol.ObolPrincipalFlag]::DoesNotRequirePreAuth)
        $actual.EncryptionType | Should-BeCollection @(
            [Obol.ObolEncryptionType]::Aes256Sha384
            [Obol.ObolEncryptionType]::Aes128Sha256
        )
        $actual.Alias | Should-BeCollection @('a', 'b')
        $actual.Rid | Should-Be 500
    }

    It "Fails with an invalid RID <Value>" -TestCases @(
        @{ Value = 0 }
        @{ Value = -1 }
    ) {
        param ($Value)

        { New-ObolPrincipalSetting -Rid $Value } |
            Should-Throw -FullyQualifiedErrorId 'ParameterArgumentValidationError,Obol.Commands.NewObolPrincipalSetting'
    }

    It "Casts a hashtable to a setting" {
        $actual = [Obol.ObolPrincipalSetting]@{
            flag = 'DoesNotRequirePreAuth'
            EncryptionType = 'Aes128Sha1'
            Alias = 'a'
            Rid = '600'
        }

        $actual.Flag | Should-Be ([Obol.ObolPrincipalFlag]::DoesNotRequirePreAuth)
        $actual.EncryptionType | Should-BeCollection @([Obol.ObolEncryptionType]::Aes128Sha1)
        $actual.Alias | Should-BeCollection @('a')
        $actual.Rid | Should-Be 600
    }

    It "Fails to cast a hashtable with an unknown property" {
        { [Obol.ObolPrincipalSetting]@{ Foo = 1 } } | Should-Throw -ExceptionMessage "*The property 'Foo' was not found*"
    }
}
