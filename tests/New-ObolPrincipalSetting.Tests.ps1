using namespace System.IO

BeforeDiscovery { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

Describe "New-ObolPrincipalSetting" {
    It "Creates a setting with the defaults" {
        $actual = New-ObolPrincipalSetting

        $actual | Should-HaveType ([Obol.ObolPrincipalSetting])
        $actual.Password | Should-BeNull
        $actual.Flag | Should-Be ([Obol.ObolPrincipalFlag]::None)
        $actual.EncryptionType | Should-BeNull
        $actual.Alias | Should-BeNull
        $actual.Rid | Should-BeNull
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
