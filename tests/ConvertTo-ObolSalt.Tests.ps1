using module ../output/Obol
using namespace System.IO

BeforeAll { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

Describe "ConvertTo-ObolSalt" {
    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
    }

    It "Gets the default salt of <Name>" -TestCases @(
        @{ Name = 'user@EXAMPLE.TEST'; Realm = $null; Expected = 'EXAMPLE.TESTuser' }
        @{ Name = 'user'; Realm = 'EXAMPLE.TEST'; Expected = 'EXAMPLE.TESTuser' }
        @{ Name = 'user@EXAMPLE.TEST'; Realm = 'EXAMPLE.TEST'; Expected = 'EXAMPLE.TESTuser' }
        @{ Name = 'HTTP/web.example.test'; Realm = 'EXAMPLE.TEST'; Expected = 'EXAMPLE.TESTHTTPweb.example.test' }
        @{ Name = 'user@example.test'; Realm = $null; Expected = 'example.testuser' }
        @{ Name = 'HTTP/a\/b'; Realm = 'EXAMPLE.TEST'; Expected = 'EXAMPLE.TESTHTTPa/b' }
    ) {
        param ($Name, $Realm, $Expected)

        $params = if ($Realm) { @{ Realm = $Realm } } else { @{} }

        $actual = ConvertTo-ObolSalt $Name @params

        $actual | Should-Be $Expected
    }

    It "Gets the default salt with -SaltType Default" {
        ConvertTo-ObolSalt user@EXAMPLE.TEST -SaltType Default | Should-Be EXAMPLE.TESTuser
    }

    It "Gets the salts of names from the pipeline" {
        $actual = 'user@EXAMPLE.TEST', 'HTTP/web@OTHER.TEST' | ConvertTo-ObolSalt

        $actual | Should-BeCollection EXAMPLE.TESTuser, OTHER.TESTHTTPweb
    }

    It "Gets the salts of principals from the pipeline" {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $password = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
        $null = $kdc | New-ObolPrincipal HTTP/web.example.test -Password $password

        $actual = $kdc | Get-ObolPrincipal HTTP/* | ConvertTo-ObolSalt

        $actual | Should-Be ($kdc | Get-ObolPrincipal HTTP/*).Salt
    }

    It "Gets the salts of keytab entries from the pipeline" {
        $entries = @(
            New-ObolKeytabEntry user@A.TEST -Key ([byte[]]::new(16)) -EncryptionType Aes128Sha1
            New-ObolKeytabEntry HTTP/web@B.TEST -Key ([byte[]]::new(16)) -EncryptionType Aes128Sha1
        )

        $actual = $entries | ConvertTo-ObolSalt

        $actual | Should-BeCollection A.TESTuser, B.TESTHTTPweb
    }

    It "Uses the realm of each pipeline object" {
        $entry = New-ObolKeytabEntry user@A.TEST -Key ([byte[]]::new(16)) -EncryptionType Aes128Sha1

        # The string has no Realm property so it gets the realm from its own name, not the previous object.
        $actual = $entry, 'other@B.TEST' | ConvertTo-ObolSalt

        $actual | Should-BeCollection A.TESTuser, B.TESTother
    }

    It "Gets the AD salt of user <Name>" -TestCases @(
        @{ Name = 'svc_web'; Realm = 'corp.example'; Expected = 'CORP.EXAMPLEsvc_web' }
        @{ Name = 'Svc_Web'; Realm = 'CORP.EXAMPLE'; Expected = 'CORP.EXAMPLESvc_Web' }
    ) {
        param ($Name, $Realm, $Expected)

        ConvertTo-ObolSalt $Name -Realm $Realm -SaltType ADUser | Should-Be $Expected
    }

    It "Gets the AD salts of users from the pipeline" {
        $actual = 'svc_web', 'svc_sql' | ConvertTo-ObolSalt -Realm CORP.EXAMPLE -SaltType ADUser

        $actual | Should-BeCollection CORP.EXAMPLEsvc_web, CORP.EXAMPLEsvc_sql
    }

    It "Gets the AD salt of computer <Name>" -TestCases @(
        @{ Name = 'WEB$'; Expected = 'CORP.EXAMPLEhostweb.corp.example' }
        @{ Name = 'Web'; Expected = 'CORP.EXAMPLEhostweb.corp.example' }
    ) {
        param ($Name, $Expected)

        ConvertTo-ObolSalt $Name -Realm Corp.Example -SaltType ADComputer | Should-Be $Expected
    }

    It "Writes an error for <Case>" -TestCases @(
        @{ Case = 'a name without a realm'; Params = @{ Name = 'user' }; ErrorId = 'RealmRequired' }
        @{ Case = 'a different realm'; Params = @{ Name = 'user@A.TEST'; Realm = 'B.TEST' }; ErrorId = 'PrincipalRealmMismatch' }
        @{ Case = 'an invalid name'; Params = @{ Name = 'a//b'; Realm = 'A.TEST' }; ErrorId = 'InvalidPrincipalName' }
        @{ Case = 'an AD user without a realm'; Params = @{ Name = 'user'; SaltType = 'ADUser' }; ErrorId = 'RealmRequired' }
        @{ Case = 'a UPN'; Params = @{ Name = 'user@corp.example'; SaltType = 'ADUser' }; ErrorId = 'InvalidADUser' }
        @{ Case = 'a DOMAIN\user name'; Params = @{ Name = 'CORP\user'; Realm = 'CORP.EXAMPLE'; SaltType = 'ADUser' }; ErrorId = 'InvalidADUser' }
        @{ Case = 'an AD computer without a realm'; Params = @{ Name = 'web'; SaltType = 'ADComputer' }; ErrorId = 'RealmRequired' }
        @{ Case = 'a computer DNS name'; Params = @{ Name = 'web.corp.example'; Realm = 'CORP.EXAMPLE'; SaltType = 'ADComputer' }; ErrorId = 'InvalidADComputer' }
        @{ Case = 'only $'; Params = @{ Name = '$'; Realm = 'CORP.EXAMPLE'; SaltType = 'ADComputer' }; ErrorId = 'InvalidADComputer' }
    ) {
        param ($Params, $ErrorId)

        $actual = ConvertTo-ObolSalt @Params -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be "$ErrorId,Obol.Commands.ConvertToObolSalt"
    }

    It "Continues with the next pipeline input after an error" {
        $actual = 'user', 'other@A.TEST' | ConvertTo-ObolSalt -ErrorAction SilentlyContinue -ErrorVariable err

        $err.Count | Should-Be 1
        $actual | Should-Be A.TESTother
    }

    It "Fails for an undefined salt type" {
        $saltType = [Enum]::ToObject([Obol.ObolSaltType], 99)

        { ConvertTo-ObolSalt user@A.TEST -SaltType $saltType } |
            Should-Throw -FullyQualifiedErrorId 'InvalidSaltType,Obol.Commands.ConvertToObolSalt'
    }
}
