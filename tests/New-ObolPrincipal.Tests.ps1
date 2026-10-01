using namespace System.IO

BeforeDiscovery { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

BeforeAll {
    $password = ConvertTo-SecureString -String 'Password123!' -AsPlainText -Force
}

Describe "New-ObolPrincipal" {
    BeforeEach {
        $kdc = Start-ObolKdc EXAMPLE.TEST
    }

    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
    }

    It "Creates a user with a password" {
        $actual = New-ObolPrincipal -Kdc $kdc -Name user -Password $password

        $actual | Should-HaveType ([Obol.ObolPrincipal])
        $actual.Name | Should-Be user
        $actual.Realm | Should-Be EXAMPLE.TEST
        $actual.FullName | Should-Be user@EXAMPLE.TEST
        $actual.Kvno | Should-Be 1
        $actual.EncryptionType | Should-BeCollection @(
            [Obol.ObolEncryptionType]::Aes256Sha1
            [Obol.ObolEncryptionType]::Aes128Sha1
        )
        $actual.Flag | Should-Be ([Obol.ObolPrincipalFlag]::None)
        $actual.Alias.Count | Should-Be 0
        $actual.Sid | Should-BeLikeString "$($kdc.DomainSid)-*"
        $actual.ToString() | Should-Be user@EXAMPLE.TEST
    }

    It "Creates a service with a random key" {
        $actual = $kdc | New-ObolPrincipal HTTP/web.example.test

        $actual.Name | Should-Be HTTP/web.example.test
        $actual.FullName | Should-Be HTTP/web.example.test@EXAMPLE.TEST
    }

    It "Creates a principal that does not require pre-authentication" {
        $actual = New-ObolPrincipal -Kdc $kdc user -Password $password -Flag DoesNotRequirePreAuth

        $actual.Flag | Should-Be ([Obol.ObolPrincipalFlag]::DoesNotRequirePreAuth)
    }

    It "Creates a principal with encryption types" {
        $actual = New-ObolPrincipal -Kdc $kdc user -Password $password -EncryptionType Aes256Sha384, Aes128Sha1

        $actual.EncryptionType | Should-BeCollection @(
            [Obol.ObolEncryptionType]::Aes256Sha384
            [Obol.ObolEncryptionType]::Aes128Sha1
        )
    }

    It "Fails with invalid encryption types <Value>" -TestCases @(
        @{ Value = @() }
        @{ Value = 'Aes128Sha1', 'Aes128Sha1' }
    ) {
        param ($Value)

        $actual = New-ObolPrincipal -Kdc $kdc user -EncryptionType $Value -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidEncryptionType,Obol.Commands.NewObolPrincipal'
    }

    It "Creates a principal with aliases" {
        $actual = New-ObolPrincipal -Kdc $kdc HTTP/web.example.test -Alias HTTP/web, HTTP/other@EXAMPLE.TEST

        $actual.Alias | Should-BeCollection @('HTTP/web', 'HTTP/other')
    }

    It "Fails with an alias in use" {
        $null = New-ObolPrincipal -Kdc $kdc HTTP/web

        $actual = New-ObolPrincipal -Kdc $kdc HTTP/web.example.test -Alias HTTP/web -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err[0].FullyQualifiedErrorId | Should-Be 'PrincipalAlreadyExists,Obol.Commands.NewObolPrincipal'
        [string]$err[0] | Should-Be "The principal name 'HTTP/web@EXAMPLE.TEST' is already used"
        Get-ObolPrincipal -Kdc $kdc HTTP/web.example.test | Should-BeNull
    }

    It "Fails with an invalid alias" {
        $actual = New-ObolPrincipal -Kdc $kdc HTTP/web.example.test -Alias HTTP/web@OTHER -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err[0].FullyQualifiedErrorId | Should-Be 'PrincipalRealmMismatch,Obol.Commands.NewObolPrincipal'
    }

    It "Gives each principal a unique SID" {
        $user1 = New-ObolPrincipal -Kdc $kdc user1 -Password $password
        $user2 = New-ObolPrincipal -Kdc $kdc user2 -Password $password

        $user1.Sid | Should-NotBe $user2.Sid
        $user1.Sid | Should-BeLikeString "$($kdc.DomainSid)-*"
    }

    It "Creates a principal with a RID" {
        $actual = New-ObolPrincipal -Kdc $kdc admin -Password $password -Rid 500

        $actual.Sid | Should-Be "$($kdc.DomainSid)-500"
    }

    It "Skips RIDs that are used when picking the next RID" {
        $null = New-ObolPrincipal -Kdc $kdc user1 -Rid 1001
        $user2 = New-ObolPrincipal -Kdc $kdc user2
        $user3 = New-ObolPrincipal -Kdc $kdc user3

        $user2.Sid | Should-Be "$($kdc.DomainSid)-1000"
        $user3.Sid | Should-Be "$($kdc.DomainSid)-1002"
    }

    It "Fails when the RID is already used" {
        $actual = New-ObolPrincipal -Kdc $kdc user -Rid 502 -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'PrincipalRidAlreadyUsed,Obol.Commands.NewObolPrincipal'
        [string]$err[0] | Should-Be "The RID 502 is already used by the principal 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST'"
    }

    It "Fails with an invalid RID <Value>" -TestCases @(
        @{ Value = 0 }
        @{ Value = -1 }
    ) {
        param ($Value)

        { New-ObolPrincipal -Kdc $kdc user -Rid $Value } |
            Should-Throw -FullyQualifiedErrorId 'ParameterArgumentValidationError,Obol.Commands.NewObolPrincipal'
    }

    It "Creates a principal with -Setting" {
        $setting = New-ObolPrincipalSetting -Password $password -Flag DoesNotRequirePreAuth -EncryptionType Aes128Sha1 -Alias other -Rid 600

        $actual = $kdc | New-ObolPrincipal user -Setting $setting

        $actual.FullName | Should-Be user@EXAMPLE.TEST
        $actual.Flag | Should-Be ([Obol.ObolPrincipalFlag]::DoesNotRequirePreAuth)
        $actual.EncryptionType | Should-Be ([Obol.ObolEncryptionType]::Aes128Sha1)
        $actual.Alias | Should-BeCollection @('other')
        $actual.Sid | Should-Be "$($kdc.DomainSid)-600"
    }

    It "Creates a principal with -Setting from a hashtable" {
        $actual = $kdc | New-ObolPrincipal user -Setting @{ Password = $password; Rid = 600 }

        $actual.Sid | Should-Be "$($kdc.DomainSid)-600"
    }

    It "Fails to use -Setting with -Password" {
        { $kdc | New-ObolPrincipal user -Setting @{} -Password $password } |
            Should-Throw -FullyQualifiedErrorId 'AmbiguousParameterSet,Obol.Commands.NewObolPrincipal'
    }

    It "Fails with an invalid -Setting <Case>" -TestCases @(
        @{ Case = 'rid'; Setting = @{ Rid = -1 }; ErrorId = 'InvalidRid' }
        @{ Case = 'password'; Setting = @{ Password = [SecureString]::new() }; ErrorId = 'EmptyPassword' }
        @{ Case = 'alias'; Setting = @{ Alias = '' }; ErrorId = 'InvalidPrincipalName' }
        @{ Case = 'encryption type'; Setting = @{ EncryptionType = @() }; ErrorId = 'InvalidEncryptionType' }
    ) {
        param ($Setting, $ErrorId)

        $actual = $kdc | New-ObolPrincipal user -Setting $Setting -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be "$ErrorId,Obol.Commands.NewObolPrincipal"
    }

    It "Fails with an undefined flag" {
        $flag = [Enum]::ToObject([Obol.ObolPrincipalFlag], 0x8000)

        $actual = $kdc | New-ObolPrincipal svc -Flag $flag -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidFlag,Obol.Commands.NewObolPrincipal'
        [string]$err[0] | Should-Be "Flag value 32768 contains values that are not supported, valid values are None, DoesNotRequirePreAuth, NotDelegated, TrustedForDelegation"
    }

    It "Fails with an undefined flag in -Setting" {
        $setting = New-ObolPrincipalSetting
        $setting.Flag = [Enum]::ToObject([Obol.ObolPrincipalFlag], 0x8001)

        $actual = $kdc | New-ObolPrincipal svc -Setting $setting -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidFlag,Obol.Commands.NewObolPrincipal'
    }

    It "Fails with an undefined encryption type" {
        $etype = [Enum]::ToObject([Obol.ObolEncryptionType], 99)

        $actual = $kdc | New-ObolPrincipal svc -EncryptionType $etype -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidEncryptionType,Obol.Commands.NewObolPrincipal'
        [string]$err[0] | Should-Be "EncryptionType '99' is not supported, valid values are Aes128Sha1, Aes256Sha1, Aes128Sha256, Aes256Sha384"
    }

    It "Accepts the KDC realm in the name" {
        $actual = New-ObolPrincipal -Kdc $kdc user@EXAMPLE.TEST -Password $password

        $actual.Name | Should-Be user
    }

    It "Fails when the realm does not match the KDC" {
        $actual = New-ObolPrincipal -Kdc $kdc user@example.test -Password $password -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'PrincipalRealmMismatch,Obol.Commands.NewObolPrincipal'
        [string]$err[0] | Should-Be "The principal realm 'example.test' does not match the KDC realm 'EXAMPLE.TEST'"
    }

    It "Fails with an invalid name '<Name>'" -TestCases @(
        @{ Name = 'HTTP/'; Message = 'a name component is empty' }
        @{ Name = '/web'; Message = 'a name component is empty' }
        @{ Name = 'a//b'; Message = 'a name component is empty' }
        @{ Name = 'user@'; Message = "the realm after '@' is empty" }
        @{ Name = 'user@A@B'; Message = "only one unescaped '@' is allowed" }
        @{ Name = 'user@A/B'; Message = "the realm cannot contain an unescaped '/'" }
        @{ Name = 'user\'; Message = "the name ends with an incomplete '\' escape" }
    ) {
        param ($Name, $Message)

        $actual = New-ObolPrincipal -Kdc $kdc $Name -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidPrincipalName,Obol.Commands.NewObolPrincipal'
        [string]$err[0] | Should-Be "Invalid principal name '$Name': $Message"
    }

    It "Creates a principal with more than two components" {
        $actual = New-ObolPrincipal -Kdc $kdc HTTP/web.example.test/svc

        $actual.Name | Should-Be HTTP/web.example.test/svc
        $actual.FullName | Should-Be HTTP/web.example.test/svc@EXAMPLE.TEST
    }

    It "Creates a principal with escaped characters '<Name>'" -TestCases @(
        @{ Name = 'a\/b'; Expected = 'a\/b' }
        @{ Name = 'a\@b'; Expected = 'a\@b' }
        @{ Name = 'a\\b'; Expected = 'a\\b' }
        @{ Name = 'a\tb'; Expected = 'a\tb' }
        @{ Name = 'a\nb'; Expected = 'a\nb' }
        @{ Name = 'a\bb'; Expected = 'a\bb' }
        @{ Name = 'a\0b'; Expected = 'a\0b' }
        @{ Name = 'a\qb'; Expected = 'aqb' }
        @{ Name = 'a\@b@EXAMPLE.TEST'; Expected = 'a\@b' }
    ) {
        param ($Name, $Expected)

        $actual = New-ObolPrincipal -Kdc $kdc $Name

        $actual.Name | Should-Be $Expected
        $actual.FullName | Should-Be "$Expected@EXAMPLE.TEST"
        Get-ObolPrincipal -Kdc $kdc -Name $Expected | Should-BeSame $actual
    }

    It "Treats an escaped '/' as part of the component" {
        $escaped = New-ObolPrincipal -Kdc $kdc 'HTTP\/web'
        $actual = New-ObolPrincipal -Kdc $kdc HTTP/web

        $actual | Should-NotBeSame $escaped
        $escaped.Name | Should-Be 'HTTP\/web'
        $actual.Name | Should-Be 'HTTP/web'
    }

    It "Fails when the principal already exists" {
        $null = New-ObolPrincipal -Kdc $kdc user -Password $password

        $actual = New-ObolPrincipal -Kdc $kdc user -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'PrincipalAlreadyExists,Obol.Commands.NewObolPrincipal'
        [string]$err[0] | Should-Be "The principal name 'user@EXAMPLE.TEST' is already used"
    }

    It "Fails to create krbtgt" {
        $null = New-ObolPrincipal -Kdc $kdc krbtgt/EXAMPLE.TEST -ErrorAction SilentlyContinue -ErrorVariable err

        $err[0].FullyQualifiedErrorId | Should-Be 'PrincipalAlreadyExists,Obol.Commands.NewObolPrincipal'
    }

    It "Allows names differing by case" {
        $null = New-ObolPrincipal -Kdc $kdc user -Password $password
        $actual = New-ObolPrincipal -Kdc $kdc USER -Password $password

        $actual.Name | Should-Be USER
    }

    It "Fails for names differing by case with -CaseInsensitivePrincipal" {
        $kdc = Start-ObolKdc OTHER.TEST -CaseInsensitivePrincipal
        $null = New-ObolPrincipal -Kdc $kdc user -Password $password

        $null = New-ObolPrincipal -Kdc $kdc USER -Password $password -ErrorAction SilentlyContinue -ErrorVariable err

        $err[0].FullyQualifiedErrorId | Should-Be 'PrincipalAlreadyExists,Obol.Commands.NewObolPrincipal'
    }

    It "Fails with an empty password" {
        $empty = [System.Security.SecureString]::new()

        $actual = New-ObolPrincipal -Kdc $kdc user -Password $empty -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err[0].FullyQualifiedErrorId | Should-Be 'EmptyPassword,Obol.Commands.NewObolPrincipal'
    }

    It "Does not create the principal with -WhatIf" {
        $actual = New-ObolPrincipal -Kdc $kdc user -Password $password -WhatIf

        $actual | Should-BeNull
        Get-ObolPrincipal -Kdc $kdc -Name user | Should-BeNull
    }

    It "Creates a principal in each KDC from the pipeline" {
        $other = Start-ObolKdc OTHER.TEST

        $actual = $kdc, $other | New-ObolPrincipal HTTP/web.example.test

        $actual.Count | Should-Be 2
        $actual[0].FullName | Should-Be HTTP/web.example.test@EXAMPLE.TEST
        $actual[1].FullName | Should-Be HTTP/web.example.test@OTHER.TEST
    }
}
