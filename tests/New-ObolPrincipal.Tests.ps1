using module ../output/Obol
using namespace System.IO

BeforeAll {
    . ([Path]::Combine($PSScriptRoot, 'common.ps1'))

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
            [Obol.Kerberos.EncryptionType]::Aes256Sha1
            [Obol.Kerberos.EncryptionType]::Aes128Sha1
        )
        $actual.Flag | Should-Be ([Obol.Kerberos.PacUserAccountControl]::None)
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
        $actual = New-ObolPrincipal -Kdc $kdc user -Password $password -Flag DontRequirePreAuth

        $actual.Flag | Should-Be ([Obol.Kerberos.PacUserAccountControl]::DontRequirePreAuth)
    }

    It "Creates a principal with encryption types" {
        $actual = New-ObolPrincipal -Kdc $kdc user -Password $password -EncryptionType Aes256Sha384, Aes128Sha1

        $actual.EncryptionType | Should-BeCollection @(
            [Obol.Kerberos.EncryptionType]::Aes256Sha384
            [Obol.Kerberos.EncryptionType]::Aes128Sha1
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
        $setting = New-ObolPrincipalSetting -Password $password -Flag DontRequirePreAuth -EncryptionType Aes128Sha1 -Alias other -Rid 600

        $actual = $kdc | New-ObolPrincipal user -Setting $setting

        $actual.FullName | Should-Be user@EXAMPLE.TEST
        $actual.Flag | Should-Be ([Obol.Kerberos.PacUserAccountControl]::DontRequirePreAuth)
        $actual.EncryptionType | Should-Be ([Obol.Kerberos.EncryptionType]::Aes128Sha1)
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

    It "Fails with an account control flag the KDC does not support: <Case>" -TestCases @(
        @{ Case = 'a PAC value'; Flag = 'AccountDisabled, DontRequirePreAuth'; Unsupported = 'AccountDisabled' }
        @{ Case = 'an undefined value'; Flag = [Enum]::ToObject([Obol.Kerberos.PacUserAccountControl], 0x80000000); Unsupported = '2147483648' }
    ) {
        $actual = $kdc | New-ObolPrincipal svc -Flag $Flag -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidFlag,Obol.Commands.NewObolPrincipal'
        [string]$err[0] | Should-Be "Flag '$Unsupported' is not supported, valid values are None, TrustedForDelegation, NotDelegated, DontRequirePreAuth, NoAuthDataRequired"
    }

    It "Fails with an unsupported flag in -Setting" {
        $setting = New-ObolPrincipalSetting
        $setting.Flag = [Obol.Kerberos.PacUserAccountControl]::SmartcardRequired

        $actual = $kdc | New-ObolPrincipal svc -Setting $setting -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidFlag,Obol.Commands.NewObolPrincipal'
    }

    It "Fails with an encryption type a principal cannot have keys for: <Case>" -TestCases @(
        @{ Case = 'a registered type'; EncryptionType = [Obol.Kerberos.EncryptionType]::Rc4Hmac }
        @{ Case = 'an undefined value'; EncryptionType = [Enum]::ToObject([Obol.Kerberos.EncryptionType], 99) }
    ) {
        # The parameter only accepts the types the KDC can create keys for.
        { $kdc | New-ObolPrincipal svc -EncryptionType $EncryptionType } |
            Should-Throw -FullyQualifiedErrorId 'ParameterArgumentValidationError,Obol.Commands.NewObolPrincipal'
    }

    It "Fails with an unsupported encryption type in a setting" {
        # A setting cast from a hashtable is not checked by the parameter validation.
        $setting = [Obol.ObolPrincipalSetting]@{ EncryptionType = 'Rc4Hmac' }

        $actual = $kdc | New-ObolPrincipal svc -Setting $setting -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidEncryptionType,Obol.Commands.NewObolPrincipal'
        [string]$err[0] | Should-Be "EncryptionType 'Rc4Hmac' is not supported, valid values are Aes256Sha1, Aes128Sha1, Aes256Sha384, Aes128Sha256"
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

Describe "New-ObolPrincipal keys" {
    BeforeAll {
        Function Get-Key([byte]$Value, [int]$Length = 32) {
            , [byte[]]([Linq.Enumerable]::Repeat($Value, $Length))
        }
    }

    BeforeEach {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $path = [Path]::Combine($TestDrive, 'test.keytab')
    }

    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
        Remove-Item $path -Force -ErrorAction Ignore
    }

    It "Creates a principal with the keys and kvno of a keytab" {
        $source = Start-ObolKdc EXAMPLE.TEST
        $original = $source | New-ObolPrincipal HTTP/web -EncryptionType Aes128Sha1, Aes256Sha384
        $original | Set-ObolPrincipal -NewRandomKey
        $source | Export-ObolKeytab $path HTTP/web

        $actual = $kdc | New-ObolPrincipal HTTP/web -Key (Import-ObolKeytab $path)

        $actual.Kvno | Should-Be 2
        $actual.EncryptionType | Should-BeCollection Aes128Sha1, Aes256Sha384
        $actual.Salt | Should-Be EXAMPLE.TESTHTTPweb
        $exported = [Path]::Combine($TestDrive, 'exported.keytab')
        $kdc | Export-ObolKeytab $exported HTTP/web
        (Import-ObolKeytab $exported | ForEach-Object { [Convert]::ToHexString($_.Key) }) |
            Should-BeCollection (Import-ObolKeytab $path | ForEach-Object { [Convert]::ToHexString($_.Key) })
    }

    It "Uses the entries for an alias and ignores other principals and realms" {
        New-TestKeytab $path @(
            @{ Name = 'HTTP/other'; Realm = 'EXAMPLE.TEST'; Kvno = 9; EncryptionType = 18; Key = (Get-Key 1) }
            @{ Name = 'HTTP/web'; Realm = 'OTHER.TEST'; Kvno = 9; EncryptionType = 18; Key = (Get-Key 2) }
            @{ Name = 'HTTP/web.example.test'; Realm = 'EXAMPLE.TEST'; Kvno = 3; EncryptionType = 18; Key = (Get-Key 3) }
        )

        $actual = $kdc | New-ObolPrincipal HTTP/web -Alias HTTP/web.example.test -Key (Import-ObolKeytab $path) -WarningVariable warn

        $warn.Count | Should-Be 0
        $actual.Kvno | Should-Be 3
        $actual.EncryptionType | Should-Be Aes256Sha1
        $kdc | Export-ObolKeytab ([Path]::Combine($TestDrive, 'out.keytab')) HTTP/web
        [Convert]::ToHexString((Import-ObolKeytab ([Path]::Combine($TestDrive, 'out.keytab')))[0].Key) |
            Should-Be ([Convert]::ToHexString((Get-Key 3)))
    }

    It "Matches names case insensitively on a case insensitive KDC" {
        $kdc = Start-ObolKdc EXAMPLE.TEST -CaseInsensitivePrincipal
        New-TestKeytab $path @(@{ Name = 'http/WEB'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 18 })

        $actual = $kdc | New-ObolPrincipal HTTP/web -Key (Import-ObolKeytab $path)

        $actual.EncryptionType | Should-Be Aes256Sha1
    }

    It "Warns for entries that cannot be used" {
        New-TestKeytab $path @(
            @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 2; EncryptionType = 23; Key = (Get-Key 1 16) }
            @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 2; EncryptionType = 18; Key = (Get-Key 1 16) }
            @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 2; EncryptionType = 17; Key = (Get-Key 1 16) }
        )

        $actual = $kdc | New-ObolPrincipal HTTP/web -Key (Import-ObolKeytab $path) -WarningAction SilentlyContinue -WarningVariable warn

        $warn.Count | Should-Be 2
        [string]$warn[0] | Should-Be 'Ignoring the keytab entry for HTTP/web@EXAMPLE.TEST with kvno 2, encryption type Rc4Hmac is not supported'
        [string]$warn[1] | Should-Be 'Ignoring the keytab entry for HTTP/web@EXAMPLE.TEST with kvno 2, the Aes256Sha1 key is 16 bytes but should be 32'
        $actual.EncryptionType | Should-Be Aes128Sha1
    }

    It "Uses the newest kvno and warns for types only in older keys" {
        New-TestKeytab $path @(
            @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 17 }
            @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 18; Key = (Get-Key 1) }
            @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 2; EncryptionType = 18; Key = (Get-Key 2) }
        )

        $actual = $kdc | New-ObolPrincipal HTTP/web -Key (Import-ObolKeytab $path) -WarningAction SilentlyContinue -WarningVariable warn

        $actual.Kvno | Should-Be 2
        $actual.EncryptionType | Should-Be Aes256Sha1
        $warn.Count | Should-Be 1
        [string]$warn[0] | Should-Be 'Ignoring the Aes128Sha1 key of HTTP/web@EXAMPLE.TEST with kvno 1, the newest keys with kvno 2 have no Aes128Sha1 key'
    }

    It "Uses the keys of the kvno given by -Kvno" {
        New-TestKeytab $path @(
            @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 17 }
            @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 18 }
            @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 2; EncryptionType = 18 }
        )

        $actual = $kdc | New-ObolPrincipal HTTP/web -Key (Import-ObolKeytab $path) -Kvno 1 -WarningVariable warn

        $warn.Count | Should-Be 0
        $actual.Kvno | Should-Be 1
        $actual.EncryptionType | Should-BeCollection Aes128Sha1, Aes256Sha1
    }

    It "Fails for <Case>" -TestCases @(
        @{
            Case = 'no matching entries'
            Entry = @(@{ Name = 'HTTP/other'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 18 })
            Kvno = $null
            ErrorId = 'NoKeytabKey'
            Message = 'No usable keys for HTTP/web@EXAMPLE.TEST were found in the keytab entries*'
        }
        @{
            Case = 'only unsupported entries'
            Entry = @(@{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 23; Key = [byte[]]::new(16) })
            Kvno = $null
            ErrorId = 'NoKeytabKey'
            Message = 'No usable keys*'
        }
        @{
            Case = 'a kvno that does not exist'
            Entry = @(@{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 18 })
            Kvno = 5
            ErrorId = 'KeytabKvnoNotFound'
            Message = '*with kvno 5 were found*the usable kvnos are 1'
        }
        @{
            Case = 'different keys for the same type and kvno'
            Entry = @(
                @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 18 }
                @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 18; Key = [byte[]](@(1) + @(0) * 31) }
            )
            Kvno = $null
            ErrorId = 'KeytabKeyConflict'
            Message = 'The keytab entries have different Aes256Sha1 keys with kvno 1*'
        }
    ) {
        param ($Entry, $Kvno, $ErrorId, $Message)

        New-TestKeytab $path $Entry
        $params = if ($null -ne $Kvno) { @{ Kvno = $Kvno } } else { @{} }

        $actual = $kdc | New-ObolPrincipal HTTP/web -Key (Import-ObolKeytab $path) @params -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be "$ErrorId,Obol.Commands.NewObolPrincipal"
        [string]$err[0] | Should-BeLikeString $Message
        $kdc | Get-ObolPrincipal HTTP/web | Should-BeNull
    }

    It "Does not bind <Case>" -TestCases @(
        @{ Case = 'Key with Password'; Params = @{ Password = (ConvertTo-SecureString a -AsPlainText -Force) }; UseKey = $true }
        @{ Case = 'Key with EncryptionType'; Params = @{ EncryptionType = 'Aes256Sha1' }; UseKey = $true }
        @{ Case = 'Salt without Password or Key'; Params = @{ Salt = 'abc' }; UseKey = $false }
    ) {
        param ($Params, $UseKey)

        if ($UseKey) {
            New-TestKeytab $path @(@{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 18 })
            $Params.Key = Import-ObolKeytab $path
        }

        { $kdc | New-ObolPrincipal HTTP/web @Params } |
            Should-Throw -FullyQualifiedErrorId 'AmbiguousParameterSet,Obol.Commands.NewObolPrincipal'
        $kdc | Get-ObolPrincipal HTTP/web | Should-BeNull
    }

    It "Fails for a setting with <Case>" -TestCases @(
        @{ Case = 'Key and Password'; Setting = @{ Password = (ConvertTo-SecureString a -AsPlainText -Force) }; UseKey = $true; ErrorId = 'KeyWithPassword' }
        @{ Case = 'Key and EncryptionType'; Setting = @{ EncryptionType = 'Aes256Sha1' }; UseKey = $true; ErrorId = 'KeyWithEncryptionType' }
        @{ Case = 'Salt without Password or Key'; Setting = @{ Salt = 'abc' }; UseKey = $false; ErrorId = 'SaltWithoutKey' }
    ) {
        param ($Setting, $UseKey, $ErrorId)

        # A setting cast from a hashtable skips parameter binding so the cmdlet checks the combination itself.
        if ($UseKey) {
            New-TestKeytab $path @(@{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 18 })
            $Setting.Key = Import-ObolKeytab $path
        }

        $kdc | New-ObolPrincipal HTTP/web -Setting ([Obol.ObolPrincipalSetting]$Setting) -ErrorAction SilentlyContinue -ErrorVariable err

        $err[0].FullyQualifiedErrorId | Should-Be "$ErrorId,Obol.Commands.NewObolPrincipal"
        $kdc | Get-ObolPrincipal HTTP/web | Should-BeNull
    }

    It "Creates a principal with a kvno and <Case>" -TestCases @(
        @{ Case = 'a password'; UsePassword = $true }
        @{ Case = 'random keys'; UsePassword = $false }
    ) {
        param ($UsePassword)

        $params = if ($UsePassword) { @{ Password = $password } } else { @{} }

        $actual = $kdc | New-ObolPrincipal HTTP/web -Kvno 300 @params

        $actual.Kvno | Should-Be 300
        $kdc | Export-ObolKeytab $path HTTP/web
        (Import-ObolKeytab $path).Kvno | Should-BeCollection 300, 300
    }

    It "Creates a principal with the keys of a password and an AD account kvno" {
        $salt = ConvertTo-ObolSalt svc_web -Realm CORP.EXAMPLE -SaltType ADUser
        $expected = New-ObolKeytabEntry HTTP/web@EXAMPLE.TEST -Password $password -Salt $salt -Kvno 7

        $actual = $kdc | New-ObolPrincipal HTTP/web -Password $password -Salt $salt -Kvno 7

        $actual.Kvno | Should-Be 7
        $kdc | Export-ObolKeytab $path HTTP/web
        (Import-ObolKeytab $path | ForEach-Object { "$($_.Kvno) $([Convert]::ToHexString($_.Key))" }) |
            Should-BeCollection ($expected | ForEach-Object { "$($_.Kvno) $([Convert]::ToHexString($_.Key))" })
    }

    It "Derives the keys from a password with a salt" {
        $salt = ConvertTo-ObolSalt svc_web -Realm corp.example -SaltType ADUser

        $actual = $kdc | New-ObolPrincipal HTTP/web -Password $password -Salt $salt -EncryptionType Aes256Sha1

        $actual.Salt | Should-Be CORP.EXAMPLEsvc_web
        $kdc | Export-ObolKeytab $path HTTP/web
        # The key MIT ktutil derives for 'Password123!' with this salt.
        [Convert]::ToHexStringLower((Import-ObolKeytab $path).Key) |
            Should-Be 'ab8c3a5300b091e044f72526e1669fa999e4cb152042325df4f4864ffdf38e5c'
    }

    It "Sets the salt of keys from a keytab" {
        New-TestKeytab $path @(@{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 18 })

        $actual = $kdc | New-ObolPrincipal HTTP/web -Key (Import-ObolKeytab $path) -Salt CUSTOM

        $actual.Salt | Should-Be CUSTOM
    }

    It "Creates a principal with keys from a setting" {
        New-TestKeytab $path @(@{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 4; EncryptionType = 17 })
        $setting = [Obol.ObolPrincipalSetting]@{ Key = Import-ObolKeytab $path; Salt = 'CUSTOM' }

        $actual = $kdc | New-ObolPrincipal HTTP/web -Setting $setting

        $actual.Kvno | Should-Be 4
        $actual.Salt | Should-Be CUSTOM
    }

    It "Fails for a negative Kvno in a setting" {
        New-TestKeytab $path @(@{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 4; EncryptionType = 17 })
        $setting = [Obol.ObolPrincipalSetting]@{ Key = Import-ObolKeytab $path; Kvno = -1 }

        $kdc | New-ObolPrincipal HTTP/web -Setting $setting -ErrorAction SilentlyContinue -ErrorVariable err

        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidKvno,Obol.Commands.NewObolPrincipal'
    }

    It "Ignores null entries in a setting" {
        New-TestKeytab $path @(@{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 4; EncryptionType = 17 })
        $setting = [Obol.ObolPrincipalSetting]@{ Key = @($null; Import-ObolKeytab $path) }

        $actual = $kdc | New-ObolPrincipal HTTP/web -Setting $setting

        $actual.Kvno | Should-Be 4
    }
}
