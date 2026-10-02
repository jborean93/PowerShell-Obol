using module ../output/Obol
using namespace System.IO

BeforeAll {
    . ([Path]::Combine($PSScriptRoot, 'common.ps1'))

    $password = ConvertTo-SecureString -String 'Password123!' -AsPlainText -Force
}

Describe "Set-ObolPrincipal" {
    BeforeEach {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $user = New-ObolPrincipal -Kdc $kdc user -Password $password
        $service = New-ObolPrincipal -Kdc $kdc HTTP/web.example.test -Alias HTTP/web
    }

    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
    }

    It "Sets a new password" {
        $actual = Set-ObolPrincipal $user -Password (ConvertTo-SecureString -String 'Other1!' -AsPlainText -Force)

        $actual | Should-BeNull
        $user.Kvno | Should-Be 2
    }

    It "Sets new random keys from the pipeline" {
        $user, $service | Set-ObolPrincipal -NewRandomKey

        $user.Kvno | Should-Be 2
        $service.Kvno | Should-Be 2
    }

    It "Outputs the principal with -PassThru" {
        $actual = $service | Set-ObolPrincipal -NewRandomKey -PassThru

        $actual | Should-BeSame $service
    }

    It "Keeps a subset of the encryption types without new keys" {
        Set-ObolPrincipal $service -EncryptionType Aes128Sha1

        $service.EncryptionType | Should-Be ([Obol.ObolEncryptionType]::Aes128Sha1)
        $service.Kvno | Should-Be 1
    }

    It "Fails with a repeated encryption type" {
        Set-ObolPrincipal $service -EncryptionType Aes128Sha1, Aes128Sha1 -ErrorAction SilentlyContinue -ErrorVariable err

        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidEncryptionType,Obol.Commands.SetObolPrincipal'
        $service.EncryptionType.Count | Should-Be 2
    }

    It "Fails with an undefined encryption type" {
        $etype = [Enum]::ToObject([Obol.ObolEncryptionType], 99)

        Set-ObolPrincipal $service -NewRandomKey -EncryptionType $etype -ErrorAction SilentlyContinue -ErrorVariable err

        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidEncryptionType,Obol.Commands.SetObolPrincipal'
        $service.Kvno | Should-Be 1
    }

    It "Fails to add an encryption type without new keys" {
        Set-ObolPrincipal $service -EncryptionType Aes256Sha384 -ErrorAction SilentlyContinue -ErrorVariable err

        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidEncryptionType,Obol.Commands.SetObolPrincipal'
        $service.EncryptionType.Count | Should-Be 2
    }

    It "Adds an encryption type with new keys" {
        Set-ObolPrincipal $service -NewRandomKey -EncryptionType Aes256Sha384, Aes256Sha1

        $service.EncryptionType | Should-BeCollection @(
            [Obol.ObolEncryptionType]::Aes256Sha384
            [Obol.ObolEncryptionType]::Aes256Sha1
        )
    }

    It "Sets the flags to <Value>" -TestCases @(
        @{ Value = 'DoesNotRequirePreAuth' }
        @{ Value = 'None' }
    ) {
        param ($Value)

        $other = if ($Value -eq 'None') { 'DoesNotRequirePreAuth' } else { 'None' }
        Set-ObolPrincipal $user -Flag $other
        Set-ObolPrincipal $user -Flag $Value

        # The flags replace the existing flags.
        $user.Flag | Should-Be ([Obol.ObolPrincipalFlag]$Value)
        $user.Kvno | Should-Be 1
    }

    It "Leaves values not set unchanged" {
        Set-ObolPrincipal $user -Flag DoesNotRequirePreAuth
        Set-ObolPrincipal $user -Alias user2

        $user.Flag | Should-Be ([Obol.ObolPrincipalFlag]::DoesNotRequirePreAuth)
        $user.Alias | Should-Be user2
    }

    It "Fails with an undefined flag" {
        $flag = [Enum]::ToObject([Obol.ObolPrincipalFlag], 0x8000)

        Set-ObolPrincipal $user -Flag $flag -ErrorAction SilentlyContinue -ErrorVariable err

        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidFlag,Obol.Commands.SetObolPrincipal'
        $user.Flag | Should-Be ([Obol.ObolPrincipalFlag]::None)
    }

    It "Replaces the aliases" {
        Set-ObolPrincipal $service -Alias HTTP/a, HTTP/b

        $service.Alias | Should-BeCollection @('HTTP/a', 'HTTP/b')
        Get-ObolPrincipal -Kdc $kdc HTTP/web | Should-BeNull
        Get-ObolPrincipal -Kdc $kdc HTTP/b | Should-BeSame $service
    }

    It "Clears the aliases" {
        Set-ObolPrincipal $service -Alias @()

        $service.Alias.Count | Should-Be 0
        Get-ObolPrincipal -Kdc $kdc HTTP/web | Should-BeNull
    }

    It "Fails with an alias in use" {
        Set-ObolPrincipal $service -Alias user -ErrorAction SilentlyContinue -ErrorVariable err

        $err[0].FullyQualifiedErrorId | Should-Be 'PrincipalAlreadyExists,Obol.Commands.SetObolPrincipal'
        $service.Alias | Should-Be HTTP/web
    }

    It "Fails with an invalid alias" {
        Set-ObolPrincipal $service -Alias 'a//b' -ErrorAction SilentlyContinue -ErrorVariable err

        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidPrincipalName,Obol.Commands.SetObolPrincipal'
    }

    It "Fails to set aliases on krbtgt" {
        $krbtgt = Get-ObolPrincipal -Kdc $kdc krbtgt/*

        Set-ObolPrincipal $krbtgt -Alias krbtgt/OTHER -ErrorAction SilentlyContinue -ErrorVariable err

        $err[0].FullyQualifiedErrorId | Should-Be 'KrbtgtPrincipal,Obol.Commands.SetObolPrincipal'
    }

    It "Fails for a removed principal" {
        Remove-ObolPrincipal $service

        Set-ObolPrincipal $service -NewRandomKey -ErrorAction SilentlyContinue -ErrorVariable err

        $err[0].FullyQualifiedErrorId | Should-Be 'PrincipalNotFound,Obol.Commands.SetObolPrincipal'
        [string]$err[0] | Should-Be "The principal 'HTTP/web.example.test@EXAMPLE.TEST' does not exist"
    }

    It "Fails with an empty password" {
        { Set-ObolPrincipal $user -Password ([System.Security.SecureString]::new()) } |
            Should-Throw -FullyQualifiedErrorId 'EmptyPassword,Obol.Commands.SetObolPrincipal'
    }

    It "Fails with both -Password and -NewRandomKey" {
        { Set-ObolPrincipal $user -Password $password -NewRandomKey } |
            Should-Throw -FullyQualifiedErrorId 'PasswordWithNewRandomKey,Obol.Commands.SetObolPrincipal'

        $user.Kvno | Should-Be 1
    }

    It "Sets principals by name and alias" {
        $actual = $kdc | Set-ObolPrincipal user, HTTP/web -NewRandomKey -PassThru

        $actual | Should-BeCollection @($user, $service)
        $user.Kvno | Should-Be 2
        $service.Kvno | Should-Be 2
    }

    It "Sets principals by name with -Kdc" {
        Set-ObolPrincipal -Kdc $kdc user@EXAMPLE.TEST -Flag DoesNotRequirePreAuth

        $user.Flag | Should-Be ([Obol.ObolPrincipalFlag]::DoesNotRequirePreAuth)
    }

    It "Fails for a name that does not exist" {
        $actual = $kdc | Set-ObolPrincipal missing, user -NewRandomKey -PassThru -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeSame $user
        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'PrincipalNotFound,Obol.Commands.SetObolPrincipal'
        [string]$err[0] | Should-Be "The principal 'missing@EXAMPLE.TEST' does not exist"
    }

    It "Fails for an invalid name" {
        $kdc | Set-ObolPrincipal user@OTHER -NewRandomKey -ErrorAction SilentlyContinue -ErrorVariable err

        $err[0].FullyQualifiedErrorId | Should-Be 'PrincipalRealmMismatch,Obol.Commands.SetObolPrincipal'
    }

    It "Does not change the principal with -WhatIf" {
        Set-ObolPrincipal $user -NewRandomKey -Alias other -WhatIf

        $user.Kvno | Should-Be 1
        $user.Alias.Count | Should-Be 0
    }
}

Describe "Set-ObolPrincipal keys" {
    BeforeEach {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $service = $kdc | New-ObolPrincipal HTTP/web -Alias HTTP/web.example.test
        $other = $kdc | New-ObolPrincipal HTTP/other
        $path = [Path]::Combine($TestDrive, 'test.keytab')
    }

    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
        Remove-Item $path -Force -ErrorAction Ignore
    }

    It "Replaces the keys and kvno with keys from a keytab" {
        $service | Set-ObolPrincipal -NewRandomKey
        $service | Set-ObolPrincipal -NewRandomKey
        New-TestKeytab $path @(@{ Name = 'HTTP/web.example.test'; Realm = 'EXAMPLE.TEST'; Kvno = 1; EncryptionType = 17 })

        $service | Set-ObolPrincipal -Key (Import-ObolKeytab $path)

        $service.Kvno | Should-Be 1
        $service.EncryptionType | Should-Be Aes128Sha1
        $service.Salt | Should-Be EXAMPLE.TESTHTTPweb
    }

    It "Sets the keys of several principals from one keytab" {
        New-TestKeytab $path @(
            @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 5; EncryptionType = 18 }
            @{ Name = 'HTTP/other'; Realm = 'EXAMPLE.TEST'; Kvno = 7; EncryptionType = 17 }
        )

        $service, $other | Set-ObolPrincipal -Key (Import-ObolKeytab $path)

        $service.Kvno | Should-Be 5
        $other.Kvno | Should-Be 7
    }

    It "Matches the aliases set in the same call" {
        New-TestKeytab $path @(@{ Name = 'HTTP/new'; Realm = 'EXAMPLE.TEST'; Kvno = 5; EncryptionType = 18 })

        $service | Set-ObolPrincipal -Alias HTTP/new -Key (Import-ObolKeytab $path)

        $service.Kvno | Should-Be 5
        $service.Alias | Should-Be HTTP/new
    }

    It "Writes an error for a principal without entries and sets the others" {
        New-TestKeytab $path @(@{ Name = 'HTTP/other'; Realm = 'EXAMPLE.TEST'; Kvno = 5; EncryptionType = 18 })

        $service, $other | Set-ObolPrincipal -Key (Import-ObolKeytab $path) -ErrorAction SilentlyContinue -ErrorVariable err

        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'NoKeytabKey,Obol.Commands.SetObolPrincipal'
        $service.Kvno | Should-Be 1
        $other.Kvno | Should-Be 5
    }

    It "Sets a password with a salt" {
        $password = ConvertTo-SecureString 'Password123!' -AsPlainText -Force

        $service | Set-ObolPrincipal -Password $password -Salt CORP.EXAMPLEsvc_web -EncryptionType Aes256Sha1

        $service.Kvno | Should-Be 2
        $service.Salt | Should-Be CORP.EXAMPLEsvc_web
        $kdc | Export-ObolKeytab $path HTTP/web
        [Convert]::ToHexStringLower((Import-ObolKeytab $path)[0].Key) |
            Should-Be 'ab8c3a5300b091e044f72526e1669fa999e4cb152042325df4f4864ffdf38e5c'
    }

    It "Sets new keys with a kvno from <Case>" -TestCases @(
        @{ Case = 'a password'; UsePassword = $true }
        @{ Case = 'random keys'; UsePassword = $false }
    ) {
        param ($UsePassword)

        $params = if ($UsePassword) {
            @{ Password = (ConvertTo-SecureString 'Password123!' -AsPlainText -Force) }
        }
        else {
            @{ NewRandomKey = $true }
        }

        $service | Set-ObolPrincipal -Kvno 9 @params

        $service.Kvno | Should-Be 9
        $kdc | Export-ObolKeytab $path HTTP/web
        (Import-ObolKeytab $path).Kvno | Select-Object -Unique | Should-Be 9
    }

    It "Changes the kvno of the existing keys" {
        $kdc | Export-ObolKeytab $path HTTP/web
        $before = Import-ObolKeytab $path | ForEach-Object { [Convert]::ToHexString($_.Key) }
        Remove-Item $path

        $service | Set-ObolPrincipal -Kvno 20

        $service.Kvno | Should-Be 20
        $kdc | Export-ObolKeytab $path HTTP/web
        $after = Import-ObolKeytab $path
        $after.Kvno | Select-Object -Unique | Should-Be 20
        ($after | ForEach-Object { [Convert]::ToHexString($_.Key) }) | Should-BeCollection $before
    }

    It "Lowers the kvno" {
        $service | Set-ObolPrincipal -NewRandomKey
        $service | Set-ObolPrincipal -NewRandomKey

        $service | Set-ObolPrincipal -Kvno 1

        $service.Kvno | Should-Be 1
    }

    It "Uses the keys of the kvno given by -Kvno from a keytab" {
        New-TestKeytab $path @(
            @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 4; EncryptionType = 17 }
            @{ Name = 'HTTP/web'; Realm = 'EXAMPLE.TEST'; Kvno = 5; EncryptionType = 18 }
        )

        $service | Set-ObolPrincipal -Key (Import-ObolKeytab $path) -Kvno 4

        $service.Kvno | Should-Be 4
        $service.EncryptionType | Should-Be Aes128Sha1
    }

    It "Fails for <Case>" -TestCases @(
        @{ Case = 'Key with NewRandomKey'; Params = @{ Key = @(); NewRandomKey = $true }; ErrorId = 'KeyWithNewRandomKey' }
        @{ Case = 'Key with Password'; Params = @{ Key = @(); Password = (ConvertTo-SecureString a -AsPlainText -Force) }; ErrorId = 'KeyWithPassword' }
        @{ Case = 'Key with EncryptionType'; Params = @{ Key = @(); EncryptionType = 'Aes256Sha1' }; ErrorId = 'KeyWithEncryptionType' }
        @{ Case = 'Salt without Password or Key'; Params = @{ Salt = 'abc' }; ErrorId = 'SaltWithoutKey' }
        @{ Case = 'Salt with NewRandomKey'; Params = @{ Salt = 'abc'; NewRandomKey = $true }; ErrorId = 'SaltWithoutKey' }
    ) {
        param ($Params, $ErrorId)

        { $service | Set-ObolPrincipal @Params } |
            Should-Throw -FullyQualifiedErrorId "$ErrorId,Obol.Commands.SetObolPrincipal"
        $service.Kvno | Should-Be 1
    }
}
