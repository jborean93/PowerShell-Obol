using namespace System.IO

BeforeDiscovery { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

BeforeAll {
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
