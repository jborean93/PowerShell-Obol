using namespace System.IO

BeforeDiscovery { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

Describe "Remove-ObolPrincipal" {
    BeforeEach {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $user = New-ObolPrincipal -Kdc $kdc user
        $service = New-ObolPrincipal -Kdc $kdc HTTP/web.example.test -Alias HTTP/web
    }

    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
    }

    It "Removes a principal" {
        $actual = Remove-ObolPrincipal $service

        $actual | Should-BeNull
        Get-ObolPrincipal -Kdc $kdc HTTP/* | Should-BeNull
    }

    It "Removes principals from the pipeline" {
        Get-ObolPrincipal -Kdc $kdc user, HTTP/* | Remove-ObolPrincipal

        (Get-ObolPrincipal -Kdc $kdc).FullName | Should-Be krbtgt/EXAMPLE.TEST@EXAMPLE.TEST
    }

    It "Removes principals by name and alias" {
        $kdc | Remove-ObolPrincipal user, HTTP/web

        (Get-ObolPrincipal -Kdc $kdc).FullName | Should-Be krbtgt/EXAMPLE.TEST@EXAMPLE.TEST
    }

    It "Removes a principal by name with -Kdc" {
        Remove-ObolPrincipal -Kdc $kdc user

        Get-ObolPrincipal -Kdc $kdc user | Should-BeNull
    }

    It "Fails for a name that does not exist" {
        $kdc | Remove-ObolPrincipal missing -ErrorAction SilentlyContinue -ErrorVariable err

        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'PrincipalNotFound,Obol.Commands.RemoveObolPrincipal'
    }

    It "Allows the name and alias to be used again" {
        Remove-ObolPrincipal $service

        $actual = New-ObolPrincipal -Kdc $kdc HTTP/web

        $actual.Name | Should-Be HTTP/web
    }

    It "Fails for krbtgt" {
        Get-ObolPrincipal -Kdc $kdc krbtgt/* | Remove-ObolPrincipal -ErrorAction SilentlyContinue -ErrorVariable err

        $err[0].FullyQualifiedErrorId | Should-Be 'KrbtgtPrincipal,Obol.Commands.RemoveObolPrincipal'
        [string]$err[0] | Should-Be 'The krbtgt principal cannot be removed'
    }

    It "Fails for a principal already removed" {
        Remove-ObolPrincipal $user

        Remove-ObolPrincipal $user -ErrorAction SilentlyContinue -ErrorVariable err

        $err[0].FullyQualifiedErrorId | Should-Be 'PrincipalNotFound,Obol.Commands.RemoveObolPrincipal'
    }

    It "Does not remove with -WhatIf" {
        Remove-ObolPrincipal $user -WhatIf

        Get-ObolPrincipal -Kdc $kdc user | Should-BeSame $user
    }
}
