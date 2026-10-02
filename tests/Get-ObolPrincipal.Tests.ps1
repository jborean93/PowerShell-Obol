using module ../output/Obol
using namespace System.IO
using namespace System.Management.Automation

BeforeAll { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

Describe "Get-ObolPrincipal" {
    BeforeEach {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $other = Start-ObolKdc OTHER.TEST
        $user = New-ObolPrincipal -Kdc $kdc user
        $service = New-ObolPrincipal -Kdc $kdc HTTP/web.example.test -Alias HTTP/alias
        $otherUser = New-ObolPrincipal -Kdc $other user
    }

    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
    }

    It "Gets the principals of a KDC" {
        $actual = Get-ObolPrincipal -Kdc $kdc

        $actual.FullName | Should-BeCollection @(
            'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST'
            'user@EXAMPLE.TEST'
            'HTTP/web.example.test@EXAMPLE.TEST'
        )
        $actual[1] | Should-BeSame $user
    }

    It "Gets the principals of every KDC from Get-ObolKdc" {
        $actual = Get-ObolKdc | Get-ObolPrincipal

        $actual.FullName | Should-BeCollection @(
            'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST'
            'user@EXAMPLE.TEST'
            'HTTP/web.example.test@EXAMPLE.TEST'
            'krbtgt/OTHER.TEST@OTHER.TEST'
            'user@OTHER.TEST'
        )
    }

    It "Gets the principals of multiple KDCs with a name" {
        $actual = Get-ObolPrincipal -Kdc $other, $kdc user

        $actual | Should-BeCollection @($otherUser, $user)
    }

    It "Gets the principals of KDCs from the pipeline" {
        $actual = $other, $kdc | Get-ObolPrincipal -Name user

        $actual | Should-BeCollection @($otherUser, $user)
    }

    It "Filters by name '<Name>'" -TestCases @(
        @{ Name = 'user'; Expected = 'user@EXAMPLE.TEST', 'user@OTHER.TEST' }
        @{ Name = 'USER'; Expected = 'user@EXAMPLE.TEST', 'user@OTHER.TEST' }
        @{ Name = 'user@OTHER.TEST'; Expected = , 'user@OTHER.TEST' }
        @{ Name = 'HTTP/*'; Expected = , 'HTTP/web.example.test@EXAMPLE.TEST' }
        @{ Name = 'krbtgt/*'; Expected = 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST', 'krbtgt/OTHER.TEST@OTHER.TEST' }
        @{ Name = 'HTTP/alias'; Expected = , 'HTTP/web.example.test@EXAMPLE.TEST' }
        @{ Name = 'HTTP/alias@EXAMPLE.TEST'; Expected = , 'HTTP/web.example.test@EXAMPLE.TEST' }
        @{ Name = 'missing'; Expected = @() }
    ) {
        param ($Name, $Expected)

        $actual = Get-ObolKdc | Get-ObolPrincipal -Name $Name

        @($actual | ForEach-Object FullName) | Should-BeCollection $Expected
    }

    It "Filters by multiple names" {
        $actual = Get-ObolPrincipal -Kdc $kdc -Name user, HTTP/web.example.test

        $actual | Should-BeCollection @($user, $service)
    }

    It "Outputs nothing when no KDCs are piped" {
        Get-ObolKdc | Stop-ObolKdc

        Get-ObolKdc | Get-ObolPrincipal | Should-BeNull
    }

    It "Gets the principals of a KDC from the pipeline with a positional name" {
        $actual = $other | Get-ObolPrincipal user

        $actual | Should-BeSame $otherUser
    }

    It "Requires a named -Kdc" {
        $actual = (Get-Command Get-ObolPrincipal).Parameters.Kdc.Attributes.Where({ $_ -is [ParameterAttribute] })

        $actual.Mandatory | Should-BeTrue
        $actual.ValueFromPipeline | Should-BeTrue
        $actual.Position | Should-Be ([int]::MinValue)
    }
}
