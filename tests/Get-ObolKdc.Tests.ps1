using namespace System.IO

BeforeDiscovery { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

Describe "Get-ObolKdc" {
    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
    }

    It "Outputs nothing when no KDCs are running" {
        Get-ObolKdc | Should-BeNull
    }

    It "Filters by realm" {
        $kdc1 = Start-ObolKdc EXAMPLE.TEST
        $kdc2 = Start-ObolKdc OTHER.TEST
        $null = Start-ObolKdc DIFFERENT.LOCAL

        # The filter is case insensitive even though realms are not.
        Get-ObolKdc -Realm example.test | Should-BeSame $kdc1

        $actual = Get-ObolKdc *.TEST
        $actual.Count | Should-Be 2
        $actual[0] | Should-BeSame $kdc1
        $actual[1] | Should-BeSame $kdc2

        $actual = Get-ObolKdc OTHER.TEST, EXAMPLE.TEST
        $actual.Count | Should-Be 2

        Get-ObolKdc -Realm MISSING.TEST | Should-BeNull
    }

    It "Filters by port" {
        $kdc1 = Start-ObolKdc EXAMPLE.TEST
        $kdc2 = Start-ObolKdc EXAMPLE.TEST

        Get-ObolKdc -Port $kdc2.Port | Should-BeSame $kdc2
        (Get-ObolKdc -Port $kdc1.Port, $kdc2.Port).Count | Should-Be 2
        Get-ObolKdc -Realm OTHER.TEST -Port $kdc1.Port | Should-BeNull
    }

    It "Does not output stopped KDCs" {
        $kdc1 = Start-ObolKdc EXAMPLE.TEST
        $kdc2 = Start-ObolKdc OTHER.TEST
        $kdc1.Dispose()

        Get-ObolKdc | Should-BeSame $kdc2
    }
}
