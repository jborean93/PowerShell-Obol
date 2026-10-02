using module ../output/Obol
using namespace System.IO
using namespace System.Net

BeforeAll { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

Describe "ConvertTo-ObolKrb5Config" {
    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
    }

    It "Creates a krb5.conf for a KDC" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $actual = ConvertTo-ObolKrb5Config $kdc -Provider Mit

        $actual | Should-Be (@(
            '[libdefaults]'
            '    default_realm = EXAMPLE.TEST'
            '    dns_lookup_kdc = false'
            '    dns_lookup_realm = false'
            '    dns_canonicalize_hostname = false'
            '    rdns = false'
            ''
            '[realms]'
            '    EXAMPLE.TEST = {'
            "        kdc = 127.0.0.1:$($kdc.Port)"
            '    }'
            ''
            '[domain_realm]'
            '    .example.test = EXAMPLE.TEST'
            '    example.test = EXAMPLE.TEST'
            ''
        ) -join "`n")
    }

    It "Creates a krb5.conf for KDCs from the pipeline with the first realm as default" {
        $first = Start-ObolKdc EXAMPLE.TEST
        $second = Start-ObolKdc OTHER.TEST

        $actual = $first, $second | ConvertTo-ObolKrb5Config

        $actual | Should-BeLikeString '*default_realm = EXAMPLE.TEST*'
        $actual | Should-BeLikeString "*    EXAMPLE.TEST = {`n        kdc = 127.0.0.1:$($first.Port)`n    }*"
        $actual | Should-BeLikeString "*    OTHER.TEST = {`n        kdc = 127.0.0.1:$($second.Port)`n    }*"
        $actual | Should-BeLikeString "*    .other.test = OTHER.TEST`n    other.test = OTHER.TEST*"
    }

    It "Lists KDCs for the same realm together" {
        $first = Start-ObolKdc EXAMPLE.TEST
        $second = Start-ObolKdc EXAMPLE.TEST

        $actual = ConvertTo-ObolKrb5Config $first, $second

        $expected = "*    EXAMPLE.TEST = {`n        kdc = 127.0.0.1:$($first.Port)`n" +
            "        kdc = 127.0.0.1:$($second.Port)`n    }*"
        $actual | Should-BeLikeString $expected
        ([regex]::Matches($actual, 'example\.test = ')).Count | Should-Be 2
    }

    It "Maps realms that differ only by case to one domain" {
        $first = Start-ObolKdc EXAMPLE.TEST
        $second = Start-ObolKdc example.test

        $actual = ConvertTo-ObolKrb5Config $first, $second

        $actual | Should-BeLikeString "*    .example.test = EXAMPLE.TEST`n    example.test = EXAMPLE.TEST`n"
        $actual | Should-BeLikeString '*    example.test = {*'
    }

    It "Uses the address of a KDC on <Address>" -TestCases @(
        @{ Address = '0.0.0.0'; Expected = '127.0.0.1' }
        @{ Address = '::'; Expected = '[::1]' }
        @{ Address = '::1'; Expected = '[::1]' }
        @{ Address = '127.0.0.1'; Expected = '127.0.0.1' }
    ) {
        param ($Address, $Expected)

        $kdc = Start-ObolKdc EXAMPLE.TEST -Address $Address

        $actual = ConvertTo-ObolKrb5Config $kdc

        $actual | Should-BeLikeString "*        kdc = $([WildcardPattern]::Escape($Expected)):$($kdc.Port)`n*"
    }

    It "Creates a krb5.conf for Heimdal" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $actual = ConvertTo-ObolKrb5Config $kdc -Provider Heimdal

        $actual | Should-Be (@(
            '[libdefaults]'
            '    default_realm = EXAMPLE.TEST'
            '    dns_lookup_kdc = false'
            '    dns_lookup_realm = false'
            '    dns_canonicalize_hostname = false'
            ''
            '[realms]'
            '    EXAMPLE.TEST = {'
            "        kdc = 127.0.0.1:$($kdc.Port)"
            '    }'
            ''
            '[domain_realm]'
            '    .example.test = EXAMPLE.TEST'
            '    example.test = EXAMPLE.TEST'
            ''
        ) -join "`n")
    }

    It "Uses the Heimdal provider on macOS and MIT elsewhere for <Provider>" -TestCases @(
        @{ Provider = $null }
        @{ Provider = 'Default' }
    ) {
        param ($Provider)

        $kdc = Start-ObolKdc EXAMPLE.TEST -Transport Tcp
        $expected = if ($IsMacOS) { 'Heimdal' } else { 'Mit' }
        $params = if ($Provider) { @{ Provider = $Provider } } else { @{} }

        $actual = ConvertTo-ObolKrb5Config $kdc @params

        $actual | Should-Be (ConvertTo-ObolKrb5Config $kdc -Provider $expected)
    }

    It "Fails for an undefined provider" {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $provider = [Enum]::ToObject([Obol.ObolKrb5Provider], 99)

        { ConvertTo-ObolKrb5Config $kdc -Provider $provider } |
            Should-Throw -FullyQualifiedErrorId 'InvalidProvider,Obol.Commands.ConvertToObolKrb5Config'
    }

    It "Sends MIT requests over TCP first when a KDC has no UDP listener" {
        $tcp = Start-ObolKdc TCP.TEST -Transport Tcp
        $udp = Start-ObolKdc UDP.TEST -Transport Udp

        $actual = ConvertTo-ObolKrb5Config $tcp, $udp -Provider Mit

        # MIT falls back to UDP when TCP fails so the UDP only KDC is still reached.
        $actual | Should-BeLikeString "*    rdns = false`n    udp_preference_limit = 1`n`n*"
        $actual | Should-BeLikeString "*        kdc = 127.0.0.1:$($tcp.Port)`n*"
        $actual | Should-BeLikeString "*        kdc = 127.0.0.1:$($udp.Port)`n*"
    }

    It "Does not set udp_preference_limit for MIT when every KDC has UDP" {
        $kdc = Start-ObolKdc EXAMPLE.TEST -Transport Udp

        $actual = ConvertTo-ObolKrb5Config $kdc -Provider Mit

        $actual | Should-NotBeLikeString '*udp_preference_limit*'
    }

    It "Sets the Heimdal transport of each KDC" {
        $tcp = Start-ObolKdc TCP.TEST -Transport Tcp
        $udp = Start-ObolKdc UDP.TEST -Transport Udp
        $both = Start-ObolKdc BOTH.TEST
        $v6 = Start-ObolKdc V6.TEST -Transport Tcp -Address ::1

        $actual = ConvertTo-ObolKrb5Config $tcp, $udp, $both, $v6 -Provider Heimdal

        $actual | Should-BeLikeString "*        kdc = tcp/127.0.0.1:$($tcp.Port)`n*"
        $actual | Should-BeLikeString "*        kdc = udp/127.0.0.1:$($udp.Port)`n*"
        $actual | Should-BeLikeString "*        kdc = 127.0.0.1:$($both.Port)`n*"
        $actual | Should-BeLikeString "*        kdc = tcp/``[::1``]:$($v6.Port)`n*"
        $actual | Should-NotBeLikeString '*udp_preference_limit*'
        $actual | Should-NotBeLikeString '*large_message_size*'
    }

    It "Writes an error for a stopped KDC and converts the others" {
        $stopped = Start-ObolKdc STOPPED.TEST
        $stopped | Stop-ObolKdc
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $actual = ConvertTo-ObolKrb5Config $stopped, $kdc -ErrorAction SilentlyContinue -ErrorVariable err

        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'KdcNotRunning,Obol.Commands.ConvertToObolKrb5Config'
        $actual | Should-BeLikeString '*default_realm = EXAMPLE.TEST*'
        $actual | Should-NotBeLikeString '*STOPPED*'
    }

    It "Outputs nothing when no KDC can be converted" {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $kdc | Stop-ObolKdc

        $actual = ConvertTo-ObolKrb5Config $kdc -ErrorAction SilentlyContinue

        $actual | Should-BeNull
    }

    It "Writes an error for realm '<Realm>'" -TestCases @(
        @{ Realm = 'EXAMPLE TEST' }
        @{ Realm = 'EXAMPLE=TEST' }
        @{ Realm = '[EXAMPLE]' }
        @{ Realm = 'EXAMPLE{' }
        @{ Realm = '#EXAMPLE' }
        @{ Realm = ';EXAMPLE' }
        @{ Realm = '"EXAMPLE"' }
    ) {
        param ($Realm)

        $kdc = Start-ObolKdc $Realm

        $actual = ConvertTo-ObolKrb5Config $kdc -ErrorAction SilentlyContinue -ErrorVariable err

        $actual | Should-BeNull
        $err.Count | Should-Be 1
        $err[0].FullyQualifiedErrorId | Should-Be 'InvalidKrb5ConfigRealm,Obol.Commands.ConvertToObolKrb5Config'
    }
}
