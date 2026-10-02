using module ../output/Obol
using namespace System.IO

BeforeAll { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

BeforeDiscovery {
    # Integration tests against the Heimdal command line tools, such as the ones macOS ships, skipped when they are
    # not installed. MIT has no kgetcred and its klist does not take --version.
    # Each tool must exist, a tool can be found more than once on PATH.
    $heimdal = -not $IsWindows -and
    -not ('kinit', 'klist', 'kgetcred' | Where-Object { -not (Get-Command $_ -CommandType Application -ErrorAction Ignore) }) -and
    ((klist --version 2>&1) -join '') -like '*Heimdal*'
    $heimdalKtutil = $heimdal -and [bool](Get-Command ktutil -CommandType Application -ErrorAction Ignore)
}

Describe "Heimdal" -Skip:(-not $heimdal) {
    BeforeAll {
        $password = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
    }

    BeforeEach {
        $dir = [Path]::Combine($TestDrive, [Path]::GetRandomFileName())
        $null = New-Item $dir -ItemType Directory
        $krb5Conf = [Path]::Combine($dir, 'krb5.conf')
        $keytab = [Path]::Combine($dir, 'test.keytab')

        $oldConfig = $env:KRB5_CONFIG
        $oldCache = $env:KRB5CCNAME
        $env:KRB5_CONFIG = $krb5Conf
        $env:KRB5CCNAME = "FILE:$([Path]::Combine($dir, 'ccache'))"
    }

    AfterEach {
        $env:KRB5_CONFIG = $oldConfig
        $env:KRB5CCNAME = $oldCache
        Get-ObolKdc | Stop-ObolKdc
        Remove-Item $dir -Recurse -Force -ErrorAction Ignore
    }

    Context "krb5.conf" {
        It "Gets tickets over <Transport>" -TestCases @(
            @{ Transport = 'Tcp' }
            @{ Transport = 'Udp' }
            @{ Transport = 'Tcp, Udp' }
        ) {
            param ($Transport)

            $kdc = Start-ObolKdc EXAMPLE.TEST -Transport $Transport -Principal @{
                user = $null
                'HTTP/web.example.test' = [Obol.ObolPrincipalSetting]@{ Alias = 'HTTP/web' }
            }
            $kdc | Export-ObolKrb5Config $krb5Conf -Provider Heimdal
            $kdc | Export-ObolKeytab $keytab user

            $null = Invoke-KerberosTool { kinit -k -t $keytab user@EXAMPLE.TEST }

            # macOS kgetcred has no --hostbased, the [domain_realm] mapping is only tested with MIT.
            $null = Invoke-KerberosTool { kgetcred HTTP/web.example.test@EXAMPLE.TEST }
            $null = Invoke-KerberosTool { kgetcred HTTP/web@EXAMPLE.TEST }
            $actual = Invoke-KerberosTool { klist -v }
            $actual | Should-BeLikeString '*Server: HTTP/web.example.test@EXAMPLE.TEST*'
            $actual | Should-BeLikeString '*Server: HTTP/web@EXAMPLE.TEST*'
        }

        It "Reaches TCP only and UDP only KDCs from one file" {
            $tcp = Start-ObolKdc TCP.TEST -Transport Tcp -Principal @{ user = $null; 'HTTP/web.tcp.test' = $null }
            $udp = Start-ObolKdc UDP.TEST -Transport Udp -Principal @{ user = $null; 'HTTP/web.udp.test' = $null }
            $tcp, $udp | Export-ObolKrb5Config $krb5Conf -Provider Heimdal
            $tcp, $udp | Get-ObolPrincipal user | Export-ObolKeytab $keytab

            foreach ($realm in 'TCP', 'UDP') {
                $null = Invoke-KerberosTool { kinit -k -t $keytab "user@$realm.TEST" }
                $null = Invoke-KerberosTool { kgetcred "HTTP/web.$($realm.ToLowerInvariant()).test@$realm.TEST" }
            }
        }
    }

    Context "Keytabs" {
        It "Gets a ticket with a password" {
            $kdc = Start-ObolKdc EXAMPLE.TEST -Principal @{ user = $password }
            $kdc | Export-ObolKrb5Config $krb5Conf -Provider Heimdal

            # Heimdal's kinit only reads a password from stdin with --password-file=STDIN.
            $null = Invoke-KerberosTool { 'Password123!' | kinit --password-file=STDIN user@EXAMPLE.TEST }

            Invoke-KerberosTool { klist -v } | Should-BeLikeString '*Server: krbtgt/EXAMPLE.TEST@EXAMPLE.TEST*'
        }

        It "Issues service tickets with the kvno of the exported keytab" {
            $kdc = Start-ObolKdc EXAMPLE.TEST -Principal @{
                user = $password
                'HTTP/web.example.test' = [Obol.ObolPrincipalSetting]@{ Alias = 'HTTP/web'; Kvno = 300 }
            }
            $kdc | Export-ObolKrb5Config $krb5Conf -Provider Heimdal
            $serviceKeytab = [Path]::Combine($dir, 'service.keytab')
            $kdc | Export-ObolKeytab $serviceKeytab HTTP/web.example.test
            $null = Invoke-KerberosTool { 'Password123!' | kinit --password-file=STDIN user@EXAMPLE.TEST }

            $null = Invoke-KerberosTool { kgetcred HTTP/web.example.test@EXAMPLE.TEST }

            Invoke-KerberosTool { klist -v } | Should-BeLikeString '*Server: HTTP/web.example.test@EXAMPLE.TEST*Ticket etype: aes256-cts-hmac-sha1-96, kvno 300*'

            # Heimdal has no kvno -k, logging in as the service with its keytab proves the keys match the KDC.
            $env:KRB5CCNAME = "FILE:$([Path]::Combine($dir, 'service-ccache'))"
            $null = Invoke-KerberosTool { kinit -k -t $serviceKeytab HTTP/web.example.test@EXAMPLE.TEST }
            $null = Invoke-KerberosTool { kinit -k -t $serviceKeytab HTTP/web@EXAMPLE.TEST }
        }

        It "Lists the entries of a keytab written by Export-ObolKeytab" -Skip:(-not $heimdalKtutil) {
            $kdc = Start-ObolKdc EXAMPLE.TEST -Principal @{
                user = $password
                'HTTP/web.example.test' = [Obol.ObolPrincipalSetting]@{ Alias = 'HTTP/web'; Kvno = 300 }
            }
            $kdc | Get-ObolPrincipal user, HTTP/* | Export-ObolKeytab $keytab

            $actual = Invoke-KerberosTool { ktutil -k $keytab list --keys }

            # The known MIT key of user@EXAMPLE.TEST for the password, and the 32-bit kvno of the service.
            $actual | Should-BeLikeString '*1  aes256-cts-hmac-sha1-96*user@EXAMPLE.TEST*cc7517320a9c6cd13de0ea137e9fe17e5724178754077af2a8c9ca80dd582a90*'
            $actual | Should-BeLikeString '*300  aes256-cts-hmac-sha1-96*HTTP/web.example.test@EXAMPLE.TEST*'
            $actual | Should-BeLikeString '*300  aes128-cts-hmac-sha1-96*HTTP/web@EXAMPLE.TEST*'
        }

        It "Reads a keytab written by ktutil" -Skip:(-not $heimdalKtutil) {
            $null = Invoke-KerberosTool { ktutil -k $keytab add -p HTTP/web@EXAMPLE.TEST -V 5 -e aes256-cts-hmac-sha1-96 -w Password123! }
            $null = Invoke-KerberosTool { ktutil -k $keytab add -p HTTP/web@EXAMPLE.TEST -V 5 -e aes128-cts-hmac-sha1-96 -w Password123! }
            $expected = New-ObolKeytabEntry HTTP/web@EXAMPLE.TEST -Password $password -Kvno 5 -EncryptionType Aes256Sha1, Aes128Sha1

            # Heimdal writes a flags field after the 32-bit kvno, the reader ignores it.
            $actual = Import-ObolKeytab $keytab

            ($actual | ForEach-Object { "$($_.FullName) $($_.Kvno) $($_.EncryptionType) $([Convert]::ToHexString($_.Key))" }) |
                Should-BeCollection ($expected | ForEach-Object { "$($_.FullName) $($_.Kvno) $($_.EncryptionType) $([Convert]::ToHexString($_.Key))" })
        }

        It "Issues tickets for keys imported from a ktutil keytab" -Skip:(-not $heimdalKtutil) {
            $serviceKeytab = [Path]::Combine($dir, 'service.keytab')
            $null = Invoke-KerberosTool { ktutil -k $serviceKeytab add -p HTTP/web.example.test@EXAMPLE.TEST -V 7 -e aes256-cts-hmac-sha1-96 -w Password123! }
            $kdc = Start-ObolKdc EXAMPLE.TEST -Principal @{ user = $password }
            $null = $kdc | New-ObolPrincipal HTTP/web.example.test -Key (Import-ObolKeytab $serviceKeytab)
            $kdc | Export-ObolKrb5Config $krb5Conf -Provider Heimdal
            $null = Invoke-KerberosTool { 'Password123!' | kinit --password-file=STDIN user@EXAMPLE.TEST }

            $null = Invoke-KerberosTool { kgetcred HTTP/web.example.test@EXAMPLE.TEST }

            Invoke-KerberosTool { klist -v } | Should-BeLikeString '*Server: HTTP/web.example.test@EXAMPLE.TEST*kvno 7*'
            $env:KRB5CCNAME = "FILE:$([Path]::Combine($dir, 'service-ccache'))"
            $null = Invoke-KerberosTool { kinit -k -t $serviceKeytab HTTP/web.example.test@EXAMPLE.TEST }
        }
    }

    Context "Enter-ObolKrb5Environment" {
        AfterEach {
            Exit-ObolKrb5Environment
        }

        It "Gets tickets with the variables it sets" {
            $kdc = Start-ObolKdc EXAMPLE.TEST -Principal @{ user = $null; 'HTTP/web.example.test' = $null }
            Enter-ObolKrb5Environment $kdc -ServicePrincipal ($kdc | Get-ObolPrincipal user) -Provider Heimdal
            $ccache = $env:KRB5CCNAME

            # Heimdal has no client keytab variable, kinit -k without -t uses the keytab from KRB5_KTNAME.
            $null = Invoke-KerberosTool { kinit -k user@EXAMPLE.TEST }
            $null = Invoke-KerberosTool { kgetcred HTTP/web.example.test@EXAMPLE.TEST }

            $actual = Invoke-KerberosTool { klist -v }
            $actual | Should-BeLikeString "*$($ccache -replace '^FILE:')*"
            $actual | Should-BeLikeString '*Server: HTTP/web.example.test@EXAMPLE.TEST*'
        }
    }
}
