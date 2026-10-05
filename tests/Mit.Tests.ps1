using module ../output/Obol
using namespace System.IO

BeforeAll { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

BeforeDiscovery {
    # Integration tests against the MIT krb5 command line tools, skipped when they are not installed. The macOS kinit
    # is Heimdal, its klist -V output does not match and it takes different arguments.
    # Each tool must exist, a tool can be found more than once on PATH.
    $mitKrb5 = -not $IsWindows -and
        -not ('kinit', 'klist', 'kvno', 'ktutil' | Where-Object { -not (Get-Command $_ -CommandType Application -ErrorAction Ignore) }) -and
        ((klist -V 2>&1) -join '') -like '*Kerberos 5 version*'
}

Describe "MIT krb5" -Skip:(-not $mitKrb5) {
    BeforeAll {
        $password = ConvertTo-SecureString 'Password123!' -AsPlainText -Force

        # Writes a keytab with ktutil addent -password for each entry, a hashtable of addent options.
        Function New-KtutilKeytab {
            param ([string]$Path, [hashtable[]]$Entry)

            $commands = foreach ($e in $Entry) {
                $salt = if ($e.Salt) { " -s $($e.Salt)" } else { '' }
                "addent -password -p $($e.Principal) -k $($e.Kvno) -e $($e.EncryptionType)$salt"
                'Password123!'
            }
            @($commands; "wkt $Path") | ktutil | Out-Null
        }
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
            $kdc | Export-ObolKrb5Config $krb5Conf -Provider Mit
            $kdc | Get-ObolPrincipal user, HTTP/* | Export-ObolKeytab $keytab

            $null = Invoke-KerberosTool { kinit -k -t $keytab user@EXAMPLE.TEST }

            # -S maps the host to the realm with the [domain_realm] section, -k decrypts the ticket with the keytab.
            Invoke-KerberosTool { kvno -k $keytab -S HTTP web.example.test } |
                Should-BeLikeString '*HTTP/web.example.test@EXAMPLE.TEST: kvno = 1, keytab entry valid*'
            Invoke-KerberosTool { kvno -k $keytab HTTP/web } |
                Should-BeLikeString '*HTTP/web@EXAMPLE.TEST: kvno = 1, keytab entry valid*'
        }

        It "Reaches TCP only and UDP only KDCs from one file" {
            $tcp = Start-ObolKdc TCP.TEST -Transport Tcp -Principal @{ user = $null; 'HTTP/web.tcp.test' = $null }
            $udp = Start-ObolKdc UDP.TEST -Transport Udp -Principal @{ user = $null; 'HTTP/web.udp.test' = $null }
            $tcp, $udp | Export-ObolKrb5Config $krb5Conf -Provider Mit
            $tcp, $udp | Get-ObolPrincipal user | Export-ObolKeytab $keytab

            foreach ($realm in 'TCP', 'UDP') {
                $null = Invoke-KerberosTool { kinit -k -t $keytab "user@$realm.TEST" }
                Invoke-KerberosTool { kvno -S HTTP "web.$($realm.ToLowerInvariant()).test" } |
                    Should-BeLikeString "*HTTP/web.$($realm.ToLowerInvariant()).test@$realm.TEST: kvno = 1*"
            }
        }
    }

    Context "Tracing" {
        It "Traces the AS and TGS exchanges of kinit and kvno" {
            $kdc = Start-ObolKdc EXAMPLE.TEST -Principal @{ user = $password; 'HTTP/web.example.test' = $null }
            $kdc | Export-ObolKrb5Config $krb5Conf -Provider Mit

            $actual = Trace-ObolKdc -Kdc $kdc {
                $null = Invoke-KerberosTool { 'Password123!' | kinit user }
                $null = Invoke-KerberosTool { kvno HTTP/web.example.test }
            }

            # kinit asks without pre-authentication first, then with the timestamp, kvno uses the TGT.
            $actual.Count | Should-Be 3
            [string[]]$actual.Request.MessageType | Should-BeCollection AsReq, AsReq, TgsReq
            [string[]]$actual.Reply.MessageType | Should-BeCollection Error, AsRep, TgsRep
            [string[]]$actual.ErrorCode | Should-BeCollection PreAuthRequired, None, None
            $actual.ClientName | Should-BeCollection 'user@EXAMPLE.TEST', 'user@EXAMPLE.TEST', 'user@EXAMPLE.TEST'
            $actual.ServiceName | Should-BeCollection 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST', 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST', 'HTTP/web.example.test@EXAMPLE.TEST'

            [int[]]$actual[0].Request.PreAuthData.Type | Should-NotContainCollection 2
            $actual[0].Key.Count | Should-Be 0
            # The error carries the salt and encryption types the client needs for the timestamp.
            $actual[0].Reply.ErrorCode | Should-Be ([Obol.Kerberos.ErrorCode]::PreAuthRequired)
            [int[]]$actual[0].Reply.MethodData.Type | Should-ContainCollection 2, 19

            [int[]]$actual[1].Request.PreAuthData.Type | Should-ContainCollection 2
            ($actual[1].Request.PreAuthData | Where-Object Type -eq EncTimestamp).Timestamp | Should-HaveType ([DateTime])
            $tgt = $actual[1].Reply.Ticket.DecryptedPart
            $tgt.Flag.HasFlag([Obol.Kerberos.TicketFlag]::Initial) | Should-BeTrue
            $tgt.Flag.HasFlag([Obol.Kerberos.TicketFlag]::PreAuthenticated) | Should-BeTrue
            $tgt.Pac.LogonInfo.UserName | Should-Be user
            $tgt.Pac.LogonInfo.DomainName | Should-Be EXAMPLE
            [Convert]::ToHexString($actual[1].Reply.DecryptedPart.Key.Value) | Should-Be ([Convert]::ToHexString($tgt.Key.Value))
            $actual[1].Key.FullName | Should-BeCollection 'user@EXAMPLE.TEST', 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST'

            # PA-TGS-REQ carries the TGT.
            [int[]]$actual[2].Request.PreAuthData.Type | Should-ContainCollection 1
            $actual[2].Request | Should-HaveType ([Obol.Kerberos.TgsRequest])
            # The KDC decrypted the TGT and the authenticator the client presented.
            $actual[2].Request.ApRequest.Ticket.DecryptedPart.ClientName.FullName | Should-Be 'user@EXAMPLE.TEST'
            [Convert]::ToHexString($actual[2].Request.ApRequest.Ticket.DecryptedPart.Key.Value) | Should-Be ([Convert]::ToHexString($tgt.Key.Value))
            $actual[2].Request.ApRequest.Authenticator.ClientName.FullName | Should-Be 'user@EXAMPLE.TEST'
            $service = $actual[2].Reply.Ticket.DecryptedPart
            $service.Key.EncryptionType | Should-Be 18
            $actual[2].Reply.Ticket.EncryptedPart.EncryptionType | Should-Be 18
            $service.Flag.HasFlag([Obol.Kerberos.TicketFlag]::PreAuthenticated) | Should-BeTrue
            $service.Flag.HasFlag([Obol.Kerberos.TicketFlag]::Initial) | Should-BeFalse
            $service.Pac | Should-NotBeNull
            $actual[2].Key.FullName | Should-BeCollection 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST', 'HTTP/web.example.test@EXAMPLE.TEST'
            $actual[2].Message | Should-BeLikeString 'TGS-REQ user@EXAMPLE.TEST -> HTTP/web.example.test@EXAMPLE.TEST: TGS-REP, Aes256Sha1 ticket and session key, *PreAuthenticated*'
        }
    }

    Context "Keytabs" {
        It "Gets a ticket with a password the exported keytab validates" {
            $kdc = Start-ObolKdc EXAMPLE.TEST -Principal @{ user = $password }
            $kdc | Export-ObolKrb5Config $krb5Conf -Provider Mit
            $kdc | Export-ObolKeytab $keytab user

            $null = Invoke-KerberosTool { 'Password123!' | kinit user }

            # kvno -k checks the user's own ticket decrypts with the key in the keytab.
            Invoke-KerberosTool { kvno -k $keytab user@EXAMPLE.TEST } | Should-BeLikeString '*keytab entry valid*'
        }

        It "Reads a keytab written by ktutil" {
            New-KtutilKeytab $keytab @(
                @{ Principal = 'HTTP/web.corp.example@CORP.EXAMPLE'; Kvno = 300; EncryptionType = 'aes256-cts-hmac-sha1-96'; Salt = 'CORP.EXAMPLEsvc_web' }
                @{ Principal = 'HTTP/web.corp.example@CORP.EXAMPLE'; Kvno = 300; EncryptionType = 'arcfour-hmac' }
            )

            $actual = Import-ObolKeytab $keytab

            $actual.FullName | Should-BeCollection @(
                'HTTP/web.corp.example@CORP.EXAMPLE'
                'HTTP/web.corp.example@CORP.EXAMPLE'
            )
            $actual.Kvno | Should-BeCollection 300, 300
            [int[]]$actual.EncryptionType | Should-BeCollection 18, 23
            [Convert]::ToHexStringLower($actual[0].Key) |
                Should-Be 'ab8c3a5300b091e044f72526e1669fa999e4cb152042325df4f4864ffdf38e5c'
        }

        It "Creates the same keys as ktutil" {
            New-KtutilKeytab $keytab @(
                @{ Principal = 'HTTP/web.corp.example@CORP.EXAMPLE'; Kvno = 5; EncryptionType = 'aes256-cts-hmac-sha384-192'; Salt = 'CORP.EXAMPLEsvc_web' }
                @{ Principal = 'HTTP/web.corp.example@CORP.EXAMPLE'; Kvno = 5; EncryptionType = 'aes128-cts-hmac-sha256-128' }
            )
            $expected = Import-ObolKeytab $keytab
            $params = @{
                Name = 'HTTP/web.corp.example@CORP.EXAMPLE'
                Password = $password
                Kvno = 5
            }

            $sha384 = New-ObolKeytabEntry @params -Salt CORP.EXAMPLEsvc_web -EncryptionType Aes256Sha384
            $sha256 = New-ObolKeytabEntry @params -EncryptionType Aes128Sha256

            [Convert]::ToHexString($sha384.Key) | Should-Be ([Convert]::ToHexString($expected[0].Key))
            [Convert]::ToHexString($sha256.Key) | Should-Be ([Convert]::ToHexString($expected[1].Key))
        }

        It "Writes a keytab ktutil reads" {
            New-ObolKeytabEntry HTTP/web@EXAMPLE.TEST -Password $password -Kvno 300 | Export-ObolKeytab $keytab

            $actual = Invoke-KerberosTool { klist -k -t -e -K $keytab }

            $actual | Should-BeLikeString '*300 * HTTP/web@EXAMPLE.TEST (aes256-cts-hmac-sha1-96)*'
            $actual | Should-BeLikeString '*300 * HTTP/web@EXAMPLE.TEST (aes128-cts-hmac-sha1-96)*'
        }

        It "Issues tickets for keys imported from a ktutil keytab with an AD salt" {
            $kdc = Start-ObolKdc CORP.EXAMPLE -Principal @{ user = $null }
            $salt = ConvertTo-ObolSalt svc_web -Realm CORP.EXAMPLE -SaltType ADUser
            $serviceKeytab = [Path]::Combine($dir, 'service.keytab')
            New-KtutilKeytab $serviceKeytab @(
                @{ Principal = 'HTTP/web.corp.example@CORP.EXAMPLE'; Kvno = 5; EncryptionType = 'aes256-cts-hmac-sha1-96'; Salt = $salt }
            )

            $null = $kdc | New-ObolPrincipal HTTP/web.corp.example -Key (Import-ObolKeytab $serviceKeytab) -Salt $salt
            $kdc | Export-ObolKrb5Config $krb5Conf -Provider Mit
            $kdc | Export-ObolKeytab $keytab user
            $null = Invoke-KerberosTool { kinit -k -t $keytab user@CORP.EXAMPLE }

            # The service ticket decrypts with the key and kvno from the ktutil keytab.
            Invoke-KerberosTool { kvno -k $serviceKeytab HTTP/web.corp.example@CORP.EXAMPLE } |
                Should-BeLikeString '*kvno = 5, keytab entry valid*'

            # A password login only works if the KDC sends the AD salt to the client.
            $null = Invoke-KerberosTool { 'Password123!' | kinit HTTP/web.corp.example@CORP.EXAMPLE }
        }

        It "Issues tickets a ktutil keytab validates for a principal with a password, AD salt and kvno" {
            $kdc = Start-ObolKdc CORP.EXAMPLE -Principal @{ user = $null }
            $salt = ConvertTo-ObolSalt svc_web -Realm CORP.EXAMPLE -SaltType ADUser
            $serviceKeytab = [Path]::Combine($dir, 'service.keytab')
            New-KtutilKeytab $serviceKeytab @(
                @{ Principal = 'HTTP/web.corp.example@CORP.EXAMPLE'; Kvno = 7; EncryptionType = 'aes256-cts-hmac-sha1-96'; Salt = $salt }
            )

            $null = $kdc | New-ObolPrincipal HTTP/web.corp.example -Password $password -Salt $salt -Kvno 7
            $kdc | Export-ObolKrb5Config $krb5Conf -Provider Mit
            $kdc | Export-ObolKeytab $keytab user
            $null = Invoke-KerberosTool { kinit -k -t $keytab user@CORP.EXAMPLE }

            Invoke-KerberosTool { kvno -k $serviceKeytab HTTP/web.corp.example@CORP.EXAMPLE } |
                Should-BeLikeString '*kvno = 7, keytab entry valid*'
        }
    }

    Context "Enter-ObolKrb5Environment" {
        BeforeEach {
            $kdc = Start-ObolKdc EXAMPLE.TEST -Principal @{ user = $null; 'HTTP/web.example.test' = $null }
            $client = $kdc | Get-ObolPrincipal user
            $service = $kdc | Get-ObolPrincipal HTTP/*
        }

        AfterEach {
            Exit-ObolKrb5Environment
        }

        It "Gets tickets with the variables it sets" {
            Enter-ObolKrb5Environment $kdc -ClientPrincipal $client -ServicePrincipal $service -Provider Mit
            $ccache = $env:KRB5CCNAME

            # -i uses the client keytab from KRB5_CLIENT_KTNAME.
            $null = Invoke-KerberosTool { kinit -k -i user@EXAMPLE.TEST }
            $null = Invoke-KerberosTool { kvno -S HTTP web.example.test }

            Invoke-KerberosTool { klist } | Should-BeLikeString "*Ticket cache: $ccache*"
            Invoke-KerberosTool { klist -k } | Should-BeLikeString '*HTTP/web.example.test@EXAMPLE.TEST*'
            Invoke-KerberosTool { kvno -k $env:KRB5_KTNAME HTTP/web.example.test } |
                Should-BeLikeString '*keytab entry valid*'
        }

        It "Gets a ticket in process with -SetNativeEnvironment" {
            Enter-ObolKrb5Environment $kdc -ClientPrincipal $client -Provider Mit -SetNativeEnvironment
            $null = Invoke-KerberosTool { kinit -k -i user@EXAMPLE.TEST }

            # .NET uses the system GSSAPI, which reads the native environment for krb5.conf and the ccache.
            $auth = [System.Net.Security.NegotiateAuthentication]::new(
                [System.Net.Security.NegotiateAuthenticationClientOptions]@{
                    Package = 'Kerberos'
                    TargetName = 'HTTP/web.example.test'
                })
            try {
                $status = [System.Net.Security.NegotiateAuthenticationStatusCode]::GenericFailure
                $token = $auth.GetOutgoingBlob([byte[]]@(), [ref]$status)

                $status | Should-Be ([System.Net.Security.NegotiateAuthenticationStatusCode]::Completed)
                $token.Length | Should-BeGreaterThan 0
            }
            finally {
                $auth.Dispose()
            }

            Invoke-KerberosTool { klist } | Should-BeLikeString '*HTTP/web.example.test@EXAMPLE.TEST*'
        }

        It "Mutually authenticates in process with -SetNativeEnvironment" {
            $params = @{
                Kdc = $kdc
                ClientPrincipal = $client
                ServicePrincipal = $service
                Provider = 'Mit'
                SetNativeEnvironment = $true
            }
            Enter-ObolKrb5Environment @params
            $null = Invoke-KerberosTool { kinit -k -i user@EXAMPLE.TEST }

            # .NET uses the system GSSAPI, the initiator reads the ccache and the acceptor the keytab in KRB5_KTNAME.
            $initiator = [System.Net.Security.NegotiateAuthentication]::new(
                [System.Net.Security.NegotiateAuthenticationClientOptions]@{
                    Package = 'Kerberos'
                    TargetName = 'HTTP/web.example.test'
                    RequireMutualAuthentication = $true
                })
            $acceptor = [System.Net.Security.NegotiateAuthentication]::new(
                [System.Net.Security.NegotiateAuthenticationServerOptions]@{
                    Package = 'Kerberos'
                })
            try {
                $initiatorStatus = [System.Net.Security.NegotiateAuthenticationStatusCode]::GenericFailure
                $acceptorStatus = $initiatorStatus
                $token = $initiator.GetOutgoingBlob([byte[]]@(), [ref]$initiatorStatus)
                $initiatorStatus | Should-Be ([System.Net.Security.NegotiateAuthenticationStatusCode]::ContinueNeeded)

                $reply = $acceptor.GetOutgoingBlob([byte[]]$token, [ref]$acceptorStatus)
                $acceptorStatus | Should-Be ([System.Net.Security.NegotiateAuthenticationStatusCode]::Completed)

                $null = $initiator.GetOutgoingBlob([byte[]]$reply, [ref]$initiatorStatus)
                $initiatorStatus | Should-Be ([System.Net.Security.NegotiateAuthenticationStatusCode]::Completed)
                $initiator.IsMutuallyAuthenticated | Should-BeTrue
                $acceptor.RemoteIdentity.Name | Should-Be 'user@EXAMPLE.TEST'
            }
            finally {
                $initiator.Dispose()
                $acceptor.Dispose()
            }
        }
    }

    Context "Use-ObolKrb5Environment" {
        It "Gets tickets in the scriptblock" {
            $params = @{
                Realm = 'EXAMPLE.TEST'
                Principal = @{ user = $null; 'HTTP/web.example.test' = $null }
                ClientPrincipal = 'user'
                ServicePrincipal = 'HTTP/web.example.test'
                Provider = 'Mit'
            }
            $actual = Use-ObolKrb5Environment @params {
                $null = Invoke-KerberosTool { kinit -k -i user }
                Invoke-KerberosTool { kvno -k $env:KRB5_KTNAME HTTP/web.example.test }
            }

            $actual | Should-BeLikeString '*HTTP/web.example.test@EXAMPLE.TEST: kvno = 1, keytab entry valid*'
            Get-ObolKdc | Should-BeNull
        }
    }
}
