using module ../output/Obol
using namespace System.IO
using namespace System.Net

BeforeAll { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

Describe "Trace-ObolKdc" {
    BeforeEach {
        # A user without pre-authentication gets a ticket from the minimal AS-REQ New-AsReq builds.
        $kdc = Start-ObolKdc EXAMPLE.TEST -Principal @{
            user = [Obol.ObolPrincipalSetting]@{ Flag = 'DontRequirePreAuth' }
        }
        $request = New-AsReq EXAMPLE.TEST user
    }

    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
    }

    Context "ScriptBlock" {
        It "Outputs the event of a request made in the scriptblock" {
            $before = Get-Date

            $actual = Trace-ObolKdc -Kdc $kdc {
                $script:reply = Invoke-KdcRequest -Port $kdc.Port -Request $request
            }

            $actual | Should-HaveType ([Obol.ObolKdcEvent])
            $actual.Kdc | Should-Be $kdc
            $actual.Realm | Should-Be EXAMPLE.TEST
            $actual.Time | Should-BeGreaterThanOrEqual $before
            $actual.Time | Should-BeLessThanOrEqual (Get-Date)
            $actual.Duration | Should-BeGreaterThan ([TimeSpan]::Zero)
            $actual.Transport | Should-Be ([Obol.ObolKdcTransport]::Tcp)
            $actual.ClientAddress.Address | Should-Be ([IPAddress]::Loopback)
            $actual.ClientAddress.Port | Should-NotBe $kdc.Port
            $actual.ErrorCode | Should-Be ([Obol.Kerberos.ErrorCode]::None)
            $actual.Exception | Should-BeNull
            $actual.ClientName | Should-Be 'user@EXAMPLE.TEST'
            $actual.ServiceName | Should-Be 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST'

            # The request decoded, New-AsReq sends no pre-authentication and asks for aes256 only.
            $actual.Request | Should-HaveType ([Obol.Kerberos.KdcRequest])
            $actual.Request.MessageType | Should-Be ([Obol.Kerberos.MessageType]::AsReq)
            $actual.Request.ProtocolVersion | Should-Be 5
            $actual.Request.PreAuthData.Count | Should-Be 0
            $actual.Request.Body.KdcOption | Should-Be ([Obol.Kerberos.KdcOption]::None)
            $actual.Request.Body.ClientName.FullName | Should-Be 'user@EXAMPLE.TEST'
            $actual.Request.Body.ClientName.NameType | Should-Be ([Obol.Kerberos.PrincipalNameType]::Principal)
            $actual.Request.Body.ServiceName.FullName | Should-Be 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST'
            $actual.Request.Body.ServiceName.Component | Should-BeCollection krbtgt, EXAMPLE.TEST
            $actual.Request.Body.Realm | Should-Be EXAMPLE.TEST
            $actual.Request.Body.EncryptionType | Should-Be 18
            $actual.Request.Body.Nonce | Should-Be 1234
            [Convert]::ToHexString($actual.Request.Bytes) | Should-Be ([Convert]::ToHexString($request))

            # The reply with the ticket and its decrypted parts.
            $actual.Reply | Should-HaveType ([Obol.Kerberos.KdcReply])
            $actual.Reply.MessageType | Should-Be ([Obol.Kerberos.MessageType]::AsRep)
            $actual.Reply.ClientName.FullName | Should-Be 'user@EXAMPLE.TEST'
            $actual.Reply.Ticket.ServiceName.FullName | Should-Be 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST'
            $actual.Reply.Ticket.EncryptedPart.EncryptionType | Should-Be 18
            $actual.Reply.Ticket.EncryptedPart.KeyVersion | Should-Be 1
            $actual.Reply.Ticket.DecryptedPart.Flag | Should-Be ([Obol.Kerberos.TicketFlag]::Initial)
            $actual.Reply.Ticket.DecryptedPart.Key.EncryptionType | Should-Be 18
            $actual.Reply.Ticket.DecryptedPart.Key.Value.Count | Should-Be 32
            $actual.Reply.Ticket.DecryptedPart.ClientName.FullName | Should-Be 'user@EXAMPLE.TEST'
            $actual.Reply.Ticket.DecryptedPart.StartTime | Should-HaveType ([DateTime])
            $actual.Reply.Ticket.DecryptedPart.EndTime | Should-BeGreaterThan $actual.Reply.Ticket.DecryptedPart.StartTime
            $actual.Reply.Ticket.DecryptedPart.RenewTill | Should-BeNull
            $actual.Reply.Ticket.DecryptedPart.Pac | Should-HaveType ([Obol.Kerberos.Pac])
            $actual.Reply.Ticket.DecryptedPart.Pac.LogonInfo.UserName | Should-Be user
            $actual.Reply.Ticket.DecryptedPart.Pac.LogonInfo.UserSid | Should-Be ($kdc | Get-ObolPrincipal user).Sid
            $actual.Reply.EncryptedPart.EncryptionType | Should-Be 18
            $actual.Reply.DecryptedPart.Nonce | Should-Be 1234
            [Convert]::ToHexString($actual.Reply.DecryptedPart.Key.Value) | Should-Be ([Convert]::ToHexString($actual.Reply.Ticket.DecryptedPart.Key.Value))
            [Convert]::ToHexString($actual.Reply.Bytes) | Should-Be ([Convert]::ToHexString($script:reply))

            # The user key the reply is encrypted with and the krbtgt key the ticket is encrypted with.
            $actual.Key[0] | Should-HaveType ([Obol.ObolKeytabEntry])
            $actual.Key.FullName | Should-BeCollection 'user@EXAMPLE.TEST', 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST'
            $actual.Key.Kvno | Should-BeCollection 1, 1
            $actual.Key[0].EncryptionType | Should-Be ([Obol.Kerberos.EncryptionType]::Aes256Sha1)
            $actual.Key[0].Key.Count | Should-Be 32
            $actual.Key[1].EncryptionType | Should-Be ($kdc | Get-ObolPrincipal krbtgt/*).EncryptionType[0]
        }

        It "Outputs the event of a rejected request" {
            $actual = Trace-ObolKdc -Kdc $kdc {
                $null = Invoke-KdcRequest -Port $kdc.Port -Request (New-AsReq EXAMPLE.TEST unknown) -Udp
            }

            $actual.Transport | Should-Be ([Obol.ObolKdcTransport]::Udp)
            $actual.ErrorCode | Should-Be ([Obol.Kerberos.ErrorCode]::ClientPrincipalUnknown)
            $actual.Exception | Should-BeNull
            $actual.ClientName | Should-Be 'unknown@EXAMPLE.TEST'
            $actual.ServiceName | Should-Be 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST'
            $actual.Key.Count | Should-Be 0
            $actual.Request | Should-HaveType ([Obol.Kerberos.KdcRequest])
            $actual.Request.Body.ClientName.FullName | Should-Be 'unknown@EXAMPLE.TEST'
            $actual.Reply | Should-HaveType ([Obol.Kerberos.ErrorReply])
            $actual.Reply.MessageType | Should-Be ([Obol.Kerberos.MessageType]::Error)
            $actual.Reply.ErrorCode | Should-Be ([Obol.Kerberos.ErrorCode]::ClientPrincipalUnknown)
            $actual.Reply.ErrorText | Should-BeNull
            $actual.Reply.ServiceName.FullName | Should-Be 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST'
            $actual.Reply.ServerTime | Should-HaveType ([DateTime])
            $actual.Reply.ToString() | Should-Be ClientPrincipalUnknown
            Get-KrbErrorCode $actual.Reply.Bytes | Should-Be 6
        }

        It "Outputs the event of a request that is not a Kerberos message" {
            $actual = Trace-ObolKdc -Kdc $kdc {
                $null = Invoke-KdcRequest -Port $kdc.Port -Request ([byte[]](1, 2, 3))
            }

            $actual.ErrorCode | Should-Be ([Obol.Kerberos.ErrorCode]::Generic)
            $actual.Exception | Should-BeNull
            $actual.ClientName | Should-BeNull
            $actual.Message | Should-BeLikeString 'Unknown request: Generic: Failed to process request: *'
            # A request that is not a Kerberos message is the plain message with its bytes.
            $actual.Request.GetType() | Should-Be ([Obol.Kerberos.Message])
            $actual.Request.MessageType | Should-Be ([Obol.Kerberos.MessageType]::Unknown)
            [Convert]::ToHexString($actual.Request.Bytes) | Should-Be 010203
            $actual.Reply | Should-HaveType ([Obol.Kerberos.ErrorReply])
            $actual.Reply.ErrorText | Should-BeLikeString 'Failed to process request: *'
        }

        It "Outputs the exception of a request that cannot be decoded" {
            $actual = Trace-ObolKdc -Kdc $kdc {
                # An AS-REQ application tag around a NULL rather than the KDC-REQ sequence.
                $null = Invoke-KdcRequest -Port $kdc.Port -Request ([byte[]](0x6A, 0x02, 0x05, 0x00))
            }

            $actual.ErrorCode | Should-Be ([Obol.Kerberos.ErrorCode]::Generic)
            $actual.Exception | Should-HaveType ([Exception])
            # The outer tag said AS-REQ but the contents did not decode.
            $actual.Request.GetType() | Should-Be ([Obol.Kerberos.Message])
            $actual.Request.MessageType | Should-Be ([Obol.Kerberos.MessageType]::AsReq)
            $actual.Message | Should-BeLikeString 'AS-REQ: Generic: Failed to process request: *'
            $actual.ToString() | Should-Be $actual.Message
        }

        It "Outputs the events in the order the requests were processed" {
            $actual = Trace-ObolKdc -Kdc $kdc {
                $null = Invoke-KdcRequest -Port $kdc.Port -Request $request
                $null = Invoke-KdcRequest -Port $kdc.Port -Request (New-AsReq EXAMPLE.TEST unknown)
                $null = Invoke-KdcRequest -Port $kdc.Port -Request $request -Udp
            }

            $actual.Count | Should-Be 3
            $actual.ClientName | Should-BeCollection 'user@EXAMPLE.TEST', 'unknown@EXAMPLE.TEST', 'user@EXAMPLE.TEST'
            [string[]]$actual.Transport | Should-BeCollection Tcp, Tcp, Udp
            [string[]]$actual.ErrorCode | Should-BeCollection None, ClientPrincipalUnknown, None
            [string[]]$actual.Reply.MessageType | Should-BeCollection AsRep, Error, AsRep
            $actual[0].Message | Should-Be 'AS-REQ user@EXAMPLE.TEST -> krbtgt/EXAMPLE.TEST@EXAMPLE.TEST: AS-REP, Aes256Sha1 ticket and session key, Initial'
            $actual[1].Message | Should-Be 'AS-REQ unknown@EXAMPLE.TEST -> krbtgt/EXAMPLE.TEST@EXAMPLE.TEST: ClientPrincipalUnknown'
            $actual[0].ToString() | Should-Be $actual[0].Message
        }

        It "Describes a ticket with a session key of another type" {
            # The krbtgt has a key for every type, a client that only offers aes128 gets an aes128 session key in a
            # ticket encrypted with the krbtgt's aes256 key.
            $request = New-AsReq EXAMPLE.TEST user -EncryptionType 17

            $actual = Trace-ObolKdc -Kdc $kdc {
                $null = Invoke-KdcRequest -Port $kdc.Port -Request $request
            }

            $actual.Reply.Ticket.EncryptedPart.EncryptionType | Should-Be 18
            $actual.Reply.Ticket.DecryptedPart.Key.EncryptionType | Should-Be 17
            $actual.Reply.EncryptedPart.EncryptionType | Should-Be 17
            $actual.Message | Should-Be 'AS-REQ user@EXAMPLE.TEST -> krbtgt/EXAMPLE.TEST@EXAMPLE.TEST: AS-REP, Aes256Sha1 ticket, Aes128Sha1 session key, Initial'
        }

        It "Describes a ticket without a PAC" {
            $other = Start-ObolKdc OTHER.TEST -Principal @{
                user = [Obol.ObolPrincipalSetting]@{ Flag = 'DontRequirePreAuth' }
                'HTTP/web.other.test' = [Obol.ObolPrincipalSetting]@{ Flag = 'NoAuthDataRequired' }
            }
            $request = New-AsReq OTHER.TEST user -ServiceName HTTP, web.other.test

            $actual = Trace-ObolKdc -Kdc $other {
                $null = Invoke-KdcRequest -Port $other.Port -Request $request
            }

            $actual.ServiceName | Should-Be 'HTTP/web.other.test@OTHER.TEST'
            $actual.Reply.Ticket.DecryptedPart.Pac | Should-BeNull
            $actual.Reply.Ticket.DecryptedPart.AuthorizationData.Count | Should-Be 0
            $actual.Message | Should-Be 'AS-REQ user@OTHER.TEST -> HTTP/web.other.test@OTHER.TEST: AS-REP, Aes256Sha1 ticket and session key, Initial, no PAC'
        }

        It "Runs the scriptblock in the caller's scope with the KDCs as arguments" {
            $value = 'caller'

            $actual = Trace-ObolKdc -Kdc $kdc {
                param ($first)

                $value = $first.Realm
            }

            $actual | Should-BeNull
            $value | Should-Be EXAMPLE.TEST
        }

        It "Does not output the scriptblock's output" {
            $actual = Trace-ObolKdc -Kdc $kdc { 'output' }

            $actual | Should-BeNull
        }

        It "Outputs the events before the scriptblock's error" {
            $actual = try {
                Trace-ObolKdc -Kdc $kdc {
                    $null = Invoke-KdcRequest -Port $kdc.Port -Request $request
                    throw 'boom'
                }
            }
            catch {
                $script:caught = $_
            }

            $actual | Should-HaveType ([Obol.ObolKdcEvent])
            $actual.ClientName | Should-Be 'user@EXAMPLE.TEST'
            $script:caught.Exception.Message | Should-Be boom
        }

        It "Only traces the KDCs given to -Kdc" {
            $other = Start-ObolKdc OTHER.TEST

            $actual = $kdc | Trace-ObolKdc {
                $null = Invoke-KdcRequest -Port $kdc.Port -Request $request
                $null = Invoke-KdcRequest -Port $other.Port -Request (New-AsReq OTHER.TEST user)
            }

            $actual | Should-HaveType ([Obol.ObolKdcEvent])
            $actual.Realm | Should-Be EXAMPLE.TEST
        }

        It "Traces a KDC given more than once, once" {
            $actual = Trace-ObolKdc -Kdc $kdc, $kdc {
                $null = Invoke-KdcRequest -Port $kdc.Port -Request $request
            }

            $actual | Should-HaveType ([Obol.ObolKdcEvent])
        }

        It "Fails for an empty -Kdc" {
            $script:ran = $false

            { Trace-ObolKdc -Kdc @() { $script:ran = $true } } |
                Should-Throw -FullyQualifiedErrorId 'ParameterArgumentValidationError,Obol.Commands.TraceObolKdc'

            $script:ran | Should-BeFalse
        }

        It "Fails if no KDC is received from the pipeline" {
            { @() | Trace-ObolKdc { 'ran' } } | Should-Throw -FullyQualifiedErrorId 'NoKdc,Obol.Commands.TraceObolKdc'
        }

        It "Fails for a stopped KDC without running the scriptblock" {
            Stop-ObolKdc $kdc
            $script:ran = $false

            { Trace-ObolKdc -Kdc $kdc { $script:ran = $true } } |
                Should-Throw -FullyQualifiedErrorId 'KdcNotRunning,Obol.Commands.TraceObolKdc'

            $script:ran | Should-BeFalse
        }
    }

    Context "Streaming" {
        BeforeEach {
            # The requests are made from another runspace while this one blocks in Trace-ObolKdc.
            $ps = New-ObolPowerShell
            $sendUdp = {
                param ($Port, [byte[]]$Request, $Count)

                Start-Sleep -Milliseconds 300
                $client = [System.Net.Sockets.UdpClient]::new()
                $endpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, $Port)
                foreach ($i in 1..$Count) {
                    $null = $client.Send($Request, $Request.Length, $endpoint)
                    Start-Sleep -Milliseconds 50
                }
                $client.Dispose()
            }
        }

        AfterEach {
            $ps.Dispose()
        }

        It "Outputs events as they happen until the pipeline is stopped" {
            $null = $ps.AddScript($sendUdp).AddArgument($kdc.Port).AddArgument($request).AddArgument(5)
            $async = $ps.BeginInvoke()
            try {
                $actual = Trace-ObolKdc -Kdc $kdc | Select-Object -First 2
            }
            finally {
                $ps.EndInvoke($async)
            }

            $actual.Count | Should-Be 2
            $actual[0] | Should-HaveType ([Obol.ObolKdcEvent])
            [string[]]$actual.Transport | Should-BeCollection Udp, Udp
            $actual.ClientName | Should-BeCollection 'user@EXAMPLE.TEST', 'user@EXAMPLE.TEST'
            $kdc.State | Should-Be ([Obol.ObolKdcState]::Running)
        }

        It "Stops when the pipeline is stopped, like Ctrl+C" {
            # Trace-ObolKdc blocks in the other runspace, stopping that pipeline is what Ctrl+C does.
            $null = $ps.AddScript({
                    param ($Kdc)

                    Trace-ObolKdc -Kdc $Kdc
                }).AddArgument($kdc)
            $async = $ps.BeginInvoke()
            Start-Sleep -Milliseconds 300
            $ps.InvocationStateInfo.State | Should-Be Running

            $ps.Stop()

            $ps.InvocationStateInfo.State | Should-Be Stopped
            $ps.Streams.Error.Count | Should-Be 0
            $kdc.State | Should-Be ([Obol.ObolKdcState]::Running)
        }

        It "Keeps the events in -OutVariable when the pipeline is stopped" {
            # The way to capture a trace of external clients: Ctrl+C ends the trace, the variable keeps the events.
            $null = $ps.AddScript({
                    param ($Kdc)

                    Trace-ObolKdc -Kdc $Kdc -OutVariable events
                }).AddArgument($kdc)
            $async = $ps.BeginInvoke()
            Start-Sleep -Milliseconds 300
            1..3 | ForEach-Object { $null = Invoke-KdcRequest -Port $kdc.Port -Request $request -Udp }
            Start-Sleep -Milliseconds 300

            $ps.Stop()

            $actual = $ps.Runspace.SessionStateProxy.GetVariable('events')
            $actual.Count | Should-Be 3
            $actual[0] | Should-HaveType ([Obol.ObolKdcEvent])
            $actual.ClientName | Should-BeCollection 'user@EXAMPLE.TEST', 'user@EXAMPLE.TEST', 'user@EXAMPLE.TEST'
        }

        It "Ends when every traced KDC has stopped" {
            $null = $ps.AddScript({
                    param ($Kdc)

                    Start-Sleep -Milliseconds 300
                    $Kdc.Dispose()
                }).AddArgument($kdc)
            $async = $ps.BeginInvoke()
            try {
                $actual = Trace-ObolKdc -Kdc $kdc
            }
            finally {
                $ps.EndInvoke($async)
            }

            $actual | Should-BeNull
            $kdc.State | Should-Be ([Obol.ObolKdcState]::Stopped)
        }

        It "Keeps tracing while one of the KDCs runs" {
            $other = Start-ObolKdc OTHER.TEST
            $null = $ps.AddScript({
                    param ($Other, $Port, [byte[]]$Request)

                    Start-Sleep -Milliseconds 200
                    $Other.Dispose()
                    Start-Sleep -Milliseconds 200
                    $client = [System.Net.Sockets.UdpClient]::new()
                    $null = $client.Send($Request, $Request.Length,
                        [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, $Port))
                    $client.Dispose()
                }).AddArgument($other).AddArgument($kdc.Port).AddArgument($request)
            $async = $ps.BeginInvoke()
            try {
                $actual = Trace-ObolKdc -Kdc $kdc, $other | Select-Object -First 1
            }
            finally {
                $ps.EndInvoke($async)
            }

            $actual.Realm | Should-Be EXAMPLE.TEST
        }
    }

    Context "RequestProcessed event" {
        It "Is received by Register-ObjectEvent" {
            $null = Register-ObjectEvent -InputObject $kdc -EventName RequestProcessed -SourceIdentifier ObolTest
            try {
                $null = Invoke-KdcRequest -Port $kdc.Port -Request $request

                $actual = Wait-Event -SourceIdentifier ObolTest -Timeout 5
                $actual | Should-NotBeNull
                $actual | Remove-Event
                $actual.Sender | Should-Be $kdc
                $actual.SourceEventArgs | Should-HaveType ([Obol.ObolKdcEvent])
                $actual.SourceEventArgs.ClientName | Should-Be 'user@EXAMPLE.TEST'
                $actual.SourceEventArgs.ErrorCode | Should-Be ([Obol.Kerberos.ErrorCode]::None)
            }
            finally {
                Unregister-Event -SourceIdentifier ObolTest
            }
        }

        It "Ignores a failing handler and still replies" {
            # The scriptblock fails on the KDC thread as it has no runspace, like a handler that throws.
            $handler = [EventHandler[Obol.ObolKdcEvent]]{ throw 'handler' }
            $kdc.add_RequestProcessed($handler)
            try {
                $actual = Trace-ObolKdc -Kdc $kdc {
                    $script:reply = Invoke-KdcRequest -Port $kdc.Port -Request $request
                }
            }
            finally {
                $kdc.remove_RequestProcessed($handler)
            }

            # The AS-REP application tag.
            $script:reply[0] | Should-Be 0x6B
            $actual.ErrorCode | Should-Be ([Obol.Kerberos.ErrorCode]::None)
            $kdc.State | Should-Be ([Obol.ObolKdcState]::Running)
        }
    }
}
