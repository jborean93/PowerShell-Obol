using module ../output/Obol
using namespace System.Collections.Generic
using namespace System.Formats.Asn1
using namespace System.IO
using namespace System.Management.Automation
using namespace System.Management.Automation.Runspaces
using namespace System.Net
using namespace System.Net.Sockets
using namespace System.Reflection

BeforeAll {
    . ([Path]::Combine($PSScriptRoot, 'common.ps1'))

    # The KRB-ERROR codes the tests expect, RFC 4120 7.5.9.
    $KrbErrorCode = @{
        KDC_ERR_C_PRINCIPAL_UNKNOWN = 6
        KRB_ERR_RESPONSE_TOO_BIG = 52
        KRB_ERR_GENERIC = 60
        KRB_ERR_FIELD_TOOLONG = 61
        KDC_ERR_WRONG_REALM = 68
    }

}

Describe "Start-ObolKdc" {
    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
    }

    It "Starts a KDC on a random loopback port" {
        $kdc = Start-ObolKdc -Realm EXAMPLE.TEST

        $kdc | Should-HaveType ([Obol.ObolKdc])
        $kdc.Realm | Should-Be EXAMPLE.TEST
        $kdc.Endpoint.Address | Should-Be ([IPAddress]::Loopback)
        $kdc.Port | Should-BeGreaterThan 0
        $kdc.Port | Should-Be $kdc.Endpoint.Port
        $kdc.State | Should-Be ([Obol.ObolKdcState]::Running)
        $kdc.Error | Should-BeNull
        $kdc.Transport | Should-Be ([Obol.ObolKdcTransport]'Tcp, Udp')
        $kdc.MaxUdpReplySize | Should-Be 4096
        $kdc.CaseInsensitivePrincipal | Should-BeFalse
        $kdc.DomainSid | Should-MatchString '^S-1-5-21-\d+-\d+-\d+$'
        $kdc.StartTime | Should-BeBefore -Expected ([DateTime]::Now.AddSeconds(1))
        $kdc.ToString() | Should-Be "EXAMPLE.TEST (127.0.0.1:$($kdc.Port))"

        $actual = Get-ObolKdc
        $actual | Should-BeSame $kdc
    }

    It "Starts a KDC on a specific port" {
        $port = Get-FreePort
        $kdc = Start-ObolKdc EXAMPLE.TEST -Port $port

        $kdc.Port | Should-Be $port
    }

    It "Starts a KDC on an IPv6 address" {
        $kdc = Start-ObolKdc EXAMPLE.TEST -Address ([IPAddress]::IPv6Loopback)

        $kdc.Endpoint.Address | Should-Be ([IPAddress]::IPv6Loopback)
        $request = New-AsReq EXAMPLE.TEST user
        $response = Invoke-KdcRequest -Port $kdc.Port -Request $request -Address ([IPAddress]::IPv6Loopback)
        Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
        $response = Invoke-KdcRequest -Port $kdc.Port -Request $request -Address ([IPAddress]::IPv6Loopback) -Udp
        Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
    }

    It "Starts a KDC on all IPv4 addresses" {
        $kdc = Start-ObolKdc EXAMPLE.TEST -Address ([IPAddress]::Any)

        $kdc.Endpoint.Address | Should-Be ([IPAddress]::Any)
        $request = New-AsReq EXAMPLE.TEST user
        $response = Invoke-KdcRequest -Port $kdc.Port -Request $request
        Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
        $response = Invoke-KdcRequest -Port $kdc.Port -Request $request -Udp
        Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
    }

    It "Starts a KDC on all addresses" {
        $kdc = Start-ObolKdc EXAMPLE.TEST -Address ([IPAddress]::IPv6Any)

        # IPv6Any is dual mode so IPv4 clients can connect.
        $response = Invoke-KdcRequest -Port $kdc.Port -Request (New-AsReq EXAMPLE.TEST user)
        Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
    }

    It "Responds to an AS-REQ over UDP" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $response = Invoke-KdcRequest -Port $kdc.Port -Request (New-AsReq EXAMPLE.TEST user) -Udp

        Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
    }

    It "Responds over UDP on all addresses" {
        $kdc = Start-ObolKdc EXAMPLE.TEST -Address ([IPAddress]::IPv6Any)

        $response = Invoke-KdcRequest -Port $kdc.Port -Request (New-AsReq EXAMPLE.TEST user) -Udp

        Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
    }

    It "Responds with KRB_ERR_RESPONSE_TOO_BIG when the UDP reply is too large" {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        # The wrong realm error includes the realm once so a long realm makes a reply over the 4096 byte default.
        # The request has it twice and macOS limits a sent datagram to 9216 bytes (net.inet.udp.maxdgram), so the
        # realm must stay under about 4500 characters.
        $realm = 'A' * 4200
        $request = New-AsReq $realm user

        $response = Invoke-KdcRequest -Port $kdc.Port -Request $request -Udp
        $actual = Get-KrbError $response
        $actual.ErrorCode | Should-Be $KrbErrorCode.KRB_ERR_RESPONSE_TOO_BIG
        $actual.EText | Should-BeLikeString '*too big for UDP, retry over TCP'

        # The same request over TCP gets the full reply.
        $response = Invoke-KdcRequest -Port $kdc.Port -Request $request
        $response.Length | Should-BeGreaterThan 4096
        $actual = Get-KrbError $response
        $actual.ErrorCode | Should-Be $KrbErrorCode.KDC_ERR_WRONG_REALM
        $actual.EText | Should-BeLikeString "*'$realm'"
    }

    It "Responds with an error to an invalid UDP request" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $response = Invoke-KdcRequest -Port $kdc.Port -Request ([byte[]]@(0x6A)) -Udp

        $actual = Get-KrbError $response
        $actual.ErrorCode | Should-Be $KrbErrorCode.KRB_ERR_GENERIC
        $actual.EText | Should-BeLikeString 'Failed to process request: *'
    }

    It "Ignores an empty UDP datagram" {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $request = New-AsReq EXAMPLE.TEST user
        $remote = [IPEndPoint]::new([IPAddress]::Loopback, $kdc.Port)

        $client = [UdpClient]::new()
        try {
            $null = $client.Send([byte[]]::new(0), 0, $remote)
            $null = $client.Send($request, $request.Length, $remote)

            # Collect every reply until none arrive for a second, only the real request is answered.
            $client.Client.ReceiveTimeout = 1000
            $codes = while ($true) {
                try {
                    $from = $null
                    Get-KrbErrorCode $client.Receive([ref]$from)
                }
                catch [SocketException] {
                    break
                }
            }
        }
        finally {
            $client.Dispose()
        }

        $codes | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
    }

    It "Sends a UDP reply exactly at the size limit" {
        # A KRB-ERROR includes the current microseconds as a DER INTEGER so its length varies by up to 2 bytes.
        # The longest form, a 3 byte value, is used for nearly every reply.
        $request = New-AsReq EXAMPLE.TEST user
        $kdc = Start-ObolKdc EXAMPLE.TEST -Transport Tcp
        $response = Invoke-KdcRequest -Port $kdc.Port -Request $request
        $maxLength = $response.Length + 3 - (Get-KrbError $response).CusecLength
        $kdc.Dispose()

        # At the limit every reply fits, retry until one is exactly the limit to check the boundary.
        $kdc = Start-ObolKdc EXAMPLE.TEST -MaxUdpReplySize $maxLength
        $exact = $false
        foreach ($i in 1..20) {
            $response = Invoke-KdcRequest -Port $kdc.Port -Request $request -Udp
            Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
            if ($response.Length -eq $maxLength) {
                $exact = $true
                break
            }
        }
        $exact | Should-BeTrue
        $kdc.Dispose()

        # One byte under the limit, a reply of the longest form is too big.
        $kdc = Start-ObolKdc EXAMPLE.TEST -MaxUdpReplySize ($maxLength - 1)
        $tooBig = $false
        foreach ($i in 1..20) {
            $actual = Get-KrbError (Invoke-KdcRequest -Port $kdc.Port -Request $request -Udp)
            if ($actual.ErrorCode -eq 52) {
                $actual.EText | Should-Be "Response of $maxLength bytes is too big for UDP, retry over TCP"
                $tooBig = $true
                break
            }
            $actual.ErrorCode | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
        }
        $tooBig | Should-BeTrue
    }

    It "Responds to concurrent clients" {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $request = New-AsReq EXAMPLE.TEST user
        $remote = [IPEndPoint]::new([IPAddress]::Loopback, $kdc.Port)
        $udpClients = [List[UdpClient]]::new()
        $tcpClients = [List[TcpClient]]::new()
        try {
            # Send every request before reading any reply so they are all outstanding at once.
            foreach ($i in 1..20) {
                $udp = [UdpClient]::new()
                $udp.Client.ReceiveTimeout = 5000
                $udpClients.Add($udp)
                $null = $udp.Send($request, $request.Length, $remote)

                $tcp = [TcpClient]::new()
                $tcpClients.Add($tcp)
                $tcp.Connect([IPAddress]::Loopback, $kdc.Port)
                Write-TcpRequest $tcp.GetStream() $request
            }

            foreach ($udp in $udpClients) {
                $from = $null
                Get-KrbErrorCode $udp.Receive([ref]$from) | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
            }
            foreach ($tcp in $tcpClients) {
                $response = Read-TcpResponse $tcp.GetStream()
                Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
            }
        }
        finally {
            $udpClients | ForEach-Object Dispose
            $tcpClients | ForEach-Object Dispose
        }
    }

    It "Starts a KDC for <Transport> only" -TestCases @(
        @{ Transport = 'Tcp'; Other = 'Udp' }
        @{ Transport = 'Udp'; Other = 'Tcp' }
    ) {
        param ($Transport, $Other)

        $kdc = Start-ObolKdc EXAMPLE.TEST -Transport $Transport

        $kdc.Transport | Should-Be ([Obol.ObolKdcTransport]$Transport)
        Test-PortFree -Port $kdc.Port -Udp:($Transport -eq 'Udp') | Should-BeFalse
        Test-PortFree -Port $kdc.Port -Udp:($Other -eq 'Udp') | Should-BeTrue

        $response = Invoke-KdcRequest -Port $kdc.Port -Request (New-AsReq EXAMPLE.TEST user) -Udp:($Transport -eq 'Udp')
        Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
    }

    It "Starts a KDC with -Transport Tcp, Udp" {
        $kdc = Start-ObolKdc EXAMPLE.TEST -Transport Tcp, Udp

        $kdc.Transport | Should-Be ([Obol.ObolKdcTransport]'Tcp, Udp')
    }

    It "Fails with an invalid transport <Value>" -TestCases @(
        @{ Value = 0; ErrorId = 'InvalidTransport' }
        @{ Value = 4; ErrorId = 'CannotConvertArgumentNoMessage' }
        @{ Value = [Enum]::ToObject([Obol.ObolKdcTransport], 4); ErrorId = 'InvalidTransport' }
        @{ Value = [Enum]::ToObject([Obol.ObolKdcTransport], 5); ErrorId = 'InvalidTransport' }
    ) {
        param ($Value, $ErrorId)

        { Start-ObolKdc EXAMPLE.TEST -Transport $Value } |
            Should-Throw -FullyQualifiedErrorId "$ErrorId,Obol.Commands.StartObolKdc"
        Get-ObolKdc | Should-BeNull
    }

    It "Uses a custom UDP reply size limit" {
        $kdc = Start-ObolKdc EXAMPLE.TEST -MaxUdpReplySize 50
        $request = New-AsReq EXAMPLE.TEST user

        $kdc.MaxUdpReplySize | Should-Be 50

        $actual = Get-KrbError (Invoke-KdcRequest -Port $kdc.Port -Request $request -Udp)
        $actual.ErrorCode | Should-Be $KrbErrorCode.KRB_ERR_RESPONSE_TOO_BIG

        $response = Invoke-KdcRequest -Port $kdc.Port -Request $request
        Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
    }

    It "Fails with an invalid UDP reply size <Value>" -TestCases @(
        @{ Value = 0 }
        @{ Value = 65508 }
    ) {
        param ($Value)

        { Start-ObolKdc EXAMPLE.TEST -MaxUdpReplySize $Value } |
            Should-Throw -FullyQualifiedErrorId 'ParameterArgumentValidationError,Obol.Commands.StartObolKdc'
    }

    It "Starts a KDC with -CaseInsensitivePrincipal" {
        $kdc = Start-ObolKdc EXAMPLE.TEST -CaseInsensitivePrincipal

        $kdc.CaseInsensitivePrincipal | Should-BeTrue
    }

    It "Creates principals with -Principal" {
        $password = ConvertTo-SecureString -String 'Password123!' -AsPlainText -Force

        $kdc = Start-ObolKdc EXAMPLE.TEST -Principal ([ordered]@{
            user = $password
            'HTTP/web.example.test' = $null
            roast = New-ObolPrincipalSetting -Password $password -Flag DontRequirePreAuth
            'HTTP/sql' = New-ObolPrincipalSetting -EncryptionType Aes128Sha1 -Alias MSSQLSvc/sql, HTTP/db
            admin = New-ObolPrincipalSetting -Password $password -Rid 500
            setting = New-ObolPrincipalSetting -Rid 600 -Alias other
            cast = [Obol.ObolPrincipalSetting]@{ Flag = 'DontRequirePreAuth' }
        })

        $actual = Get-ObolPrincipal -Kdc $kdc
        $actual.FullName | Should-BeCollection @(
            'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST'
            'user@EXAMPLE.TEST'
            'HTTP/web.example.test@EXAMPLE.TEST'
            'roast@EXAMPLE.TEST'
            'HTTP/sql@EXAMPLE.TEST'
            'admin@EXAMPLE.TEST'
            'setting@EXAMPLE.TEST'
            'cast@EXAMPLE.TEST'
        )
        $actual[1].Sid | Should-Be "$($kdc.DomainSid)-1000"
        $actual[3].Flag | Should-Be ([Obol.Kerberos.PacUserAccountControl]::DontRequirePreAuth)
        $actual[4].EncryptionType | Should-Be ([Obol.Kerberos.EncryptionType]::Aes128Sha1)
        $actual[4].Alias | Should-BeCollection @('MSSQLSvc/sql', 'HTTP/db')
        $actual[5].Sid | Should-Be "$($kdc.DomainSid)-500"
        $actual[6].Sid | Should-Be "$($kdc.DomainSid)-600"
        $actual[6].Alias | Should-BeCollection @('other')
        $actual[7].Flag | Should-Be ([Obol.Kerberos.PacUserAccountControl]::DontRequirePreAuth)
    }

    It "Fails with an invalid -Principal <Case>" -TestCases @(
        @{ Case = 'value'; Value = @{ user = 'plaintext' }; ErrorId = 'InvalidPrincipalArgument'; Message = "Invalid principal 'user' in -Principal: The value must be null for random keys, a SecureString password, or an ObolPrincipalSetting, got 'System.String'" }
        @{ Case = 'hashtable'; Value = @{ user = @{ Rid = 500 } }; ErrorId = 'InvalidPrincipalArgument'; Message = "Invalid principal 'user' in -Principal: The value must be null for random keys, a SecureString password, or an ObolPrincipalSetting, got 'System.Collections.Hashtable'" }
        @{ Case = 'rid'; Value = @{ user = [Obol.ObolPrincipalSetting]@{ Rid = 0 } }; ErrorId = 'InvalidRid'; Message = 'The RID must be greater than 0, got 0' }
        @{ Case = 'alias'; Value = @{ user = [Obol.ObolPrincipalSetting]@{ Alias = @($null) } }; ErrorId = 'InvalidPrincipalName'; Message = 'An alias must not be null or empty' }
        @{ Case = 'password'; Value = @{ user = [Obol.ObolPrincipalSetting]@{ Password = [SecureString]::new() } }; ErrorId = 'EmptyPassword'; Message = 'The password must not be empty' }
        @{ Case = 'name'; Value = @{ 'a//b' = $null }; ErrorId = 'InvalidPrincipalName'; Message = "Invalid principal name 'a//b': a name component is empty" }
        @{ Case = 'duplicate'; Value = @{ 'krbtgt/EXAMPLE.TEST' = $null }; ErrorId = 'PrincipalAlreadyExists'; Message = "The principal name 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST' is already used" }
    ) {
        param ($Value, $ErrorId, $Message)

        $err = { Start-ObolKdc EXAMPLE.TEST -Principal $Value } |
            Should-Throw -FullyQualifiedErrorId "$ErrorId,Obol.Commands.StartObolKdc"
        $err.Exception.Message | Should-BeLikeString $Message

        # The KDC is stopped and not listed.
        Get-ObolKdc | Should-BeNull
    }

    It "Uses the domain SID '<Value>'" -TestCases @(
        @{ Value = 'S-1-5-21-1-2-3'; Expected = 'S-1-5-21-1-2-3' }
        @{ Value = 's-1-5-21-4294967295-0-123'; Expected = 'S-1-5-21-4294967295-0-123' }
    ) {
        param ($Value, $Expected)

        $kdc = Start-ObolKdc EXAMPLE.TEST -DomainSid $Value -Principal @{ user = $null }

        $kdc.DomainSid | Should-Be $Expected
        (Get-ObolPrincipal -Kdc $kdc).Sid | Should-BeCollection @("$Expected-502", "$Expected-1000")
    }

    It "Fails with an invalid domain SID '<Value>'" -TestCases @(
        @{ Value = 'S-1-5-21-1-2' }
        @{ Value = 'S-1-5-21-1-2-3-4' }
        @{ Value = 'S-1-5-32-1-2-3' }
        @{ Value = 'S-1-5-21-1-2-4294967296' }
        @{ Value = 'S-1-5-21-1-2--3' }
        @{ Value = 'S-1-5-21-a-b-c' }
    ) {
        param ($Value)

        $err = { Start-ObolKdc EXAMPLE.TEST -DomainSid $Value } |
            Should-Throw -FullyQualifiedErrorId 'InvalidDomainSid,Obol.Commands.StartObolKdc'
        $err.Exception.Message | Should-Be "The domain SID '$Value' must be in the form S-1-5-21-<a>-<b>-<c> where each value is a 32-bit unsigned integer"
        Get-ObolKdc | Should-BeNull
    }

    It "Gives each KDC a different domain SID" {
        $kdc1 = Start-ObolKdc EXAMPLE.TEST
        $kdc2 = Start-ObolKdc EXAMPLE.TEST

        $kdc1.DomainSid | Should-NotBe $kdc2.DomainSid
    }

    It "Creates the krbtgt principal" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $actual = Get-ObolPrincipal -Kdc $kdc

        $actual.FullName | Should-Be 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST'
        $actual.Sid | Should-Be "$($kdc.DomainSid)-502"
    }

    It "Matches the realm case sensitively" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $actual = Get-KrbError (Invoke-KdcRequest -Port $kdc.Port -Request (New-AsReq example.test user))

        $actual.ErrorCode | Should-Be $KrbErrorCode.KDC_ERR_WRONG_REALM
        $actual.EText | Should-Be "The KDC does not serve the realm 'example.test'"
    }

    It "Fails with an invalid realm '<Value>'" -TestCases @(
        @{ Value = 'EX/AMPLE' }
        @{ Value = 'EX@AMPLE' }
        @{ Value = 'EX\AMPLE' }
        @{ Value = "EX`tAMPLE" }
    ) {
        param ($Value)

        $err = { Start-ObolKdc $Value } | Should-Throw -FullyQualifiedErrorId 'InvalidRealm,Obol.Commands.StartObolKdc'
        $err.Exception.Message | Should-Be "The realm '$Value' must not contain '/', '@', '\' or control characters"
        Get-ObolKdc | Should-BeNull
    }

    It "Serves a lower case realm" {
        $kdc = Start-ObolKdc example.test

        $kdc.Realm | Should-Be example.test
        $response = Invoke-KdcRequest -Port $kdc.Port -Request (New-AsReq example.test user)
        Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
        $response = Invoke-KdcRequest -Port $kdc.Port -Request (New-AsReq EXAMPLE.TEST user)
        Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_WRONG_REALM
    }

    It "Sets the state to faulted when a receive loop fails" {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $port = $kdc.Port
        $err = [InvalidOperationException]::new('test fault')

        # There is no reliable way to make a socket fail, call the fault handler the listener uses directly.
        $onFault = [Obol.ObolKdc].GetMethod('OnFault', [BindingFlags]'Instance, NonPublic')
        $null = $onFault.Invoke($kdc, @($err))

        $kdc.State | Should-Be ([Obol.ObolKdcState]::Faulted)
        $kdc.Error | Should-BeSame $err

        # The listener is stopped in the background.
        $timeout = [DateTime]::UtcNow.AddSeconds(10)
        while (-not (Test-PortFree $port) -and [DateTime]::UtcNow -lt $timeout) {
            Start-Sleep -Milliseconds 50
        }
        Test-PortFree $port | Should-BeTrue
        Test-PortFree $port -Udp | Should-BeTrue

        # It stays listed until stopped so the failure is visible.
        Get-ObolKdc | Should-BeSame $kdc
        $kdc | Stop-ObolKdc
        Get-ObolKdc | Should-BeNull
        $kdc.State | Should-Be ([Obol.ObolKdcState]::Faulted)
    }

    It "Keeps the first fault" {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $first = [InvalidOperationException]::new('first')
        $onFault = [Obol.ObolKdc].GetMethod('OnFault', [BindingFlags]'Instance, NonPublic')

        $null = $onFault.Invoke($kdc, @($first))
        $null = $onFault.Invoke($kdc, @([InvalidOperationException]::new('second')))

        $kdc.State | Should-Be ([Obol.ObolKdcState]::Faulted)
        $kdc.Error | Should-BeSame $first
    }

    It "Ignores a fault after the KDC is stopped" {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $kdc.Dispose()
        $onFault = [Obol.ObolKdc].GetMethod('OnFault', [BindingFlags]'Instance, NonPublic')

        $null = $onFault.Invoke($kdc, @([InvalidOperationException]::new('late')))

        $kdc.State | Should-Be ([Obol.ObolKdcState]::Stopped)
        $kdc.Error | Should-BeNull
    }

    It "Completes -Address with '<Word>'" -TestCases @(
        @{ Word = ''; Expected = '127.0.0.1', '::1', '0.0.0.0', '::' }
        @{ Word = ':'; Expected = '::1', '::' }
        @{ Word = '0'; Expected = , '0.0.0.0' }
        @{ Word = "'1"; Expected = , '127.0.0.1' }
        @{ Word = '10'; Expected = @() }
    ) {
        param ($Word, $Expected)

        $line = "Start-ObolKdc EXAMPLE.TEST -Address $Word"
        $actual = TabExpansion2 -inputScript $line -cursorColumn $line.Length

        @($actual.CompletionMatches | ForEach-Object CompletionText) | Should-BeCollection $Expected
        if ($Word -eq '') {
            $actual.CompletionMatches[0].ToolTip | Should-Be 'IPv4 loopback, only reachable from this host (default)'
        }
    }

    It "Starts multiple KDCs" {
        $kdc1 = Start-ObolKdc EXAMPLE.TEST
        $kdc2 = Start-ObolKdc OTHER.TEST

        $kdc1.Port | Should-NotBe $kdc2.Port

        $actual = Get-ObolKdc
        $actual.Count | Should-Be 2
        $actual[0] | Should-BeSame $kdc1
        $actual[1] | Should-BeSame $kdc2
    }

    It "Fails when the port is in use" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $err = { Start-ObolKdc OTHER.TEST -Port $kdc.Port } |
            Should-Throw -FullyQualifiedErrorId 'KdcBindFailed,Obol.Commands.StartObolKdc'
        $err.ErrorDetails.Message | Should-BeLikeString "Failed to start the KDC for 'OTHER.TEST' on 127.0.0.1:$($kdc.Port): *"

        (Get-ObolKdc).Count | Should-Be 1
    }

    It "Suggests another loopback address when the port is in use" -Skip:(-not $IsWindows) {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $err = { Start-ObolKdc OTHER.TEST -Port $kdc.Port } |
            Should-Throw -FullyQualifiedErrorId 'KdcBindFailed,Obol.Commands.StartObolKdc'
        $err.ErrorDetails.Message | Should-BeLikeString '* Use -Address with another 127.0.0.x address *'
    }

    It "Does not suggest an address when the port is held exclusively on every address" -Skip:(-not $IsWindows) {
        $tcp = [Socket]::new([AddressFamily]::InterNetwork, [SocketType]::Stream, [ProtocolType]::Tcp)
        try {
            $tcp.ExclusiveAddressUse = $true
            $tcp.Bind([IPEndPoint]::new([IPAddress]::Any, 0))
            $tcp.Listen()
            $port = $tcp.LocalEndPoint.Port

            $err = { Start-ObolKdc EXAMPLE.TEST -Port $port } |
                Should-Throw -FullyQualifiedErrorId 'KdcBindFailed,Obol.Commands.StartObolKdc'
            $err.ErrorDetails.Message | Should-NotBeLikeString '*-Address*'
        }
        finally {
            $tcp.Dispose()
        }
    }

    It "Does not suggest an address for a KDC not on a loopback address" -Skip:(-not $IsWindows) {
        $kdc = Start-ObolKdc EXAMPLE.TEST -Address 0.0.0.0

        $err = { Start-ObolKdc OTHER.TEST -Address 0.0.0.0 -Port $kdc.Port } |
            Should-Throw -FullyQualifiedErrorId 'KdcBindFailed,Obol.Commands.StartObolKdc'
        $err.ErrorDetails.Message | Should-NotBeLikeString '*-Address*'
    }

    It "Fails when the port is in use for UDP" {
        $udp = [UdpClient]::new([IPEndPoint]::new([IPAddress]::Loopback, 0))
        try {
            $port = $udp.Client.LocalEndPoint.Port

            { Start-ObolKdc EXAMPLE.TEST -Port $port } |
                Should-Throw -FullyQualifiedErrorId 'KdcBindFailed,Obol.Commands.StartObolKdc'
        }
        finally {
            $udp.Dispose()
        }

        Get-ObolKdc | Should-BeNull
    }

    It "Responds to an AS-REQ for an unknown principal" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $response = Invoke-KdcRequest -Port $kdc.Port -Request (New-AsReq EXAMPLE.TEST user)

        Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
    }

    It "Responds to an AS-REQ for a realm it does not serve" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $response = Invoke-KdcRequest -Port $kdc.Port -Request (New-AsReq OTHER.TEST user)

        Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_WRONG_REALM
    }

    It "Handles multiple requests on one connection" {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $request = New-AsReq EXAMPLE.TEST user

        $client = [TcpClient]::new()
        try {
            $client.Connect([IPAddress]::Loopback, $kdc.Port)
            $stream = $client.GetStream()
            $length = [byte[]]::new(4)
            [Buffers.Binary.BinaryPrimitives]::WriteInt32BigEndian($length, $request.Length)

            foreach ($i in 1..2) {
                $stream.Write($length, 0, 4)
                $stream.Write($request, 0, $request.Length)

                $respLength = [byte[]]::new(4)
                $stream.ReadExactly($respLength, 0, 4)
                $response = [byte[]]::new([Buffers.Binary.BinaryPrimitives]::ReadInt32BigEndian($respLength))
                $stream.ReadExactly($response, 0, $response.Length)

                Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
            }
        }
        finally {
            $client.Dispose()
        }
    }

    It "Handles a TCP request split across writes" {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $request = New-AsReq EXAMPLE.TEST user
        $length = [byte[]]::new(4)
        [Buffers.Binary.BinaryPrimitives]::WriteInt32BigEndian($length, $request.Length)
        $half = [int]($request.Length / 2)

        $client = [TcpClient]::new()
        try {
            $client.NoDelay = $true
            $client.Connect([IPAddress]::Loopback, $kdc.Port)
            $stream = $client.GetStream()

            # The length prefix one byte at a time then the request in two parts.
            foreach ($b in $length) {
                $stream.Write([byte[]]@($b), 0, 1)
                Start-Sleep -Milliseconds 20
            }
            $stream.Write($request, 0, $half)
            Start-Sleep -Milliseconds 20
            $stream.Write($request, $half, $request.Length - $half)

            Get-KrbErrorCode (Read-TcpResponse $stream) | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
        }
        finally {
            $client.Dispose()
        }
    }

    It "Handles pipelined TCP requests" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $client = [TcpClient]::new()
        try {
            $client.Connect([IPAddress]::Loopback, $kdc.Port)
            $stream = $client.GetStream()

            # Both requests are sent before reading, the replies come back in order.
            Write-TcpRequest $stream (New-AsReq EXAMPLE.TEST user)
            Write-TcpRequest $stream (New-AsReq OTHER.TEST user)

            Get-KrbErrorCode (Read-TcpResponse $stream) | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
            Get-KrbErrorCode (Read-TcpResponse $stream) | Should-Be $KrbErrorCode.KDC_ERR_WRONG_REALM
        }
        finally {
            $client.Dispose()
        }
    }

    It "Responds with an error to an empty TCP request and keeps the connection open" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $client = [TcpClient]::new()
        try {
            $client.Connect([IPAddress]::Loopback, $kdc.Port)
            $stream = $client.GetStream()

            Write-TcpRequest $stream ([byte[]]::new(0))
            $actual = Get-KrbError (Read-TcpResponse $stream)
            $actual.ErrorCode | Should-Be $KrbErrorCode.KRB_ERR_GENERIC
            $actual.EText | Should-BeLikeString 'Failed to process request: *'

            Write-TcpRequest $stream (New-AsReq EXAMPLE.TEST user)
            Get-KrbErrorCode (Read-TcpResponse $stream) | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
        }
        finally {
            $client.Dispose()
        }
    }

    It "Handles a client that disconnects mid request" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $client = [TcpClient]::new()
        try {
            $client.Connect([IPAddress]::Loopback, $kdc.Port)
            $stream = $client.GetStream()
            # Promise 100 bytes but only send 10.
            $stream.Write([byte[]]@(0, 0, 0, 100) + [byte[]]::new(10), 0, 14)
        }
        finally {
            $client.Dispose()
        }

        $kdc.State | Should-Be ([Obol.ObolKdcState]::Running)
        $response = Invoke-KdcRequest -Port $kdc.Port -Request (New-AsReq EXAMPLE.TEST user)
        Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
    }

    It "Responds with an error to an invalid TCP request and keeps the connection open" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $client = [TcpClient]::new()
        try {
            $client.Connect([IPAddress]::Loopback, $kdc.Port)
            $stream = $client.GetStream()

            foreach ($request in @(, [byte[]]@(0x6A)) + @(, (New-AsReq EXAMPLE.TEST user))) {
                $length = [byte[]]::new(4)
                [Buffers.Binary.BinaryPrimitives]::WriteInt32BigEndian($length, $request.Length)
                $stream.Write($length, 0, 4)
                $stream.Write($request, 0, $request.Length)

                $stream.ReadExactly($length, 0, 4)
                $response = [byte[]]::new([Buffers.Binary.BinaryPrimitives]::ReadInt32BigEndian($length))
                $stream.ReadExactly($response, 0, $response.Length)

                $actual = Get-KrbError $response
                if ($request.Length -eq 1) {
                    $actual.ErrorCode | Should-Be $KrbErrorCode.KRB_ERR_GENERIC
                    $actual.EText | Should-BeLikeString 'Failed to process request: *'
                }
                else {
                    $actual.ErrorCode | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
                }
            }
        }
        finally {
            $client.Dispose()
        }
    }

    It "Closes the connection on an invalid length prefix" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $client = [TcpClient]::new()
        try {
            $client.Connect([IPAddress]::Loopback, $kdc.Port)
            $stream = $client.GetStream()
            # Negative length, the reserved high bit is set.
            $stream.Write([byte[]]@(0x80, 0, 0, 0), 0, 4)

            $actual = Get-KrbError (Read-TcpResponse $stream)
            $actual.ErrorCode | Should-Be $KrbErrorCode.KRB_ERR_FIELD_TOOLONG
            $actual.EText | Should-Be 'Length prefix extensions are not supported'
            $stream.Read([byte[]]::new(1), 0, 1) | Should-Be 0
        }
        finally {
            $client.Dispose()
        }

        $kdc.State | Should-Be ([Obol.ObolKdcState]::Running)
        $response = Invoke-KdcRequest -Port $kdc.Port -Request (New-AsReq EXAMPLE.TEST user)
        Get-KrbErrorCode $response | Should-Be $KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN
    }

    It "Closes the connection on a request that is too large" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $client = [TcpClient]::new()
        try {
            $client.Connect([IPAddress]::Loopback, $kdc.Port)
            $stream = $client.GetStream()
            # 1 MiB + 1, the data does not need to be sent.
            $stream.Write([byte[]]@(0x00, 0x10, 0x00, 0x01), 0, 4)

            $actual = Get-KrbError (Read-TcpResponse $stream)
            $actual.ErrorCode | Should-Be $KrbErrorCode.KRB_ERR_FIELD_TOOLONG
            $actual.EText | Should-Be 'Request length 1048577 exceeds the limit of 1048576 bytes'
            $stream.Read([byte[]]::new(1), 0, 1) | Should-Be 0
        }
        finally {
            $client.Dispose()
        }
    }

    It "Stops the KDC when the runspace closes" {
        $iss = [InitialSessionState]::CreateDefault2()
        $iss.ImportPSModule((Get-Module Obol).Path)
        $rs = [RunspaceFactory]::CreateRunspace($iss)
        try {
            $rs.Open()
            $ps = [PowerShell]::Create($rs)
            $kdc = $ps.AddCommand('Start-ObolKdc').AddParameter('Realm', 'EXAMPLE.TEST').Invoke()[0]
            $ps.Dispose()

            $kdc.State | Should-Be ([Obol.ObolKdcState]::Running)
            # KDCs are tracked per runspace.
            Get-ObolKdc | Should-BeNull
        }
        finally {
            $rs.Dispose()
        }

        $kdc.State | Should-Be ([Obol.ObolKdcState]::Stopped)
        { [TcpClient]::new('127.0.0.1', $kdc.Port) } | Should-Throw
    }
}
