using module ../output/Obol
using namespace Microsoft.Win32
using namespace System.IO
using namespace System.Net
using namespace System.Net.Sockets
using namespace System.Management.Automation.Runspaces
using namespace System.Security.Principal

BeforeAll {
    . ([Path]::Combine($PSScriptRoot, 'common.ps1'))
}

BeforeDiscovery {
    $isAdmin = $IsWindows -and
        ([WindowsPrincipal]::new([WindowsIdentity]::GetCurrent())).IsInRole([WindowsBuiltinRole]::Administrator)
}

Describe "Enter-ObolSspiEnvironment" -Skip:(-not $IsWindows) {
    BeforeEach {
        $kdc = Start-ObolKdc EXAMPLE.TEST -Port 88
    }

    AfterEach {
        Exit-ObolSspiEnvironment
        Clear-ObolSspiKdc
        Get-ObolKdc | Stop-ObolKdc
    }

    Context "Thread scope" {
        It "Pins the KDC until Exit-ObolSspiEnvironment" {
            Enter-ObolSspiEnvironment $kdc

            $pin = Get-ObolSspiKdc
            $pin.Realm | Should-Be EXAMPLE.TEST
            $pin.KdcAddress | Should-Be 127.0.0.1

            Exit-ObolSspiEnvironment

            @(Get-ObolSspiKdc).Count | Should-Be 0
        }

        It "Pins each KDC from the pipeline" {
            $other = Start-ObolKdc OTHER.TEST -Address 127.0.0.2 -Port 88

            $kdc, $other | Enter-ObolSspiEnvironment

            (Get-ObolSspiKdc).Realm | Should-BeCollection @('EXAMPLE.TEST', 'OTHER.TEST')
        }

        It "Pins the loopback address for a KDC listening on all addresses" {
            $all = Start-ObolKdc OTHER.TEST -Address 0.0.0.0 -Port 88

            Enter-ObolSspiEnvironment $all

            (Get-ObolSspiKdc).KdcAddress | Should-Be 127.0.0.1
        }

        It "Writes an error for a KDC not on port 88 and pins the others" {
            $random = Start-ObolKdc OTHER.TEST

            $kdc, $random | Enter-ObolSspiEnvironment -ErrorVariable err -ErrorAction SilentlyContinue

            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId | Should-Be 'SspiKdcPortNot88,Obol.Commands.EnterObolSspiEnvironment'
            (Get-ObolSspiKdc).Realm | Should-Be EXAMPLE.TEST
        }

        It "Writes an error for a stopped KDC and enters nothing if every KDC failed" {
            $kdc | Stop-ObolKdc

            Enter-ObolSspiEnvironment $kdc -ErrorVariable err -ErrorAction SilentlyContinue

            $err[0].FullyQualifiedErrorId | Should-Be 'KdcNotRunning,Obol.Commands.EnterObolSspiEnvironment'
            @(Get-ObolSspiKdc).Count | Should-Be 0

            # Nothing was entered so another can be.
            $other = Start-ObolKdc OTHER.TEST -Port 88
            Enter-ObolSspiEnvironment $other
        }

        It "Fails if an SSPI environment is already entered" {
            Enter-ObolSspiEnvironment $kdc

            { Enter-ObolSspiEnvironment $kdc } |
                Should-Throw -FullyQualifiedErrorId 'SspiEnvironmentAlreadyEntered,Obol.Commands.EnterObolSspiEnvironment'
        }

        It "Fails if a KDC is already pinned on the thread" {
            Add-ObolSspiKdc -Realm OTHER.TEST -KdcAddress 127.0.0.2

            { Enter-ObolSspiEnvironment $kdc } |
                Should-Throw -FullyQualifiedErrorId 'SspiKdcAlreadyPinned,Obol.Commands.EnterObolSspiEnvironment'

            (Get-ObolSspiKdc).Realm | Should-Be OTHER.TEST
        }

        It "Does not enter with -WhatIf" {
            Enter-ObolSspiEnvironment $kdc -WhatIf

            @(Get-ObolSspiKdc).Count | Should-Be 0
            Enter-ObolSspiEnvironment $kdc
        }

        It "Rejects -Scope Process" {
            { Enter-ObolSspiEnvironment $kdc -Scope Process } | Should-Throw
        }

        It "Exits when the runspace that entered it closes" {
            $ps = New-ObolPowerShell -ThreadOptions ([PSThreadOptions]::ReuseThread)
            try {
                $null = $ps.AddScript({
                        $kdc = Start-ObolKdc OTHER.TEST -Address 127.0.0.2 -Port 88
                        Enter-ObolSspiEnvironment $kdc
                    }).Invoke()
            }
            finally {
                $ps.Runspace.Dispose()
                $ps.Dispose()
            }

            # The environment of the closed runspace is gone so this one can enter.
            Enter-ObolSspiEnvironment $kdc
            (Get-ObolSspiKdc).Realm | Should-Be EXAMPLE.TEST
        }
    }

    Context "Prompt" {
        BeforeEach {
            $rendering = $PSStyle.OutputRendering
            $PSStyle.OutputRendering = 'PlainText'
            $prompt = prompt
        }

        AfterEach {
            Exit-ObolKrb5Environment
            $PSStyle.OutputRendering = $rendering
        }

        It "Adds the realm to the prompt until Exit-ObolSspiEnvironment" {
            $function = ${function:global:prompt}

            Enter-ObolSspiEnvironment $kdc

            prompt | Should-Be "[EXAMPLE.TEST] $prompt"

            Exit-ObolSspiEnvironment

            prompt | Should-Be $prompt
            [object]::ReferenceEquals(${function:global:prompt}, $function) | Should-BeTrue
        }

        It "Adds the number of other realms to the prompt" {
            $other = Start-ObolKdc OTHER.TEST -Address 127.0.0.2 -Port 88

            $kdc, $other | Enter-ObolSspiEnvironment

            prompt | Should-Be "[EXAMPLE.TEST +1] $prompt"
        }

        It "Colors the realm when output rendering allows it" {
            $PSStyle.OutputRendering = 'Ansi'

            Enter-ObolSspiEnvironment $kdc

            prompt | Should-Be "$($PSStyle.Foreground.Magenta)[EXAMPLE.TEST]$($PSStyle.Reset) $prompt"
        }

        It "Leaves the prompt alone with -NoPrompt" {
            $function = ${function:global:prompt}

            Enter-ObolSspiEnvironment $kdc -NoPrompt

            [object]::ReferenceEquals(${function:global:prompt}, $function) | Should-BeTrue
        }

        It "Shows both environments and removes each label when exited in <Order> order" -TestCases @(
            @{ Order = 'entered' }
            @{ Order = 'reverse' }
        ) {
            param ($Order)

            # The labels have the same text, only the color tells them apart.
            $PSStyle.OutputRendering = 'Ansi'
            $krb5 = "$($PSStyle.Foreground.Cyan)[EXAMPLE.TEST]$($PSStyle.Reset)"
            $sspi = "$($PSStyle.Foreground.Magenta)[EXAMPLE.TEST]$($PSStyle.Reset)"

            Enter-ObolKrb5Environment $kdc
            Enter-ObolSspiEnvironment $kdc

            prompt | Should-Be "$sspi $krb5 $prompt"

            if ($Order -eq 'entered') {
                Exit-ObolKrb5Environment
                prompt | Should-Be "$sspi $prompt"
                Exit-ObolSspiEnvironment
            }
            else {
                Exit-ObolSspiEnvironment
                prompt | Should-Be "$krb5 $prompt"
                Exit-ObolKrb5Environment
            }

            prompt | Should-Be $prompt
        }

        It "Fails for an environment entered in another runspace" {
            $ps = New-ObolPowerShell
            try {
                $null = $ps.AddCommand('Enter-ObolSspiEnvironment').AddParameter('Kdc', $kdc).Invoke()

                { Exit-ObolSspiEnvironment } |
                    Should-Throw -FullyQualifiedErrorId 'SspiEnvironmentNotOwned,Obol.Commands.ExitObolSspiEnvironment'

                # Still entered, so this runspace cannot enter one.
                { Enter-ObolSspiEnvironment $kdc } |
                    Should-Throw -FullyQualifiedErrorId 'SspiEnvironmentAlreadyEntered,Obol.Commands.EnterObolSspiEnvironment'
            }
            finally {
                # Disposing the runspace that entered it exits the environment.
                $ps.Dispose()
            }

            Enter-ObolSspiEnvironment $kdc
        }

        It "Is not changed by Use-ObolSspiEnvironment" {
            $function = ${function:global:prompt}

            $actual = Use-ObolSspiEnvironment -Kdc $kdc { [object]::ReferenceEquals(${function:global:prompt}, $function) }

            $actual | Should-BeTrue
        }
    }

    Context "Machine scope" -Skip:(-not $isAdmin) {
        BeforeEach {
            Clear-ObolSspiKdc -Scope Machine
        }

        AfterEach {
            Clear-ObolSspiKdc -Scope Machine
        }

        It "Adds a binding until Exit-ObolSspiEnvironment purges the cache" {
            Enter-ObolSspiEnvironment $kdc -Scope Machine

            (Get-ObolSspiKdc -Scope Machine | Where-Object Realm -EQ EXAMPLE.TEST).KdcAddress |
                Should-Be 127.0.0.1
            @(Get-ObolSspiKdc).Count | Should-Be 0

            Exit-ObolSspiEnvironment

            Get-ObolSspiKdc -Scope Machine | Should-BeNull
        }

        It "Is not blocked by an existing thread pin" {
            Add-ObolSspiKdc -Realm OTHER.TEST -KdcAddress 127.0.0.2

            Enter-ObolSspiEnvironment $kdc -Scope Machine

            (Get-ObolSspiKdc -Scope Machine).Realm | Should-Be EXAMPLE.TEST
        }
    }

    Context "MitRealm scope" -Skip:(-not $isAdmin) {
        BeforeAll {
            $domainsPath = 'SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains'
            $hostToRealmPath = 'SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\HostToRealm'
        }

        BeforeEach {
            Clear-ObolSspiKdc -Scope Machine
        }

        AfterEach {
            Clear-ObolSspiKdc -Scope Machine
        }

        It "Adds the realm and host mapping until Exit-ObolSspiEnvironment" {
            Enter-ObolSspiEnvironment $kdc -Scope MitRealm

            $realm = Get-ItemProperty -LiteralPath "HKLM:\$domainsPath\EXAMPLE.TEST"
            $realm.KdcNames | Should-Be '127.0.0.1'
            $realm.RealmFlags | Should-Be 2
            $mapping = Get-ItemProperty -LiteralPath "HKLM:\$hostToRealmPath\EXAMPLE.TEST"
            $mapping.SpnMappings -join ',' | Should-Be '.example.test,example.test'
            @(Get-ObolSspiKdc).Count | Should-Be 0

            Exit-ObolSspiEnvironment

            Test-Path -LiteralPath "HKLM:\$domainsPath\EXAMPLE.TEST" | Should-BeFalse
            Test-Path -LiteralPath "HKLM:\$hostToRealmPath\EXAMPLE.TEST" | Should-BeFalse
        }

        It "Creates volatile keys" {
            Enter-ObolSspiEnvironment $kdc -Scope MitRealm

            foreach ($path in $domainsPath, $hostToRealmPath) {
                $key = [Registry]::LocalMachine.OpenSubKey("$path\EXAMPLE.TEST", $true)
                try {
                    { $key.CreateSubKey('stable') } | Should-Throw -ExceptionMessage '*volatile*'
                }
                finally {
                    $key.Dispose()
                }
            }
        }

        It "Lists every KDC of the realm without TcpSupported when one has no TCP" {
            $udpKdc = Start-ObolKdc EXAMPLE.TEST -Address 127.0.0.2 -Port 88 -Transport Udp

            Enter-ObolSspiEnvironment $kdc, $udpKdc -Scope MitRealm

            $realm = Get-ItemProperty -LiteralPath "HKLM:\$domainsPath\EXAMPLE.TEST"
            $realm.KdcNames -join ',' | Should-Be '127.0.0.1,127.0.0.2'
            $realm.RealmFlags | Should-Be 0
        }

        It "Purges the binding cache when entered and exited" {
            Add-ObolSspiKdc -Realm OTHER.TEST -KdcAddress 127.0.0.2 -Scope Machine

            Enter-ObolSspiEnvironment $kdc -Scope MitRealm
            Get-ObolSspiKdc -Scope Machine | Should-BeNull
            Add-ObolSspiKdc -Realm OTHER.TEST -KdcAddress 127.0.0.2 -Scope Machine
            Exit-ObolSspiEnvironment

            Get-ObolSspiKdc -Scope Machine | Should-BeNull
        }

        It "Fails without changing a realm that already exists" {
            $existing = "HKLM:\$domainsPath\EXAMPLE.TEST"
            $null = New-Item -Path $existing
            try {
                $null = New-ItemProperty -LiteralPath $existing -Name KdcNames -PropertyType MultiString -Value kdc.test

                $err = { Enter-ObolSspiEnvironment $kdc -Scope MitRealm } |
                    Should-Throw -FullyQualifiedErrorId 'SspiConfigurationExists,Obol.Commands.EnterObolSspiEnvironment'

                $err.Exception.Message | Should-BeLikeString "*ksetup.exe /removerealm 'EXAMPLE.TEST'*"
                (Get-ItemProperty -LiteralPath $existing).KdcNames | Should-Be kdc.test
                Test-Path -LiteralPath "HKLM:\$hostToRealmPath\EXAMPLE.TEST" | Should-BeFalse
            }
            finally {
                Remove-Item -LiteralPath $existing -Recurse
            }
        }

        It "Gives a command that removes an existing realm with a quote in its name" {
            $quoted = Start-ObolKdc "O'BRIEN.TEST" -Address 127.0.0.2 -Port 88
            $existing = "HKLM:\$domainsPath\O'BRIEN.TEST"
            $null = New-Item -Path $existing
            try {
                $err = { Enter-ObolSspiEnvironment $quoted -Scope MitRealm } |
                    Should-Throw -FullyQualifiedErrorId 'SspiConfigurationExists,Obol.Commands.EnterObolSspiEnvironment'

                $err.Exception.Message | Should-BeLikeString "*ksetup.exe /removerealm 'O''BRIEN.TEST'*"
                $command = [regex]::Match($err.Exception.Message, "Remove-Item -LiteralPath '.*' -Recurse").Value
                Invoke-Expression $command

                Test-Path -LiteralPath $existing | Should-BeFalse
            }
            finally {
                Remove-Item -LiteralPath $existing -Recurse -ErrorAction Ignore
            }
        }

        It "Fails without changing a host to realm mapping that already exists" {
            $key = [Registry]::LocalMachine.CreateSubKey("$hostToRealmPath\EXAMPLE.TEST", $true,
                [RegistryOptions]::Volatile)
            try {
                $err = { Enter-ObolSspiEnvironment $kdc -Scope MitRealm } |
                    Should-Throw -FullyQualifiedErrorId 'SspiConfigurationExists,Obol.Commands.EnterObolSspiEnvironment'

                $err.Exception.Message |
                    Should-BeLikeString "*HKLM\$hostToRealmPath\EXAMPLE.TEST already exists. Remove it with Remove-*"
                Test-Path -LiteralPath "HKLM:\$domainsPath\EXAMPLE.TEST" | Should-BeFalse
            }
            finally {
                $key.Dispose()
                [Registry]::LocalMachine.DeleteSubKeyTree("$hostToRealmPath\EXAMPLE.TEST")
            }
        }
    }

    Context "DcLocator scope" -Skip:(-not $isAdmin) {
        BeforeAll {
            $nrptPath = 'SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig'
        }

        BeforeEach {
            Clear-ObolSspiKdc -Scope Machine
        }

        AfterEach {
            Clear-ObolSspiKdc -Scope Machine
        }

        It "Adds an NRPT rule and answers DNS for the realm until Exit-ObolSspiEnvironment" {
            Enter-ObolSspiEnvironment $kdc -Scope DcLocator

            $rule = Get-NrptRule -Namespace .example.test
            $rule.Name -join ',' | Should-Be 'example.test,.example.test'
            $rule.GenericDNSServers | Should-Be 127.0.0.1
            # Resolved by the DNS client through the NRPT rule.
            [Dns]::GetHostAddresses('kdc1.example.test').IPAddressToString | Should-Be 127.0.0.1
            Get-ObolSspiKdc -Scope Machine | Should-BeNull

            Exit-ObolSspiEnvironment

            Get-NrptRule -Namespace .example.test | Should-BeNull
            { [Dns]::GetHostAddresses('kdc1.example.test') } | Should-Throw
            # The DNS and LDAP ports are free again.
            Test-PortFree 53 -Udp | Should-BeTrue
            Test-PortFree 389 -Udp | Should-BeTrue
        }

        It "Fails without changing an NRPT rule for the realm" {
            $path = "$nrptPath\{$([Guid]::NewGuid())}"
            $key = [Registry]::LocalMachine.CreateSubKey($path)
            try {
                $key.SetValue('Name', [string[]]@('.example.test'), [RegistryValueKind]::MultiString)
                $key.SetValue('GenericDNSServers', '127.0.0.9')

                $err = { Enter-ObolSspiEnvironment $kdc -Scope DcLocator } |
                    Should-Throw -FullyQualifiedErrorId 'SspiConfigurationExists,Obol.Commands.EnterObolSspiEnvironment'

                $err.Exception.Message | Should-BeLikeString '*Remove-DnsClientNrptRule -Name*'
                @(Get-NrptRule -Namespace .example.test).Count | Should-Be 1
                # Nothing was started, the DNS port is free.
                Test-PortFree 53 -Udp | Should-BeTrue
            }
            finally {
                $key.Dispose()
                [Registry]::LocalMachine.DeleteSubKeyTree($path)
            }
        }

        It "Fails while the Group Policy NRPT key exists" {
            # Windows ignores every local NRPT rule while this key exists, even when it is empty.
            $policyPath = 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            $createdParent = -not (Test-Path -LiteralPath "HKLM:\$policyPath")
            $key = [Registry]::LocalMachine.CreateSubKey("$policyPath\DnsPolicyConfig", $true,
                [RegistryOptions]::Volatile)
            try {
                $err = { Enter-ObolSspiEnvironment $kdc -Scope DcLocator } |
                    Should-Throw -FullyQualifiedErrorId 'SspiConfigurationExists,Obol.Commands.EnterObolSspiEnvironment'

                $err.Exception.Message | Should-BeLikeString '*Group Policy NRPT key*ignores every local NRPT rule*'
                Get-NrptRule -Namespace .example.test | Should-BeNull
            }
            finally {
                $key.Dispose()
                [Registry]::LocalMachine.DeleteSubKeyTree($(if ($createdParent) { $policyPath } else {
                            "$policyPath\DnsPolicyConfig" }))
            }
        }

        It "Fails without an NRPT rule when UDP port <Port> of the KDC address is in use" -TestCases @(
            @{ Port = 53; Service = 'DNS server' }
            @{ Port = 389; Service = 'LDAP ping responder' }
        ) {
            param ($Port, $Service)

            $udp = [UdpClient]::new([IPEndPoint]::new([IPAddress]::Loopback, $Port))
            try {
                $err = { Enter-ObolSspiEnvironment $kdc -Scope DcLocator } |
                    Should-Throw -FullyQualifiedErrorId 'SspiCallFailed,Obol.Commands.EnterObolSspiEnvironment'

                $err.Exception.Message | Should-BeLikeString "*DC locator $Service on UDP 127.0.0.1:$($Port):*"
                $err.Exception.Message | Should-BeLikeString '*such as 127.0.0.2 with -Address*'
                Get-NrptRule -Namespace .example.test | Should-BeNull
                Test-PortFree $(if ($Port -eq 53) { 389 } else { 53 }) -Udp | Should-BeTrue
            }
            finally {
                $udp.Dispose()
            }
        }

        It "Listens and points the NRPT rule at the KDC address" {
            # Another DNS server on 127.0.0.1 does not get in the way.
            $udp = [UdpClient]::new([IPEndPoint]::new([IPAddress]::Loopback, 53))
            try {
                $other = Start-ObolKdc OTHER.TEST -Address 127.0.0.2 -Port 88

                Enter-ObolSspiEnvironment $other -Scope DcLocator

                (Get-NrptRule -Namespace .other.test).GenericDNSServers | Should-Be 127.0.0.2
                [Dns]::GetHostAddresses('kdc1.other.test').IPAddressToString | Should-Be 127.0.0.2
            }
            finally {
                $udp.Dispose()
            }
        }

        It "Points the NRPT rule at every KDC of the realm" {
            $second = Start-ObolKdc EXAMPLE.TEST -Address 127.0.0.2 -Port 88

            Enter-ObolSspiEnvironment $kdc, $second -Scope DcLocator

            (Get-NrptRule -Namespace .example.test).GenericDNSServers | Should-Be '127.0.0.1;127.0.0.2'
        }

        It "Fails for KDCs that share an address" {
            # TCP and UDP port 88 are separate ports, so two KDCs can listen on the same address.
            $tcp = Start-ObolKdc EXAMPLE.TEST -Address 127.0.0.2 -Port 88 -Transport Tcp
            $udp = Start-ObolKdc OTHER.TEST -Address 127.0.0.2 -Port 88 -Transport Udp

            $err = { Enter-ObolSspiEnvironment $tcp, $udp -Scope DcLocator } |
                Should-Throw -FullyQualifiedErrorId 'SspiKdcAddressShared,Obol.Commands.EnterObolSspiEnvironment'

            $err.Exception.Message | Should-BeLikeString '*use the same address 127.0.0.2, scope DcLocator needs each KDC on its own address*'
            Get-NrptRule -Namespace .example.test | Should-BeNull
            Test-PortFree 53 -Udp | Should-BeTrue
        }

        It "Accepts the same KDC given twice" {
            Enter-ObolSspiEnvironment $kdc, $kdc -Scope DcLocator

            (Get-NrptRule -Namespace .example.test).GenericDNSServers | Should-Be 127.0.0.1
        }

        It "Fails for a realm that is not a DNS name" {
            $single = Start-ObolKdc EXAMPLE -Address 127.0.0.2 -Port 88

            $err = { Enter-ObolSspiEnvironment $single -Scope DcLocator -ErrorAction Stop } |
                Should-Throw -FullyQualifiedErrorId 'InvalidSspiRealm,Obol.Commands.EnterObolSspiEnvironment'

            $err.Exception.Message | Should-BeLikeString '*must be a DNS domain name*'
        }
    }
}

Describe "Exit-ObolSspiEnvironment" -Skip:(-not $IsWindows) {
    AfterEach {
        Exit-ObolSspiEnvironment
        Clear-ObolSspiKdc
        Get-ObolKdc | Stop-ObolKdc
    }

    It "Does nothing when no SSPI environment is entered" {
        $verbose = Exit-ObolSspiEnvironment -Verbose 4>&1

        $verbose.Message | Should-Be 'No SSPI environment is entered'
    }

    It "Does not exit with -WhatIf" {
        $kdc = Start-ObolKdc EXAMPLE.TEST -Port 88
        Enter-ObolSspiEnvironment $kdc

        Exit-ObolSspiEnvironment -WhatIf

        (Get-ObolSspiKdc).Realm | Should-Be EXAMPLE.TEST
    }

    It "Removes pins made outside the environment too" {
        $kdc = Start-ObolKdc EXAMPLE.TEST -Port 88
        Enter-ObolSspiEnvironment $kdc
        Add-ObolSspiKdc -Realm OTHER.TEST -KdcAddress 127.0.0.2

        Exit-ObolSspiEnvironment

        @(Get-ObolSspiKdc).Count | Should-Be 0
    }
}

Describe "SSPI environment cmdlets on non-Windows" -Skip:$IsWindows {
    It "<Name> errors" -TestCases @(
        @{ Name = 'Enter-ObolSspiEnvironment'; Script = { Enter-ObolSspiEnvironment (Start-ObolKdc EXAMPLE.TEST) } }
        @{ Name = 'Exit-ObolSspiEnvironment'; Script = { Exit-ObolSspiEnvironment } }
    ) {
        param ($Name, $Script)

        try {
            $Script | Should-Throw -FullyQualifiedErrorId "SspiNotSupported,Obol.Commands.$($Name -replace '-')"
        }
        finally {
            Get-ObolKdc | Stop-ObolKdc
        }
    }
}
