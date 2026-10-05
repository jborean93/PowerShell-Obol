using module ../output/Obol
using namespace System.IO
using namespace System.Net
using namespace System.Security.Principal

BeforeAll {
    . ([Path]::Combine($PSScriptRoot, 'common.ps1'))
}

BeforeDiscovery {
    $isAdmin = $IsWindows -and
        ([WindowsPrincipal]::new([WindowsIdentity]::GetCurrent())).IsInRole([WindowsBuiltinRole]::Administrator)
}

Describe "Use-ObolSspiEnvironment" -Skip:(-not $IsWindows) {
    AfterEach {
        Exit-ObolSspiEnvironment
        Clear-ObolSspiKdc
        Get-ObolKdc | Stop-ObolKdc
    }

    Context "Thread scope" {
        It "Pins the KDC realm on port 88 while the scriptblock runs and clears it after" {
            $actual = Use-ObolSspiEnvironment EXAMPLE.TEST {
                param ($kdc)

                [PSCustomObject]@{
                    Pin = Get-ObolSspiKdc
                    Port = $kdc.Endpoint.Port
                }
            }

            $actual.Pin.Realm | Should-Be EXAMPLE.TEST
            $actual.Pin.KdcAddress | Should-Be 127.0.0.1
            $actual.Port | Should-Be 88
            @(Get-ObolSspiKdc).Count | Should-Be 0
        }

        It "Does not set the krb5 environment" {
            $previous = $env:KRB5_CONFIG
            Remove-Item Env:\KRB5_CONFIG -ErrorAction Ignore
            try {
                $actual = Use-ObolSspiEnvironment EXAMPLE.TEST { $env:KRB5_CONFIG }

                $actual | Should-BeNull
            }
            finally {
                if ($null -ne $previous) {
                    $env:KRB5_CONFIG = $previous
                }
            }
        }

        It "Is the default" {
            $actual = Use-ObolSspiEnvironment EXAMPLE.TEST -Scope Thread { @(Get-ObolSspiKdc).Realm }

            $actual | Should-Be EXAMPLE.TEST
        }

        It "Pins the loopback address for a KDC listening on all addresses" {
            $actual = Use-ObolSspiEnvironment EXAMPLE.TEST -Address 0.0.0.0 { Get-ObolSspiKdc }

            $actual.KdcAddress | Should-Be 127.0.0.1
        }

        It "Pins each KDC from -Kdc and leaves them running" {
            $kdc = Start-ObolKdc EXAMPLE.TEST -Port 88
            $other = Start-ObolKdc OTHER.TEST -Address 127.0.0.2 -Port 88

            $actual = $kdc, $other | Use-ObolSspiEnvironment { Get-ObolSspiKdc }

            $actual.Realm | Should-BeCollection @('EXAMPLE.TEST', 'OTHER.TEST')
            $actual.KdcAddress | Should-BeCollection @('127.0.0.1', '127.0.0.2')
            $kdc.State | Should-Be Running
            $other.State | Should-Be Running
        }

        It "Clears the pin and stops the KDC even when the scriptblock throws" {
            { Use-ObolSspiEnvironment EXAMPLE.TEST { throw 'boom' } } | Should-Throw -ExceptionMessage boom

            @(Get-ObolSspiKdc).Count | Should-Be 0
            Get-ObolKdc | Should-BeNull
        }

        It "Fails for a KDC from -Kdc that is not on port 88" {
            $kdc = Start-ObolKdc EXAMPLE.TEST
            $script:ran = $false

            { Use-ObolSspiEnvironment -Kdc $kdc { $script:ran = $true } } |
                Should-Throw -FullyQualifiedErrorId 'SspiKdcPortNot88,Obol.Commands.UseObolSspiEnvironment'

            $script:ran | Should-BeFalse
            @(Get-ObolSspiKdc).Count | Should-Be 0
        }

        It "Fails if a KDC is already pinned on the thread" {
            Add-ObolSspiKdc -Realm OTHER.TEST -KdcAddress 127.0.0.2

            { Use-ObolSspiEnvironment EXAMPLE.TEST { 'ran' } } |
                Should-Throw -FullyQualifiedErrorId 'SspiKdcAlreadyPinned,Obol.Commands.UseObolSspiEnvironment'

            (Get-ObolSspiKdc).Realm | Should-Be OTHER.TEST
            Get-ObolKdc | Should-BeNull
        }

        It "Fails if an SSPI environment is already entered" {
            $kdc = Start-ObolKdc OTHER.TEST -Address 127.0.0.2 -Port 88
            Enter-ObolSspiEnvironment $kdc

            { Use-ObolSspiEnvironment EXAMPLE.TEST { 'ran' } } |
                Should-Throw -FullyQualifiedErrorId 'SspiEnvironmentAlreadyEntered,Obol.Commands.UseObolSspiEnvironment'

            Get-ObolKdc | Where-Object Realm -EQ EXAMPLE.TEST | Should-BeNull
        }

        It "Can be used with the krb5 environment entered" {
            $kdc = Start-ObolKdc OTHER.TEST
            Enter-ObolKrb5Environment $kdc -NoPrompt
            try {
                $actual = Use-ObolSspiEnvironment EXAMPLE.TEST { @(Get-ObolSspiKdc).Realm }

                $actual | Should-Be EXAMPLE.TEST
            }
            finally {
                Exit-ObolKrb5Environment
            }
        }
    }

    Context "Machine scope" -Skip:(-not $isAdmin) {
        BeforeEach {
            Clear-ObolSspiKdc -Scope Machine
        }

        AfterEach {
            Clear-ObolSspiKdc -Scope Machine
        }

        It "Adds a binding without a pin while the scriptblock runs and purges it after" {
            $actual = Use-ObolSspiEnvironment EXAMPLE.TEST -Scope Machine {
                [PSCustomObject]@{
                    Binding = Get-ObolSspiKdc -Scope Machine | Where-Object Realm -EQ EXAMPLE.TEST
                    Pins = @(Get-ObolSspiKdc).Count
                }
            }

            $actual.Binding.KdcAddress | Should-Be 127.0.0.1
            $actual.Pins | Should-Be 0
            Get-ObolSspiKdc -Scope Machine | Should-BeNull
        }

        It "Replaces an existing binding for the realm" {
            Add-ObolSspiKdc -Realm EXAMPLE.TEST -KdcAddress 127.0.0.5 -Scope Machine

            $actual = Use-ObolSspiEnvironment EXAMPLE.TEST -Scope Machine {
                Get-ObolSspiKdc -Scope Machine | Where-Object Realm -EQ EXAMPLE.TEST
            }

            $actual.KdcAddress | Should-Be 127.0.0.1
        }

        It "Purges the whole binding cache after, including other realms" {
            Add-ObolSspiKdc -Realm OTHER.TEST -KdcAddress 127.0.0.2 -Scope Machine

            Use-ObolSspiEnvironment EXAMPLE.TEST -Scope Machine { }

            Get-ObolSspiKdc -Scope Machine | Should-BeNull
        }

        It "Purges the binding cache even when the scriptblock throws" {
            { Use-ObolSspiEnvironment EXAMPLE.TEST -Scope Machine { throw 'boom' } } |
                Should-Throw -ExceptionMessage boom

            Get-ObolSspiKdc -Scope Machine | Should-BeNull
            Get-ObolKdc | Should-BeNull
        }

        It "Is not blocked by an existing thread pin" {
            Add-ObolSspiKdc -Realm OTHER.TEST -KdcAddress 127.0.0.2

            $actual = Use-ObolSspiEnvironment EXAMPLE.TEST -Scope Machine {
                (Get-ObolSspiKdc -Scope Machine | Where-Object Realm -EQ EXAMPLE.TEST).KdcAddress
            }

            $actual | Should-Be 127.0.0.1
            (Get-ObolSspiKdc).Realm | Should-Be OTHER.TEST
        }
    }

    Context "MitRealm scope" -Skip:(-not $isAdmin) {
        BeforeAll {
            $realmKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains\EXAMPLE.TEST'
        }

        It "Adds the realm while the scriptblock runs and removes it after" {
            $actual = Use-ObolSspiEnvironment EXAMPLE.TEST -Scope MitRealm {
                (Get-ItemProperty -LiteralPath $realmKey).KdcNames
            }

            $actual | Should-Be 127.0.0.1
            Test-Path -LiteralPath $realmKey | Should-BeFalse
        }

        It "Removes the realm even when the scriptblock throws" {
            { Use-ObolSspiEnvironment EXAMPLE.TEST -Scope MitRealm { throw 'boom' } } |
                Should-Throw -ExceptionMessage boom

            Test-Path -LiteralPath $realmKey | Should-BeFalse
            Get-ObolKdc | Should-BeNull
        }

        It "Fails before starting the KDC when the realm exists" {
            $null = New-Item -Path $realmKey
            try {
                { Use-ObolSspiEnvironment EXAMPLE.TEST -Scope MitRealm { 'ran' } } |
                    Should-Throw -FullyQualifiedErrorId 'SspiConfigurationExists,Obol.Commands.UseObolSspiEnvironment'

                Get-ObolKdc | Should-BeNull
            }
            finally {
                Remove-Item -LiteralPath $realmKey -Recurse
            }
        }
    }

    Context "DcLocator scope" -Skip:(-not $isAdmin) {
        It "Answers DNS for the realm while the scriptblock runs and removes the NRPT rule after" {
            $actual = Use-ObolSspiEnvironment EXAMPLE.TEST -Scope DcLocator {
                [Dns]::GetHostAddresses('kdc1.example.test').IPAddressToString
            }

            $actual | Should-Be 127.0.0.1
            Get-NrptRule -Namespace .example.test | Should-BeNull
            Test-PortFree 53 -Udp | Should-BeTrue
        }

        It "Fails for a realm that is not a DNS name and stops the KDC" {
            { Use-ObolSspiEnvironment EXAMPLE -Scope DcLocator { 'ran' } } |
                Should-Throw -FullyQualifiedErrorId 'InvalidSspiRealm,Obol.Commands.UseObolSspiEnvironment'

            Get-ObolKdc | Should-BeNull
            Get-NrptRule -Namespace .example | Should-BeNull
        }
    }

    Context "Machine scope without administrator rights" -Skip:(-not $isAdmin) {
        BeforeAll {
            # Created with net.exe: New-LocalUser is not on the restricted test PSModulePath. A network logon of a
            # standard user has neither SeTcbPrivilege nor SeDebugPrivilege.
            $script:testUser = "obol_use_$(Get-Random -Maximum 999999)"
            $script:testPassword = 'Obol1!aZ9kQ2wE'
            $output = net.exe user $script:testUser $script:testPassword /add 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to create the test user: $($output -join ' ')"
            }
        }

        AfterAll {
            if ($script:testUser) {
                $null = net.exe user $script:testUser /delete 2>&1
            }
        }

        It "Fails before starting the KDC" {
            $err = Invoke-AsLogonUser -Username $testUser -Password $testPassword -ScriptBlock {
                { Use-ObolSspiEnvironment EXAMPLE.TEST -Scope Machine { 'ran' } } | Should-Throw
            }

            $err.FullyQualifiedErrorId | Should-Be 'SspiCallFailed,Obol.Commands.UseObolSspiEnvironment'
            $err.Exception.Message | Should-BeLikeString '*SeTcbPrivilege*'
            Get-ObolKdc | Should-BeNull
        }

        It "Fails with scope <Scope> before starting the KDC" -TestCases @(
            @{ Scope = 'MitRealm' }
            @{ Scope = 'DcLocator' }
        ) {
            param ($Scope)

            $err = Invoke-AsLogonUser -Username $testUser -Password $testPassword -ScriptBlock {
                { Use-ObolSspiEnvironment EXAMPLE.TEST -Scope $Scope { 'ran' } } | Should-Throw
            }

            $err.FullyQualifiedErrorId | Should-Be 'SspiScopeNeedsAdministrator,Obol.Commands.UseObolSspiEnvironment'
            $err.Exception.Message | Should-BeLikeString "Scope $Scope *administrator*"
            Get-ObolKdc | Should-BeNull
        }
    }
}

Describe "Use-ObolSspiEnvironment on non-Windows" -Skip:$IsWindows {
    It "Errors without starting a KDC" {
        { Use-ObolSspiEnvironment EXAMPLE.TEST { 'ran' } } |
            Should-Throw -FullyQualifiedErrorId 'SspiNotSupported,Obol.Commands.UseObolSspiEnvironment'

        Get-ObolKdc | Should-BeNull
    }
}
