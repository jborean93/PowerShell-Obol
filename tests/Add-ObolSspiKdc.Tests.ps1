using module ../output/Obol
using namespace System.IO
using namespace System.Management.Automation
using namespace System.Management.Automation.Runspaces
using namespace System.Security.Principal

BeforeAll { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

BeforeDiscovery {
    $isAdmin = $IsWindows -and
        ([WindowsPrincipal]::new([WindowsIdentity]::GetCurrent())).IsInRole([WindowsBuiltinRole]::Administrator)

    # The privilege-route tests grant a right via PSPrivilege (the local user is made with net.exe, always available).
    $canTestPrivilegeRoutes = $isAdmin -and [bool](Get-Module -Name PSPrivilege -ListAvailable)
}

Describe "Add/Get/Clear-ObolSspiKdc thread scope" -Skip:(-not $IsWindows) {
    AfterEach {
        Clear-ObolSspiKdc
    }

    It "Pins a realm and records it" {
        $before = Get-Date
        Add-ObolSspiKdc -Realm EXAMPLE.TEST -KdcAddress 127.0.0.1
        $after = Get-Date

        $pins = Get-ObolSspiKdc
        @($pins).Count | Should-Be 1
        $pins.Scope | Should-Be ([Obol.ObolSspiKdcScope]::Thread)
        $pins.Realm | Should-Be EXAMPLE.TEST
        $pins.KdcAddress | Should-Be 127.0.0.1
        $pins.DcFlags | Should-Be ([Obol.ObolSspiDcFlags]::None)
        $pins.DiscoveryTime | Should-BeGreaterThanOrEqual $before
        $pins.DiscoveryTime | Should-BeLessThanOrEqual $after
    }

    It "Produces no output without -PassThru" {
        $actual = Add-ObolSspiKdc -Realm EXAMPLE.TEST -KdcAddress 127.0.0.1
        $actual | Should-BeNull
    }

    It "Returns the pin with -PassThru" {
        $actual = Add-ObolSspiKdc -Realm EXAMPLE.TEST -KdcAddress 127.0.0.1 -PassThru
        $actual | Should-HaveType ([Obol.ObolSspiKdc])
        $actual.Scope | Should-Be ([Obol.ObolSspiKdcScope]::Thread)
        $actual.Realm | Should-Be EXAMPLE.TEST
    }

    It "Records the flags by name" {
        $actual = Add-ObolSspiKdc -Realm EXAMPLE.TEST -KdcAddress 127.0.0.1 -DcFlags Kdc, Writable -PassThru
        $actual.DcFlags | Should-Be ([Obol.ObolSspiDcFlags]'Kdc, Writable')
    }

    It "Pins more than one realm" {
        Add-ObolSspiKdc -Realm EXAMPLE.TEST -KdcAddress 127.0.0.1
        Add-ObolSspiKdc -Realm OTHER.TEST -KdcAddress 127.0.0.2

        $pins = Get-ObolSspiKdc | Sort-Object Realm
        @($pins).Count | Should-Be 2
        $pins[0].Realm | Should-Be EXAMPLE.TEST
        $pins[1].Realm | Should-Be OTHER.TEST
    }

    It "Clears all pins" {
        Add-ObolSspiKdc -Realm EXAMPLE.TEST -KdcAddress 127.0.0.1
        Clear-ObolSspiKdc
        @(Get-ObolSspiKdc).Count | Should-Be 0
    }

    It "Does not pin with -WhatIf" {
        Add-ObolSspiKdc -Realm EXAMPLE.TEST -KdcAddress 127.0.0.1 -WhatIf
        @(Get-ObolSspiKdc).Count | Should-Be 0
    }

    It "Does not clear with -WhatIf" {
        Add-ObolSspiKdc -Realm EXAMPLE.TEST -KdcAddress 127.0.0.1
        Clear-ObolSspiKdc -WhatIf
        @(Get-ObolSspiKdc).Count | Should-Be 1
    }

    It "Fails for a realm longer than the SSP accepts" {
        # The LSA message stores the string lengths in bytes as a USHORT.
        { Add-ObolSspiKdc -Realm ('A' * 32768) -KdcAddress 127.0.0.1 } |
            Should-Throw -FullyQualifiedErrorId 'SspiCallFailed,Obol.Commands.AddObolSspiKdc' `
                -ExceptionMessage 'The realm and KDC address must be between 1 and 32767 characters'
        @(Get-ObolSspiKdc).Count | Should-Be 0
    }

    It "Formats as the realm, address and scope" {
        $actual = Add-ObolSspiKdc -Realm EXAMPLE.TEST -KdcAddress 127.0.0.1 -PassThru
        $actual.ToString() | Should-Be 'EXAMPLE.TEST -> 127.0.0.1 (Thread)'
    }

    It "Fails for an empty realm" {
        { Add-ObolSspiKdc -Realm '' -KdcAddress 127.0.0.1 } |
            Should-Throw -ExceptionType ([ParameterBindingException])
    }

    It "Rejects a KDC address with a port '<Address>'" -TestCases @(
        @{ Address = '127.0.0.1:88' }
        @{ Address = 'dc01:1088' }
        @{ Address = '[::1]:88' }
        @{ Address = '[::1]' }
    ) {
        param ($Address)
        { Add-ObolSspiKdc -Realm EXAMPLE.TEST -KdcAddress $Address } |
            Should-Throw -FullyQualifiedErrorId 'InvalidKdcAddress,Obol.Commands.AddObolSspiKdc'
    }

    It "Accepts a bare IPv6 address" {
        Add-ObolSspiKdc -Realm EXAMPLE.TEST -KdcAddress 'fe80::1' -PassThru |
            Select-Object -ExpandProperty KdcAddress | Should-Be 'fe80::1'
    }

    It "Rejects -Scope Process on Add" {
        { Add-ObolSspiKdc -Realm EXAMPLE.TEST -KdcAddress 127.0.0.1 -Scope Process } |
            Should-Throw -FullyQualifiedErrorId 'ParameterArgumentValidationError,Obol.Commands.AddObolSspiKdc'
    }

    It "Rejects -Scope Thread on Clear" {
        { Clear-ObolSspiKdc -Scope Thread } |
            Should-Throw -FullyQualifiedErrorId 'ParameterArgumentValidationError,Obol.Commands.ClearObolSspiKdc'
    }

    Context "Thread scope of the record" {
        AfterEach {
            Clear-ObolSspiKdc
        }

        It "Lists a pin made earlier on the same reused thread" {
            $ps = New-ObolPowerShell -ThreadOptions ([PSThreadOptions]::ReuseThread)
            try {
                $null = $ps.AddScript('Add-ObolSspiKdc -Realm REUSE.TEST -KdcAddress 127.0.0.1').Invoke()
                $ps.Commands.Clear()
                $seen = $ps.AddScript('@(Get-ObolSspiKdc).Realm').Invoke()

                $seen | Should-Be REUSE.TEST
            }
            finally {
                $ps.Runspace.Dispose()
                $ps.Dispose()
            }
        }

        It "Does not list a pin made on another thread" {
            $ps = New-ObolPowerShell -ThreadOptions ([PSThreadOptions]::UseNewThread)
            try {
                $null = $ps.AddScript('Add-ObolSspiKdc -Realm NEWTHREAD.TEST -KdcAddress 127.0.0.1').Invoke()
                $ps.Commands.Clear()
                $count = $ps.AddScript('@(Get-ObolSspiKdc).Count').Invoke()

                $count[0] | Should-Be 0
            }
            finally {
                $ps.Runspace.Dispose()
                $ps.Dispose()
            }
        }

        It "Clears the record of a pin made on another thread" {
            $a = New-ObolPowerShell -ThreadOptions ([PSThreadOptions]::ReuseThread)
            $b = New-ObolPowerShell -ThreadOptions ([PSThreadOptions]::ReuseThread)
            try {
                $null = $a.AddScript('Add-ObolSspiKdc -Realm CROSS.TEST -KdcAddress 127.0.0.1').Invoke()
                $a.Commands.Clear()
                $null = $b.AddScript('Clear-ObolSspiKdc').Invoke()
                $b.Commands.Clear()
                $count = $a.AddScript('@(Get-ObolSspiKdc).Count').Invoke()

                $count[0] | Should-Be 0
            }
            finally {
                $a.Runspace.Dispose()
                $a.Dispose()
                $b.Runspace.Dispose()
                $b.Dispose()
            }
        }
    }
}

Describe "Add/Get/Clear-ObolSspiKdc machine scope" -Skip:(-not $isAdmin) {
    AfterEach {
        # The binding cache is machine wide, purge the entries this test added. The OS repopulates real ones.
        Clear-ObolSspiKdc -Scope Machine
    }

    It "Adds a binding and reads it back" {
        $before = Get-Date
        Add-ObolSspiKdc -Realm OBOL.TEST -KdcAddress 127.0.0.1 -Scope Machine

        $binding = Get-ObolSspiKdc -Scope Machine | Where-Object Realm -EQ OBOL.TEST
        $binding | Should-HaveType ([Obol.ObolSspiKdc])
        $binding.Scope | Should-Be ([Obol.ObolSspiKdcScope]::Machine)
        $binding.KdcAddress | Should-Be 127.0.0.1
        $binding.AddressType | Should-Be ([Obol.ObolSspiKdcAddressType]::Inet)

        # The SSP stores the time in milliseconds since boot, so it is only accurate to the tick resolution.
        $binding.DiscoveryTime | Should-BeGreaterThanOrEqual $before.AddSeconds(-1)
        $binding.DiscoveryTime | Should-BeLessThanOrEqual (Get-Date).AddSeconds(1)
    }

    It "Returns the binding with -PassThru" {
        $binding = Add-ObolSspiKdc -Realm OBOL.TEST -KdcAddress 127.0.0.1 -Scope Machine -PassThru
        $binding.Scope | Should-Be ([Obol.ObolSspiKdcScope]::Machine)
        $binding.Realm | Should-Be OBOL.TEST
    }

    It "Records the DC flags by name" {
        Add-ObolSspiKdc -Realm OBOL.TEST -KdcAddress 127.0.0.1 -Scope Machine -DcFlags Kdc, Writable
        $binding = Get-ObolSspiKdc -Scope Machine | Where-Object Realm -EQ OBOL.TEST

        $binding.DcFlags | Should-Be ([Obol.ObolSspiDcFlags]'Kdc, Writable')
        # The SSP sets the DsGetDcName request flags from the DC flags.
        $binding.BindingFlags | Should-Be ([Obol.ObolSspiDcLocatorFlags]'WritableRequired, TryNextClosestSite')
        $binding.CacheFlags | Should-Be ([Obol.ObolSspiKdcCacheFlags]::None)
    }

    It "Purges the binding" {
        Add-ObolSspiKdc -Realm OBOL.TEST -KdcAddress 127.0.0.1 -Scope Machine
        (Get-ObolSspiKdc -Scope Machine | Where-Object Realm -EQ OBOL.TEST) | Should-NotBeNull

        Clear-ObolSspiKdc -Scope Machine

        (Get-ObolSspiKdc -Scope Machine | Where-Object Realm -EQ OBOL.TEST) | Should-BeNull
    }

    It "Does not add with -WhatIf" {
        Add-ObolSspiKdc -Realm OBOL.TEST -KdcAddress 127.0.0.1 -Scope Machine -WhatIf
        (Get-ObolSspiKdc -Scope Machine | Where-Object Realm -EQ OBOL.TEST) | Should-BeNull
    }

    It "Does not purge with -WhatIf" {
        Add-ObolSspiKdc -Realm OBOL.TEST -KdcAddress 127.0.0.1 -Scope Machine
        Clear-ObolSspiKdc -Scope Machine -WhatIf
        (Get-ObolSspiKdc -Scope Machine | Where-Object Realm -EQ OBOL.TEST) | Should-NotBeNull
    }

    It "Rejects a KDC address with a port" {
        { Add-ObolSspiKdc -Realm OBOL.TEST -KdcAddress '127.0.0.1:88' -Scope Machine } |
            Should-Throw -FullyQualifiedErrorId 'InvalidKdcAddress,Obol.Commands.AddObolSspiKdc'
    }
}

Describe "Add-ObolSspiKdc -Scope Machine SeTcbPrivilege routes" -Skip:(-not $canTestPrivilegeRoutes) {
    BeforeAll {
        Import-Module -Name PSPrivilege

        # Created with net.exe: New-LocalUser is not on the restricted test PSModulePath and the ADSI WinNT provider
        # rejects the password under the complexity policy. The 14 character password avoids net.exe's long prompt.
        $script:testUser = "obol_sspi_$(Get-Random -Maximum 999999)"
        $script:testPassword = 'Obol1!aZ9kQ2wE'
        $output = net.exe user $script:testUser $script:testPassword /add 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create the test user: $($output -join ' ')"
        }
        $script:testSid = ([NTAccount]::new($script:testUser)).Translate([SecurityIdentifier])
    }

    AfterAll {
        if ($script:testSid) {
            Remove-WindowsRight -Name SeTcbPrivilege -Account $script:testSid -ErrorAction Ignore
        }
        if ($script:testUser) {
            $null = net.exe user $script:testUser /delete 2>&1
        }
    }

    AfterEach {
        Remove-WindowsRight -Name SeTcbPrivilege -Account $script:testSid -ErrorAction Ignore
        Clear-ObolSspiKdc -Scope Machine
    }

    It "Errors when the effective token lacks SeTcbPrivilege and cannot get it" {
        $err = Invoke-AsLogonUser -Username $testUser -Password $testPassword -ScriptBlock {
            { Get-ObolSspiKdc -Scope Machine } | Should-Throw
        }

        $err.FullyQualifiedErrorId | Should-Be 'SspiCallFailed,Obol.Commands.GetObolSspiKdc'
        $err.Exception.Message | Should-BeLikeString '*SeTcbPrivilege*'
    }

    It "Works when the effective token holds SeTcbPrivilege without impersonating SYSTEM" {
        Add-WindowsRight -Name SeTcbPrivilege -Account $testSid

        $kdcAddress = Invoke-AsLogonUser -Username $testUser -Password $testPassword -ScriptBlock {
            Add-ObolSspiKdc -Realm OBOL.TEST -KdcAddress 127.0.0.1 -Scope Machine
            (Get-ObolSspiKdc -Scope Machine | Where-Object Realm -EQ OBOL.TEST).KdcAddress
        }

        $kdcAddress | Should-Be 127.0.0.1
    }
}

Describe "SSPI cmdlets on non-Windows" -Skip:$IsWindows {
    It "<Name> errors" -TestCases @(
        @{ Name = 'Add-ObolSspiKdc'; Command = 'AddObolSspiKdc'
            Script = { Add-ObolSspiKdc -Realm EXAMPLE.TEST -KdcAddress 127.0.0.1 } }
        @{ Name = 'Get-ObolSspiKdc'; Command = 'GetObolSspiKdc'; Script = { Get-ObolSspiKdc } }
        @{ Name = 'Clear-ObolSspiKdc'; Command = 'ClearObolSspiKdc'; Script = { Clear-ObolSspiKdc } }
    ) {
        param ($Command, $Script)
        $err = { & $Script } | Should-Throw -FullyQualifiedErrorId "SspiNotSupported,Obol.Commands.$Command"
        $err.Exception | Should-HaveType ([PlatformNotSupportedException])
    }
}
