using module ../output/Obol
using namespace System.IO
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
