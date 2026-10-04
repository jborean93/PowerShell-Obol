using module ../output/Obol
using namespace System.IO

BeforeAll {
    . ([Path]::Combine($PSScriptRoot, 'common.ps1'))

    $variableNames = 'KRB5_CONFIG', 'KRB5CCNAME', 'KRB5_KTNAME', 'KRB5_CLIENT_KTNAME'
}

Describe "Use-ObolKrb5Environment" {
    BeforeEach {
        $previous = @{}
        foreach ($name in $variableNames) {
            $previous[$name] = [Environment]::GetEnvironmentVariable($name)
            Remove-Item "Env:\$name" -ErrorAction Ignore
        }
    }

    AfterEach {
        Exit-ObolKrb5Environment
        Get-ObolKdc | Stop-ObolKdc
        foreach ($name in $variableNames) {
            # PowerShell passes $null to a .NET string parameter as '', which would leave an empty variable.
            if ($null -eq $previous[$name]) {
                Remove-Item "Env:\$name" -ErrorAction Ignore
            }
            else {
                Set-Item "Env:\$name" $previous[$name]
            }
        }
    }

    Context "Started KDC" {
        It "Runs the scriptblock with a KDC and the environment" {
            $actual = Use-ObolKrb5Environment EXAMPLE.TEST -Principal @{ user = $null } {
                param ($kdc)

                [PSCustomObject]@{
                    Kdc = $kdc
                    State = $kdc.State
                    Principal = ($kdc | Get-ObolPrincipal user).Name
                    Config = [File]::ReadAllText($env:KRB5_CONFIG)
                    Expected = ConvertTo-ObolKrb5Config $kdc
                    CCache = $env:KRB5CCNAME
                }
            }

            $actual.Kdc.Realm | Should-Be EXAMPLE.TEST
            $actual.State | Should-Be Running
            $actual.Principal | Should-Be user
            $actual.Config | Should-Be $actual.Expected
            $actual.CCache | Should-BeLikeString 'FILE:*'
        }

        It "Stops the KDC and exits the environment after" {
            $config = Use-ObolKrb5Environment EXAMPLE.TEST { $env:KRB5_CONFIG }

            Get-ObolKdc | Should-BeNull
            [Environment]::GetEnvironmentVariable('KRB5_CONFIG') | Should-BeNull
            Test-Path ([Path]::GetDirectoryName($config)) | Should-BeFalse
        }

        It "Passes the KDC parameters to the KDC" {
            $actual = Use-ObolKrb5Environment EXAMPLE.TEST -Transport Tcp -CaseInsensitivePrincipal { $args[0] }

            $actual.Transport | Should-Be ([Obol.ObolKdcTransport]::Tcp)
            $actual.CaseInsensitivePrincipal | Should-BeTrue
        }

        It "Writes the krb5.conf for -Provider" {
            $actual = Use-ObolKrb5Environment EXAMPLE.TEST -Transport Tcp -Provider Heimdal {
                [File]::ReadAllText($env:KRB5_CONFIG) -eq (ConvertTo-ObolKrb5Config $args[0] -Provider Heimdal)
            }

            $actual | Should-BeTrue
        }

        It "Fails if the KDC cannot start" {
            $script:ran = $false

            { Use-ObolKrb5Environment 'BAD/REALM' { $script:ran = $true } } |
                Should-Throw -FullyQualifiedErrorId 'InvalidRealm,Obol.Commands.UseObolKrb5Environment'

            $script:ran | Should-BeFalse
            [Environment]::GetEnvironmentVariable('KRB5_CONFIG') | Should-BeNull
        }

        It "Fails for a realm that cannot be written in a krb5.conf" {
            { Use-ObolKrb5Environment 'BAD]REALM' { 'ran' } } |
                Should-Throw -FullyQualifiedErrorId 'InvalidKrb5ConfigRealm,Obol.Commands.UseObolKrb5Environment'

            Get-ObolKdc | Should-BeNull
        }
    }

    Context "Existing KDCs" {
        BeforeEach {
            $kdc = Start-ObolKdc EXAMPLE.TEST -Principal @{ user = $null; 'HTTP/web.example.test' = $null }
            $other = Start-ObolKdc OTHER.TEST -Principal @{ user = $null }
        }

        It "Passes each KDC as an argument" {
            $actual = Use-ObolKrb5Environment -Kdc $kdc, $other {
                param ($first, $second)

                $first.Realm
                $second.Realm
                [File]::ReadAllText($env:KRB5_CONFIG) -eq (ConvertTo-ObolKrb5Config $first, $second)
            }

            $actual | Should-BeCollection @('EXAMPLE.TEST', 'OTHER.TEST', $true)
        }

        It "Uses KDCs from the pipeline and leaves them running" {
            $actual = $kdc, $other | Use-ObolKrb5Environment { $args.Count }

            $actual | Should-Be 2
            $kdc.State | Should-Be Running
            $other.State | Should-Be Running
        }

        It "Fails if no KDC is received from the pipeline" {
            { @() | Use-ObolKrb5Environment { 'ran' } } | Should-Throw -FullyQualifiedErrorId 'NoKdc,Obol.Commands.UseObolKrb5Environment'
        }

        It "Fails for an undefined provider" {
            $provider = [Enum]::ToObject([Obol.ObolKrb5Provider], 99)

            { Use-ObolKrb5Environment -Kdc $kdc -Provider $provider { 'ran' } } |
                Should-Throw -FullyQualifiedErrorId 'InvalidProvider,Obol.Commands.UseObolKrb5Environment'
        }

        It "Fails for a stopped KDC without running the scriptblock" {
            Stop-ObolKdc $other
            $script:ran = $false

            { $kdc, $other | Use-ObolKrb5Environment { $script:ran = $true } } |
                Should-Throw -FullyQualifiedErrorId 'KdcNotRunning,Obol.Commands.UseObolKrb5Environment'

            $script:ran | Should-BeFalse
        }

        It "Writes keytabs for -ServicePrincipal and -ClientPrincipal" {
            $params = @{
                Kdc = $kdc, $other
                ServicePrincipal = 'HTTP/web.example.test'
                ClientPrincipal = 'user', 'user@OTHER.TEST'
            }
            $actual = Use-ObolKrb5Environment @params {
                [PSCustomObject]@{
                    Service = Read-TestKeytab ($env:KRB5_KTNAME -replace '^FILE:')
                    Client = Read-TestKeytab ($env:KRB5_CLIENT_KTNAME -replace '^FILE:')
                }
            }

            $actual.Service.Name | Select-Object -Unique | Should-Be 'HTTP/web.example.test@EXAMPLE.TEST'
            $actual.Client.Name | Select-Object -Unique |
                Should-BeCollection @('user@EXAMPLE.TEST', 'user@OTHER.TEST')
        }

        It "Fails for a principal that does not exist" -TestCases @(
            @{ Name = 'missing' }
            @{ Name = 'user@MISSING.TEST' }
        ) {
            param ($Name)

            $script:ran = $false

            { Use-ObolKrb5Environment -Kdc $kdc -ClientPrincipal $Name { $script:ran = $true } } |
                Should-Throw -FullyQualifiedErrorId 'PrincipalNotFound,Obol.Commands.UseObolKrb5Environment'

            $script:ran | Should-BeFalse
            [Environment]::GetEnvironmentVariable('KRB5_CONFIG') | Should-BeNull
        }

        It "Fails for an invalid principal name" {
            { Use-ObolKrb5Environment -Kdc $kdc -ServicePrincipal 'a@b@c' { 'ran' } } |
                Should-Throw -FullyQualifiedErrorId 'InvalidPrincipalName,Obol.Commands.UseObolKrb5Environment'
        }

        It "Fails if an environment is already entered" {
            Enter-ObolKrb5Environment $kdc

            { Use-ObolKrb5Environment NEW.TEST { 'ran' } } |
                Should-Throw -FullyQualifiedErrorId 'Krb5EnvironmentAlreadyEntered,Obol.Commands.UseObolKrb5Environment'

            Get-ObolKdc | Where-Object Realm -EQ NEW.TEST | Should-BeNull
        }

        It "Leaves the prompt alone" {
            $prompt = ${function:global:prompt}

            $actual = Use-ObolKrb5Environment -Kdc $kdc { [object]::ReferenceEquals(${function:global:prompt}, $prompt) }

            $actual | Should-BeTrue
        }

        It "Sets the native environment with -SetNativeEnvironment" -Skip:$IsWindows {
            $actual = Use-ObolKrb5Environment -Kdc $kdc -SetNativeEnvironment {
                (Get-NativeEnvironmentVariable KRB5_CONFIG) -eq $env:KRB5_CONFIG
            }

            $actual | Should-BeTrue
        }
    }

    Context "Scriptblock invocation" {
        It "Writes output as it is received" {
            $actual = Use-ObolKrb5Environment EXAMPLE.TEST { 1; 2; 3 } | Select-Object -First 2

            $actual | Should-BeCollection @(1, 2)
            Get-ObolKdc | Should-BeNull
        }

        It "Runs in a new scope" {
            $value = 'caller'

            Use-ObolKrb5Environment EXAMPLE.TEST { $value = 'inner' }

            $value | Should-Be caller
        }

        It "Runs in the caller's scope with -NoNewScope" {
            $value = 'caller'

            Use-ObolKrb5Environment EXAMPLE.TEST { $value = 'inner' } -NoNewScope

            $value | Should-Be inner
        }

        It "Runs a scriptblock from a module in the caller's scope with -NoNewScope" {
            $module = New-Module -ScriptBlock {
                Function Get-TestScriptBlock { { $value = 'module' } }
            }
            $value = 'caller'

            Use-ObolKrb5Environment EXAMPLE.TEST (& $module { Get-TestScriptBlock }) -NoNewScope

            $value | Should-Be module
        }

        It "Runs each named block once like the call operator" {
            $script:cleaned = $false
            $sb = {
                param ($kdc)
                begin { "begin $($kdc.Realm)" }
                process { 'process' }
                end { 'end' }
                clean { $script:cleaned = $true }
            }

            $actual = Use-ObolKrb5Environment EXAMPLE.TEST $sb

            $actual | Should-BeCollection @('begin EXAMPLE.TEST', 'process', 'end')
            $script:cleaned | Should-BeTrue
        }

        It "Runs a function's scriptblock with its parameters" {
            Function Get-TestRealm {
                param ([Parameter(Mandatory)][Obol.ObolKdc]$Kdc)
                $Kdc.Realm
            }

            Use-ObolKrb5Environment EXAMPLE.TEST ${function:Get-TestRealm} | Should-Be EXAMPLE.TEST
        }

        It "Sets `$MyInvocation to the line that called it with -NoNewScope:<NoNewScope>" -TestCases @(
            @{ NoNewScope = $false }
            @{ NoNewScope = $true }
        ) {
            param ($NoNewScope)

            # Both on one line so the call operator gives the expected values.
            $p = @{ NoNewScope = $NoNewScope }
            $expected = & { $MyInvocation }; $actual = Use-ObolKrb5Environment EXAMPLE.TEST { $MyInvocation } @p

            $actual.ScriptLineNumber | Should-Be $expected.ScriptLineNumber
            $actual.ScriptName | Should-Be $expected.ScriptName
            $actual.PSScriptRoot | Should-Be $expected.PSScriptRoot
            $actual.PSCommandPath | Should-Be $expected.PSCommandPath
            $actual.Line | Should-Be $expected.Line
        }

        It "Runs when called without a script position" {
            $ps = New-ObolPowerShell
            try {
                $actual = $ps.AddCommand('Use-ObolKrb5Environment').
                    AddParameter('Realm', 'EXAMPLE.TEST').
                    AddParameter('ScriptBlock', { $MyInvocation.ScriptLineNumber }).
                    Invoke()

                $ps.Streams.Error | Should-BeNull
                $actual | Should-Be 1
            }
            finally {
                $ps.Dispose()
            }
        }

        It "Does not set its own variables in the caller's scope" {
            Use-ObolKrb5Environment EXAMPLE.TEST { } -NoNewScope

            Get-Variable Strip, Kdc -Scope 0 -ErrorAction Ignore | Should-BeNull
        }

        It "Throws a terminating error from the scriptblock and cleans up" {
            $err = { Use-ObolKrb5Environment EXAMPLE.TEST { throw 'failure' } } | Should-Throw

            $err.Exception.Message | Should-Be failure
            $err.InvocationInfo.Line | Should-BeLikeString "*throw 'failure'*"
            Get-ObolKdc | Should-BeNull
            [Environment]::GetEnvironmentVariable('KRB5_CONFIG') | Should-BeNull
        }

        It "Writes non-terminating errors and continues" {
            # common.ps1 sets Stop, which the scriptblock would follow.
            $ErrorActionPreference = 'Continue'

            $actual = Use-ObolKrb5Environment EXAMPLE.TEST { Write-Error 'failure'; 'after' } -ErrorVariable err 2>$null

            $actual | Should-Be after
            $err.Count | Should-Be 1
            $err[0].Exception.Message | Should-Be failure
        }

        It "Uses the caller's `$ErrorActionPreference" {
            $ErrorActionPreference = 'Stop'

            { Use-ObolKrb5Environment EXAMPLE.TEST { Write-Error 'failure'; 'after' } } |
                Should-Throw -ExceptionMessage failure
        }

        It "Does not apply -ErrorAction to the scriptblock" {
            $ErrorActionPreference = 'Continue'

            $actual = Use-ObolKrb5Environment EXAMPLE.TEST { Write-Error 'failure'; 'after' } -ErrorAction Stop 2>$null

            $actual | Should-Be after
        }

        It "Writes the other streams through the cmdlet" {
            $actual = Use-ObolKrb5Environment EXAMPLE.TEST {
                Write-Warning warning
                Write-Information information
                'output'
            } -WarningVariable warn -InformationVariable info 3>$null 6>$null

            $actual | Should-Be output
            $warn.Message | Should-Be warning
            $info.MessageData | Should-Be information
        }

        It "Redirects the streams of the scriptblock" {
            $actual = Use-ObolKrb5Environment EXAMPLE.TEST { Write-Warning warning } 3>&1

            $actual.Message | Should-Be warning
        }
    }
}
