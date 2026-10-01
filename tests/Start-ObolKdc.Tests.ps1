BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

Describe "Start-ObolKdc" {
    It "Outputs the Obol string" {
        $actual = Start-ObolKdc

        $actual | Should-HaveType ([string])
        $actual | Should-BeLikeString 'Obol KDC using Kerberos.NET *'
    }

    It "Loads Kerberos.NET in the module load context" {
        $kerberosAsm = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GetName().Name -eq 'Kerberos.NET' }

        $kerberosAsm | Should-NotBeNull
        [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext($kerberosAsm).Name | Should-Be Obol
    }
}
