# Obol
## about_Obol

# SHORT DESCRIPTION
Obol is a PowerShell module that runs a Kerberos KDC endpoint based on Kerberos.NET.

# LONG DESCRIPTION
Obol hosts a Kerberos Key Distribution Center (KDC) inside a PowerShell process using the [Kerberos.NET](https://github.com/dotnet/Kerberos.NET) library.
It is designed to provide a lightweight KDC for testing and development scenarios without needing a full Active Directory or MIT/Heimdal KDC deployment.

The module and its dependencies are loaded in a separate AssemblyLoadContext to avoid conflicts with other assemblies loaded in the PowerShell process.
