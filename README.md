# Obol

[![Test workflow](https://github.com/jborean93/PowerShell-Obol/workflows/Test%20Obol/badge.svg)](https://github.com/jborean93/PowerShell-Obol/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jborean93/PowerShell-Obol/branch/main/graph/badge.svg)](https://codecov.io/gh/jborean93/PowerShell-Obol)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/Obol.svg)](https://www.powershellgallery.com/packages/Obol)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/PowerShell-Obol/blob/main/LICENSE)

PowerShell module that runs a Kerberos KDC endpoint based on [Kerberos.NET](https://github.com/dotnet/Kerberos.NET).
It gives Kerberos clients and services a realm to test against inside a PowerShell process, without a domain controller or an MIT/Heimdal KDC install.

See [about_Obol](docs/en-US/Obol/about_Obol.md) for more details.

> [!WARNING]
> Obol is designed for testing and learning purposes.
> It should not be considered a secure solution for production environments and must not be used as the KDC for a real realm.

## Documentation

Documentation for this module and details on the cmdlets included can be found [here](docs/en-US/Obol/Obol.md).

## What is supported

| Feature | Supported |
| --- | --- |
| `AS-REQ` and `TGS-REQ` exchanges over TCP and UDP | Yes |
| Encrypted timestamp pre-authentication with `PA-ETYPE-INFO2` salts | Yes |
| AES encryption types, RFC 3962 `aes128/aes256-cts-hmac-sha1-96` and RFC 8009 `aes128-cts-hmac-sha256-128`/`aes256-cts-hmac-sha384-192` | Yes |
| RC4 and DES encryption types | No |
| A PAC in tickets with the principal's SID and groups, like an Active Directory KDC | Yes |
| Forwardable, forwarded, renewable and user-to-user tickets, `OK-AS-DELEGATE` | Yes |
| Proxiable and postdated tickets | No |
| Principal aliases and enterprise names | Yes |
| Keys from a password, random keys or an existing keytab, keytab import and export | Yes |
| Tracing every request and reply the KDC processed, including the decrypted ticket and PAC | Yes |
| Pointing MIT krb5 and Heimdal at the KDC with a generated `krb5.conf` and the krb5 environment variables | Yes |
| Pointing Windows Kerberos (SSPI) at the KDC, per thread or machine wide | Yes, Windows only |
| Cross-realm trusts and referrals | No |
| Constrained delegation (`S4U2Self`, `S4U2Proxy`) | No |
| PKINIT and FAST | No |
| Password changes (`kpasswd`) | No |
| Persisting principals, they live in memory until the KDC is stopped | No |

## Examples

### MIT krb5 and Heimdal

`Use-ObolKrb5Environment` starts a KDC with the principals given, points the krb5 environment variables at it and stops it once the scriptblock finishes.
Any client that reads `krb5.conf` can be run inside the scriptblock, such as `kinit` and `kvno` here or a Python or Java program using the system Kerberos library.

```powershell
$password = ConvertTo-SecureString -AsPlainText -Force 'Password123!'
Use-ObolKrb5Environment -Realm EXAMPLE.TEST -Principal @{ user = $password; 'HTTP/web.example.test' = $null } {
    'Password123!' | kinit user
    kvno HTTP/web.example.test
    klist
}
```

```Output
HTTP/web.example.test@EXAMPLE.TEST: kvno = 1
Ticket cache: FILE:/tmp/obol-T1aa5V/ccache
Default principal: user@EXAMPLE.TEST

Valid starting     Expires            Service principal
05/10/26 20:46:44  06/10/26 06:46:44  krbtgt/EXAMPLE.TEST@EXAMPLE.TEST
        renew until 06/10/26 20:46:43
05/10/26 20:46:44  06/10/26 06:46:44  HTTP/web.example.test@EXAMPLE.TEST
        renew until 06/10/26 20:46:43
```

Use `-ClientPrincipal` and `-ServicePrincipal` to also write keytabs for the principals, so a client can `kinit -k` and a service can decrypt the tickets.
`Enter-ObolKrb5Environment` and `Exit-ObolKrb5Environment` do the same without a scriptblock, for the `BeforeAll` and `AfterAll` of a Pester test.

### Windows SSPI

Windows Kerberos ignores `krb5.conf`.
`Use-ObolSspiEnvironment` starts the KDC on port 88 and registers it with the Kerberos SSP for the scriptblock's thread, so anything using SSPI on that thread, such as .NET's `NegotiateAuthentication`, gets its tickets from the KDC.

```powershell
$password = ConvertTo-SecureString -AsPlainText -Force 'Password123!'
Use-ObolSspiEnvironment -Realm EXAMPLE.TEST -Principal @{ user = $password; 'HTTP/web.example.test' = $null } {
    $client = [System.Net.Security.NegotiateAuthentication]::new(
        [System.Net.Security.NegotiateAuthenticationClientOptions]@{
            Package = 'Kerberos'
            Credential = [System.Net.NetworkCredential]::new('user@EXAMPLE.TEST', 'Password123!')
            TargetName = 'HTTP/web.example.test'
        })
    try {
        $status = [System.Net.Security.NegotiateAuthenticationStatusCode]::GenericFailure
        $token = $client.GetOutgoingBlob([byte[]]@(), [ref]$status)
        $status
    }
    finally {
        $client.Dispose()
    }
}
```

```Output
Completed
```

A per-thread registration needs no administrator rights but is not seen by other threads or processes, SMB for example.
`-Scope Machine`, `-Scope MitRealm` and `-Scope DcLocator` register the KDC for the whole machine in different ways and need an elevated session.
See [about_ObolSspi](docs/en-US/Obol/about_ObolSspi.md) for how Windows finds a KDC and which scope suits which client.

### Step by step

The cmdlets the two wrappers are built on can be used directly, for example to export a keytab and `krb5.conf` for a service running elsewhere and to see what a client asked the KDC for.

```powershell
$password = ConvertTo-SecureString -AsPlainText -Force 'Password123!'
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST
$kdc | New-ObolPrincipal user -Password $password
$kdc | New-ObolPrincipal HTTP/web.example.test

# A keytab for the service and a krb5.conf for the clients.
$kdc | Export-ObolKeytab ./web.keytab HTTP/web.example.test
$kdc | Export-ObolKrb5Config ./krb5.conf

# The requests made while the scriptblock ran.
Enter-ObolKrb5Environment -Kdc $kdc
$events = Trace-ObolKdc -Kdc $kdc {
    'Password123!' | kinit user
    kvno HTTP/web.example.test
}
$events.Message

Exit-ObolKrb5Environment
Stop-ObolKdc -Kdc $kdc
```

```Output
AS-REQ user@EXAMPLE.TEST -> krbtgt/EXAMPLE.TEST@EXAMPLE.TEST: PreAuthRequired
AS-REQ user@EXAMPLE.TEST -> krbtgt/EXAMPLE.TEST@EXAMPLE.TEST: AS-REP, Aes256Sha1 ticket and session key, PreAuthenticated, Initial, Renewable
TGS-REQ user@EXAMPLE.TEST -> HTTP/web.example.test@EXAMPLE.TEST: TGS-REP, Aes256Sha1 ticket and session key, PreAuthenticated, Renewable
```

Each event holds the decoded request and reply, including the parts only the KDC can decrypt such as the issued ticket and its PAC, see [about_ObolKdcEvent](docs/en-US/Obol/about_ObolKdcEvent.md).

## Requirements

These cmdlets have the following requirements

* PowerShell v7.6 or newer

## Installing

The easiest way to install this module is through
[PowerShellGet](https://docs.microsoft.com/en-us/powershell/gallery/overview).

You can install this module by running;

```powershell
# Install for only the current user
Install-PSResource -Name Obol -Scope CurrentUser

# Install for all users
Install-PSResource -Name Obol -Scope AllUsers
```

## Contributing

Contributing is quite easy, fork this repo and submit a pull request with the changes.
To build this module run `.\build.ps1 -Task Build` in PowerShell.
To test a build run `.\build.ps1 -Task Test` in PowerShell.
This script will ensure all dependencies are installed before running the test suite.
