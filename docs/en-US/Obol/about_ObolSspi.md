# ObolSspi
## about_ObolSspi

# SHORT DESCRIPTION
How Obol interacts with the Windows Kerberos Security Support Provider (SSP).

# LONG DESCRIPTION
On Linux and macOS, Kerberos clients read `krb5.conf` and the krb5 environment variables, which makes it easy to point a process at an Obol KDC.
On Windows, Kerberos is implemented by the Security Support Provider (SSP) `kerberos.dll` inside LSASS, and it ignores `krb5.conf`, `KRB5_CONFIG` and the other krb5 environment variables.
Those only affect programs that ship their own MIT krb5 or Heimdal, for example a Python or Java client.

Anything using SSPI Kerberos is affected, on both sides of an exchange:

+ an initiator (client) such as .NET `NegotiateStream`, `HttpClient` with default credentials or `System.DirectoryServices`
+ an acceptor (server) validating or acquiring a ticket

That is anything built on `InitializeSecurityContext` or `AcceptSecurityContext`.

When the SSP needs to contact a KDC it does two things:

1. It decides which realm(s) the request is for, from the credential and the target name.
   This is covered in [about_ObolSspiRealm](./about_ObolSspiRealm.md).
2. It finds a KDC for those realm(s), from various sources and environment information.
   This is covered in [about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md).

Obol provides some cmdlets to manage some of the KDC lookup mechanisms, specifically the per-thread pin and the machine-wide binding cache, which are described below.

# OBOL CMDLETS
[Add-ObolSspiKdc](./Add-ObolSspiKdc.md), [Get-ObolSspiKdc](./Get-ObolSspiKdc.md) and [Clear-ObolSspiKdc](./Clear-ObolSspiKdc.md) manage the KDC the SSP uses for a realm.
They are Windows only and write a terminating error on other platforms.
These three cmdlets can manage the per-thread pin and the machine-wide binding cache with the `-Scope` parameter controller which one.

A pin or binding cache entry only takes effect when the SSP contacts a KDC, which it does not do while a valid ticket is cached, see [WHEN A KDC IS CONTACTED in about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md#when-a-kdc-is-contacted).

Unlike `klist.exe add_bind`, Obol sends the LSA messages directly to the Kerberos SSP.
This means there is no DNS or DC locator lookup on the provided values and an unresolvable realm such as `OBOL.TEST` is still accepted.
The SSP always contacts the KDC on port 88, so the address must be a bare host or IP with no port, see [PORTS in about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md#ports).

## Per-thread pin (no admin)
`Add-ObolSspiKdc -Realm <REALM> -KdcAddress <host>`, with the default `-Scope Thread`, sends the `KerbPinKdc` message, see [PER-THREAD PIN in about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md#per-thread-pin).
It needs no administrator rights because the pin is tied to the calling thread rather than a machine-wide table.

Because the pin only applies to the thread that set it, set the pin and do the authentication on the same OS thread, with no runspace, job or `async`/`await` hop in between.
A plain sequential script in one runspace stays on one thread, but `Start-Job`, `Start-ThreadJob`, `ForEach-Object -Parallel` and async continuations do not.
A pin is also not seen by another thread in the same process, a child process, or another process in the same logon session.

Known protocols that does not run on your thread and will not see the pin are:

+ SMB: the redirector runs the handshake from the kernel.
+ CredSSP: the inner Kerberos authentication is driven from LSASS.

Windows has no way to list pins, so [Get-ObolSspiKdc](./Get-ObolSspiKdc.md) reports only the pins that Obol added itself on the calling thread.
Pinning a realm that is already pinned returns success without changing the KDC, run [Clear-ObolSspiKdc](./Clear-ObolSspiKdc.md) first to change it.
There is no per-realm unpin, [Clear-ObolSspiKdc](./Clear-ObolSspiKdc.md) (`-Scope Process`, the default) removes every pin in the process, including those of other threads.

## Binding cache (admin)
[Add-ObolSspiKdc](./Add-ObolSspiKdc.md), [Get-ObolSspiKdc](./Get-ObolSspiKdc.md) and [Clear-ObolSspiKdc](./Clear-ObolSspiKdc.md) with `-Scope Machine` are the PowerShell form of `klist.exe add_bind`, `query_bind` and `purge_bind`, see [BINDING CACHE in about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md#binding-cache).
The binding cache is machine-wide, so unlike a pin it also steers authentication brokered by the kernel such as SMB.

These operations need administrator rights and fail when being used by a non-admin user.

The SSP also adds and expires entries in this cache itself, so an entry added by Obol ages out after `FarKdcTimeout` (10 minutes by default), see [Expiry in about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md#expiry).

## SSPI environment cmdlets
[Enter-ObolSspiEnvironment](./Enter-ObolSspiEnvironment.md) and [Exit-ObolSspiEnvironment](./Exit-ObolSspiEnvironment.md) register Obol KDC objects with the SSP and remove them again, using a pin for `-Scope Thread` (the default), the binding cache for `-Scope Machine`, the static realm KDC list for `-Scope MitRealm` or the DC locator for `-Scope DcLocator`.
[Use-ObolSspiEnvironment](./Use-ObolSspiEnvironment.md) does the same around a scriptblock, starting a KDC first with `-Realm`.
They are the Windows Kerberos counterpart of `Enter-ObolKrb5Environment`, `Exit-ObolKrb5Environment` and `Use-ObolKrb5Environment`, which set the krb5 environment variables MIT krb5 and Heimdal read, including on Windows.
Both kinds can be entered at the same time.

On top of [Add-ObolSspiKdc](./Add-ObolSspiKdc.md) they:

+ Take the realm and address from the KDC, using the loopback address for a KDC listening on all addresses.
+ Require the KDC to listen on port 88, `Use-ObolSspiEnvironment` always starts its KDC on port 88 and has no `-Port`.
+ Allow one SSPI environment in the process at a time, exited automatically when the runspace that entered it closes.
+ Remove the entries on exit, which is every pin in the process with `Clear-ObolSspiKdc -Scope Process` for `Thread`, and the whole binding cache with `Clear-ObolSspiKdc -Scope Machine` for the machine wide scopes, including entries the SSP or other tools added.
  For `Thread` they refuse to enter if the thread already has a pin, as exiting would remove it.
+ For `MitRealm`, add the realm and its KDCs under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains` and a host to realm mapping under `...\Kerberos\HostToRealm`, see [STATIC REALM KDC LIST in about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md#static-realm-kdc-list).
+ For `DcLocator`, add an NRPT rule for the realm and run a DNS server and LDAP ping responder for it, see [DC LOCATOR AND DNS in about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md#dc-locator-and-dns).

`MitRealm` and `DcLocator` purge the binding cache when entered too, an entry for the realm from before would be used instead of the new configuration.
They create volatile registry keys, which Windows removes on reboot, so a killed process cannot leave them behind for good.
They never change configuration that already exists: a realm key or NRPT rule for the realm, including one left by a killed Obol process, makes them fail with how to remove it.
Windows ignores every local NRPT rule while the Group Policy key `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig` exists, even an empty one, so `DcLocator` also fails if it does.

A PowerShell console runs every command on the same thread, so after `Enter-ObolSspiEnvironment` with `Thread` the following commands use the KDC.
With `Machine` the entry ages out after `FarKdcTimeout` (10 minutes by default), see [Expiry in about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md#expiry).

Windows does not reserve ports below 1024, so binding port 88 needs no administrator rights.
The whole `127.0.0.0/8` range is loopback, so several KDCs can share port 88 on different loopback addresses (`127.0.0.2`, `127.0.0.3`, ...).
In testing a specific `127.0.0.2:88` could still be bound alongside a wildcard `0.0.0.0:88`, unless the wildcard socket had set `SO_EXCLUSIVEADDRUSE`.

## Accepting tickets with SSPI
The tickets Obol issues carry a PAC, like the ones from an Active Directory KDC.
When a Windows service accepts one with `AcceptSecurityContext`, Windows only checks the PAC itself when the service runs as `SYSTEM`, `NETWORK SERVICE` or `LOCAL SERVICE`, or holds `SeTcbPrivilege`.
Any other process makes Windows send the PAC to a domain controller of the realm to check its KDC signature (the `KERB_VERIFY_PAC` message of [MS-APDS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-apds/1d1f2b0c-8e8a-4d2a-8665-508d04976f84)), see [Understanding Microsoft Kerberos PAC Validation](https://learn.microsoft.com/en-us/archive/blogs/openspecification/understanding-microsoft-kerberos-pac-validation).
A host not joined to the realm has no domain controller to send it to, so accepting fails with `STATUS_TRUSTED_DOMAIN_FAILURE` (`0xC000018C`).
Getting a ticket as the client is not affected.

There are three ways around it:

+ Set `-Flag NoAuthDataRequired` on the service principal, so its tickets have no PAC to check, see [PRINCIPAL FLAGS in about_Obol](./about_Obol.md#principal-flags).
  This works for any process, but the client then has no groups or SIDs and Windows names it `REALM\user`.
+ Accept the tickets in a process running as `SYSTEM`, `NETWORK SERVICE` or `LOCAL SERVICE`, or holding `SeTcbPrivilege`.
  Windows then checks the PAC with the service key and builds the client's token from it, naming the client `DOMAIN\user` with the NetBIOS name of the realm.
+ Run the accepting process as a Windows service and set `ValidateKdcPacSignature` to `0` under `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`, which needs a restart and only applies to services.
# SEE ALSO
+ [about_ObolSspiRealm](./about_ObolSspiRealm.md)
+ [about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md)
+ [Add-ObolSspiKdc](./Add-ObolSspiKdc.md)
+ [Get-ObolSspiKdc](./Get-ObolSspiKdc.md)
+ [Clear-ObolSspiKdc](./Clear-ObolSspiKdc.md)
+ [Enter-ObolSspiEnvironment](./Enter-ObolSspiEnvironment.md)
+ [Exit-ObolSspiEnvironment](./Exit-ObolSspiEnvironment.md)
+ [Use-ObolSspiEnvironment](./Use-ObolSspiEnvironment.md)
+ [about_Obol](./about_Obol.md)
