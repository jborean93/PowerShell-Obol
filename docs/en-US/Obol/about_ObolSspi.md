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
[Enter-ObolSspiEnvironment](./Enter-ObolSspiEnvironment.md) and [Exit-ObolSspiEnvironment](./Exit-ObolSspiEnvironment.md) register Obol KDC objects with the SSP and remove them again.
[Use-ObolSspiEnvironment](./Use-ObolSspiEnvironment.md) does the same around a scriptblock, starting a KDC first with `-Realm`.
They are the Windows Kerberos counterpart of `Enter-ObolKrb5Environment`, `Exit-ObolKrb5Environment` and `Use-ObolKrb5Environment`, which set the krb5 environment variables MIT krb5 and Heimdal read, including on Windows.
Both kinds can be entered at the same time.

On top of [Add-ObolSspiKdc](./Add-ObolSspiKdc.md) they:

+ Take the realm and address from the KDC, using the loopback address for a KDC listening on all addresses.
+ Require the KDC to listen on port 88, `Use-ObolSspiEnvironment` always starts its KDC on port 88 and has no `-Port`.
+ Allow one SSPI environment in the process at a time, exited automatically when the runspace that entered it closes.
+ Support the `-Scope` values `Thread`, `Machine`, `MitRealm` and `DcLocator`, which pick the Windows mechanism used to find the KDC, see [SSPI ENVIRONMENT SCOPES](#sspi-environment-scopes).
+ Remove what they added on exit, see each scope for what that covers.

Windows does not reserve ports below 1024, so binding port 88 needs no administrator rights.
The whole `127.0.0.0/8` range is loopback, so several KDCs can share port 88 on different loopback addresses (`127.0.0.2`, `127.0.0.3`, ...).
In testing a specific `127.0.0.2:88` could still be bound alongside a wildcard `0.0.0.0:88`, unless the wildcard socket had set `SO_EXCLUSIVEADDRUSE`.

# SSPI ENVIRONMENT SCOPES
The `-Scope` of `Enter-ObolSspiEnvironment` and `Use-ObolSspiEnvironment` decides which Windows mechanism points the SSP at the KDC.
That decides which authentication uses the KDC, what rights are needed, and how Windows talks to the KDC.

| | Thread | Machine | MitRealm | DcLocator |
| --- | --- | --- | --- | --- |
| Windows mechanism | [Per-thread pin](./about_ObolSspiKdcLookup.md#per-thread-pin) | [Binding cache](./about_ObolSspiKdcLookup.md#binding-cache) | [Static realm KDC list](./about_ObolSspiKdcLookup.md#static-realm-kdc-list) | [DC locator](./about_ObolSspiKdcLookup.md#dc-locator-and-dns) |
| Administrator rights | No | Yes | Yes | Yes |
| Authentication that uses the KDC | The current thread only | The whole machine | The whole machine | The whole machine |
| Jobs, runspaces, other processes, SMB, CredSSP | No | Yes | Yes | Yes |
| Windows treats the realm as | An AD domain | An AD domain | An MIT realm | An AD domain |
| First AS-REQ has pre-authentication data | Yes | Yes | No | Yes |
| Windows asks for a PAC (`PA-PAC-REQUEST`) | Yes | Yes | No | Yes |
| Transport to the KDC | TCP | TCP | TCP if every KDC of the realm listens on TCP, otherwise UDP | TCP |
| How long Windows uses the KDC | Until exited | About 10 minutes (`FarKdcTimeout`) | Until exited | Until exited |
| Realm name | Any | Any | Any | A DNS name such as `EXAMPLE.TEST` |
| Extra listeners | None | None | None | UDP ports 53 and 389 on each KDC address |
| KDCs sharing an address | Allowed | Allowed | Allowed | Not allowed, each KDC needs its own address |
| Removed on exit | Every pin in the process | The whole binding cache | Its registry keys and the whole binding cache | Its NRPT rules and listeners, and the whole binding cache |
| Left behind if the process is killed | Nothing, pins end with the process | The binding cache entry, until it ages out | Volatile registry keys, until reboot | A volatile NRPT rule, until reboot |

In short:

+ Use `Thread` to test code running in the current PowerShell session, it needs nothing but the KDC.
+ Use `Machine` for a short test that needs other processes or SMB to reach the KDC.
+ Use `MitRealm` to test how Windows talks to a non-Windows KDC, such as an MIT or Heimdal KDC.
+ Use `DcLocator` to test how Windows talks to an Active Directory domain controller, or for a long running machine wide setup.

## Thread
`Thread`, the default, pins the KDC for the current thread like `Add-ObolSspiKdc -Scope Thread`, see [Per-thread pin (no admin)](#per-thread-pin-no-admin).

Pros:

+ Needs no administrator rights.
+ Changes nothing outside the PowerShell process and leaves nothing behind if the process is killed.
+ Has no time limit.

Cons:

+ Only authentication done on the thread that entered the environment uses the KDC.
  A PowerShell console and a plain script run every command on the same thread, so the commands after `Enter-ObolSspiEnvironment` use it.
  A job, another runspace, `ForEach-Object -Parallel`, an async continuation or a child process does not.
  Neither does SMB or CredSSP, which Windows runs on its own threads.
+ Windows cannot remove a single pin, so exiting removes every pin in the process, including those of other threads and of `Add-ObolSspiKdc`.
  Entering fails if the thread already has a pin from `Add-ObolSspiKdc`, as exiting would remove it.

## Machine
`Machine` adds the KDC to the machine-wide binding cache like `Add-ObolSspiKdc -Scope Machine` and `klist.exe add_bind`, see [Binding cache (admin)](#binding-cache-admin).
Adding an entry for a realm replaces any entry already there for it.

Pros:

+ Every process on the machine uses the KDC, including SMB, CredSSP and services.
+ Changes no registry or DNS configuration and runs no extra listeners.

Cons:

+ Needs administrator rights.
+ Windows only uses an entry it did not find itself for `FarKdcTimeout` minutes, 10 by default, counted from when the environment was entered.
  After that it looks up the realm the usual way, which fails for a realm only Obol knows about.
  Raise `FarKdcTimeout` for a longer test, see [Expiry in about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md#expiry).
+ Windows cannot remove a single entry, so exiting purges the whole binding cache, including the entries Windows added itself for other realms.
  Windows finds those again the next time they are needed.

## MitRealm
`MitRealm` adds the realm and its KDCs to the registry like `ksetup.exe /addkdc` and `/addhosttorealmmap`, see [STATIC REALM KDC LIST in about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md#static-realm-kdc-list):

+ `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains\<REALM>` with `KdcNames` set to the KDC addresses, and `RealmFlags` set to `TcpSupported` (`0x2`) when every KDC of the realm listens on TCP.
+ `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\HostToRealm\<REALM>` with `SpnMappings` set to `.<realm>` and `<realm>`, so a service such as `HTTP/web.example.test` is in `EXAMPLE.TEST`, like the `[domain_realm]` section of a `krb5.conf`.

Pros:

+ Every process on the machine uses the KDC, with no time limit.
+ Runs no extra listeners and works with any realm name.
+ Windows talks to the KDC the way it talks to an MIT or Heimdal KDC, which is the path to test for non-Windows KDC interop.
+ The host to realm mapping means a service name under the realm's DNS name needs no realm in the SPN.

Cons:

+ Needs administrator rights.
+ The first AS-REQ has no pre-authentication data and Windows never asks for a PAC, unlike an Active Directory domain.
+ Windows uses UDP when any KDC of the realm does not listen on TCP, in testing an unreachable UDP port failed straight away rather than falling back to TCP.
+ Fails if the `Domains` or `HostToRealm` key of the realm already exists, see [Existing configuration](#existing-configuration).

## DcLocator
`DcLocator` makes the KDC look like an Active Directory domain controller to the Windows DC locator, see [DC LOCATOR AND DNS in about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md#dc-locator-and-dns):

+ A DNS server on UDP port 53 of each KDC address answers the `_kerberos` and `_ldap` SRV records of the realm, pointing at `kdc1.<realm>`, `kdc2.<realm>`, ... and those names at the KDC addresses.
+ An LDAP ping responder on UDP port 389 of each KDC address answers the ping Netlogon sends to check the domain controller.
+ An NRPT rule, like `Add-DnsClientNrptRule -Namespace <realm>, .<realm> -NameServers <KDC address>`, sends the DNS queries for the realm name to that DNS server.

`nltest.exe /dsgetdc:<REALM> /kdc` shows the domain controller Windows finds, and [Trace-ObolKdc](./Trace-ObolKdc.md) outputs the DNS queries and LDAP pings it sends.

Pros:

+ Every process on the machine uses the KDC, with no time limit.
+ Windows talks to the KDC exactly as it does to an Active Directory domain controller, through the same `DsGetDcName` lookup.

Cons:

+ Needs administrator rights.
+ The realm must be a DNS name with at least two labels, such as `EXAMPLE.TEST`.
+ Nothing else can use UDP port 53 or 389 on the KDC address, for example a DNS server on `127.0.0.1`.
  Start the KDC on another loopback address such as `127.0.0.2` if it does.
  NRPT rules only take an IP address and the LDAP ping always uses port 389, so the ports cannot change.
+ Each KDC needs its own address, as the DNS server and LDAP ping responder of a KDC listen on its address.
+ The KDC address must be IPv4, in testing Windows only looked up the IPv4 address of the KDC host.
+ Windows ignores every local NRPT rule while the Group Policy key `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig` exists, even an empty one, so entering fails if it does.
+ Fails if an NRPT rule for the realm already exists, see [Existing configuration](#existing-configuration).
+ Netlogon keeps its own cache of the domain controller it found, which exiting does not clear, see [CLEARING CACHED STATE](#clearing-cached-state).

## Existing configuration
`MitRealm` and `DcLocator` never change configuration that already exists.
A realm key or NRPT rule for the realm, including one left by a killed Obol process, makes them fail with the command to remove it.

The registry keys and NRPT rules they create are volatile, so Windows removes them on the next reboot if the process is killed before it removes them itself.

Both purge the binding cache when entered, as an entry for the realm from before would be used instead of the new configuration, and when exited, as Windows also writes the KDC it found through the DC locator to it.

# CLEARING CACHED STATE
Windows caches tickets and KDC lookups in several places, and a cached value is used before any new configuration is looked at.
A test that changes the KDC, its principals or the scope can then still see the old KDC, or a failure from an earlier run.
Exiting an SSPI environment removes the pins or binding cache entries it added, but not the tickets the KDC issued or the caches outside the SSP.

To start a test from scratch, clear what applies:

| What | Holds | Clear with | Administrator rights |
| --- | --- | --- | --- |
| Ticket cache of your logon session | The TGT and service tickets you received | `klist.exe purge` | No |
| Ticket cache of another logon session | Tickets of another user or a service, such as SYSTEM | `klist.exe -li <LogonId> purge`, find the ID with `klist.exe sessions` | Yes |
| Per-thread pins | The KDCs pinned in the PowerShell process | `Clear-ObolSspiKdc` | No |
| Binding cache | The KDC of each realm, including failed lookups | `Clear-ObolSspiKdc -Scope Machine` or `klist.exe purge_bind` | Yes |
| DNS client cache | DNS answers, including the records of a `DcLocator` realm | `ipconfig.exe /flushdns` or `Clear-DnsClientCache` | No |
| Netlogon domain controller cache | The domain controller the DC locator found for a realm | `nltest.exe /dsgetdc:<REALM> /force` | No |

For example, from an elevated session:

```powershell
$klist = "$env:SystemRoot\System32\klist.exe"

& $klist purge             # Tickets of this logon session
& $klist -li 0x3e7 purge   # Tickets of SYSTEM, used by services running as SYSTEM
Clear-ObolSspiKdc          # Pins in this process
Clear-ObolSspiKdc -Scope Machine
Clear-DnsClientCache
```

Some tools ship their own `klist.exe`, such as the JDK, and if it comes before `System32` in `PATH` then `klist purge` runs the wrong one.
Use the full path as above, or check which one runs with `(Get-Command klist -All).Source`.

The binding cache also keeps failed lookups, so a realm that failed once can keep failing straight away, with no network traffic, until the binding cache is purged.
Without administrator rights it cannot be purged, a pin with `-Scope Thread` is checked before it, or use a realm name that was never used on the host.

Configuration left behind by a killed `MitRealm` or `DcLocator` environment is removed by the next reboot, or by hand:

```powershell
# MitRealm
ksetup.exe /removerealm EXAMPLE.TEST
Remove-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\HostToRealm\EXAMPLE.TEST' -Recurse

# DcLocator
Get-DnsClientNrptRule |
    Where-Object Comment -like 'Obol DC locator for *' |
    Remove-DnsClientNrptRule -Force
```

A reboot clears every cache above and any leftover configuration, which is the last resort when something is still cached.

# ACCEPTING TICKETS WITH SSPI
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
