# ObolSspiKdcLookup
## about_ObolSspiKdcLookup

# SHORT DESCRIPTION
How the Windows Kerberos SSP finds the KDC for a realm.

# LONG DESCRIPTION
Once the Windows Kerberos Security Support Provider (SSP) has chosen a realm, see [about_ObolSspiRealm](./about_ObolSspiRealm.md), it needs a KDC for that realm.
Windows has several ways to find one, and several of them can point it at a KDC outside of the normal domain join configuration, such as an Obol KDC.

Most of the documentation online on this topic covers domain joined hosts, there is very little on how it behaves on a host that is not domain joined.
While the information here should be correct, this is a complex topic and some of it might be misleading, incorrect or out of date.

# WHEN A KDC IS CONTACTED
The SSP only looks up and contacts a KDC when it does not already have a valid ticket for what it needs, a TGT for the client realm or a service ticket for the target.
While a valid ticket is cached in the logon session it is used as is, so none of the mechanisms below, or a change to them, has any effect on it.
For example the TGT of your own logon was obtained before a pin was set, so the pin does not change it, only later KDC calls.

To start from scratch, clear the tickets with `klist.exe purge` and authenticate again.
It purges the tickets of your own logon session and needs no administrator rights.
It only removes tickets, not the [binding cache](#binding-cache) entries, which `klist.exe purge_bind` removes.

# LOOKUP ORDER
When the SSP has to contact a KDC, it picks the KDC for the realm like this, the first match wins:

    1. per-thread pin (KerbPinKdc)              -- hit   --> use it
         | miss
    2. binding cache                            -- hit   --> use it
         | miss
    3. our own domain / local KDC               -- yes   --> use it   (*)
         | no
    4. static realm KDC list                    -- hit   --> use it   (*)
         |   (ksetup KdcNames, or GPO MITRealms <K> hosts)
         | miss
    5. DC locator (AD): _kerberos._tcp.dc._msdcs SRV -- found --> use it (*)
         | none
    fail (no KDC found)

    (*) a KDC found by the DC locator (step 5) is written to the binding cache
        (step 2) and reused until the entry ages out, so later requests stop
        at step 2. A KDC used from the static realm list (step 4) was not
        written to it in testing.

A brief explanation of the mechanism above are:

| Mechanism | Configured with | Scope | Lifetime | Admin |
| --- | --- | --- | --- | --- |
| [Per-thread pin](#per-thread-pin) | `Add-ObolSspiKdc -Scope Thread` | Thread | Until removed or the thread/process exits | No |
| [Binding cache](#binding-cache) | `Add-ObolSspiKdc -Scope Machine`, `klist.exe add_bind` | Machine | Until it ages out or reboot | Yes |
| [ksetup](#ksetup) | `ksetup.exe /addkdc <REALM> <host>`, `Enter-ObolSspiEnvironment -Scope MitRealm` | Machine | Persistent, until reboot for Obol | Yes |
| [MITRealms](#mitrealms-policy) | Group Policy `...\Kerberos\MITRealms` | Machine | Persistent | Yes |
| [DC locator](#dc-locator-and-dns) | DNS SRV records published by an AD DC, `Enter-ObolSspiEnvironment -Scope DcLocator` | Per realm, via DNS | Cached in the binding cache | No on the client, needs DNS and LDAP service. Yes for the NRPT rule Obol uses |
| [KDC proxy](#kdc-proxy-kkdcp) | Group Policy `...\Kerberos\KdcProxy\ProxyServers` | Machine | Persistent | Yes |

Obol manages the per-thread pin and the binding cache, and the SSPI environment cmdlets can also add a realm to the static realm KDC list or answer the DC locator for it, see [about_ObolSspi](./about_ObolSspi.md).
The `MITRealms` policy and the KDC proxy are standard Windows configuration and outside the scope of the module.

# PER-THREAD PIN
The pin is set with the undocumented `KerbPinKdc` message, sent to the Kerberos package with `LsaCallAuthenticationPackage` over an untrusted LSA connection, so it needs no administrator rights.
The SSP scopes the pin to the thread that sent the message.
It is not seen by other processes or other threads in the same process, and it is not inherited by new threads or child processes.

It is checked first, ahead of the binding cache and every other source, whenever the thread contacts a KDC.
The realm and KDC host are stored verbatim: there is no DNS or DC locator lookup and no DC flags are attached, unlike an entry the SSP resolves itself.

The pin lives only in LSASS memory and has no time-based expiry, the lookup never checks its age and there is no pin timeout setting.
It stops applying when the thread or process ends, or when the `KerbUnpinAllKdcs` message removes every pin in the calling process.
There is no message to list the pins and no way to remove the pin for a single realm.

# BINDING CACHE
The binding cache is a single machine-wide table in LSASS, shared by every process and logon session.
Unlike a pin it also applies to authentication brokered by the kernel, such as SMB.
It is read and changed with the `KerbAddBindingCacheEntry`, `KerbQueryBindingCache` and `KerbPurgeBindingCache` messages, which `klist.exe add_bind`, `query_bind` and `purge_bind` wrap.
All three need administrator rights, even the query.
`purge_bind` flushes the entire cache, there is no per-realm or per-server purge.

The SSP also fills the cache itself: every KDC it finds through steps 3-5 is written here with the realm, the KDC and the DC flags.

## Expiry
An entry in the binding cache ages out after a timeout.
The timeout it uses depends on whether the entry is a *near* or *far* KDC.

+ `NearKdcTimeout` when the KDC is in the client's own AD site (a "near" DC).
+ `FarKdcTimeout` when it is in another site (a "far" DC), or the entry has no site information, such as one added by hand rather than by the DC locator.

The far timeout is shorter so the client checks for a closer DC sooner.
Both the timeout here are configured in the registry as `REG_DWORD` values in minutes.

    HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters
        NearKdcTimeout  REG_DWORD  minutes a near KDC entry is reused  (default 30)
        FarKdcTimeout   REG_DWORD  minutes a far KDC entry is reused   (default 10)
    (Group Policy writes the same values under
     HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters)

A stale entry is skipped and the realm resolved again through the workflow above.
It is not removed, so `query_bind` can still list an entry that is no longer used.
When a call to a KDC fails, the retry bypasses the cache and resolves the realm again, so a stale entry cannot keep the SSP on a dead KDC.

The entry only records when it was cached, the `GetTickCount64` value shown as `DiscoveryTime` by `Get-ObolSspiKdc -Scope Machine`, and the SSP reads the current `NearKdcTimeout` / `FarKdcTimeout` at lookup time and compares it against that timestamp.
So a changed timeout also applies to entries already in the cache, the next lookup judges them against the new value (for example lowering `FarKdcTimeout` can make an already-cached far entry count as stale on the next request).

The SSP watches the `Parameters` key, so a change applies straight away once the change notification is processed, with no reboot or LSASS restart.

# STATIC REALM KDC LIST
The `ksetup` registry keys and the `MITRealms` policy both declare a realm to the SSP and register it as an MIT realm, putting the host into a compatible MIT mode for that realm.
Each entry records the realm and, optionally, the KDCs that serve it, and is checked at step 4.
They only write the registry and do not add a binding cache entry.
In testing the SSP did not add one when it used a KDC from `KdcNames` either, unlike a KDC found by the DC locator.
The SSP watches these keys, so a change takes effect without a reboot.

Whether the KDC hosts are listed is what decides how the KDC is found for that realm:

+ with KDC hosts (`ksetup` `KdcNames`, or a `MITRealms` `<K>` list): those hosts are used directly, with no DNS lookup.
+ without KDC hosts (just the realm subkey or policy value): the SSP resolves the realm through its own DNS SRV lookup of the RFC 4120 records.

The RFC 4120 record use the SRV lookup of `_kerberos._tcp.<realm>` / `_udp` (and `_kpasswd._tcp/_udp.<realm>`).
This is a separate path from the AD DC locator step 5, see [DC LOCATOR AND DNS](#dc-locator-and-dns).
It is the Kerberos SSP querying the bare `_kerberos` SRV records itself, **not** Netlogon's `DsGetDcName` with the `_kerberos._tcp.dc._msdcs.<domain>` record and CLDAP ping check.

The static list only says which realm exists and optionally which KDC serves it.
Which realm a target host specified by the SPN is in is decided separately by the host to realm mappings, see [about_ObolSspiRealm](./about_ObolSspiRealm.md).

## ksetup
`ksetup.exe /AddKdc <REALM> <host>` writes the realm subkey at `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains\<REALM>` and the value `KdcNames` is `<host>` was specified.
The `KdcNames` hosts are used directly, with no DNS SRV lookup being done.
`RealmFlags`, set with `ksetup /SetRealmFlags`, tunes per-realm behaviour such as TCP support and delegation.

    HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains\
        <REALM>\                      required: one subkey per realm, e.g. OBOL.TEST
            KdcNames      REG_MULTI_SZ  optional: explicit KDC hosts, tried in order
            KpasswdNames  REG_MULTI_SZ  optional: explicit kpasswd (password change) hosts
            RealmFlags    REG_DWORD     optional (default 0): per-realm flags
                0x1 SendAddress   0x2 TcpSupported
                0x4 Delegate      0x8 NcSupported

Only the `<REALM>` subkey is required, each value under it falls back to something when absent:

    KdcNames absent      ->  no static KDC, the realm is resolved with a bare DNS
                             SRV lookup (_kerberos._tcp.<realm> / _udp), the same as
                             a MITRealms entry with no <K>. `ksetup /addkdc <REALM>`
                             with no host leaves KdcNames unset for this.
    KpasswdNames absent  ->  password changes fall back to _kpasswd._tcp/_udp.<realm>
                             (or the KDC)
    RealmFlags absent    ->  treated as 0 (no per-realm flags)

## MITRealms policy
The Group Policy `MITRealms` key is the policy form of the same list.
Each value name is a realm and the data is a string of tags:

    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\MITRealms
        <REALM>   one REG_SZ value per realm; the value name is the realm and
                  the data is a string of tags:
            <K>host1; host2</K>   explicit KDC hosts; omit to use a bare
                                  _kerberos._tcp.<realm> SRV lookup instead
            <F>hexflags</F>       realm flags, the same bits as RealmFlags above

With a `<K>` list it behaves like `ksetup`: fixed hosts and no DNS.
Without a `<K>` list the SSP queries the RFC 4120 SRV records itself, `_kerberos._tcp.<realm>` and `_kerberos._udp.<realm>` (and `_kpasswd._tcp/_udp.<realm>`).
This bare SRV lookup is the only way DNS can find a KDC that is not an AD DC, such as Obol.
The realm still has to be declared in `MITRealms` (or `ksetup` with no host) first, so it needs an administrator, publishing the DNS record is not enough.

# DC LOCATOR AND DNS
At step 5 it passes the realm to Netlogon's `DsGetDcName` / `DsrGetDcNameEx2` and uses the DC that comes back.
Netlogon looks up the `_kerberos._tcp.dc._msdcs.<realm>` SRV record (and the site-scoped `_sites.dc._msdcs` form), then sends a CLDAP (connectionless LDAP) ping to the candidate DC to check it is alive and read its capabilities.
The KDC found is written to the binding cache with its DC flags.

As it requires a DNS SRV record and LDAP to respond to the CLDAP ping, it typically is only available for Active Directory based KDCs.
An Obol KDC on its own does not publish the `dc._msdcs` records or answer the CLDAP ping, so the DC locator never finds it.

`Enter-ObolSspiEnvironment -Scope DcLocator` fills in both:

+ An NRPT (Name Resolution Policy Table) rule, the same as `Add-DnsClientNrptRule -Namespace <realm>, .<realm> -NameServers <KDC address>`, sends every DNS query for the realm name to a DNS server Obol runs on UDP port 53 of each KDC address. NRPT rules only take the IP address of the server, the port is always 53.
+ The DNS server answers the `_kerberos` and `_ldap` SRV records under the realm with `kdc1.<realm>`, `kdc2.<realm>` and so on, one per KDC, and those names with the KDC addresses. The port in an SRV record is ignored, the KDC is always on 88.
+ A CLDAP responder on UDP port 389 of each KDC address answers the ping with a `NETLOGON_SAM_LOGON_RESPONSE_EX` describing a writable domain controller that is a KDC, with a random domain GUID and the site `Default-First-Site-Name`. The ping always goes to port 389.

The realm is then treated as an Active Directory domain: the first AS-REQ already asks for a PAC with `PA-PAC-REQUEST` and the KDC is contacted over TCP.
`nltest.exe /dsgetdc:<realm>` shows the domain controller found.

# KDC PROXY (KKDCP)
The Group Policy `ProxyServers` key sends the KDC traffic for a realm through an HTTPS proxy instead of to a KDC directly.
The value holds the proxy's own host and port and the proxy relays the messages to the KDC.

    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\KdcProxy\ProxyServers
        <REALM>  =  <proxy host[:port]>    the KKDCP (HTTPS) proxy for that realm

There is also an undocumented per-credential form set with SSPI `SetCredentialsAttributes` and `SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS`.
Obol does not use it and it is not covered here.

# PORTS
Every direct mechanism (pin, binding cache, `KdcNames`, `MITRealms` and the DC locator) reaches the KDC on port 88, and port 464 for password changes.
The port is a constant inside the SSP and is not read from the address.
A KDC address is a bare host or IP, so a value with a port such as `host:1088` or `[::1]:88` does not resolve.

The KDC proxy is the only mechanism that uses another port, and that is the port of the proxy, not the KDC.

# SEE ALSO
+ [about_ObolSspi](./about_ObolSspi.md)
+ [about_ObolSspiRealm](./about_ObolSspiRealm.md)
+ [Add-ObolSspiKdc](./Add-ObolSspiKdc.md)
