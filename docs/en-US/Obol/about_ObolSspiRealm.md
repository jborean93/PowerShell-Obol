# ObolSspiRealm
## about_ObolSspiRealm

# SHORT DESCRIPTION
How the Windows Kerberos SSP decides which realm to look up a KDC for.

# LONG DESCRIPTION
Before the Windows Kerberos Security Support Provider (SSP) can contact a KDC it has to know the realm a request is for.
This topic covers how that realm is chosen from what the caller passes to SSPI, the first step of every KDC lookup.
How the SSP then finds the KDC for that realm is covered in [about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md).

Most of the documentation online on this topic covers domain joined hosts, there is very little on how it behaves on a host that is not domain joined.
While the information here should be correct, this is a complex topic and some of it might be misleading, incorrect or out of date.

# DOMAIN MEMBERSHIP
The logic is the same whether or not the machine is domain joined, domain membership only changes the defaults and does not restrict which realm can be used.

On a domain joined host the machine's own domain is:

+ the realm used for default credentials and for a bare user name
+ the fallback realm for a host-based SPN with no explicit realm or mapping

None of that stops a domain joined host from using another realm, as long as the SSP can locate that realm's KDC through a trust referral or one of the mechanisms in [about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md).

Off-domain there is no machine domain to fall back to, so the realm must come from the credential, the target name, or a host to realm mapping.

# INITIATOR
The initiator (client) is the side of the exchange that starts the authentication, for example a call to `InitializeSecurityContext`.
It can deal with two realms, each driving its own KDC lookup, so a single authentication can run the lookup more than once:

    client realm  (from the credential)  ->  AS-REQ : get the user's TGT
    target realm  (from the target SPN)  ->  TGS-REQ: get the service ticket

The client realm is who you authenticate *as*, the target realm is where the *service* lives.

## Client realm
The client realm comes entirely from the credential the caller passes to `AcquireCredentialsHandle` in `pAuthData`, which `InitializeSecurityContext` then uses.

    default credentials (pAuthData = NULL)
        the identity of the caller's logon session; for a logged on domain user
        this is the user's TGT and realm. A local account logon has no TGT and
        no realm, but a stored credential for the target can still supply one
        (see Stored credentials below).

    explicit credentials (pAuthData = SEC_WINNT_AUTH_IDENTITY[_EX/_EX2])
        the Domain field, if set             (e.g. "OBOL.TEST", or NetBIOS "OBOL")
        otherwise a UPN in the User field    (user@OBOL.TEST -> realm OBOL.TEST)

The SSP splits the user name from the realm based on the form of the User and Domain values:

    user@REALM.COM    UPN form; realm = text after the last '@'
    DOMAIN\user       down-level form; the realm is DOMAIN, a NetBIOS name
    user  (+ Domain)  the Domain passed alongside the user is the realm
    user  (no domain) no realm supplied; falls back to the logon session realm
                      (which is nothing usable on a host that is not domain joined)

A down-level `DOMAIN\user`, or a NetBIOS `Domain` on its own, gives a NetBIOS name, which is not a Kerberos realm and has to be canonicalised to one later.
The process of NetBIOS canonicalisation is not covered here and it is recommended to always use the UPN form which provides the realm directly.

## Stored credentials
Default credentials are not only the logon session's logon credentials.
With default credentials, the Negotiate and Kerberos providers also look in the user's Windows Credential Manager for a stored credential whose target matches the server, and use it.
This is how an off-domain or local account process gets a Kerberos identity without passing credentials in code.

The relevant credentials are "Windows" (domain password) credentials, `CRED_TYPE_DOMAIN_PASSWORD`, written with `CredWriteW` or, more easily, with `cmdkey`:

    cmdkey /add:host.obol.test /user:user@OBOL.TEST /pass:...
        stored under a target name (a server, or a wildcard such as
        "*.obol.test"); SSPI picks the best target match for the service

The stored user name is parsed for its realm exactly like an explicit credential.
Storing the user as `user@OBOL.TEST` means a default credentials client, such as `HttpClient` with `UseDefaultCredentials` or an SMB path, authenticates to that target as that user in `OBOL.TEST`.

## Target realm
Once the client has its TGT from the AS-REQ, the SSP determines the realm of the service for the TGS-REQ.
The target name passed to `InitializeSecurityContext`, the SPN, is parsed like the client name and the realm is taken from the first rule that matches:

    svc/host@REALM         ->  the explicit realm after '@'
                               (e.g. HTTP/host.obol.test@OBOL.TEST)
    svc/host  (no @REALM)  ->  the host is matched against the host to realm
                               mappings (longest DNS suffix match); a hit gives
                               that realm
    neither matches        ->  the machine's own domain, then the KDC's referral
                               points at the service's real realm

Off-domain a bare host SPN is the hard case.
There is no machine domain to fall back to and no trust to refer through, so the realm must be supplied explicitly, either as the `@REALM` suffix on the SPN or with a host to realm mapping.

## Host to realm mappings
The host to realm mappings are the Windows equivalent of the MIT `krb5.conf` `[domain_realm]` section.
They map a host name, or a DNS suffix starting with `.`, to a realm and are set in the registry or through Group Policy.

The registry form is written by `ksetup.exe /AddHostToRealmMap <host or .suffix> <REALM>` and removed with `/DelHostToRealmMap`:

    HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\HostToRealm\
        <REALM>\                      one subkey per realm, e.g. OBOL.TEST
            SpnMappings  REG_MULTI_SZ   the host names and DNS suffixes in the realm,
                                        e.g. .obol.test
                                             host.obol.test

The Group Policy form is the "Define host name-to-Kerberos realm mappings" policy:

    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\domain_realm
        <REALM>   REG_SZ   one value per realm; the value name is the realm and the
                           data is the host names and DNS suffixes separated by ';',
                           e.g. OBOL.TEST = .obol.test; host.obol.test

The two sources are not merged, the SSP uses one or the other.
If the `domain_realm` policy key exists it is used and the registry `HostToRealm` key is ignored; the registry mappings are read only when the `domain_realm` policy key is absent.

A mapping only says which realm a host is in, not where that realm's KDC is.
For a custom realm such as an Obol one you usually need both: a mapping so `host.obol.test` is recognised as realm `OBOL.TEST`, and one of the mechanisms in [about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md) so the SSP can find the KDC for `OBOL.TEST`.

# ACCEPTOR
The acceptor (server) does not resolve a realm or contact a KDC.
It calls `AcquireCredentialsHandle` for its own principal, holding that principal's long-term key (the machine account key when domain joined, or a keytab or password off-domain), then `AcceptSecurityContext` with the client's AP-REQ, which carries the service ticket.
The SSP decrypts the ticket with the credential's key and builds the access token.
The realm and server principal are whatever the client resolved and the issuing KDC put in the ticket, the acceptor only needs a key that matches the server name in it.

The exception is an acceptor that then acts as an initiator, for user-to-user (it needs its own TGT) or S4U and constrained delegation.
Those do start a lookup, using the realm from the ticket's client or target name, and the initiator rules above apply.

# SEE ALSO
+ [about_ObolSspi](./about_ObolSspi.md)
+ [about_ObolSspiKdcLookup](./about_ObolSspiKdcLookup.md)
