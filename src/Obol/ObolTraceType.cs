using System;

namespace Obol;

/// <summary>The kinds of requests <c>Trace-ObolKdc</c> outputs.</summary>
[Flags]
public enum ObolTraceType
{
    /// <summary>The Kerberos requests the KDC answers, as <see cref="ObolKdcEvent"/>.</summary>
    Kdc = 1,

    /// <summary>
    /// The DNS queries the DC locator DNS server of a <c>DcLocator</c> SSPI environment answers, as
    /// <see cref="ObolDnsEvent"/>.
    /// </summary>
    Dns = 2,

    /// <summary>
    /// The LDAP pings the DC locator of a <c>DcLocator</c> SSPI environment sends, as <see cref="ObolLdapEvent"/>.
    /// </summary>
    Ldap = 4,

    /// <summary>Every kind of request.</summary>
    All = Kdc | Dns | Ldap,
}
