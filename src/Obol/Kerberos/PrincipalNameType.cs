namespace Obol.Kerberos;

/// <summary>
/// The name type of a principal name, the values are the IANA assigned numbers. A type without a name here, such
/// as one read from a keytab, is kept as its number.
/// </summary>
public enum PrincipalNameType
{
    /// <summary>NT-UNKNOWN, the type is not known.</summary>
    Unknown = 0,

    /// <summary>NT-PRINCIPAL, a user or service name, the type keytab tools write.</summary>
    Principal = 1,

    /// <summary>NT-SRV-INST, a service and other names, such as krbtgt.</summary>
    ServiceInstance = 2,

    /// <summary>NT-SRV-HST, a service with a host name as the instance.</summary>
    ServiceHost = 3,

    /// <summary>NT-SRV-XHST, a service with a host name and other components.</summary>
    ServiceExtendedHost = 4,

    /// <summary>NT-UID, a unique ID.</summary>
    Uid = 5,

    /// <summary>NT-X500-PRINCIPAL, an encoded X.509 distinguished name.</summary>
    X500Principal = 6,

    /// <summary>NT-SMTP-NAME, an email address.</summary>
    SmtpName = 7,

    /// <summary>NT-ENTERPRISE, an enterprise name such as a user principal name, RFC 6806.</summary>
    Enterprise = 10,

    /// <summary>NT-WELLKNOWN, a well known name such as WELLKNOWN/ANONYMOUS, RFC 6111.</summary>
    WellKnown = 11,

    /// <summary>NT-SRV-HST-DOMAIN, a host based service with a domain name, RFC 6806.</summary>
    ServiceHostDomain = 12,

    /// <summary>NT-MS-PRINCIPAL, a Windows NT4 style DOMAIN\user name (MS-KILE).</summary>
    MsPrincipal = -128,

    /// <summary>NT-MS-PRINCIPAL-AND-ID, a name with a SID (MS-KILE).</summary>
    MsPrincipalAndId = -129,

    /// <summary>NT-ENT-PRINCIPAL-AND-ID, an enterprise name with a SID (MS-KILE).</summary>
    EnterprisePrincipalAndId = -130,
}
