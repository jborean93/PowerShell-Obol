namespace Obol;

/// <summary>The DNS resource record types (RRTYPE) seen in the DC locator DNS queries, RFC 1035 3.2.2.</summary>
/// <remarks>Other types are shown as their number.</remarks>
public enum ObolDnsRecordType : ushort
{
    /// <summary>An IPv4 host address.</summary>
    A = 1,

    /// <summary>An authoritative name server.</summary>
    Ns = 2,

    /// <summary>The canonical name of an alias.</summary>
    Cname = 5,

    /// <summary>The start of a zone of authority.</summary>
    Soa = 6,

    /// <summary>A domain name pointer, used for reverse lookups.</summary>
    Ptr = 12,

    /// <summary>A mail exchange.</summary>
    Mx = 15,

    /// <summary>Text strings.</summary>
    Txt = 16,

    /// <summary>An IPv6 host address, RFC 3596.</summary>
    Aaaa = 28,

    /// <summary>The location of a service, RFC 2782.</summary>
    Srv = 33,

    /// <summary>The EDNS pseudo record, RFC 6891.</summary>
    Opt = 41,

    /// <summary>A query for every record of the name.</summary>
    Any = 255,
}
