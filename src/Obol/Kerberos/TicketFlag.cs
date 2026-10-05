using System;

namespace Obol.Kerberos;

/// <summary>The flags of a ticket, RFC 4120 5.3.</summary>
/// <remarks>
/// The values are the bits of the TicketFlags bit string read as a 32-bit big endian number, so bit 0 of the RFC is
/// the highest bit. They are the values Windows and MIT show.
/// </remarks>
[Flags]
public enum TicketFlag : uint
{
    None = 0,

    /// <summary>anonymous (16), the ticket is for an anonymous principal, RFC 8062.</summary>
    Anonymous = 0x00008000,

    /// <summary>enc-pa-rep (15), the reply held a PA-REQ-ENC-PA-REP checksum, RFC 6806.</summary>
    EncryptedPaRep = 0x00010000,

    /// <summary>ok-as-delegate (13), the service is trusted to accept delegated credentials.</summary>
    OkAsDelegate = 0x00040000,

    /// <summary>transited-policy-checked (12), the KDC checked the transited realms.</summary>
    TransitedPolicyChecked = 0x00080000,

    /// <summary>hw-authent (11), the client authenticated with hardware.</summary>
    HardwareAuthenticated = 0x00100000,

    /// <summary>pre-authent (10), the client pre-authenticated before the ticket was issued.</summary>
    PreAuthenticated = 0x00200000,

    /// <summary>initial (9), the ticket was issued by the AS exchange, not from a TGT.</summary>
    Initial = 0x00400000,

    /// <summary>renewable (8), the ticket can be renewed until its renew-till time.</summary>
    Renewable = 0x00800000,

    /// <summary>invalid (7), the ticket must be validated by the KDC before use.</summary>
    Invalid = 0x01000000,

    /// <summary>postdated (6), the ticket was postdated.</summary>
    Postdated = 0x02000000,

    /// <summary>may-postdate (5), postdated tickets can be issued from the ticket.</summary>
    MayPostdate = 0x04000000,

    /// <summary>proxy (4), the ticket is a proxy.</summary>
    Proxy = 0x08000000,

    /// <summary>proxiable (3), proxy tickets can be issued from the ticket.</summary>
    Proxiable = 0x10000000,

    /// <summary>forwarded (2), the ticket was forwarded or issued from a forwarded TGT.</summary>
    Forwarded = 0x20000000,

    /// <summary>forwardable (1), the ticket can be forwarded.</summary>
    Forwardable = 0x40000000,

    /// <summary>reserved (0).</summary>
    Reserved = 0x80000000,
}
