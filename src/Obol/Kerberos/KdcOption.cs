using System;

namespace Obol.Kerberos;

/// <summary>The options a client asked for in a request, the kdc-options of RFC 4120 5.4.1.</summary>
/// <remarks>
/// The values are the bits of the KDCOptions bit string read as a 32-bit big endian number, so bit 0 of the RFC is
/// the highest bit, the same layout as <see cref="TicketFlag"/>. An option bit without a name is shown as its
/// number.
/// </remarks>
[Flags]
public enum KdcOption : uint
{
    None = 0,

    /// <summary>validate (31), validate a postdated ticket.</summary>
    Validate = 0x00000001,

    /// <summary>renew (30), renew the ticket of the request.</summary>
    Renew = 0x00000002,

    /// <summary>enc-tkt-in-skey (28), encrypt the ticket with the session key of the additional ticket, user to
    /// user authentication.</summary>
    EncTktInSkey = 0x00000008,

    /// <summary>renewable-ok (27), a renewable ticket is acceptable if the requested lifetime cannot be given.
    /// </summary>
    RenewableOk = 0x00000010,

    /// <summary>disable-transited-check (26), do not check the transited realms.</summary>
    DisableTransitedCheck = 0x00000020,

    /// <summary>request-anonymous (16), request an anonymous ticket, RFC 8062.</summary>
    RequestAnonymous = 0x00008000,

    /// <summary>canonicalize (15), the KDC may reply with the canonical name of the principal, RFC 6806.</summary>
    Canonicalize = 0x00010000,

    /// <summary>cname-in-addl-tkt (14), the client name is in the additional ticket, constrained delegation
    /// (S4U2proxy), MS-SFU.</summary>
    CNameInAdditionalTicket = 0x00020000,

    /// <summary>opt-hardware-auth (11), hardware authentication is available.</summary>
    OptHardwareAuth = 0x00100000,

    /// <summary>renewable (8), request a renewable ticket.</summary>
    Renewable = 0x00800000,

    /// <summary>postdated (6), request a postdated ticket.</summary>
    Postdated = 0x02000000,

    /// <summary>allow-postdate (5), postdated tickets may be issued from the ticket.</summary>
    AllowPostdate = 0x04000000,

    /// <summary>proxy (4), request a proxy ticket.</summary>
    Proxy = 0x08000000,

    /// <summary>proxiable (3), request a proxiable ticket.</summary>
    Proxiable = 0x10000000,

    /// <summary>forwarded (2), request a forwarded ticket with the TGT of the request.</summary>
    Forwarded = 0x20000000,

    /// <summary>forwardable (1), request a forwardable ticket.</summary>
    Forwardable = 0x40000000,

    /// <summary>reserved (0).</summary>
    Reserved = 0x80000000,
}
