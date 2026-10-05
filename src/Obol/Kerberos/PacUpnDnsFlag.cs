using System;

namespace Obol.Kerberos;

/// <summary>The flags of the UPN_DNS_INFO buffer of the PAC, MS-PAC 2.10.</summary>
[Flags]
public enum PacUpnDnsFlag
{
    None = 0,

    /// <summary>U, the user has no UPN, the Upn is constructed from the SAM name.</summary>
    NoUpn = 0x00000001,

    /// <summary>S, the buffer also holds the SAM name and SID of the user.</summary>
    Extended = 0x00000002,
}
