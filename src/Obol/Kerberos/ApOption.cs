using System;

namespace Obol.Kerberos;

/// <summary>
/// The ap-options of an AP-REQ, RFC 4120 5.5.1, in the same bit layout as <see cref="TicketFlag"/>.
/// </summary>
[Flags]
public enum ApOption : uint
{
    None = 0,

    /// <summary>mutual-required (2), the client wants the service to authenticate back with an AP-REP.</summary>
    MutualRequired = 0x20000000,

    /// <summary>use-session-key (1), the ticket is encrypted with the session key of the service's TGT, user to
    /// user authentication.</summary>
    UseSessionKey = 0x40000000,

    /// <summary>reserved (0).</summary>
    Reserved = 0x80000000,
}
