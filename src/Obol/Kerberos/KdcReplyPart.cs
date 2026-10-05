using System;

namespace Obol.Kerberos;

/// <summary>
/// The EncKDCRepPart of RFC 4120 5.4.2, the part of a reply only the client can see, with the session key.
/// </summary>
public sealed class KdcReplyPart
{
    internal KdcReplyPart() { }

    /// <summary>The session key of the ticket.</summary>
    public EncryptionKey Key { get; internal init; } = null!;

    /// <summary>The last-req, times the KDC reports such as the last password change, usually one empty entry.
    /// </summary>
    public LastRequest[] LastRequest { get; internal init; } = [];

    /// <summary>The nonce of the request.</summary>
    public int Nonce { get; internal init; }

    /// <summary>The local time the client's key expires, if the KDC says.</summary>
    public DateTime? KeyExpiration { get; internal init; }

    /// <summary>The flags of the ticket.</summary>
    public TicketFlag Flag { get; internal init; }

    /// <summary>The local time of the initial authentication the ticket descends from.</summary>
    public DateTime AuthTime { get; internal init; }

    /// <summary>The local time the ticket is valid from, if set.</summary>
    public DateTime? StartTime { get; internal init; }

    /// <summary>The local time the ticket expires.</summary>
    public DateTime EndTime { get; internal init; }

    /// <summary>The local time the ticket can be renewed until, if it is renewable.</summary>
    public DateTime? RenewTill { get; internal init; }

    /// <summary>The sname and srealm, the service the ticket is for.</summary>
    public PrincipalName ServiceName { get; internal init; } = null!;

    /// <summary>The caddr, the addresses the ticket is valid from, usually none.</summary>
    public HostAddress[] Address { get; internal init; } = [];

    /// <summary>
    /// The encrypted-pa-data, such as PA-SUPPORTED-ENCTYPES with the encryption types the service supports.
    /// </summary>
    public PreAuthData[] EncryptedPreAuthData { get; internal init; } = [];

    public override string ToString() => $"{ServiceName} {Flag}, expires {EndTime}";
}
