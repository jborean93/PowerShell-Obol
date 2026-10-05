using System;

namespace Obol.Kerberos;

/// <summary>
/// The EncTicketPart of RFC 4120 5.3, the contents of a ticket only the service and the KDC can see.
/// </summary>
public sealed class TicketPart
{
    internal TicketPart() { }

    /// <summary>The flags of the ticket.</summary>
    public TicketFlag Flag { get; internal init; }

    /// <summary>The session key shared by the client and the service.</summary>
    public EncryptionKey Key { get; internal init; } = null!;

    /// <summary>The cname and crealm, the client the ticket was issued to.</summary>
    public PrincipalName ClientName { get; internal init; } = null!;

    /// <summary>The tr-type of the transited encoding, 1 for DOMAIN-X500-COMPRESS.</summary>
    public int TransitedType { get; internal init; }

    /// <summary>The realms the authentication passed through, empty within one realm.</summary>
    public byte[] Transited { get; internal init; } = [];

    /// <summary>The local time of the initial authentication the ticket descends from.</summary>
    public DateTime AuthTime { get; internal init; }

    /// <summary>The local time the ticket is valid from, if set, otherwise <see cref="AuthTime"/>.</summary>
    public DateTime? StartTime { get; internal init; }

    /// <summary>The local time the ticket expires.</summary>
    public DateTime EndTime { get; internal init; }

    /// <summary>The local time the ticket can be renewed until, if it is renewable.</summary>
    public DateTime? RenewTill { get; internal init; }

    /// <summary>The caddr, the addresses the ticket is valid from, usually none.</summary>
    public HostAddress[] Address { get; internal init; } = [];

    /// <summary>The authorization-data, the PAC is in an AD-IF-RELEVANT element.</summary>
    public AuthorizationData[] AuthorizationData { get; internal init; } = [];

    /// <summary>The PAC found in the authorization data, null if the ticket has none.</summary>
    public Pac? Pac { get; internal init; }

    public override string ToString() => $"{ClientName} {Flag}, expires {EndTime}";
}
