using System;

namespace Obol.Kerberos;

/// <summary>An Authenticator of RFC 4120 5.5.1, the client's proof it holds the session key of the ticket.</summary>
public sealed class Authenticator
{
    internal Authenticator() { }

    /// <summary>The authenticator-vno, always 5.</summary>
    public int Version { get; internal init; }

    /// <summary>The cname and crealm, must match the client of the ticket.</summary>
    public PrincipalName ClientName { get; internal init; } = null!;

    /// <summary>The cksum, in a TGS-REQ the checksum of the request body, if sent.</summary>
    public Checksum? Checksum { get; internal init; }

    /// <summary>The ctime and cusec, the local time on the client.</summary>
    public DateTime Time { get; internal init; }

    /// <summary>The subkey the client chose for the reply or the session, if sent.</summary>
    public EncryptionKey? Subkey { get; internal init; }

    /// <summary>The seq-number, if sent.</summary>
    public int? SequenceNumber { get; internal init; }

    /// <summary>The authorization-data, such as KERB-AUTH-DATA-TOKEN-RESTRICTIONS from Windows.</summary>
    public AuthorizationData[] AuthorizationData { get; internal init; } = [];

    public override string ToString() => $"{ClientName} at {Time}";
}
