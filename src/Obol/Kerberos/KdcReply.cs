namespace Obol.Kerberos;

/// <summary>An AS-REP or TGS-REP, the KDC-REP of RFC 4120 5.4.2, a ticket for the client.</summary>
public sealed class KdcReply : Message
{
    internal KdcReply(MessageType messageType, byte[] bytes) : base(messageType, bytes) { }

    /// <summary>The pvno, always 5.</summary>
    public int ProtocolVersion { get; internal init; }

    /// <summary>The padata, such as PA-ETYPE-INFO2 with the salt of the client's key in an AS-REP.</summary>
    public PreAuthData[] PreAuthData { get; internal init; } = [];

    /// <summary>The cname and crealm, the client the ticket was issued to.</summary>
    public PrincipalName ClientName { get; internal init; } = null!;

    /// <summary>The ticket, encrypted with the service's key.</summary>
    public Ticket Ticket { get; internal init; } = null!;

    /// <summary>
    /// The enc-part as sent, encrypted with the client's key for an AS-REP and the subkey or TGT session key for a
    /// TGS-REP.
    /// </summary>
    public EncryptedData EncryptedPart { get; internal init; } = null!;

    /// <summary>The decrypted enc-part, null if it was not decrypted.</summary>
    public KdcReplyPart? DecryptedPart { get; internal init; }

    public override string ToString() => $"{MessageType} {ClientName} -> {Ticket.ServiceName}";
}
