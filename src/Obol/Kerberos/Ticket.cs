namespace Obol.Kerberos;

/// <summary>A Ticket of RFC 4120 5.3, encrypted with the long-term key of the service it is for.</summary>
public sealed class Ticket
{
    internal Ticket() { }

    /// <summary>The tkt-vno, always 5.</summary>
    public int Version { get; internal init; }

    /// <summary>The realm that issued the ticket.</summary>
    public string Realm { get; internal init; } = "";

    /// <summary>The sname, the service the ticket is for.</summary>
    public PrincipalName ServiceName { get; internal init; } = null!;

    /// <summary>The enc-part as sent, encrypted with the service's key, its kvno says which version.</summary>
    public EncryptedData EncryptedPart { get; internal init; } = null!;

    /// <summary>The decrypted enc-part, null if it was not decrypted.</summary>
    public TicketPart? DecryptedPart { get; internal init; }

    public override string ToString() => $"{ServiceName} ({EncryptedPart})";
}
