namespace Obol.Kerberos;

/// <summary>
/// An AP-REQ of RFC 4120 5.5.1, a ticket with an authenticator proving the client holds its session key.
/// </summary>
public sealed class ApRequest : Message
{
    internal ApRequest(byte[] bytes) : base(MessageType.ApReq, bytes) { }

    /// <summary>The pvno, always 5.</summary>
    public int ProtocolVersion { get; internal init; }

    /// <summary>The ap-options.</summary>
    public ApOption ApOption { get; internal init; }

    /// <summary>The ticket presented, the TGT in a TGS-REQ.</summary>
    public Ticket Ticket { get; internal init; } = null!;

    /// <summary>The authenticator as sent, encrypted with the session key of the ticket.</summary>
    public EncryptedData EncryptedAuthenticator { get; internal init; } = null!;

    /// <summary>The decrypted authenticator, null if it was not decrypted.</summary>
    public Authenticator? Authenticator { get; internal init; }

    public override string ToString() => $"AP-REQ {Ticket}";
}
