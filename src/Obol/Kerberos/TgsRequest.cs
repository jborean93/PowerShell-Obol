namespace Obol.Kerberos;

/// <summary>A TGS-REQ, a KDC-REQ whose PA-TGS-REQ holds the TGT and authenticator of the client.</summary>
public sealed class TgsRequest : KdcRequest
{
    internal TgsRequest(byte[] bytes) : base(MessageType.TgsReq, bytes) { }

    /// <summary>
    /// The AP-REQ of the PA-TGS-REQ with the TGT and the authenticator, null if the request had none. The TGT's
    /// <see cref="Ticket.DecryptedPart"/> and the <see cref="ApRequest.Authenticator"/> are set when the
    /// KDC decrypted them, which it does before it checks them.
    /// </summary>
    public ApRequest? ApRequest { get; internal init; }
}
