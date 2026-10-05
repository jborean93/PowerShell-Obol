namespace Obol.Kerberos;

/// <summary>PA-TGS-REQ, the AP-REQ with the TGT and authenticator of a TGS-REQ.</summary>
public sealed class TgsRequestPreAuthData : PreAuthData
{
    internal TgsRequestPreAuthData(byte[] value, ApRequest apRequest)
        : base(PreAuthDataType.TgsReq, value)
    {
        ApRequest = apRequest;
    }

    /// <summary>The AP-REQ.</summary>
    public ApRequest ApRequest { get; }

    public override string ToString() => $"{Type} {ApRequest.Ticket}";
}
