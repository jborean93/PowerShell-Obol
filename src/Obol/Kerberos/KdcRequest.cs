namespace Obol.Kerberos;

/// <summary>
/// An AS-REQ or TGS-REQ, the KDC-REQ of RFC 4120 5.4.1. A TGS-REQ is an <see cref="TgsRequest"/>.
/// </summary>
public class KdcRequest : Message
{
    internal KdcRequest(MessageType messageType, byte[] bytes) : base(messageType, bytes) { }

    /// <summary>The pvno, always 5.</summary>
    public int ProtocolVersion { get; internal init; }

    /// <summary>
    /// The padata, the pre-authentication data such as PA-ENC-TIMESTAMP, PA-TGS-REQ or PA-PAC-REQUEST, in the order
    /// sent. The known types are decoded into derived types.
    /// </summary>
    public PreAuthData[] PreAuthData { get; internal init; } = [];

    /// <summary>The req-body, what the client asked for.</summary>
    public KdcRequestBody Body { get; internal init; } = new();

    public override string ToString() => $"{MessageType} {Body}";
}
