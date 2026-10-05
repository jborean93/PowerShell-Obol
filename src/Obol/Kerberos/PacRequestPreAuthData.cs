namespace Obol.Kerberos;

/// <summary>PA-PAC-REQUEST, whether the client wants a PAC in the ticket, MS-KILE 2.2.3.</summary>
public sealed class PacRequestPreAuthData : PreAuthData
{
    internal PacRequestPreAuthData(byte[] value, bool includePac)
        : base(PreAuthDataType.PacRequest, value)
    {
        IncludePac = includePac;
    }

    /// <summary>Whether the client asked for a PAC.</summary>
    public bool IncludePac { get; }

    public override string ToString() => $"{Type} {IncludePac}";
}
