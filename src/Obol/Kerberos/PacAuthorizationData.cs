namespace Obol.Kerberos;

/// <summary>AD-WIN2K-PAC, the privilege attribute certificate of the client, MS-PAC.</summary>
public sealed class PacAuthorizationData : AuthorizationData
{
    internal PacAuthorizationData(byte[] data, Pac pac)
        : base(AuthorizationDataType.Win2kPac, data)
    {
        Pac = pac;
    }

    /// <summary>The decoded PAC.</summary>
    public Pac Pac { get; }

    public override string ToString() => $"{Type} {Pac}";
}
