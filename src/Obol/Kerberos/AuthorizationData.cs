namespace Obol.Kerberos;

/// <summary>
/// An AuthorizationData element of RFC 4120 5.2.6. The known types are derived classes with the decoded value,
/// <see cref="IfRelevantAuthorizationData"/> and <see cref="PacAuthorizationData"/>.
/// </summary>
public class AuthorizationData
{
    internal AuthorizationData(AuthorizationDataType type, byte[] data)
    {
        Type = type;
        Data = data;
    }

    /// <summary>The ad-type, a type without a name is shown as its number.</summary>
    public AuthorizationDataType Type { get; }

    /// <summary>The ad-data as sent.</summary>
    public byte[] Data { get; }

    public override string ToString() => $"{Type}, {Data.Length} bytes";
}
