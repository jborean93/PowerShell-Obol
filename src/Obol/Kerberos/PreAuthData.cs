namespace Obol.Kerberos;

/// <summary>
/// A PA-DATA element of RFC 4120 5.2.7. The known types are derived classes with the decoded value, such as
/// <see cref="TgsRequestPreAuthData"/> and <see cref="TimestampPreAuthData"/>.
/// </summary>
public class PreAuthData
{
    internal PreAuthData(PreAuthDataType type, byte[] value)
    {
        Type = type;
        Value = value;
    }

    /// <summary>The padata-type, a type without a name is shown as its number.</summary>
    public PreAuthDataType Type { get; }

    /// <summary>The padata-value as sent.</summary>
    public byte[] Value { get; }

    public override string ToString() => $"{Type}, {Value.Length} bytes";
}
