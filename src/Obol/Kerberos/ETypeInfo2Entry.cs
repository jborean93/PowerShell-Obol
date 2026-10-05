namespace Obol.Kerberos;

/// <summary>
/// An ETYPE-INFO2-ENTRY of RFC 4120 5.2.7.5, an encryption type the KDC accepts with the salt for it.
/// </summary>
public sealed class ETypeInfo2Entry
{
    internal ETypeInfo2Entry(EncryptionType encryptionType, string? salt, byte[]? stringToKeyParameters)
    {
        EncryptionType = encryptionType;
        Salt = salt;
        StringToKeyParameters = stringToKeyParameters;
    }

    /// <summary>The encryption type a type without a name is shown as its number.</summary>
    public EncryptionType EncryptionType { get; }

    /// <summary>The salt to derive the key from the password with, the default salt if not set.</summary>
    public string? Salt { get; }

    /// <summary>The s2kparams, the iteration count for the AES types, if set.</summary>
    public byte[]? StringToKeyParameters { get; }

    public override string ToString() => Salt is null
        ? $"etype {EncryptionType}"
        : $"etype {EncryptionType} salt {Salt}";
}
