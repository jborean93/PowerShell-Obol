namespace Obol.Kerberos;

/// <summary>An EncryptionKey of RFC 4120 5.2.9, such as a session key or subkey.</summary>
public sealed class EncryptionKey
{
    internal EncryptionKey(EncryptionType encryptionType, byte[] value)
    {
        EncryptionType = encryptionType;
        Value = value;
    }

    /// <summary>The encryption type a type without a name is shown as its number.</summary>
    public EncryptionType EncryptionType { get; }

    /// <summary>The key.</summary>
    public byte[] Value { get; }

    public override string ToString() => $"etype {EncryptionType}, {Value.Length} bytes";
}
