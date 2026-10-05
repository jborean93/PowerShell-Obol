namespace Obol.Kerberos;

/// <summary>An EncryptedData of RFC 4120 5.2.9, a ciphertext with the encryption type and key version used.</summary>
public sealed class EncryptedData
{
    internal EncryptedData(EncryptionType encryptionType, int? keyVersion, byte[] cipher)
    {
        EncryptionType = encryptionType;
        KeyVersion = keyVersion;
        Cipher = cipher;
    }

    /// <summary>The encryption type a type without a name is shown as its number.</summary>
    public EncryptionType EncryptionType { get; }

    /// <summary>The version of the key used, if sent.</summary>
    public int? KeyVersion { get; }

    /// <summary>The ciphertext.</summary>
    public byte[] Cipher { get; }

    public override string ToString() => KeyVersion is int kvno
        ? $"etype {EncryptionType} kvno {kvno}, {Cipher.Length} bytes"
        : $"etype {EncryptionType}, {Cipher.Length} bytes";
}
