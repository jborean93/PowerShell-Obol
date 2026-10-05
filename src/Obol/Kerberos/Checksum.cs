namespace Obol.Kerberos;

/// <summary>A Checksum of RFC 4120 5.2.9.</summary>
public sealed class Checksum
{
    internal Checksum(ChecksumType checksumType, byte[] value)
    {
        ChecksumType = checksumType;
        Value = value;
    }

    /// <summary>
    /// The checksum type as its RFC 3961 number, such as 16 for hmac-sha1-96-aes256 or 7 for rsa-md5.
    /// </summary>
    public ChecksumType ChecksumType { get; }

    /// <summary>The checksum.</summary>
    public byte[] Value { get; }

    public override string ToString() => $"cksumtype {ChecksumType}, {Value.Length} bytes";
}
