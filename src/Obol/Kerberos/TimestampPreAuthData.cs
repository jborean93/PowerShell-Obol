using System;

namespace Obol.Kerberos;

/// <summary>PA-ENC-TIMESTAMP, the client's time encrypted with its long-term key, RFC 4120 5.2.7.2.</summary>
public sealed class TimestampPreAuthData : PreAuthData
{
    internal TimestampPreAuthData(byte[] value, EncryptedData encryptedData, DateTime? timestamp)
        : base(PreAuthDataType.EncTimestamp, value)
    {
        EncryptedData = encryptedData;
        Timestamp = timestamp;
    }

    /// <summary>The timestamp as sent, its encryption type is the key the client used.</summary>
    public EncryptedData EncryptedData { get; }

    /// <summary>The decrypted timestamp as local time, null if the KDC did not decrypt it.</summary>
    public DateTime? Timestamp { get; }

    public override string ToString() => Timestamp is DateTime time
        ? $"{Type} {time} ({EncryptedData})"
        : $"{Type} ({EncryptedData})";
}
