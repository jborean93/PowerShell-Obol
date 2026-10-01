namespace Obol;

/// <summary>The encryption types of a principal's long-term keys, the values are the IANA assigned numbers.</summary>
public enum ObolEncryptionType
{
    /// <summary>aes128-cts-hmac-sha1-96, RFC 3962.</summary>
    Aes128Sha1 = 17,

    /// <summary>aes256-cts-hmac-sha1-96, RFC 3962.</summary>
    Aes256Sha1 = 18,

    /// <summary>aes128-cts-hmac-sha256-128, RFC 8009.</summary>
    Aes128Sha256 = 19,

    /// <summary>aes256-cts-hmac-sha384-192, RFC 8009.</summary>
    Aes256Sha384 = 20,
}
