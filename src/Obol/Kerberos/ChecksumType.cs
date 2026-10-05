namespace Obol.Kerberos;

/// <summary>
/// The checksum types of RFC 3961 8., RFC 3962, RFC 6803, RFC 8009 and MS-KILE 3.1.5.1, as their registered numbers.
/// A type without a name is shown as its number.
/// </summary>
public enum ChecksumType
{
    Crc32 = 1,

    RsaMd4 = 2,

    RsaMd4Des = 3,

    DesMac = 4,

    DesMacK = 5,

    RsaMd4DesK = 6,

    RsaMd5 = 7,

    RsaMd5Des = 8,

    RsaMd5Des3 = 9,

    HmacSha1Des3Kd = 12,

    HmacSha1Des3 = 13,

    /// <summary>The unkeyed SHA-1 checksum.</summary>
    Sha1 = 14,

    /// <summary>The checksum of aes128-cts-hmac-sha1-96.</summary>
    HmacSha1Aes128 = 15,

    /// <summary>The checksum of aes256-cts-hmac-sha1-96.</summary>
    HmacSha1Aes256 = 16,

    CmacCamellia128 = 17,

    CmacCamellia256 = 18,

    /// <summary>The checksum of aes128-cts-hmac-sha256-128.</summary>
    HmacSha256Aes128 = 19,

    /// <summary>The checksum of aes256-cts-hmac-sha384-192.</summary>
    HmacSha384Aes256 = 20,

    /// <summary>KERB_CHECKSUM_MD5_HMAC, the unkeyed MD5 of Windows.</summary>
    Md5Hmac = -137,

    /// <summary>KERB_CHECKSUM_HMAC_MD5, the checksum of rc4-hmac.</summary>
    HmacMd5 = -138,
}
