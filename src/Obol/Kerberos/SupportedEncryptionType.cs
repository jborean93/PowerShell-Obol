using System;

namespace Obol.Kerberos;

/// <summary>
/// The bits of the PA-SUPPORTED-ENCTYPES value, MS-KILE 2.2.7, the encryption types a service supports and the
/// features its domain controller supports.
/// </summary>
[Flags]
public enum SupportedEncryptionType : uint
{
    None = 0,

    Des56Crc = 0x00000001,

    Des56Md5 = 0x00000002,

    Rc4Hmac = 0x00000004,

    Aes128Sha1 = 0x00000008,

    Aes256Sha1 = 0x00000010,

    /// <summary>aes256-cts-hmac-sha1-96 session keys only, the service has no key of the type.</summary>
    Aes256Sha1SessionKey = 0x00000020,

    Aes128Sha256 = 0x00000040,

    Aes256Sha384 = 0x00000080,

    FastSupported = 0x00010000,

    CompoundIdentitySupported = 0x00020000,

    ClaimsSupported = 0x00040000,

    ResourceSidCompressionDisabled = 0x00080000,
}
