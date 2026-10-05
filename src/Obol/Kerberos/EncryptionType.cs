namespace Obol.Kerberos;

/// <summary>
/// The encryption types of RFC 3961 8., RFC 3962, RFC 6803, RFC 8009 and MS-KILE, as their registered numbers. A
/// principal can only have keys of the AES types, the cmdlets reject the others. A type without a name is shown as
/// its number.
/// </summary>
public enum EncryptionType
{
    /// <summary>ENCTYPE_NULL, no encryption.</summary>
    Null = 0,

    DesCbcCrc = 1,

    DesCbcMd4 = 2,

    DesCbcMd5 = 3,

    Des3CbcMd5 = 5,

    /// <summary>des3-cbc-sha1, the old triple DES type without key derivation.</summary>
    Des3CbcSha1 = 7,

    /// <summary>dsaWithSHA1-CmsOID, a PKINIT signature algorithm, RFC 4556.</summary>
    DsaSha1Cms = 9,

    /// <summary>md5WithRSAEncryption-CmsOID, a PKINIT signature algorithm, RFC 4556.</summary>
    Md5RsaCms = 10,

    /// <summary>sha1WithRSAEncryption-CmsOID, a PKINIT signature algorithm, RFC 4556.</summary>
    Sha1RsaCms = 11,

    /// <summary>rc2CBC-EnvOID, a PKINIT content encryption algorithm, RFC 4556.</summary>
    Rc2CbcEnv = 12,

    /// <summary>rsaEncryption-EnvOID, a PKINIT key transport algorithm, RFC 4556.</summary>
    RsaEnv = 13,

    /// <summary>rsaES-OAEP-ENV-OID, a PKINIT key transport algorithm, RFC 4556.</summary>
    RsaEsOaepEnv = 14,

    /// <summary>des-ede3-cbc-Env-OID, a PKINIT content encryption algorithm, RFC 4556.</summary>
    DesEde3CbcEnv = 15,

    /// <summary>des3-cbc-sha1-kd, RFC 3961.</summary>
    Des3CbcSha1Kd = 16,

    /// <summary>aes128-cts-hmac-sha1-96, RFC 3962.</summary>
    Aes128Sha1 = 17,

    /// <summary>aes256-cts-hmac-sha1-96, RFC 3962.</summary>
    Aes256Sha1 = 18,

    /// <summary>aes128-cts-hmac-sha256-128, RFC 8009.</summary>
    Aes128Sha256 = 19,

    /// <summary>aes256-cts-hmac-sha384-192, RFC 8009.</summary>
    Aes256Sha384 = 20,

    /// <summary>rc4-hmac, RFC 4757.</summary>
    Rc4Hmac = 23,

    /// <summary>rc4-hmac-exp, the export strength rc4-hmac, RFC 4757.</summary>
    Rc4HmacExp = 24,

    /// <summary>camellia128-cts-cmac, RFC 6803.</summary>
    Camellia128Cmac = 25,

    /// <summary>camellia256-cts-cmac, RFC 6803.</summary>
    Camellia256Cmac = 26,

    /// <summary>subkey-keymaterial, an opaque key, RFC 3961.</summary>
    SubkeyKeyMaterial = 65,

    /// <summary>The Windows NT 4 RC4 with MD4 type, MS-KILE.</summary>
    Rc4Md4 = -128,

    /// <summary>The pre-release Windows 2000 rc4-hmac type, MS-KILE.</summary>
    Rc4HmacOld = -133,

    /// <summary>The pre-release Windows 2000 export strength rc4-hmac type, MS-KILE.</summary>
    Rc4HmacOldExp = -135,
}
