using System;

namespace Obol.Kerberos;

/// <summary>
/// The UserAccountControl of the PAC logon information, the MS-SAMR 2.2.1.12 USER_* values. These are not the LDAP
/// userAccountControl values. The <c>-Flag</c> of a principal takes the bits the KDC acts on, see
/// <c>about_Obol</c>.
/// </summary>
[Flags]
public enum PacUserAccountControl : uint
{
    None = 0,

    /// <summary>USER_ACCOUNT_DISABLED.</summary>
    AccountDisabled = 0x00000001,

    /// <summary>USER_HOME_DIRECTORY_REQUIRED.</summary>
    HomeDirectoryRequired = 0x00000002,

    /// <summary>USER_PASSWORD_NOT_REQUIRED.</summary>
    PasswordNotRequired = 0x00000004,

    /// <summary>USER_TEMP_DUPLICATE_ACCOUNT.</summary>
    TempDuplicateAccount = 0x00000008,

    /// <summary>USER_NORMAL_ACCOUNT.</summary>
    NormalAccount = 0x00000010,

    /// <summary>USER_MNS_LOGON_ACCOUNT.</summary>
    MnsLogonAccount = 0x00000020,

    /// <summary>USER_INTERDOMAIN_TRUST_ACCOUNT.</summary>
    InterdomainTrustAccount = 0x00000040,

    /// <summary>USER_WORKSTATION_TRUST_ACCOUNT.</summary>
    WorkstationTrustAccount = 0x00000080,

    /// <summary>USER_SERVER_TRUST_ACCOUNT.</summary>
    ServerTrustAccount = 0x00000100,

    /// <summary>USER_DONT_EXPIRE_PASSWORD.</summary>
    DontExpirePassword = 0x00000200,

    /// <summary>USER_ACCOUNT_AUTO_LOCKED.</summary>
    AccountAutoLocked = 0x00000400,

    /// <summary>USER_ENCRYPTED_TEXT_PASSWORD_ALLOWED.</summary>
    EncryptedTextPasswordAllowed = 0x00000800,

    /// <summary>USER_SMARTCARD_REQUIRED.</summary>
    SmartcardRequired = 0x00001000,

    /// <summary>USER_TRUSTED_FOR_DELEGATION, tickets for the principal get OK-AS-DELEGATE.</summary>
    TrustedForDelegation = 0x00002000,

    /// <summary>USER_NOT_DELEGATED, the principal never gets a forwardable ticket.</summary>
    NotDelegated = 0x00004000,

    /// <summary>USER_USE_DES_KEY_ONLY.</summary>
    UseDesKeyOnly = 0x00008000,

    /// <summary>USER_DONT_REQUIRE_PREAUTH, the principal can get a ticket without pre-authentication.</summary>
    DontRequirePreAuth = 0x00010000,

    /// <summary>USER_PASSWORD_EXPIRED.</summary>
    PasswordExpired = 0x00020000,

    /// <summary>USER_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION.</summary>
    TrustedToAuthenticateForDelegation = 0x00040000,

    /// <summary>USER_NO_AUTH_DATA_REQUIRED, service tickets for the principal have no PAC.</summary>
    NoAuthDataRequired = 0x00080000,

    /// <summary>USER_PARTIAL_SECRETS_ACCOUNT.</summary>
    PartialSecretsAccount = 0x00100000,

    /// <summary>USER_USE_AES_KEYS.</summary>
    UseAesKeys = 0x00200000,
}
