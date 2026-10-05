namespace Obol.Kerberos;

/// <summary>
/// The error-code of a KRB-ERROR, or <see cref="None"/> when the KDC answered a request with a ticket.
/// </summary>
/// <remarks>
/// The values are the error codes of RFC 4120 7.5.9, RFC 4556 (PKINIT), RFC 6113 (FAST) and RFC 8062 (anonymous
/// PKINIT), the name of each in those documents is in its description. A code without a name is shown as its number.
/// </remarks>
public enum ErrorCode
{
    /// <summary>KDC_ERR_NONE, no error, the request was answered with a ticket.</summary>
    None = 0,

    /// <summary>KDC_ERR_NAME_EXP, the client's entry in the database has expired.</summary>
    NameExpired = 1,

    /// <summary>KDC_ERR_SERVICE_EXP, the server's entry in the database has expired.</summary>
    ServiceExpired = 2,

    /// <summary>KDC_ERR_BAD_PVNO, the requested protocol version number is not supported.</summary>
    BadProtocolVersion = 3,

    /// <summary>KDC_ERR_C_OLD_MAST_KVNO, the client's key is encrypted in an old master key.</summary>
    ClientOldMasterKeyVersion = 4,

    /// <summary>KDC_ERR_S_OLD_MAST_KVNO, the server's key is encrypted in an old master key.</summary>
    ServiceOldMasterKeyVersion = 5,

    /// <summary>KDC_ERR_C_PRINCIPAL_UNKNOWN, the client was not found in the database.</summary>
    ClientPrincipalUnknown = 6,

    /// <summary>KDC_ERR_S_PRINCIPAL_UNKNOWN, the server was not found in the database.</summary>
    ServicePrincipalUnknown = 7,

    /// <summary>KDC_ERR_PRINCIPAL_NOT_UNIQUE, multiple principal entries in the database.</summary>
    PrincipalNotUnique = 8,

    /// <summary>KDC_ERR_NULL_KEY, the client or server has a null key.</summary>
    NullKey = 9,

    /// <summary>KDC_ERR_CANNOT_POSTDATE, the ticket is not eligible for postdating.</summary>
    CannotPostdate = 10,

    /// <summary>KDC_ERR_NEVER_VALID, the requested start time is later than the end time.</summary>
    NeverValid = 11,

    /// <summary>KDC_ERR_POLICY, the KDC policy rejects the request.</summary>
    Policy = 12,

    /// <summary>KDC_ERR_BADOPTION, the KDC cannot accommodate the requested option.</summary>
    BadOption = 13,

    /// <summary>KDC_ERR_ETYPE_NOSUPP, the KDC has no support for the encryption type.</summary>
    EncryptionTypeNotSupported = 14,

    /// <summary>KDC_ERR_SUMTYPE_NOSUPP, the KDC has no support for the checksum type.</summary>
    ChecksumTypeNotSupported = 15,

    /// <summary>KDC_ERR_PADATA_TYPE_NOSUPP, the KDC has no support for the padata type.</summary>
    PaDataTypeNotSupported = 16,

    /// <summary>KDC_ERR_TRTYPE_NOSUPP, the KDC has no support for the transited type.</summary>
    TransitedTypeNotSupported = 17,

    /// <summary>KDC_ERR_CLIENT_REVOKED, the client's credentials have been revoked.</summary>
    ClientRevoked = 18,

    /// <summary>KDC_ERR_SERVICE_REVOKED, the credentials for the server have been revoked.</summary>
    ServiceRevoked = 19,

    /// <summary>KDC_ERR_TGT_REVOKED, the TGT has been revoked.</summary>
    TgtRevoked = 20,

    /// <summary>KDC_ERR_CLIENT_NOTYET, the client is not yet valid.</summary>
    ClientNotYetValid = 21,

    /// <summary>KDC_ERR_SERVICE_NOTYET, the server is not yet valid.</summary>
    ServiceNotYetValid = 22,

    /// <summary>KDC_ERR_KEY_EXPIRED, the password has expired.</summary>
    KeyExpired = 23,

    /// <summary>KDC_ERR_PREAUTH_FAILED, the pre-authentication information was invalid.</summary>
    PreAuthFailed = 24,

    /// <summary>KDC_ERR_PREAUTH_REQUIRED, additional pre-authentication is required.</summary>
    PreAuthRequired = 25,

    /// <summary>KDC_ERR_SERVER_NOMATCH, the requested server and ticket do not match.</summary>
    ServerNoMatch = 26,

    /// <summary>KDC_ERR_MUST_USE_USER2USER, the server principal is valid for user to user only.</summary>
    MustUseUserToUser = 27,

    /// <summary>KDC_ERR_PATH_NOT_ACCEPTED, the KDC policy rejects the transited path.</summary>
    PathNotAccepted = 28,

    /// <summary>KDC_ERR_SVC_UNAVAILABLE, a service is not available.</summary>
    ServiceUnavailable = 29,

    /// <summary>KRB_AP_ERR_BAD_INTEGRITY, the integrity check on the decrypted field failed.</summary>
    BadIntegrity = 31,

    /// <summary>KRB_AP_ERR_TKT_EXPIRED, the ticket has expired.</summary>
    TicketExpired = 32,

    /// <summary>KRB_AP_ERR_TKT_NYV, the ticket is not yet valid.</summary>
    TicketNotYetValid = 33,

    /// <summary>KRB_AP_ERR_REPEAT, the request is a replay.</summary>
    Repeat = 34,

    /// <summary>KRB_AP_ERR_NOT_US, the ticket is not for us.</summary>
    NotUs = 35,

    /// <summary>KRB_AP_ERR_BADMATCH, the ticket and authenticator do not match.</summary>
    BadMatch = 36,

    /// <summary>KRB_AP_ERR_SKEW, the clock skew is too great.</summary>
    Skew = 37,

    /// <summary>KRB_AP_ERR_BADADDR, incorrect net address.</summary>
    BadAddress = 38,

    /// <summary>KRB_AP_ERR_BADVERSION, protocol version mismatch.</summary>
    BadVersion = 39,

    /// <summary>KRB_AP_ERR_MSG_TYPE, invalid message type.</summary>
    MessageType = 40,

    /// <summary>KRB_AP_ERR_MODIFIED, the message stream was modified.</summary>
    Modified = 41,

    /// <summary>KRB_AP_ERR_BADORDER, the message is out of order.</summary>
    BadOrder = 42,

    /// <summary>KRB_AP_ERR_BADKEYVER, the specified version of the key is not available.</summary>
    BadKeyVersion = 44,

    /// <summary>KRB_AP_ERR_NOKEY, the service key is not available.</summary>
    NoKey = 45,

    /// <summary>KRB_AP_ERR_MUT_FAIL, mutual authentication failed.</summary>
    MutualAuthenticationFailed = 46,

    /// <summary>KRB_AP_ERR_BADDIRECTION, incorrect message direction.</summary>
    BadDirection = 47,

    /// <summary>KRB_AP_ERR_METHOD, an alternative authentication method is required.</summary>
    Method = 48,

    /// <summary>KRB_AP_ERR_BADSEQ, incorrect sequence number in the message.</summary>
    BadSequence = 49,

    /// <summary>KRB_AP_ERR_INAPP_CKSUM, inappropriate type of checksum in the message.</summary>
    InappropriateChecksum = 50,

    /// <summary>KRB_AP_PATH_NOT_ACCEPTED, the policy rejects the transited path.</summary>
    ApPathNotAccepted = 51,

    /// <summary>KRB_ERR_RESPONSE_TOO_BIG, the response is too big for UDP, retry with TCP.</summary>
    ResponseTooBig = 52,

    /// <summary>KRB_ERR_GENERIC, a generic error.</summary>
    Generic = 60,

    /// <summary>KRB_ERR_FIELD_TOOLONG, a field is too long for this implementation.</summary>
    FieldTooLong = 61,

    /// <summary>KDC_ERR_CLIENT_NOT_TRUSTED, the client certificate is not trusted.</summary>
    ClientNotTrusted = 62,

    /// <summary>KDC_ERR_KDC_NOT_TRUSTED, the KDC certificate is not trusted.</summary>
    KdcNotTrusted = 63,

    /// <summary>KDC_ERR_INVALID_SIG, the signature is invalid.</summary>
    InvalidSignature = 64,

    /// <summary>KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED, the Diffie-Hellman parameters are not accepted.</summary>
    DhKeyParametersNotAccepted = 65,

    /// <summary>KDC_ERR_CERTIFICATE_MISMATCH, the certificate does not match the client.</summary>
    CertificateMismatch = 66,

    /// <summary>KRB_AP_ERR_NO_TGT, no TGT was available to validate USER-TO-USER.</summary>
    NoTgt = 67,

    /// <summary>KDC_ERR_WRONG_REALM, the KDC does not serve the requested realm.</summary>
    WrongRealm = 68,

    /// <summary>KRB_AP_ERR_USER_TO_USER_REQUIRED, the ticket must be obtained user to user.</summary>
    UserToUserRequired = 69,

    /// <summary>KDC_ERR_CANT_VERIFY_CERTIFICATE, the certificate cannot be verified.</summary>
    CannotVerifyCertificate = 70,

    /// <summary>KDC_ERR_INVALID_CERTIFICATE, the certificate is invalid.</summary>
    InvalidCertificate = 71,

    /// <summary>KDC_ERR_REVOKED_CERTIFICATE, the certificate has been revoked.</summary>
    RevokedCertificate = 72,

    /// <summary>KDC_ERR_REVOCATION_STATUS_UNKNOWN, the revocation status of the certificate is unknown.</summary>
    RevocationStatusUnknown = 73,

    /// <summary>KDC_ERR_REVOCATION_STATUS_UNAVAILABLE, the revocation status is unavailable.</summary>
    RevocationStatusUnavailable = 74,

    /// <summary>KDC_ERR_CLIENT_NAME_MISMATCH, the client name does not match the certificate.</summary>
    ClientNameMismatch = 75,

    /// <summary>KDC_ERR_KDC_NAME_MISMATCH, the KDC name does not match the certificate.</summary>
    KdcNameMismatch = 76,

    /// <summary>KDC_ERR_INCONSISTENT_KEY_PURPOSE, the certificate key purpose is inconsistent.</summary>
    InconsistentKeyPurpose = 77,

    /// <summary>KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED, the digest algorithm of the certificate is rejected.</summary>
    DigestInCertificateNotAccepted = 78,

    /// <summary>KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED, the pa-checksum must be included.</summary>
    PaChecksumMustBeIncluded = 79,

    /// <summary>KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED, the digest of the signed data is rejected.</summary>
    DigestInSignedDataNotAccepted = 80,

    /// <summary>KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED, public key encryption is not supported.</summary>
    PublicKeyEncryptionNotSupported = 81,

    /// <summary>KRB_AP_ERR_PRINCIPAL_UNKNOWN, the principal is unknown.</summary>
    ApPrincipalUnknown = 82,

    /// <summary>KRB_AP_ERR_REALM_UNKNOWN, the realm is unknown.</summary>
    RealmUnknown = 83,

    /// <summary>KRB_AP_ERR_PRINCIPAL_RESERVED, the principal name is reserved.</summary>
    PrincipalReserved = 84,

    /// <summary>KRB_AP_ERR_IAKERB_KDC_NOT_FOUND, the IAKERB proxy could not find a KDC.</summary>
    IakerbKdcNotFound = 85,

    /// <summary>KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE, the KDC did not respond to the IAKERB proxy.</summary>
    IakerbKdcNoResponse = 86,

    /// <summary>KDC_ERR_PREAUTH_EXPIRED, the pre-authentication has expired.</summary>
    PreAuthExpired = 90,

    /// <summary>KDC_ERR_MORE_PREAUTH_DATA_REQUIRED, more pre-authentication data is required.</summary>
    MorePreAuthDataRequired = 91,

    /// <summary>KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET, the pre-authentication set is not acceptable.</summary>
    PreAuthBadAuthenticationSet = 92,

    /// <summary>KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS, unknown critical FAST options were requested.</summary>
    UnknownCriticalFastOptions = 93,
}
