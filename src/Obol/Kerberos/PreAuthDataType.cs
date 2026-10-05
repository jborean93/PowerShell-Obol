namespace Obol.Kerberos;

/// <summary>
/// The type of a pre-authentication data element, the padata-type numbers of RFC 4120 7.5.2 and the IANA registry. A
/// type without a name is shown as its number.
/// </summary>
public enum PreAuthDataType
{
    /// <summary>PA-TGS-REQ, the AP-REQ with the TGT of a TGS-REQ.</summary>
    TgsReq = 1,

    /// <summary>PA-ENC-TIMESTAMP, the encrypted timestamp a client pre-authenticates with.</summary>
    EncTimestamp = 2,

    /// <summary>PA-PW-SALT, the salt of the client's key.</summary>
    PwSalt = 3,

    /// <summary>PA-ETYPE-INFO, the encryption types and salts the KDC accepts.</summary>
    ETypeInfo = 11,

    /// <summary>PA-PK-AS-REQ, PKINIT, RFC 4556.</summary>
    PkAsReq = 16,

    /// <summary>PA-PK-AS-REP, PKINIT, RFC 4556.</summary>
    PkAsRep = 17,

    /// <summary>PA-ETYPE-INFO2, the encryption types, salts and string-to-key parameters the KDC accepts.</summary>
    ETypeInfo2 = 19,

    /// <summary>PA-SVR-REFERRAL-INFO, RFC 6806.</summary>
    ServerReferralInfo = 20,

    /// <summary>PA-PAC-REQUEST, whether the client wants a PAC in the ticket, MS-KILE.</summary>
    PacRequest = 128,

    /// <summary>PA-FOR-USER, the user a service asks a ticket for, S4U2self, MS-SFU.</summary>
    ForUser = 129,

    /// <summary>PA-S4U-X509-USER, S4U2self with a certificate, MS-SFU.</summary>
    S4UX509User = 130,

    /// <summary>PA-AS-CHECKSUM, MS-KILE.</summary>
    AsChecksum = 132,

    /// <summary>PA-FX-COOKIE, RFC 6113.</summary>
    FxCookie = 133,

    /// <summary>PA-AUTHENTICATION-SET, RFC 6113.</summary>
    AuthenticationSet = 134,

    /// <summary>PA-AUTH-SET-SELECTED, RFC 6113.</summary>
    AuthSetSelected = 135,

    /// <summary>PA-FX-FAST, a FAST armored request or reply, RFC 6113.</summary>
    FxFast = 136,

    /// <summary>PA-FX-ERROR, a FAST armored error, RFC 6113.</summary>
    FxError = 137,

    /// <summary>PA-ENCRYPTED-CHALLENGE, RFC 6113.</summary>
    EncryptedChallenge = 138,

    /// <summary>PA-PKINIT-KX, anonymous PKINIT, RFC 8062.</summary>
    PkinitKx = 147,

    /// <summary>PA-PKU2U-NAME, PKU2U.</summary>
    Pku2uName = 148,

    /// <summary>PA-REQ-ENC-PA-REP, the client asks for a checksum of the request in the reply, RFC 6806.</summary>
    ReqEncPaRep = 149,

    /// <summary>PA-AS-FRESHNESS, the client supports the freshness token, RFC 8070.</summary>
    AsFreshness = 150,

    /// <summary>KERB-KEY-LIST-REQ, MS-KILE.</summary>
    KeyListReq = 161,

    /// <summary>KERB-KEY-LIST-REP, MS-KILE.</summary>
    KeyListRep = 162,

    /// <summary>PA-SUPPORTED-ENCTYPES, the encryption types the service supports, MS-KILE.</summary>
    SupportedEncryptionTypes = 165,

    /// <summary>PA-PAC-OPTIONS, the PAC options the client asks for, MS-KILE.</summary>
    PacOptions = 167,
}
