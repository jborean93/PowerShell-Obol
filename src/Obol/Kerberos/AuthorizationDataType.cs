namespace Obol.Kerberos;

/// <summary>
/// The type of an authorization data element, the ad-type numbers of RFC 4120 7.5.4 and MS-KILE. A type without a
/// name is shown as its number.
/// </summary>
public enum AuthorizationDataType
{
    /// <summary>AD-IF-RELEVANT, elements the application may ignore, holds the PAC.</summary>
    IfRelevant = 1,

    /// <summary>AD-INTENDED-FOR-SERVER.</summary>
    IntendedForServer = 2,

    /// <summary>AD-INTENDED-FOR-APPLICATION-CLASS.</summary>
    IntendedForApplicationClass = 3,

    /// <summary>AD-KDC-ISSUED, elements signed by the KDC.</summary>
    KdcIssued = 4,

    /// <summary>AD-AND-OR.</summary>
    AndOr = 5,

    /// <summary>AD-MANDATORY-FOR-KDC.</summary>
    MandatoryForKdc = 8,

    /// <summary>AD-CAMMAC, RFC 7751.</summary>
    Cammac = 96,

    /// <summary>AD-AUTHENTICATION-INDICATOR, RFC 8129.</summary>
    AuthenticationIndicator = 97,

    /// <summary>AD-WIN2K-PAC, the privilege attribute certificate, MS-PAC.</summary>
    Win2kPac = 128,

    /// <summary>AD-ETYPE-NEGOTIATION, the encryption types the client supports, RFC 4537.</summary>
    ETypeNegotiation = 129,

    /// <summary>KERB-AUTH-DATA-TOKEN-RESTRICTIONS, MS-KILE.</summary>
    AuthDataTokenRestrictions = 141,

    /// <summary>KERB-LOCAL, MS-KILE.</summary>
    Local = 142,

    /// <summary>AD-AUTH-DATA-AP-OPTIONS, MS-KILE.</summary>
    AuthDataApOptions = 143,

    /// <summary>AD-AUTH-DATA-TARGET-NAME, MS-KILE.</summary>
    AuthDataTargetName = 144,
}
