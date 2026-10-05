namespace Obol.Kerberos;

/// <summary>
/// The key usage numbers of RFC 4120 7.5.1, RFC 4121 and RFC 6113 that separate the keys derived from one key for
/// each encrypted part of a message.
/// </summary>
public enum KeyUsage
{
    /// <summary>The PA-ENC-TIMESTAMP of an AS-REQ, with the client key.</summary>
    PaEncTimestamp = 1,

    /// <summary>The enc-part of a Ticket, with the service key.</summary>
    Ticket = 2,

    /// <summary>The enc-part of an AS-REP, with the client key.</summary>
    AsRepEncryptedPart = 3,

    /// <summary>The enc-authorization-data of a TGS-REQ, with the TGT session key.</summary>
    TgsReqAuthorizationDataSessionKey = 4,

    /// <summary>The enc-authorization-data of a TGS-REQ, with the authenticator subkey.</summary>
    TgsReqAuthorizationDataSubkey = 5,

    /// <summary>The checksum of the TGS-REQ body in the authenticator of its PA-TGS-REQ.</summary>
    PaTgsReqChecksum = 6,

    /// <summary>The authenticator of the PA-TGS-REQ of a TGS-REQ, with the TGT session key.</summary>
    PaTgsReqAuthenticator = 7,

    /// <summary>The enc-part of a TGS-REP, with the TGT session key.</summary>
    TgsRepEncryptedPartSessionKey = 8,

    /// <summary>The enc-part of a TGS-REP, with the authenticator subkey.</summary>
    TgsRepEncryptedPartSubkey = 9,

    /// <summary>The checksum in the authenticator of an AP-REQ.</summary>
    ApReqAuthenticatorChecksum = 10,

    /// <summary>The authenticator of an AP-REQ, with the ticket session key.</summary>
    ApReqAuthenticator = 11,

    /// <summary>The enc-part of an AP-REP.</summary>
    ApRepEncryptedPart = 12,

    /// <summary>The enc-part of a KRB-PRIV.</summary>
    PrivEncryptedPart = 13,

    /// <summary>The enc-part of a KRB-CRED.</summary>
    CredEncryptedPart = 14,

    /// <summary>The checksum of a KRB-SAFE.</summary>
    SafeChecksum = 15,

    /// <summary>The checksum of AD-KDC-ISSUED authorization data.</summary>
    AdKdcIssuedChecksum = 19,

    /// <summary>GSS-API wrap tokens sealed by the acceptor, RFC 4121.</summary>
    AcceptorSeal = 22,

    /// <summary>GSS-API MIC tokens signed by the acceptor, RFC 4121.</summary>
    AcceptorSign = 23,

    /// <summary>GSS-API wrap tokens sealed by the initiator, RFC 4121.</summary>
    InitiatorSeal = 24,

    /// <summary>GSS-API MIC tokens signed by the initiator, RFC 4121.</summary>
    InitiatorSign = 25,

    /// <summary>The checksum of a FAST request, RFC 6113.</summary>
    FastRequestChecksum = 50,

    /// <summary>The enc-fast-req of a FAST request, RFC 6113.</summary>
    FastEncryptedRequest = 51,

    /// <summary>The enc-fast-rep of a FAST reply, RFC 6113.</summary>
    FastEncryptedReply = 52,

    /// <summary>The finished message of a FAST reply, RFC 6113.</summary>
    FastFinished = 53,

    /// <summary>The PA-ENCRYPTED-CHALLENGE of the client, RFC 6113.</summary>
    EncryptedChallengeClient = 54,

    /// <summary>The PA-ENCRYPTED-CHALLENGE of the KDC, RFC 6113.</summary>
    EncryptedChallengeKdc = 55,

    /// <summary>The checksum of the AS-REQ in PA-REQ-ENC-PA-REP, RFC 6113.</summary>
    AsReq = 56,
}
