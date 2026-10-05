namespace Obol.Kerberos;

/// <summary>The type of a Kerberos message, the values are the msg-type numbers of RFC 4120 5.10.</summary>
public enum MessageType
{
    /// <summary>The message could not be decoded.</summary>
    Unknown = 0,

    /// <summary>KRB_AS_REQ, the initial authentication request of a client.</summary>
    AsReq = 10,

    /// <summary>KRB_AS_REP, the reply to an AS-REQ with a ticket.</summary>
    AsRep = 11,

    /// <summary>KRB_TGS_REQ, a request for a ticket with a TGT.</summary>
    TgsReq = 12,

    /// <summary>KRB_TGS_REP, the reply to a TGS-REQ with a ticket.</summary>
    TgsRep = 13,

    /// <summary>KRB_AP_REQ, a ticket and authenticator presented to a service, or to the KDC in PA-TGS-REQ.</summary>
    ApReq = 14,

    /// <summary>KRB_AP_REP, the reply of a service for mutual authentication.</summary>
    ApRep = 15,

    /// <summary>KRB_SAFE, an integrity protected application message.</summary>
    Safe = 20,

    /// <summary>KRB_PRIV, an encrypted application message.</summary>
    Priv = 21,

    /// <summary>KRB_CRED, forwarded credentials.</summary>
    Cred = 22,

    /// <summary>KRB_ERROR, an error reply.</summary>
    Error = 30,
}
