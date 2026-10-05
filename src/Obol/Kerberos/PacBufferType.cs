namespace Obol.Kerberos;

/// <summary>
/// The type of a PAC buffer, the ulType values of MS-PAC 2.4. A type without a name is shown as its number.
/// </summary>
public enum PacBufferType
{
    /// <summary>KERB_VALIDATION_INFO, the logon information with the user and group SIDs.</summary>
    LogonInfo = 1,

    /// <summary>PAC_CREDENTIAL_INFO, credentials for PKINIT logons.</summary>
    CredentialInfo = 2,

    /// <summary>The server signature over the PAC.</summary>
    ServerChecksum = 6,

    /// <summary>The KDC signature over the server signature.</summary>
    KdcChecksum = 7,

    /// <summary>PAC_CLIENT_INFO, the client name and authentication time.</summary>
    ClientInfo = 10,

    /// <summary>S4U_DELEGATION_INFO, the constrained delegation path.</summary>
    DelegationInfo = 11,

    /// <summary>UPN_DNS_INFO, the user principal name and DNS domain.</summary>
    UpnDnsInfo = 12,

    /// <summary>PAC_CLIENT_CLAIMS_INFO.</summary>
    ClientClaims = 13,

    /// <summary>PAC_DEVICE_INFO.</summary>
    DeviceInfo = 14,

    /// <summary>PAC_DEVICE_CLAIMS_INFO.</summary>
    DeviceClaims = 15,

    /// <summary>The ticket signature over the ticket outside the PAC.</summary>
    TicketChecksum = 16,

    /// <summary>PAC_ATTRIBUTES_INFO, whether the client asked for the PAC.</summary>
    Attributes = 17,

    /// <summary>PAC_REQUESTOR, the SID of the requesting client.</summary>
    Requestor = 18,

    /// <summary>The full signature over the PAC, including the server and KDC signatures.</summary>
    FullChecksum = 19,
}
