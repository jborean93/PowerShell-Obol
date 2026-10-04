using System;

namespace Obol;

/// <summary>
/// The domain controller flags (<c>DS_*</c>) of a KDC, as returned by <c>DsGetDcName</c>.
/// </summary>
/// <remarks>
/// Used for <c>Add-ObolSspiKdc -DcFlags</c>: for a machine binding the DC flags recorded for the KDC, for a thread
/// pin the flags a request is matched against. <see cref="None"/> is the usual value for a test KDC: as a pin filter
/// it matches any request, as a binding value it records no flags. Values can be combined, for example
/// <c>Kdc, Writable</c>.
/// </remarks>
[Flags]
public enum ObolSspiDcFlags : uint
{
    /// <summary>No flags. As a pin filter this matches any request.</summary>
    None = 0,

    /// <summary>The KDC is the PDC of the domain (<c>DS_PDC_FLAG</c>).</summary>
    Pdc = 0x00000001,

    /// <summary>The KDC is a global catalog of the forest (<c>DS_GC_FLAG</c>).</summary>
    Gc = 0x00000004,

    /// <summary>The server supports LDAP (<c>DS_LDAP_FLAG</c>).</summary>
    Ldap = 0x00000008,

    /// <summary>The server is a directory service domain controller (<c>DS_DS_FLAG</c>).</summary>
    DirectoryService = 0x00000010,

    /// <summary>The server is running the KDC service (<c>DS_KDC_FLAG</c>).</summary>
    Kdc = 0x00000020,

    /// <summary>The server is running the time service (<c>DS_TIMESERV_FLAG</c>).</summary>
    TimeServer = 0x00000040,

    /// <summary>The server is in the closest site to the client (<c>DS_CLOSEST_FLAG</c>).</summary>
    Closest = 0x00000080,

    /// <summary>The server has a writable directory (<c>DS_WRITABLE_FLAG</c>).</summary>
    Writable = 0x00000100,

    /// <summary>The server is a reliable time service (<c>DS_GOOD_TIMESERV_FLAG</c>).</summary>
    GoodTimeServer = 0x00000200,

    /// <summary>The name is a non-domain naming context served by LDAP (<c>DS_NDNC_FLAG</c>).</summary>
    NonDomainNamingContext = 0x00000400,

    /// <summary>The server holds a selective set of secrets (<c>DS_SELECT_SECRET_DOMAIN_6_FLAG</c>).</summary>
    SelectSecretDomain = 0x00000800,

    /// <summary>The server holds all secrets (<c>DS_FULL_SECRET_DOMAIN_6_FLAG</c>).</summary>
    FullSecretDomain = 0x00001000,

    /// <summary>The server is running the web service (<c>DS_WS_FLAG</c>).</summary>
    WebService = 0x00002000,

    /// <summary>The server runs Windows Server 2012 or later (<c>DS_DS_8_FLAG</c>).</summary>
    DirectoryService8 = 0x00004000,

    /// <summary>The server runs Windows Server 2012 R2 or later (<c>DS_DS_9_FLAG</c>).</summary>
    DirectoryService9 = 0x00008000,

    /// <summary>The server runs Windows Server 2016 or later (<c>DS_DS_10_FLAG</c>).</summary>
    DirectoryService10 = 0x00010000,

    /// <summary>The server supports key list requests (<c>DS_KEY_LIST_FLAG</c>).</summary>
    KeyList = 0x00020000,

    /// <summary>The server runs Windows Server 2025 or later (<c>DS_DS_13_FLAG</c>).</summary>
    DirectoryService13 = 0x00040000,

    /// <summary>The server runs Windows Server 2022 or later (<c>DS_DS_12_FLAG</c>).</summary>
    DirectoryService12 = 0x00080000,

    /// <summary>The KDC name returned is a DNS name (<c>DS_DNS_CONTROLLER_FLAG</c>).</summary>
    DnsController = 0x20000000,

    /// <summary>The domain name is a DNS name (<c>DS_DNS_DOMAIN_FLAG</c>).</summary>
    DnsDomain = 0x40000000,

    /// <summary>The forest name is a DNS name (<c>DS_DNS_FOREST_FLAG</c>).</summary>
    DnsForest = 0x80000000,
}
