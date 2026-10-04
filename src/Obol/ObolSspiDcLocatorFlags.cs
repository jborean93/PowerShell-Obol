using System;

namespace Obol;

/// <summary>
/// The <c>DsGetDcName</c> request flags (<c>DS_*</c>) the SSP uses to locate the KDC of a binding cache entry.
/// </summary>
/// <remarks>
/// The <c>Flags</c> member of <c>KERB_BINDING_CACHE_ENTRY_DATA</c>. These are the requirements passed to
/// <c>DsGetDcName</c>, unlike <see cref="ObolSspiDcFlags"/> which are the flags it returns for the KDC found. For an
/// entry added with <c>Add-ObolSspiKdc</c> the SSP sets them from the DC flags, <c>Kdc, Writable</c> gives
/// <see cref="WritableRequired"/> and <see cref="TryNextClosestSite"/>.
/// </remarks>
[Flags]
public enum ObolSspiDcLocatorFlags : uint
{
    /// <summary>No flags.</summary>
    None = 0,

    /// <summary>Ignores cached DC data and does a fresh discovery (<c>DS_FORCE_REDISCOVERY</c>).</summary>
    ForceRediscovery = 0x00000001,

    /// <summary>The DC must support directory services (<c>DS_DIRECTORY_SERVICE_REQUIRED</c>).</summary>
    DirectoryServiceRequired = 0x00000010,

    /// <summary>A DC that supports directory services is preferred (<c>DS_DIRECTORY_SERVICE_PREFERRED</c>).</summary>
    DirectoryServicePreferred = 0x00000020,

    /// <summary>The DC must be a global catalog server (<c>DS_GC_SERVER_REQUIRED</c>).</summary>
    GcServerRequired = 0x00000040,

    /// <summary>The DC must be the PDC of the domain (<c>DS_PDC_REQUIRED</c>).</summary>
    PdcRequired = 0x00000080,

    /// <summary>Uses cached DC data even when it is expired (<c>DS_BACKGROUND_ONLY</c>).</summary>
    BackgroundOnly = 0x00000100,

    /// <summary>The DC must have an IP address (<c>DS_IP_REQUIRED</c>).</summary>
    IpRequired = 0x00000200,

    /// <summary>The DC must be running the KDC service (<c>DS_KDC_REQUIRED</c>).</summary>
    KdcRequired = 0x00000400,

    /// <summary>The DC must be running the time service (<c>DS_TIMESERV_REQUIRED</c>).</summary>
    TimeServerRequired = 0x00000800,

    /// <summary>The DC must host a writable copy of the directory (<c>DS_WRITABLE_REQUIRED</c>).</summary>
    WritableRequired = 0x00001000,

    /// <summary>A DC that is a reliable time server is preferred (<c>DS_GOOD_TIMESERV_PREFERRED</c>).</summary>
    GoodTimeServerPreferred = 0x00002000,

    /// <summary>The DC returned is not the current computer (<c>DS_AVOID_SELF</c>).</summary>
    AvoidSelf = 0x00004000,

    /// <summary>Only an LDAP server is needed, not necessarily a DC (<c>DS_ONLY_LDAP_NEEDED</c>).</summary>
    OnlyLdapNeeded = 0x00008000,

    /// <summary>The domain name is a flat (NetBIOS) name (<c>DS_IS_FLAT_NAME</c>).</summary>
    IsFlatName = 0x00010000,

    /// <summary>The domain name is a DNS name (<c>DS_IS_DNS_NAME</c>).</summary>
    IsDnsName = 0x00020000,

    /// <summary>Tries the next closest site when none is in the caller's (<c>DS_TRY_NEXTCLOSEST_SITE</c>).</summary>
    TryNextClosestSite = 0x00040000,

    /// <summary>The DC must run Windows Server 2008 or later (<c>DS_DIRECTORY_SERVICE_6_REQUIRED</c>).</summary>
    DirectoryService6Required = 0x00080000,

    /// <summary>The DC must be running the web service (<c>DS_WEB_SERVICE_REQUIRED</c>).</summary>
    WebServiceRequired = 0x00100000,

    /// <summary>The DC must run Windows Server 2012 or later (<c>DS_DIRECTORY_SERVICE_8_REQUIRED</c>).</summary>
    DirectoryService8Required = 0x00200000,

    /// <summary>The names returned are DNS names (<c>DS_RETURN_DNS_NAME</c>).</summary>
    ReturnDnsName = 0x40000000,

    /// <summary>The names returned are flat names (<c>DS_RETURN_FLAT_NAME</c>).</summary>
    ReturnFlatName = 0x80000000,
}
