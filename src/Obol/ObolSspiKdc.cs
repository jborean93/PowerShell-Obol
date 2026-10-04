using System;

namespace Obol;

/// <summary>
/// A KDC that has been cached in the Windows Kerberos SSP.
/// </summary>
/// <remarks>
/// <see cref="Scope"/> says whether it has been bound/cached at the thread or machien level. A <c>Thread</c> entry
/// comes from Obol's own per-thread record (LSASS has no read-back) and only sets the properties common to both. A
/// <c>Machine</c> entry is a live read of the LSASS binding cache (KERB_BINDING_CACHE_ENTRY_DATA) and also sets
/// <see cref="KdcName"/>, <see cref="AddressType"/>, <see cref="BindingFlags"/> and <see cref="CacheFlags"/>.
/// <see cref="Realm"/>, <see cref="KdcAddress"/>, <see cref="DcFlags"/> and <see cref="DiscoveryTime"/> are set for
/// both.
/// </remarks>
public sealed class ObolSspiKdc
{
    private ObolSspiKdc(ObolSspiKdcScope scope, string realm, string kdcAddress, ObolSspiDcFlags dcFlags,
        DateTime discoveryTime)
    {
        Scope = scope;
        Realm = realm;
        KdcAddress = kdcAddress;
        DcFlags = dcFlags;
        DiscoveryTime = discoveryTime;
    }

    /// <summary>Whether this is a per-thread pin or a machine-wide binding.</summary>
    public ObolSspiKdcScope Scope { get; }

    /// <summary>The realm the entry steers.</summary>
    public string Realm { get; }

    /// <summary>The host name or IP address of the KDC. The port is always 88.</summary>
    public string KdcAddress { get; }

    /// <summary>For a thread pin the DC flags a request must match (None matches any). For a machine entry the DC
    /// flags DsGetDcName returned for an SSP-resolved KDC, or the flags supplied to Add-ObolSspiKdc for one added by
    /// hand (None if none were given).</summary>
    public ObolSspiDcFlags DcFlags { get; }

    /// <summary>The local time the entry was made: when Obol pinned it, or when the SSP cached the binding.</summary>
    /// <remarks>The SSP stores a binding's time as a GetTickCount64 value, it is converted when read.</remarks>
    public DateTime DiscoveryTime { get; }

    /// <summary>The KDC name resolved for the realm, often empty for a hand-added entry. Machine scope only.</summary>
    public string? KdcName { get; private init; }

    /// <summary>How <see cref="KdcAddress"/> is read, an internet or NetBIOS address. Machine scope only.</summary>
    public ObolSspiKdcAddressType? AddressType { get; private init; }

    /// <summary>The DsGetDcName request flags for locating the realm's KDC, set by the SSP from the DC flags. Machine
    /// scope only.</summary>
    public ObolSspiDcLocatorFlags? BindingFlags { get; private init; }

    /// <summary>Flags about the entry itself, None for an entry added by hand. Machine scope only.</summary>
    public ObolSspiKdcCacheFlags? CacheFlags { get; private init; }

    /// <summary>Builds a thread-scoped pin record made now.</summary>
    internal static ObolSspiKdc ForThread(string realm, string kdcAddress, ObolSspiDcFlags dcFlags)
        => new(ObolSspiKdcScope.Thread, realm, kdcAddress, dcFlags, DateTime.Now);

    /// <summary>Builds a machine-scoped binding cache entry.</summary>
    internal static ObolSspiKdc ForMachine(string realm, string kdcAddress, ObolSspiDcFlags dcFlags,
        DateTime discoveryTime, string kdcName, ObolSspiKdcAddressType addressType,
        ObolSspiDcLocatorFlags bindingFlags, ObolSspiKdcCacheFlags cacheFlags)
        => new(ObolSspiKdcScope.Machine, realm, kdcAddress, dcFlags, discoveryTime)
        {
            KdcName = kdcName,
            AddressType = addressType,
            BindingFlags = bindingFlags,
            CacheFlags = cacheFlags,
        };

    public override string ToString() => $"{Realm} -> {KdcAddress} ({Scope})";
}
