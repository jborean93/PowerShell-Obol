using System;

namespace Obol;

/// <summary>The flags of a binding cache entry itself, rather than of its KDC.</summary>
/// <remarks>
/// The <c>CacheFlags</c> member of <c>KERB_BINDING_CACHE_ENTRY_DATA</c>, <see cref="NoDcFlags"/> is the only
/// documented value. Like <c>KdcName</c> it is expected to be set for an entry the SSP found through the DC locator,
/// an entry added by hand with <c>Add-ObolSspiKdc</c> has <see cref="None"/>.
/// </remarks>
[Flags]
public enum ObolSspiKdcCacheFlags : uint
{
    /// <summary>No flags.</summary>
    None = 0,

    /// <summary>No DC flags were found for the KDC (<c>KERB_NO_DC_FLAGS</c>).</summary>
    NoDcFlags = 0x10000000,
}
