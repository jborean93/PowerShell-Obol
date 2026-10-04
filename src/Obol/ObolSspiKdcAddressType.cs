namespace Obol;

/// <summary>How the KDC address of a binding cache entry is interpreted.</summary>
/// <remarks>
/// The values match the <c>DS_*_ADDRESS</c> constants used by the DC locator. Obol infers it from the address when
/// adding an entry, see <see cref="Obol.Commands.SspiCommandHelper.InferAddressType"/>, and reads it back from the
/// <c>AddressType</c> of the binding cache entry.
/// </remarks>
public enum ObolSspiKdcAddressType
{
    /// <summary>An IP address or DNS host name (<c>DS_INET_ADDRESS</c>).</summary>
    Inet = 1,

    /// <summary>A NetBIOS computer name (<c>DS_NETBIOS_ADDRESS</c>).</summary>
    NetBios = 2,
}
