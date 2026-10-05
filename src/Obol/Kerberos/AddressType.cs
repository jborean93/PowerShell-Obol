namespace Obol.Kerberos;

/// <summary>
/// The type of a host address in a ticket or request, RFC 4120 7.5.3. A type without a name is shown as its number.
/// </summary>
public enum AddressType
{
    /// <summary>An IPv4 address, 4 bytes.</summary>
    IPv4 = 2,

    /// <summary>A directional address, RFC 4120 7.1.</summary>
    Directional = 3,

    /// <summary>A NetBIOS name, 16 bytes padded with spaces.</summary>
    NetBios = 20,

    /// <summary>An IPv6 address, 16 bytes.</summary>
    IPv6 = 24,
}
