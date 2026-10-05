using System;
using System.Net;
using System.Text;

namespace Obol.Kerberos;

/// <summary>A HostAddress of RFC 4120 5.2.5, an address a ticket is restricted to.</summary>
public sealed class HostAddress
{
    internal HostAddress(AddressType addressType, byte[] address)
    {
        AddressType = addressType;
        Address = address;
    }

    /// <summary>The address type, such as <c>IPv4</c>, a type without a name is shown as its number.</summary>
    public AddressType AddressType { get; }

    /// <summary>The address bytes.</summary>
    public byte[] Address { get; }

    public override string ToString() => AddressType switch
    {
        AddressType.IPv4 or AddressType.IPv6 when Address.Length is 4 or 16
            => new IPAddress(Address).ToString(),
        AddressType.NetBios => Encoding.ASCII.GetString(Address).TrimEnd(),
        _ => $"{AddressType} {Convert.ToHexString(Address)}",
    };
}
