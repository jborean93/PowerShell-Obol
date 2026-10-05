using System;
using System.Net;

namespace Obol;

/// <summary>A DNS query or LDAP ping to the DC locator listeners and the reply sent.</summary>
/// <remarks>
/// The listener sets the transport details and the processor the rest as it goes, so a request that fails part way
/// through still reports what was read of it. <see cref="ObolDnsEvent"/> and <see cref="ObolLdapEvent"/> are the
/// public views.
/// </remarks>
internal abstract class DcLocatorExchange
{
    /// <summary>The local time the request was received.</summary>
    public DateTime Time { get; set; }

    /// <summary>How long processing the request took.</summary>
    public TimeSpan Duration { get; set; }

    /// <summary>The address and port the request was sent from.</summary>
    public IPEndPoint? ClientAddress { get; set; }

    /// <summary>The address the request was received on, the address of a KDC.</summary>
    public IPAddress LocalAddress { get; set; } = IPAddress.None;

    /// <summary>The request as received.</summary>
    public byte[] RequestBytes { get; set; } = [];

    /// <summary>The reply to send, null if the request is not answered.</summary>
    public byte[]? ReplyBytes { get; set; }

    /// <summary>The exception that stopped the request from being answered, if any.</summary>
    public Exception? Exception { get; set; }
}
