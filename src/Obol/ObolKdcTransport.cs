using System;

namespace Obol;

/// <summary>The transports a KDC listens on, RFC 4120 7.2.</summary>
[Flags]
public enum ObolKdcTransport
{
    /// <summary>Kerberos over TCP.</summary>
    Tcp = 1,

    /// <summary>Kerberos over UDP.</summary>
    Udp = 2,
}
