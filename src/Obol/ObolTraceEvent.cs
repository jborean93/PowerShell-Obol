using System;
using System.Net;

namespace Obol;

/// <summary>A request answered for an <see cref="ObolKdc"/> and the reply sent, as output by <c>Trace-ObolKdc</c>.
/// </summary>
/// <remarks>
/// The base of <see cref="ObolKdcEvent"/> for a Kerberos request, and <see cref="ObolDnsEvent"/> and
/// <see cref="ObolLdapEvent"/> for the DC locator requests of a <c>DcLocator</c> SSPI environment.
/// </remarks>
public abstract class ObolTraceEvent : EventArgs
{
    private protected ObolTraceEvent(
        ObolKdc kdc,
        DateTime time,
        TimeSpan duration,
        ObolKdcTransport transport,
        IPEndPoint? clientAddress)
    {
        Kdc = kdc;
        Time = time;
        Duration = duration;
        Transport = transport;
        ClientAddress = clientAddress;
    }

    /// <summary>A one line summary of the request and its reply.</summary>
    public abstract string Message { get; }

    /// <summary>The KDC the request was answered for.</summary>
    public ObolKdc Kdc { get; }

    /// <summary>The realm of the KDC.</summary>
    public string Realm => Kdc.Realm;

    /// <summary>The local time the request was received.</summary>
    public DateTime Time { get; }

    /// <summary>How long it took to process the request, not including the network.</summary>
    public TimeSpan Duration { get; }

    /// <summary>The transport the request arrived on, <c>Tcp</c> or <c>Udp</c>.</summary>
    public ObolKdcTransport Transport { get; }

    /// <summary>The address and port the client sent the request from, null if it was already gone.</summary>
    public IPEndPoint? ClientAddress { get; }

    public override string ToString() => Message;
}
