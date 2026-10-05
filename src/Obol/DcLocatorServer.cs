using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Obol;

/// <summary>
/// The DNS server and CLDAP responder the Windows DC locator uses to find the KDCs of a DC locator SSPI environment.
/// </summary>
/// <remarks>
/// The DNS client only sends queries to port 53 and the locator only pings UDP port 389 of the address in the DNS
/// reply, so neither port can be changed. Both listen on the address of each KDC, like a domain controller that is
/// also the DNS server, so the address of the KDC picks the address of everything. The NRPT rule of a realm points
/// at the addresses of its KDCs.
/// </remarks>
internal sealed class DcLocatorServer : IDisposable
{
    /// <summary>The port the DNS client sends queries to.</summary>
    public const int DnsPort = 53;

    /// <summary>The port the DC locator sends the LDAP ping to.</summary>
    public const int LdapPort = 389;


    /// <summary>The largest UDP datagram that can be received.</summary>
    private const int MaxDatagramLength = 65535;

    /// <summary>Disables reporting ICMP port unreachable as a receive error on a Windows UDP socket.</summary>
    private const int SIO_UDP_CONNRESET = -1744830452;

    private static readonly TimeSpan s_stopTimeout = TimeSpan.FromSeconds(5);

    private readonly CancellationTokenSource _cts = new();
    private readonly List<Task> _loops = [];
    private readonly List<Socket> _sockets = [];

    private DcLocatorServer()
    {
    }

    /// <summary>Binds the DNS and CLDAP sockets for the domains and starts answering.</summary>
    /// <exception cref="SspiKdcException">A port could not be bound, such as when a DNS server uses it.</exception>
    public static DcLocatorServer Start(IReadOnlyList<DcLocatorDomain> domains)
    {
        DcLocatorDns dns = new(domains);
        DcLocatorLdap ldap = new(domains);

        DcLocatorServer server = new();
        try
        {
            // Every socket is bound before any is answered so a port in use fails without answering anything.
            List<(Socket Dns, Socket Ldap, IPAddress Address)> sockets = [];
            foreach (IPAddress address in domains.SelectMany(d => d.Kdcs).Select(k => k.Address).Distinct())
            {
                sockets.Add((server.Bind(new(address, DnsPort)), server.Bind(new(address, LdapPort)), address));
            }

            foreach ((Socket dnsSocket, Socket ldapSocket, IPAddress address) in sockets)
            {
                server.Run(dnsSocket, (request, _) => dns.Process(request.Span));
                server.Run(ldapSocket, (request, _) => ldap.Process(request, address));
            }
        }
        catch
        {
            server.Dispose();
            throw;
        }
        return server;
    }

    private Socket Bind(IPEndPoint endpoint)
    {
        Socket socket = new(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        _sockets.Add(socket);
        if (OperatingSystem.IsWindows())
        {
            socket.IOControl(SIO_UDP_CONNRESET, [0, 0, 0, 0], null);
        }
        // Another process bound to the port with SO_REUSEADDR must not be able to take the datagrams.
        socket.ExclusiveAddressUse = true;
        try
        {
            socket.Bind(endpoint);
        }
        catch (SocketException e)
        {
            string service = endpoint.Port == DnsPort ? "DNS server" : "LDAP ping responder";
            string hint = e.SocketErrorCode is SocketError.AddressAlreadyInUse or SocketError.AccessDenied
                ? ", another process such as a DNS server or domain controller may be using it. The DNS server and " +
                    "LDAP ping responder listen on the KDC address, start the KDC on another address such as " +
                    "127.0.0.2 with -Address."
                : "";
            throw SspiKdcException.Create($"Failed to start the DC locator {service} on UDP {endpoint}: " +
                $"{e.Message}{hint}");
        }
        return socket;
    }

    private void Run(Socket socket, Func<ReadOnlyMemory<byte>, IPEndPoint, byte[]?> process)
        => _loops.Add(Task.Run(() => ReceiveLoopAsync(socket, process, _cts.Token)));

    private static async Task ReceiveLoopAsync(
        Socket socket,
        Func<ReadOnlyMemory<byte>, IPEndPoint, byte[]?> process,
        CancellationToken cancelToken)
    {
        byte[] buffer = new byte[MaxDatagramLength];
        EndPoint any = new IPEndPoint(
            socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
        while (!cancelToken.IsCancellationRequested)
        {
            try
            {
                SocketReceiveFromResult result = await socket.ReceiveFromAsync(buffer, any, cancelToken)
                    .ConfigureAwait(false);
                IPEndPoint remote = (IPEndPoint)result.RemoteEndPoint;

                byte[]? reply;
                try
                {
                    reply = process(buffer.AsMemory(0, result.ReceivedBytes), remote);
                }
                catch (Exception)
                {
                    // A request the parsers did not expect is dropped, the client retries or gives up.
                    reply = null;
                }

                if (reply is not null)
                {
                    await socket.SendToAsync(reply, remote, cancelToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException)
            {
                // A failed receive or send only loses that datagram.
                await Task.Delay(10, CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        foreach (Socket socket in _sockets)
        {
            socket.Dispose();
        }
        try
        {
            Task.WaitAll([.. _loops], s_stopTimeout);
        }
        catch (AggregateException)
        {
            // The loops catch everything they expect, there is nothing to report an unexpected failure to.
        }
        _cts.Dispose();
    }
}
