using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Obol.Protocol;

namespace Obol;

/// <summary>Accepts Kerberos requests over TCP and UDP and passes them to the <see cref="KdcProcessor"/>.</summary>
/// <remarks>
/// Kerberos.NET has its own TCP listener but it does not expose the bound endpoint, which is needed to listen on a
/// random port, does not wait for the connections to close when stopped and has no UDP support.
/// </remarks>
internal sealed class KdcListener : IDisposable
{
    /// <summary>The largest TCP request accepted, RFC 4120 7.2.2 lets the KDC set its own limit.</summary>
    private const int MaxRequestLength = 1024 * 1024;

    /// <summary>The largest UDP datagram that can be received.</summary>
    private const int MaxDatagramLength = 65535;

    /// <summary>The default largest UDP reply, the default of the MIT KDC max_dgram_reply_size setting.</summary>
    public const int DefaultMaxUdpReplySize = 4096;

    /// <summary>The largest UDP payload that can be sent over IPv4.</summary>
    public const int MaxUdpPayloadSize = 65507;

    /// <summary>How many random ports are tried to find one free for both TCP and UDP.</summary>
    private const int RandomPortAttempts = 10;

    /// <summary>How long to wait for the receive loops and requests to finish when stopping.</summary>
    private static readonly TimeSpan s_stopTimeout = TimeSpan.FromSeconds(5);

    /// <summary>The first delay after a socket error, doubled on each consecutive error.</summary>
    private static readonly TimeSpan s_minErrorDelay = TimeSpan.FromMilliseconds(10);

    /// <summary>The longest delay between retries after consecutive socket errors.</summary>
    private static readonly TimeSpan s_maxErrorDelay = TimeSpan.FromSeconds(1);

    /// <summary>Disables reporting ICMP port unreachable as a receive error on a Windows UDP socket.</summary>
    private const int SIO_UDP_CONNRESET = -1744830452;

    private readonly KdcProcessor _processor;
    private readonly Socket? _tcpSocket;
    private readonly Socket? _udpSocket;
    private readonly CancellationTokenSource _cts = new();
    private readonly HashSet<Task> _requests = [];
    private Action<Exception>? _onFault;
    private Action<KdcExchange>? _onExchange;
    private Task _tcpAcceptTask = Task.CompletedTask;
    private Task _udpReceiveTask = Task.CompletedTask;
    private int _disposed;

    private KdcListener(KdcProcessor processor, Socket? tcpSocket, Socket? udpSocket, int maxUdpReplySize)
    {
        _processor = processor;
        _tcpSocket = tcpSocket;
        _udpSocket = udpSocket;
        MaxUdpReplySize = maxUdpReplySize;
        Endpoint = (IPEndPoint)(tcpSocket ?? udpSocket)!.LocalEndPoint!;
        Transport = (tcpSocket is null ? 0 : ObolKdcTransport.Tcp) | (udpSocket is null ? 0 : ObolKdcTransport.Udp);
    }

    /// <summary>The endpoint the listener is bound to, the same port is used for TCP and UDP.</summary>
    public IPEndPoint Endpoint { get; }

    /// <summary>The transports the listener is bound to.</summary>
    public ObolKdcTransport Transport { get; }

    /// <summary>
    /// The largest UDP reply sent, larger replies are replaced by KRB_ERR_RESPONSE_TOO_BIG so the client retries
    /// over TCP.
    /// </summary>
    public int MaxUdpReplySize { get; }

    /// <summary>Creates the KDC and binds the endpoint for the transports requested.</summary>
    /// <param name="store">The principals of the realm.</param>
    /// <param name="endpoint">The endpoint to bind, port 0 picks a port that is free for every transport.</param>
    /// <param name="transport">The transports to listen on.</param>
    /// <param name="maxUdpReplySize">The largest UDP reply to send.</param>
    public static KdcListener Bind(
        PrincipalStore store,
        IPEndPoint endpoint,
        ObolKdcTransport transport,
        int maxUdpReplySize)
    {
        (Socket? tcpSocket, Socket? udpSocket) = BindSockets(
            endpoint,
            transport.HasFlag(ObolKdcTransport.Tcp),
            transport.HasFlag(ObolKdcTransport.Udp));

        return new(new KdcProcessor(store), tcpSocket, udpSocket, maxUdpReplySize);
    }

    /// <summary>Starts accepting requests.</summary>
    /// <param name="onFault">Called if a receive loop fails unexpectedly and the listener should be stopped.</param>
    /// <param name="onExchange">
    /// Called with each request and its reply before the reply is sent, on the thread that processed the request.
    /// An exception it throws is ignored.
    /// </param>
    public void Start(Action<Exception> onFault, Action<KdcExchange>? onExchange = null)
    {
        _onFault = onFault;
        _onExchange = onExchange;
        if (_tcpSocket is not null)
        {
            _tcpAcceptTask = Task.Run(() => RunLoopAsync(TcpAcceptLoopAsync));
        }
        if (_udpSocket is not null)
        {
            _udpReceiveTask = Task.Run(() => RunLoopAsync(UdpReceiveLoopAsync));
        }
    }

    private static (Socket? Tcp, Socket? Udp) BindSockets(IPEndPoint endpoint, bool tcp, bool udp)
    {
        // A random TCP port may already be used for UDP, try a few before giving up. On Windows the port can also be
        // in a range reserved for UDP only, such as by Hyper-V or WinNAT, which fails with access denied.
        int attempts = endpoint.Port == 0 && tcp && udp ? RandomPortAttempts : 1;
        for (int i = 1; ; i++)
        {
            Socket? tcpSocket = null;
            Socket? udpSocket = null;
            try
            {
                IPEndPoint bindEndpoint = endpoint;
                if (tcp)
                {
                    tcpSocket = CreateSocket(endpoint, SocketType.Stream, ProtocolType.Tcp);
                    tcpSocket.Bind(endpoint);
                    tcpSocket.Listen();
                    bindEndpoint = (IPEndPoint)tcpSocket.LocalEndPoint!;
                }
                if (udp)
                {
                    udpSocket = CreateSocket(endpoint, SocketType.Dgram, ProtocolType.Udp);
                    if (OperatingSystem.IsWindows())
                    {
                        udpSocket.IOControl(SIO_UDP_CONNRESET, [0, 0, 0, 0], null);
                    }
                    udpSocket.Bind(bindEndpoint);
                }

                return (tcpSocket, udpSocket);
            }
            catch (SocketException e) when (
                e.SocketErrorCode is SocketError.AddressAlreadyInUse or SocketError.AccessDenied
                && udpSocket is not null
                && i < attempts)
            {
                tcpSocket?.Dispose();
                udpSocket.Dispose();
            }
            catch
            {
                tcpSocket?.Dispose();
                udpSocket?.Dispose();
                throw;
            }
        }
    }

    private static Socket CreateSocket(IPEndPoint endpoint, SocketType socketType, ProtocolType protocolType)
    {
        Socket socket = new(endpoint.AddressFamily, socketType, protocolType);
        if (endpoint.Address.Equals(IPAddress.IPv6Any))
        {
            socket.DualMode = true;
        }
        return socket;
    }

    /// <summary>Runs a receive loop and reports an unexpected failure so the KDC can be marked as faulted.</summary>
    private async Task RunLoopAsync(Func<CancellationToken, Task> loop)
    {
        CancellationToken cancelToken = _cts.Token;
        try
        {
            await loop(cancelToken).ConfigureAwait(false);
        }
        catch (Exception) when (cancelToken.IsCancellationRequested)
        {
            // The listener is stopping.
        }
        catch (Exception e)
        {
            _onFault?.Invoke(e);
        }
    }

    /// <summary>Waits before retrying after a socket error so a persistent error does not spin the CPU.</summary>
    /// <returns>The delay to use after the next consecutive error.</returns>
    private static async Task<TimeSpan> DelayAfterErrorAsync(TimeSpan delay, CancellationToken cancelToken)
    {
        await Task.Delay(delay, cancelToken).ConfigureAwait(false);
        TimeSpan next = delay * 2;
        return next > s_maxErrorDelay ? s_maxErrorDelay : next;
    }

    /// <summary>Errors caused by a single client that do not affect the listening socket.</summary>
    private static bool IsClientError(SocketError error)
        => error is SocketError.ConnectionReset or SocketError.ConnectionAborted or SocketError.ConnectionRefused;

    private void TrackRequest(Task request)
    {
        lock (_requests)
        {
            _requests.Add(request);
        }
        _ = request.ContinueWith(
            t =>
            {
                lock (_requests)
                {
                    _requests.Remove(t);
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private async Task TcpAcceptLoopAsync(CancellationToken cancelToken)
    {
        TimeSpan errorDelay = s_minErrorDelay;
        while (true)
        {
            Socket client;
            try
            {
                client = await _tcpSocket!.AcceptAsync(cancelToken).ConfigureAwait(false);
            }
            catch (SocketException e) when (!cancelToken.IsCancellationRequested)
            {
                // A client that disconnects before the accept completes should not stop the listener. Other
                // errors, like running out of file descriptors, may clear up so retry with a delay.
                if (!IsClientError(e.SocketErrorCode))
                {
                    errorDelay = await DelayAfterErrorAsync(errorDelay, cancelToken).ConfigureAwait(false);
                }
                continue;
            }

            errorDelay = s_minErrorDelay;
            TrackRequest(HandleTcpConnectionAsync(client, cancelToken));
        }
    }

    /// <summary>Processes each request on the connection until the client closes it.</summary>
    private async Task HandleTcpConnectionAsync(Socket client, CancellationToken cancelToken)
    {
        // Yield so a client that sends immediately does not run on the accept loop.
        await Task.Yield();

        try
        {
            IPEndPoint? remote = GetRemoteEndpoint(client);
            using NetworkStream stream = new(client, ownsSocket: true);
            byte[] lengthBuffer = new byte[4];
            while (true)
            {
                int read = await stream.ReadAtLeastAsync(lengthBuffer, lengthBuffer.Length,
                    throwOnEndOfStream: false, cancelToken).ConfigureAwait(false);
                if (read < lengthBuffer.Length)
                {
                    return;
                }

                // The high bit is reserved for extensions which are not supported, the int is negative when set.
                // RFC 4120 7.2.2 requires KRB_ERR_FIELD_TOOLONG for this, it is also used for a request over the
                // limit. The stream cannot be resynchronised so the connection is closed afterwards.
                int length = BinaryPrimitives.ReadInt32BigEndian(lengthBuffer);
                if (length < 0 || length > MaxRequestLength)
                {
                    string reason = length < 0
                        ? "Length prefix extensions are not supported"
                        : $"Request length {length} exceeds the limit of {MaxRequestLength} bytes";
                    KdcExchange error = _processor.CreateRequestTooLongExchange(reason);
                    error.Time = DateTime.Now;
                    error.Transport = ObolKdcTransport.Tcp;
                    error.ClientAddress = remote;
                    Report(error);
                    await WriteTcpResponseAsync(stream, error.ReplyBytes, cancelToken).ConfigureAwait(false);
                    return;
                }

                byte[] request = new byte[length];
                await stream.ReadExactlyAsync(request, cancelToken).ConfigureAwait(false);

                KdcExchange exchange = ProcessRequest(request, ObolKdcTransport.Tcp, remote);
                Report(exchange);
                await WriteTcpResponseAsync(stream, exchange.ReplyBytes, cancelToken).ConfigureAwait(false);
            }
        }
        catch (Exception e) when (e is OperationCanceledException or IOException or SocketException
            or ObjectDisposedException)
        {
            // The client went away or the listener is stopping.
        }
    }

    private static async Task WriteTcpResponseAsync(NetworkStream stream, ReadOnlyMemory<byte> response,
        CancellationToken cancelToken)
    {
        byte[] responseBuffer = new byte[response.Length + 4];
        BinaryPrimitives.WriteInt32BigEndian(responseBuffer, response.Length);
        response.CopyTo(responseBuffer.AsMemory(4));
        await stream.WriteAsync(responseBuffer, cancelToken).ConfigureAwait(false);
    }

    private async Task UdpReceiveLoopAsync(CancellationToken cancelToken)
    {
        EndPoint anyEndpoint = _udpSocket!.AddressFamily == AddressFamily.InterNetworkV6
            ? new IPEndPoint(IPAddress.IPv6Any, 0)
            : new IPEndPoint(IPAddress.Any, 0);
        byte[] buffer = new byte[MaxDatagramLength];
        TimeSpan errorDelay = s_minErrorDelay;

        while (true)
        {
            SocketReceiveFromResult result;
            try
            {
                result = await _udpSocket.ReceiveFromAsync(buffer, SocketFlags.None, anyEndpoint, cancelToken)
                    .ConfigureAwait(false);
            }
            catch (SocketException e) when (!cancelToken.IsCancellationRequested)
            {
                // An ICMP error from an earlier reply can be reported as a receive error, other errors may clear
                // up so retry with a delay.
                if (!IsClientError(e.SocketErrorCode))
                {
                    errorDelay = await DelayAfterErrorAsync(errorDelay, cancelToken).ConfigureAwait(false);
                }
                continue;
            }

            errorDelay = s_minErrorDelay;
            if (result.ReceivedBytes == 0)
            {
                continue;
            }

            byte[] request = buffer.AsSpan(0, result.ReceivedBytes).ToArray();
            TrackRequest(HandleUdpRequestAsync(request, result.RemoteEndPoint, cancelToken));
        }
    }

    private async Task HandleUdpRequestAsync(byte[] request, EndPoint remoteEndpoint, CancellationToken cancelToken)
    {
        try
        {
            KdcExchange exchange = ProcessRequest(request, ObolKdcTransport.Udp, remoteEndpoint as IPEndPoint);
            if (exchange.ReplyBytes.Length > MaxUdpReplySize)
            {
                // This is sent even if it is over the limit itself, the client needs a reply to retry over TCP.
                _processor.ReplaceResponseTooBig(exchange,
                    $"Response of {exchange.ReplyBytes.Length} bytes is too big for UDP, retry over TCP");
            }
            Report(exchange);

            await _udpSocket!.SendToAsync(exchange.ReplyBytes, SocketFlags.None, remoteEndpoint, cancelToken)
                .ConfigureAwait(false);
        }
        catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException)
        {
            // The listener is stopping or the reply could not be sent, UDP clients retry on their own.
        }
    }

    /// <summary>Processes a request and records when it arrived, how long it took and where it came from.</summary>
    private KdcExchange ProcessRequest(byte[] request, ObolKdcTransport transport, IPEndPoint? remote)
    {
        DateTime time = DateTime.Now;
        long start = Stopwatch.GetTimestamp();
        KdcExchange exchange = _processor.Process(request);
        exchange.Duration = Stopwatch.GetElapsedTime(start);
        exchange.Time = time;
        exchange.Transport = transport;
        exchange.ClientAddress = remote;
        return exchange;
    }

    /// <summary>Reports an exchange to the callback, a failure in it must not stop the reply.</summary>
    private void Report(KdcExchange exchange)
    {
        try
        {
            _onExchange?.Invoke(exchange);
        }
        catch (Exception)
        {
            // The callback is not the KDC's concern, the client still gets its reply.
        }
    }

    private static IPEndPoint? GetRemoteEndpoint(Socket client)
    {
        try
        {
            return client.RemoteEndPoint as IPEndPoint;
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException)
        {
            // The client already went away.
            return null;
        }
    }

    public void Dispose()
    {
        // This can be called by the fault handler and the KDC at the same time.
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _cts.Cancel();
        _tcpSocket?.Dispose();
        _udpSocket?.Dispose();

        // The tasks handle their own exceptions, this only waits for them to finish. The receive loops are waited
        // on first so no new requests are added after the snapshot.
        DateTime deadline = DateTime.UtcNow + s_stopTimeout;
        bool finished = Task.WaitAll([_tcpAcceptTask, _udpReceiveTask], s_stopTimeout);
        if (finished)
        {
            Task[] requests;
            lock (_requests)
            {
                requests = [.. _requests];
            }
            TimeSpan remaining = deadline - DateTime.UtcNow;
            finished = Task.WaitAll(requests, remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero);
        }

        // A request still running after the timeout may yet use the token.
        if (finished)
        {
            _cts.Dispose();
        }
    }
}
