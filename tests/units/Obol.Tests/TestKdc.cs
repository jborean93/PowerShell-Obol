using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Obol.Protocol;

namespace Obol.Tests;

/// <summary>A KDC listening on a random loopback port with the principal store exposed for the test.</summary>
internal sealed class TestKdc : IDisposable
{
    public const string Realm = "EXAMPLE.TEST";
    public const string Password = "Password123!";

    private readonly KdcListener _listener;

    public TestKdc(
        bool caseInsensitive = false,
        ObolKdcTransport transport = ObolKdcTransport.Tcp,
        bool start = true,
        int maxUdpReplySize = KdcListener.DefaultMaxUdpReplySize)
    {
        // Registered with the test so TestKdcHooks fails the test if the listener faults.
        TestContext.Current?.StateBag
            .GetOrAdd(TestKdcHooks.StateBagKey, _ => new ConcurrentQueue<TestKdc>())
            .Enqueue(this);

        Store = new PrincipalStore(Realm, caseInsensitive);
        _listener = KdcListener.Bind(Store, new IPEndPoint(IPAddress.Loopback, 0), transport, maxUdpReplySize);
        if (start)
        {
            Start();
        }
    }

    /// <summary>Starts answering requests, for a KDC created with start set to false.</summary>
    public void Start() => _listener.Start(e => Fault = e, Exchanges.Enqueue);

    public PrincipalStore Store { get; }

    /// <summary>The requests the listener answered, in the order they were processed.</summary>
    public ConcurrentQueue<KdcExchange> Exchanges { get; } = new();

    public Exception? Fault { get; private set; }

    public IPEndPoint Endpoint => _listener.Endpoint;

    public ObolPrincipal AddUser(
        string name,
        string password = Password,
        Kerberos.PacUserAccountControl flags = Kerberos.PacUserAccountControl.None,
        EncryptionType[]? encryptionTypes = null)
        => Store.Create(name.Split('/'), ToSecureString(password), flags,
            ToObolEncryptionTypes(encryptionTypes));

    public ObolPrincipal AddService(string name, EncryptionType[]? encryptionTypes = null, string[]? aliases = null)
        => Store.Create(name.Split('/'), password: null, flags: Kerberos.PacUserAccountControl.None,
            ToObolEncryptionTypes(encryptionTypes), aliases?.Select(a => a.Split('/')).ToArray());

    private static Kerberos.EncryptionType[]? ToObolEncryptionTypes(EncryptionType[]? types)
        => types?.Select(t => (Kerberos.EncryptionType)t).ToArray();

    public KerberosClient CreateClient()
    {
        KerberosClient client = new();
        client.Configuration.Defaults.DnsLookupKdc = false;
        client.PinKdc(Realm, Endpoint.ToString());
        return client;
    }

    public void Dispose() => _listener.Dispose();

    /// <summary>Sends a request over TCP and returns the reply.</summary>
    public async Task<byte[]> SendTcpAsync(ReadOnlyMemory<byte> request)
    {
        using TcpClient client = new();
        await client.ConnectAsync(Endpoint);
        using NetworkStream stream = client.GetStream();
        byte[] length = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, request.Length);
        await stream.WriteAsync(length);
        await stream.WriteAsync(request);

        await stream.ReadExactlyAsync(length);
        byte[] reply = new byte[BinaryPrimitives.ReadInt32BigEndian(length)];
        await stream.ReadExactlyAsync(reply);
        return reply;
    }

    /// <summary>Sends a request over UDP and returns the reply.</summary>
    public async Task<byte[]> SendUdpAsync(ReadOnlyMemory<byte> request)
    {
        using UdpClient client = new(Endpoint.AddressFamily);
        await client.SendAsync(request, Endpoint);
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        UdpReceiveResult result = await client.ReceiveAsync(timeout.Token);
        return result.Buffer;
    }

    /// <summary>The client's cached TGT.</summary>
    public static KerberosClientCacheEntry GetTgt(KerberosClient client)
        => client.Cache.GetCacheItem<KerberosClientCacheEntry>($"krbtgt/{Realm}");

    /// <summary>Decrypts a service ticket with the service's key for its encryption type.</summary>
    public static KrbEncTicketPart DecryptTicket(KrbTicket ticket, ObolPrincipal service)
        => ticket.EncryptedPart.Decrypt(
            service.State.GetKey(ticket.EncryptedPart.EType.ToObol())!,
            KeyUsage.Ticket,
            b => KrbEncTicketPart.DecodeApplication(b));

    public static SecureString ToSecureString(string value)
    {
        SecureString secure = new();
        foreach (char c in value)
        {
            secure.AppendChar(c);
        }
        secure.MakeReadOnly();
        return secure;
    }
}
