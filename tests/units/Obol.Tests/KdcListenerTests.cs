using System;
using System.Buffers.Binary;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Obol.Protocol;

namespace Obol.Tests;

/// <summary>The listener over UDP, the Kerberos.NET client prefers TCP so the replies are checked by hand.</summary>
public class KdcListenerTests
{
    private static (KerberosKey Key, ReadOnlyMemory<byte> Request) NewAsReq(TestKdc kdc)
    {
        ObolPrincipal user = kdc.AddUser("user");
        KerberosKey key = user.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;
        return (key, KdcProcessorTests.NewAsReq("user", key, DateTimeOffset.UtcNow).EncodeApplication());
    }

    private static KrbEncAsRepPart DecryptAsRep(byte[] reply, KerberosKey key)
        => KrbAsRep.DecodeApplication(reply).EncryptedPart.Decrypt(
            key,
            KeyUsage.EncAsRepPart,
            b => KrbEncAsRepPart.DecodeApplication(b));

    [Test]
    public async Task AnswersOverUdp()
    {
        using TestKdc kdc = new(transport: ObolKdcTransport.Udp);
        (KerberosKey key, ReadOnlyMemory<byte> request) = NewAsReq(kdc);

        byte[] reply = await kdc.SendUdpAsync(request);

        // An AS-REP with a PAC fits in the default limit so a client does not need TCP for it.
        await Assert.That(reply.Length).IsLessThanOrEqualTo(KdcListener.DefaultMaxUdpReplySize);
        await Assert.That(DecryptAsRep(reply, key).Nonce).IsEqualTo(1234);
    }

    [Test]
    public async Task ReplacesLargeUdpReplyWithError()
    {
        using TestKdc kdc = new(transport: ObolKdcTransport.Tcp | ObolKdcTransport.Udp, maxUdpReplySize: 200);
        (KerberosKey key, ReadOnlyMemory<byte> request) = NewAsReq(kdc);

        byte[] udpReply = await kdc.SendUdpAsync(request);
        byte[] tcpReply = await kdc.SendTcpAsync(request);

        // The client retries over TCP and gets the full reply.
        KrbError error = KrbError.DecodeApplication(udpReply);
        await Assert.That(error.ErrorCode).IsEqualTo(KerberosErrorCode.KRB_ERR_RESPONSE_TOO_BIG);
        await Assert.That(error.EText)
            .IsEqualTo($"Response of {tcpReply.Length} bytes is too big for UDP, retry over TCP");
        await Assert.That(tcpReply.Length).IsGreaterThan(200);
        await Assert.That(DecryptAsRep(tcpReply, key).Nonce).IsEqualTo(1234);
    }

    [Test]
    public async Task ReportsExchangeForEachTransport()
    {
        using TestKdc kdc = new(transport: ObolKdcTransport.Tcp | ObolKdcTransport.Udp);
        (_, ReadOnlyMemory<byte> request) = NewAsReq(kdc);
        DateTime before = DateTime.Now;

        byte[] tcpReply = await kdc.SendTcpAsync(request);
        byte[] udpReply = await kdc.SendUdpAsync(request);

        // The exchange is reported before the reply is sent so both are there once the replies arrived.
        KdcExchange[] exchanges = [.. kdc.Exchanges];
        await Assert.That(exchanges).Count().IsEqualTo(2);

        await Assert.That(exchanges[0].Transport).IsEqualTo(ObolKdcTransport.Tcp);
        await Assert.That(exchanges[0].RequestBytes.ToArray()).IsEquivalentTo(request.ToArray());
        await Assert.That(exchanges[0].ReplyBytes.ToArray()).IsEquivalentTo(tcpReply);
        await Assert.That(exchanges[0].ClientAddress!.Address).IsEqualTo(IPAddress.Loopback);
        await Assert.That(exchanges[0].ClientAddress!.Port).IsNotEqualTo(kdc.Endpoint.Port);
        await Assert.That(exchanges[0].Time).IsGreaterThanOrEqualTo(before);
        await Assert.That(exchanges[0].Time).IsLessThanOrEqualTo(DateTime.Now);
        await Assert.That(exchanges[0].Duration).IsGreaterThan(TimeSpan.Zero);
        await Assert.That(exchanges[0].ErrorCode).IsEqualTo(Kerberos.ErrorCode.None);

        await Assert.That(exchanges[1].Transport).IsEqualTo(ObolKdcTransport.Udp);
        await Assert.That(exchanges[1].ReplyBytes.ToArray()).IsEquivalentTo(udpReply);
        await Assert.That(exchanges[1].ClientAddress!.Address).IsEqualTo(IPAddress.Loopback);
    }

    [Test]
    public async Task ReportsTooBigUdpReplyAsError()
    {
        using TestKdc kdc = new(transport: ObolKdcTransport.Udp, maxUdpReplySize: 200);
        (_, ReadOnlyMemory<byte> request) = NewAsReq(kdc);

        byte[] udpReply = await kdc.SendUdpAsync(request);

        KdcExchange exchange = kdc.Exchanges.Single();
        await Assert.That(exchange.RequestType).IsEqualTo(Kerberos.MessageType.AsReq);
        await Assert.That(exchange.ErrorCode).IsEqualTo(Kerberos.ErrorCode.ResponseTooBig);
        await Assert.That(exchange.ErrorText).EndsWith("is too big for UDP, retry over TCP");
        await Assert.That(exchange.ClientName).IsEqualTo($"user@{TestKdc.Realm}");
        await Assert.That(exchange.Reply).IsNull();
        await Assert.That(exchange.ReplyBytes.ToArray()).IsEquivalentTo(udpReply);
    }

    [Test]
    public async Task ReportsTooLongTcpRequestAsError()
    {
        using TestKdc kdc = new();
        using TcpClient client = new();
        await client.ConnectAsync(kdc.Endpoint);
        using NetworkStream stream = client.GetStream();
        byte[] length = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, 2 * 1024 * 1024);
        await stream.WriteAsync(length);

        await stream.ReadExactlyAsync(length);
        byte[] reply = new byte[BinaryPrimitives.ReadInt32BigEndian(length)];
        await stream.ReadExactlyAsync(reply);

        KdcExchange exchange = kdc.Exchanges.Single();
        await Assert.That(exchange.RequestType).IsEqualTo(Kerberos.MessageType.Unknown);
        await Assert.That(exchange.ErrorCode).IsEqualTo(Kerberos.ErrorCode.FieldTooLong);
        await Assert.That(exchange.ErrorText).StartsWith("Request length 2097152 exceeds");
        await Assert.That(exchange.Transport).IsEqualTo(ObolKdcTransport.Tcp);
        await Assert.That(exchange.ClientAddress!.Address).IsEqualTo(IPAddress.Loopback);
        await Assert.That(exchange.RequestBytes.Length).IsEqualTo(0);
        await Assert.That(exchange.ReplyBytes.ToArray()).IsEquivalentTo(reply);
        await Assert.That(KrbError.DecodeApplication(reply).ErrorCode)
            .IsEqualTo(KerberosErrorCode.KRB_ERR_FIELD_TOOLONG);
    }

    [Test]
    public async Task IgnoresFailingExchangeCallback()
    {
        PrincipalStore store = new(TestKdc.Realm, caseInsensitive: false);
        ObolPrincipal user = store.Create(["user"], TestKdc.ToSecureString(TestKdc.Password),
            Kerberos.PacUserAccountControl.None);
        KerberosKey key = user.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;
        using KdcListener listener = KdcListener.Bind(store, new IPEndPoint(IPAddress.Loopback, 0),
            ObolKdcTransport.Tcp, KdcListener.DefaultMaxUdpReplySize);
        Exception? fault = null;
        int reported = 0;
        listener.Start(e => fault = e, _ =>
        {
            reported++;
            throw new InvalidOperationException("handler");
        });

        using TcpClient client = new();
        await client.ConnectAsync(listener.Endpoint);
        using NetworkStream stream = client.GetStream();
        ReadOnlyMemory<byte> request = KdcProcessorTests.NewAsReq("user", key, DateTimeOffset.UtcNow)
            .EncodeApplication();
        byte[] length = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, request.Length);
        await stream.WriteAsync(length);
        await stream.WriteAsync(request);
        await stream.ReadExactlyAsync(length);
        byte[] reply = new byte[BinaryPrimitives.ReadInt32BigEndian(length)];
        await stream.ReadExactlyAsync(reply);

        // The client still got its AS-REP and the listener kept running.
        await Assert.That(reported).IsEqualTo(1);
        await Assert.That(DecryptAsRep(reply, key).Nonce).IsEqualTo(1234);
        await Assert.That(fault).IsNull();
    }
}
