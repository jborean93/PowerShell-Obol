using System;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Obol.Tests;

/// <summary>The listener over UDP, the Kerberos.NET client prefers TCP so the replies are checked by hand.</summary>
public class KdcListenerTests
{
    private static (KerberosKey Key, ReadOnlyMemory<byte> Request) NewAsReq(TestKdc kdc)
    {
        ObolPrincipal user = kdc.AddUser("user");
        KerberosKey key = user.State.GetKey(EncryptionType.AES256_CTS_HMAC_SHA1_96)!;
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
}
